"""Loopback-only API for interactive, local project source scans."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.responses import Response

from src.analysis.taint_engine import TaintEngine
from src.analysis.cross_file_resolver import CrossFileResolver
from src.analysis.reachability import ReachabilityAnalyzer
from src.analysis.runtime_reachability import apply_runtime_observations
from src.reporting.compliance_evidence import build_compliance_evidence
from src.engine.cfg_builder import CFGBuilder
from src.multitenancy.sandbox_runner import ASTSandboxRunner
from src.multilingual.tree_sitter_engine import TreeSitterEngine
from src.ml.cpg_runtime import configured_cpg_predictions
from src.monitoring.metrics_collector import MetricsCollector
from src.parser.multi_lang_parser import MultiLangParser
from src.policy.security_gate import evaluate_security_gate
from src.reporting.executive_report import build_html_report, build_pdf_report
from src.reporting.sarif_generator import SARIFReporter
from src.reporting.scan_metrics import ScanMetricsStore, build_scan_metrics
from src.scoring.vulnerability_scorer import VulnerabilityScorer

app = FastAPI(title="AutoForge Local AST Analyzer")
_api_metrics = MetricsCollector()
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/api/v1/parser-health")
def parser_health() -> dict[str, Any]:
    return _TREE_SITTER_ENGINE.health_info()


class AnalyzeRequest(BaseModel):
    source: str = Field(max_length=256_000)
    file_path: str = Field(default="uploaded.py", min_length=1, max_length=1024)
    checks: list[str] = Field(default_factory=lambda: ["syntax", "taint", "control_flow"])


class ProjectFile(BaseModel):
    file_path: str = Field(min_length=1, max_length=1024)
    source: str = Field(max_length=256_000)
    expected_sha256: str | None = Field(default=None, max_length=64)


class ProjectAnalyzeRequest(BaseModel):
    files: list[ProjectFile] = Field(min_length=1, max_length=1000)
    runtime_executed_functions: list[str] | None = Field(default=None, max_length=10000)


class AnalyzeFindingsRequest(BaseModel):
    repo_path: str = Field(min_length=1, max_length=4096)
    findings: list[dict[str, Any]] = Field(max_length=10000)


class ScoreFindingsRequest(BaseModel):
    tagged_findings: list[dict[str, Any]] = Field(max_length=10000)


class SecurityReportRequest(BaseModel):
    metrics: dict[str, Any]
    findings: list[dict[str, Any]]
    format: Literal["html", "pdf"]


_scan_metrics_store: ScanMetricsStore | None = None
_LOGGER = logging.getLogger(__name__)
_TREE_SITTER_ENGINE = TreeSitterEngine()


@app.middleware("http")
async def instrument_requests(request, call_next):
    started_at = time.perf_counter()
    status_code = 500
    try:
        if request.url.path in {
            "/analyze",
            "/api/v1/analyze",
            "/api/v1/analyze-project",
        }:
            with _api_metrics.track_scan():
                response = await call_next(request)
        else:
            response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        _api_metrics.record_http_request(
            request.method,
            route_path,
            status_code,
            time.perf_counter() - started_at,
        )
        _api_metrics.update_memory_usage()


def _cpg_predictions(
    sources: dict[str, str],
) -> tuple[dict[str, float], dict[str, Any]]:
    if not os.getenv("CPG_GNN_CHECKPOINT", "").strip():
        return configured_cpg_predictions(sources)
    try:
        with _api_metrics.track_inference("cpg_gnn"):
            return configured_cpg_predictions(sources)
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        _LOGGER.exception("CPG-GNN inference failed")
        return {}, {
            "name": "CPG GNN",
            "available": False,
            "status": "failed",
            "confidence": None,
            "reason": str(error)[:1000],
        }


def _record_findings_metrics(findings: list[dict[str, Any]]) -> None:
    supported = [
        finding
        for finding in findings
        if str(finding.get("severity", "")).upper() in {"CRITICAL", "HIGH", "MEDIUM"}
    ]
    _api_metrics.record_findings(supported)


def _metrics_store() -> ScanMetricsStore:
    global _scan_metrics_store
    if _scan_metrics_store is None:
        _scan_metrics_store = ScanMetricsStore()
    return _scan_metrics_store


def _record_scan_metrics(
    result: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    files_received: int,
    files_analyzed: int,
) -> dict[str, Any]:
    metrics = build_scan_metrics(
        findings,
        files_received=files_received,
        files_analyzed=files_analyzed,
    )
    metrics["history_id"] = _metrics_store().record(metrics)
    result["metrics"] = metrics
    return result


_SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".rs": "rust",
    ".sql": "sql",
}
_SUPPORTED_CHECKS = {"syntax", "taint", "control_flow"}
_PROJECT_EXTENSIONS = set(_SUPPORTED_EXTENSIONS) | {
    ".bash", ".c", ".cc", ".conf", ".cpp", ".cs", ".css", ".dockerfile", ".go",
    ".h", ".hpp", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".mjs",
    ".php", ".properties", ".rb", ".rs", ".sh", ".sql", ".tf",
    ".toml", ".ts", ".tsx", ".xml", ".yaml", ".yml",
}
_PROJECT_FILENAMES = {
    "dockerfile", "makefile", "requirements.txt", "package.json",
    "package-lock.json", "pom.xml", "go.mod", "go.sum",
}
_EXCLUDED_PROJECT_PARTS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
    "build", "dist", "target", "__pycache__", ".pytest_cache",
}
_SECRET_FILENAMES = {
    ".env", ".env.local", ".env.production", "id_rsa", "id_ed25519",
    ".npmrc", ".pypirc", ".netrc", "authorized_keys", "known_hosts",
    "credentials", "secrets",
}
_MAX_PROJECT_BYTES = 20_000_000
_SCANNER_TIMEOUT_SECONDS = 180


def _validate_file_path(file_path: str) -> str:
    normalized = file_path.replace("\\", "/")
    path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(file_path)
    if (
        path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or any(part in {".", ".."} for part in normalized.split("/"))
        or path.suffix.lower() not in _SUPPORTED_EXTENSIONS
    ):
        raise HTTPException(
            status_code=422,
            detail="file_path must be a repository-relative supported source filename",
        )
    return normalized


def _validate_project_file_path(file_path: str) -> str:
    normalized = file_path.replace("\\", "/")
    path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(file_path)
    filename = path.name.lower()
    suffix = path.suffix.lower()
    if (
        path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
        or any(part.lower() in _EXCLUDED_PROJECT_PARTS for part in path.parts[:-1])
        or filename in _SECRET_FILENAMES
        or filename.startswith(".env.")
        or any(token in filename for token in ("secret", "credential", "private-key", "service-account"))
        or suffix in {".pem", ".key", ".p12", ".pfx"}
        or (filename not in _PROJECT_FILENAMES and suffix not in _PROJECT_EXTENSIONS)
    ):
        raise HTTPException(
            status_code=422,
            detail="file_path must be a repository-relative, non-secret source or configuration file",
        )
    return normalized


def _severity(value: Any) -> str:
    normalized = str(value or "INFO").upper()
    if normalized in {"ERROR", "CRITICAL"}:
        return "CRITICAL"
    if normalized in {"WARNING", "HIGH"}:
        return "HIGH"
    if normalized == "MEDIUM":
        return normalized
    return "LOW"


def _relative_scanner_path(value: Any, root: Path) -> str:
    if not isinstance(value, str) or not value:
        return ""
    candidate = Path(value)
    if not candidate.is_absolute():
        return PurePosixPath(value.replace("\\", "/")).as_posix()
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return PurePosixPath(value.replace("\\", "/")).name


def _run_project_scanners(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    tools: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []
    commands = {
        "semgrep": [
            "semgrep", "scan", "--config", "p/default", "--json",
            "--metrics=off", str(root),
        ],
        "checkov": [
            sys.executable, "-m", "checkov.main", "-d", str(root), "-o", "json",
            "--skip-download",
        ],
    }

    for tool, command in commands.items():
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_SCANNER_TIMEOUT_SECONDS,
                env=env,
                shell=False,
                cwd=root,
            )
        except FileNotFoundError:
            tools[tool] = {
                "status": "unavailable",
                "finding_count": 0,
                "error": f"{tool} is not installed or is not available on PATH.",
            }
            continue
        except subprocess.TimeoutExpired:
            tools[tool] = {
                "status": "timed_out",
                "finding_count": 0,
                "error": f"{tool} exceeded the {_SCANNER_TIMEOUT_SECONDS}-second scan limit.",
            }
            continue
        except OSError as error:
            tools[tool] = {
                "status": "failed",
                "finding_count": 0,
                "error": str(error)[:1000],
            }
            continue

        try:
            payload = json.loads(completed.stdout) if completed.stdout.strip() else None
        except json.JSONDecodeError:
            payload = None
        accepted_codes = {0, 1}
        if payload is None or completed.returncode not in accepted_codes:
            error_text = (completed.stderr or completed.stdout).strip()
            tools[tool] = {
                "status": "failed",
                "finding_count": 0,
                "error": error_text[-1000:] or f"{tool} exited with code {completed.returncode}.",
            }
            continue

        tool_findings: list[dict[str, Any]] = []
        if tool == "semgrep":
            raw_findings = payload.get("results", []) if isinstance(payload, dict) else []
            for item in raw_findings:
                extra = item.get("extra") or {}
                tool_findings.append({
                    "source": "Semgrep",
                    "rule_id": item.get("check_id", "SEMGREP"),
                    "file": _relative_scanner_path(item.get("path"), root),
                    "line": (item.get("start") or {}).get("line"),
                    "severity": _severity(extra.get("severity")),
                    "message": extra.get("message", ""),
                })
        else:
            entries = payload if isinstance(payload, list) else [payload]
            for entry in entries:
                failed_checks = (entry.get("results") or {}).get("failed_checks", [])
                for item in failed_checks:
                    line_range = item.get("file_line_range") or []
                    tool_findings.append({
                        "source": "Checkov",
                        "rule_id": item.get("check_id", "CHECKOV"),
                        "file": _relative_scanner_path(
                            item.get("file_abs_path") or item.get("file_path"), root
                        ),
                        "line": line_range[0] if line_range else None,
                        "severity": _severity(item.get("severity")),
                        "message": item.get("check_name", ""),
                    })

        findings.extend(tool_findings)
        tool_status = {
            "status": "complete",
            "finding_count": len(tool_findings),
        }
        if tool == "semgrep":
            scan_errors = payload.get("errors", []) if isinstance(payload, dict) else []
            scan_paths = payload.get("paths", {}) if isinstance(payload, dict) else {}
            scanned_paths = scan_paths.get("scanned", []) if isinstance(scan_paths, dict) else []
            tool_status["config"] = "p/default"
            tool_status["files_scanned"] = len(scanned_paths) if isinstance(scanned_paths, list) else 0
            if scan_errors:
                error_messages = [
                    item.get("message", str(item)) if isinstance(item, dict) else str(item)
                    for item in scan_errors
                ] if isinstance(scan_errors, list) else [str(scan_errors)]
                tool_status["status"] = "partial"
                tool_status["error"] = (
                    f"Semgrep reported {len(error_messages)} scan error(s): "
                    + "; ".join(error_messages[:5])
                )[:1000]
        tools[tool] = tool_status
    return tools, findings


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ready", "service": "ast-analyzer"}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return health()


@app.get("/readyz")
def readyz() -> dict[str, Any]:
    checkpoint = os.getenv("CPG_GNN_CHECKPOINT", "").strip()
    checkpoint_exists = bool(checkpoint and Path(checkpoint).expanduser().is_file())
    cpg_status = {
        "configured": bool(checkpoint),
        "checkpoint_available": checkpoint_exists if checkpoint else None,
    }
    if checkpoint and not checkpoint_exists:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "service": "ast-analyzer",
                "cpg_gnn": cpg_status,
            },
        )
    return {
        "status": "ready",
        "service": "ast-analyzer",
        "cpg_gnn": cpg_status,
    }


@app.get("/metrics")
def prometheus_metrics() -> Response:
    return Response(
        content=_api_metrics.render(),
        media_type=_api_metrics.content_type,
    )


@app.post("/analyze")
def analyze_scanner_findings(request: AnalyzeFindingsRequest) -> dict[str, Any]:
    workspace_root = Path(os.getenv("AST_SCAN_WORKSPACE_ROOT", "/workspace")).resolve()
    project_root = Path(request.repo_path).resolve()
    if (
        project_root == workspace_root
        or workspace_root not in project_root.parents
        or not project_root.is_dir()
    ):
        raise HTTPException(
            status_code=422,
            detail="repo_path must be an existing scan directory under AST_SCAN_WORKSPACE_ROOT",
        )

    python_sources: dict[str, str] = {}
    for path in project_root.rglob("*.py"):
        resolved = path.resolve()
        if workspace_root not in resolved.parents or not resolved.is_file():
            continue
        if any(part.lower() in _EXCLUDED_PROJECT_PARTS for part in path.relative_to(project_root).parts):
            continue
        if resolved.stat().st_size > 256_000:
            continue
        try:
            python_sources[path.relative_to(project_root).as_posix()] = resolved.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

    try:
        reachability = (
            ReachabilityAnalyzer().analyze_project(project_root, request.findings)
            if python_sources
            else {
                "tagged_findings": [
                    {**finding, "reachability": "UNKNOWN"}
                    for finding in request.findings
                ]
            }
        )
    except (OSError, SyntaxError, ValueError, RuntimeError) as error:
        raise HTTPException(status_code=422, detail=f"AST analysis failed: {error}") from error

    predictions, model_status = _cpg_predictions(python_sources)
    tagged_findings = reachability["tagged_findings"]
    for finding in tagged_findings:
        confidence = predictions.get(finding.get("file"))
        if confidence is not None:
            finding["cpg_gnn_file_confidence"] = confidence
    _record_findings_metrics(tagged_findings)
    return {"tagged_findings": tagged_findings, "model": model_status}


@app.post("/score")
def score_scanner_findings(request: ScoreFindingsRequest) -> list[dict[str, Any]]:
    scored = VulnerabilityScorer.score_findings(request.tagged_findings)
    priority_by_state = {
        ("REACHABLE_CODE", "CRITICAL"): ("P0", "Critical"),
        ("REACHABLE_CODE", "HIGH"): ("P1", "High"),
        ("REACHABLE_CODE", "MEDIUM"): ("P2", "Medium"),
        ("REACHABLE_CODE", "LOW"): ("P3", "Low"),
        ("UNREACHABLE_NOISE", "CRITICAL"): ("P2", "Medium"),
        ("UNREACHABLE_NOISE", "HIGH"): ("P3", "Low"),
    }
    for finding in scored:
        priority, label = priority_by_state.get(
            (finding.get("reachability"), finding.get("severity")),
            ("P3", "Low"),
        )
        finding["priority"] = priority
        finding["priority_label"] = label
    return scored


@app.post("/api/v1/analyze")
def analyze_source(request: AnalyzeRequest) -> dict[str, Any]:
    return _analyze_source(request, record_metrics=True)


def _analyze_source(
    request: AnalyzeRequest,
    *,
    record_metrics: bool,
    include_cpg: bool = True,
) -> dict[str, Any]:
    file_path = _validate_file_path(request.file_path)
    if len(request.source.encode("utf-8")) > 256_000:
        raise HTTPException(status_code=422, detail="source exceeds the 256,000-byte size limit")
    if not request.checks or set(request.checks) - _SUPPORTED_CHECKS:
        raise HTTPException(
            status_code=422,
            detail=f"checks must be a non-empty subset of {sorted(_SUPPORTED_CHECKS)}",
        )

    language = _SUPPORTED_EXTENSIONS[PurePosixPath(file_path).suffix.lower()]
    if language != "python":
        result = _analyze_tree_sitter_source(request.source, file_path, language)
        if not record_metrics:
            return result
        return _record_scan_metrics(
            result,
            result["findings"],
            files_received=1,
            files_analyzed=1,
        )

    try:
        parsed_tree = ASTSandboxRunner().parse(request.source)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    parsed = MultiLangParser().parse_source(
        request.source,
        file_path=file_path,
        language="python",
    )
    cfg = CFGBuilder().build(parsed_tree).to_dict() if "control_flow" in request.checks else None
    source_lines = request.source.splitlines()
    raw_findings: list[dict[str, Any]] = []
    if "taint" in request.checks:
        for finding in TaintEngine().analyze_cfg(request.source, file_path=file_path):
            item = asdict(finding)
            item.update(
                {
                    "file": file_path,
                    "message": (
                        f"Untrusted input from {finding.source} reaches {finding.sink}."
                    ),
                    "code_snippet": (
                        source_lines[finding.line - 1][:512]
                        if 0 < finding.line <= len(source_lines)
                        else ""
                    ),
                    "ml_confidence": 1.0,
                }
            )
            raw_findings.append(item)

    scored_findings = VulnerabilityScorer.score_findings(raw_findings)
    for finding in scored_findings:
        finding.pop("ml_confidence", None)
    model_status: dict[str, Any] = {
        "name": "CPG GNN",
        "available": False,
        "status": "not_applicable",
        "confidence": None,
        "reason": "CPG-GNN inference is currently supported for Python source only.",
    }
    if language == "python" and include_cpg:
        predictions, model_status = _cpg_predictions({file_path: request.source})
        confidence = predictions.get(file_path)
        if confidence is not None:
            for finding in scored_findings:
                finding["cpg_gnn_file_confidence"] = confidence

    severity_counts = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for finding in scored_findings:
        severity_counts[finding["severity"]] += 1

    result = {
        "file_path": file_path,
        "language": parsed.language,
        "checks_run": ["syntax", *(
            check for check in ("taint", "control_flow") if check in request.checks
        )],
        "summary": {
            "finding_count": len(scored_findings),
            "severity_counts": severity_counts,
        },
        "findings": scored_findings,
        "policy_gate": evaluate_security_gate(scored_findings),
        "model": model_status,
        "ast": parsed.tree,
        "cfg": cfg,
        "sarif": SARIFReporter.build_report(scored_findings),
    }
    if not record_metrics:
        return result
    _record_findings_metrics(scored_findings)
    return _record_scan_metrics(
        result,
        scored_findings,
        files_received=1,
        files_analyzed=1,
    )


@app.post("/api/v1/analyze-project")
def analyze_project(request: ProjectAnalyzeRequest) -> dict[str, Any]:
    project_files: list[tuple[str, str]] = []
    provenance_records: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    total_bytes = 0
    for item in request.files:
        file_path = _validate_project_file_path(item.file_path)
        path_key = file_path.casefold()
        if path_key in seen_paths:
            raise HTTPException(status_code=422, detail=f"duplicate project path: {file_path}")
        seen_paths.add(path_key)
        source_size = len(item.source.encode("utf-8"))
        if source_size > 256_000:
            raise HTTPException(status_code=422, detail=f"{file_path} exceeds the 256,000-byte per-file limit")
        source_digest = hashlib.sha256(item.source.encode("utf-8")).hexdigest()
        if item.expected_sha256 is not None:
            expected_digest = item.expected_sha256.lower()
            if len(expected_digest) != 64 or any(
                character not in "0123456789abcdef" for character in expected_digest
            ):
                raise HTTPException(
                    status_code=422,
                    detail=f"{file_path} expected_sha256 must be a 64-character hexadecimal SHA-256 digest",
                )
            if source_digest != expected_digest:
                raise HTTPException(
                    status_code=422,
                    detail=f"{file_path} source SHA-256 does not match expected_sha256",
                )
            provenance_status = "MATCHED"
        else:
            provenance_status = "UNVERIFIED"
        provenance_records.append({
            "file_path": file_path,
            "sha256": source_digest,
            "status": provenance_status,
        })
        total_bytes += source_size
        if total_bytes > _MAX_PROJECT_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"project source exceeds the {_MAX_PROJECT_BYTES:,}-byte scan limit",
            )
        project_files.append((file_path, item.source))

    file_results: list[dict[str, Any]] = []
    unified_findings: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="autoforge-scan-") as temporary_directory:
        project_root = Path(temporary_directory) / "project"
        python_root = Path(temporary_directory) / "python-project"
        project_root.mkdir()
        python_root.mkdir()
        valid_python_files: list[tuple[str, str]] = []

        for file_path, source in project_files:
            target = project_root.joinpath(*PurePosixPath(file_path).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")

            result: dict[str, Any] | None = None
            error: str | None = None
            if PurePosixPath(file_path).suffix.lower() in _SUPPORTED_EXTENSIONS:
                try:
                    result = _analyze_source(
                        AnalyzeRequest(
                            source=source,
                            file_path=file_path,
                            checks=["syntax", "taint", "control_flow"],
                        ),
                        record_metrics=False,
                        include_cpg=False,
                    )
                except HTTPException as scan_error:
                    error = str(scan_error.detail)

            file_results.append({
                "file_path": file_path,
                "status": "analyzed" if result else "failed" if error else "scanner_only",
                "error": error,
                "result": result,
            })
            if result:
                for finding in result["findings"]:
                    unified_findings.append({
                        **finding,
                        "file": file_path,
                        "source": "AST",
                        "language": result["language"],
                    })
                if PurePosixPath(file_path).suffix.lower() == ".py":
                    valid_python_files.append((file_path, source))

        scanner_status, scanner_findings = _run_project_scanners(project_root)
        unified_findings.extend(scanner_findings)

        reachability_status = "not_available"
        reachability_details: dict[str, Any] = {
            "status": reachability_status,
            "reachable_functions": [],
            "missing_entry_points": [],
        }
        if valid_python_files:
            for file_path, source in valid_python_files:
                target = python_root.joinpath(*PurePosixPath(file_path).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
            try:
                resolver = CrossFileResolver(python_root)
                cross_file_findings = resolver.analyze_taint()
                existing = {
                    (item.get("file"), item.get("line"), item.get("rule_id"))
                    for item in unified_findings
                }
                for finding in cross_file_findings:
                    key = (finding.get("file"), finding.get("line"), finding.get("rule_id"))
                    if key in existing:
                        continue
                    enriched = VulnerabilityScorer.score_finding({
                        **finding,
                        "message": (
                            f"Cross-file flow from {finding.get('source')} reaches "
                            f"{finding.get('sink')}."
                        ),
                        "source": "AST cross-file",
                        "language": "python",
                    })
                    unified_findings.append(enriched)
                    existing.add(key)

                reachability = ReachabilityAnalyzer().analyze_project(
                    python_root,
                    unified_findings,
                )
                unified_findings = reachability["tagged_findings"]
                reachability_status = "complete"
                reachability_details = {
                    "status": reachability_status,
                    "reachable_functions": reachability["reachable_functions"],
                    "missing_entry_points": reachability["missing_entry_points"],
                }
            except (OSError, SyntaxError, ValueError) as error:
                reachability_status = "failed"
                reachability_details = {
                    "status": reachability_status,
                    "reachable_functions": [],
                    "missing_entry_points": [],
                    "error": str(error)[:1000],
                }

    try:
        unified_findings, runtime_evidence = apply_runtime_observations(
            unified_findings,
            request.runtime_executed_functions,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    severity_counts = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for finding in unified_findings:
        severity = str(finding.get("severity", "")).upper()
        if severity in severity_counts:
            severity_counts[severity] += 1

    python_sources = dict(valid_python_files)
    cpg_predictions, model_status = _cpg_predictions(python_sources)
    for finding in unified_findings:
        confidence = cpg_predictions.get(finding.get("file"))
        if confidence is not None:
            finding["cpg_gnn_file_confidence"] = confidence
    _record_findings_metrics(unified_findings)

    result = {
        "files": file_results,
        "content_integrity": {
            "status": (
                "verified"
                if all(record["status"] == "MATCHED" for record in provenance_records)
                else "partially_verified"
                if any(record["status"] == "MATCHED" for record in provenance_records)
                else "unverified"
            ),
            "files": provenance_records,
        },
        "findings": unified_findings,
        "compliance_evidence": build_compliance_evidence(unified_findings),
        "tools": scanner_status,
        "reachability": reachability_details,
        "runtime_evidence": runtime_evidence,
        "policy_gate": evaluate_security_gate(unified_findings),
        "model": model_status,
        "summary": {
            "files_received": len(project_files),
            "files_analyzed": sum(result["status"] == "analyzed" for result in file_results),
            "files_scanner_only": sum(result["status"] == "scanner_only" for result in file_results),
            "files_failed": sum(result["status"] == "failed" for result in file_results),
            "finding_count": len(unified_findings),
            "severity_counts": severity_counts,
            "reachable": sum(item.get("reachability") == "REACHABLE_CODE" for item in unified_findings),
            "unreachable": sum(item.get("reachability") == "UNREACHABLE_NOISE" for item in unified_findings),
            "unverified": sum(item.get("reachability") in {None, "UNKNOWN", "NOT_ANALYZED"} for item in unified_findings),
        },
    }
    return _record_scan_metrics(
        result,
        unified_findings,
        files_received=len(project_files),
        files_analyzed=sum(item["status"] == "analyzed" for item in file_results),
    )


@app.get("/api/v1/metrics/history")
def scan_metrics_history(limit: int = 30) -> dict[str, Any]:
    try:
        scans = _metrics_store().history(limit)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {"scans": scans, "count": len(scans)}


@app.post("/api/v1/reports")
def generate_security_report(request: SecurityReportRequest) -> Response:
    if request.format == "html":
        return Response(
            build_html_report(request.metrics, request.findings),
            media_type="text/html; charset=utf-8",
            headers={
                "Content-Disposition":
                    'attachment; filename="SECURITY_SUMMARY_REPORT.html"'
            },
        )
    try:
        report = build_pdf_report(request.metrics, request.findings)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return Response(
        report,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                'attachment; filename="SECURITY_SUMMARY_REPORT.pdf"'
        },
    )


def _analyze_tree_sitter_source(
    source: str,
    file_path: str,
    language: str,
) -> dict[str, Any]:
    try:
        parsed = _TREE_SITTER_ENGINE.parse_source(
            source,
            language,
            file_path=file_path,
        )
    except (RuntimeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    if parsed.has_errors:
        _LOGGER.warning(
            "Tree-sitter reported syntax errors",
            extra={"language": language, "file_path": file_path, "error_count": parsed.error_count},
        )
    syntax_nodes = [
        node for node in parsed.graph.nodes if node.kind in {"ERROR", "MISSING"}
    ]
    severity_counts = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}

    diagnostics = [
        {
            "file": file_path,
            "line": node.line,
            "rule_id": "PARSER_DIAGNOSTIC",
            "message": (
                f"The {language} parser reported a {node.kind.lower()} syntax node"
                f"{f' near {node.text!r}' if node.text else ''}; "
                "this is not a confirmed security vulnerability."
            ),
            "parser_node": node.kind,
            "code_snippet": source.splitlines()[node.line - 1][:512]
            if 0 < node.line <= len(source.splitlines())
            else "",
        }
        for node in syntax_nodes
    ]
    if parsed.has_errors and not diagnostics:
        diagnostics.append({
            "file": file_path,
            "line": 1,
            "rule_id": "PARSER_DIAGNOSTIC",
            "message": (
                f"The {language} parser reported {parsed.error_count} syntax issue(s); "
                "this is not a confirmed security vulnerability."
            ),
            "code_snippet": source.splitlines()[0][:512] if source.splitlines() else "",
        })

    syntax_tree = {
        "type": parsed.root_type,
        "nodes": [
            {"id": node.node_id, "type": node.kind, "line": node.line, "text": node.text}
            for node in parsed.graph.nodes
        ],
        "edges": [
            {"source": source_id, "target": target_id, "type": edge_type}
            for source_id, target_id, edge_type in parsed.graph.edges
        ],
    }
    return {
        "file_path": file_path,
        "language": parsed.language,
        "checks_run": ["syntax"],
        "summary": {
            "finding_count": 0,
            "severity_counts": severity_counts,
            "syntax_error_count": parsed.error_count,
        },
        "findings": [],
        "diagnostics": diagnostics,
        "policy_gate": evaluate_security_gate([]),
        "model": {
            "name": "CPG GNN",
            "available": False,
            "status": "not_applicable",
            "confidence": None,
            "reason": "CPG-GNN inference is currently supported for Python source only.",
        },
        "ast": syntax_tree,
        "cfg": None,
        "sarif": SARIFReporter.build_report([]),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8090)
