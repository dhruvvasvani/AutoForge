"""Loopback-only API for interactive, local project source scans."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.analysis.taint_engine import TaintEngine
from src.analysis.cross_file_resolver import CrossFileResolver
from src.analysis.reachability import ReachabilityAnalyzer
from src.engine.cfg_builder import CFGBuilder
from src.multitenancy.sandbox_runner import ASTSandboxRunner
from src.multilingual.tree_sitter_engine import TreeSitterEngine
from src.parser.multi_lang_parser import MultiLangParser
from src.policy.security_gate import evaluate_security_gate
from src.reporting.sarif_generator import SARIFReporter
from src.scoring.vulnerability_scorer import VulnerabilityScorer

app = FastAPI(title="AutoForge Local AST Analyzer")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class AnalyzeRequest(BaseModel):
    source: str = Field(max_length=256_000)
    file_path: str = Field(default="uploaded.py", min_length=1, max_length=1024)
    checks: list[str] = Field(default_factory=lambda: ["syntax", "taint", "control_flow"])


class ProjectFile(BaseModel):
    file_path: str = Field(min_length=1, max_length=1024)
    source: str = Field(max_length=256_000)


class ProjectAnalyzeRequest(BaseModel):
    files: list[ProjectFile] = Field(min_length=1, max_length=1000)


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
            "semgrep", "scan", "--config", "p/security-audit", "--json",
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
        tools[tool] = {
            "status": "complete",
            "finding_count": len(tool_findings),
        }
    return tools, findings


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/api/v1/analyze")
def analyze_source(request: AnalyzeRequest) -> dict[str, Any]:
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
        return _analyze_tree_sitter_source(request.source, file_path, language)

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

    severity_counts = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for finding in scored_findings:
        severity_counts[finding["severity"]] += 1

    return {
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
        "model": {
            "name": "CPG GNN",
            "available": False,
            "confidence": None,
            "reason": "GNN inference is not part of this local source-scan workflow.",
        },
        "ast": parsed.tree,
        "cfg": cfg,
        "sarif": SARIFReporter.build_report(scored_findings),
    }


@app.post("/api/v1/analyze-project")
def analyze_project(request: ProjectAnalyzeRequest) -> dict[str, Any]:
    project_files: list[tuple[str, str]] = []
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
                    result = analyze_source(
                        AnalyzeRequest(
                            source=source,
                            file_path=file_path,
                            checks=["syntax", "taint", "control_flow"],
                        )
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

    return {
        "files": file_results,
        "findings": unified_findings,
        "tools": scanner_status,
        "reachability": reachability_details,
        "policy_gate": evaluate_security_gate(unified_findings),
        "model": {
            "name": "CPG GNN",
            "available": False,
            "status": "not_available",
            "confidence": None,
            "reason": "No trained CPG GNN checkpoint is installed for this local scan.",
        },
        "summary": {
            "files_received": len(project_files),
            "files_analyzed": sum(result["status"] == "analyzed" for result in file_results),
            "files_scanner_only": sum(result["status"] == "scanner_only" for result in file_results),
            "files_failed": sum(result["status"] == "failed" for result in file_results),
            "finding_count": len(unified_findings),
            "reachable": sum(item.get("reachability") == "REACHABLE_CODE" for item in unified_findings),
            "unreachable": sum(item.get("reachability") == "UNREACHABLE_NOISE" for item in unified_findings),
            "unverified": sum(item.get("reachability") in {None, "UNKNOWN", "NOT_ANALYZED"} for item in unified_findings),
        },
    }


def _analyze_tree_sitter_source(
    source: str,
    file_path: str,
    language: str,
) -> dict[str, Any]:
    try:
        parsed = TreeSitterEngine().parse_source(source, language)
    except (RuntimeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    syntax_nodes = [
        node for node in parsed.graph.nodes if node.kind in {"ERROR", "MISSING"}
    ]
    findings = [
        {
            "file": file_path,
            "line": node.line,
            "rule_id": "SYNTAX_ERROR",
            "severity": "LOW",
            "message": f"Parser reported a {node.kind.lower()} syntax node.",
            "code_snippet": source.splitlines()[node.line - 1][:512]
            if 0 < node.line <= len(source.splitlines())
            else "",
        }
        for node in syntax_nodes
    ]
    if parsed.has_errors and not findings:
        findings.append(
            {
                "file": file_path,
                "line": 1,
                "rule_id": "SYNTAX_ERROR",
                "severity": "LOW",
                "message": f"Parser reported {parsed.error_count} syntax issue(s).",
                "code_snippet": source.splitlines()[0][:512] if source.splitlines() else "",
            }
        )

    severity_counts = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for finding in findings:
        severity_counts[finding["severity"]] += 1
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
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "syntax_error_count": parsed.error_count,
        },
        "findings": findings,
        "policy_gate": evaluate_security_gate(findings),
        "model": {
            "name": "CPG GNN",
            "available": False,
            "confidence": None,
            "reason": "GNN inference is not part of this local source-scan workflow.",
        },
        "ast": syntax_tree,
        "cfg": None,
        "sarif": SARIFReporter.build_report(findings),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8090)
