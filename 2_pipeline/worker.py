"""Redis worker that runs analyzer scans and posts completed findings."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from client import BackendClient
from post_processor import format_scan_results
from redis_producer import ASTScanProducer, SCAN_QUEUE_ORDER, SCAN_STATUS_PREFIX

logger = logging.getLogger(__name__)
SUPPORTED_EXTENSIONS = {".py", ".java", ".js", ".jsx", ".mjs", ".cjs"}
MAX_SOURCE_BYTES = 1_000_000


def _analyze_source_file(file_path: str, source: str) -> tuple[str, list[dict[str, Any]], list[float]]:
    TaintEngine, MultiLangParser = _analyzer_imports()
    from src.ml.multilingual_features import extract_features
    parsed = MultiLangParser().parse_source(source, file_path)
    features = extract_features(parsed.tree, source)
    findings: list[dict[str, Any]] = []
    if parsed.language == "python":
        for finding in TaintEngine().analyze(source, file_path):
            findings.append({
                "file": file_path,
                "line": finding.line,
                "rule_id": finding.rule_id,
                "description": f"Tainted value from {finding.source} reaches {finding.sink}",
                "severity": "HIGH",
                "reachable": True,
                "has_sanitizer": finding.has_sanitizer,
                "source": finding.source,
                "sink": finding.sink,
            })
    return file_path, findings, features


def _analyze_source_pair(item: tuple[str, str]) -> tuple[str, list[dict[str, Any]], list[float]]:
    return _analyze_source_file(*item)


def _analyzer_imports():
    import sys

    analyzer_path = str(Path(__file__).resolve().parent.parent / "3_ast_analyzer")
    if analyzer_path not in sys.path:
        sys.path.insert(0, analyzer_path)
    from src.analysis.taint_engine import TaintEngine
    from src.parser.multi_lang_parser import MultiLangParser

    return TaintEngine, MultiLangParser


class PipelineWorker:
    def __init__(
        self,
        redis_client: Any | None = None,
        backend_client: BackendClient | None = None,
    ) -> None:
        self.producer = ASTScanProducer(redis_client)
        self.redis = self.producer.redis_client
        self.backend = backend_client or BackendClient.from_environment()
        self.model_checkpoint = os.getenv("AST_MODEL_CHECKPOINT")

    def run_once(self, timeout_seconds: int = 5) -> dict[str, Any] | None:
        try:
            item = self.redis.blpop(list(SCAN_QUEUE_ORDER), timeout=timeout_seconds)
        except TypeError:
            item = self.redis.blpop(SCAN_QUEUE_ORDER[1], timeout=timeout_seconds)
        if not item:
            return None
        raw = item[1] if isinstance(item, (tuple, list)) else item
        try:
            job = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            logger.error("Dropping malformed scan queue item: %s", exc)
            return None
        return self.process_job(job)

    def process_job(self, job: dict[str, Any]) -> dict[str, Any]:
        scan_id = job.get("scan_id")
        if not isinstance(scan_id, str) or not scan_id:
            raise ValueError("queued job requires scan_id")
        status_key = f"{SCAN_STATUS_PREFIX}{scan_id}"
        self.redis.hset(status_key, mapping={"status": "IN_PROGRESS"})
        try:
            source_files = self._get_source_files(job)
            findings = self._analyze_and_score(source_files, self.model_checkpoint)
            result = {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "commit_sha": job.get("commit_sha"),
                "vulnerabilities": findings,
            }
            if job.get("post_results_to_backend"):
                self.backend.submit_results(scan_id, result)
            self.redis.hset(status_key, mapping={
                "status": "COMPLETED",
                "result": json.dumps(format_scan_results(result)),
            })
            return result
        except Exception as exc:
            self.redis.hset(status_key, mapping={"status": "FAILED", "error": str(exc)})
            logger.exception("Scan %s failed", scan_id)
            raise

    def _get_source_files(self, job: dict[str, Any]) -> dict[str, str]:
        files = job.get("files")
        if isinstance(files, dict):
            return self._filter_files(files)
        repo = job.get("repository")
        if not isinstance(repo, dict) or not isinstance(repo.get("clone_url"), str):
            raise ValueError("job requires inline files or a repository clone_url")
        url = repo["clone_url"]
        host = urlparse(url).hostname
        if host not in {"github.com", "www.github.com", "gitlab.com", "www.gitlab.com"}:
            raise ValueError("repository clone URL must use GitHub or GitLab")
        commit = job.get("commit_sha")
        if not isinstance(commit, str) or not commit:
            raise ValueError("repository scan requires commit_sha")
        with tempfile.TemporaryDirectory(prefix="autoforge-scan-") as directory:
            checkout = Path(directory) / "repo"
            self._run_git(["git", "clone", "--no-checkout", "--depth", "1", url, str(checkout)])
            self._run_git(["git", "-C", str(checkout), "fetch", "--depth", "1", "origin", commit])
            self._run_git(["git", "-C", str(checkout), "checkout", "--detach", "FETCH_HEAD"])
            return self._read_files(checkout)

    @staticmethod
    def _run_git(command: list[str]) -> None:
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)

    @staticmethod
    def _filter_files(files: dict[str, Any]) -> dict[str, str]:
        return {
            path: source for path, source in files.items()
            if isinstance(path, str)
            and not Path(path).is_absolute()
            and ".." not in Path(path).parts
            and Path(path).suffix.lower() in SUPPORTED_EXTENSIONS
            and isinstance(source, str)
            and len(source.encode("utf-8")) <= MAX_SOURCE_BYTES
        }

    @classmethod
    def _read_files(cls, root: Path, selected: list[str] | None = None) -> dict[str, str]:
        candidates = [
            str(path.relative_to(root)) for path in root.rglob("*")
            if path.is_file()
            and not any(part.lower() in {
                ".git", ".venv", "venv", "node_modules", "vendor", "build", "dist"
            } for part in path.relative_to(root).parts)
            and path.suffix.lower() in SUPPORTED_EXTENSIONS
        ]
        sources: dict[str, str] = {}
        for relative in candidates:
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts:
                continue
            full_path = (root / path).resolve()
            if root.resolve() not in full_path.parents or not full_path.is_file():
                continue
            if full_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            if full_path.stat().st_size > MAX_SOURCE_BYTES:
                continue
            try:
                sources[path.as_posix()] = full_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                logger.warning("Skipping non-UTF-8 source file %s", relative)
        if not sources:
            raise ValueError("scan contains no supported source files")
        return sources

    @staticmethod
    def _analyze_files(files: dict[str, str]) -> list[dict[str, Any]]:
        return PipelineWorker._analyze_and_score(files, None)

    @staticmethod
    def _analyze_and_score(
        files: dict[str, str], model_checkpoint: str | None
    ) -> list[dict[str, Any]]:
        _analyzer_imports()
        from src.engine.parallel_executor import ParallelExecutor
        from src.scoring.risk_aggregator import RiskAggregator
        from src.scoring.scoring_engine import ScoringEngine

        work = list(files.items())
        max_workers = min(os.cpu_count() or 1, int(os.getenv("AST_WORKERS", "4")))
        parsed = ParallelExecutor(max_workers=max_workers).map(_analyze_source_pair, work)

        inference = None
        if model_checkpoint:
            from src.ml.inference import ASTInference
            inference = ASTInference.from_checkpoint(model_checkpoint)

        cross_file_findings: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory(prefix="autoforge-project-") as directory:
            project_root = Path(directory).resolve()
            python_sources = [
                (path, source) for path, source in files.items()
                if Path(path).suffix.lower() == ".py"
                and not Path(path).is_absolute()
                and ".." not in Path(path).parts
            ]
            for relative, source in python_sources:
                destination = (project_root / relative).resolve()
                if project_root not in destination.parents:
                    raise ValueError(f"Invalid source path: {relative}")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(source, encoding="utf-8")
            if python_sources:
                from src.analysis.cross_file_resolver import CrossFileResolver
                cross_file_findings = CrossFileResolver(project_root).analyze_taint()

        all_findings: list[dict[str, Any]] = []
        feature_by_file = {path: features for path, _, features in parsed}
        merged_findings: dict[tuple[str, int, str], dict[str, Any]] = {}
        for file_path, findings, _ in parsed:
            for finding in findings:
                merged_findings[(file_path, finding["line"], finding["rule_id"])] = finding
        for finding in cross_file_findings:
            key = (finding["file"], finding["line"], finding["rule_id"])
            merged_findings[key] = {
                **finding,
                "description": f"Tainted value from {finding['source']} reaches {finding['sink']}",
            }
        for finding in merged_findings.values():
            if finding["file"] not in feature_by_file:
                continue
            static = RiskAggregator.aggregate(
                finding["rule_id"],
                reachability="direct",
                partial_sanitizer=finding["has_sanitizer"],
            )
            probability = inference.predict(feature_by_file[finding["file"]]) if inference else None
            hybrid = ScoringEngine.calculate_hybrid_risk(static["final_score"], probability)
            finding.update({
                "static_risk_score": static["final_score"],
                "ml_probability": probability,
                "combined_risk_score": hybrid["combined_risk_score"],
                "severity": hybrid["severity"],
            })
            all_findings.append(finding)
        return all_findings


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    worker = PipelineWorker()
    logger.info("AutoForge Redis worker started")
    while True:
        worker.run_once()


if __name__ == "__main__":
    main()
