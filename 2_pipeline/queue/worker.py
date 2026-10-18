"""
worker.py - AutoForge scan worker (Pipeline module)

Per job:
  Redis list `scan_jobs`
    -> fetch the exact commit from GitHub (shallow, falls back to full clone)
    -> Semgrep + Checkov
    -> AST/ML service  (POST /analyze, POST /score)        [Dhruv]
    -> AI fix for P0/P1 findings (POST /api/fix)            [Kartik's ai-fix-service]
    -> POST results to backend /api/internal/scans/{id}/results   [Abhishek]
    -> Redis list `scan_results`, stage events on Redis channel `scan_events`
    -> delete the clone

Every external service is optional: if it is down the worker degrades and still
finishes the job (see `ast_status` in the result).

Config comes from environment variables (all prefixed AUTOFORGE_), see CONFIG below.
"""

import argparse
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

import redis
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ----------------------------------------------------------------- CONFIG
def _env(name, default):
    return os.environ.get(f"AUTOFORGE_{name}", default)


QUEUE_NAME = _env("QUEUE", "scan_jobs")
RESULTS_QUEUE = _env("RESULTS_QUEUE", "scan_results")
EVENTS_CHANNEL = _env("EVENTS_CHANNEL", "scan_events")

REDIS_HOST = _env("REDIS_HOST", "localhost")
REDIS_PORT = int(_env("REDIS_PORT", "6379"))

AST_SERVICE_URL = _env("AST_SERVICE_URL", "http://localhost:8001").rstrip("/")  # "" = disabled
BACKEND_URL = _env("BACKEND_URL", "http://localhost:8080").rstrip("/")
INTERNAL_SECRET = _env("INTERNAL_SECRET", "")  # sent as X-Internal-Secret (backend gate comes later)
AI_FIX_URL = _env("AI_FIX_URL", "http://localhost:5050").rstrip("/")
AI_FIX_ENABLED = _env("AI_FIX_ENABLED", "true").lower() == "true"
MAX_FIXES_PER_SCAN = int(_env("MAX_FIXES", "3"))

CLONE_TIMEOUT = int(_env("CLONE_TIMEOUT", "300"))
SCAN_TIMEOUT = int(_env("SCAN_TIMEOUT", "600"))
WORKSPACE_DIR = Path(_env("WORKSPACE_DIR", str(Path(tempfile.gettempdir()) / "autoforge_workspaces")))

# semgrep/checkov crash on Windows (cp1252) without UTF-8 forced
UTF8_ENV = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}

COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
REPO_NAME_RE = re.compile(r"^[\w.-]+/[\w.-]+$")

PRIORITY_LABELS = {"P0": "Critical", "P1": "High", "P2": "Medium", "P3": "Low"}
# same matrix as 3_ast_analyzer/week5_scoring/risk_scorer.py
PRIORITY_MATRIX = {
    ("REACHABLE_CODE", "error"): "P0",
    ("REACHABLE_CODE", "warning"): "P1",
    ("UNREACHABLE_NOISE", "error"): "P2",
    ("UNREACHABLE_NOISE", "warning"): "P3",
}
LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".c": "c", ".cpp": "cpp", ".tf": "terraform", ".yaml": "yaml",
    ".yml": "yaml", ".json": "json",
}


# ----------------------------------------------------------------- helpers
def _rmtree(path):
    """rmtree that also removes read-only git pack files (Windows)."""
    def _fix(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_fix)
    else:
        shutil.rmtree(path, onerror=_fix)


def fallback_priority(severity):
    """Severity-only priority, used when reachability is unknown."""
    s = (severity or "").upper()
    if s in ("ERROR", "CRITICAL", "HIGH"):
        return "P1"
    if s in ("WARNING", "MEDIUM"):
        return "P2"
    return "P3"


def local_score(finding):
    """Reachability + severity -> priority (mirror of risk_scorer.score_finding)."""
    reach = finding.get("reachability", "UNREACHABLE_NOISE")
    sev = str(finding.get("severity", "warning")).lower()
    priority = PRIORITY_MATRIX.get((reach, sev), "P3")
    out = dict(finding)
    out["priority"] = priority
    out["priority_label"] = PRIORITY_LABELS[priority]
    return out


class ScanWorker:
    def __init__(self, redis_host=REDIS_HOST, redis_port=REDIS_PORT):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_client = None
        self.connected = self.connect()

    # ------------------------------------------------------------- redis
    def connect(self):
        try:
            # protocol=2 avoids the HELLO error on older Redis servers
            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=10,
                health_check_interval=30,
                protocol=2,
            )
            self.redis_client.ping()
            logger.info("Connected to Redis at %s:%s", self.redis_host, self.redis_port)
            return True
        except Exception as e:
            logger.error("Failed to connect to Redis: %s", e)
            return False

    def emit(self, scan_id, stage, status="OK", message=""):
        """Stage event for live logs. Backend/frontend can subscribe to the Redis channel."""
        event = {
            "scan_id": scan_id,
            "stage": stage,
            "status": status,
            "message": message,
            "timestamp": datetime.now().isoformat(),
        }
        try:
            self.redis_client.publish(EVENTS_CHANNEL, json.dumps(event))
        except Exception as e:
            logger.debug("emit failed: %s", e)

    def push_result(self, result):
        try:
            self.redis_client.rpush(RESULTS_QUEUE, json.dumps(result))
            logger.info("Result pushed to %s", RESULTS_QUEUE)
        except Exception as e:
            logger.error("Failed to push result: %s", e)

    # --------------------------------------------------------------- job
    @staticmethod
    def parse_job(job_json):
        """Accepts the new schema (repoFullName/commitSha/scan_id/repo_url) and the old one."""
        job = json.loads(job_json)
        if not isinstance(job, dict):
            raise ValueError("job is not a JSON object")

        repo = job.get("repoFullName") or job.get("repository_id")
        commit = job.get("commitSha") or job.get("commit_sha") or job.get("commit_hash")
        repo_url = job.get("repo_url")
        if not repo_url and isinstance(repo, str) and REPO_NAME_RE.match(repo):
            repo_url = f"https://github.com/{repo}.git"

        return {
            "scan_id": job.get("scan_id") or job.get("job_id"),
            "repo": repo,
            "commit": commit,
            "repo_url": repo_url,
            "source_file": job.get("source_file"),
        }

    def _git(self, cwd, args, timeout):
        return subprocess.run(
            ["git", "-C", str(cwd), *args],
            check=True, capture_output=True, text=True, timeout=timeout, env=UTF8_ENV,
        )

    def prepare_repo(self, repo_url, commit, scan_id):
        """Exact commit on disk. Shallow fetch first (fast for big repos), full clone as fallback."""
        if not repo_url.startswith("https://"):
            raise ValueError("repo_url must be an https:// URL")
        if not COMMIT_RE.match(str(commit)):
            raise ValueError(f"invalid commit sha: {commit!r}")

        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(scan_id))
        workdir = WORKSPACE_DIR / safe_id
        if workdir.exists():
            _rmtree(workdir)
        WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
        workdir.mkdir()

        try:
            self._git(workdir, ["init", "-q"], 30)
            self._git(workdir, ["remote", "add", "origin", repo_url], 30)
            self._git(workdir, ["fetch", "--depth", "1", "-q", "origin", commit], CLONE_TIMEOUT)
            self._git(workdir, ["checkout", "-q", "FETCH_HEAD"], 120)
            logger.info("   shallow fetch + checkout %s", commit[:10])
        except Exception as e:
            logger.warning("   shallow fetch failed (%s) - falling back to full clone", str(e)[:200])
            _rmtree(workdir)
            subprocess.run(
                ["git", "clone", "-q", repo_url, str(workdir)],
                check=True, capture_output=True, text=True, timeout=CLONE_TIMEOUT, env=UTF8_ENV,
            )
            self._git(workdir, ["checkout", "-q", commit], 120)
            logger.info("   full clone + checkout %s", commit[:10])
        return workdir

    def process_job(self, job_json):
        job = {}
        scan_id = "unknown"
        workdir = None
        lock_key = None
        try:
            job = self.parse_job(job_json)
            scan_id = job["scan_id"] if job["scan_id"] is not None else f"job-{int(time.time())}"
            logger.info("Processing scan %s  repo=%s  commit=%s", scan_id, job["repo"], job["commit"])

            # duplicate guard: same scan_id twice (webhook retried) is ignored
            if job["scan_id"] is not None:
                lock_key = f"scan:lock:{scan_id}"
                if not self.redis_client.set(lock_key, "1", nx=True, ex=3600):
                    logger.warning("Duplicate scan %s ignored", scan_id)
                    self.emit(scan_id, "DUPLICATE_IGNORED", "SKIPPED")
                    lock_key = None  # the lock belongs to the first run
                    return None

            self.emit(scan_id, "JOB_RECEIVED")

            # STEP 0: source code
            if job["repo_url"] and job["commit"]:
                logger.info("STEP 0: fetching source")
                workdir = self.prepare_repo(job["repo_url"], job["commit"], scan_id)
                source = workdir
                self.emit(scan_id, "REPO_CLONED", message=str(job["commit"])[:10])
            elif job["source_file"]:
                source = Path(job["source_file"])
            else:
                raise ValueError("job has neither repo_url+commit nor source_file")

            logger.info("STEP 1: Semgrep")
            semgrep = self.run_semgrep(str(source))
            self.emit(scan_id, "SEMGREP_DONE", message=f"{len(semgrep.get('results', []))} findings")

            logger.info("STEP 2: Checkov")
            checkov = self.run_checkov(str(source))
            self.emit(scan_id, "CHECKOV_DONE", message=f"{len(checkov.get('results', []))} findings")

            logger.info("STEP 3: merge")
            findings = self.merge_results(semgrep, checkov, source)
            logger.info("   total findings: %d", len(findings))

            logger.info("STEP 4: AST reachability + priority")
            ast = self.run_ast_analysis(source, findings)
            actionable = ast["actionable_findings"]
            self.emit(
                scan_id, "AST_DONE",
                status="OK" if ast["ast_status"].startswith("OK") else "DEGRADED",
                message=f"{len(actionable)} actionable, {len(ast['filtered_noise'])} noise ({ast['ast_status']})",
            )

            logger.info("STEP 5: AI fixes for P0/P1")
            fixes = self.generate_fixes(source, actionable, scan_id)

            logger.info("STEP 6: results -> backend + Redis")
            posted = self.post_to_backend(job, scan_id, ast)
            self.emit(scan_id, "RESULTS_POSTED", status="OK" if posted else "SKIPPED")

            summary = {}
            for f in actionable:
                summary[f.get("priority", "P3")] = summary.get(f.get("priority", "P3"), 0) + 1

            final = {
                "job_id": scan_id,
                "repository_id": job["repo"],
                "commit_hash": job["commit"],
                "timestamp": datetime.now().isoformat(),
                "status": "COMPLETED",
                "ast_status": ast["ast_status"],
                "raw_findings": len(findings),
                "actionable_findings": len(actionable),
                "noise_removed": len(ast["filtered_noise"]),
                "priority_summary": summary,
                "fixes_generated": fixes,
                "backend_posted": posted,
                "results": ast,
            }
            self.push_result(final)
            self.emit(scan_id, "COMPLETED")
            logger.info("Job %s completed", scan_id)
            return final

        except Exception as e:
            logger.error("Job failed: %s", e, exc_info=True)
            if lock_key:
                try:
                    self.redis_client.delete(lock_key)  # allow a retry
                except Exception:
                    pass
            self.push_result({
                "job_id": scan_id,
                "repository_id": job.get("repo"),
                "commit_hash": job.get("commit"),
                "status": "FAILED",
                "error": str(e)[:500],
                "timestamp": datetime.now().isoformat(),
            })
            self.emit(scan_id, "FAILED", "ERROR", str(e)[:200])
            return None
        finally:
            if workdir is not None:
                _rmtree(workdir)  # clone is deleted after every scan

    # ---------------------------------------------------------- scanners
    def run_semgrep(self, path):
        try:
            result = subprocess.run(
                ["semgrep", "--config", "auto", "--json", path],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=SCAN_TIMEOUT, env=UTF8_ENV,
            )
            if result.returncode in (0, 1) and result.stdout:
                return json.loads(result.stdout)
            logger.warning("Semgrep error (exit %s): %s", result.returncode, result.stderr[-300:])
        except FileNotFoundError:
            logger.warning("Semgrep not installed")
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep timed out after %ss", SCAN_TIMEOUT)
        except Exception as e:
            logger.error("Semgrep failed: %s", e)
        return {"results": []}

    def run_checkov(self, path):
        try:
            flag = "-d" if Path(path).is_dir() else "-f"
            result = subprocess.run(
                # python -m: works even when the checkov exe is not on PATH (Windows)
                # --skip-download: no Prisma Cloud call (api0.prismacloud.io timeouts)
                [sys.executable, "-m", "checkov.main", flag, path, "-o", "json", "--skip-download"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=SCAN_TIMEOUT, env=UTF8_ENV,
            )
            if result.returncode in (0, 1) and result.stdout:
                data = json.loads(result.stdout)
                entries = data if isinstance(data, list) else [data]
                failed = []
                for entry in entries:
                    failed.extend(entry.get("results", {}).get("failed_checks", []))
                return {"results": failed}
            logger.warning("Checkov error (exit %s): %s", result.returncode, result.stderr[-300:])
        except subprocess.TimeoutExpired:
            logger.warning("Checkov timed out after %ss", SCAN_TIMEOUT)
        except Exception as e:
            logger.error("Checkov failed: %s", e)
        return {"results": []}

    @staticmethod
    def _relative(path, root):
        if not path:
            return path
        try:
            return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
        except (ValueError, OSError):
            return str(path).replace("\\", "/")

    def merge_results(self, semgrep, checkov, root):
        findings = []
        for f in semgrep.get("results", []):
            findings.append({
                "rule_id": f.get("check_id", "unknown"),
                "file": self._relative(f.get("path"), root),
                "line": f.get("start", {}).get("line"),
                "severity": f.get("extra", {}).get("severity", "INFO"),
                "message": f.get("extra", {}).get("message", ""),
                "source": "semgrep",
            })
        for f in checkov.get("results", []):
            line_range = f.get("file_line_range") or [None]
            findings.append({
                "rule_id": f.get("check_id", "unknown"),
                "file": self._relative(f.get("file_abs_path") or f.get("file_path"), root),
                "line": line_range[0],
                "severity": f.get("severity") or "WARNING",
                "message": f.get("check_name", ""),
                "source": "checkov",
            })
        return findings

    # ------------------------------------------------------- AST service
    @staticmethod
    def _ast_result(status, actionable, noise, total, error=None):
        out = {
            "ast_status": status,
            "total_findings": total,
            "actionable_findings": actionable,
            "filtered_noise": noise,
            "noise_reduction_percent": round(len(noise) / max(total, 1) * 100, 1),
        }
        if error:
            out["ast_error"] = error[:300]
        return out

    def _ast_fallback(self, findings, reason):
        """AST service unavailable: keep everything, priority from severity only."""
        out = []
        for f in findings:
            g = dict(f)
            g["reachability"] = "NOT_ANALYZED"
            g["priority"] = fallback_priority(f.get("severity"))
            g["priority_label"] = PRIORITY_LABELS[g["priority"]]
            out.append(g)
        return self._ast_result("FALLBACK_SEVERITY_ONLY", out, [], len(findings), reason)

    def run_ast_analysis(self, root, findings):
        """Contract (plan doc, Week 8):
             POST /analyze {repo_path, findings[]}  -> {tagged_findings[]}
             POST /score   {tagged_findings[]}      -> priority tiers
        """
        if not findings:
            return self._ast_result("OK", [], [], 0)
        if not AST_SERVICE_URL:
            return self._ast_fallback(findings, "AUTOFORGE_AST_SERVICE_URL not set")

        try:
            r = requests.post(f"{AST_SERVICE_URL}/analyze",
                              json={"repo_path": str(root), "findings": findings}, timeout=120)
            r.raise_for_status()
            tagged = r.json().get("tagged_findings")
            if tagged is None:
                raise ValueError("no tagged_findings in /analyze response")
        except Exception as e:
            logger.warning("AST /analyze unavailable (%s) - severity-only priority", e)
            return self._ast_fallback(findings, str(e))

        status = "OK"
        try:
            r = requests.post(f"{AST_SERVICE_URL}/score", json={"tagged_findings": tagged}, timeout=60)
            r.raise_for_status()
            body = r.json()
            scored = body if isinstance(body, list) else (
                body.get("scored_findings") or body.get("tagged_findings") or body.get("findings"))
            if not scored or not all("priority" in f for f in scored):
                raise ValueError("unexpected /score response shape")
        except Exception as e:
            logger.warning("AST /score unusable (%s) - scoring locally", e)
            scored = [local_score(f) for f in tagged]
            status = "OK_LOCAL_SCORING"

        for f in scored:
            f.setdefault("priority_label", PRIORITY_LABELS.get(f.get("priority"), "Low"))
        noise = [f for f in scored if f.get("reachability") == "UNREACHABLE_NOISE"]
        actionable = [f for f in scored if f.get("reachability") != "UNREACHABLE_NOISE"]
        return self._ast_result(status, actionable, noise, len(findings))

    # --------------------------------------------------------- AI fixes
    @staticmethod
    def _language(file):
        return LANGUAGES.get(Path(file or "").suffix.lower(), "unknown")

    @staticmethod
    def _snippet(root, rel, line, radius=15):
        if not rel:
            return None
        base = Path(root).resolve()
        p = (base / rel).resolve()
        if base not in p.parents or not p.is_file():  # no path traversal out of the clone
            return None
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        n = int(line or 1)
        return "\n".join(lines[max(0, n - 1 - radius): min(len(lines), n + radius)])[:4000]

    def generate_fixes(self, root, findings, scan_id):
        """Only P0 (Critical) / P1 (High), max AUTOFORGE_MAX_FIXES per scan."""
        if not AI_FIX_ENABLED:
            return 0
        candidates = sorted(
            (f for f in findings if f.get("priority") in ("P0", "P1")),
            key=lambda f: f["priority"],
        )[:MAX_FIXES_PER_SCAN]

        done = 0
        for f in candidates:
            code = self._snippet(root, f.get("file"), f.get("line"))
            if not code:
                continue
            try:
                r = requests.post(
                    f"{AI_FIX_URL}/api/fix",
                    json={
                        "code": code,
                        "language": self._language(f.get("file")),
                        "vulnerability": f"{f.get('rule_id')}: {f.get('message')}",
                    },
                    timeout=90,
                )
                r.raise_for_status()
                body = r.json()
                f["ai_fix"] = {"success": bool(body.get("success")), "result": body.get("result")}
                if body.get("success"):
                    done += 1
                    self.emit(scan_id, "FIX_GENERATED", message=f"{f.get('file')}:{f.get('line')}")
            except requests.ConnectionError:
                logger.warning("AI fix service not reachable - skipping fix generation")
                f["ai_fix"] = {"success": False, "error": "ai-fix-service unreachable"}
                break
            except Exception as e:  # Gemini failure/timeouts must not fail the scan
                logger.warning("AI fix failed for %s: %s", f.get("file"), e)
                f["ai_fix"] = {"success": False, "error": str(e)[:300]}
        return done

    # ----------------------------------------------------------- backend
    def post_to_backend(self, job, scan_id, ast):
        """POST /api/internal/scans/{id}/results (current DTO: repoFullName, commitSha, semgrep[], checkov[]).
        Extra fields (reachability/priority/ai_fix/tagged_findings) are ignored by the backend until
        the Week 9 payload is agreed. Needs the numeric backend scan id; test jobs with UUIDs are skipped.
        """
        if not str(scan_id).isdigit():
            logger.info("scan_id %s is not a backend scan id - skipping backend POST", scan_id)
            return False

        def item(f):
            return {
                "check_id": f.get("rule_id"),
                "path": f.get("file"),
                "start": {"line": f.get("line") or 0},
                "extra": {"severity": f.get("severity"), "message": f.get("message")},
                "source": f.get("source"),
                "reachability": f.get("reachability"),
                "priority": f.get("priority"),
                "ai_fix": f.get("ai_fix"),
            }

        actionable = ast["actionable_findings"]
        payload = {
            "repoFullName": job["repo"],
            "commitSha": job["commit"],
            "semgrep": [item(f) for f in actionable if f.get("source") == "semgrep"],
            "checkov": [item(f) for f in actionable if f.get("source") == "checkov"],
            "tagged_findings": [item(f) for f in actionable + ast["filtered_noise"]],
        }
        headers = {"X-Internal-Secret": INTERNAL_SECRET} if INTERNAL_SECRET else {}
        try:
            r = requests.post(f"{BACKEND_URL}/api/internal/scans/{scan_id}/results",
                              json=payload, headers=headers, timeout=60)
            r.raise_for_status()
            return True
        except Exception as e:
            logger.warning("Backend POST failed (%s) - result is still in Redis", e)
            return False

    # ---------------------------------------------------------- consumer
    def start_consuming(self):
        logger.info("Worker started - polling %s (Ctrl+C to stop)", QUEUE_NAME)
        while True:
            try:
                # lpop + sleep, not blpop: blpop gives "Timeout reading from socket" on Docker/Windows
                job_json = self.redis_client.lpop(QUEUE_NAME)
                if job_json:
                    self.process_job(job_json)
                else:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Worker stopped")
                break
            except redis.exceptions.RedisError as e:
                logger.error("Redis error: %s - reconnecting in 5s", e)
                time.sleep(5)
                self.connect()
            except Exception as e:
                logger.error("Consumer error: %s", e, exc_info=True)
                time.sleep(5)


def main():
    parser = argparse.ArgumentParser(description="AutoForge scan worker")
    parser.add_argument("--redis-host", default=REDIS_HOST)
    parser.add_argument("--redis-port", type=int, default=REDIS_PORT)
    args = parser.parse_args()

    logger.info("AutoForge scan worker")
    logger.info("  queue=%s results=%s events=%s", QUEUE_NAME, RESULTS_QUEUE, EVENTS_CHANNEL)
    logger.info("  AST=%s  backend=%s  ai-fix=%s (enabled=%s)",
                AST_SERVICE_URL or "disabled", BACKEND_URL, AI_FIX_URL, AI_FIX_ENABLED)

    worker = ScanWorker(redis_host=args.redis_host, redis_port=args.redis_port)
    if not worker.connected:
        sys.exit("Cannot reach Redis - start it first (docker start redis)")
    worker.start_consuming()


if __name__ == "__main__":
    main()