import json
import logging
import subprocess
import sys
import argparse
from pathlib import Path
from datetime import datetime
import redis
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

AST_ANALYZER_PATH = Path(__file__).parent.parent.parent / "3_ast_analyzer"

QUEUE_NAME = "scan_jobs"
RESULTS_QUEUE = "scan_results"


class ScanWorker:
    def __init__(self, redis_host="localhost", redis_port=6379):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_client = None
        self.connect()

    def connect(self):
        try:
            # Explicitly setting protocol=2 prevents the 'HELLO' command error on older Redis servers
            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                decode_responses=True,
                socket_connect_timeout=5,
                protocol=2
            )
            self.redis_client.ping()
            logger.info(f"✓ Connected to Redis at {self.redis_host}:{self.redis_port}")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to connect to Redis: {e}")
            return False

    def process_job(self, job_data):
        try:
            logger.info(f"📥 Processing job: {job_data}")

            job = json.loads(job_data)
            repo_id = job.get("repository_id")
            commit_hash = job.get("commit_hash")
            source_file = job.get("source_file")

            logger.info(f"   Repository: {repo_id}")
            logger.info(f"   Commit: {commit_hash}")
            logger.info(f"   Source: {source_file}")

            logger.info("🔍 STEP 1: Running Semgrep scanner...")
            semgrep_results = self.run_semgrep(source_file)
            logger.info(f"   Found: {len(semgrep_results.get('results', []))} issues")

            logger.info("🔍 STEP 2: Running Checkov scanner...")
            checkov_results = self.run_checkov(source_file)
            logger.info(f"   Found: {len(checkov_results.get('results', []))} issues")

            logger.info("📊 STEP 3: Merging scanner results...")
            merged_results = self.merge_results(semgrep_results, checkov_results)
            logger.info(f"   Total: {len(merged_results.get('results', []))} findings")

            logger.info("🌳 STEP 4: Running AST analysis...")
            ast_results = self.run_ast_analysis(source_file, merged_results)
            actionable = ast_results.get("actionable_findings", [])
            logger.info(f"   Actionable: {len(actionable)} findings")
            logger.info(f"   Noise reduction: {ast_results.get('noise_reduction_percent')}%")

            logger.info("✅ STEP 5: Preparing final results...")
            final_results = {
                "job_id": job.get("job_id"),
                "repository_id": repo_id,
                "commit_hash": commit_hash,
                "timestamp": datetime.now().isoformat(),
                "status": "COMPLETED",
                "raw_findings": len(merged_results.get("results", [])),
                "actionable_findings": len(actionable),
                "noise_removed": len(merged_results.get("results", [])) - len(actionable),
                "results": ast_results
            }

            logger.info("📤 STEP 6: Pushing results to backend queue...")
            self.push_result(final_results)

            logger.info("✅ Job completed successfully!")
            return final_results

        except Exception as e:
            logger.error(f"✗ Job processing failed: {e}", exc_info=True)
            error_result = {
                "job_id": job_data.get("job_id") if isinstance(job_data, dict) else "unknown",
                "status": "FAILED",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
            self.push_result(error_result)
            return None

    def run_semgrep(self, source_file):
        try:
            logger.debug(f"   Running: semgrep --json {source_file}")

            result = subprocess.run(
                ["semgrep", "--json", source_file],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30
            )

            if result.returncode in (0, 1):
                return json.loads(result.stdout)
            else:
                logger.warning(f"Semgrep error: {result.stderr}")
                return {"results": []}

        except FileNotFoundError:
            logger.warning("Semgrep not installed, using sample data")
            return {"results": []}
        except Exception as e:
            logger.error(f"Semgrep execution failed: {e}")
            return {"results": []}

    def run_checkov(self, source_file):
        try:
            logger.debug(f"   Running: checkov -f {source_file} --quiet")

            result = subprocess.run(
                ["checkov", "-f", source_file, "--quiet"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode in (0, 1):
                return json.loads(result.stdout) if result.stdout else {"results": []}
            else:
                logger.warning(f"Checkov error: {result.stderr}")
                return {"results": []}

        except FileNotFoundError:
            logger.warning("Checkov not installed, using sample data")
            return {"results": []}
        except Exception as e:
            logger.error(f"Checkov execution failed: {e}")
            return {"results": []}

    def merge_results(self, semgrep_results, checkov_results):
        all_results = []

        for finding in semgrep_results.get("results", []):
            all_results.append({
                "rule_id": finding.get("check_id", "unknown"),
                "file": finding.get("path"),
                "line": finding.get("start", {}).get("line"),
                "severity": finding.get("extra", {}).get("severity", "INFO"),
                "message": finding.get("extra", {}).get("message", ""),
                "function": finding.get("extra", {}).get("metavars", {}).get("function", "unknown"),
                "source": "semgrep"
            })

        for finding in checkov_results.get("results", []):
            all_results.append({
                "rule_id": finding.get("check_id", "unknown"),
                "file": finding.get("file_path"),
                "line": finding.get("file_line_range", [0])[0],
                "severity": finding.get("check_result", {}).get("result", "INFO"),
                "message": finding.get("check_name", ""),
                "function": "unknown",
                "source": "checkov"
            })

        return {"results": all_results}

    def run_ast_analysis(self, source_file, scan_results):
        try:
            logger.debug(f"   Calling AST analyzer for: {source_file}")

            temp_scan_file = Path(f"scan_input_{int(time.time())}.json").resolve()
            with open(temp_scan_file, "w") as f:
                json.dump(scan_results, f)

            ast_analyzer_str = AST_ANALYZER_PATH.resolve().as_posix()
            source_file_str = Path(source_file).resolve().as_posix()
            temp_scan_str = temp_scan_file.as_posix()

            python_code = f"""
import sys
sys.path.insert(0, '{ast_analyzer_str}')
from week2_prototype.noise_filter import extract_functions
from week3_reachability.ast_engine import ASTReachabilityAnalyzer
from week5_scoring.risk_scorer import score_finding
import json

with open('{temp_scan_str}', 'r') as f:
    scan_results = json.load(f)

findings = scan_results.get('results', [])

call_graph = extract_functions('{source_file_str}')
reachability_analyzer = ASTReachabilityAnalyzer(entry_points=['main', 'handle_login', 'get_user_profile'])
reachable = reachability_analyzer.find_reachable(call_graph)

filtered = []
for f in findings:
    func = f.get('function', 'unknown')
    if func in reachable:
        f['reachability'] = 'REACHABLE_CODE'
        priority = score_finding(f)
        f['priority'] = priority
        filtered.append(f)

result = {{
    'total_findings': len(findings),
    'actionable_findings': filtered,
    'reachable_count': len(reachable),
    'noise_reduction_percent': round((len(findings) - len(filtered)) / max(len(findings), 1) * 100, 1)
}}
print(json.dumps(result))
"""

            result = subprocess.run(
                ["python", "-c", python_code],
                capture_output=True,
                text=True,
                timeout=60
            )

            # Cleanup temp scan file
            if temp_scan_file.exists():
                temp_scan_file.unlink()

            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                logger.error(f"AST analysis error: {result.stderr}")
                return {
                    "actionable_findings": [],
                    "noise_reduction_percent": 0,
                    "error": result.stderr
                }

        except Exception as e:
            logger.error(f"AST analysis failed: {e}")
            return {
                "actionable_findings": [],
                "noise_reduction_percent": 0,
                "error": str(e)
            }

    def push_result(self, result):
        try:
            self.redis_client.rpush(RESULTS_QUEUE, json.dumps(result))
            logger.info(f"✓ Result pushed to {RESULTS_QUEUE}")
        except Exception as e:
            logger.error(f"✗ Failed to push result: {e}")

    def start_consuming(self):
        logger.info(f"🚀 Worker started - listening on {QUEUE_NAME}...")
        logger.info("Waiting for scan jobs... (Press Ctrl+C to stop)")

        while True:
            try:
                job_data = self.redis_client.blpop(QUEUE_NAME, timeout=5)

                if job_data:
                    _, job_json = job_data
                    logger.info(f"\n📥 Got job from queue")
                    self.process_job(job_json)

                else:
                    pass

            except KeyboardInterrupt:
                logger.info("\n🛑 Worker stopped")
                break
            except Exception as e:
                logger.error(f"Consumer error: {e}", exc_info=True)
                time.sleep(5)


def main():
    parser = argparse.ArgumentParser(description="AutoForge scan worker")
    parser.add_argument("--redis-host", default="localhost", help="Redis host")
    parser.add_argument("--redis-port", type=int, default=6379, help="Redis port")
    parser.add_argument("--max-workers", type=int, default=4, help="Max concurrent workers")

    args = parser.parse_args()

    logger.info("=" * 80)
    logger.info("🚀 AutoForge Background Scan Worker")
    logger.info("=" * 80)

    worker = ScanWorker(redis_host=args.redis_host, redis_port=args.redis_port)

    logger.info("\n📋 Validating environment...")
    if AST_ANALYZER_PATH.exists():
        logger.info(f"   ✓ AST Analyzer path: {AST_ANALYZER_PATH}")
    else:
        logger.warning(f"   ✗ AST Analyzer not found: {AST_ANALYZER_PATH}")

    worker.start_consuming()


if __name__ == "__main__":
    main()