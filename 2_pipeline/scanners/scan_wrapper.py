import argparse
import json
import os
import subprocess
import sys


def run_semgrep(repo_path):
    output_file = os.path.join(repo_path, "_semgrep_temp.json")
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "-o", output_file, repo_path],
            capture_output=True, text=True,
            encoding="utf-8", errors="ignore", shell=True, env=env
        )
        if result.returncode != 0:
            print("Semgrep stderr:", result.stderr)
            print("Semgrep stdout:", result.stdout)
            return []
        if not os.path.exists(output_file):
            return []
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        try:
            os.remove(output_file)
        except OSError:
            pass
        return data.get("results", [])
    except Exception as e:
        print(f"Semgrep failed: {e}")
        return []


def run_checkov(repo_path):
    try:
        result = subprocess.run(
            ["checkov", "-d", repo_path, "-o", "json"],
            capture_output=True, text=True,
            encoding="utf-8", errors="ignore", shell=True
        )
        if not result.stdout or not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        if isinstance(data, list):
            return data
        return [data]
    except Exception as e:
        print(f"Checkov failed: {e}")
        return []


def normalize_semgrep(results):
    normalized = []
    for r in results:
        check_id = r.get("check_id") or "SEMGREP-GENERIC"
        path = r.get("path") or "unknown"
        line = r.get("start", {}).get("line", 1) or 1
        msg = r.get("extra", {}).get("message") or check_id
        sev = (r.get("extra", {}).get("severity") or "MEDIUM").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "MEDIUM"
        normalized.append({
            "source": "semgrep",
            "rule_id": check_id,
            "check_id": check_id,
            "file": path,
            "path": path,
            "file_path": path,
            "line": line,
            "line_number": line,
            "severity": sev,
            "message": msg,
            "title": msg,
            "code_snippet": r.get("extra", {}).get("lines"),
            "is_reachable": True,
            "reachability_status": "REACHABLE",
            "priority": "P2",
            "extra": r.get("extra", {}),
        })
    return normalized


def normalize_checkov(results_list):
    normalized = []
    for entry in results_list:
        failed_checks = entry.get("results", {}).get("failed_checks", [])
        for c in failed_checks:
            check_id = c.get("check_id") or "CKV-GENERIC"
            path = c.get("file_path") or "unknown"
            line_range = c.get("file_line_range", [1])
            line = line_range[0] if line_range and line_range[0] is not None else 1
            msg = c.get("check_name") or check_id
            sev = (c.get("severity") or "MEDIUM").upper()
            if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                sev = "MEDIUM"
            normalized.append({
                "source": "checkov",
                "rule_id": check_id,
                "check_id": check_id,
                "file": path,
                "path": path,
                "file_path": path,
                "line": line,
                "line_number": line,
                "severity": sev,
                "message": msg,
                "title": msg,
                "code_snippet": None,
                "is_reachable": True,
                "reachability_status": "REACHABLE",
                "priority": "P2",
                "extra": {"severity": sev, "message": msg, "check_name": msg},
            })
    return normalized


def main():
    parser = argparse.ArgumentParser(description="AutoForge Scanner Wrapper")
    parser.add_argument("repo_path", nargs="?", default=None, help="Positional repository path")
    parser.add_argument("--source-dir", "--source_dir", dest="source_dir", default=None, help="Source directory")
    parser.add_argument("--output", "-o", dest="output", default=None, help="Output JSON path")
    args = parser.parse_args()

    repo_path = args.source_dir or args.repo_path
    if not repo_path:
        print("Usage: python scan_wrapper.py [--source-dir <repo_path>] [--output <output.json>] [repo_path]")
        sys.exit(1)

    print(f"Scanning target: {repo_path}")
    print("Running Semgrep...")
    semgrep_raw = run_semgrep(repo_path)
    semgrep_findings = normalize_semgrep(semgrep_raw)

    print("Running Checkov...")
    checkov_raw = run_checkov(repo_path)
    checkov_findings = normalize_checkov(checkov_raw)

    all_findings = semgrep_findings + checkov_findings

    result_data = {
        "findings": all_findings,
        "scored_findings": all_findings,
        "semgrep": semgrep_findings,
        "checkov": checkov_findings,
    }

    output_path = args.output
    if output_path:
        output_dir = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(output_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result_data, f, indent=2)
        print(f"Done. {len(all_findings)} findings written to {output_path}")

    # Also write combined_scan_results.json in repo directory for legacy tools
    combined_path = os.path.join(repo_path, "combined_scan_results.json")
    try:
        with open(combined_path, "w", encoding="utf-8") as f:
            json.dump(all_findings, f, indent=2)
    except Exception:
        pass


if __name__ == "__main__":
    main()
