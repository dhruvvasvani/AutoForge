import argparse
import subprocess
import json
import sys
import os


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
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        os.remove(output_file)
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
        normalized.append({
            "source": "semgrep",
            "rule_id": r.get("check_id"),
            "file": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "severity": r.get("extra", {}).get("severity"),
            "message": r.get("extra", {}).get("message"),
        })
    return normalized


def normalize_checkov(results_list):
    normalized = []
    for entry in results_list:
        failed_checks = entry.get("results", {}).get("failed_checks", [])
        for c in failed_checks:
            normalized.append({
                "source": "checkov",
                "rule_id": c.get("check_id"),
                "file": c.get("file_path"),
                "line": c.get("file_line_range", [None])[0],
                "severity": c.get("severity", "UNKNOWN"),
                "message": c.get("check_name"),
            })
    return normalized


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run Semgrep + Checkov and write combined findings JSON."
    )
    # Old style: python scan_wrapper.py <repo_path>
    parser.add_argument("repo_path", nargs="?", help="Repository path (positional)")
    # Backend style: --source-dir <dir> --output <file>
    parser.add_argument("--source-dir", dest="source_dir", help="Repository path")
    parser.add_argument("--output", dest="output", help="Result JSON file path")
    args = parser.parse_args()

    repo_path = args.source_dir or args.repo_path
    if not repo_path:
        parser.error("repo path required (positional or --source-dir)")
    if not os.path.isdir(repo_path):
        parser.error(f"repo path is not a directory: {repo_path}")
    return repo_path, args.output


def main():
    repo_path, output_arg = parse_args()

    print("Running Semgrep...")
    semgrep_raw = run_semgrep(repo_path)
    semgrep_findings = normalize_semgrep(semgrep_raw)

    print("Running Checkov...")
    checkov_raw = run_checkov(repo_path)
    checkov_findings = normalize_checkov(checkov_raw)

    all_findings = semgrep_findings + checkov_findings

    output_path = output_arg or os.path.join(repo_path, "combined_scan_results.json")
    out_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2)

    print(f"Done. {len(all_findings)} findings written to {output_path}")


if __name__ == "__main__":
    main()