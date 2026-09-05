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


def main():
    if len(sys.argv) < 2:
        print("Usage: python scan_wrapper.py <repo_path>")
        sys.exit(1)

    repo_path = sys.argv[1]

    print("Running Semgrep...")
    semgrep_raw = run_semgrep(repo_path)
    semgrep_findings = normalize_semgrep(semgrep_raw)

    print("Running Checkov...")
    checkov_raw = run_checkov(repo_path)
    checkov_findings = normalize_checkov(checkov_raw)

    all_findings = semgrep_findings + checkov_findings

    output_path = os.path.join(repo_path, "combined_scan_results.json")
    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2)

    print(f"Done. {len(all_findings)} findings written to {output_path}")


if __name__ == "__main__":
    main()