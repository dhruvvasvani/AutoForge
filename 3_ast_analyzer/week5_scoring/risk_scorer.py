import argparse
import json

PRIORITY_MATRIX = {
    ("REACHABLE_CODE", "error"): "P0",
    ("REACHABLE_CODE", "warning"): "P1",
    ("UNREACHABLE_NOISE", "error"): "P2",
    ("UNREACHABLE_NOISE", "warning"): "P3",
}

PRIORITY_LABELS = {
    "P0": "Critical",
    "P1": "High",
    "P2": "Medium",
    "P3": "Low",
}


def score_finding(finding):
    reachability = finding.get("reachability", "UNREACHABLE_NOISE")
    severity = finding.get("severity", "warning").lower()
    priority = PRIORITY_MATRIX.get((reachability, severity), "P3")
    return priority


def score_findings(findings):
    scored = []
    for f in findings:
        priority = score_finding(f)
        f_copy = dict(f)
        f_copy["priority"] = priority
        f_copy["priority_label"] = PRIORITY_LABELS[priority]
        scored.append(f_copy)
    scored.sort(key=lambda x: x["priority"])
    return scored


def main():
    parser = argparse.ArgumentParser(description="Risk scoring for filtered SAST findings")
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", default="scored_results.json")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    all_findings = data.get("clean_findings", []) + data.get("filtered_noise", [])
    scored = score_findings(all_findings)

    output = {"scored_findings": scored}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Wrote {args.out}")
    for item in scored:
        print(f"[{item['priority']} - {item['priority_label']}] {item.get('rule', item.get('id'))}")


if __name__ == "__main__":
    main()

