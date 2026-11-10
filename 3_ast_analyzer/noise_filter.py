"""CLI for conservative, project-wide AST reachability annotations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

ANALYZER_ROOT = Path(__file__).resolve().parent
if str(ANALYZER_ROOT) not in sys.path:
    sys.path.insert(0, str(ANALYZER_ROOT))

from src.analysis.reachability import ReachabilityAnalyzer


class ASTNoiseFilter:
    """Annotate real scanner findings without dropping unverified findings."""

    def __init__(self, main_entry_points: Sequence[str]) -> None:
        self.analyzer = ReachabilityAnalyzer(entry_points=main_entry_points)

    def process_scan_file(
        self,
        json_file_path: str | Path,
        source_root: str | Path,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        payload = json.loads(Path(json_file_path).read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping):
            raise ValueError("scan payload must be a JSON object")
        findings = payload.get("results")
        if not isinstance(findings, list):
            raise ValueError("scan payload 'results' must be a JSON array")
        if any(not isinstance(finding, Mapping) for finding in findings):
            raise ValueError("every scanner result must be a JSON object")

        normalized_findings: list[dict[str, Any]] = []
        for finding in findings:
            normalized = dict(finding)
            start = normalized.get("start")
            if "line" not in normalized and isinstance(start, Mapping):
                normalized["line"] = start.get("line")
            if "rule_id" not in normalized and "check_id" in normalized:
                normalized["rule_id"] = normalized["check_id"]
            extra = normalized.get("extra")
            if isinstance(extra, Mapping):
                normalized.setdefault("message", extra.get("message"))
                normalized.setdefault("severity", extra.get("severity"))
            normalized_findings.append(normalized)

        result = self.analyzer.analyze_project(source_root, normalized_findings)
        reachable: list[dict[str, Any]] = []
        review: list[dict[str, Any]] = []
        for finding in result["tagged_findings"]:
            finding["action_required"] = True
            reachability = finding["reachability"]
            if reachability == "REACHABLE_CODE":
                finding["status"] = "REACHABLE_STATIC"
                reachable.append(finding)
            else:
                finding["status"] = (
                    "NOT_REACHED_STATIC"
                    if reachability == "UNREACHABLE_NOISE"
                    else "UNVERIFIED_REACHABILITY"
                )
                review.append(finding)
        return reachable, review


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Annotate actual scanner findings with project-wide AST reachability."
    )
    parser.add_argument(
        "--scan",
        type=Path,
        required=True,
        help="path to actual scanner results JSON",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="root directory containing the scanned source files",
    )
    parser.add_argument(
        "--entry-point",
        action="append",
        required=True,
        help="Python entry-point function name; repeat for multiple names",
    )
    args = parser.parse_args()

    reachable, review = ASTNoiseFilter(args.entry_point).process_scan_file(
        args.scan, args.source_root
    )
    print(
        f"Analysis complete: {len(reachable)} statically reachable findings, "
        f"{len(review)} findings kept for review."
    )
    for finding in reachable + review:
        location = finding.get("file") or finding.get("path") or finding.get("file_path")
        line = finding.get("line") or finding.get("line_number") or "?"
        print(
            f"{finding['status']}: {finding.get('rule_id', 'unknown rule')} "
            f"({location or 'unknown file'}:{line})"
        )
        evidence = finding.get("reachability_evidence")
        if isinstance(evidence, Mapping):
            print(f"  Review/evidence: {evidence.get('reason', 'No evidence available.')}")


if __name__ == "__main__":
    main()
