from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.analysis.reachability import ReachabilityAnalyzer
from src.analysis.taint_engine import TaintEngine

_CASE_NAME = re.compile(r"BenchmarkTest\d+\Z")


def _column(fieldnames: Iterable[str] | None, expected: str) -> str:
    for fieldname in fieldnames or ():
        normalized = " ".join(fieldname.strip().lstrip("#").split()).lower()
        if normalized == expected:
            return fieldname
    raise ValueError(f"OWASP expected-results CSV is missing the {expected!r} column")


def _metrics(predictions: set[str], vulnerable_cases: set[str]) -> dict[str, Any]:
    true_positives = len(predictions & vulnerable_cases)
    false_positives = len(predictions - vulnerable_cases)
    false_negatives = len(vulnerable_cases - predictions)
    precision = (
        true_positives / len(predictions)
        if predictions else None
    )
    recall = (
        true_positives / len(vulnerable_cases)
        if vulnerable_cases else None
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "flagged_cases": len(predictions),
    }


def benchmark_owasp_python(benchmark_root: str | Path) -> dict[str, Any]:
    root = Path(benchmark_root).resolve()
    source_root = root / "testcode"
    expected_results = root / "expectedresults-0.1.csv"
    if not source_root.is_dir():
        raise NotADirectoryError(source_root)

    try:
        with expected_results.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            name_column = _column(reader.fieldnames, "test name")
            label_column = _column(reader.fieldnames, "real vulnerability")
            rows = list(reader)
    except OSError as error:
        raise ValueError(f"could not read OWASP expected results: {error}") from error
    if not rows:
        raise ValueError("OWASP expected-results CSV contains no test cases")

    vulnerable_cases: set[str] = set()
    findings: list[dict[str, Any]] = []
    seen_cases: set[str] = set()
    for row_number, row in enumerate(rows, start=2):
        case_name = (row.get(name_column) or "").strip()
        if not _CASE_NAME.fullmatch(case_name):
            raise ValueError(f"OWASP expected-results row {row_number} has invalid test name")
        if case_name in seen_cases:
            raise ValueError(f"OWASP expected-results contains duplicate case {case_name}")
        seen_cases.add(case_name)

        raw_label = (row.get(label_column) or "").strip().lower()
        if raw_label not in {"true", "false"}:
            raise ValueError(
                f"OWASP expected-results row {row_number} has invalid vulnerability label"
            )
        if raw_label == "true":
            vulnerable_cases.add(case_name)

        source_path = source_root / f"{case_name}.py"
        if not source_path.is_file():
            raise FileNotFoundError(f"OWASP source is missing for case {case_name}")
        source = source_path.read_text(encoding="utf-8")
        for finding in TaintEngine().analyze_cfg(source, file_path=str(source_path)):
            findings.append({
                "file": source_path.relative_to(source_root).as_posix(),
                "line": finding.line,
                "rule_id": finding.rule_id,
                "case_id": case_name,
            })

    reachability = ReachabilityAnalyzer().analyze_project(source_root, findings)
    raw_cases = {finding["case_id"] for finding in findings}
    filtered_cases = {
        finding["case_id"]
        for finding in reachability["tagged_findings"]
        if finding["reachability"] == "REACHABLE_CODE"
    }
    unreachable_findings = sum(
        finding["reachability"] == "UNREACHABLE_NOISE"
        for finding in reachability["tagged_findings"]
    )
    unverified_findings = sum(
        finding["reachability"] == "UNKNOWN"
        for finding in reachability["tagged_findings"]
    )
    baseline_metrics = _metrics(raw_cases, vulnerable_cases)
    filtered_metrics = _metrics(filtered_cases, vulnerable_cases)
    baseline_false_positives = baseline_metrics["false_positives"]
    false_positive_reduction = (
        (baseline_false_positives - filtered_metrics["false_positives"])
        / baseline_false_positives
        if baseline_false_positives else None
    )
    return {
        "dataset": "OWASP Benchmark for Python v0.1",
        "cases": len(rows),
        "positive_cases": len(vulnerable_cases),
        "negative_cases": len(rows) - len(vulnerable_cases),
        "raw_finding_count": len(findings),
        "unreachable_finding_count": unreachable_findings,
        "unverified_finding_count": unverified_findings,
        "removed_case_count": len(raw_cases - filtered_cases),
        "prediction_reduction": (
            len(raw_cases - filtered_cases) / len(raw_cases)
            if raw_cases else None
        ),
        "false_positive_reduction": false_positive_reduction,
        "baseline": baseline_metrics,
        "reachability_filtered": filtered_metrics,
        "missing_entry_points": reachability["missing_entry_points"],
    }


def main(argv: list[str] | None = None) -> int:
    default_root = Path(__file__).resolve().parents[1] / "data" / "owasp_benchmark"
    parser = argparse.ArgumentParser(
        description="Measure AST taint and reachability results against OWASP Benchmark Python v0.1 labels."
    )
    parser.add_argument("--benchmark-dir", type=Path, default=default_root)
    parser.add_argument("--output", type=Path, default=None)
    arguments = parser.parse_args(argv)
    try:
        report = benchmark_owasp_python(arguments.benchmark_dir)
        output = json.dumps(report, indent=2, sort_keys=True)
        if arguments.output is not None:
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_text(output + "\n", encoding="utf-8")
        print(output)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
