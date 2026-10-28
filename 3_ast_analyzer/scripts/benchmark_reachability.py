from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


FindingKey = tuple[str, int, str]


def _read_findings(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("findings", payload.get("tagged_findings"))
    if not isinstance(payload, list):
        raise ValueError(f"{path} must contain a findings array")
    if not all(isinstance(item, dict) for item in payload):
        raise ValueError(f"{path} contains a finding that is not an object")
    return payload


def _finding_keys(findings: list[dict[str, Any]], source: str) -> set[FindingKey]:
    keys: set[FindingKey] = set()
    for index, finding in enumerate(findings):
        file_path = finding.get("file")
        line = finding.get("line")
        rule_id = finding.get("rule_id")
        if (
            not isinstance(file_path, str)
            or isinstance(line, bool)
            or not isinstance(line, int)
            or not isinstance(rule_id, str)
        ):
            raise ValueError(
                f"{source} finding {index} needs string file/rule_id and integer line"
            )
        normalized_path = file_path.replace("\\", "/").removeprefix("./")
        keys.add((normalized_path, line, rule_id))
    return keys


def _quality_metrics(predictions: set[FindingKey], truth: set[FindingKey]) -> dict[str, Any]:
    true_positives = len(predictions & truth)
    false_positives = len(predictions - truth)
    false_negatives = len(truth - predictions)
    precision = (
        true_positives / (true_positives + false_positives)
        if true_positives + false_positives
        else None
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if true_positives + false_negatives
        else None
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
        "prediction_count": len(predictions),
        "ground_truth_count": len(truth),
    }


def benchmark(
    baseline_path: Path,
    filtered_path: Path,
    ground_truth_path: Path,
) -> dict[str, Any]:
    baseline = _finding_keys(_read_findings(baseline_path), str(baseline_path))
    filtered = _finding_keys(_read_findings(filtered_path), str(filtered_path))
    truth = _finding_keys(_read_findings(ground_truth_path), str(ground_truth_path))
    baseline_metrics = _quality_metrics(baseline, truth)
    filtered_metrics = _quality_metrics(filtered, truth)
    baseline_false_positives = baseline_metrics["false_positives"]
    false_positive_reduction = (
        (baseline_false_positives - filtered_metrics["false_positives"])
        / baseline_false_positives
        if baseline_false_positives
        else None
    )
    return {
        "matching": "normalized file path + line + rule_id",
        "baseline": baseline_metrics,
        "ast_filtered": filtered_metrics,
        "false_positive_reduction": false_positive_reduction,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare scanner and AST-filtered findings against labeled ground truth."
    )
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--ast-filtered", required=True, type=Path)
    parser.add_argument("--ground-truth", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        report = benchmark(
            arguments.baseline,
            arguments.ast_filtered,
            arguments.ground_truth,
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
