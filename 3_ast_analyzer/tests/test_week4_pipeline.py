from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.engine.task_broker import ParallelASTBroker
from src.ml.dataset_generator import generate_ast_dataset
from src.ml.noise_filter import ASTNoiseFilter


def test_week4_synthetic_training_and_parallel_ast_filtering(tmp_path):
    dataset_path = tmp_path / "synthetic_ast_dataset.json"
    generated_path = generate_ast_dataset(num_samples=100, output_file=dataset_path)
    dataset = json.loads(Path(generated_path).read_text(encoding="utf-8"))
    assert len(dataset) == 100
    assert {row["is_real_vulnerability"] for row in dataset} == {0, 1}
    assert "synthetic_ast_node_" in dataset[0]["id"]

    noise_filter = ASTNoiseFilter()
    noise_filter.train(generated_path)
    assert noise_filter.is_trained

    broker = ParallelASTBroker(max_workers=2)
    processed = broker.run_batch(
        [
            ("dangerous.py", "value = request.getParameter('q')\ndb.execute(value)\n"),
            ("plain.py", "value = 1\n"),
        ]
    )
    assert len(processed) == 2
    assert processed[0]["status"] == "PROCESSED"
    assert processed[0]["language"] == "python"
    assert processed[0]["nodes_analyzed"] > 0
    assert processed[0]["user_input_tainted"] is True
    assert processed[0]["sanitizer_present"] is False
    assert processed[0]["sink_distance"] == 1
    assert processed[0]["cyclomatic_complexity"] == 1
    assert processed[1]["user_input_tainted"] is False
    sanitized = broker.process_file_ast(
        ("sanitized.py", "safe = html.escape(user_input)\n")
    )
    assert sanitized["sanitizer_present"] is True
    assert 0.0 <= noise_filter.predict_confidence(processed[0]) <= 1.0

    nested = broker.process_file_ast(
        ("nested.py", "if condition:\n    while condition:\n        value = 1\n")
    )
    assert nested["cyclomatic_complexity"] == 3
    assert nested["max_nesting_depth"] == 2

    positive = next(row for row in dataset if row["is_real_vulnerability"] == 1)
    negative = next(row for row in dataset if row["is_real_vulnerability"] == 0)
    originals = [dict(positive), dict(negative)]
    filtered = noise_filter.filter_findings(originals, threshold=0.5)
    assert len(filtered) == 1
    assert filtered[0]["is_real_vulnerability"] == 1
    assert filtered[0]["ml_confidence"] >= 0.5
    assert "ml_confidence" not in originals[0]


def test_week4_filter_fails_open_when_model_is_untrained():
    finding = {
        "cyclomatic_complexity": 3,
        "max_nesting_depth": 1,
        "sink_distance": 1,
        "user_input_tainted": True,
        "sanitizer_present": False,
    }
    result = ASTNoiseFilter().filter_findings([finding])
    assert result == [{**finding, "ml_confidence": 1.0}]


@pytest.mark.parametrize("invalid_threshold", [-0.1, 1.1, float("nan")])
def test_week4_filter_rejects_invalid_threshold(invalid_threshold):
    with pytest.raises(ValueError, match="threshold"):
        ASTNoiseFilter().filter_findings([], threshold=invalid_threshold)


def test_week4_broker_rejects_invalid_worker_count_and_source():
    with pytest.raises(ValueError, match="max_workers"):
        ParallelASTBroker(max_workers=0)
    with pytest.raises(ValueError, match="file_data"):
        ParallelASTBroker().process_file_ast(("invalid.py", None))


def test_week4_dataset_generation_rejects_empty_dataset(tmp_path):
    with pytest.raises(ValueError, match="num_samples"):
        generate_ast_dataset(0, tmp_path / "empty.json")
