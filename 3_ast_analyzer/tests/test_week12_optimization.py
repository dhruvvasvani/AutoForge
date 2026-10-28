from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.ir import symbol_table
from scripts.benchmark_reachability import benchmark
from scripts.promote_checkpoint import promote
from scripts.train_feedback_candidate import build_training_dataset
from src.ml import cpg_runtime
from src.multilingual.tree_sitter_engine import TreeSitterEngine
from scripts.benchmark_owasp_python import benchmark_owasp_python


def test_tree_sitter_incremental_edit_matches_full_parse(tmp_path):
    source_file = tmp_path / "module.js"
    engine = TreeSitterEngine()
    initial_source = "function run() {\n  return 1;\n}\n"
    updated_source = "const title = '✓';\nfunction run() {\n  return 42;\n}\n"

    initial = engine.parse_source(initial_source, "javascript", file_path=source_file)
    cached = engine.parse_source(initial_source, "javascript", file_path=source_file)
    assert cached.graph == initial.graph
    incremental = engine.parse_source(updated_source, "javascript", file_path=source_file)
    full = TreeSitterEngine().parse_source(updated_source, "javascript")

    assert incremental.graph == full.graph
    assert incremental.has_errors == full.has_errors
    assert incremental.error_count == full.error_count
    assert engine.cache_info() == {
        "entries": 1,
        "capacity": 128,
        "hits": 1,
        "incremental_parses": 1,
        "full_parses": 1,
    }


def test_tree_sitter_cache_evicts_oldest_entry(tmp_path):
    engine = TreeSitterEngine(cache_capacity=1)
    engine.parse_source("const a = 1;", "javascript", file_path=tmp_path / "a.js")
    engine.parse_source("const b = 2;", "javascript", file_path=tmp_path / "b.js")

    assert engine.cache_info()["entries"] == 1
    engine.parse_source("const a = 1;", "javascript", file_path=tmp_path / "a.js")
    assert engine.cache_info()["full_parses"] == 3


def test_symbol_table_reuses_cached_tree_and_invalidates_changed_source(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    source_file = tmp_path / "module.py"
    source_file.write_text("def run():\n    return 1\n", encoding="utf-8")
    real_parse = symbol_table.ast.parse
    parse_count = 0

    def counting_parse(*args, **kwargs):
        nonlocal parse_count
        parse_count += 1
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(symbol_table.ast, "parse", counting_parse)
    first = symbol_table.SymbolTable.from_project(tmp_path)
    second = symbol_table.SymbolTable.from_project(tmp_path)

    assert parse_count == 1
    assert second.module_trees["module"] is first.module_trees["module"]
    assert second.module_sources["module"] == "def run():\n    return 1\n"

    source_file.write_text("def run():\n    return 2\n", encoding="utf-8")
    updated = symbol_table.SymbolTable.from_project(tmp_path)
    assert parse_count == 2
    assert updated.module_trees["module"] is not first.module_trees["module"]


def test_reachability_benchmark_reports_quality_and_noise_reduction(tmp_path):
    baseline = tmp_path / "baseline.json"
    filtered = tmp_path / "filtered.json"
    truth = tmp_path / "truth.json"
    baseline.write_text(
        '{"findings":[{"file":"src\\\\a.py","line":4,"rule_id":"SQLI"},'
        '{"file":"src/noise.py","line":8,"rule_id":"XSS"}]}',
        encoding="utf-8",
    )
    filtered.write_text(
        '[{"file":"src/a.py","line":4,"rule_id":"SQLI"}]',
        encoding="utf-8",
    )
    truth.write_text(
        '[{"file":"src/a.py","line":4,"rule_id":"SQLI"}]',
        encoding="utf-8",
    )

    report = benchmark(baseline, filtered, truth)

    assert report["baseline"]["false_positives"] == 1
    assert report["ast_filtered"]["f1"] == 1.0
    assert report["false_positive_reduction"] == 1.0


def test_owasp_python_benchmark_reports_recall_loss_and_false_positive_reduction(
    tmp_path,
):
    benchmark_root = tmp_path / "owasp"
    source_root = benchmark_root / "testcode"
    source_root.mkdir(parents=True)
    (benchmark_root / "expectedresults-0.1.csv").write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
        "BenchmarkTest00003,sqli,true,89\n",
        encoding="utf-8",
    )
    (source_root / "BenchmarkTest00001.py").write_text(
        "@app.post('/one')\n"
        "def endpoint():\n"
        "    db.execute(input())\n",
        encoding="utf-8",
    )
    (source_root / "BenchmarkTest00002.py").write_text(
        "@app.post('/two')\n"
        "def endpoint():\n"
        "    db.execute(input())\n",
        encoding="utf-8",
    )
    (source_root / "BenchmarkTest00003.py").write_text(
        "def unused():\n"
        "    db.execute(input())\n",
        encoding="utf-8",
    )

    report = benchmark_owasp_python(benchmark_root)

    assert report["cases"] == 3
    assert report["positive_cases"] == 2
    assert report["baseline"]["true_positives"] == 2
    assert report["baseline"]["false_positives"] == 1
    assert report["reachability_filtered"]["true_positives"] == 1
    assert report["reachability_filtered"]["false_positives"] == 1
    assert report["reachability_filtered"]["false_negatives"] == 1
    assert report["removed_case_count"] == 1
    assert report["prediction_reduction"] == 1 / 3
    assert report["false_positive_reduction"] == 0.0


def test_feedback_dataset_uses_only_approved_syntax_valid_labels(tmp_path):
    feedback = tmp_path / "feedback.json"
    baseline = tmp_path / "baseline.json"
    output = tmp_path / "training.json"
    feedback.write_text(
        '[{"id":1,"reviewStatus":"APPROVED","label":"FALSE_POSITIVE",'
        '"sourceSnippet":"def safe():\\n    return 1\\n"},'
        '{"id":2,"reviewStatus":"APPROVED","label":"CONFIRMED_VULNERABILITY",'
        '"sourceSnippet":"def unsafe(value):\\n    eval(value)\\n"},'
        '{"id":3,"reviewStatus":"PENDING","label":"FALSE_POSITIVE",'
        '"sourceSnippet":"def pending():\\n    pass\\n"},'
        '{"id":4,"reviewStatus":"APPROVED","label":"FALSE_POSITIVE",'
        '"sourceSnippet":"def broken(:\\n"}]',
        encoding="utf-8",
    )
    baseline.write_text(
        '[{"code":"def safe_baseline():\\n    return 1\\n","label":0},'
        '{"code":"def vulnerable_baseline(value):\\n    eval(value)\\n","label":1}]',
        encoding="utf-8",
    )

    counts = build_training_dataset(feedback, baseline, output, min_feedback=2)
    rows = json.loads(output.read_text(encoding="utf-8"))

    assert counts == {
        "baseline_examples": 2,
        "approved_feedback_examples": 2,
        "skipped_invalid_examples": 1,
        "combined_examples": 4,
        "feedback_ids": [1, 2],
    }
    assert len(rows) == 4
    assert {row["label"] for row in rows} == {0, 1}


def test_checkpoint_promotion_replaces_active_file_atomically(tmp_path):
    candidate = tmp_path / "candidate.pt"
    active = tmp_path / "active.pt"
    candidate.write_bytes(b"new reviewed model")
    active.write_bytes(b"old model")

    promote(candidate, active)

    assert active.read_bytes() == b"new reviewed model"
    assert candidate.read_bytes() == b"new reviewed model"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["active.pt", "candidate.pt"]


def test_cpg_runtime_cache_key_changes_when_checkpoint_is_replaced(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    checkpoint = tmp_path / "model.pt"
    checkpoint.write_bytes(b"old")
    loaded_signatures = []

    def fake_load(path, model_name, device, modified_ns, size):
        loaded_signatures.append((modified_ns, size))
        return object(), object()

    monkeypatch.setenv("CPG_GNN_CHECKPOINT", str(checkpoint))
    monkeypatch.setattr(cpg_runtime, "_load_runtime", fake_load)
    monkeypatch.setattr(cpg_runtime, "predict_file_confidences", lambda *_: {})

    cpg_runtime.configured_cpg_predictions({})
    checkpoint.write_bytes(b"new checkpoint")
    cpg_runtime.configured_cpg_predictions({})

    assert len(loaded_signatures) == 2
    assert loaded_signatures[0] != loaded_signatures[1]
