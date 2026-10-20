from __future__ import annotations

import json
import logging
import math
import sys
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.ml.cpg_gnn import CPGGNN
from src.ml.cpg_builder import build_cpg
from src.monitoring.logger import JSONFormatter, get_security_logger, log_security_event
from src.monitoring.metrics_collector import MetricsCollector
from src.multilingual.tree_sitter_engine import TreeSitterEngine
from src.optimization.batch_processor import CPGBatchProcessor, collate_cpg_graphs


@pytest.mark.parametrize(
    ("language", "source", "root_type"),
    [
        ("javascript", "function run() { return 1; }", "program"),
        ("typescript", "const value: number = 1;", "program"),
        ("tsx", "const View = () => <main />;", "program"),
        ("go", "package main\nfunc main() {}", "source_file"),
        ("java", "class Main { void run() {} }", "program"),
    ],
)
def test_tree_sitter_engine_builds_structural_graphs(language, source, root_type):
    result = TreeSitterEngine().parse_source(source, language)

    assert result.language == language
    assert result.root_type == root_type
    assert result.graph.nodes
    assert result.graph.edges_of_type("ast")
    assert all(source < len(result.graph.nodes) and target < len(result.graph.nodes)
               for source, target, _ in result.graph.edges)


def test_tree_sitter_python_uses_existing_ast_cfg_and_dfg_builder():
    result = TreeSitterEngine().parse_source(
        "def run(value):\n    copy = value\n    return copy\n",
        "python",
    )

    assert result.graph.edges_of_type("ast")
    assert result.graph.edges_of_type("cfg")
    assert result.graph.edges_of_type("dfg")


def test_tree_sitter_engine_reports_syntax_errors_and_unsupported_languages():
    invalid = TreeSitterEngine().parse_source("function {", "javascript")
    assert invalid.has_errors
    assert invalid.error_count > 0

    with pytest.raises(ValueError, match="Unsupported language"):
        TreeSitterEngine().parse_source("code", "rust")


def test_tree_sitter_engine_parses_source_files_by_extension(tmp_path):
    source_file = tmp_path / "service.go"
    source_file.write_text("package service\n", encoding="utf-8")

    result = TreeSitterEngine().parse_file(source_file)

    assert result.language == "go"
    assert result.root_type == "source_file"


def test_prometheus_metrics_record_scans_findings_inference_and_memory():
    collector = MetricsCollector()
    with collector.track_scan():
        pass
    with collector.track_inference("cpg_gnn"):
        pass
    collector.record_findings(
        [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "HIGH"},
        ]
    )
    assert collector.update_memory_usage(12345) == 12345

    metrics = collector.render().decode()
    assert "ast_scan_duration_seconds_count 1.0" in metrics
    assert 'vulnerabilities_detected_total{severity="CRITICAL"} 1.0' in metrics
    assert 'vulnerabilities_detected_total{severity="HIGH"} 2.0' in metrics
    assert 'ml_inference_latency_seconds_count{model="cpg_gnn"} 1.0' in metrics
    assert "memory_usage_bytes 12345.0" in metrics


def test_metrics_reject_invalid_severities_and_counts():
    collector = MetricsCollector()
    with pytest.raises(ValueError, match="severity"):
        collector.record_findings([{"severity": "INFO"}])
    with pytest.raises(ValueError, match="non-negative"):
        collector.record_findings(-1)
    with pytest.raises(ValueError, match="model"):
        with collector.track_inference(" "):
            pass


def test_json_security_audit_logs_redact_secrets():
    logger = logging.getLogger("test.autoforge.security")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(self.format(record))

    handler = Capture()
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)

    log_security_event(
        "pull_request.scan",
        outcome="completed",
        logger=logger,
        repository="owner/repo",
        token="do-not-log",
        findings={"CRITICAL": 1},
    )

    record = json.loads(records[0])
    assert record["event"] == "pull_request.scan"
    assert record["outcome"] == "completed"
    assert record["repository"] == "owner/repo"
    assert record["token"] == "[REDACTED]"
    assert record["findings"] == {"CRITICAL": 1}
    assert "do-not-log" not in records[0]


def test_security_logger_reuses_single_json_handler():
    name = "test.autoforge.security.singleton"
    logger = logging.getLogger(name)
    logger.handlers.clear()

    assert get_security_logger(name) is get_security_logger(name)
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0].formatter, JSONFormatter)


def test_batch_processor_bounds_batches_preserves_order_and_records_benchmark():
    sources = [
        (f"module_{index}.py", f"value_{index} = {index}\n")
        for index in range(37)
    ]
    processor = CPGBatchProcessor(batch_size=5, max_workers=2)

    batches = list(processor.iter_batches(sources))

    assert [len(batch.graphs) for batch in batches] == [5] * 7 + [2]
    assert all(batch.workers_used <= 2 for batch in batches)
    assert all(batch.estimated_memory_bytes > 0 for batch in batches)
    assert all(batch.duration_seconds > 0 for batch in batches)
    assert all(math.isfinite(batch.graphs_per_second) for batch in batches)
    assert all(batch.graphs_per_second > 0 for batch in batches)
    assert sum(len(batch.graphs) for batch in batches) == len(sources)
    assert [graph.nodes[0].text for batch in batches for graph in batch.graphs] == [
        source.rstrip() for _, source in sources
    ]


def test_batch_processor_prunes_only_when_configured_and_reindexes_edges():
    source = "def analyze(value):\n    copy = value\n    return copy\n"
    full_graph = build_cpg(source)
    processor = CPGBatchProcessor(
        batch_size=1,
        max_workers=1,
        max_nodes_per_graph=3,
    )

    batch = next(processor.iter_batches([("module.py", source)]))
    graph = batch.graphs[0]

    assert len(full_graph.nodes) > len(graph.nodes) == 3
    assert batch.pruned_graphs == 1
    assert [node.node_id for node in graph.nodes] == [0, 1, 2]
    assert all(
        source_id < len(graph.nodes) and target_id < len(graph.nodes)
        for source_id, target_id, _ in graph.edges
    )


def test_batch_processor_validates_source_shape_and_worker_limits():
    with pytest.raises(ValueError, match="memory_limit_bytes"):
        CPGBatchProcessor(memory_limit_bytes=1)
    with pytest.raises(ValueError, match="source"):
        list(CPGBatchProcessor(max_workers=1).iter_batches([("module.py", 3)]))


def test_cpg_collation_batches_node_features_edges_and_labels():
    import torch

    graphs = [
        build_cpg("left = 1\n", label=0),
        build_cpg("right = left\n", label=1),
    ]
    node_features = [
        torch.ones((len(graph.nodes), 8), dtype=torch.float32)
        for graph in graphs
    ]

    batch = collate_cpg_graphs(graphs, node_features)

    assert batch["node_features"].shape == (sum(len(g.nodes) for g in graphs), 8)
    assert batch["graph_batch"].shape[0] == batch["node_features"].shape[0]
    assert batch["labels"].tolist() == [0.0, 1.0]
    assert batch["edge_index"].shape[0] == 2
    assert batch["edge_type"].shape[0] == batch["edge_index"].shape[1]
    assert int(batch["edge_index"].max()) < batch["node_features"].shape[0]
    logits = CPGGNN(input_dim=8)(
        batch["node_features"],
        batch["edge_index"],
        batch["edge_type"],
        batch["graph_batch"],
    )
    assert logits.shape == (2,)


def test_cpg_collation_rejects_missing_or_mismatched_graph_features():
    import torch

    graph = build_cpg("value = 1\n")
    with pytest.raises(ValueError, match="one tensor per graph"):
        collate_cpg_graphs([graph], [])
    with pytest.raises(ValueError, match="one row per graph node"):
        collate_cpg_graphs([graph], [torch.ones((1, 4))])


def test_metrics_integer_counts_require_an_explicit_valid_severity():
    collector = MetricsCollector()
    collector.record_findings(2, severity="HIGH")
    with pytest.raises(ValueError, match="severity"):
        collector.record_findings(1, severity="LOW")
    assert 'vulnerabilities_detected_total{severity="HIGH"} 2.0' in collector.render().decode()
