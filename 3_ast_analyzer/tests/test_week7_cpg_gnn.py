from __future__ import annotations

import ast
import csv
import json
import sys
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.ml.cpg_builder import EDGE_TYPES, build_cpg, merge_cpg_graphs
from src.ml.cpg_training import (
    LabeledCPG,
    _reject_held_out_overlap,
    load_cpg_dataset,
    stratified_split,
)


def test_cpg_contains_ast_cfg_and_data_flow_edges():
    graph = build_cpg(
        "def route(request):\n"
        "    value = request.args['q']\n"
        "    if value:\n"
        "        db.execute(value)\n"
        "    return value\n",
        label=1,
    )

    assert graph.label == 1
    assert graph.nodes
    assert graph.edges_of_type("ast")
    assert graph.edges_of_type("cfg")
    assert graph.edges_of_type("dfg")
    assert all(kind in EDGE_TYPES for _, _, kind in graph.edges)


def test_assignments_link_uses_to_the_previous_definition():
    source = "x = 1\nx = x + 1\nsink(x)\n"
    graph = build_cpg(source)
    name_nodes = [
        (graph.nodes[index], node)
        for index, node in enumerate(ast.walk(ast.parse(source)))
        if isinstance(node, ast.Name) and node.id == "x"
    ]
    stores = {
        node.lineno: cpg_node.node_id
        for cpg_node, node in name_nodes
        if isinstance(node.ctx, ast.Store)
    }
    loads = {
        node.lineno: cpg_node.node_id
        for cpg_node, node in name_nodes
        if isinstance(node.ctx, ast.Load)
    }

    assert (stores[1], loads[2], "dfg") in graph.edges
    assert (stores[2], loads[3], "dfg") in graph.edges
    assert (stores[2], loads[2], "dfg") not in graph.edges


def test_merge_adds_cross_file_data_flow_edge_and_reindexes_nodes():
    source = build_cpg("def handler():\n    value = get_input()\n")
    target = build_cpg("def execute(query):\n    db.execute(query)\n")

    merged = merge_cpg_graphs(
        {"routes.py": source, "database.py": target},
        [("routes.py", 0, "database.py", 0)],
    )

    assert len(merged.nodes) == len(source.nodes) + len(target.nodes)
    assert (0, len(source.nodes), "dfg") in merged.edges
    assert [node.node_id for node in merged.nodes] == list(range(len(merged.nodes)))


def test_merge_rejects_cross_file_edges_outside_the_graph():
    graph = build_cpg("value = 1\n")
    with pytest.raises(ValueError, match="invalid node id"):
        merge_cpg_graphs({"app.py": graph}, [("app.py", 99, "app.py", 0)])


def test_dataset_loading_and_stratified_80_10_10_split(tmp_path):
    dataset_path = tmp_path / "examples.json"
    rows = [
        {"code": f"value = {index}\n", "label": index % 2}
        for index in range(20)
    ]
    dataset_path.write_text(json.dumps(rows), encoding="utf-8")

    examples = load_cpg_dataset(dataset_path)
    train, validation, test = stratified_split(examples, seed=3)

    assert (len(train), len(validation), len(test)) == (16, 2, 2)
    assert {example.label for example in train} == {0, 1}
    assert {example.label for example in validation} == {0, 1}
    assert {example.label for example in test} == {0, 1}
    assert len({id(example) for example in train + validation + test}) == len(examples)


def test_stratified_split_keeps_duplicate_source_examples_together():
    examples = [
        *(LabeledCPG(f"vulnerable_{index} = 1", 1) for index in range(6)),
        *(LabeledCPG(f"safe_{index} = 0", 0) for index in range(6)),
        LabeledCPG("vulnerable_0 = 1", 0),
    ]

    train, validation, test = stratified_split(examples, seed=3)

    source_sets = [{example.source for example in split} for split in (train, validation, test)]
    assert not (source_sets[0] & source_sets[1])
    assert not (source_sets[0] & source_sets[2])
    assert not (source_sets[1] & source_sets[2])


def test_held_out_dataset_rejects_source_overlap():
    with pytest.raises(ValueError, match="also present in training or validation"):
        _reject_held_out_overlap(
            [LabeledCPG("def check():\n    return 1\n", 0)],
            [LabeledCPG("\ndef check():\n    return 1\n", 1)],
        )


def test_pycode_vul_csv_keeps_original_and_patch_in_the_same_split(tmp_path):
    dataset_path = tmp_path / "train.csv"
    with dataset_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=[
                "label",
                "vulnerable_function_source",
                "patched_function_source",
            ],
        )
        writer.writeheader()
        for label in (0, 1):
            for index in range(6):
                writer.writerow(
                    {
                        "label": label,
                        "vulnerable_function_source": f"value = {label * 10 + index}\n",
                        "patched_function_source": f"safe_value = {label * 10 + index}\n",
                    }
                )

    examples = load_cpg_dataset(dataset_path)
    train, validation, test = stratified_split(examples, seed=3)

    assert len(examples) == 24
    assert {example.label for example in examples} == {0, 1}
    assert all({example.label for example in part} == {0, 1} for part in (train, validation, test))
    split_groups = [
        {example.group_id for example in part}
        for part in (train, validation, test)
    ]
    assert not (split_groups[0] & split_groups[1])
    assert not (split_groups[0] & split_groups[2])
    assert not (split_groups[1] & split_groups[2])


def test_pycode_vul_held_out_csv_uses_class_and_function_code_columns(tmp_path):
    dataset_path = tmp_path / "test.csv"
    with dataset_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=["class", "function_code", "patched_function_source"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "class": 1,
                "function_code": "def vulnerable():\n    return eval(input())\n",
                "patched_function_source": "def fixed():\n    return input()\n",
            }
        )
        writer.writerow(
            {
                "class": 0,
                "function_code": "def safe():\n    return 1\n",
                "patched_function_source": "def ignored_patch():\n    return 2\n",
            }
        )

    examples = load_cpg_dataset(dataset_path)

    assert len(examples) == 2
    assert [example.label for example in examples] == [1, 0]


def test_csv_loader_accepts_large_code_fields(tmp_path):
    dataset_path = tmp_path / "large.csv"
    long_literal = "a" * 140_000
    with dataset_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=["class", "function_code"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "class": 1,
                "function_code": f"value = {long_literal!r}\n",
            }
        )

    examples = load_cpg_dataset(dataset_path)

    assert len(examples) == 1
    assert examples[0].label == 1


def test_dataset_rejects_invalid_labels_and_syntax(tmp_path):
    invalid_label = tmp_path / "invalid-label.json"
    invalid_label.write_text(json.dumps([{"code": "x = 1", "label": True}]), encoding="utf-8")
    with pytest.raises(ValueError, match="0/1 label"):
        load_cpg_dataset(invalid_label)

    invalid_source = tmp_path / "invalid-source.json"
    invalid_source.write_text(json.dumps([{"code": "if:", "label": 1}]), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid Python"):
        load_cpg_dataset(invalid_source)


def test_stratified_split_requires_both_classes():
    examples = [
        *[LabeledCPG(f"safe_{index}", 0) for index in range(3)],
        *[LabeledCPG(f"vulnerable_{index}", 1) for index in range(2)],
    ]
    with pytest.raises(ValueError, match="at least 3 examples per class"):
        stratified_split(examples)


def test_gnn_forward_pass_and_probability():
    torch = pytest.importorskip("torch")
    from src.ml.cpg_gnn import CPGGNN, predict_graph_confidence

    model = CPGGNN(input_dim=16)
    features = torch.randn(4, 16)
    edge_index = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
    edge_type = torch.tensor([EDGE_TYPES["ast"], EDGE_TYPES["dfg"]], dtype=torch.long)
    graph_batch = torch.tensor([0, 0, 1, 1], dtype=torch.long)
    logits = model(features, edge_index, edge_type, graph_batch)

    assert logits.shape == (2,)
    confidence = predict_graph_confidence(
        model,
        features[:2],
        edge_index[:, :1],
        edge_type[:1],
    )
    assert 0.0 <= confidence <= 1.0
