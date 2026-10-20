from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.MLOps.feedback_collector import FeedbackCollector
from src.MLOps.retrain_trigger import RetrainTrigger
from src.multitenancy.sandbox_runner import ASTSandboxRunner
from src.multitenancy.tenant_manager import TenantManager
from src.policy_studio.policy_evaluator import PolicyEvaluator
from src.policy_studio.rule_compiler import PolicyCompileError, compile_rules


def test_tenant_workspaces_are_isolated_and_credentials_are_required(tmp_path):
    manager = TenantManager(
        tmp_path / "workspaces",
        {"tenant-a": "secret-a", "tenant-b": "secret-b"},
        max_jobs_per_window=2,
        max_concurrent_jobs=1,
    )
    job = manager.start_scan("tenant-a", "secret-a")
    assert job.workspace == tmp_path / "workspaces" / "tenant-a"
    assert manager.workspace_for("tenant-b", "secret-b") != job.workspace

    with pytest.raises(PermissionError, match="invalid tenant credentials"):
        manager.start_scan("tenant-a", "secret-b")
    with pytest.raises(RuntimeError, match="concurrent scan limit"):
        manager.start_scan("tenant-a", "secret-a")

    manager.finish_scan("tenant-a", "secret-a", job.job_id)
    second_job = manager.start_scan("tenant-a", "secret-a")
    manager.finish_scan("tenant-a", "secret-a", second_job.job_id)
    with pytest.raises(RuntimeError, match="rate limit"):
        manager.start_scan("tenant-a", "secret-a")


def test_tenant_id_cannot_escape_workspace_root(tmp_path):
    manager = TenantManager(tmp_path / "workspaces", {"tenant": "secret"})
    with pytest.raises(ValueError, match="tenant_id"):
        manager.workspace_for("..", "secret")
    with pytest.raises(PermissionError):
        manager.workspace_for("tenant", "incorrect")


def test_sandbox_parses_bounded_source_without_execution():
    runner = ASTSandboxRunner(max_source_bytes=100, max_ast_nodes=5)
    tree = runner.parse("value = 1")
    assert tree.body[0].targets[0].id == "value"

    with pytest.raises(ValueError, match="size limit"):
        runner.parse("value = '" + ("x" * 100) + "'")

    with pytest.raises(ValueError, match="node limit"):
        runner.parse("a = b = c = d = e = 1")

    with pytest.raises(ValueError, match="could not be parsed"):
        runner.parse("def broken(")


def test_policy_compiles_yaml_and_detects_only_the_configured_api():
    policy = """
rules:
  - id: no-eval
    node_type: Call
    call_names: [eval]
    severity: HIGH
    message: Avoid dynamic evaluation
"""
    evaluator = PolicyEvaluator()
    evaluator.set_policy("tenant-a", policy)
    evaluator.set_policy(
        "tenant-b",
        {
            "rules": [
                {
                    "id": "no-exec",
                    "node_type": "Call",
                    "call_names": ["exec"],
                    "severity": "CRITICAL",
                    "message": "Avoid execution",
                }
            ]
        },
    )

    assert [finding["rule_id"] for finding in evaluator.evaluate("tenant-a", "eval(user_input)")] == [
        "no-eval"
    ]
    assert evaluator.evaluate("tenant-a", "exec(user_input)") == []
    assert evaluator.evaluate("tenant-b", "exec(user_input)")[0]["severity"] == "CRITICAL"


def test_policy_regex_selectors_match_api_names():
    evaluator = PolicyEvaluator()
    evaluator.set_policy(
        "tenant-a",
        {
            "rules": [
                {
                    "id": "no-dynamic-execution",
                    "node_type": "Call",
                    "call_name_regex": r"^(eval|exec)$",
                    "severity": "HIGH",
                    "message": "Dynamic execution is prohibited",
                }
            ]
        },
    )

    assert len(evaluator.evaluate("tenant-a", "eval(user_input)")) == 1
    assert len(evaluator.evaluate("tenant-a", "exec(user_input)")) == 1
    assert evaluator.evaluate("tenant-a", "safe_call(user_input)") == []


@pytest.mark.parametrize(
    "policy",
    [
        {"rules": [{"id": "duplicate", "node_type": "Call", "call_names": ["eval"],
                    "severity": "HIGH", "message": "first"},
                   {"id": "duplicate", "node_type": "Call", "call_names": ["exec"],
                    "severity": "HIGH", "message": "second"}]},
        {"rules": [{"id": "bad", "node_type": "Call", "call_names": ["eval"],
                    "severity": "UNKNOWN", "message": "bad severity"}]},
        {"rules": [{"id": "unsafe", "node_type": "Call", "call_names": ["eval"],
                    "severity": "HIGH", "message": "ok", "python": "__import__('os').system('x')"}]},
    ],
)
def test_policy_rejects_duplicate_invalid_and_executable_fields(policy):
    with pytest.raises(PolicyCompileError):
        compile_rules(policy)


def test_feedback_isolated_by_tenant_and_requires_consistent_labels(tmp_path):
    collector = FeedbackCollector(tmp_path / "feedback.sqlite3")
    feedback_id = collector.record_feedback(
        "tenant-a",
        "finding-1",
        "false_positive",
        reason="Reviewed by developer",
        training_example={"code": "def safe():\n    return 1\n", "label": 0},
    )
    collector.record_feedback(
        "tenant-b",
        "finding-1",
        "true_positive",
        training_example={"code": "eval(user_input)\n", "label": 1},
    )

    pending = collector.pending_training_examples("tenant-a")
    assert len(pending) == 1
    assert pending[0].feedback_id == feedback_id
    assert pending[0].training_example["label"] == 0
    assert collector.pending_training_examples("tenant-b")[0].training_example["label"] == 1
    with pytest.raises(ValueError, match="agree"):
        collector.record_feedback(
            "tenant-a",
            "finding-2",
            "false_positive",
            training_example={"code": "eval(x)", "label": 1},
        )

    collector.mark_trained("tenant-a", [feedback_id])
    assert collector.pending_training_examples("tenant-a") == []
    assert len(collector.pending_training_examples("tenant-b")) == 1


def test_retrain_trigger_combines_baseline_and_feedback_per_tenant(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            [
                {"code": "def safe():\n    return 1\n", "label": 0},
                {"code": "def vulnerable(x):\n    eval(x)\n", "label": 1},
            ]
        ),
        encoding="utf-8",
    )
    collector = FeedbackCollector(tmp_path / "feedback.sqlite3")
    collector.record_feedback(
        "tenant-a",
        "finding-a",
        "false_positive",
        training_example={"code": "def safe_again():\n    return 2\n", "label": 0},
    )
    collector.record_feedback(
        "tenant-b",
        "finding-b",
        "true_positive",
        training_example={"code": "def unsafe(x):\n    eval(x)\n", "label": 1},
    )
    calls = []

    def trainer(dataset_path, checkpoint_path):
        rows = json.loads(Path(dataset_path).read_text(encoding="utf-8"))
        calls.append((Path(dataset_path).exists(), Path(checkpoint_path), rows))
        return {"examples": len(rows)}

    trigger = RetrainTrigger(
        collector,
        tmp_path / "models",
        baseline_dataset_path=baseline_path,
        min_feedback=1,
        trainer=trainer,
    )
    assert trigger.maybe_retrain("tenant-a").feedback_count == 1
    assert trigger.maybe_retrain("tenant-a") is None
    assert trigger.maybe_retrain("tenant-b").tenant_id == "tenant-b"
    assert len(calls) == 2
    assert calls[0][0] is True
    assert calls[0][1] == tmp_path / "models" / "tenant-a" / "cpg_gnn.pt"
    assert len(calls[0][2]) == 3
    assert calls[1][1] != calls[0][1]


def test_retrain_failure_keeps_feedback_pending(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            [
                {"code": "def safe():\n    return 1\n", "label": 0},
                {"code": "def unsafe(x):\n    eval(x)\n", "label": 1},
            ]
        ),
        encoding="utf-8",
    )
    collector = FeedbackCollector(tmp_path / "feedback.sqlite3")
    collector.record_feedback(
        "tenant-a",
        "finding-a",
        "false_positive",
        training_example={"code": "def safe_again():\n    return 2\n", "label": 0},
    )
    trigger = RetrainTrigger(
        collector,
        tmp_path / "models",
        baseline_dataset_path=baseline_path,
        min_feedback=1,
        trainer=lambda *_: (_ for _ in ()).throw(RuntimeError("training failed")),
    )

    with pytest.raises(RuntimeError, match="training failed"):
        trigger.maybe_retrain("tenant-a")
    assert len(collector.pending_training_examples("tenant-a")) == 1


def test_retrain_waits_for_feedback_threshold(tmp_path):
    collector = FeedbackCollector(tmp_path / "feedback.sqlite3")
    trigger = RetrainTrigger(
        collector,
        tmp_path / "models",
        min_feedback=2,
        trainer=lambda *_: pytest.fail("trainer must not run below threshold"),
    )
    assert trigger.maybe_retrain("tenant-a") is None
