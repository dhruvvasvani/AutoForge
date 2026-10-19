from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.analysis.cross_file_resolver import CrossFileResolver
from src.analysis.taint_engine import TaintEngine
from src.ml.multilingual_features import FEATURE_NAMES, extract_features
from src.ml.preprocess import FeatureStandardizer
from src.parser.multi_lang_parser import MultiLangParser
from src.reporting.pipeline_gate import evaluate_findings
from src.reporting.sarif_exporter import SARIFExporter
from src.scoring.risk_aggregator import RiskAggregator
from src.scoring.scoring_engine import ScoringEngine


def test_java_and_javascript_return_structured_syntax_trees():
    parser = MultiLangParser()
    java = parser.parse_source("class Demo { void run() { call(); } }", "Demo.java")
    javascript = parser.parse_source("function run() { call(); }", "demo.js")
    assert java.tree["type"] == "program"
    assert javascript.tree["type"] == "program"
    assert java.tree["children"]
    assert javascript.tree["children"]


def test_direct_source_to_sink_and_sanitizer_signal():
    engine = TaintEngine()
    findings = engine.analyze(
        "db.execute(request.getParameter('q'))\n"
        "safe = sanitize(request.getParameter('x'))\n"
        "db.execute(safe)\n"
    )
    assert len(findings) == 2
    assert findings[0].line == 1
    assert findings[1].has_sanitizer


def test_cross_file_import_links_argument_and_taint_sink(tmp_path):
    (tmp_path / "app.py").write_text(
        "from helpers import consume\n"
        "def handler(request):\n"
        "    value = request.getParameter('id')\n"
        "    consume(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        "def consume(data):\n"
        "    db.execute(data)\n",
        encoding="utf-8",
    )
    resolver = CrossFileResolver(tmp_path)
    graph = resolver.resolve()
    assert graph["call_edges"][0]["callee"] == "helpers.consume"
    assert graph["call_edges"][0]["argument_bindings"] == {"data": "value"}
    findings = resolver.analyze_taint()
    assert findings[0]["file"] == "helpers.py"
    assert findings[0]["line"] == 2


def test_interprocedural_tainted_return_reaches_sink(tmp_path):
    (tmp_path / "app.py").write_text(
        "def fetch(request):\n"
        "    return request.getParameter('q')\n"
        "def handler(request):\n"
        "    value = fetch(request)\n"
        "    db.execute(value)\n",
        encoding="utf-8",
    )
    findings = CrossFileResolver(tmp_path).analyze_taint()
    assert any(item["function"] == "app.handler" and item["line"] == 5 for item in findings)


def test_pipeline_worker_uses_cross_file_taint_results():
    sys.path.insert(0, str(ANALYZER_ROOT.parent / "2_pipeline"))
    from worker import PipelineWorker

    findings = PipelineWorker._analyze_files({
        "app.py": "from helpers import consume\n"
                  "def handler(request):\n"
                  "    value = request.getParameter('id')\n"
                  "    consume(value)\n",
        "helpers.py": "def consume(data):\n"
                      "    db.execute(data)\n",
    })
    assert any(item["file"] == "helpers.py" and item["line"] == 2 for item in findings)


def test_scoring_features_scaling_and_ci_gate():
    score = RiskAggregator.aggregate("SQLI_RAW_CONCAT", reachability="interprocedural")
    assert score["final_score"] == 7.65
    assert score["severity"] == "HIGH"
    hybrid = ScoringEngine.calculate_hybrid_risk(9.0, 0.5)
    assert hybrid["combined_risk_score"] == 7.4
    assert len(extract_features({"type": "Module", "body": [{"type": "Call"}]})) == len(FEATURE_NAMES)

    standardizer = FeatureStandardizer().fit_transform([[1, 10], [3, 30]])
    assert standardizer == [[-1.0, -1.0], [1.0, 1.0]]
    gate = evaluate_findings([{"severity": "HIGH", "combined_risk_score": 8.2}])
    assert gate["passed"] is False
    assert evaluate_findings([{"severity": "LOW"}])["passed"] is True


def test_sarif_and_ci_gate_interoperate(tmp_path):
    destination = SARIFExporter.export_to_sarif(
        [{
            "rule_id": "AF-TAINT-001",
            "file": "src/app.py",
            "line": 8,
            "severity": "CRITICAL",
            "combined_risk_score": 9.0,
            "message": "Unsafe database query",
        }],
        tmp_path / "report.sarif",
    )
    report = json.loads(destination.read_text(encoding="utf-8"))
    sarif_finding = report["runs"][0]["results"][0]
    assert sarif_finding["locations"][0]["physicalLocation"]["region"]["startLine"] == 8
    assert evaluate_findings([{
        "severity": sarif_finding["properties"]["severity"],
        "combined_risk_score": sarif_finding["properties"]["combinedRiskScore"],
    }])["passed"] is False


def test_model_forward_and_checkpoint_inference(tmp_path):
    torch = pytest.importorskip("torch")
    from src.ml.inference import ASTInference
    from src.ml.models import ASTVulnerabilityClassifier

    model = ASTVulnerabilityClassifier(input_dim=len(FEATURE_NAMES))
    output = model(torch.zeros((2, len(FEATURE_NAMES))))
    assert output.shape == (2, 1)
    assert bool(((output >= 0) & (output <= 1)).all())
    checkpoint_path = tmp_path / "model.pt"
    torch.save({
        "input_dim": len(FEATURE_NAMES),
        "state_dict": model.state_dict(),
    }, checkpoint_path)
    prediction = ASTInference.from_checkpoint(checkpoint_path).predict([0.0] * len(FEATURE_NAMES))
    assert 0.0 <= prediction <= 1.0
