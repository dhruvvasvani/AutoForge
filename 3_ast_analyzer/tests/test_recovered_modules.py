from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.analysis.taint_engine import TaintEngine
from src.parser.multi_lang_parser import MultiLangParser
from src.reporting.sarif_exporter import SARIFExporter
from src.scoring.scoring_engine import ScoringEngine


def test_python_parser_and_taint_analysis():
    parsed = MultiLangParser().parse_source(
        "value = request.getParameter('id')\ndb.execute(value)",
        "sample.py",
    )
    assert parsed.language == "python"
    findings = TaintEngine().analyze(parsed.source)
    assert findings[0].rule_id == "SQLI_RAW_CONCAT"
    assert findings[0].line == 2


def test_hybrid_score_weights_and_sarif_output(tmp_path):
    score = ScoringEngine.calculate_score(0.8, 0.5)
    assert score["combined_risk_score"] == 0.68
    output = SARIFExporter.export_to_sarif(
        [{
            "rule_id": "AF-TAINT-001",
            "file": "src/app.py",
            "line": 3,
            "message": "Tainted SQL",
            "combined_risk_score": score["combined_risk_score"],
            "code_snippet": "db.execute(value)",
        }],
        tmp_path / "demo_results.sarif",
    )
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["version"] == "2.1.0"
    result = report["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] == "db.execute(value)"
