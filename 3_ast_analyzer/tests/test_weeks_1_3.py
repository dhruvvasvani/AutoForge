from __future__ import annotations

import sys
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.analysis.cross_file_resolver import CrossFileResolver
from src.analysis.reachability import ReachabilityAnalyzer
from src.analysis.taint_engine import TaintEngine
from src.engine.cfg_builder import CFGBuilder
from src.ir.symbol_table import SymbolTable
from src.parser.multi_lang_parser import MultiLangParser


def test_week1_python_parser_and_scope_aware_symbols(tmp_path):
    source = (
        "import os as operating_system\n"
        "class Repository:\n"
        "    def find(self, name):\n"
        "        result = name\n"
        "        return result\n"
    )
    file_path = tmp_path / "repository.py"
    file_path.write_text(source, encoding="utf-8")
    parsed = MultiLangParser().parse_file(file_path)
    assert parsed.language == "python"
    assert parsed.tree["type"] == "Module"

    table = SymbolTable.from_project(tmp_path)
    symbol = table.resolve("repository.Repository.find")
    assert symbol is not None
    assert symbol.parameters == ("self", "name")
    assert table.imports["repository"]["operating_system"] == "os"
    scope = table.scopes["repository.Repository.find"]
    assert scope.variables["name"].kind == "parameter"
    assert scope.variables["result"].kind == "variable"


def test_week2_cfg_models_branches_loop_and_exit():
    cfg = CFGBuilder().build(
        "def inspect(flag, items):\n"
        "    if flag:\n"
        "        value = 1\n"
        "    else:\n"
        "        value = 2\n"
        "    for item in items:\n"
        "        if item:\n"
        "            continue\n"
        "        value = item\n"
        "    return value\n"
    )
    blocks = list(cfg.blocks.values())
    branch = next(block for block in blocks if block.kind == "branch")
    loop = next(block for block in blocks if block.kind == "loop")
    assert {edge for edge in branch.successors.values()} == {"true", "false"}
    assert {edge for edge in loop.successors.values()} == {"true", "false"}
    assert any(
        blocks[target].kind == "loop"
        for block in blocks
        if block.kind == "statement" and block.code == ["continue"]
        for target in block.successors
    )
    assert cfg.exit in cfg.reachable_blocks()


def test_week3_cfg_taint_finds_sources_and_sinks_across_branches():
    source = (
        "def handler(request, condition):\n"
        "    if condition:\n"
        "        value = request.getParameter('q')\n"
        "    else:\n"
        "        value = 'safe'\n"
        "    db.execute(value)\n"
    )
    findings = TaintEngine().analyze_cfg(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "SQLI_RAW_CONCAT"
    assert findings[0].line == 6


def test_week3_cross_file_parameter_taint_reaches_sink(tmp_path):
    package = tmp_path / "service"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "routes.py").write_text(
        "from .database import query\n"
        "def handler(request):\n"
        "    value = request.getParameter('id')\n"
        "    query(value)\n",
        encoding="utf-8",
    )
    (package / "database.py").write_text(
        "def query(statement):\n"
        "    connection.execute(statement)\n",
        encoding="utf-8",
    )
    findings = CrossFileResolver(tmp_path).analyze_taint()
    assert len(findings) == 1
    assert findings[0]["file"] == "service/database.py"
    assert findings[0]["line"] == 2
    assert findings[0]["rule_id"] == "SQLI_RAW_CONCAT"


def test_week3_reachability_links_entry_point_to_cross_file_callee(tmp_path):
    package = tmp_path / "service"
    package.mkdir()
    (package / "routes.py").write_text(
        "from .handlers import process\n"
        "def main(request):\n"
        "    process(request)\n",
        encoding="utf-8",
    )
    (package / "handlers.py").write_text(
        "def process(request):\n"
        "    return request.getParameter('q')\n"
        "def unused():\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = ReachabilityAnalyzer(["main"]).analyze_project(
        tmp_path,
        [
            {"file": "service/handlers.py", "line": 2, "rule_id": "source"},
            {"function": "unused", "rule_id": "dead-code"},
        ],
    )

    assert "service.routes.main" in result["reachable_functions"]
    assert "service.handlers.process" in result["reachable_functions"]
    assert result["tagged_findings"][0]["reachability"] == "REACHABLE_CODE"
    assert result["tagged_findings"][1]["reachability"] == "UNREACHABLE_NOISE"
