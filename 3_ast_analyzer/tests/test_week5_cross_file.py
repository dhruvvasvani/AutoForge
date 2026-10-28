from __future__ import annotations

import sys
from pathlib import Path

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.analysis.cross_file_resolver import CrossFileResolver
from src.ir.symbol_table import SymbolTable
from week4_pipeline.pipeline_cli import run_cross_file, run_single_file


def test_cross_file_taint_binds_keyword_arguments(tmp_path):
    (tmp_path / "routes.py").write_text(
        "from helpers import execute_query as run_query\n"
        "def handler(request):\n"
        "    run_query(statement=request.getParameter('id'))\n",
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        "def execute_query(statement):\n"
        "    db.execute(statement)\n",
        encoding="utf-8",
    )

    resolver = CrossFileResolver(tmp_path)
    graph = resolver.resolve()
    assert graph["call_edges"][0]["callee"] == "helpers.execute_query"
    assert graph["call_edges"][0]["argument_bindings"] == {
        "statement": "request.getParameter('id')"
    }
    findings = resolver.analyze_taint()
    assert len(findings) == 1
    assert findings[0]["file"] == "helpers.py"
    assert findings[0]["line"] == 2


def test_cross_file_taint_resolves_imported_inherited_methods(tmp_path):
    package = tmp_path / "service"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "routes.py").write_text(
        "from .helpers import Repository as Repo\n"
        "def handler(request):\n"
        "    Repo().run(statement=request.getParameter('id'))\n",
        encoding="utf-8",
    )
    (package / "helpers.py").write_text(
        "from .database import QueryBase\n"
        "class Repository(QueryBase):\n"
        "    def run(self, statement):\n"
        "        self.execute_query(statement)\n",
        encoding="utf-8",
    )
    (package / "database.py").write_text(
        "class QueryBase:\n"
        "    def execute_query(self, statement):\n"
        "        db.execute(statement)\n",
        encoding="utf-8",
    )

    resolver = CrossFileResolver(tmp_path)
    graph = resolver.resolve()
    callees = {edge["callee"] for edge in graph["call_edges"]}
    assert "service.helpers.Repository.run" in callees
    assert "service.database.QueryBase.execute_query" in callees

    findings = resolver.analyze_taint()
    assert len(findings) == 1
    assert findings[0]["file"] == "service/database.py"
    assert findings[0]["line"] == 3


def test_cross_file_resolution_does_not_guess_ambiguous_bare_calls(tmp_path):
    (tmp_path / "app.py").write_text(
        "def handler(value):\n"
        "    consume(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "one.py").write_text(
        "def consume(value):\n"
        "    return value\n",
        encoding="utf-8",
    )
    (tmp_path / "two.py").write_text(
        "def consume(value):\n"
        "    db.execute(value)\n",
        encoding="utf-8",
    )

    graph = CrossFileResolver(tmp_path).resolve()
    assert not any(
        edge["caller"] == "app.handler" and edge["call_name"] == "consume"
        for edge in graph["call_edges"]
    )


def test_project_index_skips_generated_python_directories(tmp_path):
    (tmp_path / "app.py").write_text("def handler():\n    return 1\n", encoding="utf-8")
    generated = tmp_path / "node_modules" / "dependency"
    generated.mkdir(parents=True)
    (generated / "broken.py").write_text("this is not valid python !!!", encoding="utf-8")
    build_output = tmp_path / "target"
    build_output.mkdir()
    (build_output / "generated.py").write_text("also not valid python !!!", encoding="utf-8")

    table = SymbolTable.from_project(tmp_path)

    assert set(table.modules) == {"app"}
    assert table.resolve("app.handler") is not None


def test_pipeline_cli_uses_canonical_cross_file_reachability(tmp_path):
    (tmp_path / "app.py").write_text(
        "from helpers import process\n"
        "def main():\n"
        "    process()\n",
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        "def process():\n"
        "    return 1\n",
        encoding="utf-8",
    )
    scan_path = tmp_path / "findings.json"
    scan_path.write_text(
        '[{"function": "helpers.process", "rule_id": "TEST"}]',
        encoding="utf-8",
    )

    result = run_cross_file(
        tmp_path,
        scan_path,
        tmp_path / "out.json",
        ["main"],
        0,
        "json",
    )

    assert result["summary"]["unverified"] == 1
    assert result["unverified_findings"][0]["depth"] is None


def test_pipeline_cli_keeps_unresolved_findings_in_unverified_output(tmp_path):
    (tmp_path / "main.py").write_text(
        "def main():\n    return 1\n",
        encoding="utf-8",
    )
    scan_path = tmp_path / "findings.json"
    scan_path.write_text(
        '[{"rule_id":"MISSING_FUNCTION"},{"function":"absent"}]',
        encoding="utf-8",
    )

    result = run_cross_file(
        tmp_path,
        scan_path,
        tmp_path / "out.json",
        ["main"],
        None,
        "json",
    )

    assert result["summary"]["unverified"] == 2
    assert len(result["unverified_findings"]) == 2


def test_pipeline_cli_recognizes_http_route_decorators_as_entry_points(tmp_path):
    source_path = tmp_path / "routes.py"
    source_path.write_text(
        "@router.get('/items')\n"
        "def list_items():\n"
        "    load_items()\n"
        "def load_items():\n"
        "    return []\n",
        encoding="utf-8",
    )
    scan_path = tmp_path / "findings.json"
    scan_path.write_text(
        '[{"function":"routes.list_items"},{"function":"routes.load_items"}]',
        encoding="utf-8",
    )

    result = run_cross_file(
        tmp_path,
        scan_path,
        tmp_path / "out.json",
        [],
        None,
        "json",
    )

    assert result["summary"]["reachable"] == 2
    assert [finding["reachability"] for finding in result["clean_findings"]] == [
        "REACHABLE_CODE",
        "REACHABLE_CODE",
    ]


def test_single_file_pipeline_preserves_unresolved_findings(tmp_path):
    source_path = tmp_path / "main.py"
    source_path.write_text(
        "def main():\n    return 1\n",
        encoding="utf-8",
    )
    scan_path = tmp_path / "findings.json"
    scan_path.write_text(
        '[{"file":"main.py","rule_id":"MISSING_LINE"}]',
        encoding="utf-8",
    )

    result = run_single_file(
        source_path,
        scan_path,
        tmp_path / "out.json",
        ["main"],
    )

    assert result["summary"]["unverified"] == 1
    assert result["unverified_findings"][0]["reachability"] == "UNKNOWN"
