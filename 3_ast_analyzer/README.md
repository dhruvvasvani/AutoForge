# AutoForge AST Analyzer

The canonical analyzer implementation is in `src/`. It currently provides
Python AST parsing, scope-aware symbol collection, control-flow graphs,
intra-procedural taint analysis, Python cross-file taint propagation,
reachability tagging, scoring, ML feature extraction/inference, and SARIF
reporting.

Python taint analysis is implemented for Python source. Java and JavaScript
parsers provide normalized syntax trees, but taint tracking for those
languages, a recovered training dataset, and trained model weights are not
currently included.

## Setup

Requires Python 3.10 or later.

```powershell
python -m pip install -r 3_ast_analyzer\requirements.txt
```

Semgrep's Python package does not install on native Windows, so pip skips that
optional dependency there. The analyzer still runs Semgrep if its `semgrep`
executable is already on `PATH`; otherwise its results identify Semgrep as
unavailable. To install Semgrep as part of setup, use WSL and run the analyzer
in that same WSL environment.

## Local project scan service

Start the analyzer from the repository root after installing the requirements:

```powershell
python -m uvicorn src.dashboard_api:app --app-dir 3_ast_analyzer --host 127.0.0.1 --port 8090
```

The React dashboard submits the selected project files to this loopback-only
service. Python files receive AST, taint, CFG, and cross-file reachability
analysis; other supported languages receive parser-backed syntax checks.
Semgrep and Checkov run as separate static scanners. The GNN status is reported
as unavailable until a trained checkpoint is installed; the analyzer does not
substitute sample findings or execute submitted code.

For full local use, start the Spring Boot backend in its `demo` profile as
described in [1_backend/README.md](../1_backend/README.md), then start Vite:

```powershell
cd 4_frontend
npm run dev
```

Register or sign in to reach the dashboard. Set `VITE_API_URL`,
`VITE_ANALYZER_URL`, and `VITE_WEBHOOK_URL` before starting Vite to override
the local service addresses.

## Verify

Run the meaningful analyzer tests from the repository root:

```powershell
python -m pytest 3_ast_analyzer\tests\test_weeks_1_3.py -q
```

Run the full analyzer suite:

```powershell
python -m pytest 3_ast_analyzer\tests -q
```

## Week 1–3 entry points

- Week 1: `src\parser\multi_lang_parser.py` and `src\ir\symbol_table.py`
- Week 2: `src\engine\cfg_builder.py`
- Week 3: `src\analysis\taint_engine.py`, `src\analysis\cross_file_resolver.py`,
  and `src\analysis\reachability.py`

The `week1_foundations`, `week2_prototype`, and `week3_reachability` folders
are preserved as legacy demos. New implementation and tests should target
`src/` and `tests/`.
