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
