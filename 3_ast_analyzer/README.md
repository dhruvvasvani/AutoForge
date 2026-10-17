# AutoForge — AST & Static Analysis Prioritization Engine

**Track Owner:** Dhruv Vasvani
**Core Objective:** Eliminate SAST noise by parsing ASTs (Tree-sitter) and evaluating runtime call-graph reachability.

## Install

```bash
python -m venv venv
source venv/bin/activate # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Requires Python 3.9+.

## Structure

```
ast_noise_filter/
├── week1_foundations/ Parser setup, basic node traversal
│ ├── parser_setup.py
│ └── sample_mock.py
├── week2_prototype/ PoC caller-callee extraction
│ └── noise_filter.py
├── week3_reachability/ Core engine: call graph + BFS reachability + tagging
│ └── ast_engine.py
├── week4_pipeline/ CLI wrapper, writes filtered_scan_results.json
│ └── pipeline_cli.py
├── week5_scoring/ P0-P3 rule-based risk scoring
│ └── risk_scorer.py
├── sample_data/
│ └── combined_scan_results.json
└── requirements.txt
```

## Usage (per week)

**Week 1 — validate parser**
```bash
cd week1_foundations
python parser_setup.py sample_mock.py
```

**Week 2 — extract call relationships**
```bash
cd week2_prototype
python noise_filter.py ../week1_foundations/sample_mock.py
```

**Week 3 — reachability tagging**
```bash
cd week3_reachability
python ast_engine.py ../week1_foundations/sample_mock.py ../sample_data/combined_scan_results.json
```

**Week 4 — full pipeline (raw scan -> filtered_scan_results.json)**
```bash
cd week4_pipeline
python pipeline_cli.py \
 --source ../week1_foundations/sample_mock.py \
 --scan ../sample_data/combined_scan_results.json \
 --out filtered_scan_results.json
```

**Week 5 — risk scoring (P0-P3)**
```bash
cd week5_scoring
python risk_scorer.py --input ../week4_pipeline/filtered_scan_results.json --out scored_results.json
```

## Priority Matrix (Week 5)

| Reachability | Severity | Priority | Label |
|---|---|---|---|
| Reachable | error | P0 | Critical |
| Reachable | warning | P1 | High |
| Unreachable | error | P2 | Medium |
| Unreachable | warning | P3 | Low |

## Notes

- Entry points default to `["main", "handle_login", "get_user_profile"]` — override via `--entry-points` in week4 CLI, or `ASTReachabilityAnalyzer(entry_points=[...])` directly.
- `week3_reachability/ast_engine.py` is the core reusable module; week4/week5 import/consume its output rather than duplicating logic.
- Swap in your real `combined_scan_results.json` and source file(s) in place of the sample data.
