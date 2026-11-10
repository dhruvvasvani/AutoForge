# AutoForge AST Analyzer 

**Demo 2 date:** 4 November 2026

## Project in brief

AutoForge is a static-analysis project for identifying and explaining potential
security issues in source code. The AST analyzer parses submitted code, checks
for supported security patterns, and returns findings with file locations and
context. It analyzes code statically; it does not execute submitted source.

The analyzer's strongest security-analysis coverage is Python. Java,
JavaScript, TypeScript/TSX, Go, and Rust have parser-backed support, but should
not be presented as having equivalent Python taint-analysis coverage.

## Demo 1 — Project introduction and design

Use this part to introduce the problem, explain the design, and walk through
the main code paths:

1. **Request and pipeline:** `src/dashboard_api.py` receives analyzer requests
   and orchestrates project analysis.
2. **Parsing:** `src/parser/multi_lang_parser.py` converts supported source
   files to a normalized syntax representation. Python uses Python's built-in
   AST; other supported languages use Tree-sitter parsing.
3. **Control flow:** `src/engine/cfg_builder.py` represents Python execution
   paths as a control-flow graph (CFG).
4. **Taint tracking:** `src/analysis/taint_engine.py` follows selected
   untrusted inputs (sources) toward potentially dangerous operations (sinks)
   and accounts for recognized sanitizers.
5. **Cross-file calls:** `src/analysis/cross_file_resolver.py` resolves
   supported Python imports and calls across files.
6. **Reachability:** `src/analysis/reachability.py` uses a static call graph
   and recognized entry points to add reachability evidence. This is static
   evidence, not proof of runtime execution or dead code.
7. **Risk and output:** `src/scoring/vulnerability_scorer.py` adds score,
   severity, CWE, and remediation metadata. `src/reporting/sarif_generator.py`
   can export findings in SARIF.

**SARIF** means *Static Analysis Results Interchange Format*. It is a standard
JSON format for exchanging scanner findings with code-scanning tools, such as
GitHub Code Scanning. It carries details such as rules, messages, file
locations, severity, and optional remediation metadata.

## Demo 2 — Working demonstration (4 November 2026)

### Start the analyzer

Open a PowerShell terminal at the repository root:

```powershell
cd L:\AutoForge-main-github
.\.venv\Scripts\python.exe -m uvicorn src.dashboard_api:app --app-dir 3_ast_analyzer --host 127.0.0.1 --port 8090
```

Keep this terminal open. If the root Python environment has not been set up
yet, install the analyzer requirements once:

```powershell
cd L:\AutoForge-main-github
python -m pip install -r 3_ast_analyzer\requirements.txt
```

### Start the frontend

Open a second PowerShell terminal:

```powershell
cd L:\AutoForge-main-github\4_frontend
npm run dev -- --host 127.0.0.1
```

Open **http://localhost:5173/analyze**. This standalone analyzer page is
intended to work without signing in. Select a small source file or project
folder and start an analysis. The frontend proxies analyzer requests to
`127.0.0.1:8090`.

Check analyzer health from another PowerShell terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8090/health
```

The response should report `status: ready`.

### What to show

- The submitted file/project and returned scan results.
- A finding's rule, severity, source file, and line.
- Taint source-to-sink explanation when a supported Python pattern is detected.
- Reachability evidence and risk score when available.
- SARIF export, if demonstrating the report format.

For a quick code walkthrough, open the files listed in the Demo 1 section. The
related regression tests include:

```powershell
python -m pytest 3_ast_analyzer\tests\test_week5_cross_file.py 3_ast_analyzer\tests\test_week6_scoring_sarif.py 3_ast_analyzer\tests\test_week7_cpg_gnn.py
```

## Data and model notes for the viva

- The CPG-GNN training work used **PyCode-Vul** (`S-AIR-L/PyCode-Vul`).
  The current training status is incomplete and no trained checkpoint is
  present in this checkout; do not claim that this current run produced a
  validated model.
- **CodeBERT-base** is a pretrained encoder from Microsoft. Its model card
  describes training on CodeSearchNet. It is an encoder, not the PyCode-Vul
  vulnerability dataset.
- The OWASP Benchmark for Python is a security-scanner evaluation benchmark,
  not the CPG-GNN training dataset.
- The repository includes OWASP Benchmark Python materials and CodeBERT model
  files. Check their upstream licenses and terms before redistributing them.

## Limitations to state clearly

- Static analysis can miss issues or report uncertain results; zero findings
  do not prove that code is secure.
- Python has the analyzer's taint-tracking coverage. Other supported languages
  currently receive parser-backed checks, not equivalent taint tracking.
- Static reachability may not resolve dynamic dispatch, reflection, callbacks,
  or runtime-generated calls.
- Optional CPG-GNN confidence is experimental, informational, and does not
  change the deterministic findings or policy gate.
- The analyzer does not execute uploaded source code.
