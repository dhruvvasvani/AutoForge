# AutoForge AST Analyzer

The canonical analyzer implementation is in `src/`. It currently provides
Python AST parsing, scope-aware symbol collection, control-flow graphs,
intra-procedural taint analysis, Python cross-file taint propagation,
reachability tagging, scoring, ML feature extraction/inference, and SARIF
reporting.

Python taint analysis is implemented for Python source. Java, JavaScript,
TypeScript, TSX, Go, Rust, and SQL are supported for parser-backed syntax
checks, but
taint tracking for those languages, a recovered training dataset, and trained
model weights are not currently included.

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

The standalone frontend route at `/analyze` submits selected project files to
this loopback-only service without requiring the account backend; scan history
and feedback synchronization are optional. The signed-in dashboard uses the
same analyzer. Python files receive AST, taint, CFG, and cross-file reachability
analysis; other supported languages receive parser-backed syntax checks.
Non-Python security checks depend on Semgrep's `p/default` rules, while Checkov
checks infrastructure configuration; a completed scan with zero findings is
not a guarantee that a project is vulnerability-free. Python reachability starts
from configured function names and common HTTP route
decorators; unresolved findings remain unverified instead of being treated as
dead code.
Some accepted project files, including HTML, CSS, and configuration formats,
are scanner-only and are not represented in the AST coverage count.
Optional CPG-GNN
predictions are informational and never replace deterministic findings or
change the policy gate. The analyzer does not execute submitted code.
The UI shows only findings returned by the analyzer; service or scan failures
never generate sample findings. Its countdown is a rough client-side estimate,
not streamed analyzer progress.
The dashboard's AI-fix handoff exports the actual scan findings and bounded
source excerpts as JSON, or copies a prompt for an external coding assistant.
It does not call an AI service or edit project files. The GitHub pipeline's
separate AI-fix integration is disabled in the default Compose configuration.
Project-scan clients may provide an expected SHA-256 digest per source file;
the analyzer rejects mismatches and reports missing digests as unverified.
This digest check is not a signature or source-authentication mechanism.
Responses also include partial CWE-to-OWASP finding evidence, not a compliance
assessment. See [the Week 15 handover](../5_docs/WEEK_15_HANDOVER.md).

### Week 11 service operations

The analyzer API is containerized by `Dockerfile` and is included in the root
`docker-compose.yml`. In the full scan path, the Redis-backed worker in
`2_pipeline` owns background scan execution and reports progress to the backend;
the analyzer HTTP endpoints themselves remain synchronous. Start the local
stack from the repository root with Docker Desktop running:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Set strong local values in `.env` before starting. The analyzer exposes
`/health` and `/readyz` for health probes and `/metrics` for Prometheus-format
request, scan-duration, inference-duration, finding-count, and memory metrics.
The Compose stack starts Prometheus, available locally at
`http://localhost:9090`, and scrapes the analyzer every 15 seconds. The scan
API's SQLite history is local dashboard telemetry, not the production-of-record
scan database.

To enable CPG-GNN inference, Place your compatible checkpoint under `3_ast_analyzer/src/ml`, then set
`CPG_GNN_CHECKPOINT` in `.env` to
`/models/checkpoints/cpg_gnn_full_10epoch.pt`. Compose mounts
`3_ast_analyzer/src/ml` at `/models/checkpoints` and the local CodeBERT files
at `/models/codebert-base`. The checkpoint must be present on the host. Model
load failures are reported in the scan's `model` status while non-ML AST
analysis continues. Confidence is file-level telemetry, not a vulnerability
verdict.

The analyzer service does not maintain its own Redis queue: requests from
automated repository scans are made by the pipeline worker after it dequeues a
job. Direct dashboard requests are synchronous and can take longer for large
projects.

### Week 10 metrics, reports, and quality gate

Successful local scans expose aggregated metrics and persist a bounded recent
history in `~/.autoforge/scan_history.sqlite3` (override the location with
`AST_SCAN_HISTORY_DB`). The dashboard reads `/api/v1/metrics/history` and
generates downloadable HTML or PDF executive summaries through
`/api/v1/reports`. When signed in, it also synchronizes aggregate-only metrics
to the authenticated Spring Boot backend (`POST /api/scan-metrics`), where
history is scoped to the user account; source code and findings are not sent.
PDF output requires the installed `reportlab` dependency.

Run the CI gate against the analyzer's JSON findings output:

```powershell
python 3_ast_analyzer\src\reporting\pipeline_gate.py path\to\scored_results.json
```

The command exits with status 1 when a finding exceeds the configured risk
threshold or has a configured blocking severity; explicitly unreachable noise
is reported but does not block. The default maximum risk score is 8 and
`CRITICAL` findings block. A GitHub Actions workflow and repository branch
protection are still required to enforce this command on pull requests.
The reachability CLI keeps findings whose function cannot be resolved, or whose
analysis was truncated by a depth limit, in `unverified_findings` rather than
discarding or classifying them as unreachable noise.

CPG-GNN inference is opt-in for the local project analyzer. Set
`CPG_GNN_CHECKPOINT` to a compatible checkpoint; the configured CodeBERT model
must be available locally or downloadable in that environment. File-level
confidence is displayed as informational telemetry and does not change finding
reachability or quality-gate outcomes.

## GitHub pull-request scanning

The production webhook and worker in `src/deployment` accept signed
`pull_request` events and analyze added diff lines. The worker fetches only
changed file contents into an isolated temporary directory, runs Semgrep on
those files and Checkov when changed IaC files are present, then combines
scanner findings with Python taint analysis before posting inline review
comments, a commit status, and SARIF. Required scanner failures fail the
security gate by default; set `STATIC_SCANNERS_REQUIRED=false` only when a
degraded scan is intentional. The production container installs both scanners.
The separate push-event ingestion path remains in `2_pipeline/webhook` and
queues repository scans through the pipeline worker.

Start the pull-request webhook receiver and its background worker locally by
setting `WEBHOOK_SECRET`, `GITHUB_REPOSITORY`, and `GITHUB_TOKEN` in the root
`.env`, then running:

```powershell
docker compose --profile github up --build webhook ast-worker
```

The receiver is published on `127.0.0.1:8091` by default; change the host port
with `AUTOFORGE_WEBHOOK_PORT`. GitHub cannot deliver to localhost directly, so
use a trusted HTTPS tunnel or deploy the receiver, then configure the public
URL ending in `/api/v1/github/events` in GitHub. The dashboard health check
verifies receiver configuration, queue health, and worker credentials, but
cannot confirm that the background worker process is actively running. Keep
the GitHub token and webhook secret server-side.

Optional AI remediation is disabled unless `AI_FIX_ENABLED=true` and
`AI_FIX_URL` are configured. Successful suggestions are included in inline
review comments for high/critical Python findings. The worker never commits
generated code or pushes to a repository.

The separate GitHub pull-request worker does not currently load a CPG-GNN
checkpoint. Its reachable findings come from the Python taint engine; the
checkpoint integration described above currently applies to the analyzer API,
not the PR worker.

### Manually scan a GitHub repository

From the signed-in dashboard, enter a public GitHub repository as
`owner/repository` and select **Connect**, then choose **Fetch latest & scan**.
The backend resolves its default branch and latest commit through the GitHub
REST API and queues that exact commit through the existing Redis-backed
pipeline worker. The dashboard reports progress and, when complete, shows
persisted scanner findings with AST reachability and risk-priority metadata.
This is finding-level analysis, not a rendered AST browser or a guarantee that
all vulnerabilities will be detected. Private repositories are not supported
because the application does not currently configure server-side GitHub
credentials; never paste a personal access token into the browser. The scan is
read-only: it does not apply fixes, commit, push, or merge changes. Any
remediation and push remain a manual developer action.

## Train the AST feature classifier

The classifier trains on labeled source code and the same 16 structural AST
features used during analyzer scans. Use Python, Java, or JavaScript samples
with a binary `label` (`1` vulnerable, `0` non-vulnerable). JSON rows use
`code` (or `source`) and `label`; CSV files can use `function_code` and
`class`/`label`. PyCode-Vul CSVs with `vulnerable_function_source`,
`patched_function_source`, and `label`/`class` are supported; patched samples
are added as label `0` and kept in the same data split as their original.

In Kaggle, enable a GPU notebook accelerator, attach/download a dataset, then
install the focused dependencies and run from the analyzer directory:

```bash
pip install -q torch tree-sitter-language-pack
python -m src.ml.ast_training --dataset /kaggle/input/pycode-vul/train.csv \
    --checkpoint /kaggle/working/ast_classifier.pt --max-epochs 50
```

Download PyCode-Vul from its [project repository](https://github.com/soarsmu/PyCode-Vul).
The [CodeXGLUE Devign dataset](https://github.com/microsoft/CodeXGLUE/tree/main/Code-Code/Defect-detection/Devign)
and [Big-Vul dataset](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset)
are additional open research datasets, but they primarily contain C/C++ and
need language/column adaptation for this trainer. Check each dataset's license
and terms before redistribution or commercial use.

The script prints held-out test metrics and writes a checkpoint consumable by
`ASTInference.from_checkpoint`. The standalone AST classifier is not currently
connected to production scan scoring; using its predictions in scans requires
an explicit integration step. Do not treat synthetic demo data as model quality
evidence.

The separate CPG-GNN is implemented by `src/ml/cpg_training.py`. A
10-epoch checkpoint was trained from the prepared PyCode-Vul data in Kaggle,
but prior pilot runs reused examples from the official test CSV. Therefore its
reported test metrics are exploratory, not an independent final evaluation.
Retrain/evaluate after reserving a genuinely untouched test set before making
quality claims or relying on the model. The trainer keeps exact duplicate source
snippets in the same internal split and rejects exact source overlap between
training/validation data and an explicitly supplied held-out test dataset.

### Week 11 remaining work

| Area | Current status | Remaining work |
|---|---|---|
| AST container | Analyzer API Dockerfile, Compose service, health/readiness probes, and Prometheus metrics are present. | Build and exercise the complete stack in CI and a deployment-like environment; test shutdown, restart, and persistent volumes. |
| Async scans | The pipeline worker consumes Redis scan jobs and persists coarse progress through the backend. The AST API runs synchronously when called. | Add a job-status API for direct dashboard scans if they must be asynchronous; define retry, dead-letter, cancellation, and idempotency behavior consistently across services. |
| Progress streaming | Pipeline emits Redis stage events and the backend stores latest progress. | Add durable event history and a WebSocket/SSE stream if real-time push is required; currently the UI does not receive a Redis event stream directly. Add explicit GNN-stage progress. |
| CPG-GNN serving | Analyzer API can load the configured checkpoint and local CodeBERT encoder; predictions are informational. | Complete clean held-out evaluation, monitor latency/memory, and decide whether the separate GitHub PR worker should use the model. |
| Database | Compose provides local PostgreSQL for the backend; analyzer scan history remains local SQLite telemetry. | Configure and verify Neon credentials/TLS, migrations, backup/retention, connection-pool sizing, and production persistence. Keep the backend as the production system of record. |
| AST webhook worker | `src/deployment` has a separate durable SQLite-backed GitHub PR queue. | Decide whether to retain this distinct ingestion path or migrate it to the shared Redis queue; document delivery and retry guarantees. |
| Logging/operations | Services write application logs to container output and expose health/metrics endpoints. | Add centralized log collection, dashboards/alerts, secrets management, rate limits, and production access controls. |
| AI context extraction | The Week 9 finding-to-function context helper is not complete. | Implement the AST context extractor and publish its request/response contract to the backend fix service. |

### Week 12 AST optimization and governance

The analyzer now uses bounded Tree-sitter per-file incremental parsing, a
content-validated cache for Python project ASTs, bounded parallel project
parsing, and parallel CPG graph construction before batched GNN inference.
Backend role controls include `LEAD_DEVELOPER` and `SECURITY_AUDITOR`; the
React route guard can check one role or an accepted-role list. Swagger
documents JWT bearer authentication.

#### Week 2 noise-filter benchmark

Run the analyzer's taint findings and reachability filter against the checked-in
OWASP Benchmark for Python v0.1 labels:

```powershell
python 3_ast_analyzer\scripts\benchmark_owasp_python.py
```

The current checked-in run has 1,230 cases (452 labeled vulnerable): 17 cases
are flagged, with 7 true positives and 10 false positives (41.18% precision,
1.55% recall, 0.0299 F1). Reachability removes 0 cases, so the measured false
positive reduction is 0%. These are case-level results for this older,
checked-in benchmark and this analyzer configuration; they are not a claim of
production quality. In particular, low recall means this result does not
support using the analyzer as a complete vulnerability detector.

The implementation and handover checklist are in
[5_docs/WEEK_12_AST_HANDOVER.md](../5_docs/WEEK_12_AST_HANDOVER.md). Run the
reproducible findings comparison only with aligned baseline, AST-filtered, and
independently labeled ground-truth JSON files:

```powershell
python 3_ast_analyzer\scripts\benchmark_reachability.py `
  --baseline path\to\scanner.json `
  --ast-filtered path\to\ast-filtered.json `
  --ground-truth path\to\confirmed-findings.json
```

The OWASP benchmark above does not measure large-repository latency or
generalize to an independent production corpus. Do not infer either from its
results.

### Week 13 feedback and MLOps

The local dashboard can submit explicitly confirmed Python finding feedback
to the authenticated backend. The backend retains a bounded source excerpt,
requires administrator approval before training use, and exposes the reviewed
feedback threshold. Rust syntax parsing and a parser-health endpoint are also
available. Candidate model training and manual atomic promotion are documented
in [5_docs/WEEK_13_MLOPS_HANDOVER.md](../5_docs/WEEK_13_MLOPS_HANDOVER.md).
Training is not yet a durable asynchronous auto-trigger; approved labels must
be reviewed, exported, trained, evaluated, and manually promoted.

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
