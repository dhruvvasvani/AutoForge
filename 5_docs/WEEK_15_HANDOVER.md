# 16-Week AST Analyzer Workflow Audit

## Overall assessment

The repository contains a substantial, tested AST/security-analysis foundation
and pieces of the later DevSecOps and MLOps workflow. It does **not** implement
the full 16-week target as an integrated, production-validated autonomous
platform. In particular, Week 16 is not implemented, and Weeks 13–15 provide
limited or manually operated capabilities rather than autonomous operation.

Status meanings:

- **Partial** — a related capability exists, but important scope, integration,
  trust, or operational requirements from the roadmap are not met.
- **Not implemented** — no corresponding implementation was found.

## Week-by-week status

| Week | Status | Verified implementation and boundary |
| --- | --- | --- |
| 1 — Parser setup | Partial | Python is parsed with the standard-library `ast`; Java and JavaScript use Tree-sitter through a normalized parser facade. This is not a Tree-sitter parser for every language, and language analysis depth differs. |
| 2 — Heuristic noise filtering | Partial | AST-based filtering/scoring components exist. The noise-filter model fails open when untrained, and no independent, measured noise-reduction result is provided. |
| 3 — Control-flow and reachability | Partial | CFG construction, entry-point reachability, and reachable/unreachable labels exist, with tests for Python examples. Dynamic dispatch, complete language coverage, and exact execution paths are not established. |
| 4 — Pipeline CLI | Partial | `week4_pipeline/pipeline_cli.py` provides a CLI for single-file and cross-file analysis. It is not proof of one fully unified production pipeline across every scanner, language, and service. |
| 5 — Cross-file tracing and risk scoring | Partial | Python imports, statically resolved calls, taint propagation, reachability, and finding scoring exist. Dynamic imports, general polymorphic resolution, and cross-repository or REST/gRPC call edges are not implemented. |
| 6 — CPG-GNN training | Partial | Python CPG construction, dataset loading/splitting, training/inference code, and a checkpoint (`src/ml/cpg_gnn_full_10epoch.pt`) exist. The graph uses AST, approximate CFG, and lexical DFG edges; the repository does not establish model quality, production calibration, or enterprise-scale performance. |
| 7 — AI fix generation | Partial | The GitHub PR worker can optionally request suggestions from a separately configured `AI_FIX_URL` and include them in review comments. There is no demonstrated backend service named `ai-fix-service`, nor safe patch application, regression verification, or rollback. |
| 8 — Backend and persistence | Partial | Spring Boot APIs and database-backed scan/repository records exist. The complete AST graph and scored analyzer output are not demonstrated as a durable, end-to-end persisted product contract. |
| 9 — Webhook and changed-code ingestion | Partial | Signed GitHub pull-request events, changed-file/diff analysis, static scanners, AST/taint analysis, status/review reporting, and a separate queued pipeline exist. Coverage is not equivalent to full multi-language, cross-repository analysis. |
| 10 — Quality gates and executive reports | Partial | A CLI quality gate and HTML/PDF report generation exist. A checked-in CI workflow and branch-protection enforcement are not established by this audit; no independent noise-reduction benchmark is supplied. |
| 11 — Containers and asynchronous work | Partial | Docker/Compose and background workers exist; the repository has a Redis-backed pipeline queue and a separate SQLite-backed PR-job queue. The direct analyzer API remains synchronous. WebSocket progress streaming and production-scale orchestration are not implemented or validated. |
| 12 — Optimization and RBAC | Partial | Bounded parser/index caches, incremental parsing, batched/local GNN inference, and backend role enforcement exist. Representative large-repository performance results and production deployment validation are absent. |
| 13 — Feedback and MLOps | Partial | Authenticated feedback collection, administrator review, candidate training, and manual checkpoint promotion/reload components exist. Automated durable retraining triggers, automated quality-based promotion, and zero-downtime production rollout are not established end to end. |
| 14 — Runtime tracing and self-healing | Partial | The analyzer accepts caller-supplied runtime function names and marks matching statically reachable findings for priority. It does not collect or authenticate APM/eBPF traces, verify revision/freshness, create patches, or automatically commit/merge PRs. |
| 15 — Threat intelligence and provenance | Partial | Optional source SHA-256 matching and partial CWE-to-OWASP evidence are implemented. No live CVE/NVD feed, CVE-to-component matching, signature verification, trusted manifest, distributed inference, or SOC 2/ISO compliance dashboard was found. |
| 16 — AST mutation and quantum-safe analysis | Not implemented | No adversarial AST mutation-testing engine, PQC/weak-cryptography reachability analysis, or autonomous detect-verify-patch-deploy loop was found. |

## Status of the four technically difficult components

| Component | Status | What is present; what is not |
| --- | --- | --- |
| Cross-file and multi-language call graphs | Partial | Python static import/call resolution, selected inheritance cases, taint propagation, and reachability are tested. This is not general dynamic or polymorphic resolution; Java/JavaScript syntax parsing does not imply equivalent call-graph/taint analysis. No service-contract-based gRPC/REST or cross-repository graph construction was found. |
| CPG-GNN features and training | Partial | Python graph construction, dataset preparation, grouped/stratified splits, model code, inference, and a checkpoint are present. CFG/DFG construction is explicitly approximate/lexical. Passing unit tests does not establish representative data quality, leakage-free real-world evaluation, calibrated vulnerability prioritization, or scalable multi-node inference. |
| Context-aware remediation and patch verification | Partial, with verification workflow not implemented | Optional AI suggestions can be attached to PR findings. No AST mutation/patch application pipeline, isolated patch execution, automated pytest/JUnit regression check, fail-safe rollback, or automatic merge was found. Suggestions must not be presented as verified fixes. |
| Queueing and worker orchestration | Partial | There are separate Redis and SQLite queues, worker processes, retries/status reporting, and container definitions. The analyzer API itself remains synchronous; no WebSocket progress stream or evidence of production load/failure testing was found. |

## Capabilities explicitly not done

- Live threat-intelligence ingestion and auditable CVE-driven risk
  reprioritization. A threat match must not be treated as proof of code
  reachability.
- Authenticated source/package provenance: trusted signer identity, signed
  manifests, key rotation/revocation, and signature verification before
  parsing. An optional digest only checks that source text matches that digest.
- Distributed, multi-node GNN inference and validated enterprise-scale
  throughput.
- SOC 2 and ISO 27001 control mapping or a live regulatory compliance
  dashboard. The existing OWASP output is partial finding evidence, not a
  compliance assessment.
- Adversarial AST mutation testing and post-quantum cryptographic dependency
  tracing.
- Verified autonomous remediation: patch synthesis/application, isolated
  regression validation, automatic PR merge/deployment, and a complete
  self-healing loop.
- A completed production-readiness proof for the complete platform, including
  enforced CI policy, representative scale/failure testing, and operational
  telemetry validation.

## Verification performed

Ran the analyzer and pipeline test suites from the repository root:

```powershell
.venv\Scripts\python.exe -m pytest 3_ast_analyzer\tests 2_pipeline\tests -q
```

Result: **173 passed**. These tests verify covered component behavior; they do
not prove production deployment, external service configuration, model
effectiveness on independent data, large-scale capacity, or end-to-end
autonomous operation. No production environment or independent labeled
benchmark was available for this audit.
