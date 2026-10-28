# Week 12 AST Optimization and Handover

## Delivered in the repository

- Tree-sitter parsing now caches a bounded number of per-file syntax trees,
  returns the cached result for unchanged contents, and incrementally reparses
  edited files. The cache uses resolved file path and language as its identity;
  callers that do not provide a file path still receive a normal full parse.
- Python project indexing keeps parsed module trees and source text for reuse by
  cross-file resolution and taint analysis. A content digest invalidates changed
  modules, and the shared LRU cache is bounded by an estimated memory budget.
  Project file reads and parsing use a bounded thread pool.
- CPG graph construction is parallelized with at most four worker threads.
  Encoder/model work remains batched and inference remains serialized by the
  request, avoiding concurrent model execution on the GPU.
- Backend roles now include `USER`, `LEAD_DEVELOPER`, `SECURITY_AUDITOR`,
  `FACULTY`, and `ADMIN`. Registration remains `USER`. Admin-only mutations
  include user status/role/plan changes, user deletion, and plan-request
  decisions; faculty retains access to legacy admin GET endpoints. Security
  auditors may access admin GET endpoints but cannot mutate records.
- The frontend route guard accepts one required role or a list of acceptable
  roles. Backend authorization remains the enforcement boundary.
- Swagger UI documents JWT bearer authentication.
- A benchmark script compares scanner findings and AST-filtered findings
  against labeled ground truth. It reports precision, recall, F1, false
  positives/negatives, and false-positive reduction without inventing results.

## Running the benchmark

Prepare three JSON files: scanner baseline, AST-filtered output, and a
ground-truth list containing only confirmed true findings. Each file may be a
JSON array or an object with a `findings` or `tagged_findings` array. Findings
must include `file`, integer `line`, and `rule_id`. Matching is exact after
normalizing path separators; line/rule mapping differences must be resolved
before comparing datasets.

```powershell
python 3_ast_analyzer\scripts\benchmark_reachability.py `
  --baseline path\to\scanner.json `
  --ast-filtered path\to\ast-filtered.json `
  --ground-truth path\to\confirmed-findings.json
```

The report is meaningful only when all three inputs use the same project
revision, file path conventions, and finding identity. Report confidence
intervals or per-project breakdowns before using the results as a capstone
claim. No benchmark was run by this code change because no independent labeled
baseline/ground-truth bundle was supplied.

## Verification still needed outside this change

- Run the benchmark on an independent, license-cleared dataset and retain the
  exact inputs, commit, and generated JSON report.
- Run backend authorization tests with real JWTs for each role and confirm
  role assignment is performed by an administrator. New role values fit the
  existing `users.role` string column; review production migration strategy
  before applying schema changes to Neon.
- Measure parse and inference latency on a representative large repository,
  comparing cache hits and misses under the same runtime and hardware.
- Validate the Compose deployment and container health checks with Docker
  Desktop running. Docker was unavailable during implementation.
- Decide whether lead developers and security auditors need dedicated
  frontend pages/actions; the current frontend has a generic route guard but
  no role-specific admin/audit screens.

## Architecture and security notes

The analyzer API remains synchronous for direct dashboard requests. The
Redis-backed pipeline worker owns queued repository scans; this work does not
add WebSocket progress streaming. CPG scores remain informational and do not
change deterministic findings or policy-gate decisions. Role checks in React
are UX only; Spring Security and method-level authorization enforce access on
the server.
