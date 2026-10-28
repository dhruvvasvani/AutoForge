# Week 13 MLOps and Post-Deployment Handover

## Implemented

- The local dashboard offers explicit `Mark false positive` and
  `Confirm vulnerability` actions for Python findings. Submitting a label
  requires a signed-in account and sends a source excerpt of at most 16,000
  characters to the Spring Boot backend. The UI discloses this retention.
- Backend feedback is owned by the authenticated user, deduplicated by
  account/finding key, and starts in `PENDING`. Administrators can review,
  approve, or reject it. User-dismissal alone is not treated as ground truth;
  only approved rows can be included in a candidate training set.
- The database migration is `V9__add_reviewed_finding_feedback.sql`. Admin
  endpoints expose pending/approved queues and an untrained-only filter.
  `/api/admin/mlops/feedback/summary` reports the number of approved,
  not-yet-trained examples and whether the 500-example threshold is reached.
- Rust is now a supported Tree-sitter grammar in the analyzer's source API.
  `/api/v1/parser-health` reports observed language/node types, parse errors,
  and cache statistics for this process. Syntax errors are logged.
- The webhook service health response includes durable queue counts.
- Approved feedback can be used to train a versioned candidate, never
  activated automatically. A separate command atomically promotes a manually
  reviewed candidate; inference reloads the checkpoint when its file changes,
  without restarting the analyzer process.

## Feedback and candidate workflow

1. A developer signs in, reviews a Python finding, and explicitly submits a
   false-positive or confirmed-vulnerability label. The source excerpt is
   persisted in PostgreSQL for review/training. Avoid submitting code that
   contains secrets or data that should not be retained.
2. An administrator reviews feedback through `GET /api/admin/mlops/feedback`
   and approves or rejects each row with
   `PATCH /api/admin/mlops/feedback/{id}` and body `{"status":"APPROVED"}` or
   `{"status":"REJECTED"}`. Use the `APPROVED` and `untrainedOnly=true`
   query when exporting candidate data.
3. Check `GET /api/admin/mlops/feedback/summary`; at least 500 approved,
   untrained, syntax-valid Python examples are required by default, with both
   labels represented. Save the admin response array as
   `approved-feedback.json` and run:

   ```powershell
   python 3_ast_analyzer\scripts\train_feedback_candidate.py `
     --feedback path\to\approved-feedback.json `
     --baseline path\to\license-cleared-baseline.csv `
     --candidate path\to\cpg_gnn_candidate_v2.pt
   ```

   The command reports feedback IDs used and validation/test metrics. Invalid
   Python snippets are excluded; their IDs are not included in the output.
   The training dataset temporary file is removed after the run. Review the
   candidate and validation metrics against a clean, independent baseline
   before promotion. The model's existing split/quality limitations still
   apply; do not infer production quality from the training run alone.
4. After a successful candidate build, mark only the included IDs as consumed:
   `POST /api/admin/mlops/feedback/trained/batch` with
   `{"feedbackIds":[...]}`. Failed runs leave feedback eligible for another
   attempt.
5. After a separate human quality review, activate the model:

   ```powershell
   python 3_ast_analyzer\scripts\promote_checkpoint.py `
     --candidate path\to\cpg_gnn_candidate_v2.pt `
     --active path\to\configured\cpg_gnn_model.pt
   ```

   Configure `CPG_GNN_CHECKPOINT` to the active path. Promotion stages a copy
   in the same directory and atomically replaces the active file. The analyzer
   loads the new checkpoint for subsequent inference requests; requests already
   using the previous model can finish with it.

For PostgreSQL admin API access, authenticate normally and use the bearer
token; do not put credentials in the frontend or training artifacts.

## Still pending

- The 500-sample threshold is monitored, not an automatic asynchronous trigger.
  A durable queued training job, worker lifecycle/status API, retry policy, and
  notification are still needed before claiming end-to-end automated MLOps.
- Candidate validation is reported, but automated comparison against a
  registered production baseline and enforced promotion criteria are not yet
  implemented. Promotion deliberately remains manual.
- Parser observations and syntax failures are exposed/logged by the analyzer
  process, not yet persisted in PostgreSQL. Cross-service parser/worker anomaly
  aggregation, alerts, and self-healing actions remain future work.
- Rust support currently provides syntax/tree observations, not Rust
  vulnerability taint/reachability analysis. Other language support should
  not be represented as equivalent Python analysis.
- The webhook API reports queue counts; alert thresholds, service-level
  dashboards, and an operator recovery workflow still need deployment tests.
- Run backend migration/authorization tests and validate model replacement
  under real inference traffic before production rollout.
