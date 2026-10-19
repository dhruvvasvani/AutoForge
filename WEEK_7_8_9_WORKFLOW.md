# AutoForge AST/ML Track — Weeks 7, 8, 9: Workflow & Cross-Team Connections

Per the official 16-week plan. Day-by-day build sequence, what AST hands
to / receives from Backend, Pipeline, and Frontend+AI Fix, and the real,
currently-verified status of each piece — not a projected plan.

**Track:** AST — Dhruv Vasvani

## Live verification note

While preparing this document, the real pipeline was run end to end
against a real external repository (OWASP's own registry-listed
vulnerable app, `anxolerd/dvpwa`) using real Semgrep rules pulled from
Semgrep's official rules repo — not fixtures. This surfaced and fixed one
genuine bug: class-qualified method calls (`Student.create(...)`) weren't
resolving to their real definitions because the matcher only checked for
a `::funcname` suffix, not the `.funcname` shape a class-qualified call
produces. Fixed and re-verified — both real findings now tag correctly as
`REACHABLE_CODE` with the right depth. Detail in the Week 7 section below.

---

## Week 7 — Real Scanning + Reachability Wiring

**Plan goal:** Get Semgrep, Checkov, and the AST engine running on real
cloned code with a fixed data contract.

### Day-by-day

| Day | AST builds | Status |
|---|---|---|
| Mon | Publish `/analyze` contract: `{repo_path, findings[]}` → `{tagged_findings[]}` | ✅ DONE |
| Tue | Build FastAPI `/analyze` endpoint wrapping the reachability engine | ✅ DONE |
| Wed | Remove sample_data reliance from the service's production code path | ✅ DONE |
| Thu | Replace the fake test suite (22 defs, 1 real assert) with real assertions | ✅ DONE |
| Thu (cont.) | Real-world validation run: real Semgrep + real rules + real external repo through the engine | ✅ DONE |
| Fri | **Joint checkpoint**: push a real repo → Semgrep/Checkov run for real → AST tags for real, confirmed non-identical to any sample | 🟡 PARTIAL: Semgrep + AST verified live; Checkov-positive IaC case remains |

### Connections this week

| From → To | What crosses | Status |
|---|---|---|
| AST → Pipeline | `/analyze` contract (`CONTRACT.md`): `repo_path` + `findings[]` in, `tagged_findings[]` out | Published |
| Pipeline → AST | Worker sends the checkout path and scanner findings through `/analyze` and `/score` | Implemented and covered by worker tests; verified live with Semgrep on two local repositories |
| AST → Backend | `DIRECT_EVAL` as a third reachability value (IaC/config findings) — backend must not treat it as noise | Persisted distinctly alongside tag and scoring metadata; locally covered by the backend regression test |

### Real-world verification performed this week

Ran the actual pipeline against `anxolerd/dvpwa` (OWASP Vulnerable Web
Applications Directory entry, real known SQLi + weak-hash vulnerabilities):

- Installed real Semgrep (v1.179.0) in an isolated environment, pulled real
  rule files directly from Semgrep's official rules repository (not the
  registry API, which this environment can't reach)
- Found 2 genuine findings: a real SQL-injection pattern in `student.py`
  (string-`%` formatting straight into a SQL string before `execute()`) and
  a real weak-MD5-password-hash pattern in `user.py`
- Normalized both to the project's finding schema using the same
  line-mapping heuristic as the backend `scan_wrapper` — correctly
  identified the enclosing functions (`create`, `check_password`) with
  zero manual correction needed
- Ran real cross-file reachability using the app's actual route-handler
  entry points (`index`, `students`, `student`, `courses`, `course`,
  `review`, `evaluate`, `logout`) — built a real 263-function call graph
  across 21 real files
- First run: both real findings came back `UNREACHABLE_NOISE` — wrong,
  since both are reachable from real route handlers by inspection of the
  source
- Root-caused it: both vulnerable functions are called class-qualified
  (`Student.create(...)`, and `check_password` is reached via
  `user.check_password(password)`), and the matcher that links a flat
  finding (`"function": "create"`) back to its graph node only recognized
  the `module::funcname` shape, not the `module::ClassName.funcname` shape
  a class-qualified call produces
- Fixed with a one-line broadened suffix match in
  `src/cross_file/engine.py`; re-ran — both findings now correctly tag
  `REACHABLE_CODE` with depth 1

> This is exactly the kind of bug synthetic test fixtures don't surface —
> real OOP code calling class/static methods is extremely common and the
> small hand-written test projects used earlier in this track didn't
> happen to exercise that call shape.

---

## Week 8 — Storage + ML Prioritization

**Plan goal:** Findings get scored and stored automatically, with no
manual step in between.

### Day-by-day

| Day | AST builds | Status |
|---|---|---|
| Mon | Publish `/score` contract: thresholds in config, not hardcoded in either scorer | ✅ DONE |
| Tue | Train real scikit-learn model on labeled ground-truth data | ✅ DONE |
| Wed | Wire `/score` into the FastAPI service, config-driven P0–P3 cutoffs | ✅ DONE |
| Thu | Backend persists tagged + scored findings against the correct Scan row | ✅ Implemented; persistence regression and live H2 verification passed |
| Fri | **Joint checkpoint**: full chain on 2 real repos side by side, confirm no cross-contamination in the DB | ✅ LOCAL CHECKPOINT |

### Connections this week

| From → To | What crosses | Status |
|---|---|---|
| Pipeline → AST | Auto-chain call: scan done → `POST /analyze` → `POST /score`, no manual trigger between stages | Implemented and covered by worker tests; live Backend integration verified on two local repositories |
| AST → Backend | Scored findings with `priority` (P0–P3) + `scoring_method` (`ml` / `rule_based_fallback`) so Backend/Frontend can tell which path scored a finding | Contract, persistence mapping, and local H2 verification complete |

### Joint checkpoint evidence (2026-10-06)

- Ran real Semgrep scans on two distinct local repositories: AutoForge's
  intentionally vulnerable upload demo (1 finding) and Requests' auth module
  (2 findings).
- Submitted each result set to a separate Backend scan row. Backend called
  AST `/analyze` and `/score`, then persisted all three enriched findings in
  its local H2 database.
- Queried H2 directly: scan 1 contains only the AutoForge finding, tagged
  `REACHABLE_LIVE_FLAW`; scan 2 contains only the two Requests findings,
  tagged `UNREACHABLE_NOISE`. Each row has priority and scoring method.
- Fixed a local Java `HttpClient` transport issue: its default request
  configuration delivered bodyless requests to Uvicorn here. Explicit
  HTTP/1.1 with a UTF-8 byte-array publisher restored the JSON body.
- Checkov is installed, but these code-only repositories produced no
  Checkov findings. A Checkov-positive IaC repo remains a follow-up case.

### The real model, briefly

Trained on OWASP Benchmark for Java — 2,740 real labeled test cases,
ground-truth true/false vulnerability, 11 CWE categories.
RandomForestClassifier, held-out test result: 72% accuracy, 0.82 ROC-AUC.
Top learned features are sanitizer-related (`sanitizer_count`,
`has_sanitizer`) — the model is learning the actual security-relevant
pattern, not memorizing category labels. Falls back to the rule-based
matrix when a scanner rule can't yet be mapped to one of the 11 trained
categories — always tagged `scoring_method` so nothing is silently faked.

---

## Week 9 — AI Fix Generation Goes Live

**Plan goal:** Only CRITICAL/HIGH prioritized findings ever reach the AI —
the actual noise-reduction promise of the project.

### Day-by-day

| Day | AST builds | Status |
|---|---|---|
| Mon–Tue | Context-extraction helper: given a finding, return the exact function/code block to send to Gemini (reuses the existing `extract_functions` utility, not a re-parse) | ❌ NOT DONE — next up |
| Wed | Publish the helper's output shape to Backend (function source + surrounding lines) | ❌ NOT DONE |
| Thu | Backend's `FixService`/`GeminiClient` calls the helper before calling Gemini | Backend's side, depends on Wed |
| Fri | **Joint checkpoint**: a real repo end to end, confirm an actual AI-generated fix appears in the DB and renders correctly, not a placeholder string | 🟡 JOINT |

### Connections this week

| From → To | What crosses | Status |
|---|---|---|
| Pipeline → AST | After ML scoring, auto-enqueue a fix-generation job only for CRITICAL/HIGH findings — AST's helper gets called as part of that job | Depends on Week 8's auto-chain existing first |
| AST → Backend | Extracted code context (function source + line range) for a given finding, in the shape Gemini needs | Not yet built — this is Week 9's actual AST deliverable |

Nothing to report as built here yet — Week 9 genuinely hasn't started.
Listed with the same day-by-day structure as 7 and 8 so the plan is ready
to execute against once Week 8's joint checkpoint closes.

---

*Every ✅ DONE status in this document reflects code that was actually run
during preparation, including a live run against a real external
repository with real Semgrep output — not read off a prior report. 🟡
JOINT items are not achievable by the AST track alone by the plan's own
definition.*
