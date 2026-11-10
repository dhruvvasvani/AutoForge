# AutoForge

AutoForge is a Phase 1 DevSecOps project for scanning source code, explaining
security findings, reducing noise with static analysis and reachability
evidence, and supporting review of suggested remediations.

**Course:** Project-I, CSE/IT, Government Engineering College, Ajmer

**Team:** Dhruv Vasvani, Birendra Nagar, Abhishek Vijayvargiya, Kartik Sharma

**Demo 2:** 4 November 2026

## Problem Statement

Security scanners generate a large volume of alerts from GitHub repos, leading
to severe alert fatigue and reduced trust in the output. Many teams rely on
slow manual reviews or incomplete triage, which makes it difficult to identify
real risks quickly and act on them with confidence.

AutoForge addresses this by combining static-analysis evidence, reachability
checks, and remediation support in a single workflow built for secure code
review and developer trust.

## Product Vision

AutoForge scans GitHub repositories, inspects code with static analysis, and
prioritizes findings using severity, reachability, and contextual evidence. The
platform helps engineers review security alerts faster while keeping the review
flow transparent, explainable, and actionable.

## Phase 1 Architecture

```text
GitHub Repo -> Webhook / Scanner Trigger -> Scan Pipeline -> AST Analyzer
                 |                             |                     |
                 v                             v                     v
           Spring Boot API               Redis Queue Worker      Security Findings
                 |                             |                     |
                 v                             v                     v
             PostgreSQL + Storage         Semgrep + Checkov     Reachability + Taint Analysis
                 |                                           |
                 v                                           v
             Frontend Dashboard + Analyzer UI           SARIF + Risk Scoring
```

### Core components

- GitHub repository ingestion and project lifecycle handling
- Scan pipeline with CI-like job orchestration and work queueing
- Static analyzer for Python taint tracking and risk scoring
- Reachability evidence and file-level finding explanations
- Frontend dashboard and standalone analyzer review flow

## Team Roles & Task Split

| Role | Member | Primary responsibilities |
|---|---|---|
| Backend & Lead Integration | **Abhishek Vijayvargiya** | Spring Boot APIs, project lifecycle, repository workflow, authentication, webhook handling, and integration glue |
| GitHub & Scan Pipeline | **Birendra Nagar** | Semgrep/Checkov orchestration, Redis workers, exact-commit handling, aggregation, and stage-event integration |
| AST Analyzer | **Dhruv Vasvani** | Python AST analysis, taint tracking, reachability evidence, scoring, analyzer API, and SARIF output |
| AI Remediation & Frontend | **Kartik Sharma** | React dashboard, analyzer experience, and AI-fix workflow integration |

## Demo 2: working demonstration

The verified local walkthrough demonstrates the analyzer API and standalone
analysis page. It does not by itself prove the complete GitHub-to-PR workflow.

1. From the repository root, start the analyzer:

   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn src.dashboard_api:app --app-dir 3_ast_analyzer --host 127.0.0.1 --port 8090
   ```

2. In another terminal, start the frontend:

   ```powershell
   cd 4_frontend
   npm run dev -- --host 127.0.0.1
   ```

3. Open `http://localhost:5173/analyze`, submit a small source file or project,
   and inspect the returned findings. Check service readiness at
   `http://127.0.0.1:8090/health`.

This demo can show finding rules, severity, file and line locations, supported
Python taint source-to-sink explanations, reachability evidence when available,
and SARIF export. The analyzer is static; it does not execute submitted code.
See the [analyzer demo guide](3_ast_analyzer/ast.md) for setup details and
limitations.

## What is in place

- **Analyzer:** API-driven source analysis, Python AST/control-flow and taint
  analysis, cross-file/reachability evidence, scoring, and SARIF reporting.
  Java, JavaScript/TypeScript, Go, and Rust have parser-backed support, but not
  equivalent Python taint-analysis coverage.
- **Backend:** Spring Boot services for authentication, projects/repositories,
  scans, findings, feedback, policies, and reports; PostgreSQL/Flyway support
  and a local development profile are present.
- **Scan pipeline:** Semgrep and Checkov scanning, Redis-backed worker flow,
  exact-commit fetching, result submission, and progress events are implemented
  across the pipeline and backend.
- **Frontend:** React pages for authentication, dashboard/repository workflows,
  and a standalone analyzer page are present.
- **Local deployment:** Docker Compose defines the backend, PostgreSQL, Redis,
  analyzer, pipeline worker, frontend, and optional GitHub webhook services.

## Remaining for the Phase 1 main submission

1. **Prove the integrated flow:** Run a repeatable end-to-end test with a
   disposable GitHub repository: signed push, backend scan/job creation, Redis
   worker, Semgrep/Checkov, analyzer, persisted results, and dashboard display.
   Record which optional services are enabled and capture test evidence.
2. **Verify external integrations:** With test credentials, validate the
   configured AI-fix and GitHub pull-request paths. Keep generated changes
   reviewable; AutoForge does not merge a PR automatically.
3. **Run a clean-checkout release check:** Build the frontend and backend, run
   the analyzer, pipeline, and backend tests, and verify database migrations
   plus the documented Compose startup with fresh local configuration.
4. **Finish submission evidence:** Align the final report with the Phase 1
   rubric, document architecture and limitations, and include reproducible
   setup, test results, and Demo 2 screenshots or recording.

Treat the full GitHub-to-PR workflow and external-service behavior as pending
until those checks have been run and recorded. Static-analysis findings can be
incomplete or uncertain; zero findings do not establish that a repository is
secure.

## Main components

| Component | Location |
|---|---|
| Spring Boot backend | [`1_backend/`](1_backend/README.md) |
| Scan pipeline | [`2_pipeline/`](2_pipeline/README.md) |
| AST analyzer and Demo 2 guide | [`3_ast_analyzer/`](3_ast_analyzer/ast.md) |
| React frontend | [`4_frontend/`](4_frontend/) |
| Local service orchestration | [`docker-compose.yml`](docker-compose.yml) |
