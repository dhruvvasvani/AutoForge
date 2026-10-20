# 1_backend — Spring Boot Core

## Week-by-week status

| Week | Deliverable | File(s) |
|---|---|---|
| 1-5 | Spring Boot skeleton, entities, JWT auth, DTOs, exception handling | see `entity/`, `security/`, `dto/` |
| 6 | PostgreSQL indexes, User/Plan module completion, plan-request endpoint | `db/migration/V2__week6_indexes_and_constraints.sql`, `controller/PlanController.java` |
| 7-8 | Admin Panel APIs: user mgmt + plan-request approval | `service/AdminService.java`, `controller/AdminController.java` |
| 9 | Repository APIs + GitHub integration (webhook -> Scan row) | `service/RepositoryService.java`, `service/ScanService.java`, `controller/RepositoryController.java`, `controller/GithubWebhookController.java` |

## Run

For local development without PostgreSQL, start the demo profile. It uses an
in-memory H2 database, so user and repository records are discarded when the
backend stops:

```bash
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=demo"
```

The backend listens on `http://localhost:8089`. This profile supports local
registration, login, and repository APIs. GitHub-triggered scan jobs additionally
need Redis and a running pipeline worker.

## Key endpoints added in Weeks 6-9

- `POST /api/plans/request?planName=PAID` — request a plan upgrade
- `GET /api/admin/users` — paginated user list (Admin/Faculty only)
- `PATCH /api/admin/users/{id}/status?status=PAUSED` — pause/activate a user
- `PATCH /api/admin/users/{id}/limit` — change a user's plan
- `DELETE /api/admin/users/{id}` — delete a user
- `GET /api/admin/plan-requests?status=PENDING` — list plan requests
- `PATCH /api/admin/plan-requests/{id}/approve` / `/reject`
- `POST /api/repositories` — connect a GitHub repo (`{ "githubRepoFullName": "org/repo" }`)
- `GET /api/repositories` — list your connected repos
- `DELETE /api/repositories/{id}` — disconnect a repo
- `POST /api/webhooks/github` — now persists a `WebhookEvent` + `QUEUED` `Scan` row on a verified push
