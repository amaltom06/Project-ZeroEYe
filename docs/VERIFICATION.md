# Verification record

Local run date: **10 October 2026, Asia/Calcutta**. Environment: Windows 11 (build 26200), Node 24.13.0, Python 3.14.3, workspace-local PostgreSQL 18.1. This record distinguishes observed results from untested release gates.

| Check | Result |
|---|---|
| Exact npm installation | Passed; portable lockfile includes Windows/Linux platform binaries |
| Prisma 6.19 client generation | Passed |
| Initial public-schema migration | Passed |
| Isolated PostgreSQL integration migrations | Passed; temporary schemas removed by finally cleanup |
| API and React TypeScript/build | Passed via npm run build; Vite 8.3.4 production chunks built |
| Pure detection rule tests | 10 passed |
| API security unit tests | 4 passed |
| React login/empty/error-state tests | 3 passed |
| Python agent and investigation tests | 15 passed on Windows |
| Full-stack integration assertions | 66 passed against actual PostgreSQL and FastAPI |
| Compiled API startup | Passed using node apps/api/dist/apps/api/src/index.js |
| Local HTTP readiness | Dashboard, compiled API database health, and investigation health returned HTTP 200 |
| Windows packaging | CLI and service one-directory builds passed with PyInstaller 6.22.3 |
| Built Windows CLI startup | ZeroEye-Agent.exe --help exited 0 |
| JavaScript dependency audit | Final npm audit reported 0 known vulnerabilities (all severities) |
| Browser visual QA/screenshots | Not run: computer-use inventory returned no browsers |
| Native Windows Security-log/service/installer test | Not run: no administrator token; no service installed; Inno Setup absent |
| Docker/HTTPS/backup restore/hosted CI | Not run: Docker absent; configuration source only |
| Optional model inference | Not run: no Ollama model/provider installed |
| Python vulnerability audit | Not performed; dependencies pinned to tested versions |

JavaScript source tests total **17**; Python tests total **15**; integration assertions total **66**. Compiled test artifacts were excluded so duplicate rule tests do not inflate these totals. One Python warning remains: the installed Starlette TestClient deprecates its httpx adapter. It did not cause failures; a test-client adapter migration is future maintenance.

The integration suite verifies valid/invalid login, HttpOnly cookies, anonymous denial, Origin/CSRF, membership/tenant isolation, viewer privilege denials, concurrent one-use enrollment, hashed secrets, heartbeats, strict event fields, timestamps, deduplication, deterministic evidence alerts, incident creation/resolution/reopen, assignment constraints, notes, database metrics, exports, reports, authenticated/isolated WebSockets, API-to-service investigation citations, bounded read-only tool isolation, server-derived demo identity and segregation, credential rotation/revocation, audit records and logout.

Agent tests cover actual Windows DPAPI roundtrip in a temporary file, event XML including 1102 UserData/provider, missing-IP handling, entity rejection, durable checkpoint/queue atomicity, event/byte capacity, retry bounds, redirect refusal, response memory limit and a mocked-collector run through the actual queue/transport acknowledgment/shutdown lifecycle. They do not prove real Security-log permissions or SCM integration.

Issues discovered and fixed during verification: root .env loading across workspaces; Prisma aggregate typing; advisory-lock void return deserialization; tenant-key propagation in nested incident evidence; stale-session UI cache cleanup; compiled test discovery; old vulnerable test/migration tooling; portable optional-dependency lockfile resolution; conflicting Vite 7/8 plugin types and Vite 8 chunking configuration. Final successful checks above supersede those earlier failures.

Prisma CLI transitives deepmerge-ts and effect are explicitly patched through root overrides, and the test runner is Vitest 5.0.3. Recheck overrides on a future Prisma upgrade rather than silently dropping them. See [Vite migration guidance](https://vite.dev/guide/migration), [Prisma migration guidance](https://www.prisma.io/docs/orm/v6/prisma-migrate/getting-started), and [Ollama output validation](https://docs.ollama.com/capabilities/structured-outputs) for referenced implementation contracts.

Passing these checks does not mean the full MVP acceptance criteria or production security review are complete. See PROGRESS.md and LIMITATIONS.md before distribution.

Final fixture cleanup check: the normal public schema contained 0 users, 0 devices and 0 events; no integration test schemas remained. Task-owned API, web, investigation and PostgreSQL processes were stopped after checks. Existing .env and database files are retained under ignored local paths.
