# ZEROEYE implementation status

Verified on Windows on **10 October 2026 (Asia/Calcutta)**. File presence is distinct from runtime acceptance. Full MVP status: **incomplete**.

| Module | Status | Verification / remaining work |
|---|---|---|
| Monorepo and local prerequisites | Implemented and locally verified | Node 24/Python 3.14, workspaces, exact npm install, portable lockfile, pinned Python dependencies |
| PostgreSQL and Prisma | Implemented and locally verified | PostgreSQL 18.1 started; initial migration and isolated-schema migrations applied; client generated |
| Authentication and tenancy | Implemented and locally verified | Registration/login/logout, cookie sessions, CSRF, membership selection, role denials and cross-tenant tests |
| Device enrollment and credentials | Implemented and locally verified | Concurrent one-use enrollment, hashed tokens, policies, rotation and revocation |
| Ingestion and event explorer | Implemented and locally verified | Strict validation, deduplication, stored events, filters/pagination, exports, evidence references |
| Dashboard foundation | Built; browser visual QA pending | API database metrics, React empty/login/error tests and HTTP 200; no browser surface available |
| Deterministic detections | Implemented and locally verified | Eight rules, positive/negative/correlation/policy tests; supporting evidence and suppression |
| Realtime | Implemented and locally verified | Authenticated WebSocket opens; foreign-tenant subscription rejected; polling fallback source |
| Windows agent | Built and unit verified; native acceptance pending | Parser, queue/recovery, DPAPI, retry, bounded responses, shutdown tests; both executables built and CLI help starts |
| Investigation tools and baseline | Implemented and locally verified | Typed bounded tools, tenant rejection, injection/opt-out tests and API → FastAPI evidence summaries |
| Optional model provider | Implemented; not invoked | Ollama schema validation/provider abstraction; model installation and actual inference pending |
| Incident management | Implemented and locally verified | Creation/evidence, notes, assignment constraints, resolution notes, reopen and audit trails |
| Defensive response | Advisory only | Recommendations saved; no endpoint-changing actions or auto containment |
| Notifications/reporting | Core implemented; expanded features planned | In-app updates/read state, CSV/JSON events and JSON reports; email/preferences/PDF/Excel pending |
| Retention | Implemented; not run against application data | Explicit policy script preserves incident-linked evidence; production archive policy pending |
| Installer | Source ready; compiler and native validation missing | Inno Setup absent; no installer, reboot or uninstall acceptance test |
| Deployment/CI/backups | Source ready; environment verification pending | Docker absent; containers/TLS/CI/backup restore not run here |
| Production authentication lifecycle | Planned | Email verification/reset, MFA, invitation/removal/role-change lifecycle |
| Optional enterprise analytics | Planned | Statistical baselines, Sigma import, cross-device correlation and richer report scheduling |
| Release security review | Pending | Clean VM testing, signatures, operational review and independent assessment |

See [verification](VERIFICATION.md), [limitations](LIMITATIONS.md), [setup](../README.md), and [native validation instructions](windows-agent.md). No real Security logs were collected. No Windows service was registered. No public deployment or cloud spending occurred.
