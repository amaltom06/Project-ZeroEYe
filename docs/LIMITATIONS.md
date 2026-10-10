# Known limits and unfinished acceptance criteria

This is a substantial working local implementation. It is not the completed ZEROEYE MVP described in the master brief.

| Area | Current boundary |
|---|---|
| Installer | Two Windows executable directories built; Inno installer source exists. Compiler absent; installer, reboot and uninstall tests not performed. |
| Real Windows telemetry | Parser/API/queue/DPAPI tests run on Windows. No protected Security logs were read and no service was installed; native real-device end-to-end acceptance remains pending administrator authorization. |
| Browser QA | No connected browser was available. React automated login/empty/error-state tests and HTTP checks passed; screenshots, keyboard/dialog focus and mobile visual QA remain pending. |
| Model assistance | Deterministic evidence summary verified through the API. Optional Ollama structured suggestions implemented but no model/provider was installed or invoked. It is not trained ML. |
| Authentication | Register/login/logout/session/CSRF/RBAC work. Email verification, reset, MFA, public-signup controls and mail delivery are pending. |
| Membership | Organization creation and existing-user addition work. Invitations, removal and role-change/last-owner lifecycle are pending. |
| Detection | Eight bounded deterministic rules, policy controls and suppression. Context reads at most 2,000 records per device within ten minutes; very high volume can truncate evidence. Cross-device spraying and late-event re-evaluation across prior batches are pending. |
| Incident response | Assignment, evidence, notes, status, resolution/reopen and advisory records. No endpoint commands, blocking, account disabling or automatic containment. |
| Notifications | In-app enrollment/detection/incident updates and per-user read state. Email, preferences, deduplicated offline transitions and escalation schedules are pending. |
| Analytics/reports | 24-hour event/failure chart, present-state counts, CSV/JSON events and JSON summary reports. PDF/Excel, scheduled reports, rule effectiveness and resolution-time analytics are pending. |
| Storage/retention | Indexed PostgreSQL with migrations, device-event deduplication and incident evidence FKs. Retention is an explicit script, not automatic. Incident/audit/report archives and encrypted-at-rest deployment need review. |
| Infrastructure | Docker/Compose/HTTPS/backup/CI source exists. Docker absent; containers, clean CI, public TLS and backup restores were not run. |
| Scaling | Single API process. IP limits are process-local, and WebSockets have no distributed fanout. Production reverse proxy rate-limit behavior needs tuning. |
| Security review | Automated isolation/role/CSRF/secret/validation tests and dependency scans. Independent penetration testing, signed binaries, tamper-evident audit and production operational review remain pending. |

Never present synthetic records, an encoded PowerShell match, or a model hypothesis as confirmed compromise. A rule match is a signal requiring analyst verification. Native collection of command lines is off by default, so the encoded-command rule requires explicitly approved command-line telemetry to operate.
