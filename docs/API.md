# ZEROEYE API contract 0.1.0

Base path: /api. JSON request size limit: 512 KiB. Errors return `{error: string}`; validation errors also return bounded field paths/messages. 401 = missing/expired credentials; 403 = Origin/CSRF/membership/role denial; foreign-tenant resource lookups return 404; 409 = unique conflict; 413 = oversized request; 429 = rate limit; 503 = unavailable investigation service. No raw Prisma/stack errors reach clients.

See [OpenAPI](openapi.json) for paths, request schemas and security schemes. The contract is versioned as 0.1.0; a URL /v1 prefix is not introduced yet.

## Browser boundary

POST register accepts email/name/password (12–128 characters)/organization/demo. POST login accepts email/password. Both require the configured Origin, set the HttpOnly session cookie and return user identity plus a CSRF token. GET me returns `{user, csrf, organizations:[{id,name,role,demo}], currentOrganizationId}`. Never expose the cookie/token in logs.

Other browser APIs require the session cookie. X-Organization-ID is optional and must match an active membership. All unsafe methods also require Origin matching WEB_ORIGIN and X-CSRF-Token matching the session. Sessions expire after SESSION_HOURS (default 12). POST logout revokes the current session.

Role shorthand: Analyst+ = Owner/Admin/Analyst. Admin+ = Owner/Admin. Viewer can use read endpoints; audit is Admin+ only.

| Route / action | Payload / result |
|---|---|
| POST organizations | `{name,demo?}`; caller becomes Owner |
| GET organizations/members | Member records with safe user identity |
| POST organizations/members, Admin+ | `{email,role}`; existing registered user only; only Owner can grant Owner |
| GET devices | Device array, heartbeat/event/health fields and collection policy |
| POST devices/enrollment-token, Admin+ | No body; `{token,expiresAt}`; token returned once |
| GET/PATCH devices/:id, Admin+ for PATCH | PATCH `{tags?,eventIds?}`; configVersion increments |
| DELETE devices/:id, Admin+ | Soft deactivate; revoke all credentials; retain evidence |
| GET events | `{items,total,page,limit}`; items include device hostname |
| GET events/:id | Normalized stored event with metadata |
| GET events/export | format=csv or json; maximum 10,000 rows; CSV formula-injection protection |
| GET alerts | Paginated alert list; severity/status filters |
| GET alerts/:id | Alert, MITRE mapping and supporting authorized events |
| PATCH alerts/:id, Analyst+ | `{status:"ACKNOWLEDGED"}` |
| GET/PATCH rules/:ruleId, Admin+ for PATCH | GET list at /rules; PATCH replaces policy, not a partial merge |
| POST incidents, Analyst+ | `{alertId}`; one incident per alert, evidence attached transactionally |
| GET incidents / incidents/:id | List or incident with bounded investigation evidence/notes/actions |
| PATCH incidents/:id, Analyst+ | `{status?,assignedTo?,resolutionNotes?}`; current-tenant assignee only; resolving requires notes |
| POST incidents/:id/comments, Analyst+ | `{body}`, max 5,000 characters |
| POST incidents/:id/events, Analyst+ | `{eventIds:[uuid]}`, max 100; every event must be current-tenant |
| POST incidents/:id/recommendations, Analyst+ | `{kind,recommendation}`; kind ACCOUNT_REVIEW/IP_BLOCK_REVIEW/CONTAINMENT_GUIDANCE/INVESTIGATION_TASK; advisory only |
| POST ai/investigate, Analyst+ | `{incidentId}`; persists provider/result and audit record |
| GET ai/investigations/:id | Saved authorized investigation |
| GET dashboard/overview | Device/event/alert/incident/health counters and recent records; reporting day UTC |
| GET dashboard/trends | 24 hourly buckets `{hour,events,failures}`; database aggregate |
| GET notifications | Latest 100 organization notifications plus current user's read state |
| PATCH notifications/:id | Marks read for current user only |
| GET/PATCH settings, Admin+ for PATCH | `{retentionDays,externalAiEnabled}` |
| GET audit, Admin+ | Paginated audit records |
| GET reports | Latest 50 saved summaries |
| POST reports/generate, Analyst+ | `{kind:"SECURITY_SUMMARY"}`; timestamped metrics snapshot |
| GET reports/:id/export | Authorized JSON snapshot download |

Pagination: page defaults to 1, limit to 25 (max 100); event, alert and incident lists return totals. Event filters: deviceId, windowsEventId, category, severity, username substring, exact sourceIp, ISO-offset from/to and q (account/process/eventKey substring). Default time range is last 24 hours. Stored source events have INFO severity; alert severity comes from the rule. Correlation certainty is RULE_MATCH, not a machine-learned confidence score.

Rule defaults: threshold 5; window 120 seconds (spraying 300); suppression 120 seconds. Policy accepts enabled, threshold (2–100), windowSeconds (30–600), suppressionSeconds (0–3600), UTC allowedHours and trustedUsers. Time/privilege rules require explicit nonempty configuration.

## Agent boundary

Agent routes do not accept browser sessions. Enrollment uses `{enrollmentToken,hostname,osVersion,agentVersion:"0.1.0"}` and returns `{deviceId,deviceToken,eventIds,configVersion,simulated}`. The token is consumed atomically under concurrent requests. Subsequent requests use Authorization: Bearer <deviceToken>.

Heartbeat: POST /agent/heartbeat `{queueDepth,error?}` returns latest eventIds/configVersion/simulated. Events: POST /agent/events `{events:[Event]}` returns `{accepted,duplicates,alerts}`. Allowed providers/IDs and metadata lengths are in OpenAPI. Microsoft-Windows-Eventlog is allowed only for event 1102. orgId/deviceId/simulated in event payloads are rejected. Timestamps must be no more than five minutes in the future and no older than 30 days. Device collection policy is enforced.

POST /agent/rotate revokes existing credentials and returns a new deviceToken once. Persist it securely; an interrupted rotation needs re-enrollment/recovery. POST /agent/revoke disables the device and invalidates credentials. No arbitrary endpoint-command API exists.

WebSocket /api/live?orgId=<uuid> requires an active cookie session, exact Origin and membership. It sends `{type:"connected"}` and scoped invalidation messages (events/devices/incidents/alerts); clients fetch data via authorized APIs. Clients reconnect after five seconds and poll every 30 seconds.

## Investigation service

FastAPI /investigate requires the separate AI_SERVICE_TOKEN bearer credential. Browser cookies never reach it. The API retrieves up to 100 current-tenant incident-linked events through the bounded tool layer. Only event IDs, UUIDs, timestamps, outcomes and simulation flags are sent. Responses contain provider, summary, facts with evidenceIds, hypotheses, nextSteps and limitations. Unknown evidence references are rejected. Optional model failure falls back to deterministic facts. The service has no writes to endpoint policy or database.
