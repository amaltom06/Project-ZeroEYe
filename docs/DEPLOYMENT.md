# Local containers, HTTPS, backups and operations

Docker Desktop was not installed in the verification environment. These files are configuration source and have not been deployed/tested. Native development with workspace-local PostgreSQL is verified separately.

## Docker Compose local environment

Install Docker Desktop with WSL2 according to its official Windows documentation. Keep the native Windows agent outside Linux containers. Copy the environment template and replace secrets with independently generated random values; do not overwrite an existing working .env. Use a URL-safe random hexadecimal database password. Docker's database password and the local embedded database password are independent.

Required .env entries:

```dotenv
POSTGRES_PASSWORD=<random hexadecimal password>
AI_SERVICE_TOKEN=<random 32-byte token>
COMPOSE_WEB_ORIGIN=http://localhost:8080
COMPOSE_NODE_ENV=development
```

```powershell
rtk proxy docker compose up --build -d
rtk proxy docker compose ps
rtk proxy docker compose logs --tail 100 api ai web
```

Open http://localhost:8080. Only the web gateway is bound to host loopback. PostgreSQL, API and AI ports remain within the Compose network. A migration job must complete before the API starts. Keep the database volume; do not use a volume-removal command for routine shutdown.

```powershell
rtk proxy docker compose down
```

## HTTPS deployment

Review the security design first. Use a domain you own and a host you administer. Configure its DNS, the random secrets above, and ZEROEYE_DOMAIN. Confirm hosting costs and expose only ports 80/443. Caddy requests/renews public TLS certificates. The override sets NODE_ENV=production and WEB_ORIGIN=https://your-domain, enables Secure cookies and removes the loopback development port.

```powershell
rtk proxy docker compose -f docker-compose.yml -f infrastructure/deployment/compose.https.yml up --build -d
```

The override uses Compose's !reset tag; use a recent Compose version that supports it. Pin tested container image digests and GitHub Action revisions before a public release. Do not publish a dev Vite server. This project has no automatic cloud provisioning, code-signing certificate, DNS changes or spending setup.

## PostgreSQL backups

For containers, create a custom-format backup **inside** the container, then copy it to a protected host directory. PowerShell redirection can corrupt binary dumps in some versions, so do not stream a custom-format dump through text redirection.

```powershell
$backupDirectory = Join-Path (Get-Location) '.runtime/backups'
New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null
rtk proxy docker compose exec -T postgres pg_dump -U zeroeye -d zeroeye -Fc -f /tmp/zeroeye-backup.dump
rtk proxy docker compose cp postgres:/tmp/zeroeye-backup.dump .runtime/backups/zeroeye-backup.dump
```

Backup files contain sensitive security telemetry. Encrypt them, restrict access and copy them to separately protected storage. Set a schedule, retention period, monitoring and recovery-time objective.

Restore into a **new test database first**, never into a live database without an approved recovery plan:

```powershell
rtk proxy docker compose cp .runtime/backups/zeroeye-backup.dump postgres:/tmp/zeroeye-backup.dump
rtk proxy docker compose exec -T postgres createdb -U zeroeye zeroeye_restore_test
rtk proxy docker compose exec -T postgres pg_restore -U zeroeye -d zeroeye_restore_test --no-owner /tmp/zeroeye-backup.dump
```

Validate row counts and representative tenant queries against the restored database. These backup/restore commands have not been executed here because Docker is absent.

## Operations

- /api/health queries PostgreSQL before reporting healthy. Investigation service has /health; the API returns a controlled 503 when it is unavailable.
- API request logs contain request IDs, route templates, duration and status rather than credentials/bodies. Audit records live in PostgreSQL. Protect log access.
- Schedule `npm run retention` only after reviewing its evidence-retention policy and having recoverable backups. It deletes old unlinked events/heartbeats and preserves incident-linked evidence. It is not scheduled automatically.
- A single API process with process-local rate limiting/WebSockets is the current deployment target. Multi-instance deployments need shared notification fanout and distributed rate limits.
- Use external monitoring for process failure, disk/database capacity, error rate, certificate expiration, backup success and agent heartbeat age.
- Production needs a restricted application database role and a separate migration role; Compose's single development database user is not a least-privilege production design.
- Local native setup has no cloud fees. Hosting, backups, domain/certificate services and optional remote AI may have fees determined by the providers you choose.
