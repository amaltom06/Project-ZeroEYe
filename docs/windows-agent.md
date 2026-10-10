# Windows agent setup and release gates

The collector uses modern Windows Event Log APIs: EvtQuery, EvtNext, EvtRender, EvtSeek and XML bookmarks. Its first checkpoint starts at the newest matching record; historical logs are not imported. Event 1102 uses the Microsoft-Windows-Eventlog provider and UserData; other supported Security events use Microsoft-Windows-Security-Auditing and EventData. Missing account/IP fields are allowed.

Supported IDs: 4624, 4625, 4634, 4648, 4672, 4688, 4720, 4726, 4740, 1102. Availability depends on Windows audit policy. The agent never changes that policy.

## Source development

Prepare dependencies from an ordinary PowerShell terminal as shown in the README. Use the project Python environment. Then, only on an authorized device, open an **administrator-approved PowerShell terminal** for enrollment and service operations. Enrollment asks for monitoring consent, the backend origin and a hidden one-use token; the token is never a command-line argument.

```powershell
rtk proxy .runtime/python/Scripts/python.exe agents/windows/src/main.py enroll
```

Enrollment protects `C:\ProgramData\ZeroEye` for SYSTEM and Administrators using an explicit DACL, then stores the device token under machine DPAPI. Do not weaken this ACL. The service runs as LocalSystem so it can read protected Security logs. A least-privilege service account with appropriate Security-log rights is a future release hardening option.

Command lines are removed by default. If your authorized organization explicitly approves collection, an administrator may set `collectCommandLine` to true in the protected identity file; do not change the encrypted token. Command lines can contain secrets and are never sent to the AI service.

To run the agent in the foreground for a controlled test:

```powershell
rtk proxy .runtime/python/Scripts/python.exe agents/windows/src/main.py run
```

Use Ctrl+C to stop. The source agent refuses credentials from a demo organization. The demo generator uses a separate simulated endpoint.

## Package and install

Builds require Windows and the development Python requirements:

```powershell
rtk proxy npm.cmd run agent:build
rtk proxy agents/windows/dist/ZeroEye-Agent/ZeroEye-Agent.exe --help
```

This produces **directories** containing the CLI/service executables and their required DLLs; do not distribute a lone EXE from a one-directory build.

Install Inno Setup 6 from its official source. Building the installer is an ordinary compile; installing it requests UAC administrator permission:

```powershell
rtk proxy ISCC.exe agents/windows/installer/zeroeye.iss
```

Output: `agents/windows/dist/ZeroEye-Agent-Setup.exe`. Silent installation is disabled. The wizard shows disclosures and requires consent, registers automatic startup, then opens an enrollment prompt. Service startup requires a saved identity. Local service control without the installer is available for authorized testing:

```powershell
# Administrator-approved terminal only; these change Windows service registration.
rtk proxy agents/windows/dist/ZeroEye-Service/ZeroEye-Service.exe --startup auto install
rtk proxy agents/windows/dist/ZeroEye-Service/ZeroEye-Service.exe start
rtk proxy agents/windows/dist/ZeroEye-Service/ZeroEye-Service.exe stop
rtk proxy agents/windows/dist/ZeroEye-Service/ZeroEye-Service.exe remove
```

## Reliability and privacy

- 10,000-event / 20 MiB logical payload queue, SQLite WAL and atomic enqueue/bookmark commits.
- Backpressure pauses collection without advancing the bookmark. Windows may still overwrite old logs during a long outage; retention of the source log is outside the agent's control.
- 100-record batches; retries with exponential backoff capped near five minutes; independent 30-second heartbeats; five-second collection polling.
- TLS verification remains enabled. Redirects are rejected. Plain HTTP is allowed only to loopback for development.
- Logs rotate at 2 MiB with three backups; logs contain diagnostic categories rather than raw events/credentials.
- Removed-policy or older-than-30-day queued events are dropped with a diagnostic count; they are outside the server's accepted ingest window.
- If a bookmark becomes invalid after log clearing/rollover, collection reports a health error. An administrator can use `reset-checkpoint`, review its warning and type RESET. Pending queue data remains; this explicitly acknowledges an evidence gap.

## Uninstall and release checklist

The installer uninstaller stops the service, attempts backend self-revocation, removes registration and application files, and asks whether to delete the local queue/diagnostics. If offline, revoke the device through Devices as soon as possible. Historical backend evidence follows the organization's retention policy.

Before distribution, test on a clean Windows VM: install consent/UAC, denied consent, enrollment expiry/reuse, Security-log permissions, real selected events reaching the backend, offline queue, restart/bookmark recovery, policy update, credential revocation, reboot startup and complete uninstall. Record OS versions and any errors. Verify executable signatures and apply Authenticode code signing with an organizational certificate; unsigned installers may trigger Windows reputation warnings.

**Current gate:** executables were built and CLI help was smoke-tested. Inno Setup was absent, and no service installation, real Security-log collection, reboot or uninstall test was performed. The installer source is unverified.

Sources: [Microsoft EvtQuery](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery), [bookmarking](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events), [4625 schema](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625), [1102 schema](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102), [pywin32 implementation](https://github.com/mhammond/pywin32/blob/main/win32/src/win32evtlog.i).
