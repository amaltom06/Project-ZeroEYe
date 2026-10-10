# Presenting ZEROEYE: a five-to-seven-minute live demonstration

This demonstration uses clearly labeled **simulated activity through the actual running system**. Enrollment, API validation, PostgreSQL storage, detection rules, evidence links, incidents and investigation summaries are real application operations. It does not prove native Windows collection, service installation or production readiness.

## What to say at the beginning

> ZEROEYE is a Windows security monitoring application. Its agent collects selected security events from an authorized computer. The backend stores those events and checks them against detection rules. The dashboard helps an analyst review alerts, inspect evidence and manage incidents. Today I am using simulated events to demonstrate the running backend and investigation workflow. This demonstration does not install an agent or attack a computer.

Explain the flow in one sentence: **Windows events → agent → backend and database → detection rules → dashboard → analyst investigation**. For this presentation, a synthetic device replaces the Windows collector at the ingestion boundary.

## Prepare before the meeting

1. Confirm the dashboard is available at http://localhost:5173. The database, API and investigation service must remain running.
2. Sign in using your local ZEROEYE account. If you have no account, choose Create a workspace and register with a password of at least 12 characters. You may select the demo checkbox here.
3. Open an ordinary PowerShell terminal in `D:\project\zeroeye`. No administrator terminal is needed for this simulated demo.
4. Run:

```powershell
rtk proxy npm.cmd run demo:live
```

5. Enter your ZEROEYE email and password in the private credential prompt. If you have no DEMO workspace, the utility offers to create **ZEROEYE Presentation**: type **CREATE** to accept. It refuses LIVE workspaces and requires Owner/Admin access to the selected demo.
6. If you created a workspace in the terminal, refresh the browser so it appears in the organization selector. Select the workspace named in the terminal. Keep the **DEMO** label visible.
7. Rehearse once. Each run creates a separate simulated endpoint and seven new records, so overall dashboard counts accumulate. Filter Live Events by the current presentation endpoint when checking that run.

The credential is used only for the local demo process. It is not put in command arguments or saved in a project file. Do not screen-share the credential dialog.

## Show these steps in order

| Step | What to show | What to say | Expected result with default rules |
|---|---|---|---|
| 1 | Overview and Devices; press Enter in the terminal | “A workspace begins with its own devices and evidence. This run enrolls a simulated device.” | A new `SIMULATED-PRESENTATION-…` endpoint appears and reports a heartbeat. |
| 2 | Live Events; press Enter for stage 1 | “These are five sample failed login events for the same account and source. The rule watches their pattern.” | Five 4625 records arrive individually. The fifth produces **Repeated failed logons**, HIGH. |
| 3 | Open that detection | “This alert links to the five events that triggered it. It is a signal to investigate, rather than proof of a compromise.” | Five supporting event links and a rule explanation. |
| 4 | Press Enter for stage 2, then review detections | “A successful login after those failures adds context. We would check whether the account owner recognizes it.” | One 4624 record and **Success after repeated failures**, HIGH, with six evidence events. |
| 5 | Press Enter for stage 3 | “This sample record represents a cleared Security log. No actual Windows log is cleared in this demo.” | One 1102 record and **Security audit log cleared**, CRITICAL. |
| 6 | Open the success-after-failures alert and choose Create incident | “An incident organizes the evidence and the analyst’s work.” | A saved incident with six linked events. |
| 7 | Choose Investigate evidence | “The current investigator computes facts from the stored evidence and lists hypotheses separately. A language model is not enabled.” | Saved evidence summary, event citations and follow-up suggestions. |
| 8 | Add an analyst note, resolve with resolution notes, optionally export a report | “The analyst documents a decision and preserves an audit trail.” | Notes, resolution and a timestamped report can be reviewed. |

Suggested note: `Presentation test: reviewed the six simulated login events. No real account was attacked.`

Suggested resolution: `Resolved as an authorized synthetic demonstration. This does not establish a real compromise.`

The sample scenario has fixed timestamps within one minute so you can pause between stages. The terminal reports the API's actual accepted-event and alert counts. A fresh endpoint with the unchanged default rules produces **seven events and three alerts**. Custom rule settings can change the alert count. Live dashboard updates use authenticated WebSockets with polling fallback.

Finish by pressing Enter in the terminal. The utility disables the simulated device credential and closes its own login session; your browser session stays separate. Historical demo evidence remains available. The demo endpoint is inactive afterward by design.

## Questions you may be asked

**Is this an antivirus?** It is a security monitoring and investigation application. The current build generates alerts and advisory recommendations; it does not automatically block processes, disable accounts or isolate computers.

**Is the activity real?** The application is running and its backend is processing real requests. The activity records are explicitly simulated. No real Windows Security log is read, changed or cleared for this presentation.

**Where does the data go?** In this local setup, it goes to the API and PostgreSQL database on this computer. External model processing is off by default.

**Is the AI deciding that a computer is hacked?** No. The current investigator is a deterministic evidence summarizer. Its hypotheses require human verification; an optional model integration has not been enabled or tested.

**Can it monitor another computer?** The native agent source and executables exist, but real Windows collection and service lifecycle testing remain unfinished. The current backend is bound to loopback. Remote endpoints require a separately configured, reachable HTTPS deployment.

**Is it finished?** This is a working local development implementation. Native installer/service testing, real collector end-to-end testing, browser visual QA and production release work remain pending.

## If something does not appear

- Check that the browser is at **localhost:5173** and the organization selector matches the terminal's DEMO workspace.
- If the workspace was just created, refresh the browser once.
- If updates lag, wait for the polling refresh or refresh the page. Check the selected event time range and device filter.
- If accepted events are present but a detection is missing, check that ZE-001, ZE-008 and ZE-005 are enabled with their default thresholds in Detection Rules.
- If login fails, use the account registered in this local application; the credential prompt is not asking for your Windows login.
- If the investigation service is unavailable, event ingestion and detections still work. Start the investigation service before showing that step.
- If the utility cannot revoke its device because the API is unavailable, revoke that simulated endpoint in Devices once the API returns.

Full setup and one-shot demo instructions: [demo.md](demo.md). Current implementation limits: [LIMITATIONS.md](LIMITATIONS.md).
