# Isolated synthetic demonstration

For a staged presentation with a private credential prompt, run `rtk proxy npm.cmd run demo:live` from the project root. The utility pauses between enrollment, five failed logins, a successful login and a sample audit-clearing record. See [the presenter walkthrough](presentation.md) for exact screen order and talking points. It uses the real local backend, keeps the simulated endpoint reporting during the presentation and disables its credential on exit.

Create or select an organization explicitly marked DEMO. You can create one during registration or in Settings. Real and demo data live in different organizations. Server enrollment determines each device's simulation flag; event payloads cannot set or override it. Native Windows collection refuses a demo identity.

The generator uses documentation-only IP addresses, synthetic accounts and a simulated endpoint. It exercises actual ingestion/storage/rules and never attacks a device. It generates five failed logons, a success and an audit-clearing record; all become server-marked simulated records. It does not create real Windows events.

In PowerShell, with the database and API running:

```powershell
$demoCredential = Get-Credential -Message 'Use your local ZEROEYE test account'
$env:ZEROEYE_DEMO_PASSWORD = $demoCredential.GetNetworkCredential().Password
try {
  rtk proxy npm.cmd run demo
} finally {
  Remove-Item Env:ZEROEYE_DEMO_PASSWORD -ErrorAction SilentlyContinue
  $demoCredential = $null
}
```

Enter your registered email when asked, then select the numbered demo organization. Passwords are passed through the process environment for this local utility, never through command arguments or committed files. Use a dedicated demonstration account. The generated endpoint's token is held only in process memory; its historical data remains simulated, and its status becomes offline after two minutes without a heartbeat.

Review Threat Detection, create an incident, add analyst notes, run Investigate evidence and resolve with notes. The investigation discloses simulated evidence. Export from Live Events or Reports. Never relabel a demo alert as a genuine compromise in a portfolio.
