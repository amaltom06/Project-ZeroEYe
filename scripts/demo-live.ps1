$ErrorActionPreference = 'Stop'
$previousEmail = $env:ZEROEYE_DEMO_EMAIL
$previousPassword = $env:ZEROEYE_DEMO_PASSWORD
$demoCredential = $null
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    Write-Host 'ZEROEYE presentation: simulated events through the real local backend.'
    $demoCredential = Get-Credential -Message 'Enter your local ZEROEYE email and password'
    if ($null -eq $demoCredential) { throw 'Credential prompt cancelled.' }
    $env:ZEROEYE_DEMO_EMAIL = $demoCredential.UserName
    $env:ZEROEYE_DEMO_PASSWORD = $demoCredential.GetNetworkCredential().Password
    rtk proxy node scripts/demo-live.mjs
    $demoExitCode = $LASTEXITCODE
} finally {
    $env:ZEROEYE_DEMO_EMAIL = $previousEmail
    $env:ZEROEYE_DEMO_PASSWORD = $previousPassword
    $demoCredential = $null
    Pop-Location
}
exit $demoExitCode
