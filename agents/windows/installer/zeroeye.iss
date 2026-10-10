#define MyAppName "ZEROEYE Security Monitoring Agent"
#define MyAppVersion "0.1.0"
[Setup]
AppId={{7D6A50C8-08AA-4E2C-BE33-21C49936E573}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=ZEROEYE Project
DefaultDirName={autopf}\ZEROEYE
DefaultGroupName=ZEROEYE
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=ZeroEye-Agent-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
InfoBeforeFile=monitoring-disclosure.txt
UninstallDisplayName={#MyAppName}
[Dirs]
Name: "{commonappdata}\ZeroEye"
[Files]
Source: "..\dist\ZeroEye-Agent\*"; DestDir: "{app}\cli"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\ZeroEye-Service\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "monitoring-disclosure.txt"; DestDir: "{app}"
[Icons]
Name: "{group}\Monitoring disclosure"; Filename: "{app}\monitoring-disclosure.txt"
Name: "{group}\Uninstall ZEROEYE"; Filename: "{uninstallexe}"
[Run]
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\ZeroEye"" /inheritance:r /grant:r ""*S-1-5-18:(OI)(CI)F"" ""*S-1-5-32-544:(OI)(CI)F"""; Flags: runhidden waituntilterminated
Filename: "{app}\service\ZeroEye-Service.exe"; Parameters: "--startup auto install"; Flags: runhidden waituntilterminated
Filename: "{app}\cli\ZeroEye-Agent.exe"; Parameters: "enroll"; Description: "Enroll using your backend URL and one-use token"; Flags: postinstall skipifsilent waituntilterminated
Filename: "{app}\service\ZeroEye-Service.exe"; Parameters: "start"; Flags: postinstall skipifsilent runhidden waituntilterminated; Check: IdentityExists
[Code]
var ConsentPage: TInputOptionWizardPage;
procedure InitializeWizard;
begin
 ConsentPage := CreateInputOptionPage(wpInfoBefore, 'Monitoring consent', 'Authorize documented monitoring', 'Confirm that you may administer this computer and understand which Security log fields are collected.', False, False);
 ConsentPage.Add('I authorize ZEROEYE to monitor the documented Security event logs on this computer.');
end;
function NextButtonClick(CurPageID: Integer): Boolean;
begin
 Result := True;
 if CurPageID = ConsentPage.ID then begin
  Result := ConsentPage.Values[0];
  if not Result then MsgBox('Explicit monitoring consent is required to continue.', mbError, MB_OK);
 end;
end;
function InitializeSetup(): Boolean;
begin
 Result := not WizardSilent;
 if not Result then MsgBox('Silent installation is disabled because monitoring consent and enrollment must be explicit.', mbError, MB_OK);
end;
function IdentityExists(): Boolean;
begin
 Result := FileExists(ExpandConstant('{commonappdata}\ZeroEye\identity.json'));
end;
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var Code: Integer;
begin
 if CurUninstallStep = usUninstall then begin
  Exec(ExpandConstant('{app}\service\ZeroEye-Service.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{app}\cli\ZeroEye-Agent.exe'), 'revoke', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{app}\service\ZeroEye-Service.exe'), 'remove', '', SW_HIDE, ewWaitUntilTerminated, Code);
  if MsgBox('The service is removed. Delete local queued Security telemetry and diagnostic logs from ProgramData\ZeroEye? Choose No to retain them.', mbConfirmation, MB_YESNO) = IDYES then DelTree(ExpandConstant('{commonappdata}\ZeroEye'), True, True, True);
 end;
end;
