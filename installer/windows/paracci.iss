#define AppName "Paracci"
#define AppExeName "Paracci.exe"
#define AppPublisher "Paracci"
#define AppId "{{1A51B3D6-AE20-46A8-9F01-4D7899C33B12}"
#define FileProgId "Paracci.EncryptedMessage"

#ifndef AppVersion
  #error AppVersion must be provided with /DAppVersion=MAJOR.MINOR.PATCH
#endif

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppComments=Offline secure messaging for encrypted message exchange.
AppCopyright=Copyright (c) 2026 Paracci. All rights reserved.
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
PrivilegesRequired=lowest
DisableWelcomePage=no
DisableProgramGroupPage=yes
DisableReadyPage=no
LicenseFile=..\..\LICENSE
SetupIconFile=..\..\paracci_icon.ico
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}
OutputDir=..\..\builds\windows
OutputBaseFilename=Paracci-Setup-v{#AppVersion}
VersionInfoVersion={#AppVersion}.0
VersionInfoProductVersion={#AppVersion}.0
ChangesAssociations=yes
CreateUninstallRegKey=yes
Uninstallable=yes
Compression=lzma2
SolidCompression=yes

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nParacci is an offline secure messaging application for encrypted message exchange.%n%nIt is recommended that you close all other applications before continuing.

[Types]
Name: "standard"; Description: "Standard installation"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "startmenu"; Description: "Create Start Menu folder and shortcuts"; Types: standard
Name: "desktopicon"; Description: "Create Desktop shortcut"; Types: standard
Name: "fileassoc"; Description: "Associate .paracci files with Paracci"; Types: standard

[Files]
; Never install a sibling data directory: its presence switches the application to Portable Mode.
Source: "..\..\builds\windows\Paracci\*"; DestDir: "{app}"; Excludes: "\data\*"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Components: startmenu
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"; Components: startmenu
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Components: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Classes\.paracci"; ValueType: string; ValueName: ""; ValueData: "{#FileProgId}"; Flags: uninsdeletevalue uninsdeletekeyifempty; Components: fileassoc
; An empty named value is the Windows-compatible OpenWithProgids registration form available in [Registry].
Root: HKCU; Subkey: "Software\Classes\.paracci\OpenWithProgids"; ValueType: string; ValueName: "{#FileProgId}"; ValueData: ""; Flags: uninsdeletevalue uninsdeletekeyifempty; Components: fileassoc
Root: HKCU; Subkey: "Software\Classes\{#FileProgId}"; ValueType: string; ValueName: ""; ValueData: "Paracci Encrypted Message"; Flags: uninsdeletekey; Components: fileassoc
Root: HKCU; Subkey: "Software\Classes\{#FileProgId}\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExeName}"",0"; Components: fileassoc
Root: HKCU; Subkey: "Software\Classes\{#FileProgId}\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExeName}"" ""%1"""; Components: fileassoc

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
const
  PreviousUninstallKey =
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{1A51B3D6-AE20-46A8-9F01-4D7899C33B12}_is1';

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  UninstallCommand: String;
  ResultCode: Integer;
begin
  Result := '';
  NeedsRestart := False;

  if not RegQueryStringValue(HKCU, PreviousUninstallKey, 'UninstallString', UninstallCommand) then
    Exit;

  Log('Existing Paracci installer registration found; removing the previous version.');
  if not Exec(
    '>',
    UninstallCommand + ' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode) then
  begin
    Result := 'The previous Paracci installation could not be removed automatically. ' +
      'Installation cannot continue.';
    Exit;
  end;

  if ResultCode <> 0 then
    Result := 'The previous Paracci uninstaller returned error code ' +
      IntToStr(ResultCode) + '. Installation cannot continue.';
end;
