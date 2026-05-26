Dim fso, WshShell
Set fso = CreateObject("Scripting.FileSystemObject")
Set WshShell = CreateObject("WScript.Shell")

Dim parentFolder
parentFolder = fso.GetParentFolderName(WScript.ScriptFullName)
If parentFolder = "" Then parentFolder = "."

' Resolve OS-specific local AppData path for Paracci
Dim localAppData, userDir
localAppData = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%")
If localAppData = "%LOCALAPPDATA%" Or localAppData = "" Then
    Dim userProfile
    userProfile = WshShell.ExpandEnvironmentStrings("%USERPROFILE%")
    If userProfile = "%USERPROFILE%" Or userProfile = "" Then
        userDir = parentFolder & "\data"
    Else
        userDir = userProfile & "\AppData\Local\Paracci"
    End If
Else
    userDir = localAppData & "\Paracci"
End If

' Ensure the directory exists
If Not fso.FolderExists(userDir) Then
    On Error Resume Next
    fso.CreateFolder userDir
    On Error GoTo 0
End If

Dim errorLogPath, successTmpPath
errorLogPath = userDir & "\paracci_startup_error.log"
successTmpPath = userDir & "\paracci_startup_success.tmp"

' Clean up files from any previous execution
If fso.FileExists(errorLogPath) Then
    On Error Resume Next
    fso.DeleteFile errorLogPath, True
    On Error GoTo 0
End If
If fso.FileExists(successTmpPath) Then
    On Error Resume Next
    fso.DeleteFile successTmpPath, True
    On Error GoTo 0
End If

' Set working directory to the script's directory
WshShell.CurrentDirectory = parentFolder

' Run run.bat in hidden mode (0) and detach (False)
WshShell.Run chr(34) & "run.bat" & chr(34), 0, False

' Poll for up to 90 seconds (to allow venv creation and dependency installation if needed)
Dim maxWaitSeconds, elapsed
maxWaitSeconds = 90
elapsed = 0

Dim successDetected, errorDetected
successDetected = False
errorDetected = False

Do While elapsed < maxWaitSeconds
    If fso.FileExists(errorLogPath) Then
        errorDetected = True
        Exit Do
    End If
    If fso.FileExists(successTmpPath) Then
        successDetected = True
        Exit Do
    End If
    
    WScript.Sleep 1000 ' Sleep 1 second
    elapsed = elapsed + 1
Loop

If errorDetected Then
    ' Display warning popup (48) with 30-second timeout showing the error log location
    WshShell.Popup "Paracci failed to start. Please check '" & errorLogPath & "' for details.", 30, "Paracci Startup Error", 48
ElseIf successDetected Then
    ' Clean up the sentinel file
    On Error Resume Next
    fso.DeleteFile successTmpPath, True
    On Error GoTo 0
End If

Set WshShell = Nothing
Set fso = Nothing
