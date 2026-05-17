Set WshShell = CreateObject("WScript.Shell")
' Run run.bat in hidden mode (0)
WshShell.Run chr(34) & "run.bat" & chr(34), 0
Set WshShell = Nothing
