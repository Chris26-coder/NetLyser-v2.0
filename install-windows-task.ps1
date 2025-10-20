# PowerShell script to create a scheduled task that runs NetLyser at startup
$action = New-ScheduledTaskAction -Execute 'C:\Users\chris\AppData\Local\Programs\Python\Python313\python.exe' -Argument 'C:\Users\chris\Downloads\netlyser-main\netlyser-main\netlyser.py'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "NetLyser" -Action $action -Trigger $trigger -Principal $principal -Description "Run NetLyser at system startup"
