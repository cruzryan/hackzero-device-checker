# Registers the paired checker in the signed-in person's session. A per-user
# scheduled task is intentional: the device private key belongs to that user,
# not LocalSystem. No administrator prompt is needed for this registration.
param(
  [Parameter(Mandatory = $true)] [string]$ExecutablePath
)

$resolved = (Resolve-Path -LiteralPath $ExecutablePath).Path
$action = New-ScheduledTaskAction -Execute $resolved -Argument 'run'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 0)
Register-ScheduledTask -TaskName 'HackZero Device Checker' -Action $action -Trigger $trigger -Settings $settings -Description 'Runs read-only HackZero Device Checker posture reporting for the signed-in user.' -Force | Out-Null
Write-Output 'HackZero Device Checker starts automatically when this person signs in.'
