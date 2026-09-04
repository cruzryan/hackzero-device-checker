Unregister-ScheduledTask -TaskName 'HackZero Device Checker' -Confirm:$false -ErrorAction SilentlyContinue
Write-Output 'HackZero Device Checker automatic start was removed. Local evidence history remains in HackZero.'
