$ErrorActionPreference = 'Stop'
$TaskName = 'wcprime-' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$InstallDir = Join-Path $env:LOCALAPPDATA 'wc-prime'
$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($Task) {
    Stop-ScheduledTask -TaskName $TaskName
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
$Binary = Join-Path $InstallDir 'wcprime.exe'
if (Test-Path -LiteralPath $Binary) { Remove-Item -LiteralPath $Binary -Force }
Write-Output 'wcprime task and executable removed. Saved configuration has been retained.'
