param(
    [string]$Source = (Join-Path $PSScriptRoot 'wcprime.exe')
)
$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path $env:LOCALAPPDATA 'wc-prime'
$Binary = Join-Path $InstallDir 'wcprime.exe'
$User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$TaskName = 'wcprime-' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
    throw "Binary not found: $Source. Pass -Source with the downloaded wcprime.exe path."
}
# Stop an existing task before replacing a running executable.
$Existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($Existing) { Stop-ScheduledTask -TaskName $TaskName }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
if ([IO.Path]::GetFullPath($Source) -ne [IO.Path]::GetFullPath($Binary)) {
    Copy-Item -LiteralPath $Source -Destination $Binary -Force
}
$Action = New-ScheduledTaskAction -Execute $Binary -Argument 'run' -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $User
$Principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -Hidden -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
    -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
# The GUI-subsystem binary has no console. Redirect stdout explicitly for `url`.
$UrlFile = [IO.Path]::GetTempFileName()
try {
    for ($Attempt = 0; $Attempt -lt 20; $Attempt++) {
        $Process = Start-Process -FilePath $Binary -ArgumentList 'url' `
            -RedirectStandardOutput $UrlFile -PassThru -Wait -WindowStyle Hidden
        $Link = Get-Content -LiteralPath $UrlFile -Raw
        if ($Process.ExitCode -eq 0 -and $Link) { Write-Output $Link.Trim(); break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $Link) { Write-Warning 'Service started; run wcprime.exe url once initialization completes.' }
} finally {
    Remove-Item -LiteralPath $UrlFile -Force
}
