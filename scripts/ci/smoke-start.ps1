# Starts the built application, checks that it keeps running with a main
# window and that it created and migrated its SQLite database, then stops it.
# This proves the Tauri shell, WebView2 and the backend setup start on
# Windows; it does not exercise the UI.
param([Parameter(Mandatory = $true)][string]$Exe)
$ErrorActionPreference = "Stop"

$db = Join-Path $env:LOCALAPPDATA "io.github.stardely62.networkintelligence\ni.sqlite3"
if (Test-Path $db) { Remove-Item $db -Force }

$p = Start-Process -FilePath (Resolve-Path $Exe) -PassThru
try {
    $deadline = (Get-Date).AddSeconds(40)
    $window = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        if ($p.HasExited) { throw "application exited early with code $($p.ExitCode)" }
        $p.Refresh()
        if ($p.MainWindowHandle -ne 0 -and (Test-Path $db)) { $window = $true; break }
    }
    if (-not $window) { throw "no main window or database after 40 s (window=$($p.MainWindowHandle), db=$(Test-Path $db))" }
    Start-Sleep -Seconds 5
    if ($p.HasExited) { throw "application exited after start with code $($p.ExitCode)" }
    Write-Host "main window: $($p.MainWindowTitle); database: $db ($((Get-Item $db).Length) bytes)"
}
finally {
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
    # WebView2 runs in child processes; make sure none survive.
    Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $p.Id } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
