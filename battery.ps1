# No parameter block: forward --json, --stdin and other CLI options unchanged.
$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $OutputEncoding
$script:MonitorPython = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    $candidate = & py -3 -c "import sys; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0) { $script:MonitorPython = [string]($candidate | Select-Object -Last 1) }
}
if (-not $script:MonitorPython -and (Get-Command python -ErrorAction SilentlyContinue)) {
    $candidate = & python -c "import sys; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0) { $script:MonitorPython = [string]($candidate | Select-Object -Last 1) }
}
if (-not $script:MonitorPython) {
    Write-Error 'Install Python 3.10+ from https://www.python.org/downloads/windows/ (include the Python launcher).'
    exit 1
}
& $script:MonitorPython -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) { Write-Error 'Python 3.10 or newer is required.'; exit 1 }
& $script:MonitorPython (Join-Path $PSScriptRoot 'battery_monitor.py') @args
exit $LASTEXITCODE
