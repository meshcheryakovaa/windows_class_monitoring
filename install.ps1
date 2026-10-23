$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'battery.ps1') setup @args
exit $LASTEXITCODE
