$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'battery.ps1') update @args
exit $LASTEXITCODE
