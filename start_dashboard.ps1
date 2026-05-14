# Compatibility wrapper for older documentation.
# The canonical entrypoint is run.ps1.

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $scriptPath "run.ps1")
exit $LASTEXITCODE
