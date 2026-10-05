$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root "desktop\.venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Desktop environment is missing. Run .\setup_desktop.ps1 first."
}
Push-Location $root
try {
    & $python -m desktop.app
    if ($LASTEXITCODE -ne 0) { throw "Desktop application stopped with exit code $LASTEXITCODE." }
} finally {
    Pop-Location
}
