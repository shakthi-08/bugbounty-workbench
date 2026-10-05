$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Get-Command py -ErrorAction SilentlyContinue
if (-not $python) {
    throw "Python Launcher (py) is required. Install Python 3.13 and enable the launcher."
}
& $python.Source -3.13 -m venv (Join-Path $root "backend\.venv")
if ($LASTEXITCODE -ne 0) { throw "Could not create the backend Python 3.13 environment." }
$venvPython = Join-Path $root "backend\.venv\Scripts\python.exe"
& $venvPython -m pip install -r (Join-Path $root "backend\requirements-dev.lock")
if ($LASTEXITCODE -ne 0) { throw "Backend dependency installation failed." }
Write-Host "Backend environment is ready. Run .\migrate_database.ps1 before starting the backend."
