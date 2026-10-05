$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Get-Command py -ErrorAction SilentlyContinue
if (-not $python) {
    throw "Python Launcher (py) is required. Install Python 3.13 and enable the launcher."
}
& $python.Source -3.13 -m venv (Join-Path $root "desktop\.venv")
if ($LASTEXITCODE -ne 0) { throw "Could not create the desktop Python 3.13 environment." }
$venvPython = Join-Path $root "desktop\.venv\Scripts\python.exe"
& $venvPython -m pip install -r (Join-Path $root "desktop\requirements.lock")
if ($LASTEXITCODE -ne 0) { throw "Desktop dependency installation failed." }
Write-Host "Desktop environment is ready. Start the backend separately, then run .\start_desktop.ps1."
