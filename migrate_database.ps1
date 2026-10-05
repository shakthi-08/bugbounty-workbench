$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backend = Join-Path $root "backend"
$python = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Backend environment is missing. Run .\setup_backend.ps1 first."
}
Push-Location $backend
try {
    & $python -m alembic -c alembic.ini upgrade head
    if ($LASTEXITCODE -ne 0) { throw "Database migration failed; review the Alembic output." }
    & $python -m alembic -c alembic.ini current
    if ($LASTEXITCODE -ne 0) { throw "Could not verify the current database revision." }
} finally {
    Pop-Location
}
