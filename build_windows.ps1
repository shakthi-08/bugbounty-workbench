$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$builder = Join-Path $root "desktop\.venv\Scripts\pyinstaller.exe"
$spec = Join-Path $root "desktop_workbench.spec"
if (-not (Test-Path -LiteralPath $builder -PathType Leaf)) {
    throw "PyInstaller is missing. Install desktop\requirements-packaging.lock in desktop\.venv first."
}
Push-Location $root
try {
    & $builder --clean --noconfirm $spec
    if ($LASTEXITCODE -ne 0) { throw "Windows package build failed." }
    $exe = Join-Path $root "dist\BugBountyWorkbench\BugBountyWorkbench.exe"
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Build finished without the expected executable." }
    Write-Host "Package created: $exe"
    Write-Host "Start the local backend separately with .\start_backend.ps1."
} finally {
    Pop-Location
}
