# Bug Bounty Workbench

Bug Bounty Workbench is a Windows-local security assessment application. Its
FastAPI backend uses SQLAlchemy, SQLite, and Alembic. A native PySide6 desktop
application communicates with the backend through a loopback-only API client.
The desktop does not access the database directly.

## Requirements and installation

Use 64-bit Python 3.13 on Windows with the Python Launcher (`py`). From a
PowerShell window in the repository directory:

```powershell
.\setup_backend.ps1
.\setup_desktop.ps1
```

These create separate virtual environments and install the exact dependency
versions in the checked-in lock files. The setup scripts do not download
external tools or alter system configuration. `backend\requirements.txt` and
`desktop\requirements.txt` list the direct application dependencies;
`backend\requirements-dev.lock`, `desktop\requirements.lock`, and
`desktop\requirements-packaging.lock` pin the reproducible Windows environment.

## Database and configuration

By default, backend data is stored at:

```text
%LOCALAPPDATA%\BugBountyWorkbench\bugbounty.db
```

If `LOCALAPPDATA` is missing, the application uses the current user's
`AppData\Local\BugBountyWorkbench` directory. `BUGBOUNTY_DATA_DIR` overrides
the directory. Absolute values are resolved directly; relative values are
resolved from the backend package directory, independently of the shell's
working directory. Paths containing spaces are supported. Running Alembic
creates the selected directory if needed. The API refuses to start against an
unmigrated or wrong-revision database.

The repository's existing development database is
`backend\bugbounty.db`. To explicitly continue using it, set the same data
directory in the migration and backend PowerShell sessions:

```powershell
$env:BUGBOUNTY_DATA_DIR = (Join-Path $PWD "backend")
.\migrate_database.ps1
```

In the PowerShell window used to run the backend, set the same value before
starting it. Otherwise the normal `%LOCALAPPDATA%` default is used. Never
delete or replace an existing database as part of setup.

Manual migration commands, run from the repository root:

```powershell
Push-Location backend
try {
    .\.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
    .\.venv\Scripts\python.exe -m alembic -c alembic.ini current
} finally { Pop-Location }
```

Current schema head: `c73f9a21d604`. The Phase 12 work requires no database
schema changes.

## Start the application

Start the backend in one PowerShell window:

```powershell
.\start_backend.ps1
```

Start the desktop application in another:

```powershell
.\start_desktop.ps1
```

The backend binds to `127.0.0.1:8000`; the desktop defaults to that URL and
accepts loopback addresses only. Set `BUGBOUNTY_API_BASE_URL` to another local
loopback port if required. The desktop does not launch a backend silently.
Health is available at `http://127.0.0.1:8000/health` and OpenAPI at
`http://127.0.0.1:8000/openapi.json`.

## Windows desktop package

The supported package is a PyInstaller onedir bundle. It includes the PySide6
runtime and desktop assets but keeps the backend as a separately installed and
started process. From the repository root:

```powershell
desktop\.venv\Scripts\python.exe -m pip install -r desktop\requirements-packaging.lock
.\build_windows.ps1
```

The executable is `dist\BugBountyWorkbench\BugBountyWorkbench.exe`. Start the
backend with `start_backend.ps1` before opening the packaged desktop app. The
package contains no credentials and makes no external connections.

## Test commands

Run the full backend functional suites, recon regressions, and desktop suite
from the repository root:

```powershell
backend\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_phase*.py" -v
backend\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_recon*.py" -v
desktop\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_desktop*.py" -v
```

## Security model and limitations

Projects own their scopes, assets, findings, jobs, assessments, evidence, and
audit records. Security jobs use the existing authorization and explicit
approval workflow; target scope is rechecked before execution. Recon remains
bounded to the implemented DNS, HTTP, TLS, and fixed-path web workflows. The
desktop exposes no arbitrary URL scanning or shell execution control.

Evidence and audit use existing database structures. Assessments and JSON,
Markdown, and HTML reports use stored observations only. Report generation
performs no network requests, omits filesystem paths and sensitive values, and
does not treat a missing finding as proof of security. Findings describe the
implemented observations and deterministic analysis; exploitability is not
guaranteed and can require manual validation. This local Workbench does not
provide unrestricted offensive scanning or public SaaS authentication.

## Final architecture

```text
PySide6 desktop -> loopback FastAPI -> SQLAlchemy async -> SQLite
                                         Alembic migrations
```

Desktop and backend are separate processes. The backend owns authorization,
scope checks, approvals, bounded recon execution, evidence, audit, findings,
risk, and report generation.
