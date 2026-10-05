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

Current schema head: `d6249ab317e1` (Phase 13). The migration registers the
built-in TCP service-awareness adapter in the existing tool catalog; it does
not create a parallel results or evidence schema.

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
bounded to DNS, HTTP, TLS, fixed-path endpoint inspection, and TCP service
awareness. The desktop exposes no arbitrary URL scanning or shell execution
control.

## Phase 13 reconnaissance

Phase 13 extends the existing approved SecurityJob workflow. Passive Subfinder
results are capped at 100 (the desktop can select a lower cap), deduplicated,
checked against current project scope, restricted to descendants of the
selected root, and materialized as existing domain assets. Subfinder must be
installed and configured locally; it is a passive source adapter, not a
wordlist enumerator.

Web endpoint inspection chooses up to 12 paths from a fixed built-in path list.
It keeps same-host authorization checks, at most two redirects, eight-second
per-request bounds, a 60-second overall cap, and the existing bounded response
size. TCP service awareness requires an existing authorized IP asset and checks
only TCP ports 22, 80, 443, 445, 8080, and 8443, with at most a three-second
connection timeout. Port requests are individually reauthorized and audited.
No UDP, ranges, recursive crawling, fuzzing, credentials, or exploitation are
provided. Observations are not proof of vulnerabilities.

Stored assets, observations, and canonical findings can be inspected through
`GET /projects/{project_id}/recon/correlation`. The response is a deterministic,
read-only grouping by observed hostname and retains observation/job provenance;
it does not create findings or alter Phase 10 risk values. The Scan view exposes
the same bounded result/path/port controls before job approval.

Evidence and audit use existing database structures. Assessments and JSON,
Markdown, and HTML reports use stored observations only. Report generation
performs no network requests, omits filesystem paths and sensitive values, and
does not treat a missing finding as proof of security. Findings describe the
implemented observations and deterministic analysis; exploitability is not
guaranteed and can require manual validation. This local Workbench does not
provide unrestricted offensive scanning or public SaaS authentication.

## Final architecture

## Phase 14 advanced web and API assessment

The Scan view can request a web or API assessment for a selected project asset.
Each request is a SecurityJob, needs explicit approval, and is checked against
current project scope both when approved and when run. Assessments inspect at
most 100 stored endpoint observations and create deduplicated, evidence-backed
candidate findings through the existing Finding and Evidence tables. Web
checks cover observed session-cookie attributes, CORS, advertised unusual
methods, HTTP-to-HTTPS observations, and server disclosure. Existing Phase 9
security-header assessment remains the source for header-gap analysis.

API metadata is normalized from an OpenAPI document already present in stored
observation metadata; extraction caps the document at 64 KiB, paths at 100,
and parameters at 50 per operation. Query parameters in observed URLs are
listed as input-surface metadata. Malformed specifications are safely ignored.
The Phase 14 API does not accept arbitrary URLs and does not make network
requests: API documentation must first be captured by the existing approved,
fixed-path web-surface workflow. Credentials and cookie values are not retained
by the Phase 14 analyzers. These are conservative candidates requiring manual
validation, not proof of exploitability. No fuzzing, destructive methods,
credential attacks, recursive crawl, or command execution is provided.

The new project-scoped endpoints are `POST /projects/{project_id}/security-assessments/{web|api}`,
`POST /projects/{project_id}/security-assessments/{web|api}/{job_id}/approve`,
`POST /projects/{project_id}/security-assessments/{web|api}/{job_id}/run`, and
`GET /projects/{project_id}/security-assessments/{web|api}`. This phase adds no
database migration. Tests are in `tests/test_phase14.py`.

```text
PySide6 desktop -> loopback FastAPI -> SQLAlchemy async -> SQLite
                                         Alembic migrations
```

Desktop and backend are separate processes. The backend owns authorization,
scope checks, approvals, bounded recon execution, evidence, audit, findings,
risk, and report generation.
