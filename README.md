# Bug Bounty Workbench V1

Bug Bounty Workbench is a local Windows application for organizing authorized
security assessments. It helps track project scope and assets, collect bounded
reconnaissance observations, assess discovered web and API surfaces, record
security candidates with evidence, and prepare project reports. Heuristic
candidates are observations for review; they are not claims of confirmed
exploitation.

## Architecture

The native PySide6 desktop application talks to a separate FastAPI backend on
loopback. The backend uses asynchronous SQLAlchemy, SQLite, and Alembic. The
backend owns project isolation, current-scope authorization, approval checks,
bounded execution, audit events, results, evidence, finding correlation and
risk, and report generation. The desktop does not connect to SQLite directly.

```text
PySide6 desktop -> loopback FastAPI -> SQLAlchemy async -> SQLite
                                           Alembic migrations
```

The application version is 1.0.0. The current schema head is
`d6249ab317e1`; Phase 14, Phase 15, and V1 integration required no schema
migration beyond the existing history.

## Windows setup

Use 64-bit Python 3.13 with the Python Launcher. In PowerShell at the
repository root:

```powershell
.\setup_backend.ps1
.\setup_desktop.ps1
.\migrate_database.ps1
```

The setup scripts create separate backend and desktop virtual environments
and install dependencies from the checked-in lock files. They do not install
external reconnaissance tools or change system configuration.

By default, data is stored in
`%LOCALAPPDATA%\BugBountyWorkbench\bugbounty.db`. `BUGBOUNTY_DATA_DIR` can
select another directory. Paths with spaces are supported. The repository's
development database is `backend\bugbounty.db`; to use it, set the same
directory before migration and backend startup:

```powershell
$env:BUGBOUNTY_DATA_DIR = (Join-Path $PWD "backend")
.\migrate_database.ps1
.\start_backend.ps1
```

Never replace or delete an existing database to install the application. The
backend verifies the selected database revision during startup.

## Run the application

Start the backend in one PowerShell window and the desktop in another:

```powershell
.\start_backend.ps1
```

```powershell
.\start_desktop.ps1
```

The backend binds to `127.0.0.1:8000`. The desktop accepts loopback API URLs
only and does not launch the backend silently. Health is available at
`http://127.0.0.1:8000/health`; API documentation is at
`http://127.0.0.1:8000/docs`.

The desktop workflow is Dashboard, Projects, Scopes, Assets, Findings,
Evidence, Recon & Assessment, and Reports. Assessment controls use project assets
and stored observations rather than a generic target URL field. Security
operations show pending approval, approved, and execution status. Assessment
results refresh findings and evidence in the selected project.

## Assessment capabilities

* **Project and scope management:** project-owned scopes and assets, included
  and excluded rules, and explicit target scope decisions.
* **Reconnaissance:** bounded DNS enrichment, HTTP observations, TLS and
  certificate inspection, technology indicators, fixed-path web surface
  discovery, and selected TCP service awareness.
* **Web and API assessment:** inspection of authorized stored surfaces;
  bounded observations of cookie attributes, CORS, redirects, disclosure,
  methods, and API documentation metadata. The existing Phase 9 assessment
  handles security-header gaps.
* **Authentication and authorization:** observed authentication and session
  surfaces, cookie observations, documented security requirements, and
  access-control candidates such as sensitive operations lacking declared
  authentication metadata or resource identifier parameters.
* **Vulnerability candidates:** safe observation-based indicators for HTML
  reflection, database or parser errors, path and fetch parameters, redirects,
  upload surfaces, and secret-like or internal information disclosure.
* **Findings and reporting:** deterministic normalization, deduplication,
  correlation, severity, confidence and risk prioritization, linked evidence,
  audit history, assessment summaries, and JSON, Markdown, and HTML export.

All assessment requests are project-scoped SecurityJobs. The backend checks
project ownership and current scope at execution, enforces approval where
network activity is involved, applies request and result caps, and records
audit events. Evidence and exported reports redact sensitive fields and keep
bounded useful context. Reports use stored authorized observations and do
not perform network activity.

## Security boundaries and limitations

Use this application only for assets covered by explicit authorization and
the project's current scope. Active operations require an approved job and
are bounded by server-side controls. HTTP operations use timeouts, response
caps, and bounded redirects; API document and endpoint counts are capped.
Incoming API request bodies are limited to 2 MiB. Fixed-path discovery is
limited and does not recursively crawl.

The application does not provide brute force, password spraying, credential
stuffing, credential harvesting, token theft, unrestricted crawling, arbitrary
URL scanning, internal-network probing, arbitrary commands or shell access,
destructive HTTP methods, state changes, ID enumeration, privilege escalation,
or automated exploitation. It does not upload test files or send exploit
payloads. Phase 15 candidates require manual verification when indicated;
missing metadata or a suspicious parameter name alone does not prove a
vulnerability. Risk scores support prioritization and do not establish
exploitability. Absence of a finding does not establish security.

## Development and verification

Run the backend, recon, Phase 16, and desktop test suites from the repository
root:

```powershell
backend\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_phase*.py" -v
backend\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_recon*.py" -v
desktop\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_desktop*.py" -v
```

The test network operations use deterministic fakes; the test suite does not
scan external hosts. Additional local checks include Python compilation,
`pip check`, `alembic upgrade head`, and `alembic check` from `backend`.

## Windows package

The supported desktop build uses PyInstaller onedir. It bundles the desktop,
PySide6 runtime, and resources; the FastAPI backend remains a separately
installed and started process:

```powershell
desktop\.venv\Scripts\python.exe -m pip install -r desktop\requirements-packaging.lock
.\build_windows.ps1
```

The executable is `dist\BugBountyWorkbench\BugBountyWorkbench.exe`. Start
the backend with `start_backend.ps1` before opening the packaged desktop. Basic
desktop startup does not require internet access.
