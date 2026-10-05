# Backend setup

The backend uses SQLite in the current Windows user's local application data
directory by default:

```text
%LOCALAPPDATA%\BugBountyWorkbench\bugbounty.db
```

Set `BUGBOUNTY_DATA_DIR` to use another data directory. Relative values are
resolved from this `backend` directory. The migration command and API must use
the same value.

## Apply migrations

Install the dependencies in `requirements.txt`, then run migrations before
starting the API:

```powershell
Set-Location <repository>\backend
.\.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
```

To preserve and migrate the existing development database at
`backend\bugbounty.db` in place, use that directory explicitly:

```powershell
Set-Location <repository>\backend
$env:BUGBOUNTY_DATA_DIR = (Get-Location).Path
.\.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
```

The baseline migration validates existing `projects` and `scopes` columns and
leaves compatible tables and their rows intact. It creates any missing current
tables, including `assets` and `findings`, and records its revision in
`alembic_version`. It does not drop data; its downgrade deliberately refuses
to run.

The API does not run migrations at startup. If the database is missing, not at
the expected revision, or lacks a current table, startup fails with the
migration command to run.

## Start the local API

After migration, the development server remains bound to loopback:

```powershell
Set-Location <repository>\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

To keep using the existing development database, set `BUGBOUNTY_DATA_DIR` in
the same PowerShell session before starting Uvicorn.

The API integration tests use the additional test client dependency listed in
`requirements-dev.txt`. Install it with
`python -m pip install -r backend/requirements-dev.txt`. From the repository root,
run the tests with:

```powershell
Set-Location <repository>
..\backend\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Phase 3 foundation and Phase 4 execution

The `f438b4b9161f` migration adds a database-backed assessment taxonomy
(domains, categories, and test modules), a metadata-only tool registry, ten
global scan-profile definitions, security jobs, normalized results, local
evidence references, and a security audit log. The taxonomy uses stable keys
for web, API, network, infrastructure, identity, mobile, cloud, container,
Kubernetes, source, dependency, secrets, IaC, IoT, firmware, desktop, binary,
wireless, blockchain, Web3, and AI/LLM assessments. Catalog records are seeded
by the migration and are idempotent within that migration.

The tool and adapter registries are separate. Catalog entries without an
implemented adapter remain metadata only. Phase 4 adds two adapter controlled
Windows recon tools: `windows_nslookup` for DNS A record lookups and `curl_head`
for a single HTTP HEAD request and observed Server header. Availability is
detected from the executable PATH (`nslookup.exe`, `curl.exe`) when `/tools` is
read and again before execution. The app does not install tools. Other catalog
tools remain unavailable until real adapters are implemented.

Jobs are created in `pending_approval` only after the backend independently
validates the project target using the existing scope engine. Explicit
exclusions override inclusion, and a target without a matching inclusion is
blocked. A selected asset must belong to the same project and match the job
target. Derived targets are revalidated independently. Approval records the
approver and timestamp and freezes target, scope, profile, module, tool, and
parameter snapshots. Scope and tool availability are checked again before
execution. The runner uses explicit adapter arguments and no shell, captures
stdout/stderr, enforces a 300 second maximum timeout and a 2 MB output cap, and
supports cancellation. HTTP redirects are not followed. Job statuses include
queued, running, completed, failed, cancelled, timed_out, and blocked.

Results use the existing normalized payload for DNS addresses, HTTP endpoints,
and observed server technology. Stdout/stderr artifacts are stored under
`%LOCALAPPDATA%\BugBountyWorkbench\evidence\recon` or the configured
`BUGBOUNTY_DATA_DIR`, with SHA-256 and execution metadata in Evidence records.
The job execution endpoint only reads files in that recon artifact directory.
Audit records cover job creation, authorization, execution, failure, timeout,
cancellation, scope rejection, results, and evidence.

API routes include `/assessment-domains`, `/assessment-categories`,
`/assessment-modules`, `/tools`, `/scan-profiles`, project-scoped
`/security-jobs`, `/security-jobs/{id}/run`, `/security-jobs/{id}/execution`,
`/security-results`, `/evidence`, and `/security-audit`. The desktop uses HTTP
only; the backend remains authoritative for scope and execution.

Recon is limited to a DNS A lookup or one HTTP HEAD request. There is no
subdomain enumeration, port scanning, crawling, exploitation, or broad target
discovery. Explicit project scope and job approval are required. Apply the
Phase 4 migration before starting the API with `python -m alembic -c alembic.ini upgrade head`.

## Phase 7: bounded TLS certificate inspection

The `tls_inspector` catalog entry uses Python's standard-library `ssl` and
`asyncio` support. It makes one TLS connection to the explicitly selected DNS
hostname on TCP port 443, with the platform CA store and hostname verification
enabled. Connection setup is limited to 1–30 seconds (15 seconds by default),
and TLS shutdown is bounded as well. A certificate verification failure is
reported without retrying with verification disabled.

Direct TLS jobs must reference an existing asset belonging to the selected
project. The asset value must match the target and pass current project scope
checks. The Scan view also supports selecting authorized host results from a
completed job; it creates a separate approval-gated TLS job for each selected
host after rechecking current scope. Every job is revalidated at approval and
again immediately before execution. There is no arbitrary-host TLS endpoint.

Normalized results include the hostname and port, connected address, TLS
version, cipher, certificate subject and issuer, serial number, validity dates
and current validity state, DNS subject alternative names, SHA-256 certificate
fingerprint, hostname verification state, and a bounded connection error when
present. The standard library does not expose parsed public-key parameters on
this path, so the feature does not attempt to decode certificate keys. Results,
small normalized evidence files, job lifecycle, authorization decisions, and
audit events use the existing security result, evidence, job, and audit tables;
no schema change is needed. Private keys are never collected.

TLS inspection intentionally does not scan other ports or hosts, enumerate
subdomains, perform downgrade or certificate attacks, exploit vulnerabilities,
or bypass certificate checks. Phase 7 uses the existing migration that registers
the TLS tool; apply migrations with `python -m alembic -c alembic.ini upgrade head`.
Run backend tests from the repository root with
`backend\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_phase*.py" -v`
and
`backend\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_recon_execution.py" -v`.
The desktop suite uses
`desktop\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_desktop*.py" -v`.

## Phase 8: bounded web surface discovery and technology indicators

The `web_surface_discovery` built-in adapter checks five fixed paths on one
selected web asset: `/`, `/robots.txt`, `/sitemap.xml`,
`/.well-known/security.txt`, and `/security.txt`. It sends sequential GET
requests, follows at most two same-host redirects, caps response headers at
32 KiB, captures at most 64 KiB of each body, limits each request to at most
eight seconds, and stops the overall operation after 60 seconds. It does not
recursively crawl links or retain response bodies. Redirects to other hosts,
queries, unsupported destinations, or unapproved service ports are recorded
and never requested.

Every job requires an existing asset in the selected project, an in-scope
authorization decision, and explicit approval. The backend rechecks scope
before each initial or redirected request. The API accepts project/job/asset
context through the existing security-job routes; it is not an arbitrary-host
scanner. Results contain normalized endpoint status, response headers,
content length/bytes, redirect observations, bounded timing, and errors.
Fingerprinting uses only observed Server/X-Powered-By headers, cookie names,
HTML generator markers, and common HTML asset/framework markers. Each
technology includes concise evidence and a conservative `high`, `medium`, or
`low` confidence; these are indicators, not definitive identification.
Cookie values and full page bodies are not stored. No extra dependency or
schema migration is needed beyond the migration that registers the built-in
tool. Run the backend and desktop test commands above; Phase 8 tests are in
`tests/test_phase8.py` and the desktop Scan view tests are in
`tests/test_desktop_scan_view.py`.

Phase 8 intentionally does not spider recursively, enumerate arbitrary paths,
scan ports, exploit vulnerabilities, brute force, attack certificates, or
follow redirects outside current authorized scope.

## Phase 9: passive security header and web configuration assessment

Phase 9 consumes a completed Phase 8 endpoint result already stored for the
selected project asset. It makes no HTTP requests. It evaluates HSTS, CSP,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options,
safe cookie attribute summaries, and observed Server/X-Powered-By disclosures.
Cookie values are discarded during Phase 8 parsing and are never persisted.

Request an assessment with `POST /projects/{project_id}/security-header-assessments`
using `asset_id`, `observation_id`, and optionally `requested_by`. Approve it
with `/security-header-assessments/{job_id}/approve`, then start it with
`/security-header-assessments/{job_id}/run`. The backend rechecks project/asset,
source observation, scope authorization, and approval before evaluation.

Missing CSP and low-impact headers are informational or low. Confidence is
high for directly observed states, medium for contextual indicators, and low
for heuristic cookie relevance. Evidence is concise and normalized; remediation
is defensive. Stable fingerprints suppress repeated issues for the same
project, asset, endpoint, and type. Audit events record requests, authorization,
approval, evaluation, findings, duplicates, completion, and rejection. Phase 9
does not exploit, authenticate, attack credentials, probe arbitrary URLs, crawl,
or implement another TLS scanner. Migration `e92c4b71ad30` adds finding metadata
and stable fingerprinting. Run backend tests with
`backend\\.venv\\Scripts\\python.exe -m unittest discover -s tests -v` and
desktop tests with `desktop\\.venv\\Scripts\\python.exe -m unittest discover -s tests -p "test_desktop*.py" -v`.

## Phase 10: finding normalization, correlation, and risk priority

Phase 10 analyzes persisted findings only and performs no network requests.
Normalization trims repeated whitespace, canonicalizes categories and severity
labels, normalizes endpoint scheme/host/default ports/path, omits query and
fragment from identity, and retains original human-readable values and evidence.
The identity fingerprint is a deterministic SHA-256 over project, asset,
normalized endpoint, category, and issue condition; it excludes timestamps.

`POST /projects/{project_id}/findings/correlate` explicitly saves normalization,
canonical duplicate relationships, occurrence counts, correlation families,
risk score, priority, and explanation. Duplicate rows and evidence are retained;
duplicate evidence references remain visible with the canonical finding. The
operation is audited and rechecks current authorization for associated assets.
GET `/findings/analysis`, `/findings/{finding_id}/risk`, `/risk-summary`, and
`/risk-summary/assets/{asset_id}` calculate deterministic read-only views.

Severity remains the original issue classification. Risk uses fixed bases
(informational 0, low 25, medium 50, high 75, critical 95) multiplied by a
confidence factor (low .5, medium .75, high 1), rounded to an integer. Priority
maps scores 0–19 informational, 20–39 low, 40–59 medium, 60–79 high, and 80–100
critical. Asset modifiers are currently zero because no validated criticality
field exists; correlation adds explanatory context but never raises severity
or score. Asset/project summaries use the highest finding score and average,
not a sum, so many low findings cannot inflate aggregate risk. Correlation is
limited to same-asset, same-endpoint security header, transport, cookie, and
information/technology disclosure families. This is contextual grouping, not
proof of exploitability. Migration `f1a8c6d30b42` adds identity, canonical link,
occurrence, risk, priority, explanation, and correlation fields to findings.

## Phase 11: assessments, evidence, reports, and export

Assessments are project-scoped records with `draft`, `in_progress`,
`completed`, and `archived` lifecycle states. A report is assembled from stored
project records when requested; generating or exporting it performs no network
activity. Current asset authorization is rechecked, findings are reported
through the Phase 10 canonical identity/risk semantics, and duplicate
occurrences and existing evidence references are retained. Evidence exports
include safe labels, provenance allowlists, hashes, and record identifiers;
filesystem paths and sensitive values are omitted or redacted. Report creation,
updates, generation, statistics, and exports are recorded in the existing
security audit log.

Available project-scoped API routes are `GET/POST /projects/{project_id}/assessments`,
`GET/PATCH /projects/{project_id}/assessments/{assessment_id}`, report and
statistics retrieval under `/report` and `/report/statistics`, and JSON,
Markdown, and HTML exports under `/export/{json|markdown|html}`. Assessment IDs
are checked against the path project. Reports include deterministic executive
summary, scope, stored reconnaissance, canonical findings, Phase 10 risk and
correlation details, statistics, affected assets, evidence references,
remediation themes, methodology, audit summary, and limitations.

The methodology describes only stored DNS, bounded HTTP, TLS/certificate,
fixed-path web surface, technology, and Phase 9 configuration observations,
plus Phase 10 normalization/correlation/risk. It does not claim exploitation,
credential attacks, brute force, authenticated testing, or vulnerability
verification. Severity remains distinct from remediation priority. Risk is a
prioritization aid; lack of a finding does not establish that a project is
secure. Migration `c73f9a21d604` adds the assessment lifecycle table.

Run the full backend tests from the repository root with
`backend\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_phase*.py" -v`
and recon regression tests with
`backend\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_recon*.py" -v`.
Phase 11 verification completed with 63 Phase 1-11 tests, 10 recon regression
tests, and 22 desktop tests (95 total).
