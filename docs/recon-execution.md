# Phase 4 reconnaissance execution

The desktop sends job requests to FastAPI; it never launches a process or opens
the database. A recon job belongs to one project and snapshots its target,
scope, profile, module, selected tool, and parameters. FastAPI checks the target
at creation, approval, and execution start using the existing scope validator.
An explicit exclusion wins over an inclusion. Approval is required before the
execution endpoint queues work.

The execution registry enables these adapters:

| Adapter key | Executable | Request |
| --- | --- | --- |
| `windows_nslookup` | `nslookup.exe` | DNS A record lookup |
| `curl_head` | `curl.exe` | One HTTP HEAD request; no redirect following |
| `subfinder` | Configured `subfinder.exe` | ProjectDiscovery passive subdomain enumeration (`-silent -d <authorized-domain>`) |

Executables are checked at tool listing and immediately before launch. Subfinder
can use a PATH entry or an explicit local executable path in its registered tool
configuration. The application never installs Subfinder. Its adapter does not
enable active enumeration options.
The adapter supplies executable and arguments; the API does not accept a
command line or shell. Process output is drained with a 2 MB cap, process
runtime is capped at 300 seconds, and a cancellation terminates the child.

Normalized output is stored in `security_results`; stdout and stderr are
written under `<BUGBOUNTY_DATA_DIR>/evidence/recon` and linked from `evidence`
with a SHA-256 digest and timestamps. The job execution endpoint reads only
those locally generated artifacts. Job and authorization lifecycle events use
the shared `security_audit_logs` table. The application does not install tools.

Subfinder output is normalized as individual hostname results. Each hostname is
checked against the project's current scope after execution; exclusions take
priority, and only currently authorized hostnames are persisted as results.
Rejected and malformed output is recorded in audit metadata, while the original
stdout/stderr remains available in hashed evidence.

## Phase 6 DNS and explicitly selected HTTP probes

The registered `windows_nslookup` adapter accepts only A, AAAA, CNAME, MX, NS,
and TXT record types. It runs one bounded `nslookup.exe -type=<TYPE> <target>`
process per requested type using the shared supervisor. DNS names and addresses
are normalized into individual `dns_record` results. Hostname-valued answers
are checked against current scope; rejected candidates remain out of results and
are recorded in audit metadata. TXT values are available in normalized results,
but are redacted from evidence artifacts.

`curl_head` keeps HEAD as its default mode. Selected hosts can instead create a
separate `bounded_get` HTTP job through the `probe-selected` endpoint. That
endpoint accepts only authorized hostname candidates present in the completed
source job, checks current scope again, and creates a distinct pending-approval
job for each selection. Each job still requires approval and an explicit run.
Bounded GET requests do not follow redirects, use a 20 second default timeout,
request only a small byte range, and cap response transfer size. The parser
records status, title, redirect origin, Server, and selected safe headers.
Evidence retains safe headers and status while omitting response bodies and
redacting potentially secret response headers.

The desktop Scan view displays authorized discovered hostname candidates as
selectable rows. “Create HTTP Jobs for Selected Hosts” does not run probes; it
creates per-host approval-gated jobs that the user must select, approve, and
start separately. No migration was needed for Phase 6; the database head remains
`b5e7104c92ad`.
