# Windows desktop application

The native PySide6 shell communicates with the FastAPI backend over HTTP and
does not open SQLite directly. It accepts loopback API hosts only. The default
API base is `http://127.0.0.1:8000`; override it with
`BUGBOUNTY_API_BASE_URL` when the local backend uses another loopback port.

From the repository root, run `setup_desktop.ps1` once, start the backend in a
separate PowerShell window with `start_backend.ps1`, and run
`start_desktop.ps1`. If the backend is unavailable, the window remains open
and reports its connection state. Recon operations remain explicit, scoped,
approval-gated actions in the existing Scan workflow.

For a release package, install the locked packaging dependencies into the
desktop environment and run `build_windows.ps1`. The resulting
`dist\BugBountyWorkbench\BugBountyWorkbench.exe` is a native onedir package;
the local backend remains a separately started process. See the root README
for installation, data directory, migration, packaging, and security details.

Run desktop tests from the repository root with:

```powershell
desktop\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_desktop*.py" -v
```
