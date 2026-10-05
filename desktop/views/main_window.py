from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ..api_worker import ApiWorker
from ..widgets.status_pill import StatusPill
from .assets_view import AssetsView
from .dashboard_view import DashboardView
from .findings_view import FindingsView
from .evidence_view import EvidenceView
from .projects_view import ProjectsView
from .reports_view import ReportsView
from .scan_view import ScanView
from .scopes_view import ScopesView


class MainWindow(QMainWindow):
    NAV_ITEMS = [
        ("Dashboard", "dashboard"),
        ("Projects", "projects"),
        ("Scopes", "scopes"),
        ("Assets", "assets"),
        ("Findings", "findings"),
        ("Evidence", "evidence"),
        ("Recon & Assessment", "scan"),
        ("Reports", "reports"),
    ]

    def __init__(self, api_client, backend_manager, parent=None):
        super().__init__(parent)
        self.api_client = api_client
        self.backend_manager = backend_manager
        self.thread_pool = QThreadPool.globalInstance()
        self._workers = set()
        self.projects: list[dict] = []
        self.project_id: int | None = None
        self.current_project: dict | None = None
        self.scopes: list[dict] | None = None
        self.assets: list[dict] = []
        self.findings: list[dict] = []
        self._recon_completion_refreshes: set[int] = set()
        self.nav_buttons: dict[str, QPushButton] = {}

        self.setWindowTitle("Bug Bounty Workbench")
        self.setMinimumSize(1024, 700)
        self.resize(1280, 820)
        self._build_ui()
        self.dashboard_view.refresh_button.clicked.connect(self.refresh_workspace)
        self.refresh_button.clicked.connect(self.refresh_workspace)
        self.projects_view.project_selected.connect(self._select_project)
        self._select_page("Dashboard")
        self.scan_view.request_api.connect(self._request)
        self.findings_view.request_api.connect(self._request)
        self.reports_view.request_api.connect(self._request)
        self.reports_view.project_selected.connect(self._select_project)
        self.scan_view.set_domains([])
        self.refresh_workspace()
        self._request("scan_domains", "/assessment-domains")
        self._request("scan_profiles", "/scan-profiles")
        self._request("scan_tools", "/tools")

    def _build_ui(self):
        central = QWidget()
        central.setObjectName("appRoot")
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 24, 16, 18)
        sidebar_layout.setSpacing(8)

        brand = QLabel("BUG BOUNTY\nWORKBENCH")
        brand.setObjectName("brand")
        sidebar_layout.addWidget(brand)
        local_note = QLabel("LOCAL SECURITY WORKSPACE")
        local_note.setObjectName("sidebarCaption")
        sidebar_layout.addWidget(local_note)
        sidebar_layout.addSpacing(22)

        for label, key in self.NAV_ITEMS:
            button = QPushButton(label)
            button.setObjectName("navButton")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, item=label: self._select_page(item))
            sidebar_layout.addWidget(button)
            self.nav_buttons[label] = button
        sidebar_layout.addStretch(1)
        sidebar_footer = QLabel("Local data | Guided workflow")
        sidebar_footer.setObjectName("sidebarCaption")
        sidebar_layout.addWidget(sidebar_footer)
        root_layout.addWidget(sidebar)

        content = QWidget()
        content.setObjectName("contentArea")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar_layout = QHBoxLayout(topbar)
        topbar_layout.setContentsMargins(28, 14, 28, 14)
        self.connection_pill = StatusPill("Connecting...")
        self.refresh_button = QPushButton("Reconnect / Refresh")
        self.refresh_button.setObjectName("secondaryButton")
        topbar_layout.addWidget(self.connection_pill)
        topbar_layout.addStretch(1)
        topbar_layout.addWidget(self.refresh_button)
        content_layout.addWidget(topbar)

        self.error_banner = QLabel()
        self.error_banner.setObjectName("errorBanner")
        self.error_banner.setWordWrap(True)
        self.error_banner.hide()
        content_layout.addWidget(self.error_banner)

        self.stack = QStackedWidget()
        self.views = {
            "Dashboard": DashboardView(),
            "Projects": ProjectsView(),
            "Scopes": ScopesView(),
            "Assets": AssetsView(),
            "Findings": FindingsView(),
            "Evidence": EvidenceView(),
            "Reports": ReportsView(),
            "Recon & Assessment": ScanView(),
        }
        for view in self.views.values():
            self.stack.addWidget(view)
        content_layout.addWidget(self.stack, 1)
        root_layout.addWidget(content, 1)
        self.setCentralWidget(central)

        self.dashboard_view = self.views["Dashboard"]
        self.projects_view = self.views["Projects"]
        self.scopes_view = self.views["Scopes"]
        self.assets_view = self.views["Assets"]
        self.findings_view = self.views["Findings"]
        self.evidence_view = self.views["Evidence"]
        self.reports_view = self.views["Reports"]
        self.scan_view = self.views["Recon & Assessment"]

    def _select_page(self, name: str):
        view = self.views.get(name)
        if view is None:
            return
        self.stack.setCurrentWidget(view)
        for label, button in self.nav_buttons.items():
            button.setChecked(label == name)
        if name == "Projects" and not self.projects:
            self._request("projects", "/projects")
        elif name == "Scopes" and self.project_id is not None:
            self._request("scopes", f"/projects/{self.project_id}/scopes")
        elif name == "Assets" and self.project_id is not None:
            self._request("assets", f"/projects/{self.project_id}/assets")
        elif name == "Findings" and self.project_id is not None:
            self._request("finding_analysis", f"/projects/{self.project_id}/findings/analysis")
            self._request("finding_summary", f"/projects/{self.project_id}/risk-summary")

    def refresh_workspace(self):
        self.error_banner.hide()
        self._request("health", "/health")
        self._request("projects", "/projects")
        if self.project_id is not None:
            self._request_project_data()

    def _request_project_data(self):
        if self.project_id is None:
            return
        project_id = self.project_id
        self._request("scopes", f"/projects/{project_id}/scopes")
        self._request("assets", f"/projects/{project_id}/assets")
        self._request("finding_analysis", f"/projects/{project_id}/findings/analysis")
        self._request("finding_summary", f"/projects/{project_id}/risk-summary")
        self._request("evidence", f"/projects/{project_id}/evidence?limit=500")
        self._request("scan_correlation", f"/projects/{project_id}/recon/correlation")

    def _request(self, key: str, path: str, method: str = "GET", payload=None):
        # ScanView signals are ordered (key, method, path, payload).
        if path in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            key, method, path, payload = key, path, method, payload
        parts = path.lstrip("/").split("/")
        if len(parts) > 1 and parts[0] == "projects" and parts[1].isdigit():
            key = f"{key}::project:{parts[1]}"
        worker = ApiWorker(self.api_client, key, path, method, payload)
        self._workers.add(worker)
        worker.signals.succeeded.connect(self._on_request_succeeded)
        worker.signals.failed.connect(self._on_request_failed)
        worker.signals.finished.connect(self._release_worker)
        self.thread_pool.start(worker)

    def _release_worker(self, worker):
        self._workers.discard(worker)

    def _on_request_succeeded(self, key: str, data):
        key, project_id = self._unpack_project_key(key)
        if project_id is not None and project_id != self.project_id:
            return
        if key == "health":
            self.connection_pill.set_connected(True, "Backend connected")
            self.dashboard_view.set_backend_status(True, "Connected")
            self.error_banner.hide()
        elif key == "projects":
            self._update_projects(data)
        elif key == "scopes":
            self.scopes_view.set_error(None)
            self.scopes = data if isinstance(data, list) else []
            self.scopes_view.set_items(self.scopes)
            self.scan_view.set_context(self.current_project, self.scopes)
            self._update_dashboard_counts()
        elif key == "assets":
            self.assets_view.set_error(None)
            self.assets = data if isinstance(data, list) else []
            self.assets_view.set_items(self.assets)
            self._update_dashboard_counts()
        elif key == "findings":
            self.findings_view.set_error(None)
            self.findings = data if isinstance(data, list) else []
            self.findings_view.set_items(self.findings)
            self._update_dashboard_counts()
        elif key == "finding_analysis":
            self.findings_view.set_error(None)
            self.findings = data if isinstance(data, list) else []
            self.findings_view.set_items(self.findings)
            self._update_dashboard_counts()
        elif key == "finding_summary":
            self.findings_view.set_summary(data)
        elif key == "evidence":
            self.evidence_view.set_items(data)
        elif key == "finding_correlate":
            self.findings_view.set_correlation_result(data)
            self._request("finding_analysis", f"/projects/{self.project_id}/findings/analysis")
            self._request("finding_summary", f"/projects/{self.project_id}/risk-summary")
        elif key == "report_assessments":
            self.reports_view.set_assessments(data)
        elif key == "report_assessment":
            self.reports_view.set_assessment(data)
        elif key in {"report_assessment_create", "report_assessment_update"}:
            if not isinstance(data, dict) or not isinstance(data.get("id"), int):
                self.reports_view.set_error("The backend returned an invalid assessment response.")
                return
            if key == "report_assessment_create":
                self.reports_view.assessment_id = data.get("id")
                self.reports_view.assessment_name.clear()
            self._request("report_assessments", f"/projects/{self.reports_view.project_id}/assessments")
        elif key == "report_snapshot":
            self.reports_view.set_report(data)
        elif key.startswith("report_export_"):
            self.reports_view.set_export_result(key, data)
        elif key == "scan_domains":
            self.scan_view.set_domains(data)
        elif key == "scan_categories":
            self.scan_view.set_categories(data)
        elif key == "scan_modules":
            self.scan_view.set_modules(data)
        elif key == "scan_profiles":
            self.scan_view.set_profiles(data)
        elif key == "scan_tools":
            self.scan_view.set_tools(data)
        elif key == "scan_scopes":
            self.scopes = data if isinstance(data, list) else []
            self.scan_view.set_context(self.current_project, self.scopes, self.assets)
        elif key == "scan_assets":
            self.assets = data if isinstance(data, list) else []
            self.scan_view.set_context(self.current_project, self.scopes, self.assets)
        elif key == "scan_scope_check":
            self.scan_view.set_scope_decision(data)
        elif key in {"scan_created_job", "scan_job"}:
            self.scan_view.set_job(data)
        elif key in {"scan_probe_jobs", "scan_tls_jobs"}:
            self.scan_view.set_probe_jobs(data)
        elif key == "scan_execution":
            self.scan_view.set_execution(data)
            job_id = (data or {}).get("job_id")
            if (data or {}).get("status") == "completed" and job_id not in self._recon_completion_refreshes:
                self._recon_completion_refreshes.add(job_id)
                self._request("scan_assets", f"/projects/{self.project_id}/assets")
                self._request("scan_correlation", f"/projects/{self.project_id}/recon/correlation")
        elif key == "scan_correlation":
            self.scan_view.set_correlation(data)
        elif key in {"phase9_created", "phase9_job"}:
            self.scan_view.set_phase9_job(data)
        elif key in {"phase14_created", "phase14_job"}:
            self.scan_view.set_phase14_job(data)
        elif key in {"phase15_created", "phase15_job"}:
            self.scan_view.set_phase15_job(data)
        elif key == "phase15_run":
            findings=data.get("findings",[])
            self.scan_view.execution_output.setPlainText(
                f"Phase 15 {data.get('status')}: {data.get('endpoints_inspected',0)} endpoints, "
                f"{len(data.get('surfaces',[]))} auth/session surfaces, {len(findings)} new candidates.\n"+
                "\n".join(f"[{row.get('category')} / {row.get('severity')} / {row.get('confidence')} confidence] "
                    f"{row.get('title')}\nEvidence: {row.get('evidence')}\nManual verification: {row.get('manual_verification')}"
                    for row in findings))
            self._send("finding_analysis", "GET", f"/projects/{self.current_project['id']}/findings/analysis")
            self._send("finding_summary", "GET", f"/projects/{self.current_project['id']}/risk-summary")
            self._request("evidence", f"/projects/{self.current_project['id']}/evidence?limit=500")
        elif key == "phase14_run":
            self.scan_view.execution_output.setPlainText(
                f"Assessment {data.get('status')}: {data.get('endpoints_inspected', 0)} endpoints, "
                f"{len(data.get('api_documents', []))} API documents, "
                f"{len(data.get('findings', []))} new findings.\n" + "\n".join(
                    f"[{row.get('severity', '').upper()} / {row.get('confidence')} confidence] {row.get('title')}"
                    for row in data.get('findings', [])))
            self._send("finding_analysis", "GET", f"/projects/{self.current_project['id']}/findings/analysis")
            self._send("finding_summary", "GET", f"/projects/{self.current_project['id']}/risk-summary")
            self._request("evidence", f"/projects/{self.current_project['id']}/evidence?limit=500")
        elif key == "phase9_run":
            rows = (data or {}).get("findings", [])
            self.scan_view.execution_output.setPlainText("\n".join(
                f"[{row.get('severity', '').upper()} / {row.get('confidence', '')} confidence] {row.get('title')}\n"
                f"Evidence: {row.get('evidence')}\nRemediation: {row.get('remediation')}" for row in rows
            ) or "Assessment completed with no findings.")
            self._send("finding_analysis", "GET", f"/projects/{self.current_project['id']}/findings/analysis")
            self._send("finding_summary", "GET", f"/projects/{self.current_project['id']}/risk-summary")
            self._request("evidence", f"/projects/{self.current_project['id']}/evidence?limit=500")

    def _on_request_failed(self, key: str, message: str):
        key, project_id = self._unpack_project_key(key)
        if project_id is not None and project_id != self.project_id:
            return
        if key == "health":
            self.connection_pill.set_connected(False, "Backend unavailable")
            self.dashboard_view.set_backend_status(False, "Unavailable")
        if key in ("health", "projects"):
            self.error_banner.setText(
                f"Backend connection problem: {message}  Use Reconnect / Refresh to try again."
            )
            self.error_banner.show()
        elif key == "scopes":
            self.scopes = None
            self.scopes_view.set_error(message)
            self.scan_view.set_context(self.current_project, None)
        elif key == "assets":
            self.assets_view.set_error(message)
        elif key in {"findings", "finding_analysis", "finding_summary", "finding_correlate"}:
            self.findings_view.set_error(message)
        elif key == "evidence":
            self.evidence_view.set_error(message)
        elif key.startswith("report_"):
            self.reports_view.set_error(message)
        elif key.startswith(("scan_", "phase9_", "phase14_", "phase15_")):
            self.scan_view.job_status.setText(f"Request failed: {message}")

    @staticmethod
    def _unpack_project_key(key: str):
        marker = "::project:"
        if marker not in key:
            return key, None
        base, raw_project_id = key.rsplit(marker, 1)
        try:
            return base, int(raw_project_id)
        except ValueError:
            return key, None

    def _update_projects(self, data):
        previous_project_id = self.project_id
        self.projects = data if isinstance(data, list) else []
        available_ids = [project.get("id") for project in self.projects]
        if self.project_id not in available_ids:
            self.project_id = self.projects[0].get("id") if self.projects else None
        self.current_project = next(
            (project for project in self.projects if project.get("id") == self.project_id),
            None,
        )
        self.findings_view.set_project(self.project_id)
        self.reports_view.set_projects(self.projects, self.project_id)
        if self.project_id != previous_project_id:
            self.scopes = None
            self.assets = []
            self.findings = []
            self.scopes_view.set_items([])
            self.assets_view.set_items([])
            self.findings_view.set_items([])
            self.evidence_view.set_items([])
        self.projects_view.set_projects(self.projects, self.project_id)
        self.dashboard_view.set_project(
            self.current_project.get("name") if self.current_project else None
        )
        self.scan_view.set_context(self.current_project, self.scopes)
        self.scan_view.set_projects(self.projects, self.project_id)
        if self.project_id is not None:
            self._request_project_data()
        else:
            self.scopes = []
            self.assets = []
            self.findings = []
            self.scopes_view.set_items([])
            self.assets_view.set_items([])
            self.findings_view.set_items([])
            self.evidence_view.set_items([])
            self.dashboard_view.set_counts(0, 0, 0)

    def _select_project(self, project_id: int):
        if project_id == self.project_id:
            return
        self.project_id = project_id
        self.current_project = next(
            (project for project in self.projects if project.get("id") == project_id),
            None,
        )
        self.findings_view.set_project(self.project_id)
        self.reports_view.set_projects(self.projects, self.project_id)
        self.dashboard_view.set_project(
            self.current_project.get("name") if self.current_project else None
        )
        self.scopes = None
        self.assets = []
        self.findings = []
        self.evidence_view.set_items([])
        self.scan_view.set_context(self.current_project, None)
        self.scan_view.set_projects(self.projects, self.project_id)
        self._request_project_data()

    def _update_dashboard_counts(self):
        scopes_count = len(self.scopes) if self.scopes is not None else 0
        self.dashboard_view.set_counts(scopes_count, len(self.assets), len(self.findings))
