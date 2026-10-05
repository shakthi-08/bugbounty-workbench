from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QPushButton, QVBoxLayout, QPlainTextEdit,
)

from .base import BaseView


class ScanView(BaseView):
    request_api = Signal(str, str, str, object)

    def __init__(self, parent=None):
        super().__init__("Reconnaissance & Security Assessment",
                         "Run bounded reconnaissance, web/API checks, and security candidate assessments against authorized project assets.", parent)
        form = QFormLayout()
        self.project_selector = QComboBox()
        self.domain_selector = QComboBox()
        self.category_selector = QComboBox()
        self.module_selector = QListWidget()
        self.module_selector.setMaximumHeight(120)
        self.profile_selector = QComboBox()
        self.target_selector = QComboBox()
        self.target_selector.setEditable(True)
        self.dns_record_types = QLineEdit("A,AAAA,CNAME,MX,NS,TXT")
        self.dns_record_types.setPlaceholderText("Comma-separated: A, AAAA, CNAME, MX, NS, TXT")
        self.endpoint_path_limit = QLineEdit("12")
        self.endpoint_path_limit.setMaxLength(2)
        self.subdomain_result_limit = QLineEdit("100")
        self.subdomain_result_limit.setMaxLength(3)
        self.service_ports = QLineEdit("22,80,443,445,8080,8443")
        self.service_ports.setPlaceholderText("Allowlist only: 22, 80, 443, 445, 8080, 8443")
        self.tool_selector = QListWidget()
        self.tool_selector.setMaximumHeight(100)
        self.discovered_hosts = QListWidget()
        self.discovered_hosts.setMaximumHeight(130)
        self.probe_job_selector = QComboBox()
        self.probe_job_selector.hide()
        self.web_observation_selector = QComboBox()
        self.web_observation_selector.setObjectName("phase9ObservationSelector")
        self.scope_status = QLabel("BLOCKED — select a project and target")
        self.scope_status.setObjectName("inlineError")
        form.addRow("Project", self.project_selector)
        form.addRow("Assessment domain", self.domain_selector)
        form.addRow("Category", self.category_selector)
        form.addRow("Test module(s)", self.module_selector)
        form.addRow("Profile", self.profile_selector)
        form.addRow("Target / asset", self.target_selector)
        form.addRow("Scope status", self.scope_status)
        form.addRow("DNS record types", self.dns_record_types)
        form.addRow("Subdomain result cap (1–100)", self.subdomain_result_limit)
        form.addRow("Fixed endpoint path cap (1–12)", self.endpoint_path_limit)
        form.addRow("TCP ports (fixed allowlist, max 6)", self.service_ports)
        form.addRow("Registered tools (Subfinder runs passively)", self.tool_selector)
        form.addRow("Authorized web observation", self.web_observation_selector)
        self.layout.addLayout(form)
        self.approval = QCheckBox("I reviewed the target, scope decision, profile, modules, and tools")
        self.user_name = QLineEdit("local-user")
        self.user_name.setPlaceholderText("Approving user")
        controls = QHBoxLayout()
        self.create_button = QPushButton("Create Job")
        self.approve_button = QPushButton("Approve Job")
        self.cancel_button = QPushButton("Cancel Job")
        self.run_button = QPushButton("Start Recon")
        self.approve_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.run_button.setEnabled(False)
        controls.addWidget(self.create_button)
        controls.addWidget(self.approve_button)
        controls.addWidget(self.run_button)
        controls.addWidget(self.cancel_button)
        self.layout.addWidget(self.approval)
        self.layout.addWidget(self.user_name)
        self.layout.addLayout(controls)
        self.job_status = QLabel("Job status: none")
        self.job_status.setObjectName("infoBanner")
        self.job_status.setWordWrap(True)
        self.layout.addWidget(self.job_status)
        workflow = QLabel("Workflow: select a project asset, review its current scope authorization, choose an operation, create the job, approve it, and start it explicitly. Web discovery uses a fixed path list and never crawls recursively.")
        workflow.setObjectName("infoBanner")
        workflow.setWordWrap(True)
        self.layout.addWidget(workflow)
        web_note = QLabel("Web surface discovery and TLS inspection require an existing in-scope project asset. Endpoint discovery uses at most 12 fixed paths, same-host redirects (maximum two), small response samples, and an eight-second request timeout. TCP awareness is limited to six fixed ports on an explicitly selected IP asset, with a three-second connection timeout.")
        web_note.setObjectName("infoBanner")
        web_note.setWordWrap(True)
        self.layout.addWidget(web_note)
        self.layout.addWidget(QLabel("Authorized discovered hosts (select before creating HTTP jobs)"))
        self.layout.addWidget(self.discovered_hosts)
        self.probe_button = QPushButton("Create HTTP Jobs for Selected Hosts")
        self.probe_button.setEnabled(False)
        self.layout.addWidget(self.probe_button)
        self.tls_button = QPushButton("Create TLS Inspection Jobs for Selected Hosts")
        self.tls_button.setEnabled(False)
        self.layout.addWidget(self.tls_button)
        phase9_controls = QHBoxLayout()
        self.phase9_request_button = QPushButton("Request Header Assessment")
        self.phase9_approve_button = QPushButton("Approve Header Assessment")
        self.phase9_run_button = QPushButton("Start Header Assessment")
        for button in (self.phase9_request_button, self.phase9_approve_button, self.phase9_run_button): button.setEnabled(False)
        phase9_controls.addWidget(self.phase9_request_button)
        phase9_controls.addWidget(self.phase9_approve_button)
        phase9_controls.addWidget(self.phase9_run_button)
        self.layout.addLayout(phase9_controls)
        phase14_controls = QHBoxLayout()
        self.phase14_web_button = QPushButton("Request Web Assessment")
        self.phase14_api_button = QPushButton("Request API Assessment")
        self.phase14_approve_button = QPushButton("Approve Assessment")
        self.phase14_run_button = QPushButton("Run Assessment")
        for button in (self.phase14_web_button, self.phase14_api_button, self.phase14_approve_button, self.phase14_run_button):
            phase14_controls.addWidget(button)
        self.layout.addLayout(phase14_controls)
        self.phase14_web_button.clicked.connect(lambda: self._phase14_request("web"))
        self.phase14_api_button.clicked.connect(lambda: self._phase14_request("api"))
        self.phase14_approve_button.clicked.connect(self._phase14_approve)
        self.phase14_run_button.clicked.connect(self._phase14_run)
        for button in (self.phase14_approve_button, self.phase14_run_button): button.setEnabled(False)
        phase15_controls = QHBoxLayout()
        self.phase15_auth_button = QPushButton("Authentication")
        self.phase15_access_button = QPushButton("Authorization Candidates")
        self.phase15_vuln_button = QPushButton("Vulnerability Candidates")
        self.phase15_approve_button = QPushButton("Approve Phase 15")
        self.phase15_run_button = QPushButton("Run Phase 15")
        for button in (self.phase15_auth_button,self.phase15_access_button,self.phase15_vuln_button,
                       self.phase15_approve_button,self.phase15_run_button): phase15_controls.addWidget(button)
        self.layout.addWidget(QLabel("Authentication, authorization, and vulnerability candidates (stored observations only)"))
        self.layout.addLayout(phase15_controls)
        self.phase15_auth_button.clicked.connect(lambda: self._phase15_request("authentication"))
        self.phase15_access_button.clicked.connect(lambda: self._phase15_request("authorization"))
        self.phase15_vuln_button.clicked.connect(lambda: self._phase15_request("vulnerabilities"))
        self.phase15_approve_button.clicked.connect(self._phase15_approve)
        self.phase15_run_button.clicked.connect(self._phase15_run)
        self.phase15_approve_button.setEnabled(False)
        self.phase15_run_button.setEnabled(False)
        self.layout.addWidget(self.probe_job_selector)
        notice = QLabel("Execution uses registered local tools only after scope review and explicit approval. Subfinder must be installed manually; unavailable tools stay disabled.")
        notice.setObjectName("infoBanner")
        notice.setWordWrap(True)
        self.layout.addWidget(notice)
        self.execution_output = QPlainTextEdit()
        self.execution_output.setReadOnly(True)
        self.execution_output.setPlaceholderText("Job output, results, and evidence references appear here.")
        self.execution_output.setMaximumBlockCount(1000)
        self.layout.addWidget(self.execution_output)
        self.correlation_button = QPushButton("Refresh Recon Correlation")
        self.layout.addWidget(self.correlation_button)
        self.correlation_output = QPlainTextEdit()
        self.correlation_output.setReadOnly(True)
        self.correlation_output.setPlaceholderText("Stored assets, observations, evidence references, and findings are grouped by hostname here.")
        self.correlation_output.setMaximumBlockCount(500)
        self.layout.addWidget(self.correlation_output)
        self.layout.addStretch(1)
        self.projects = []
        self.scopes = []
        self.assets = []
        self.modules = []
        self.tools = []
        self.profiles = []
        self.enabled_profiles = []
        self.current_job = None
        self.probe_jobs = []
        self.source_job_id = None
        self.source_job_status = None
        self.domain_selector.currentIndexChanged.connect(self._domain_changed)
        self.category_selector.currentIndexChanged.connect(self._category_changed)
        self.project_selector.currentIndexChanged.connect(self._project_changed)
        self.profile_selector.currentIndexChanged.connect(self._profile_changed)
        self.target_selector.currentTextChanged.connect(self._target_changed)
        self.target_selector.currentIndexChanged.connect(self._update_buttons)
        self.create_button.clicked.connect(self._create_job)
        self.approve_button.clicked.connect(self._approve_job)
        self.cancel_button.clicked.connect(self._cancel_job)
        self.run_button.clicked.connect(self._run_job)
        self.probe_button.clicked.connect(self._create_probe_jobs)
        self.tls_button.clicked.connect(self._create_tls_jobs)
        self.phase9_request_button.clicked.connect(self._phase9_request)
        self.phase9_approve_button.clicked.connect(self._phase9_approve)
        self.phase9_run_button.clicked.connect(self._phase9_run)
        self.correlation_button.clicked.connect(self._refresh_correlation)
        self.probe_job_selector.currentIndexChanged.connect(self._probe_job_changed)
        self.approval.stateChanged.connect(self._update_buttons)
        self.tool_selector.itemChanged.connect(self._update_buttons)
        self.module_selector.itemChanged.connect(self._update_buttons)
        self.discovered_hosts.itemChanged.connect(self._update_buttons)
        self._update_buttons()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(1500)
        self.refresh_timer.timeout.connect(self._refresh_job)

    def _send(self, key, method, path, payload=None):
        self.request_api.emit(key, method, path, payload)

    def set_projects(self, projects, selected_id=None):
        self.projects = projects or []
        self.project_selector.blockSignals(True)
        self.project_selector.clear()
        for project in self.projects:
            self.project_selector.addItem(project.get("name", "Project"), project.get("id"))
        index = self.project_selector.findData(selected_id)
        self.project_selector.setCurrentIndex(index if index >= 0 else (0 if self.projects else -1))
        self.project_selector.blockSignals(False)
        self._project_changed()

    def set_domains(self, rows):
        self.domain_selector.clear()
        default_index = -1
        for row in rows or []:
            if row.get("enabled"):
                self.domain_selector.addItem(row["name"], row["id"])
                if row.get("key") == "web":
                    default_index = self.domain_selector.count() - 1
        if default_index >= 0:
            self.domain_selector.setCurrentIndex(default_index)
        else:
            self._domain_changed()

    def set_categories(self, rows):
        self.category_selector.clear()
        for row in rows or []:
            if row.get("enabled"):
                self.category_selector.addItem(row["name"], row["id"])
        self._category_changed()

    def set_modules(self, rows):
        self.modules = rows or []
        self.module_selector.clear()
        allowed_ids = set(self.profile_selector.currentData() or [])
        for row in self.modules:
            if row.get("enabled") and (not allowed_ids or row["id"] in allowed_ids):
                item = QListWidgetItem(row["name"])
                item.setData(256, row["id"])
                item.setCheckState(Qt.CheckState.Unchecked)
                self.module_selector.addItem(item)

    def set_profiles(self, rows):
        self.profiles = rows or []
        self.enabled_profiles = [row for row in self.profiles if row.get("enabled")]
        self.profile_selector.clear()
        default_index = -1
        for row in self.enabled_profiles:
            self.profile_selector.addItem(row["name"], row.get("module_ids", []))
            if row.get("key") == "web_baseline":
                default_index = self.profile_selector.count() - 1
        if default_index >= 0:
            self.profile_selector.setCurrentIndex(default_index)

    def _profile_changed(self, *_):
        self.set_modules(self.modules)

    def set_tools(self, rows):
        self.tools = rows or []
        self.tool_selector.clear()
        for row in self.tools:
            if row.get("enabled") and row.get("local_only"):
                available = bool(row.get("adapter_available"))
                label = f"{row['name']} — {row.get('availability_reason', 'unavailable')}"
                if row.get("key") == "subfinder" and not available:
                    label += " (manual installation required)"
                item = QListWidgetItem(label)
                item.setData(256, row["id"])
                item.setCheckState(Qt.CheckState.Unchecked)
                if not available:
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled & ~Qt.ItemFlag.ItemIsUserCheckable)
                self.tool_selector.addItem(item)

    def set_context(self, project, scopes, assets=None):
        self.scopes = scopes or []
        self.assets = assets or []
        previous = self.target_selector.currentText()
        self.target_selector.blockSignals(True)
        self.target_selector.clear()
        asset_targets = {
            str(asset.get("value") or asset.get("name") or asset.get("url", ""))
            for asset in self.assets
        }
        seen = set()
        for scope in self.scopes:
            if scope.get("included"):
                target = scope.get("value", "")
                if target in asset_targets:
                    continue
                self.target_selector.addItem(target, {"target": target, "asset_id": None})
                seen.add((target, None))
        for asset in self.assets:
            target = asset.get("value") or asset.get("name") or asset.get("url")
            if target and (target, asset.get("id")) not in seen:
                self.target_selector.addItem(str(target), {"target": str(target), "asset_id": asset.get("id")})
        if previous:
            self.target_selector.setEditText(previous)
        self.target_selector.blockSignals(False)
        self._target_changed(self.target_selector.currentText())
        self._update_buttons()

    def set_scope_decision(self, decision):
        allowed = bool(decision and decision.get("allowed"))
        reason = (decision or {}).get("reason", "No scope result")
        self.scope_status.setText(f"{'AUTHORIZED' if allowed else 'BLOCKED'} — {reason}")
        self.scope_status.setObjectName("infoBanner" if allowed else "inlineError")
        self.scope_status.style().unpolish(self.scope_status)
        self.scope_status.style().polish(self.scope_status)
        self._update_buttons()

    def set_job(self, job):
        self.current_job = job
        if not job:
            return
        for index, known in enumerate(self.probe_jobs):
            if known.get("id") == job.get("id"):
                self.probe_jobs[index] = job
                self.probe_job_selector.setItemData(index, job)
        status = job.get("status", "unknown").upper().replace("_", " ")
        error = job.get("error")
        self.job_status.setText(f"Job #{job.get('id')}: {status}" + (f" — {error}" if error else ""))
        self.approve_button.setEnabled(status == "PENDING APPROVAL" and self.approval.isChecked())
        self.run_button.setEnabled(status == "APPROVED" and bool(job.get("profile_snapshot", {}).get("tool_ids")))
        self.cancel_button.setEnabled(status in {"PENDING APPROVAL", "APPROVED", "QUEUED", "RUNNING"})
        if status in {"QUEUED", "RUNNING"}:
            self.refresh_timer.start()
        else:
            self.refresh_timer.stop()

    def set_execution(self, data):
        if not data:
            return
        lines = [f"Execution: {data.get('status', 'unknown')} ", f"Error: {data['error']}" if data.get("error") else ""]
        for evidence in data.get("evidence", []):
            metadata = evidence.get("metadata", {})
            if metadata.get("tool_key") == "subfinder":
                lines.append(
                    f"Subfinder: {metadata.get('accepted_hosts', 0)} accepted, "
                    f"{len(metadata.get('rejected_by_scope') or [])} "
                    "rejected by current scope"
                )
        for result in data.get("results", []):
            details = ", ".join(f"{key}={value}" for key, value in result.get("normalized_data", {}).items())
            lines.append(f"[{result.get('result_type')}] {result.get('title')} — {details}")
        for result in data.get("results", []):
            normalized = result.get("normalized_data", {})
            if result.get("result_type") == "technology":
                lines.append(f"  Confidence: {normalized.get('confidence', 'unknown')}")
                lines.extend(f"  Evidence: {item}" for item in normalized.get("evidence", []))
            if normalized.get("observation_type") == "redirect_blocked":
                lines.append(f"  Redirect blocked: {normalized.get('to_host') or 'unsupported destination'}")
            if normalized.get("inspection_error"):
                lines.append(f"  Error: {normalized['inspection_error']}")
        self.web_observation_selector.clear()
        for result in data.get("results", []):
            normalized = result.get("normalized_data", {})
            if result.get("result_type") == "endpoint" and normalized.get("http_status") is not None:
                self.web_observation_selector.addItem(
                    f"{result.get('title', 'HTTP observation')} (result #{result.get('id')})", result.get("id"))
        self.phase9_request_button.setEnabled(bool(self.web_observation_selector.count() and self.project_selector.currentData()))
        candidates = []
        for result in data.get("results", []):
            normalized = result.get("normalized_data", {})
            if (result.get("result_type") == "subdomain"
                    and normalized.get("authorization_status") == "authorized"):
                candidates.append(normalized.get("hostname"))
            elif (result.get("result_type") == "dns_record"
                  and normalized.get("authorization_status") == "authorized"):
                candidates.append(normalized.get("candidate_hostname"))
        candidates = list(dict.fromkeys(host for host in candidates if host))
        if candidates:
            self.source_job_id = data.get("job_id")
            self.source_job_status = data.get("status")
            self.discovered_hosts.clear()
            for hostname in candidates:
                item = QListWidgetItem(hostname)
                item.setData(256, hostname)
                item.setCheckState(Qt.CheckState.Unchecked)
                self.discovered_hosts.addItem(item)
        for evidence in data.get("evidence", []):
            lines.append(f"Evidence: {evidence.get('path_reference')} (SHA-256 {evidence.get('content_hash')})")
            if evidence.get("output"):
                lines.append(evidence["output"])
        self.execution_output.setPlainText("\n".join(line for line in lines if line))
        self._update_buttons()

    def set_correlation(self, data):
        if not isinstance(data, dict) or not isinstance(data.get("groups"), list):
            self.correlation_output.setPlainText("Recon correlation data was not valid.")
            return
        lines = []
        for group in data["groups"]:
            lines.append(f"{group.get('hostname')}  [{group.get('id')}]")
            for scope in group.get("scopes", []):
                lines.append(f"  Scope #{scope.get('id')}: {scope.get('value')} ({'included' if scope.get('included') else 'excluded'})")
            for asset in group.get("assets", []):
                lines.append(f"  Asset #{asset.get('id')} ({asset.get('type')}) source={asset.get('source') or 'unspecified'}")
            for observation in group.get("observations", []):
                lines.append(f"  {observation.get('result_type')} #{observation.get('id')}: {observation.get('title')} (job #{observation.get('job_id')}, evidence {observation.get('evidence_ids', [])})")
            for finding in group.get("findings", []):
                lines.append(f"  Finding #{finding.get('id')} [{finding.get('severity')}]: {finding.get('title')}")
        self.correlation_output.setPlainText("\n".join(lines) if lines else "No stored recon correlation data for this project.")

    def _refresh_correlation(self):
        project_id = self.project_selector.currentData()
        if project_id is not None:
            self._send("scan_correlation", "GET", f"/projects/{project_id}/recon/correlation")

    def set_probe_jobs(self, jobs):
        self.probe_jobs = jobs or []
        self.probe_job_selector.blockSignals(True)
        self.probe_job_selector.clear()
        for job in self.probe_jobs:
            host = job.get("target_snapshot", {}).get("target", "")
            self.probe_job_selector.addItem(f"Job #{job.get('id')} — {host}", job)
        self.probe_job_selector.setVisible(bool(self.probe_jobs))
        self.probe_job_selector.blockSignals(False)
        if self.probe_jobs:
            self._probe_job_changed(0)

    def _probe_job_changed(self, index):
        job = self.probe_job_selector.itemData(index) if index >= 0 else None
        if job:
            self.set_job(job)

    def _project_changed(self, *_):
        project_id = self.project_selector.currentData()
        if project_id is None:
            return
        self._send("scan_scopes", "GET", f"/projects/{project_id}/scopes")
        self._send("scan_assets", "GET", f"/projects/{project_id}/assets")

    def _domain_changed(self, *_):
        domain_id = self.domain_selector.currentData()
        if domain_id is not None:
            self._send("scan_categories", "GET", f"/assessment-categories?domain_id={domain_id}")

    def _category_changed(self, *_):
        category_id = self.category_selector.currentData()
        if category_id is not None:
            self._send("scan_modules", "GET", f"/assessment-modules?category_id={category_id}")

    def _target_changed(self, target):
        project_id = self.project_selector.currentData()
        if project_id is not None and target.strip():
            self._send("scan_scope_check", "POST", f"/projects/{project_id}/scope-check", {"target": target.strip()})
        else:
            self.set_scope_decision({"allowed": False, "reason": "Select a project and target."})

    def _selected_ids(self, widget):
        return [widget.item(i).data(256) for i in range(widget.count()) if widget.item(i).checkState()]

    def _selection(self):
        target = self.target_selector.currentText().strip()
        payload = self.target_selector.currentData()
        if not isinstance(payload, dict) or payload.get("target") != target:
            payload = {"target": target, "asset_id": None}
        return target, payload

    def _create_job(self):
        if not self.approval.isChecked():
            return
        project_id = self.project_selector.currentData()
        profile_index = self.profile_selector.currentIndex()
        profile_ids = [row["id"] for row in self.enabled_profiles]
        if project_id is None or profile_index < 0 or not self._selected_ids(self.module_selector):
            self.job_status.setText("Choose a project, profile, and at least one test module.")
            return
        target, target_data = self._selection()
        payload = {"profile_id": profile_ids[profile_index], "target": target,
                   "asset_id": target_data.get("asset_id"),
                   "module_ids": self._selected_ids(self.module_selector),
                   "tool_ids": self._selected_ids(self.tool_selector),
                   "requested_by": self.user_name.text().strip() or "local-user",
                   "parameters": self._job_parameters()}
        self._send("scan_created_job", "POST", f"/projects/{project_id}/security-jobs", payload)

    def _job_parameters(self):
        selected_tool_keys = {
            row.get("key") for row in self.tools
            if row.get("id") in self._selected_ids(self.tool_selector)
        }
        parameters = {}
        if "windows_nslookup" in selected_tool_keys:
            parameters["record_types"] = [value.strip().upper() for value in self.dns_record_types.text().split(",")
                                           if value.strip()]
        if "web_surface_discovery" in selected_tool_keys:
            try:
                max_paths = int(self.endpoint_path_limit.text())
            except ValueError:
                max_paths = 12
            parameters.update({"timeout": 5, "max_paths": max_paths})
        if "tcp_service_awareness" in selected_tool_keys:
            ports = []
            for raw in self.service_ports.text().split(","):
                raw = raw.strip()
                if raw.isdigit():
                    ports.append(int(raw))
            parameters.update({"timeout": 2, "ports": ports})
        if "subfinder" in selected_tool_keys:
            try:
                max_results = int(self.subdomain_result_limit.text())
            except ValueError:
                max_results = 100
            parameters.update({"timeout": 60, "max_results": max_results})
        return parameters

    def _create_probe_jobs(self):
        if not self.current_job or not self.source_job_id:
            return
        hosts = [self.discovered_hosts.item(i).data(256) for i in range(self.discovered_hosts.count())
                 if self.discovered_hosts.item(i).checkState() == Qt.CheckState.Checked]
        if not hosts:
            return
        project_id = self.project_selector.currentData()
        self._send("scan_probe_jobs", "POST",
                   f"/projects/{project_id}/security-jobs/{self.source_job_id}/probe-selected",
                   {"hostnames": hosts})

    def _create_tls_jobs(self):
        if not self.current_job or not self.source_job_id:
            return
        hosts = [self.discovered_hosts.item(i).data(256) for i in range(self.discovered_hosts.count())
                 if self.discovered_hosts.item(i).checkState() == Qt.CheckState.Checked]
        if hosts:
            project_id = self.project_selector.currentData()
            self._send("scan_tls_jobs", "POST",
                       f"/projects/{project_id}/security-jobs/{self.source_job_id}/inspect-tls-selected",
                       {"hostnames": hosts})

    def _phase9_request(self):
        selected = self.target_selector.currentData()
        if not isinstance(selected, dict) or not selected.get("asset_id") or self.web_observation_selector.currentData() is None:
            self.job_status.setText("Select an existing authorized asset and a completed web observation.")
            return
        project_id = self.project_selector.currentData()
        self._send("phase9_created", "POST", f"/projects/{project_id}/security-header-assessments",
                   {"asset_id": selected["asset_id"], "observation_id": self.web_observation_selector.currentData(),
                    "requested_by": self.user_name.text().strip() or "local-user"})

    def set_phase9_job(self, job):
        if not job: return
        self.phase9_job = job
        status = job.get("status")
        self.job_status.setText(f"Header assessment #{job.get('id')}: {str(status).replace('_', ' ').upper()}")
        self.phase9_approve_button.setEnabled(status == "pending_approval" and self.approval.isChecked())
        self.phase9_run_button.setEnabled(status == "approved")

    def _phase9_approve(self):
        if getattr(self, "phase9_job", None):
            self._send("phase9_job", "POST", f"/projects/{self.project_selector.currentData()}/security-header-assessments/{self.phase9_job['id']}/approve",
                       {"approved_by": self.user_name.text().strip() or "local-user"})

    def _phase9_run(self):
        if getattr(self, "phase9_job", None):
            self._send("phase9_run", "POST", f"/projects/{self.project_selector.currentData()}/security-header-assessments/{self.phase9_job['id']}/run")

    def _phase14_request(self, kind):
        _, selected = self._selection()
        if not self.approval.isChecked() or not isinstance(selected, dict) or not selected.get("asset_id"):
            self.job_status.setText("Select an existing project asset and review the assessment request.")
            return
        project_id = self.project_selector.currentData()
        self._send("phase14_created", "POST", f"/projects/{project_id}/security-assessments/{kind}",
            {"asset_id":selected["asset_id"],"requested_by":self.user_name.text().strip() or "local-user"})

    def set_phase14_job(self, job):
        if not job: return
        previous = getattr(self, "phase14_job", None) or {}
        if "assessment" not in job and previous.get("id") == job.get("id"):
            job = {**job, "assessment": previous.get("assessment", "web")}
        self.phase14_job = job
        status = job.get("status", "unknown")
        self.job_status.setText(f"Phase 14 {job.get('assessment', 'assessment')} #{job.get('id')}: {status.upper()}")
        self.phase14_approve_button.setEnabled(status == "pending_approval" and self.approval.isChecked())
        self.phase14_run_button.setEnabled(status == "approved")

    def _phase14_approve(self):
        job = getattr(self, "phase14_job", None)
        if job:
            kind = job.get("assessment", "web")
            self._send("phase14_job", "POST", f"/projects/{self.project_selector.currentData()}/security-assessments/{kind}/{job['id']}/approve",
                {"approved_by":self.user_name.text().strip() or "local-user"})

    def _phase14_run(self):
        job = getattr(self, "phase14_job", None)
        if job:
            kind = job.get("assessment", "web")
            self._send("phase14_run", "POST", f"/projects/{self.project_selector.currentData()}/security-assessments/{kind}/{job['id']}/run")

    def _phase15_request(self, kind):
        _, selected = self._selection()
        if not self.approval.isChecked() or not isinstance(selected, dict) or not selected.get("asset_id"):
            self.job_status.setText("Select an existing project asset and review the Phase 15 assessment request.")
            return
        project_id = self.project_selector.currentData()
        self._send("phase15_created", "POST", f"/projects/{project_id}/security-assessments/{kind}",
            {"asset_id":selected["asset_id"],"requested_by":self.user_name.text().strip() or "local-user"})

    def set_phase15_job(self, job):
        if not job: return
        previous = getattr(self, "phase15_job", None) or {}
        if "assessment" not in job and previous.get("id") == job.get("id"):
            job = {**job, "assessment": previous.get("assessment", "authentication")}
        self.phase15_job=job
        status=job.get("status", "unknown")
        self.job_status.setText(f"Phase 15 {job.get('assessment', 'security')} #{job.get('id')}: {status.upper()}")
        self.phase15_approve_button.setEnabled(status=="pending_approval" and self.approval.isChecked())
        self.phase15_run_button.setEnabled(status=="approved")

    def _phase15_approve(self):
        job=getattr(self,"phase15_job",None)
        if job:
            kind=job.get("assessment","authentication")
            self._send("phase15_job","POST",f"/projects/{self.project_selector.currentData()}/security-assessments/{kind}/{job['id']}/approve",
                {"approved_by":self.user_name.text().strip() or "local-user"})

    def _phase15_run(self):
        job=getattr(self,"phase15_job",None)
        if job:
            kind=job.get("assessment","authentication")
            self._send("phase15_run","POST",f"/projects/{self.project_selector.currentData()}/security-assessments/{kind}/{job['id']}/run")

    def _approve_job(self):
        if self.current_job and self.approval.isChecked():
            project_id = self.project_selector.currentData()
            self._send("scan_job", "POST", f"/projects/{project_id}/security-jobs/{self.current_job['id']}/approve",
                       {"approved_by": self.user_name.text().strip() or "local-user"})

    def _cancel_job(self):
        if self.current_job:
            project_id = self.project_selector.currentData()
            self._send("scan_job", "POST", f"/projects/{project_id}/security-jobs/{self.current_job['id']}/cancel")

    def _run_job(self):
        if self.current_job and self.current_job.get("status") == "approved" and self.current_job.get("profile_snapshot", {}).get("tool_ids"):
            project_id = self.project_selector.currentData()
            self._send("scan_job", "POST", f"/projects/{project_id}/security-jobs/{self.current_job['id']}/run")

    def _refresh_job(self):
        if self.current_job:
            project_id = self.project_selector.currentData()
            job_id = self.current_job['id']
            self._send("scan_job", "GET", f"/projects/{project_id}/security-jobs/{job_id}")
            self._send("scan_execution", "GET", f"/projects/{project_id}/security-jobs/{job_id}/execution")

    def _update_buttons(self, *_):
        decision_authorized = self.scope_status.text().startswith("AUTHORIZED")
        self.create_button.setEnabled(bool(
            decision_authorized and self.approval.isChecked()
            and self._selected_ids(self.module_selector)
            and self._selected_ids(self.tool_selector)
            and self._selected_asset_required()
        ))
        if self.current_job:
            self.set_job(self.current_job)
        self.probe_button.setEnabled(bool(
            self.source_job_id and self.source_job_status == "completed"
            and self._selected_ids(self.discovered_hosts)
        ))
        self.tls_button.setEnabled(bool(
            self.source_job_id and self.source_job_status == "completed"
            and self._selected_ids(self.discovered_hosts)
        ))

    def _selected_asset_required(self):
        selected_keys = {row.get("key") for row in self.tools
                         if row.get("id") in self._selected_ids(self.tool_selector)}
        if not selected_keys.intersection({"tls_inspector", "web_surface_discovery", "tcp_service_awareness"}):
            return True
        _, selected = self._selection()
        return selected.get("asset_id") is not None
