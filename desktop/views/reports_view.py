import html
from pathlib import Path

from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from .base import BaseView


class ReportsView(BaseView):
    request_api = Signal(str, str, str, object)
    project_selected = Signal(int)

    def __init__(self, parent=None):
        super().__init__("Reports", "Create project-scoped assessment reports from stored authorized observations.", parent)
        self.project_selector = QComboBox()
        self.assessment_selector = QComboBox()
        self.assessment_name = QLineEdit()
        self.assessment_name.setPlaceholderText("Assessment name")
        self.status_selector = QComboBox()
        self.status_selector.addItems(["draft", "in_progress", "completed", "archived"])
        self.create_button = QPushButton("Create Assessment")
        self.update_status_button = QPushButton("Update Status")
        self.refresh_button = QPushButton("Refresh Report")
        self.status_label = QLabel("Select or create an assessment.")
        self.status_label.setObjectName("infoBanner")
        self.status_label.setWordWrap(True)
        form = QFormLayout()
        form.addRow("Project", self.project_selector)
        form.addRow("Assessment", self.assessment_selector)
        form.addRow("New assessment name", self.assessment_name)
        form.addRow("Set status", self.status_selector)
        self.layout.addLayout(form)
        buttons = QHBoxLayout()
        for button in (self.create_button, self.update_status_button, self.refresh_button): buttons.addWidget(button)
        self.layout.addLayout(buttons)
        self.layout.addWidget(self.status_label)
        self.summary = QLabel("No assessment report loaded.")
        self.summary.setObjectName("placeholderCard")
        self.summary.setWordWrap(True)
        self.layout.addWidget(self.summary)
        self.preview = QTextBrowser()
        self.preview.setObjectName("assessmentReportPreview")
        self.preview.setOpenExternalLinks(False)
        self.preview.setPlaceholderText("Select an assessment to generate its report preview.")
        self.layout.addWidget(self.preview, 1)
        exports = QHBoxLayout()
        self.export_json_button = QPushButton("Export JSON")
        self.export_markdown_button = QPushButton("Export Markdown")
        self.export_html_button = QPushButton("Export HTML")
        for button in (self.export_json_button, self.export_markdown_button, self.export_html_button):
            button.setEnabled(False)
            exports.addWidget(button)
        self.layout.addLayout(exports)
        self.projects = []
        self.assessments = []
        self.project_id = None
        self.assessment_id = None
        self.report = None
        self._export_paths = {}
        self.project_selector.currentIndexChanged.connect(self._project_changed)
        self.assessment_name.textChanged.connect(self._set_controls)
        self.assessment_selector.currentIndexChanged.connect(self._assessment_changed)
        self.create_button.clicked.connect(self._create_assessment)
        self.update_status_button.clicked.connect(self._update_status)
        self.refresh_button.clicked.connect(self._refresh_report)
        self.export_json_button.clicked.connect(lambda: self._export("json"))
        self.export_markdown_button.clicked.connect(lambda: self._export("markdown"))
        self.export_html_button.clicked.connect(lambda: self._export("html"))
        self.create_button.setEnabled(False)
        self.update_status_button.setEnabled(False)
        self.refresh_button.setEnabled(False)

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

    def set_assessments(self, rows):
        if not isinstance(rows, list) or any(
            not isinstance(row, dict) or not isinstance(row.get("id"), int)
            or not isinstance(row.get("name"), str) or not isinstance(row.get("status"), str)
            for row in rows
        ):
            self.assessments = []
            self.assessment_selector.clear()
            self.assessment_id = None
            self.report = None
            self.preview.clear()
            self.set_error("The backend returned an invalid assessments response.")
            self._set_controls()
            return
        self.assessments = rows
        old_id = self.assessment_id
        self.assessment_selector.blockSignals(True)
        self.assessment_selector.clear()
        for row in self.assessments:
            self.assessment_selector.addItem(f"{row['name']} — {row['status']}", row["id"])
        index = self.assessment_selector.findData(old_id)
        if index < 0 and self.assessments: index = 0
        self.assessment_selector.setCurrentIndex(index)
        self.assessment_selector.blockSignals(False)
        self._assessment_changed()
        if not self.assessments:
            self.assessment_id = None
            self.report = None
            self.preview.clear()
            self.summary.setText("No assessments exist for this project. Create one to prepare a report.")
            self._set_controls()

    def set_assessment(self, assessment):
        if (not isinstance(assessment, dict) or not isinstance(assessment.get("id"), int)
                or not isinstance(assessment.get("status"), str)):
            self.set_error("The backend returned an invalid assessment response.")
            return
        self.assessment_id = assessment.get("id")
        self.status_label.setText(f"Assessment #{assessment['id']} · {assessment['status']}")
        index = self.status_selector.findText(assessment.get("status", "draft"))
        if index >= 0: self.status_selector.setCurrentIndex(index)
        self._set_controls()

    def set_report(self, report):
        required = {"assessment", "project", "generated_at", "executive_summary", "scope",
                    "risk_overview", "findings", "affected_assets", "evidence", "methodology",
                    "reconnaissance", "remediation_themes", "audit_summary", "limitations"}
        dictionaries = ("assessment", "project", "scope", "risk_overview")
        lists = ("findings", "affected_assets", "evidence", "methodology",
                 "reconnaissance", "remediation_themes", "audit_summary", "limitations")
        if (not isinstance(report, dict) or not required.issubset(report)
                or not all(isinstance(report.get(key), dict) for key in dictionaries)
                or not all(isinstance(report.get(key), list) for key in lists)):
            self.report = None
            self.preview.clear()
            self.summary.setText("The backend returned an invalid report response.")
            self.set_error("The report could not be displayed because its response was incomplete.")
            self._set_controls()
            return
        try:
            assessment = report["assessment"]
            risk = report["risk_overview"]
            severity = risk["severity_distribution"]
            priority = risk["priority_distribution"]
            summary_text = (
                f"{assessment['name']} | {assessment['status']} | Assets: {report['scope']['asset_count']} | "
                f"Canonical findings: {risk['total_canonical_findings']} (occurrences {risk['total_occurrences']}) | "
                f"Evidence: {risk['evidence_count']} | Highest risk: {risk['highest_risk_score']}/100 | "
                f"Severity I/L/M/H/C: {severity.get('informational', 0)}/{severity.get('low', 0)}/"
                f"{severity.get('medium', 0)}/{severity.get('high', 0)}/{severity.get('critical', 0)} | "
                f"Priority I/L/M/H/C: {priority.get('informational', 0)}/{priority.get('low', 0)}/"
                f"{priority.get('medium', 0)}/{priority.get('high', 0)}/{priority.get('critical', 0)}"
            )
            preview_html = self._render_preview(report)
        except (KeyError, TypeError, ValueError, AttributeError):
            self.report = None
            self.preview.clear()
            self.summary.setText("The backend returned an invalid report response.")
            self.set_error("The report could not be displayed because its response was invalid.")
            self._set_controls()
            return
        self.report = report
        self._set_controls()
        self.status_label.setText(f"Assessment #{assessment.get('id', self.assessment_id)} | {assessment['status']}")
        self.summary.setText(summary_text)
        self.preview.setHtml(preview_html)

    @staticmethod
    def _render_preview(report):
        e = html.escape
        sections = ["<h1>Assessment Report</h1>", "<h2>Assessment Overview</h2>",
            f"<p><b>{e(report['assessment']['name'])}</b> · Project {report['project']['id']} · Status {e(report['assessment']['status'])}<br>Generated {e(report['generated_at'])}<br>Authorized assets: {report['scope']['asset_count']}</p>",
            "<h2>Executive Summary</h2>", f"<p>{e(report['executive_summary'])}</p>", "<h2>Scope</h2>",
            "<ul>" + "".join(f"<li>{e(item['value'])} ({e(item['type'])}, {item['finding_count']} findings)</li>" for item in report['scope']['authorized_assets']) + "</ul>"]
        if not report["scope"]["authorized_assets"]: sections.append("<p>No currently authorized assets are recorded.</p>")
        sections.append("<h2>Reconnaissance</h2>")
        if report.get("reconnaissance"):
            sections.append("<ul>" + "".join(
                f"<li>{e(item['type'])}: {e(item['title'])} · {e(item['target'] or '—')} · {e(item['summary'] or '')}</li>"
                for item in report["reconnaissance"]) + "</ul>")
        else:
            sections.append("<p>No authorized stored reconnaissance observations are available.</p>")
        sections += ["<h2>Methodology</h2><ul>" + "".join(f"<li>{e(item)}</li>" for item in report["methodology"]) + "</ul>",
            "<h2>Risk Overview</h2>", f"<p>{e(str(report['risk_overview']))}</p>", "<h2>Findings</h2>"]
        if not report["findings"]: sections.append("<p>No reportable findings are currently recorded.</p>")
        for item in report["findings"]:
            sections.append(f"<h3>{e(item['title'])}</h3><p>Severity: {e(item['severity'])} · Confidence: {e(item['confidence'])} · Risk: {item['risk_score']}/100 · Priority: {e(item['priority'])}<br>Category: {e(item['category'])} · Asset: {e(item['asset'] or '—')} · Endpoint: {e(item['endpoint'] or '—')}<br>Correlation: {e(', '.join(item['correlation_groups']) or 'none')} · Occurrences: {item['occurrence_count']}<br>Evidence: {e(item['evidence'] or '—')}<br>Risk explanation: {e(item['risk_explanation'])}<br>Remediation: {e(item['remediation'] or '—')}</p>")
        sections.append("<h2>Affected Assets</h2>")
        sections.append("<ul>" + "".join(f"<li>{e(item['value'])} · {item['finding_count']} findings · risk {item['highest_risk_score']}</li>" for item in report["affected_assets"]) + "</ul>" if report["affected_assets"] else "<p>No affected assets.</p>")
        sections.append("<h2>Evidence</h2>")
        sections.append("<ul>" + "".join(f"<li>#{item['id']} {e(item['title'])} ({e(item['type'])}) · source {e(str(item.get('provenance') or {}))} · finding {e(str(item.get('finding_id') or '—'))} · result {e(str(item.get('result_id') or '—'))} · job {e(str(item.get('job_id') or '—'))} · hash {e(str(item.get('content_hash') or '—'))}</li>" for item in report["evidence"]) + "</ul>" if report["evidence"] else "<p>No evidence references are available.</p>")
        sections += ["<h2>Remediation</h2><ul>" + "".join(f"<li>{e(item)}</li>" for item in report["remediation_themes"]) + "</ul>",
            "<h2>Audit Summary</h2><ul>" + "".join(f"<li>{e(item['created_at'])} · {e(item['action'])} · {e(item['entity_type'])} {e(str(item['entity_id'] or ''))}</li>" for item in report["audit_summary"]) + "</ul>",
            "<h2>Limitations</h2><ul>" + "".join(f"<li>{e(item)}</li>" for item in report["limitations"]) + "</ul>"]
        return "<!doctype html><html><head><meta charset='utf-8'><style>body{font:14px Segoe UI,Arial;color:#202938}h1,h2{color:#17365d}</style></head><body>" + "".join(sections) + "</body></html>"

    def set_error(self, message):
        self.status_label.setText(f"Report request failed: {message}" if message else "Ready.")
        if message:
            for button in (self.export_json_button, self.export_markdown_button, self.export_html_button):
                button.setEnabled(False)

    def set_export_result(self, key, result):
        path = self._export_paths.pop(key, None)
        if not path: return
        if not isinstance(result, dict) or not isinstance(result.get("content"), str):
            self.set_error("The backend returned an invalid export response.")
            return
        try:
            Path(path).write_text(result.get("content", ""), encoding="utf-8")
            self.status_label.setText(f"Report exported to {path}")
        except (OSError, ValueError) as error:
            self.set_error(f"Could not save export: {error}")

    def _set_controls(self):
        has_project = self.project_selector.currentData() is not None
        has_assessment = self.assessment_id is not None
        self.create_button.setEnabled(has_project and bool(self.assessment_name.text().strip()))
        self.update_status_button.setEnabled(has_assessment)
        self.refresh_button.setEnabled(has_assessment)
        for button in (self.export_json_button, self.export_markdown_button, self.export_html_button):
            button.setEnabled(has_assessment and self.report is not None)

    def _project_changed(self, *_):
        project_id = self.project_selector.currentData()
        self.project_id = project_id
        self.assessment_id = None
        self.report = None
        self.assessment_selector.clear()
        self.preview.clear()
        self._set_controls()
        if project_id is not None:
            self.project_selected.emit(project_id)
            self._send("report_assessments", "GET", f"/projects/{project_id}/assessments")
        else:
            self.summary.setText("Select a project to view or create an assessment.")

    def _assessment_changed(self, *_):
        assessment_id = self.assessment_selector.currentData()
        if assessment_id is None: return
        self.assessment_id = assessment_id
        self._set_controls()
        prefix = f"/projects/{self.project_id}/assessments/{assessment_id}"
        self._send("report_assessment", "GET", prefix)
        self._send("report_snapshot", "GET", f"{prefix}/report")

    def _create_assessment(self):
        name = self.assessment_name.text().strip()
        if self.project_id is not None and name:
            self._send("report_assessment_create", "POST", f"/projects/{self.project_id}/assessments", {"name": name})

    def _update_status(self):
        if self.assessment_id is not None:
            self._send("report_assessment_update", "PATCH",
                f"/projects/{self.project_id}/assessments/{self.assessment_id}",
                {"status": self.status_selector.currentText()})

    def _refresh_report(self):
        if self.assessment_id is not None:
            self._send("report_snapshot", "GET", f"/projects/{self.project_id}/assessments/{self.assessment_id}/report")

    def _export(self, fmt):
        if self.assessment_id is None: return
        suffix = {"json":"json", "markdown":"md", "html":"html"}[fmt]
        path, _ = QFileDialog.getSaveFileName(self, f"Export {fmt.upper()} report", f"assessment_{self.assessment_id}.{suffix}", f"{fmt.upper()} (*.{suffix})")
        if not path: return
        key = f"report_export_{fmt}"
        self._export_paths[key] = path
        self._send(key, "GET", f"/projects/{self.project_id}/assessments/{self.assessment_id}/export/{fmt}")
