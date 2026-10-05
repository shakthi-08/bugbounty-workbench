from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel, QPushButton, QTextEdit

from .collection_view import CollectionView


class FindingsView(CollectionView):
    request_api = Signal(str, str, str, object)

    def __init__(self, parent=None):
        super().__init__(
            "Findings",
            "Review normalized findings, explainable risk, and related security observations.",
            [("Title", "title"), ("Severity", "severity"), ("Confidence", "confidence"),
             ("Risk", "risk_score"), ("Priority", "priority"), ("Category", "category"),
             ("Endpoint", "endpoint"), ("Correlation", "correlation_groups")],
            "No findings have been recorded for this project yet.",
            parent,
        )
        self.summary = QLabel("Risk summary: select a project.")
        self.summary.setObjectName("infoBanner")
        self.summary.setWordWrap(True)
        self.layout.insertWidget(0, self.summary)
        self.correlate_button = QPushButton("Normalize, Correlate, and Save Risk")
        self.correlate_button.clicked.connect(self._correlate)
        self.layout.insertWidget(1, self.correlate_button)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(150)
        self.details.setPlaceholderText("Select a finding to review evidence, remediation, and risk explanation.")
        self.layout.addWidget(self.details)
        self.project_id = None
        self.table.itemSelectionChanged.connect(self._show_details)
        self._rows = []

    def set_project(self, project_id):
        self.project_id = project_id
        self.correlate_button.setEnabled(project_id is not None)

    def set_summary(self, summary):
        if not summary:
            self.summary.setText("Risk summary unavailable.")
            return
        sev = summary.get("severity_distribution", {})
        priority = summary.get("priority_distribution", {})
        self.summary.setText(
            f"{summary.get('total_findings', 0)} findings across {summary.get('affected_asset_count', 0)} assets | "
            f"Severity: info {sev.get('informational', 0)}, low {sev.get('low', 0)}, medium {sev.get('medium', 0)}, "
            f"high {sev.get('high', 0)}, critical {sev.get('critical', 0)} | "
            f"Highest risk {summary.get('highest_risk_score', 0)}/100 | "
            f"Priority: low {priority.get('low', 0)}, medium {priority.get('medium', 0)}, "
            f"high {priority.get('high', 0)}, critical {priority.get('critical', 0)}"
        )

    def set_items(self, rows):
        self._rows = rows or []
        super().set_items(self._rows)
        self._show_details()

    def _show_details(self):
        if not hasattr(self, "details"):
            return
        index = self.table.currentRow()
        if index < 0 or index >= len(self._rows):
            self.details.clear()
            return
        row = self._rows[index]
        refs = row.get("evidence_references", [])
        self.details.setPlainText(
            f"Asset: {row.get('asset_id') or 'project'} | Endpoint: {row.get('endpoint') or '—'}\n"
            f"Correlation: {', '.join(row.get('correlation_groups') or []) or 'none'}\n"
            f"Risk explanation: {row.get('risk_explanation') or 'Not calculated yet; run correlation and risk.'}\n"
            f"Evidence: {row.get('evidence') or '—'}\n"
            f"Evidence references: {', '.join(str(item.get('id')) for item in refs) or 'none'}\n"
            f"Remediation: {row.get('remediation') or '—'}"
        )

    def _correlate(self):
        if self.project_id is not None:
            self.request_api.emit("finding_correlate", "POST",
                f"/projects/{self.project_id}/findings/correlate", {})

    def set_correlation_result(self, data):
        if data:
            self.summary.setText(
                f"Analysis saved: {data.get('findings_processed', 0)} processed, "
                f"{data.get('canonical_findings', 0)} canonical, "
                f"{data.get('duplicates_suppressed', 0)} duplicates suppressed, "
                f"{len(data.get('correlation_groups', []))} correlation groups."
            )
