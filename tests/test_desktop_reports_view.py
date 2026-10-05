import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtWidgets import QApplication
from desktop.views.main_window import MainWindow
from desktop.views.reports_view import ReportsView
from desktop.api_client import ApiClientError


def empty_report():
    return {
        "assessment": {"id": 7, "name": "Review", "status": "in_progress"},
        "project": {"id": 3, "name": "Project"}, "generated_at": "2026-01-01T00:00:00+00:00",
        "executive_summary": "No reportable findings are currently recorded.",
        "scope": {"asset_count": 0, "authorized_assets": []},
        "reconnaissance": [],
        "methodology": ["Stored observations only."],
        "risk_overview": {"severity_distribution": {}, "priority_distribution": {},
            "total_canonical_findings": 0, "total_occurrences": 0, "evidence_count": 0,
            "highest_risk_score": 0},
        "findings": [], "affected_assets": [], "evidence": [], "remediation_themes": [],
        "audit_summary": [], "limitations": ["Report generation does not perform network activity."],
    }


class ReportsViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_project_assessment_controls_and_empty_states(self):
        view = ReportsView()
        requests = []
        view.request_api.connect(lambda *args: requests.append(args))
        view.set_projects([{"id": 5, "name": "Selected project"}], 5)
        self.assertEqual(view.project_selector.currentData(), 5)
        self.assertEqual(requests[0][0], "report_assessments")
        self.assertIn("/projects/5/assessments", requests[0][2])
        view.set_assessments([])
        self.assertIn("No assessments", view.summary.text())
        self.assertFalse(view.export_json_button.isEnabled())
        view.assessment_name.setText("Assessment")
        self.assertTrue(view.create_button.isEnabled())
        view.create_button.click()
        self.assertEqual(requests[-1][1], "POST")
        self.assertNotIn("url", str(requests[-1]).lower())

    def test_populated_report_renders_statistics_methodology_limitations_and_exports(self):
        view = ReportsView()
        view.set_projects([{"id": 3, "name": "Project"}], 3)
        view.set_assessment({"id": 7, "status": "in_progress"})
        report = empty_report()
        report["findings"] = [{"title": "Missing header", "severity": "low", "confidence": "high",
            "risk_score": 25, "priority": "low", "category": "security_header", "asset": "example.test",
            "endpoint": "https://example.test/", "correlation_groups": ["security_headers:g"],
            "occurrence_count": 2, "evidence": "Header absent", "risk_explanation": "Direct observation.",
            "remediation": "Configure the header."}]
        report["risk_overview"].update({"total_canonical_findings": 1, "total_occurrences": 2,
            "severity_distribution": {"low": 1}, "priority_distribution": {"low": 1}, "evidence_count": 1,
            "highest_risk_score": 25})
        report["scope"].update({"asset_count": 1, "authorized_assets": [{"value": "example.test", "type": "domain", "finding_count": 1, "highest_risk_score": 25}]})
        report["affected_assets"] = [{"value": "example.test", "finding_count": 1, "highest_risk_score": 25}]
        report["evidence"] = [{"id": 8, "title": "Header evidence", "type": "observation", "finding_id": 2,
            "result_id": 3, "job_id": 4, "content_hash": "abc"}]
        view.set_report(report)
        self.assertIn("Highest risk: 25/100", view.summary.text())
        rendered = view.preview.toHtml()
        for section in ("Executive Summary", "Scope", "Reconnaissance", "Risk Overview", "Findings", "Affected Assets", "Evidence", "Methodology", "Limitations", "Audit Summary"):
            self.assertIn(section, rendered)
        self.assertIn("Missing header", rendered)
        self.assertTrue(view.export_json_button.isEnabled())
        self.assertTrue(view.export_markdown_button.isEnabled())
        self.assertTrue(view.export_html_button.isEnabled())

    def test_main_window_offscreen_navigation_opens_reports(self):
        class FakeClient:
            def request_json(self, method, path, payload=None):
                if path == "/health": return {"status": "healthy"}
                if path in {"/projects", "/assessment-domains", "/scan-profiles", "/tools"}: return []
                return []
        window = MainWindow(FakeClient(), object())
        window.show()
        window.thread_pool.waitForDone(5000)
        self.app.processEvents()
        window.nav_buttons["Reports"].click()
        self.assertIs(window.stack.currentWidget(), window.reports_view)
        window.close()

    def test_missing_backend_is_reported_without_crashing(self):
        class OfflineClient:
            def request_json(self, method, path, payload=None):
                raise ApiClientError("Cannot reach the local API")
        window = MainWindow(OfflineClient(), None)
        window.thread_pool.waitForDone(5000)
        self.app.processEvents()
        self.assertIn("Backend connection problem", window.error_banner.text())
        self.assertEqual(window.connection_pill.text(), "Backend unavailable")
        window.close()

    def test_invalid_report_and_export_responses_are_safe(self):
        view = ReportsView()
        view.set_assessment({"id": 9, "status": "draft"})
        view.set_report({"unexpected": "shape"})
        self.assertIsNone(view.report)
        self.assertIn("incomplete", view.status_label.text())
        view._export_paths["report_export_json"] = "unused.json"
        view.set_export_result("report_export_json", {"content": 4})
        self.assertIn("invalid export", view.status_label.text())

    def test_export_writes_only_the_selected_destination(self):
        view = ReportsView()
        with tempfile.TemporaryDirectory(prefix="report export ") as temp:
            destination = Path(temp) / "selected report.json"
            view._export_paths["report_export_json"] = str(destination)
            view.set_export_result("report_export_json", {"content": '{"report": true}'})
            self.assertEqual(destination.read_text(encoding="utf-8"), '{"report": true}')
            self.assertIn("selected report.json", view.status_label.text())


if __name__ == "__main__":
    unittest.main()
