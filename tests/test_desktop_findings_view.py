import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PySide6.QtWidgets import QApplication
from desktop.views.findings_view import FindingsView

class FindingsViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app=QApplication.instance() or QApplication([])

    def test_risk_fields_correlation_summary_and_detail_render(self):
        view=FindingsView()
        view.set_project(3)
        view.set_summary({"total_findings":1,"affected_asset_count":1,
            "severity_distribution":{"informational":0,"low":1,"medium":0,"high":0,"critical":0},
            "priority_distribution":{"informational":0,"low":1,"medium":0,"high":0,"critical":0},"highest_risk_score":25})
        view.set_items([{"id":1,"title":"Missing X-Content-Type-Options","severity":"low",
            "confidence":"high","risk_score":25,"priority":"low","category":"security_header",
            "endpoint":"https://example.test/login","correlation_groups":["security_headers:abc"],
            "risk_explanation":"Low severity, directly observed.","evidence":"header missing",
            "evidence_references":[{"id":9}],"remediation":"Set nosniff"}])
        headers=[view.table.horizontalHeaderItem(i).text() for i in range(view.table.columnCount())]
        self.assertTrue({"Severity","Confidence","Risk","Priority","Category","Correlation"} <= set(headers))
        self.assertIn("Highest risk 25/100",view.summary.text())
        view.table.selectRow(0)
        text=view.details.toPlainText()
        self.assertIn("security_headers:abc",text)
        self.assertIn("Evidence: header missing",text)
        self.assertIn("Remediation: Set nosniff",text)
        self.assertIn("Low severity, directly observed.",text)

    def test_correlate_button_requests_project_scoped_analysis(self):
        view=FindingsView(); view.set_project(17)
        captured=[]
        view.request_api.connect(lambda *args: captured.append(args))
        view.correlate_button.click()
        self.assertEqual(captured[0][0],"finding_correlate")
        self.assertEqual(captured[0][1],"POST")
        self.assertIn("/projects/17/findings/correlate",captured[0][2])

if __name__ == "__main__": unittest.main()
