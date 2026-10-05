import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel
from desktop.views.scan_view import ScanView


class ScanViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_recon_view_initializes_with_explicit_execution_controls(self):
        view = ScanView()
        controls = {widget.text() for widget in view.findChildren(type(view.create_button))}
        self.assertTrue({"Create Job", "Approve Job", "Start Recon", "Cancel Job"} <= controls)
        self.assertIn("Project", {label.text() for label in view.findChildren(QLabel)})
        self.assertFalse(view.create_button.isEnabled())
        visible_text = " ".join(label.text() for label in view.findChildren(QLabel))
        self.assertIn("explicit approval", visible_text)

    def test_scope_decision_controls_job_creation(self):
        view = ScanView()
        view.set_projects([{"id": 2, "name": "Local project"}], 2)
        view.set_scope_decision({"allowed": True, "reason": "Included scope"})
        view.approval.setChecked(True)
        self.assertFalse(view.create_button.isEnabled())
        view.module_selector.addItem("DNS lookup")
        view.module_selector.item(0).setData(256, 5)
        view.module_selector.item(0).setCheckState(Qt.CheckState.Checked)
        view.set_tools([{"id": 9, "key": "curl_head", "name": "curl", "enabled": True,
                         "local_only": True, "adapter_available": True,
                         "availability_reason": "installed"}])
        view.tool_selector.item(0).setCheckState(Qt.CheckState.Checked)
        self.assertTrue(view.create_button.isEnabled())
        view.set_scope_decision({"allowed": False, "reason": "Excluded target"})
        self.assertFalse(view.create_button.isEnabled())

    def test_approved_job_runs_only_with_a_selected_available_tool(self):
        view = ScanView()
        view.set_tools([{"id": 9, "key": "curl_head", "name": "curl", "enabled": True,
                         "local_only": True, "adapter_available": True}])
        view.tool_selector.item(0).setCheckState(Qt.CheckState.Checked)
        view.set_job({"id": 17, "status": "approved", "profile_snapshot": {"tool_ids": [9]}})
        self.assertTrue(view.run_button.isEnabled())
        self.assertFalse(view.approve_button.isEnabled())

    def test_dns_to_explicit_selected_http_probe_workflow(self):
        view = ScanView()
        view.set_projects([{"id": 2, "name": "Local project"}], 2)
        view.set_tools([{"id": 10, "key": "windows_nslookup", "name": "nslookup",
                         "enabled": True, "local_only": True, "adapter_available": True}])
        view.tool_selector.item(0).setCheckState(Qt.CheckState.Checked)
        self.assertEqual(view._job_parameters()["record_types"], ["A", "AAAA", "CNAME", "MX", "NS", "TXT"])
        view.set_job({"id": 33, "status": "completed", "profile_snapshot": {"tool_ids": [10]}})
        view.set_execution({"job_id": 33, "status": "completed", "results": [
            {"result_type": "subdomain", "normalized_data": {
                "hostname": "api.example.test", "authorization_status": "authorized"}},
            {"result_type": "dns_record", "normalized_data": {
                "candidate_hostname": "alias.example.test", "authorization_status": "authorized"}},
            {"result_type": "dns_record", "normalized_data": {
                "candidate_hostname": "external.test", "authorization_status": "rejected"}},
        ], "evidence": [], "error": None})
        self.assertEqual(view.discovered_hosts.count(), 2)
        view.discovered_hosts.item(0).setCheckState(Qt.CheckState.Checked)
        self.assertTrue(view.probe_button.isEnabled())
        captured = []
        view.request_api.connect(lambda *args: captured.append(args))
        view._create_probe_jobs()
        self.assertEqual(captured[0][0], "scan_probe_jobs")
        self.assertEqual(captured[0][1], "POST")
        self.assertIn("/33/probe-selected", captured[0][2])
        self.assertEqual(captured[0][3], {"hostnames": ["api.example.test"]})

    def test_tls_action_requires_explicit_selection_of_discovered_host(self):
        view = ScanView()
        view.set_projects([{"id": 2, "name": "Local project"}], 2)
        view.set_job({"id": 33, "status": "completed", "profile_snapshot": {"tool_ids": [10]}})
        view.set_execution({"job_id": 33, "status": "completed", "results": [
            {"result_type": "subdomain", "normalized_data": {
                "hostname": "api.example.test", "authorization_status": "authorized"}},
        ], "evidence": [], "error": None})
        view.discovered_hosts.item(0).setCheckState(Qt.CheckState.Checked)
        self.assertTrue(view.tls_button.isEnabled())
        captured = []
        view.request_api.connect(lambda *args: captured.append(args))
        view._create_tls_jobs()
        self.assertEqual(captured[0][0], "scan_tls_jobs")
        self.assertIn("/33/inspect-tls-selected", captured[0][2])
        self.assertEqual(captured[0][3], {"hostnames": ["api.example.test"]})

    def test_direct_tls_job_requires_selecting_an_existing_asset(self):
        view = ScanView()
        view.set_projects([{"id": 2, "name": "Local project"}], 2)
        view.set_context(None, [{"value": "example.test", "included": True}], [])
        view.set_scope_decision({"allowed": True, "reason": "Included scope"})
        view.approval.setChecked(True)
        view.module_selector.addItem("TLS inspection")
        view.module_selector.item(0).setData(256, 5)
        view.module_selector.item(0).setCheckState(Qt.CheckState.Checked)
        view.set_tools([{"id": 11, "key": "tls_inspector", "name": "TLS inspector",
                         "enabled": True, "local_only": True, "adapter_available": True}])
        view.tool_selector.item(0).setCheckState(Qt.CheckState.Checked)
        self.assertFalse(view.create_button.isEnabled())
        view.set_context(None, [{"value": "example.test", "included": True}], [
            {"id": 7, "value": "example.test", "asset_type": "domain"}])
        self.assertTrue(view.create_button.isEnabled())

    def test_web_surface_job_requires_selected_asset_and_sets_bounded_timeout(self):
        view = ScanView()
        view.set_projects([{"id": 2, "name": "Local project"}], 2)
        view.set_context(None, [{"value": "example.test", "included": True}], [])
        view.set_scope_decision({"allowed": True, "reason": "Included scope"})
        view.approval.setChecked(True)
        view.module_selector.addItem("Web discovery")
        view.module_selector.item(0).setData(256, 5)
        view.module_selector.item(0).setCheckState(Qt.CheckState.Checked)
        view.set_tools([{"id": 12, "key": "web_surface_discovery", "name": "Web surface",
                         "enabled": True, "local_only": True, "adapter_available": True}])
        view.tool_selector.item(0).setCheckState(Qt.CheckState.Checked)
        self.assertFalse(view.create_button.isEnabled())
        view.set_context(None, [{"value": "example.test", "included": True}], [
            {"id": 8, "value": "example.test", "asset_type": "domain"}])
        self.assertTrue(view.create_button.isEnabled())
        self.assertEqual(view._job_parameters(), {"timeout": 5, "max_paths": 12})

    def test_phase13_bounded_controls_and_service_asset_requirement(self):
        view = ScanView()
        view.set_projects([{"id": 2, "name": "Local project"}], 2)
        view.set_context(None, [{"value": "192.0.2.10", "included": True}], [])
        view.set_scope_decision({"allowed": True, "reason": "Included scope"})
        view.approval.setChecked(True)
        view.module_selector.addItem("Service awareness")
        view.module_selector.item(0).setData(256, 5)
        view.module_selector.item(0).setCheckState(Qt.CheckState.Checked)
        view.set_tools([{"id": 14, "key": "tcp_service_awareness", "name": "TCP service awareness",
                         "enabled": True, "local_only": True, "adapter_available": True}])
        view.tool_selector.item(0).setCheckState(Qt.CheckState.Checked)
        self.assertFalse(view.create_button.isEnabled())
        view.set_context(None, [{"value": "192.0.2.10", "included": True}], [
            {"id": 17, "value": "192.0.2.10", "asset_type": "ip"}])
        self.assertTrue(view.create_button.isEnabled())
        self.assertEqual(view._job_parameters(), {"timeout": 2, "ports": [22, 80, 443, 445, 8080, 8443]})
        self.assertTrue(any(label.text().startswith("Fixed endpoint path cap")
                            for label in view.findChildren(QLabel)))
        view.set_correlation({"groups": [{"hostname": "192.0.2.10", "id": "stable-id",
            "scopes": [{"id": 2, "value": "192.0.2.10", "included": True}],
            "assets": [{"id": 17, "type": "ip", "source": "fixture"}],
            "observations": [{"id": 4, "result_type": "service", "title": "TCP 443 reachable",
                              "job_id": 9, "evidence_ids": [3]}],
            "findings": [{"id": 6, "title": "Example finding", "severity": "low"}]}]})
        text = view.correlation_output.toPlainText()
        self.assertIn("TCP 443 reachable", text)
        self.assertIn("evidence [3]", text)
        self.assertIn("Example finding", text)

    def test_web_surface_results_show_confidence_evidence_redirect_and_errors(self):
        view = ScanView()
        view.set_execution({"status": "completed", "results": [
            {"result_type": "technology", "title": "nginx", "normalized_data": {
                "technology": "nginx", "confidence": "high",
                "evidence": ["Server header identified nginx."]}},
            {"result_type": "configuration", "title": "Redirect blocked", "normalized_data": {
                "observation_type": "redirect_blocked", "to_host": "outside.test"}},
            {"result_type": "endpoint", "title": "Failed path", "normalized_data": {
                "inspection_error": "HTTP request timed out."}},
        ], "evidence": [], "error": None})
        output = view.execution_output.toPlainText()
        self.assertIn("Confidence: high", output)
        self.assertIn("Server header identified nginx.", output)
        self.assertIn("Redirect blocked: outside.test", output)
        self.assertIn("HTTP request timed out.", output)

    def test_phase9_uses_only_completed_endpoint_observation_and_existing_asset(self):
        view = ScanView()
        view.set_projects([{"id": 2, "name": "Local project"}], 2)
        view.set_context(None, [], [{"id": 8, "value": "https://example.test"}])
        view.set_execution({"results": [
            {"id": 31, "result_type": "endpoint", "title": "HTTP 200",
             "normalized_data": {"http_status": 200, "url": "https://example.test/"}},
            {"id": 32, "result_type": "technology", "title": "Server",
             "normalized_data": {"technology": "nginx"}},
        ]})
        self.assertEqual(view.web_observation_selector.count(), 1)
        self.assertEqual(view.web_observation_selector.currentData(), 31)
        captured = []
        view.request_api.connect(lambda *args: captured.append(args))
        view._phase9_request()
        self.assertEqual(captured[0][0], "phase9_created")
        self.assertIn("security-header-assessments", captured[0][2])
        self.assertEqual(captured[0][3]["asset_id"], 8)

    def test_phase9_controls_are_present_and_dont_accept_arbitrary_urls(self):
        view = ScanView()
        self.assertEqual(view.phase9_request_button.text(), "Request Header Assessment")
        self.assertFalse(view.phase9_request_button.isEnabled())
        self.assertFalse(hasattr(view, "phase9_url_input"))

    def test_phase14_assessment_uses_approval_states(self):
        view = ScanView()
        view.set_projects([{"id": 3, "name": "Authorized project"}], 3)
        view.approval.setChecked(True)
        view.set_phase14_job({"id": 44, "assessment": "api", "status": "pending_approval"})
        self.assertTrue(view.phase14_approve_button.isEnabled())
        self.assertFalse(view.phase14_run_button.isEnabled())
        view.set_phase14_job({"id": 44, "assessment": "api", "status": "approved"})
        self.assertTrue(view.phase14_run_button.isEnabled())

    def test_phase15_controls_use_pending_approval_then_approved_states(self):
        view=ScanView()
        self.assertEqual(view.phase15_auth_button.text(), "Authentication")
        self.assertEqual(view.phase15_access_button.text(), "Authorization Candidates")
        self.assertEqual(view.phase15_vuln_button.text(), "Vulnerability Candidates")
        view.approval.setChecked(True)
        view.set_phase15_job({"id":55,"assessment":"vulnerabilities","status":"pending_approval"})
        self.assertTrue(view.phase15_approve_button.isEnabled())
        self.assertFalse(view.phase15_run_button.isEnabled())
        view.set_phase15_job({"id":55,"assessment":"vulnerabilities","status":"approved"})
        self.assertTrue(view.phase15_run_button.isEnabled())


if __name__ == "__main__":
    unittest.main()
