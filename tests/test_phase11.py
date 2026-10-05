import sys
import unittest
from pathlib import Path
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from test_phase1 import api_client
from app.core.database import AsyncSessionLocal
from app.models.asset import Asset
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.scan_profile import ScanProfile
from app.models.scope import Scope
from app.models.security_job import SecurityJob
from app.models.security_result import SecurityResult
from sqlalchemy import select


class Phase11AssessmentApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.context = api_client()
        self.client = await self.context.__aenter__()

    async def asyncTearDown(self):
        await self.context.__aexit__(None, None, None)

    async def project(self, name=None):
        response = await self.client.post("/projects", json={"name": name or f"P11 {uuid4()}"})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    async def test_assessment_crud_lifecycle_and_project_binding(self):
        project = await self.project()
        other = await self.project()
        base = f"/projects/{project['id']}/assessments"
        created = await self.client.post(base, json={"name": "Quarterly review", "description": "Stored data only"})
        self.assertEqual(created.status_code, 201, created.text)
        assessment = created.json()
        self.assertEqual(assessment["status"], "draft")
        self.assertEqual((await self.client.get(base)).json()[0]["id"], assessment["id"])
        self.assertEqual((await self.client.get(f"{base}/{assessment['id']}")).status_code, 200)
        self.assertEqual((await self.client.get(f"/projects/{other['id']}/assessments/{assessment['id']}")).status_code, 404)
        self.assertEqual((await self.client.get("/projects/999999/assessments")).status_code, 404)
        self.assertEqual((await self.client.patch(f"{base}/{assessment['id']}", json={"status": "completed"})).status_code, 409)
        started = await self.client.patch(f"{base}/{assessment['id']}", json={"status": "in_progress"})
        self.assertEqual(started.status_code, 200, started.text)
        completed = await self.client.patch(f"{base}/{assessment['id']}", json={"status": "completed"})
        self.assertIsNotNone(completed.json()["completed_at"])
        self.assertEqual((await self.client.patch(f"{base}/{assessment['id']}", json={"status": "archived"})).json()["status"], "archived")

    async def test_empty_snapshot_statistics_and_all_exports(self):
        project = await self.project()
        base = f"/projects/{project['id']}/assessments"
        assessment = (await self.client.post(base, json={"name": "Empty report"})).json()
        report_response = await self.client.get(f"{base}/{assessment['id']}/report")
        report = report_response.json()
        self.assertEqual(report["risk_overview"]["total_canonical_findings"], 0)
        self.assertEqual(report["scope"]["asset_count"], 0)
        self.assertIn("No reportable findings", report["executive_summary"])
        self.assertIn("do not perform new network activity", " ".join(report["limitations"]).lower())
        self.assertEqual((await self.client.get(f"{base}/{assessment['id']}/report/statistics")).status_code, 200)
        json_export = await self.client.get(f"{base}/{assessment['id']}/export/json")
        md_export = await self.client.get(f"{base}/{assessment['id']}/export/markdown")
        html_export = await self.client.get(f"{base}/{assessment['id']}/export/html")
        self.assertEqual(json_export.status_code, 200)
        self.assertEqual(json_export.json()["assessment"]["id"], assessment["id"])
        self.assertEqual(md_export.status_code, 200)
        for heading in ("# Assessment Report", "## Executive Summary", "## Methodology", "## Evidence", "## Audit Summary", "## Limitations"):
            self.assertIn(heading, md_export.text)
        self.assertEqual(html_export.status_code, 200)
        self.assertIn("<h1>Assessment Report</h1>", html_export.text)
        self.assertTrue(any(row["action"] == "assessment_report_exported_html" for row in report["audit_summary"]) is False)
        refreshed = (await self.client.get(f"{base}/{assessment['id']}/report")).json()
        self.assertTrue(any(row["action"] == "assessment_report_generated" for row in refreshed["audit_summary"]))

    async def test_snapshot_uses_authorized_stored_data_canonical_findings_and_safe_evidence(self):
        project = await self.project('<Project & "Review">')
        project_id = project["id"]
        await self.client.post(f"/projects/{project_id}/scopes", json={"value": "example.test", "scope_type": "domain", "included": True})
        asset = (await self.client.post(f"/projects/{project_id}/assets", json={"value": "example.test", "asset_type": "domain"})).json()
        outside = (await self.client.post(f"/projects/{project_id}/assets", json={"value": "outside.invalid", "asset_type": "domain"})).json()
        assessment = (await self.client.post(f"/projects/{project_id}/assessments", json={"name": "<Quarterly & review>"})).json()
        async with AsyncSessionLocal() as db:
            profile_id = (await db.execute(select(ScanProfile.id).where(ScanProfile.key == "web_baseline"))).scalar_one()
            job = SecurityJob(project_id=project_id, profile_id=profile_id, asset_id=asset["id"], status="completed",
                requested_by="fixture", target_snapshot={"target": "example.test"}, scope_snapshot={}, profile_snapshot={}, parameters={})
            db.add(job)
            await db.flush()
            result = SecurityResult(project_id=project_id, job_id=job.id, target="example.test", result_type="endpoint",
                title="HTTPS observation", summary="Stored response metadata", normalized_data={"url": "https://example.test/", "http_status": 200, "authorization": "secret-value"})
            canonical = Finding(project_id=project_id, asset_id=asset["id"], job_id=job.id,
                title="Missing X-Content-Type-Options", severity="low", confidence="high", category="security_header",
                endpoint="https://example.test/login", description="Directly observed", evidence="Header missing",
                remediation="Set nosniff.", occurrence_count=2, risk_score=25, priority="low", risk_explanation="Direct observation.",
                correlation_groups=["security_headers:group"])
            db.add_all([result, canonical])
            await db.flush()
            duplicate = Finding(project_id=project_id, asset_id=asset["id"], job_id=job.id,
                title=canonical.title, severity="low", confidence="high", category="security_header", endpoint=canonical.endpoint,
                description="Repeated observation", status="duplicate", canonical_finding_id=canonical.id,
                identity_fingerprint=canonical.identity_fingerprint, occurrence_count=1)
            evidence = Evidence(project_id=project_id, job_id=job.id, result_id=result.id, finding_id=canonical.id,
                evidence_type="observation", title="Header observation", description="Header absent", path_reference="C:/private/evidence.json",
                content_hash="a" * 64, metadata_json={"source": "fixture", "api_key": "must-not-appear"})
            unsafe_evidence = Evidence(project_id=project_id, evidence_type="note", title="Outside evidence", description="private", path_reference="secret/path")
            db.add_all([duplicate, evidence, unsafe_evidence])
            await db.commit()
        base = f"/projects/{project_id}/assessments/{assessment['id']}"
        response = await self.client.get(f"{base}/report")
        self.assertEqual(response.status_code, 200, response.text)
        report = response.json()
        self.assertEqual(report["scope"]["asset_count"], 1)
        self.assertEqual(len(report["reconnaissance"]), 1)
        self.assertNotIn("secret-value", str(report))
        self.assertNotIn("private/evidence", str(report))
        self.assertNotIn("api_key", str(report).lower())
        stats = report["risk_overview"]
        self.assertEqual(stats["total_canonical_findings"], 1)
        self.assertEqual(stats["duplicate_occurrences"], 1)
        self.assertEqual(stats["severity_distribution"]["low"], 1)
        self.assertEqual(stats["highest_risk_score"], 25)
        self.assertEqual(report["findings"][0]["occurrence_count"], 2)
        self.assertEqual(report["findings"][0]["severity"], "low")
        self.assertEqual(report["findings"][0]["priority"], "low")
        self.assertEqual(len(report["evidence"]), 1)
        self.assertEqual(report["affected_assets"][0]["id"], asset["id"])
        self.assertTrue(any("TLS/certificate" in item for item in report["methodology"]))
        self.assertTrue(any("manual validation" in item for item in report["limitations"]))
        exported_html = (await self.client.get(f"{base}/export/html")).text
        self.assertIn("&lt;Quarterly &amp; review&gt;", exported_html)
        self.assertNotIn("<Quarterly", exported_html)
        markdown = (await self.client.get(f"{base}/export/markdown")).text
        self.assertIn("## Remediation", markdown)
        self.assertIn("## Affected Assets", markdown)

    async def test_invalid_assessment_and_export_routes_are_project_scoped(self):
        project = await self.project()
        other = await self.project()
        self.assertEqual((await self.client.get(f"/projects/{project['id']}/assessments/123456/report")).status_code, 404)
        self.assertEqual((await self.client.get(f"/projects/{other['id']}/assessments/123456/export/html")).status_code, 404)

    async def test_blank_names_and_unknown_lifecycle_status_are_rejected(self):
        project = await self.project()
        base = f"/projects/{project['id']}/assessments"
        self.assertEqual((await self.client.post(base, json={"name": "   "})).status_code, 422)
        assessment = (await self.client.post(base, json={"name": "Validated"})).json()
        invalid = await self.client.patch(f"{base}/{assessment['id']}", json={"status": "running"})
        self.assertEqual(invalid.status_code, 422)
        current = await self.client.get(f"{base}/{assessment['id']}")
        self.assertEqual(current.json()["status"], "draft")


if __name__ == "__main__":
    unittest.main()
