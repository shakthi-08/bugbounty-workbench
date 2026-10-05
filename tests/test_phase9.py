import unittest
import sys
from pathlib import Path
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))
from test_phase1 import api_client
from app.core.database import AsyncSessionLocal
from app.models.security_job import SecurityJob
from app.models.security_result import SecurityResult
from app.models.scan_profile import ScanProfile
from sqlalchemy import select
from datetime import datetime, timezone
from app.services.security_header_assessment import assess_observation
from app.services.web_surface_inspection import _response_headers


class Phase9AssessmentTests(unittest.TestCase):
    def test_conservative_headers_and_stable_fingerprints(self):
        result = {"final_url":"https://example.test/", "url":"https://example.test/",
                  "security_headers":{}, "cookie_security":[], "server":"nginx/1.2",
                  "powered_by":None}
        findings = assess_observation(result, project_id=1, asset_id=2, endpoint=result["url"])
        by_type = {item["type"]: item for item in findings}
        self.assertEqual(by_type["Strict-Transport-Security"]["severity"], "low")
        self.assertEqual(by_type["Content-Security-Policy"]["severity"], "informational")
        self.assertEqual(by_type["server"]["severity"], "informational")
        again = assess_observation(result, project_id=1, asset_id=2, endpoint=result["url"])
        self.assertEqual([x["fingerprint"] for x in findings], [x["fingerprint"] for x in again])

    def test_weak_csp_and_cookie_redaction_shape(self):
        result = {"url":"https://example.test/", "final_url":"https://example.test/",
                  "security_headers":{"content-security-policy":"default-src * 'unsafe-inline'"},
                  "cookie_security":[{"name":"sessionid","secure":False,"httponly":False,"samesite":None}]}
        findings = assess_observation(result, project_id=1, asset_id=2, endpoint=result["url"])
        self.assertTrue(any(x["type"] == "Content-Security-Policy" and x["evidence"]["observed"] == "weak" for x in findings))
        cookie = next(x for x in findings if x["category"] == "cookie")
        self.assertEqual(cookie["severity"], "low")
        self.assertNotIn("value", str(cookie["evidence"]).lower())

    def test_set_cookie_values_are_never_returned(self):
        _, headers = _response_headers(b"HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=secret123; Secure; HttpOnly; SameSite=Lax\r\n\r\n")
        self.assertEqual(headers["cookie_names"], "sessionid")
        self.assertEqual(headers["cookie_security"], [{"name":"sessionid","secure":True,"httponly":True,"samesite":"lax"}])
        self.assertNotIn("secret123", str(headers))


class Phase9ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.context = api_client()
        self.client = await self.context.__aenter__()

    async def asyncTearDown(self):
        await self.context.__aexit__(None, None, None)

    async def test_authorized_observation_approval_finding_and_duplicate_suppression(self):
        project = (await self.client.post("/projects", json={"name": f"P9 {uuid4()}"})).json()
        pid = project["id"]
        await self.client.post(f"/projects/{pid}/scopes", json={"value":"example.test","scope_type":"domain","included":True})
        asset = (await self.client.post(f"/projects/{pid}/assets", json={"value":"example.test","asset_type":"domain"})).json()
        async with AsyncSessionLocal() as db:
            profile_id = (await db.execute(select(ScanProfile.id).where(ScanProfile.key == "web_baseline"))).scalar_one()
            source_job = SecurityJob(project_id=pid, profile_id=profile_id, asset_id=asset["id"], status="completed",
                requested_by="fixture", target_snapshot={"target":"example.test"}, scope_snapshot={},
                profile_snapshot={}, parameters={}, started_at=datetime.now(timezone.utc), completed_at=datetime.now(timezone.utc))
            db.add(source_job); await db.flush()
            source = SecurityResult(project_id=pid, job_id=source_job.id, target="example.test", result_type="endpoint",
                title="HTTP 200", normalized_data={"asset_id":asset["id"],"url":"https://example.test/",
                  "final_url":"https://example.test/","http_status":200,"security_headers":{},"cookie_security":[],"server":"nginx"})
            db.add(source); await db.commit(); source_id=source.id
        request = await self.client.post(f"/projects/{pid}/security-header-assessments", json={"asset_id":asset["id"],"observation_id":source_id})
        self.assertEqual(request.status_code, 200, request.text)
        jid=request.json()["id"]
        self.assertEqual((await self.client.post(f"/projects/{pid}/security-header-assessments/{jid}/run")).status_code, 409)
        approved=await self.client.post(f"/projects/{pid}/security-header-assessments/{jid}/approve",json={"approved_by":"reviewer"})
        self.assertEqual(approved.json()["status"],"approved")
        result=await self.client.post(f"/projects/{pid}/security-header-assessments/{jid}/run")
        self.assertEqual(result.status_code,200,result.text)
        self.assertTrue(any(item["confidence"] == "high" and "evidence" in item for item in result.json()["findings"]))
        again = await self.client.post(f"/projects/{pid}/security-header-assessments", json={"asset_id":asset["id"],"observation_id":source_id})
        jid2=again.json()["id"]
        await self.client.post(f"/projects/{pid}/security-header-assessments/{jid2}/approve",json={"approved_by":"reviewer"})
        duplicate=await self.client.post(f"/projects/{pid}/security-header-assessments/{jid2}/run")
        self.assertEqual(duplicate.status_code,200,duplicate.text)
        self.assertEqual(duplicate.json()["findings"],[])
        findings=(await self.client.get(f"/projects/{pid}/findings")).json()
        self.assertTrue(all(item["fingerprint"] and item["remediation"] for item in findings))


if __name__ == "__main__": unittest.main()
