import sys
import unittest
from pathlib import Path
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))
from test_phase1 import api_client
from app.core.database import AsyncSessionLocal
from app.models.security_job import SecurityJob
from app.models.security_result import SecurityResult
from app.models.scan_profile import ScanProfile
from app.services.advanced_web_assessment import assess_observation, extract_api_surface, extract_input_surface
from sqlalchemy import select
from datetime import datetime, timezone


class Phase14AnalysisTests(unittest.TestCase):
    def test_cookie_cors_disclosure_methods_and_transport_candidates(self):
        rows = assess_observation({"url":"http://api.example.test/v1?account=4", "final_url":"http://api.example.test/v1",
            "server":"nginx/1", "security_headers":{"access-control-allow-origin":"*",
            "access-control-allow-credentials":"true"}, "allow":"GET, TRACE",
            "cookie_security":[{"name":"sessionid","secure":False,"httponly":False,"samesite":None}]},
            1, 2, "http://api.example.test/v1")
        categories = {r["category"] for r in rows}
        self.assertTrue({"cookie", "cors", "information_disclosure", "http_methods", "transport_policy"} <= categories)
        self.assertNotIn("secret123", str(rows))
        self.assertEqual([r["fingerprint"] for r in rows], [r["fingerprint"] for r in assess_observation(
            {"url":"http://api.example.test/v1?account=4", "final_url":"http://api.example.test/v1", "server":"nginx/1",
             "security_headers":{"access-control-allow-origin":"*","access-control-allow-credentials":"true"},"allow":"GET, TRACE",
             "cookie_security":[{"name":"sessionid","secure":False,"httponly":False,"samesite":None}]},
            1,2,"http://api.example.test/v1")])

    def test_openapi_and_observed_query_parameters_are_bounded_and_normalized(self):
        api = extract_api_surface({"openapi":"3.0.0","info":{"title":"Example","version":"1"},
            "components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},
            "paths":{"/users":{"get":{"security":[{"bearer":[]}],"parameters":[{"name":"id","in":"query"}]}}}},
            "https://api.example.test/openapi.json")
        self.assertEqual(api["title"], "Example")
        self.assertEqual(api["endpoints"][0]["method"], "GET")
        self.assertEqual(api["parameters"][0]["name"], "id")
        self.assertEqual(api["security_schemes"], ["bearer"])
        self.assertEqual(extract_api_surface("not json", "x")["endpoints"], [])
        self.assertEqual(extract_input_surface({}, "https://x.test/?q=1")[0]["name"], "q")


class Phase14JobTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.context = api_client(); self.client = await self.context.__aenter__()

    async def asyncTearDown(self):
        await self.context.__aexit__(None, None, None)

    async def test_health_openapi_and_project_assessment_routes(self):
        self.assertEqual((await self.client.get("/health")).json()["status"], "healthy")
        schema=(await self.client.get("/openapi.json")).json()
        self.assertIn("/projects/{project_id}/security-assessments/{kind}", schema["paths"])

    async def test_asset_scope_approval_recheck_evidence_and_deduplication(self):
        project=(await self.client.post("/projects",json={"name":f"P14 {uuid4()}"})).json(); pid=project["id"]
        await self.client.post(f"/projects/{pid}/scopes",json={"value":"p14.example.test","scope_type":"domain","included":True})
        asset=(await self.client.post(f"/projects/{pid}/assets",json={"value":"p14.example.test","asset_type":"domain"})).json()
        async with AsyncSessionLocal() as db:
            profile=(await db.execute(select(ScanProfile).where(ScanProfile.key=="web_baseline"))).scalar_one()
            source_job=SecurityJob(project_id=pid,profile_id=profile.id,asset_id=asset["id"],status="completed",requested_by="fixture",
                target_snapshot={"target":asset["value"]},scope_snapshot={},profile_snapshot={},parameters={})
            db.add(source_job); await db.flush()
            db.add(SecurityResult(project_id=pid,job_id=source_job.id,target="https://p14.example.test/",result_type="endpoint",
                title="HTTP 200",normalized_data={"asset_id":asset["id"],"url":"https://p14.example.test/","http_status":200,
                    "server":"nginx/1","cookie_security":[{"name":"sessionid","secure":False,"httponly":False}],
                    "security_headers":{"access-control-allow-origin":"*"}})); await db.commit()
        created=await self.client.post(f"/projects/{pid}/security-assessments/web",json={"asset_id":asset["id"]})
        self.assertEqual(created.status_code,200,created.text); jid=created.json()["id"]
        self.assertEqual((await self.client.post(f"/projects/{pid}/security-assessments/web/{jid}/run")).status_code,409)
        await self.client.post(f"/projects/{pid}/security-assessments/web/{jid}/approve",json={"approved_by":"reviewer"})
        result=await self.client.post(f"/projects/{pid}/security-assessments/web/{jid}/run")
        self.assertEqual(result.status_code,200,result.text); self.assertTrue(result.json()["findings"])
        self.assertEqual(result.json()["endpoints_inspected"],1)
        rows=(await self.client.get(f"/projects/{pid}/findings")).json()
        self.assertTrue(any("CORS" in r["title"] for r in rows))
        again=(await self.client.post(f"/projects/{pid}/security-assessments/web",json={"asset_id":asset["id"]})).json()
        await self.client.post(f"/projects/{pid}/security-assessments/web/{again['id']}/approve",json={"approved_by":"reviewer"})
        dedup=await self.client.post(f"/projects/{pid}/security-assessments/web/{again['id']}/run")
        self.assertEqual(dedup.json()["findings"],[])

    async def test_out_of_scope_asset_and_lost_scope_are_rejected(self):
        project=(await self.client.post("/projects",json={"name":f"P14 {uuid4()}"})).json(); pid=project["id"]
        await self.client.post(f"/projects/{pid}/scopes",json={"value":"p14-out.example.test","scope_type":"domain","included":True})
        asset=(await self.client.post(f"/projects/{pid}/assets",json={"value":"p14-out.example.test","asset_type":"domain"})).json()
        created=(await self.client.post(f"/projects/{pid}/security-assessments/api",json={"asset_id":asset["id"]})).json()
        await self.client.post(f"/projects/{pid}/security-assessments/api/{created['id']}/approve",json={"approved_by":"reviewer"})
        await self.client.post(f"/projects/{pid}/scopes",json={"value":"p14-out.example.test","scope_type":"domain","included":False})
        self.assertEqual((await self.client.post(f"/projects/{pid}/security-assessments/api/{created['id']}/run")).status_code,403)


if __name__ == "__main__": unittest.main()
