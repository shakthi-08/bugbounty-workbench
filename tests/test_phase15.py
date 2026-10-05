import sys
import unittest
from pathlib import Path
from uuid import uuid4

BACKEND=Path(__file__).resolve().parents[1]/"backend"
sys.path.insert(0,str(BACKEND))
from test_phase1 import api_client
from app.core.database import AsyncSessionLocal
from app.models.security_job import SecurityJob
from app.models.security_result import SecurityResult
from app.models.scan_profile import ScanProfile
from app.models.evidence import Evidence
from app.services.security_candidate_assessment import analyze_security_observation, sanitize_excerpt, detect_excerpt_indicators
from sqlalchemy import select


class Phase15CandidateTests(unittest.TestCase):
    def test_auth_surface_cookie_and_token_parameter_candidates_redact_values(self):
        result=analyze_security_observation({"url":"https://app.example.test/login?access_token=secret-value",
            "http_status":200,"cookie_security":[{"name":"sessionid","secure":False,"httponly":False}],
            "method":"GET"},project_id=1,asset_id=2,endpoint="https://app.example.test/login?access_token=secret-value",kind="authentication")
        self.assertEqual(result["surfaces"][0]["type"],"authentication")
        self.assertEqual({item["detection"] for item in result["candidates"]},
                         {"weak_session_cookie","sensitive_query_parameter"})
        self.assertNotIn("secret-value",str(result))
        self.assertTrue(all(item["evidence"]["classification"].startswith("candidate") for item in result["candidates"]))

    def test_authorization_candidates_do_not_enumerate_or_modify_ids(self):
        api={"endpoints":[{"path":"/users/{user_id}","method":"GET","security_required":False}],
             "parameters":[{"endpoint":"/users/{user_id}","name":"user_id","location":"path","authentication_required":False}]}
        result=analyze_security_observation({"api_spec_observation":api},project_id=1,asset_id=2,
            endpoint="https://app.example.test/openapi.json",kind="authorization")
        self.assertTrue(any("horizontal access-control" in item["title"] for item in result["candidates"]))
        self.assertTrue(any(item["detection"]=="sensitive_endpoint_without_security_metadata" for item in result["candidates"]))
        self.assertTrue(all(item["evidence"]["classification"]=="candidate requiring manual verification" for item in result["candidates"]))
        self.assertNotIn("alternate_id",str(result))

    def test_bounded_vulnerability_candidate_categories_and_secret_redaction(self):
        data={"url":"https://app.example.test/search?q=hello&redirect_to=%2Fhome&file_path=report&user_id=7",
            "response_excerpt":"<html><div>hello</div> SQLSTATE[42000] private AKIA1234567890ABCDEF password=should-hide internal.corp /var/app/config.py</html>"}
        result=analyze_security_observation(data,project_id=1,asset_id=2,endpoint=data["url"],kind="vulnerabilities")
        types={item["detection"] for item in result["candidates"]}
        self.assertTrue({"reflected_input_in_html","database_error_signature","secret_like_response_content",
            "internal_hostname","filesystem_path",
            "redirect_parameter","filesystem_parameter","resource_identifier_parameter"}<=types)
        serialized=str(result)
        self.assertNotIn("AKIA1234567890ABCDEF",serialized)
        self.assertNotIn("should-hide",serialized)
        self.assertNotIn("/var/app",serialized)
        self.assertTrue(all(item["confidence"] in {"low","medium","high"} for item in result["candidates"]))

    def test_sanitizer_caps_and_removes_secrets_and_paths(self):
        value=sanitize_excerpt("Authorization: Bearer abcdef api_key=secret-value /etc/passwd " + "x"*5000)
        self.assertLessEqual(len(value),2048)
        self.assertNotIn("abcdef",value); self.assertNotIn("secret-value",value)
        self.assertNotIn("/etc/passwd",value)
        indicators=detect_excerpt_indicators('api_key="hidden" SQLSTATE[42000] internal.corp /etc/passwd')
        self.assertTrue({"secret_like","database_error","internal_hostname","filesystem_path"}<=set(indicators))


class Phase15WorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.context=api_client(); self.client=await self.context.__aenter__()

    async def asyncTearDown(self):
        await self.context.__aexit__(None,None,None)

    async def test_scope_approval_audit_evidence_findings_and_deduplication(self):
        p=(await self.client.post("/projects",json={"name":f"P15 {uuid4()}"})).json(); pid=p["id"]
        await self.client.post(f"/projects/{pid}/scopes",json={"value":"p15.example.test","scope_type":"domain","included":True})
        asset=(await self.client.post(f"/projects/{pid}/assets",json={"value":"p15.example.test","asset_type":"domain"})).json()
        async with AsyncSessionLocal() as db:
            profile=(await db.execute(select(ScanProfile).where(ScanProfile.key=="web_baseline"))).scalar_one()
            source=SecurityJob(project_id=pid,profile_id=profile.id,asset_id=asset["id"],status="completed",requested_by="fixture",
                target_snapshot={"target":asset["value"]},scope_snapshot={},profile_snapshot={},parameters={})
            db.add(source); await db.flush()
            db.add(SecurityResult(project_id=pid,job_id=source.id,target="https://p15.example.test/login?access_token=LEAKME",
                result_type="endpoint",title="Login observation",normalized_data={"asset_id":asset["id"],
                "url":"https://p15.example.test/login?access_token=LEAKME","http_status":200,"method":"GET",
                "cookie_security":[{"name":"sessionid","secure":False,"httponly":False,"value":"COOKIELEAK"}],
                "response_excerpt":"stack trace"})); await db.commit()
        created=await self.client.post(f"/projects/{pid}/security-assessments/authentication",json={"asset_id":asset["id"]})
        self.assertEqual(created.status_code,200,created.text); jid=created.json()["id"]
        self.assertEqual((await self.client.post(f"/projects/{pid}/security-assessments/authentication/{jid}/run")).status_code,409)
        await self.client.post(f"/projects/{pid}/security-assessments/authentication/{jid}/approve",json={"approved_by":"reviewer"})
        result=await self.client.post(f"/projects/{pid}/security-assessments/authentication/{jid}/run")
        self.assertEqual(result.status_code,200,result.text); self.assertEqual(result.json()["endpoints_inspected"],1)
        self.assertTrue(result.json()["findings"])
        serialized=str(result.json())
        self.assertNotIn("LEAKME",serialized); self.assertNotIn("COOKIELEAK",serialized)
        async with AsyncSessionLocal() as db:
            persisted=list((await db.scalars(select(SecurityResult).where(SecurityResult.job_id==jid))).all())
            evidence=list((await db.scalars(select(Evidence).where(Evidence.job_id==jid))).all())
            self.assertNotIn("LEAKME",str([row.normalized_data for row in persisted]))
            self.assertNotIn("COOKIELEAK",str([row.metadata_json for row in evidence]))
        findings=(await self.client.get(f"/projects/{pid}/findings")).json()
        self.assertTrue(findings)
        again=(await self.client.post(f"/projects/{pid}/security-assessments/authentication",json={"asset_id":asset["id"]})).json()
        await self.client.post(f"/projects/{pid}/security-assessments/authentication/{again['id']}/approve",json={"approved_by":"reviewer"})
        rerun=await self.client.post(f"/projects/{pid}/security-assessments/authentication/{again['id']}/run")
        self.assertEqual(rerun.json()["findings"],[])
        audit=(await self.client.get(f"/projects/{pid}/security-audit")).json()
        self.assertIn("advanced_assessment_completed",{row["action"] for row in audit})

    async def test_scope_is_rechecked_at_execution_and_assessment_kind_is_validated(self):
        p=(await self.client.post("/projects",json={"name":f"P15 {uuid4()}"})).json(); pid=p["id"]
        await self.client.post(f"/projects/{pid}/scopes",json={"value":"p15-scope.example.test","scope_type":"domain","included":True})
        asset=(await self.client.post(f"/projects/{pid}/assets",json={"value":"p15-scope.example.test","asset_type":"domain"})).json()
        self.assertEqual((await self.client.post(f"/projects/{pid}/security-assessments/unknown",json={"asset_id":asset["id"]})).status_code,404)
        job=(await self.client.post(f"/projects/{pid}/security-assessments/authorization",json={"asset_id":asset["id"]})).json()
        await self.client.post(f"/projects/{pid}/security-assessments/authorization/{job['id']}/approve",json={"approved_by":"reviewer"})
        await self.client.post(f"/projects/{pid}/scopes",json={"value":"p15-scope.example.test","scope_type":"domain","included":False})
        self.assertEqual((await self.client.post(f"/projects/{pid}/security-assessments/authorization/{job['id']}/run")).status_code,403)


if __name__=="__main__": unittest.main()
