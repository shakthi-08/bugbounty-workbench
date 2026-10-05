import sys
import unittest
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from test_phase1 import api_client, DATABASE_PATH, ALEMBIC_CONFIG
from alembic import command
from app.core.database import AsyncSessionLocal
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.services.finding_risk import (correlate_findings, normalize_endpoint,
    normalize_finding, risk_for, summarize_findings)


def row(fid, *, title="Missing X-Content-Type-Options", severity="low", confidence="high",
        category="security_header", asset=2, endpoint="https://example.test/login"):
    return {"id":fid,"project_id":1,"asset_id":asset,"title":title,"severity":severity,
        "confidence":confidence,"category":category,"status":"open","endpoint":endpoint,
        "description":"Observed configuration","evidence":"original evidence","remediation":"configure safely"}


class FindingRiskUnitTests(unittest.TestCase):
    def test_endpoint_normalization_removes_query_and_default_port(self):
        self.assertEqual(normalize_endpoint(" HTTPS://Example.TEST:443/login/?token=private#frag "),
                         "https://example.test/login")

    def test_normalization_preserves_severity_and_human_values(self):
        normalized = normalize_finding(row(1, title="  Missing   CSP  ", severity="MeDiUm", category=" Security Header "))
        self.assertEqual(normalized["severity"], "medium")
        self.assertEqual(normalized["category"], "security_header")
        self.assertEqual(normalized["title"], "Missing CSP")
        self.assertEqual(normalized["original"]["title"], "  Missing   CSP  ")
        self.assertEqual(normalized["original"]["evidence"], "original evidence")

    def test_identity_is_stable_across_formatting_queries_and_timestamps(self):
        one = row(1, endpoint="HTTPS://Example.TEST:443/login?one=1")
        two = row(2, endpoint="https://example.test/login/?two=2")
        one["created_at"], two["created_at"] = "2020", "2030"
        self.assertEqual(normalize_finding(one)["identity_fingerprint"], normalize_finding(two)["identity_fingerprint"])

    def test_identity_changes_with_security_condition_and_asset(self):
        baseline = normalize_finding(row(1))["identity_fingerprint"]
        self.assertNotEqual(baseline, normalize_finding(row(2, title="Missing Content-Security-Policy"))["identity_fingerprint"])
        self.assertNotEqual(baseline, normalize_finding(row(3, asset=9))["identity_fingerprint"])

    def test_severity_scores_and_priority_bands(self):
        cases = [("informational",0,"informational"),("low",25,"low"),("medium",50,"medium"),
                 ("high",75,"high"),("critical",95,"critical")]
        for severity, score, priority in cases:
            calculated = risk_for({"severity":severity,"confidence":"high","category":"test"})
            self.assertEqual((calculated["risk_score"],calculated["priority"]),(score,priority))
        self.assertEqual(risk_for({"severity":"low","confidence":"low","category":"test"})["risk_score"],13)

    def test_confidence_is_conservative_score_deterministic_and_explained(self):
        finding = {"severity":"critical","confidence":"low","category":"cookie_security"}
        first, second = risk_for(finding), risk_for(finding)
        self.assertEqual(first, second)
        self.assertEqual(first["risk_score"],48)
        self.assertNotEqual(first["priority"],"critical")
        self.assertIn("Confidence factor", first["risk_explanation"])

    def test_related_finding_correlation_families_and_unrelated_separation(self):
        inputs = [
            normalize_finding(row(1, title="HSTS missing", category="security_header")),
            normalize_finding(row(2, title="CSP missing", category="security_header")),
            normalize_finding(row(3, title="Cookie sessionid attributes missing", category="cookie")),
            normalize_finding(row(4, title="Server header discloses version", category="information_disclosure")),
            normalize_finding(row(5, title="SQL query bug", category="application_logic")),
        ]
        correlated = correlate_findings(inputs)
        families = {group["group"] for group in correlated["groups"]}
        self.assertTrue({"transport_security","security_headers","cookie_security","information_disclosure"} <= families)
        self.assertEqual(correlated["by_finding"][5], [])

    def test_summary_does_not_additive_inflate_many_low_findings(self):
        rows = []
        for index in range(100):
            item = normalize_finding(row(index+1, title=f"Unique issue {index}", severity="low", category="general", endpoint=f"/p/{index}"))
            item.update(risk_for(item))
            rows.append(item)
        summary = summarize_findings(rows)
        self.assertEqual(summary["severity_distribution"]["low"],100)
        self.assertEqual(summary["highest_risk_score"],19 if rows[0]["confidence"] == "low" else 25)
        self.assertLess(summary["highest_risk_score"],80)
        self.assertEqual(summary["affected_asset_count"],1)
        self.assertTrue(summary["top_remediation_priorities"])


class FindingRiskApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        if not DATABASE_PATH.is_file():
            DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
            command.upgrade(ALEMBIC_CONFIG, "head")
        self.context=api_client()
        self.client=await self.context.__aenter__()

    async def asyncTearDown(self):
        await self.context.__aexit__(None,None,None)

    async def test_risk_api_persistence_duplicate_evidence_and_summaries(self):
        project=(await self.client.post("/projects",json={"name":f"P10 {uuid4()}"})).json(); pid=project["id"]
        await self.client.post(f"/projects/{pid}/scopes",json={"value":"example.test","scope_type":"domain","included":True})
        asset=(await self.client.post(f"/projects/{pid}/assets",json={"value":"example.test","asset_type":"domain"})).json(); aid=asset["id"]
        async with AsyncSessionLocal() as db:
            first=Finding(project_id=pid,asset_id=aid,title="Missing X-Content-Type-Options",severity="low",status="open",
                endpoint="https://EXAMPLE.test/login?token=redacted",description="Observed",evidence="evidence A",
                category="security_header",confidence="high",remediation="Set nosniff")
            second=Finding(project_id=pid,asset_id=aid,title=" Missing   X-Content-Type-Options ",severity="low",status="open",
                endpoint="https://example.test:443/login?tracking=1",description="Observed again",evidence="evidence B",
                category="Security Header",confidence="medium",remediation="Set nosniff")
            db.add_all([first,second]); await db.flush()
            db.add_all([Evidence(project_id=pid,finding_id=first.id,evidence_type="json",title="A",metadata_json={}),
                        Evidence(project_id=pid,finding_id=second.id,evidence_type="json",title="B",metadata_json={})])
            await db.commit(); first_id,second_id=first.id,second.id
        calculated=await self.client.post(f"/projects/{pid}/findings/correlate")
        self.assertEqual(calculated.status_code,200,calculated.text)
        self.assertEqual(calculated.json()["duplicates_suppressed"],1)
        analysis=(await self.client.get(f"/projects/{pid}/findings/analysis")).json()
        canonical=next(item for item in analysis if item["id"]==first_id)
        duplicate=next(item for item in analysis if item["id"]==second_id)
        self.assertEqual(duplicate["canonical_finding_id"],first_id)
        self.assertEqual(canonical["occurrence_count"],2)
        self.assertEqual({item["title"] for item in canonical["evidence_references"]},{"A","B"})
        self.assertEqual(canonical["severity"],"low")
        self.assertEqual(canonical["risk_score"],25)
        self.assertEqual(canonical["priority"],"low")
        risk=await self.client.get(f"/projects/{pid}/findings/{first_id}/risk")
        self.assertEqual(risk.status_code,200)
        asset_summary=await self.client.get(f"/projects/{pid}/risk-summary/assets/{aid}")
        project_summary=await self.client.get(f"/projects/{pid}/risk-summary")
        self.assertEqual(asset_summary.json()["total_findings"],1)
        self.assertEqual(project_summary.json()["affected_assets"],[aid])
        self.assertEqual(project_summary.json()["severity_distribution"]["low"],1)
        persisted=await self.client.post(f"/projects/{pid}/findings/correlate")
        self.assertEqual(persisted.json()["duplicates_suppressed"],0)
        async with AsyncSessionLocal() as db:
            stored=await db.get(Finding,first_id)
            self.assertIsNotNone(stored.identity_fingerprint)
            self.assertEqual(stored.risk_score,25)
            self.assertEqual(stored.occurrence_count,2)

    async def test_invalid_project_asset_and_out_of_scope_project_are_rejected(self):
        missing=await self.client.get("/projects/999999/risk-summary")
        self.assertEqual(missing.status_code,404)
        project=(await self.client.post("/projects",json={"name":f"P10 scope {uuid4()}"})).json(); pid=project["id"]
        await self.client.post(f"/projects/{pid}/scopes",json={"value":"example.test","scope_type":"domain","included":True})
        asset=(await self.client.post(f"/projects/{pid}/assets",json={"value":"example.test","asset_type":"domain"})).json()
        wrong=await self.client.get(f"/projects/{pid}/risk-summary/assets/{asset['id']+1000}")
        self.assertEqual(wrong.status_code,404)
        await self.client.post(f"/projects/{pid}/scopes",json={"value":"example.test","scope_type":"domain","included":False})
        denied=await self.client.get(f"/projects/{pid}/risk-summary/assets/{asset['id']}")
        self.assertEqual(denied.status_code,403)


if __name__ == "__main__": unittest.main()
