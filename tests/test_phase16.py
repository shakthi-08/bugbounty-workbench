import unittest
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_phase1 import api_client


class Phase16HardeningTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.context = api_client()
        self.client = await self.context.__aenter__()
        project = await self.client.post("/projects", json={"name": f"V1 {uuid4()}"})
        self.project_id = project.json()["id"]
        await self.client.post(f"/projects/{self.project_id}/scopes", json={
            "value": "v1-in-scope.example.test", "scope_type": "domain", "included": True,
        })
        self.asset = (await self.client.post(f"/projects/{self.project_id}/assets", json={
            "value": "v1-in-scope.example.test", "asset_type": "domain",
        })).json()

    async def asyncTearDown(self):
        await self.context.__aexit__(None, None, None)

    async def test_manual_finding_rechecks_scope_and_sanitizes_secrets(self):
        out_of_scope = await self.client.post(f"/projects/{self.project_id}/findings", json={
            "asset_id": self.asset["id"], "endpoint": "https://outside.example.net/path",
            "title": "Out of scope", "severity": "low", "description": "test",
        })
        self.assertEqual(out_of_scope.status_code, 403)

        created = await self.client.post(f"/projects/{self.project_id}/findings", json={
            "asset_id": self.asset["id"], "endpoint": "https://v1-in-scope.example.test/path",
            "title": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
            "severity": "low", "description": "api_key=secret-value", "evidence": "cookie=session-secret",
        })
        self.assertEqual(created.status_code, 201, created.text)
        self.assertNotIn("eyJhbGci", str(created.json()))
        self.assertNotIn("secret-value", str(created.json()))
        self.assertNotIn("session-secret", str(created.json()))
        audit = (await self.client.get(f"/projects/{self.project_id}/security-audit")).json()
        self.assertIn("finding_created", {row["action"] for row in audit})
        self.assertIn("finding_scope_validation_failure", {row["action"] for row in audit})

    async def test_evidence_nested_sensitive_fields_are_redacted(self):
        finding = await self.client.post(f"/projects/{self.project_id}/findings", json={
            "asset_id": self.asset["id"], "title": "Observation", "severity": "info",
            "description": "Stored evidence sanitization test.",
        })
        self.assertEqual(finding.status_code, 201, finding.text)
        evidence = await self.client.post(f"/projects/{self.project_id}/evidence", json={
            "finding_id": finding.json()["id"], "evidence_type": "json", "title": "Safe metadata",
            "description": "Authorization: Bearer abcdefghijklmnop",
            "metadata": {"session_cookie": "cookie-secret", "note": "token=token-secret"},
        })
        self.assertEqual(evidence.status_code, 201, evidence.text)
        stored = str(evidence.json())
        self.assertNotIn("cookie-secret", stored)
        self.assertNotIn("token-secret", stored)
        self.assertNotIn("abcdefghijklmnop", stored)
        self.assertEqual(evidence.json()["metadata"]["session_cookie"], "[REDACTED]")

    async def test_oversized_api_payload_is_rejected_before_parsing(self):
        response = await self.client.post("/projects", headers={"Content-Length": str(3 * 1024 * 1024)})
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()
