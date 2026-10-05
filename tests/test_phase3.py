import asyncio
import hashlib
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from unittest.mock import AsyncMock, patch

from test_phase1 import ALEMBIC_CONFIG, DATABASE_PATH, api_client

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.core.database import AsyncSessionLocal
from app.services import recon_execution
from app.models.assessment_taxonomy import TestModule
from app.models.scan_profile import ScanProfile
from app.models.tool import Tool
from app.services.tool_adapters import CurlHeadAdapter, NslookupAdapter, SubfinderAdapter
from alembic import command


class Phase3ApiTests(unittest.IsolatedAsyncioTestCase):
    async def create_workspace(self, scope="example.test", excluded=None):
        project = await self.client.post("/projects", json={"name": f"P3 {uuid4()}"})
        self.assertEqual(project.status_code, 201, project.text)
        project_id = project.json()["id"]
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": scope, "scope_type": "domain", "included": True,
        })
        if excluded:
            await self.client.post(f"/projects/{project_id}/scopes", json={
                "value": excluded, "scope_type": "domain", "included": False,
            })
        profiles = (await self.client.get("/scan-profiles")).json()
        profile = next(row for row in profiles if row["key"] == "web_baseline")
        modules = (await self.client.get("/assessment-modules")).json()
        module = next(row for row in modules if row["id"] in profile["module_ids"])
        return project_id, profile, module

    async def asyncSetUp(self):
        # test_phase1 owns and cleans its isolated test directory at its module
        # teardown; recreate the same isolated schema for this test module.
        if not DATABASE_PATH.is_file():
            DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
            command.upgrade(ALEMBIC_CONFIG, "head")
        self._context = api_client()
        self.client = await self._context.__aenter__()

    async def asyncTearDown(self):
        await self._context.__aexit__(None, None, None)

    async def create_job(self, project_id, profile, module, target="example.test", tool_ids=None):
        return await self.client.post(f"/projects/{project_id}/security-jobs", json={
            "profile_id": profile["id"], "target": target,
            "module_ids": [module["id"]], "requested_by": "phase3-test", "tool_ids": tool_ids or [],
        })

    async def test_taxonomy_tools_and_profiles_are_available(self):
        domains = (await self.client.get("/assessment-domains")).json()
        domain_keys = {row["key"] for row in domains}
        self.assertTrue({"web", "api", "android", "ios", "cloud", "kubernetes", "ai_llm"} <= domain_keys)
        self.assertEqual((await self.client.get(f"/assessment-domains/{domains[0]['id']}")).status_code, 200)
        categories = (await self.client.get("/assessment-categories")).json()
        self.assertTrue({"bola_idor", "prompt_injection", "smart_contract", "firmware_acquisition"} <= {row["key"] for row in categories})
        self.assertEqual((await self.client.get(f"/assessment-categories/{categories[0]['id']}")).status_code, 200)
        tools = (await self.client.get("/tools")).json()
        self.assertTrue({"nmap", "nuclei", "semgrep", "gitleaks", "slither"} <= {row["key"] for row in tools})
        self.assertIn("subfinder", {row["key"] for row in tools})
        self.assertEqual((await self.client.get(f"/tools/{tools[0]['id']}")).status_code, 200)
        subfinder_status = await self.client.get("/tools/subfinder/status")
        self.assertEqual(subfinder_status.status_code, 200)
        self.assertTrue(subfinder_status.json()["passive_only"])
        profiles = (await self.client.get("/scan-profiles")).json()
        self.assertTrue({"passive_recon", "web_baseline", "kubernetes_baseline"} <= {row["key"] for row in profiles})
        self.assertEqual((await self.client.get(f"/scan-profiles/{profiles[0]['id']}")).status_code, 200)
        modules = (await self.client.get("/assessment-modules")).json()
        self.assertEqual((await self.client.get(f"/assessment-modules/{modules[0]['id']}")).status_code, 200)

    async def test_subfinder_filters_current_scope_and_persists_evidence_and_audit(self):
        project_id, _, _ = await self.create_workspace(excluded="private.example.test")
        profiles = (await self.client.get("/scan-profiles")).json()
        profile = next(row for row in profiles if row["key"] == "passive_recon")
        modules = (await self.client.get("/assessment-modules")).json()
        module = next(row for row in modules if row["domain_key"] == "network"
                      and row["category_key"] == "asset_discovery")
        tool = next(row for row in (await self.client.get("/tools")).json()
                    if row["key"] == "subfinder")
        payload = {
            "profile_id": profile["id"], "target": "example.test",
            "module_ids": [module["id"]], "tool_ids": [tool["id"]],
            "requested_by": "phase5-test", "parameters": {"timeout": 10},
        }
        raw_output = "example.test\nAPI.Example.test.\napi.example.test\nprivate.example.test\nunrelated.net\nevil-example.test\nbad..example.test\n"
        fake_process = recon_execution.ProcessResult(
            raw_output, "deterministic fake stderr", 0,
            datetime.now(timezone.utc), datetime.now(timezone.utc), "completed",
        )
        with patch.object(SubfinderAdapter, "check_availability", return_value=(True, "fake executable")), \
             patch("app.services.recon_execution.run_process", new=AsyncMock(return_value=fake_process)):
            created = await self.client.post(f"/projects/{project_id}/security-jobs", json=payload)
            self.assertEqual(created.status_code, 201, created.text)
            job_id = created.json()["id"]
            approved = await self.client.post(
                f"/projects/{project_id}/security-jobs/{job_id}/approve",
                json={"approved_by": "phase5-reviewer"},
            )
            self.assertEqual(approved.json()["status"], "approved")
            started = await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/run")
            self.assertEqual(started.status_code, 200, started.text)
            for _ in range(30):
                job = await self.client.get(f"/projects/{project_id}/security-jobs/{job_id}")
                if job.json()["status"] not in {"queued", "running"}:
                    break
                await asyncio.sleep(0.01)
            execution = await self.client.get(
                f"/projects/{project_id}/security-jobs/{job_id}/execution")

        self.assertEqual(job.json()["status"], "completed")
        results = execution.json()["results"]
        hostnames = {row["normalized_data"]["hostname"] for row in results}
        self.assertEqual(hostnames, {"example.test", "api.example.test"})
        self.assertTrue(all(row["result_type"] == "subdomain" for row in results))
        self.assertTrue(all(row["normalized_data"]["authorization_status"] == "authorized"
                            for row in results))
        evidence = execution.json()["evidence"][0]
        self.assertIn(raw_output, evidence["output"])
        self.assertEqual(hashlib.sha256(Path(evidence["path_reference"]).read_bytes()).hexdigest(),
                         evidence["content_hash"])
        self.assertEqual(evidence["metadata"]["discovered_hosts"], 5)
        self.assertEqual(evidence["metadata"]["accepted_hosts"], 2)
        self.assertEqual(len(evidence["metadata"]["rejected_by_scope"]), 3)
        audit = (await self.client.get(f"/projects/{project_id}/security-audit")).json()
        processed = next(row for row in audit if row["action"] == "subfinder_results_processed")
        self.assertEqual(processed["details"]["discovered"], 5)
        self.assertEqual(processed["details"]["accepted"], 2)
        self.assertEqual(processed["details"]["rejected_by_scope"], 3)
        self.assertEqual(processed["details"]["malformed_lines"], 1)
        self.assertIn("derived_result_scope_rejected", {row["action"] for row in audit})
        with patch.object(CurlHeadAdapter, "check_availability", return_value=(True, "fake curl")):
            selected = await self.client.post(
                f"/projects/{project_id}/security-jobs/{job_id}/probe-selected",
                json={"hostnames": ["API.EXAMPLE.TEST."]},
            )
            self.assertEqual(selected.status_code, 201, selected.text)
            probe_job = selected.json()[0]
            self.assertEqual(probe_job["status"], "pending_approval")
            self.assertEqual(probe_job["target_snapshot"]["target"], "api.example.test")
            self.assertEqual(probe_job["parameters"]["http_mode"], "bounded_get")
            self.assertEqual(probe_job["parameters"]["source_job_id"], job_id)
            self.assertFalse(probe_job["approved_by"])
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "api.example.test", "scope_type": "subdomain", "included": False,
        })
        blocked_selection = await self.client.post(
            f"/projects/{project_id}/security-jobs/{job_id}/probe-selected",
            json={"hostnames": ["api.example.test"]},
        )
        self.assertEqual(blocked_selection.status_code, 403)
        jobs = (await self.client.get(f"/projects/{project_id}/security-jobs")).json()
        self.assertEqual(sum(job["parameters"].get("source_job_id") == job_id for job in jobs), 1)
        audit = (await self.client.get(f"/projects/{project_id}/security-audit")).json()
        self.assertIn("hosts_selected_for_http_probe", {row["action"] for row in audit})
        self.assertIn("host_selection_scope_rejected", {row["action"] for row in audit})

    async def test_dns_enrichment_and_selected_http_probe_are_explicit_and_safe(self):
        project_id, _, _ = await self.create_workspace(excluded="external.test")
        profile = next(row for row in (await self.client.get("/scan-profiles")).json()
                       if row["key"] == "passive_recon")
        module = next(row for row in (await self.client.get("/assessment-modules")).json()
                      if row["domain_key"] == "network" and row["category_key"] == "asset_discovery")
        nslookup = next(row for row in (await self.client.get("/tools")).json()
                        if row["key"] == "windows_nslookup")
        payload = {"profile_id": profile["id"], "target": "example.test",
                   "module_ids": [module["id"]], "tool_ids": [nslookup["id"]],
                   "requested_by": "phase6-test",
                   "parameters": {"record_types": ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]}}
        output_by_type = [
            "Server: resolver\nAddress: 192.0.2.53\nName: example.test\nAddress: 198.51.100.8\n",
            "Server: resolver\nAddress: 192.0.2.53\nName: example.test\nAddress: 2001:db8::8\n",
            "example.test canonical name = api.example.test.\n",
            "example.test MX preference = 10, mail exchanger = mail.external.test.\n",
            "example.test nameserver = ns.example.test.\n",
            'example.test text = "verification-secret-abc"\n',
        ]
        fake_dns = [recon_execution.ProcessResult(
            output, "", 0, datetime.now(timezone.utc), datetime.now(timezone.utc), "completed")
                    for output in output_by_type]
        with patch.object(NslookupAdapter, "check_availability", return_value=(True, "fake nslookup")), \
             patch("app.services.recon_execution.run_process", new=AsyncMock(side_effect=fake_dns)):
            created = await self.client.post(f"/projects/{project_id}/security-jobs", json=payload)
            self.assertEqual(created.json()["status"], "pending_approval", created.text)
            job_id = created.json()["id"]
            approved = await self.client.post(
                f"/projects/{project_id}/security-jobs/{job_id}/approve",
                json={"approved_by": "phase6-reviewer"})
            self.assertEqual(approved.json()["status"], "approved")
            await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/run")
            for _ in range(30):
                job = await self.client.get(f"/projects/{project_id}/security-jobs/{job_id}")
                if job.json()["status"] not in {"queued", "running"}:
                    break
                await asyncio.sleep(0.01)
            dns_execution = await self.client.get(
                f"/projects/{project_id}/security-jobs/{job_id}/execution")

        self.assertEqual(job.json()["status"], "completed")
        dns_results = dns_execution.json()["results"]
        self.assertEqual({row["normalized_data"]["record_type"] for row in dns_results},
                         {"A", "AAAA", "CNAME", "NS", "TXT"})
        cname = next(row for row in dns_results if row["normalized_data"]["record_type"] == "CNAME")
        self.assertEqual(cname["normalized_data"]["authorization_status"], "authorized")
        self.assertNotIn("mail.external.test", {row["normalized_data"].get("candidate_hostname")
                                                 for row in dns_results})
        dns_evidence = dns_execution.json()["evidence"][0]
        self.assertNotIn("verification-secret-abc", dns_evidence["output"])

        with patch.object(CurlHeadAdapter, "check_availability", return_value=(True, "fake curl")), \
             patch("app.services.recon_execution.run_process", new=AsyncMock(return_value=
                 recon_execution.ProcessResult(
                     "HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: session=secret\r\n"
                     "Content-Type: text/html\r\n\r\n<html><title>API surface</title></html>\n"
                     "BBWB_HTTP_META:200\t-\thttps://api.example.test/\n",
                     "", 0, datetime.now(timezone.utc), datetime.now(timezone.utc), "completed"))):
            selected = await self.client.post(
                f"/projects/{project_id}/security-jobs/{job_id}/probe-selected",
                json={"hostnames": ["api.example.test"]})
            self.assertEqual(selected.status_code, 201, selected.text)
            probe = selected.json()[0]
            self.assertEqual(probe["status"], "pending_approval")
            await self.client.post(
                f"/projects/{project_id}/security-jobs/{probe['id']}/approve",
                json={"approved_by": "phase6-reviewer"})
            await self.client.post(f"/projects/{project_id}/security-jobs/{probe['id']}/run")
            for _ in range(30):
                probe_status = await self.client.get(
                    f"/projects/{project_id}/security-jobs/{probe['id']}")
                if probe_status.json()["status"] not in {"queued", "running"}:
                    break
                await asyncio.sleep(0.01)
            http_execution = await self.client.get(
                f"/projects/{project_id}/security-jobs/{probe['id']}/execution")
        self.assertEqual(probe_status.json()["status"], "completed")
        endpoint = next(row for row in http_execution.json()["results"]
                        if row["result_type"] == "endpoint")
        self.assertEqual(endpoint["normalized_data"]["http_status"], 200)
        self.assertEqual(endpoint["normalized_data"]["title"], "API surface")
        http_evidence = http_execution.json()["evidence"][0]["output"]
        self.assertIn("nginx", http_evidence)
        self.assertNotIn("Set-Cookie", http_evidence)
        self.assertNotIn("session=secret", http_evidence)
        audit = (await self.client.get(f"/projects/{project_id}/security-audit")).json()
        self.assertIn("hosts_selected_for_http_probe", {row["action"] for row in audit})
        self.assertIn("execution_completed", {row["action"] for row in audit})

    async def test_job_requires_approval_and_run_requires_a_real_tool(self):
        project_id, profile, module = await self.create_workspace()
        created = await self.create_job(project_id, profile, module)
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.json()["status"], "pending_approval")
        premature = await self.client.post(
            f"/projects/{project_id}/security-jobs/{created.json()['id']}/run")
        self.assertEqual(premature.status_code, 409)
        self.assertIn("explicit approval", premature.json()["detail"])
        await self.client.post(f"/projects/{project_id}/security-jobs/{created.json()['id']}/approve",
                               json={"approved_by": "reviewer"})
        run = await self.client.post(f"/projects/{project_id}/security-jobs/{created.json()['id']}/run")
        self.assertEqual(run.status_code, 409)
        self.assertIn("registered recon tool", run.json()["detail"])

    async def test_approval_persists_actor_timestamp_and_snapshot(self):
        project_id, profile, module = await self.create_workspace()
        created = await self.create_job(project_id, profile, module)
        approved = await self.client.post(
            f"/projects/{project_id}/security-jobs/{created.json()['id']}/approve",
            json={"approved_by": "reviewer"},
        )
        self.assertEqual(approved.status_code, 200, approved.text)
        data = approved.json()
        self.assertEqual(data["status"], "approved")
        self.assertEqual(data["approved_by"], "reviewer")
        self.assertTrue(data["approval_timestamp"])
        self.assertTrue(data["scope_snapshot"]["authorization"]["allowed"])
        scopes_before = data["scope_snapshot"]
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "new.example.test", "scope_type": "domain", "included": True,
        })
        fetched = await self.client.get(f"/projects/{project_id}/security-jobs/{data['id']}")
        self.assertEqual(fetched.json()["scope_snapshot"], scopes_before)
        run = await self.client.post(f"/projects/{project_id}/security-jobs/{data['id']}/run")
        self.assertEqual(run.status_code, 409)
        self.assertIn("registered recon tool", run.json()["detail"])

    async def test_authorized_recon_persists_results_evidence_and_audits(self):
        project_id, profile, module = await self.create_workspace()
        modules = (await self.client.get("/assessment-modules")).json()
        curl_module = next(row for row in modules
                          if row["domain_key"] == "web" and row["category_key"] == "discovery")
        tools = (await self.client.get("/tools")).json()
        tool = next(row for row in tools if row["key"] == "curl_head")
        created = await self.create_job(project_id, profile, curl_module, tool_ids=[tool["id"]])
        self.assertEqual(created.json()["status"], "pending_approval")
        job_id = created.json()["id"]
        approved = await self.client.post(
            f"/projects/{project_id}/security-jobs/{job_id}/approve",
            json={"approved_by": "reviewer"},
        )
        self.assertEqual(approved.json()["status"], "approved")
        fake_process = recon_execution.ProcessResult(
            "HTTP/1.1 200 OK\r\nServer: test-server\r\n\nBBWB_STATUS:200\n", "", 0,
            datetime.now(timezone.utc), datetime.now(timezone.utc), "completed",
        )
        with patch("app.services.tool_adapters.CurlHeadAdapter.check_availability", return_value=(True, "test fake")), \
             patch("app.services.recon_execution.run_process", new=AsyncMock(return_value=fake_process)):
            started = await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/run")
            self.assertEqual(started.status_code, 200, started.text)
            for _ in range(20):
                status_response = await self.client.get(f"/projects/{project_id}/security-jobs/{job_id}")
                if status_response.json()["status"] not in {"queued", "running"}:
                    break
                await asyncio.sleep(0.01)
            execution = await self.client.get(
                f"/projects/{project_id}/security-jobs/{job_id}/execution")
        self.assertEqual(status_response.json()["status"], "completed")
        self.assertEqual(execution.status_code, 200)
        self.assertTrue(any(r["result_type"] == "endpoint" and r["normalized_data"]["http_status"] == 200
                            for r in execution.json()["results"]))
        self.assertTrue(execution.json()["evidence"])
        self.assertIn("HTTP/1.1", execution.json()["evidence"][0]["output"])
        audit = (await self.client.get(f"/projects/{project_id}/security-audit")).json()
        actions = {row["action"] for row in audit}
        self.assertTrue({"authorization_checked", "execution_started", "execution_completed"} <= actions)

    async def test_out_of_scope_and_exclusion_are_blocked(self):
        project_id, profile, module = await self.create_workspace(excluded="private.example.test")
        out_of_scope = await self.create_job(project_id, profile, module, "outside.invalid")
        excluded = await self.create_job(project_id, profile, module, "private.example.test")
        self.assertEqual(out_of_scope.json()["status"], "blocked")
        self.assertEqual(excluded.json()["status"], "blocked")
        self.assertIn("scope", excluded.json()["error"].lower())
        audit = (await self.client.get(f"/projects/{project_id}/security-audit")).json()
        self.assertIn("scope_validation_failure", {row["action"] for row in audit})
        self.assertIn("authorization_checked", {row["action"] for row in audit})

    async def test_missing_project_and_profile_are_rejected(self):
        missing_project = await self.client.post("/projects/999999/security-jobs", json={
            "profile_id": 1, "target": "example.test", "module_ids": [1],
        })
        self.assertEqual(missing_project.status_code, 404)
        project_id, _, module = await self.create_workspace()
        missing_profile = await self.client.post(f"/projects/{project_id}/security-jobs", json={
            "profile_id": 999999, "target": "example.test", "module_ids": [module["id"]],
        })
        self.assertEqual(missing_profile.status_code, 404)

    async def test_disabled_profile_module_and_tool_block_jobs(self):
        project_id, profile, module = await self.create_workspace()
        tool = (await self.client.get("/tools")).json()[0]
        async def toggle(model, item_id, enabled):
            async with AsyncSessionLocal() as db:
                row = await db.get(model, item_id)
                row.enabled = enabled
                await db.commit()

        async def submit(tool_ids=None):
            return await self.client.post(f"/projects/{project_id}/security-jobs", json={
                "profile_id": profile["id"], "target": "example.test",
                "module_ids": [module["id"]], "tool_ids": tool_ids or [],
            })

        try:
            await toggle(ScanProfile, profile["id"], False)
            self.assertEqual((await submit()).json()["status"], "blocked")
            await toggle(ScanProfile, profile["id"], True)
            await toggle(TestModule, module["id"], False)
            self.assertEqual((await submit()).json()["status"], "blocked")
            await toggle(TestModule, module["id"], True)
            await toggle(Tool, tool["id"], False)
            self.assertEqual((await submit([tool["id"]])).json()["status"], "blocked")
        finally:
            await toggle(ScanProfile, profile["id"], True)
            await toggle(TestModule, module["id"], True)
            await toggle(Tool, tool["id"], True)

    async def test_unavailable_adapter_is_blocked_and_audited(self):
        project_id, profile, module = await self.create_workspace()
        tools = (await self.client.get("/tools")).json()
        tool = next(row for row in tools if row["key"] == "curl_head")
        modules = (await self.client.get("/assessment-modules")).json()
        module = next(row for row in modules
                      if row["domain_key"] == "web" and row["category_key"] == "discovery")
        with patch("app.services.tool_adapters.CurlHeadAdapter.check_availability",
                   return_value=(False, "curl.exe missing in test")):
            created = await self.create_job(project_id, profile, module, tool_ids=[tool["id"]])
        self.assertEqual(created.json()["status"], "blocked")
        self.assertIn("unavailable", created.json()["error"])
        audit = (await self.client.get(f"/projects/{project_id}/security-audit")).json()
        self.assertIn("job_blocked", {row["action"] for row in audit})
        self.assertIn("adapter_availability_checked", {row["action"] for row in audit})

    async def test_tool_must_match_the_selected_assessment_module(self):
        project_id, profile, module = await self.create_workspace()
        tools = (await self.client.get("/tools")).json()
        curl_tool = next(row for row in tools if row["key"] == "curl_head")
        created = await self.create_job(project_id, profile, module, tool_ids=[curl_tool["id"]])
        self.assertEqual(created.json()["status"], "blocked")
        self.assertIn("does not support", created.json()["error"])

    async def test_running_job_can_be_cancelled(self):
        project_id, profile, module = await self.create_workspace()
        tools = (await self.client.get("/tools")).json()
        tool = next(row for row in tools if row["key"] == "curl_head")
        modules = (await self.client.get("/assessment-modules")).json()
        module = next(row for row in modules
                      if row["domain_key"] == "web" and row["category_key"] == "discovery")
        created = await self.create_job(project_id, profile, module, tool_ids=[tool["id"]])
        job_id = created.json()["id"]
        await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/approve",
                               json={"approved_by": "reviewer"})

        async def wait_forever(*_):
            await asyncio.sleep(30)

        with patch("app.services.tool_adapters.CurlHeadAdapter.check_availability",
                   return_value=(True, "test fake")), \
             patch("app.services.recon_execution.run_process", new=wait_forever):
            await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/run")
            cancelled = await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/cancel")
        self.assertEqual(cancelled.status_code, 200, cancelled.text)
        self.assertEqual(cancelled.json()["status"], "cancelled")
        audit = (await self.client.get(f"/projects/{project_id}/security-audit")).json()
        self.assertIn("execution_cancelled", {row["action"] for row in audit})

    async def test_results_evidence_and_audit_are_persisted_without_secret_logs(self):
        project_id, profile, module = await self.create_workspace()
        created = await self.create_job(project_id, profile, module)
        approved = await self.client.post(f"/projects/{project_id}/security-jobs/{created.json()['id']}/approve",
                                          json={"approved_by": "reviewer"})
        job = approved.json()
        result = await self.client.post(f"/projects/{project_id}/security-results", json={
            "job_id": job["id"], "module_id": module["id"], "target": "example.test",
            "result_type": "generic", "title": "Normalized metadata",
            "normalized_data": {"api_key": "do-not-log-this"},
        })
        self.assertEqual(result.status_code, 201, result.text)
        listed_results = await self.client.get(f"/projects/{project_id}/security-results")
        self.assertEqual(listed_results.status_code, 200)
        self.assertEqual(listed_results.json()[0]["id"], result.json()["id"])
        result_detail = await self.client.get(
            f"/projects/{project_id}/security-results/{result.json()['id']}"
        )
        self.assertEqual(result_detail.status_code, 200)
        evidence = await self.client.post(f"/projects/{project_id}/evidence", json={
            "result_id": result.json()["id"], "evidence_type": "json", "title": "Local evidence",
            "metadata": {"token": "private-value"},
        })
        self.assertEqual(evidence.status_code, 201, evidence.text)
        evidence_list = await self.client.get(f"/projects/{project_id}/evidence")
        self.assertEqual(evidence_list.status_code, 200)
        audit = await self.client.get(f"/projects/{project_id}/security-audit")
        self.assertEqual(audit.status_code, 200)
        serialized = audit.text
        self.assertNotIn("do-not-log-this", serialized)
        self.assertNotIn("private-value", serialized)
        self.assertIn("job_approved", serialized)
        self.assertIn("result_imported", serialized)
        self.assertIn("evidence_created", serialized)

    async def test_derived_targets_are_checked_independently(self):
        project_id, profile, module = await self.create_workspace()
        created = await self.create_job(project_id, profile, module)
        response = await self.client.post(
            f"/projects/{project_id}/security-jobs/{created.json()['id']}/derived-target-check",
            json={"target": "api.example.test"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["allowed"])
        denied = await self.client.post(
            f"/projects/{project_id}/security-jobs/{created.json()['id']}/derived-target-check",
            json={"target": "outside.invalid"},
        )
        self.assertFalse(denied.json()["allowed"])

    async def test_arbitrary_shell_parameters_are_rejected(self):
        project_id, profile, module = await self.create_workspace()
        response = await self.client.post(f"/projects/{project_id}/security-jobs", json={
            "profile_id": profile["id"], "target": "example.test", "module_ids": [module["id"]],
            "parameters": {"nested": {"shell_command": "unsafe"}},
        })
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
