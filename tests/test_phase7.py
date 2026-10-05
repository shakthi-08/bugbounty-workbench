import asyncio
import hashlib
import json
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from test_phase1 import DATABASE_PATH, api_client

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.services.recon_execution import parse_output
from app.services.tool_adapters import TlsInspectionAdapter, adapter_registry
from app.core.database import AsyncSessionLocal
from app.models.security_job import SecurityJob
from app.models.security_result import SecurityResult


class _SslObject:
    def getpeercert(self, binary_form=False):
        if binary_form:
            return b"bounded test certificate DER"
        return {
            "subject": ((('commonName', 'example.test'),),),
            "issuer": ((('organizationName', 'Test CA'),),),
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Jan  1 00:00:00 2027 GMT",
            "serialNumber": "01AB",
            "subjectAltName": (("DNS", "example.test"), ("DNS", "API.Example.test.")),
        }

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


class _Writer:
    def __init__(self):
        self.ssl_object = _SslObject()
        self.closed = False

    def get_extra_info(self, key):
        return self.ssl_object if key == "ssl_object" else ("192.0.2.4", 443)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class TlsAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_tls_certificate_metadata_and_validation_are_normalized(self):
        writer = _Writer()

        async def fake_open_connection(host, port, **kwargs):
            self.assertEqual((host, port), ("example.test", 443))
            self.assertEqual(kwargs["server_hostname"], "example.test")
            self.assertTrue(kwargs["ssl"].check_hostname)
            self.assertEqual(kwargs["ssl"].verify_mode, ssl.CERT_REQUIRED)
            return object(), writer

        with patch("app.services.tool_adapters.asyncio.open_connection", new=fake_open_connection):
            data = await TlsInspectionAdapter().inspect("EXAMPLE.TEST", 3)
        self.assertTrue(data["verification_status"])
        self.assertEqual(data["tls_version"], "TLSv1.3")
        self.assertEqual(data["cipher"], "TLS_AES_256_GCM_SHA384")
        self.assertEqual(data["subject"]["commonName"], ["example.test"])
        self.assertEqual(data["issuer"]["organizationName"], ["Test CA"])
        self.assertEqual(data["valid_until"], "Jan  1 00:00:00 2027 GMT")
        self.assertEqual(data["sans"], ["api.example.test", "example.test"])
        self.assertEqual(data["resolved_endpoint"], "192.0.2.4")
        self.assertEqual(data["serial_number"], "01AB")
        self.assertEqual(data["fingerprint_sha256"], hashlib.sha256(b"bounded test certificate DER").hexdigest())
        self.assertEqual(data["hostname_verification"], "passed")
        self.assertFalse(data["certificate_expired"])
        self.assertFalse(data["certificate_not_yet_valid"])
        self.assertTrue(writer.closed)

    async def test_certificate_verification_failure_is_not_retried_unverified(self):
        fail = AsyncMock(side_effect=ssl.SSLCertVerificationError(1, "certificate verify failed"))
        with patch("app.services.tool_adapters.asyncio.open_connection", new=fail):
            data = await TlsInspectionAdapter().inspect("example.test", 2)
        self.assertFalse(data["verification_status"])
        self.assertIn("Certificate verification failed", data["connection_error"])
        fail.assert_awaited_once()

    async def test_timeout_connection_failure_and_cancellation_are_bounded(self):
        async def timeout(*args, **kwargs):
            raise asyncio.TimeoutError

        with patch("app.services.tool_adapters.asyncio.open_connection", new=timeout):
            result = await TlsInspectionAdapter().inspect("example.test", 1)
        self.assertEqual(result["connection_error"], "TLS connection timed out.")

        async def failure(*args, **kwargs):
            raise OSError("connection refused")

        with patch("app.services.tool_adapters.asyncio.open_connection", new=failure):
            result = await TlsInspectionAdapter().inspect("example.test", 1)
        self.assertIn("connection refused", result["connection_error"])

        async def wait(*args, **kwargs):
            await asyncio.Event().wait()

        with patch("app.services.tool_adapters.asyncio.open_connection", new=wait):
            task = asyncio.create_task(TlsInspectionAdapter().inspect("example.test", 5))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

    def test_target_is_fixed_to_hostname_443_and_metadata_parser_rejects_malformed(self):
        adapter = TlsInspectionAdapter()
        with self.assertRaises(ValueError):
            adapter.build_execution_plan("example.test:8443", {"timeout": 3})
        with self.assertRaises(ValueError):
            adapter.build_execution_plan("https://example.test", {"timeout": 3})
        plan = adapter.build_execution_plan("example.test", {"timeout": 3})
        self.assertEqual(plan.metadata["port"], 443)
        self.assertEqual(plan.executable, "builtin:python-ssl")
        self.assertEqual(parse_output("tls_inspector", "example.test", "not json"), [])
        parsed = parse_output("tls_inspector", "example.test", '{"hostname":"example.test","sans":[]}')
        self.assertEqual(parsed[0]["result_type"], "certificate")
        self.assertEqual(parse_output("tls_inspector", "evil-example.test",
                                      '{"hostname":"example.test"}'), [])

    def test_tls_adapter_is_registered_available_and_evidence_hash_is_sha256(self):
        adapter = adapter_registry.get_for_tool("tls_inspector")
        self.assertIsInstance(adapter, TlsInspectionAdapter)
        self.assertEqual(adapter_registry.check_tool("tls_inspector", "builtin:python-ssl")[0], True)
        raw = b'{"hostname":"example.test","verification_status":true}'
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "e22b0868a044f2c305e2fac29f5c912e417cc43f2d9e3e584c2da8a5daa314b9")


class TlsApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.context = api_client()
        self.client = await self.context.__aenter__()

    async def asyncTearDown(self):
        await self.context.__aexit__(None, None, None)

    async def test_status_scope_approval_execution_results_evidence_and_audit(self):
        project = await self.client.post("/projects", json={"name": f"TLS {uuid4()}"})
        project_id = project.json()["id"]
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "example.test", "scope_type": "domain", "included": True})
        asset = await self.client.post(f"/projects/{project_id}/assets", json={
            "value": "example.test", "asset_type": "domain", "source": "user_selected"})
        profile = next(row for row in (await self.client.get("/scan-profiles")).json()
                       if row["key"] == "web_baseline")
        module = next(row for row in (await self.client.get("/assessment-modules")).json()
                      if row["key"] == "web_discovery_review")
        tool = next(row for row in (await self.client.get("/tools")).json()
                    if row["key"] == "tls_inspector")
        status = await self.client.get("/tools/tls/status")
        self.assertTrue(status.json()["available"])
        self.assertEqual(status.json()["port"], 443)
        create = await self.client.post(f"/projects/{project_id}/security-jobs", json={
            "profile_id": profile["id"], "target": "example.test",
            "asset_id": asset.json()["id"],
            "module_ids": [module["id"]], "tool_ids": [tool["id"]],
            "parameters": {"timeout": 2}})
        self.assertEqual(create.status_code, 201, create.text)
        job_id = create.json()["id"]
        self.assertEqual((await self.client.post(
            f"/projects/{project_id}/security-jobs/{job_id}/run")).status_code, 409)
        approved = await self.client.post(
            f"/projects/{project_id}/security-jobs/{job_id}/approve", json={"approved_by": "reviewer"})
        self.assertEqual(approved.json()["status"], "approved")
        metadata = {"hostname": "example.test", "port": 443, "verification_status": True,
                    "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                    "subject": {"commonName": ["example.test"]}, "issuer": {"commonName": ["Test CA"]},
                    "serial_number": None, "valid_from": "Jan  1 00:00:00 2025 GMT",
                    "valid_until": "Jan  1 00:00:00 2027 GMT", "sans": ["example.test"],
                    "resolved_endpoint": "192.0.2.4", "connection_error": None}
        with patch.object(TlsInspectionAdapter, "inspect", new=AsyncMock(return_value=metadata)):
            started = await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/run")
            self.assertEqual(started.status_code, 200)
            for _ in range(30):
                execution = await self.client.get(
                    f"/projects/{project_id}/security-jobs/{job_id}/execution")
                if execution.json()["status"] not in {"queued", "running"}:
                    break
                await asyncio.sleep(.05)
        payload = execution.json()
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["results"][0]["result_type"], "certificate")
        self.assertEqual(payload["results"][0]["normalized_data"]["tls_version"], "TLSv1.3")
        evidence = payload["evidence"][0]
        self.assertEqual(evidence["content_hash"], hashlib.sha256(evidence["output"].encode()).hexdigest())
        self.assertEqual(json.loads(evidence["output"])["verification_status"], True)
        audit = (await self.client.get(f"/projects/{project_id}/security-audit")).json()
        actions = {row["action"] for row in audit}
        self.assertTrue({"job_created", "authorization_checked", "job_approved",
                         "execution_started", "tls_inspection_requested",
                         "tls_authorization_accepted", "tls_approval_accepted",
                         "tls_execution_started", "tls_inspection_results_processed",
                         "tls_execution_completed", "execution_completed"} <= actions)

    async def test_tls_generic_job_requires_existing_project_asset(self):
        project = await self.client.post("/projects", json={"name": f"TLS asset {uuid4()}"})
        project_id = project.json()["id"]
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "example.test", "scope_type": "domain", "included": True})
        asset = await self.client.post(f"/projects/{project_id}/assets", json={
            "value": "example.test", "asset_type": "domain", "source": "user_selected"})
        profile = next(row for row in (await self.client.get("/scan-profiles")).json()
                       if row["key"] == "web_baseline")
        module = next(row for row in (await self.client.get("/assessment-modules")).json()
                      if row["key"] == "web_discovery_review")
        tool = next(row for row in (await self.client.get("/tools")).json()
                    if row["key"] == "tls_inspector")
        payload = {"profile_id": profile["id"], "target": "example.test",
                   "module_ids": [module["id"]], "tool_ids": [tool["id"]]}
        missing_asset = await self.client.post(f"/projects/{project_id}/security-jobs", json=payload)
        self.assertEqual(missing_asset.status_code, 201)
        self.assertEqual(missing_asset.json()["status"], "blocked")
        self.assertIn("existing asset", missing_asset.json()["error"])
        payload["asset_id"] = asset.json()["id"]
        accepted = await self.client.post(f"/projects/{project_id}/security-jobs", json=payload)
        self.assertEqual(accepted.json()["status"], "pending_approval")
        wrong_project = await self.client.post("/projects", json={"name": f"Other {uuid4()}"})
        rejected = await self.client.post(
            f"/projects/{wrong_project.json()['id']}/security-jobs", json=payload)
        self.assertEqual(rejected.status_code, 201)
        self.assertEqual(rejected.json()["status"], "blocked")

    async def test_out_of_scope_target_and_scope_change_block_tls(self):
        project = await self.client.post("/projects", json={"name": f"TLS scope {uuid4()}"})
        project_id = project.json()["id"]
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "example.test", "scope_type": "domain", "included": True})
        asset = await self.client.post(f"/projects/{project_id}/assets", json={
            "value": "example.test", "asset_type": "domain", "source": "user_selected"})
        profiles = (await self.client.get("/scan-profiles")).json()
        profile = next(row for row in profiles if row["key"] == "web_baseline")
        modules = (await self.client.get("/assessment-modules")).json()
        module = next(row for row in modules if row["key"] == "web_discovery_review")
        tool = next(row for row in (await self.client.get("/tools")).json()
                    if row["key"] == "tls_inspector")
        payload = {"profile_id": profile["id"], "target": "evil-example.test",
                   "asset_id": asset.json()["id"],
                   "module_ids": [module["id"]], "tool_ids": [tool["id"]]}
        denied = await self.client.post(f"/projects/{project_id}/security-jobs", json=payload)
        self.assertEqual(denied.status_code, 201)
        self.assertEqual(denied.json()["status"], "blocked")
        payload["target"] = "example.test"
        created = await self.client.post(f"/projects/{project_id}/security-jobs", json=payload)
        job_id = created.json()["id"]
        await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/approve",
                               json={"approved_by": "reviewer"})
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "example.test", "scope_type": "domain", "included": False})
        run = await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/run")
        self.assertEqual(run.status_code, 403)

    async def test_explicit_discovered_host_selection_creates_approval_gated_tls_job(self):
        project = await self.client.post("/projects", json={"name": f"TLS select {uuid4()}"})
        project_id = project.json()["id"]
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "example.test", "scope_type": "domain", "included": True})
        profile = next(row for row in (await self.client.get("/scan-profiles")).json()
                       if row["key"] == "web_baseline")
        module = next(row for row in (await self.client.get("/assessment-modules")).json()
                      if row["key"] == "web_discovery_review")
        source = await self.client.post(f"/projects/{project_id}/security-jobs", json={
            "profile_id": profile["id"], "target": "example.test", "module_ids": [module["id"]]})
        source_id = source.json()["id"]
        async with AsyncSessionLocal() as db:
            source_job = await db.get(SecurityJob, source_id)
            source_job.status = "completed"
            db.add(SecurityResult(project_id=project_id, job_id=source_id, target="example.test",
                                  result_type="subdomain", title="api.example.test",
                                  normalized_data={"hostname": "api.example.test",
                                                   "authorization_status": "authorized"}))
            await db.commit()
        selected = await self.client.post(
            f"/projects/{project_id}/security-jobs/{source_id}/inspect-tls-selected",
            json={"hostnames": ["API.Example.test."]})
        self.assertEqual(selected.status_code, 201, selected.text)
        self.assertEqual(len(selected.json()), 1)
        self.assertEqual(selected.json()[0]["target_snapshot"]["target"], "api.example.test")
        self.assertEqual(selected.json()[0]["status"], "pending_approval")
        self.assertEqual((await self.client.post(
            f"/projects/{project_id}/security-jobs/{selected.json()[0]['id']}/run")).status_code, 409)
        audit = (await self.client.get(f"/projects/{project_id}/security-audit")).json()
        self.assertIn("hosts_selected_for_tls_inspection", {row["action"] for row in audit})
