import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from test_phase1 import api_client

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.services.recon_execution import parse_output, _parse_subfinder_output
from app.services.tool_adapters import TcpServiceAwarenessAdapter, WebSurfaceAdapter
from app.services.web_surface_inspection import EXTENDED_DISCOVERY_PATHS


class TcpServiceAwarenessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.adapter = TcpServiceAwarenessAdapter()

    def test_only_authorized_ip_shape_and_fixed_ports_are_accepted(self):
        self.assertEqual(self.adapter.build_execution_plan("192.0.2.10", {}).metadata["ports"],
                         list(self.adapter.ALLOWED_PORTS))
        with self.assertRaises(ValueError):
            self.adapter.build_execution_plan("example.test", {})
        with self.assertRaises(ValueError):
            self.adapter.build_execution_plan("192.0.2.10", {"ports": [1]})
        with self.assertRaises(ValueError):
            self.adapter.build_execution_plan("192.0.2.10", {"ports": list(range(1, 8))})

    async def test_each_port_is_reauthorized_and_connection_timeouts_are_bounded(self):
        class Writer:
            def close(self): pass
            async def wait_closed(self): pass

        calls = []
        async def connect(host, port):
            calls.append((host, port))
            if port == 80:
                return None, Writer()
            raise ConnectionRefusedError()
        authorized = []
        async def authorize(host, port):
            authorized.append((host, port))
            return port != 443

        with patch("app.services.tool_adapters.asyncio.open_connection", new=connect):
            result = await self.adapter.inspect("192.0.2.10", 1, [80, 443], authorize)
        self.assertEqual(calls, [("192.0.2.10", 80)])
        self.assertEqual(authorized, [("192.0.2.10", 80), ("192.0.2.10", 443)])
        self.assertEqual([item["state"] for item in result["observations"]], ["reachable", "blocked"])


class BoundedEndpointDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_path_limit_selects_only_fixed_candidate_paths(self):
        requested = []
        async def request(url, timeout):
            requested.append(url)
            return {"status": 404, "headers": {}, "body": b"", "content_length": 0,
                    "truncated": False, "response_bytes": 0, "duration_ms": 1}
        async def authorize(_host, _url):
            return True, "authorized"

        with patch("app.services.web_surface_inspection._single_request", new=request):
            result = await WebSurfaceAdapter().inspect("https://192.0.2.8", 1, authorize, max_paths=7)
        self.assertEqual(len(requested), 7)
        self.assertEqual([item["url"].removeprefix("https://192.0.2.8") for item in result["endpoints"]],
                         list(EXTENDED_DISCOVERY_PATHS[:7]))
        with self.assertRaises(ValueError):
            await WebSurfaceAdapter().inspect("https://192.0.2.8", 1, authorize, max_paths=13)

    def test_service_result_parser_and_subdomain_result_cap(self):
        parsed = parse_output("tcp_service_awareness", "192.0.2.10",
            '{"target":"192.0.2.10","observations":[{"host":"192.0.2.10","port":443,"state":"reachable"}]}')
        self.assertEqual(parsed[0]["result_type"], "service")
        output = "\n".join(f"host{i}.example.test" for i in range(5))
        candidates, malformed = _parse_subfinder_output(output, "subfinder", max_results=2)
        self.assertEqual(len(candidates), 2)
        self.assertEqual(malformed, [])


class Phase13JobAuthorizationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._context = api_client()
        self.client = await self._context.__aenter__()

    async def asyncTearDown(self):
        await self._context.__aexit__(None, None, None)

    async def test_tcp_job_uses_existing_asset_approval_and_current_scope(self):
        project = await self.client.post("/projects", json={"name": f"Phase13 {uuid4()}"})
        project_id = project.json()["id"]
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "192.0.2.10", "scope_type": "ip", "included": True})
        asset = await self.client.post(f"/projects/{project_id}/assets", json={
            "value": "192.0.2.10", "asset_type": "ip", "source": "fixture"})
        self.assertEqual(asset.status_code, 201)
        profiles = (await self.client.get("/scan-profiles")).json()
        profile = next(item for item in profiles if item["key"] == "network_discovery")
        module = next(item for item in (await self.client.get("/assessment-modules")).json()
                      if item["key"] == "network_service_identification_review")
        tool = next(item for item in (await self.client.get("/tools")).json()
                    if item["key"] == "tcp_service_awareness")
        response = await self.client.post(f"/projects/{project_id}/security-jobs", json={
            "profile_id": profile["id"], "target": "192.0.2.10", "asset_id": asset.json()["id"],
            "module_ids": [module["id"]], "tool_ids": [tool["id"]],
            "requested_by": "phase13-test", "parameters": {"timeout": 2, "ports": [80]}})
        self.assertEqual(response.status_code, 201, response.text)
        job = response.json()
        self.assertEqual(job["status"], "pending_approval")
        self.assertEqual((await self.client.post(
            f"/projects/{project_id}/security-jobs/{job['id']}/run")).status_code, 409)
        approved = await self.client.post(
            f"/projects/{project_id}/security-jobs/{job['id']}/approve",
            json={"approved_by": "reviewer"})
        self.assertEqual(approved.json()["status"], "approved")
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "192.0.2.10", "scope_type": "ip", "included": False})
        blocked = await self.client.post(f"/projects/{project_id}/security-jobs/{job['id']}/run")
        self.assertEqual(blocked.status_code, 403)

    async def test_correlation_is_project_scoped_and_deterministic(self):
        missing = await self.client.get("/projects/999999/recon/correlation")
        self.assertEqual(missing.status_code, 404)
        project = await self.client.post("/projects", json={"name": f"Correlation {uuid4()}"})
        project_id = project.json()["id"]
        first = await self.client.get(f"/projects/{project_id}/recon/correlation")
        second = await self.client.get(f"/projects/{project_id}/recon/correlation")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), second.json())
        self.assertEqual(first.json()["groups"], [])

    async def test_approved_service_job_persists_result_evidence_and_audit(self):
        project = await self.client.post("/projects", json={"name": f"Service {uuid4()}"})
        project_id = project.json()["id"]
        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "192.0.2.11", "scope_type": "ip", "included": True})
        asset = await self.client.post(f"/projects/{project_id}/assets", json={
            "value": "192.0.2.11", "asset_type": "ip", "source": "fixture"})
        profile = next(item for item in (await self.client.get("/scan-profiles")).json()
                       if item["key"] == "network_discovery")
        module = next(item for item in (await self.client.get("/assessment-modules")).json()
                      if item["key"] == "network_service_identification_review")
        tool = next(item for item in (await self.client.get("/tools")).json()
                    if item["key"] == "tcp_service_awareness")
        created = await self.client.post(f"/projects/{project_id}/security-jobs", json={
            "profile_id": profile["id"], "target": "192.0.2.11", "asset_id": asset.json()["id"],
            "module_ids": [module["id"]], "tool_ids": [tool["id"]], "requested_by": "fixture",
            "parameters": {"timeout": 2, "ports": [443]}})
        job_id = created.json()["id"]
        await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/approve",
                               json={"approved_by": "reviewer"})
        fake = {"target": "192.0.2.11", "observations": [{"host": "192.0.2.11",
            "port": 443, "protocol": "tcp", "state": "reachable", "service": "https",
            "duration_ms": 1, "error_class": None}]}
        async def inspect_with_authorization(target, timeout, ports, authorize):
            for port in ports:
                if not await authorize(target, port):
                    return {"target": target, "observations": []}
            return fake
        with patch("app.services.tool_adapters.TcpServiceAwarenessAdapter.inspect",
                   new=AsyncMock(side_effect=inspect_with_authorization)):
            started = await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/run")
            self.assertEqual(started.status_code, 200)
            execution = None
            for _ in range(100):
                execution = await self.client.get(
                    f"/projects/{project_id}/security-jobs/{job_id}/execution")
                if execution.json()["status"] in {"completed", "failed"}:
                    break
                await asyncio.sleep(0.01)
        self.assertEqual(execution.json()["status"], "completed", execution.text)
        self.assertEqual(execution.json()["results"][0]["result_type"], "service")
        self.assertTrue(execution.json()["evidence"])
        correlation = (await self.client.get(f"/projects/{project_id}/recon/correlation")).json()
        group = next(row for row in correlation["groups"] if row["hostname"] == "192.0.2.11")
        self.assertEqual(group["observations"][0]["result_type"], "service")
        self.assertTrue(group["observations"][0]["evidence_ids"])
        self.assertEqual(group["scopes"][0]["value"], "192.0.2.11")
        audit = (await self.client.get(f"/projects/{project_id}/security-audit")).json()
        self.assertIn("service_port_requested", {item["action"] for item in audit})
        self.assertIn("service_awareness_results_processed", {item["action"] for item in audit})


if __name__ == "__main__":
    unittest.main()
