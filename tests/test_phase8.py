import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from test_phase1 import api_client

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.services.web_surface_inspection import (
    DISCOVERY_PATHS, MAX_REDIRECTS, MAX_RESPONSE_BYTES,
    WebSurfaceInspectionService, _fingerprints,
)
from app.services.tool_adapters import WebSurfaceAdapter
from app.services.recon_execution import parse_output
from app.models.security_job import SecurityJob
from app.models.security_result import SecurityResult
from app.core.database import AsyncSessionLocal


def _response(status=200, headers=(), body=b""):
    merged = list(headers)
    if not any(key.lower() == "content-length" for key, _ in merged):
        merged.append(("Content-Length", str(len(body))))
    wire = f"HTTP/1.1 {status} Test\r\n".encode()
    wire += b"".join(f"{key}: {value}\r\n".encode() for key, value in merged)
    return wire + b"\r\n" + body


class _Writer:
    def __init__(self):
        self.request = b""
        self.closed = False

    def write(self, value):
        self.request += value

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class WebSurfaceInspectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_five_fixed_paths_are_sequentially_authorized_and_fingerprinted(self):
        writers = []
        response = _response(200, [
            ("Content-Type", "text/html; charset=utf-8"), ("Server", "nginx/1.25"),
            ("Set-Cookie", "PHPSESSID=secret-cookie-value; Path=/"),
        ], b'<meta name="generator" content="WordPress 6"><script src="/wp-content/site.js"></script>')

        async def open_connection(host, port, **kwargs):
            self.assertEqual(host, "example.test")
            reader = asyncio.StreamReader()
            reader.feed_data(response)
            reader.feed_eof()
            writer = _Writer()
            writers.append(writer)
            return reader, writer

        authorizations = []

        async def authorize(host, url):
            authorizations.append((host, url))
            return True, "included scope"

        with patch("app.services.web_surface_inspection.asyncio.open_connection", new=open_connection):
            result = await WebSurfaceInspectionService().inspect("example.test", 2, authorize)

        self.assertEqual(len(writers), len(DISCOVERY_PATHS))
        self.assertEqual(len(authorizations), len(DISCOVERY_PATHS))
        self.assertTrue(all(writer.request.startswith(b"GET ") for writer in writers))
        self.assertEqual([urlsplit_path(item[1]) for item in authorizations], list(DISCOVERY_PATHS))
        self.assertEqual(len(result["endpoints"]), 5)
        found = {item["technology"]: item for item in result["technologies"]}
        self.assertIn("nginx", found)
        self.assertIn("WordPress", found)
        self.assertIn("PHP", found)
        self.assertTrue(all(item["evidence"] for item in found.values()))
        self.assertEqual(found["WordPress"]["confidence"], "high")
        self.assertNotIn(b"secret-cookie-value", json.dumps(result).encode())

    async def test_response_body_is_capped_and_truncation_is_reported(self):
        body = b"x" * (MAX_RESPONSE_BYTES + 100)
        response = _response(200, [("Content-Type", "text/html"),
                                   ("Content-Length", str(len(body)))], body)

        async def open_connection(*args, **kwargs):
            reader = asyncio.StreamReader()
            reader.feed_data(response)
            reader.feed_eof()
            return reader, _Writer()

        async def authorize(*args):
            return True, "authorized"

        with patch("app.services.web_surface_inspection.asyncio.open_connection", new=open_connection):
            result = await WebSurfaceInspectionService().inspect("https://example.test", 2, authorize)
        self.assertEqual(result["endpoints"][0]["response_bytes"], MAX_RESPONSE_BYTES)
        self.assertTrue(result["endpoints"][0]["truncated"])

    async def test_timeout_is_normalized_for_each_fixed_path(self):
        async def timeout(*args, **kwargs):
            await asyncio.Future()

        with patch("app.services.web_surface_inspection.asyncio.open_connection", new=timeout):
            result = await WebSurfaceInspectionService().inspect(
                "example.test", 1, AsyncMock(return_value=(True, "authorized")))
        self.assertEqual(len(result["endpoints"]), len(DISCOVERY_PATHS))
        self.assertTrue(all(item.get("error") == "HTTP request timed out."
                            for item in result["endpoints"]))

    async def test_external_redirect_is_blocked_before_another_request(self):
        opened = []

        async def open_connection(host, port, **kwargs):
            opened.append((host, port))
            payload = (_response(302, [("Location", "https://outside.test/private")])
                       if len(opened) == 1 else _response(404))
            reader = asyncio.StreamReader()
            reader.feed_data(payload)
            reader.feed_eof()
            return reader, _Writer()

        with patch("app.services.web_surface_inspection.asyncio.open_connection", new=open_connection):
            result = await WebSurfaceInspectionService().inspect(
                "example.test", 2, AsyncMock(return_value=(True, "authorized")))
        self.assertTrue(all(host == "example.test" for host, _ in opened))
        self.assertEqual(len(opened), len(DISCOVERY_PATHS))
        blocked = [event for event in result["events"] if event["event"] == "redirect_blocked"]
        self.assertEqual(blocked[0]["to_host"], "outside.test")
        blocked_rows = [item for item in result["endpoints"] if item.get("error")]
        self.assertTrue(any("left the selected authorized host" in item["error"]
                            for item in blocked_rows), repr(result["endpoints"]))

    async def test_same_host_redirect_limit_and_fixed_request_ceiling(self):
        requests = []

        async def open_connection(host, port, **kwargs):
            requests.append(host)
            reader = asyncio.StreamReader()
            reader.feed_data(_response(302, [("Location", "/again")]))
            reader.feed_eof()
            return reader, _Writer()

        with patch("app.services.web_surface_inspection.asyncio.open_connection", new=open_connection):
            result = await WebSurfaceInspectionService().inspect(
                "example.test", 2, AsyncMock(return_value=(True, "authorized")))
        self.assertEqual(len(requests), len(DISCOVERY_PATHS) * (MAX_REDIRECTS + 1))
        self.assertLessEqual(len(requests), 15)
        self.assertTrue(any("Redirect limit reached" in item.get("error", "")
                            for item in result["endpoints"]))

    async def test_fingerprinting_requires_observable_evidence(self):
        found = _fingerprints("https://example.test/", "example.test", {},
                              b"<html><body>ordinary page</body></html>")
        self.assertEqual(found, [])

    async def test_rejected_authorization_makes_no_network_request(self):
        async def forbidden_connection(*args, **kwargs):
            self.fail("network connection must not occur after authorization rejection")

        with patch("app.services.web_surface_inspection.asyncio.open_connection",
                   new=forbidden_connection):
            result = await WebSurfaceInspectionService().inspect(
                "example.test", 1, AsyncMock(return_value=(False, "excluded by scope")))
        self.assertEqual(result["endpoints"][0]["error"],
                         "Request blocked by current scope authorization: excluded by scope")

    def test_adapter_and_result_parser_are_fixed_host_and_structured(self):
        adapter = WebSurfaceAdapter()
        self.assertTrue(adapter_registry_available(adapter))
        self.assertEqual(adapter.build_execution_plan("example.test", {}).metadata["fixed_paths"], True)
        with self.assertRaises(ValueError):
            adapter.build_execution_plan("https://example.test", {"timeout": 9})
        output = json.dumps({"hostname": "example.test", "endpoints": [{
            "hostname": "example.test", "url": "https://example.test/robots.txt",
            "http_status": 200, "response_bytes": 0}], "technologies": [{
                "hostname": "example.test", "technology": "nginx", "confidence": "high",
                "evidence": ["Server header identified nginx."],
                "endpoint_url": "https://example.test/"}], "events": [{
                    "event": "redirect_blocked", "to_host": "outside.test",
                    "reason": "different_host"}]})
        results = parse_output("web_surface_discovery", "example.test", output)
        self.assertEqual({row["result_type"] for row in results}, {"endpoint", "technology", "configuration"})
        self.assertEqual(parse_output("web_surface_discovery", "other.test", output), [])


def urlsplit_path(value):
    from urllib.parse import urlsplit
    return urlsplit(value).path


def adapter_registry_available(adapter):
    from app.services.tool_adapters import adapter_registry
    registered = adapter_registry.get_for_tool("web_surface_discovery")
    return isinstance(registered, WebSurfaceAdapter) and isinstance(adapter, WebSurfaceAdapter)


class WebSurfaceApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.context = api_client()
        self.client = await self.context.__aenter__()

    async def asyncTearDown(self):
        await self.context.__aexit__(None, None, None)

    async def _workspace(self):
        project = await self.client.post("/projects", json={"name": f"Web surface {uuid4()}"})
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
                    if row["key"] == "web_surface_discovery")
        return project_id, asset.json()["id"], profile, module, tool

    async def test_asset_scope_approval_execution_results_evidence_and_audit(self):
        project_id, asset_id, profile, module, tool = await self._workspace()
        status = await self.client.get("/tools/web-surface/status")
        self.assertTrue(status.json()["available"])
        self.assertEqual(len(status.json()["paths"]), 5)
        body = {"hostname": "example.test", "endpoints": [{
            "hostname": "example.test", "url": "https://example.test/",
            "final_url": "https://example.test/", "http_status": 200,
            "content_type": "text/html", "content_length": 42, "response_bytes": 42,
            "truncated": False, "server": "nginx", "powered_by": None,
            "security_headers": {}, "cookie_names": [], "redirect_chain": [],
            "duration_ms": 12}], "technologies": [{
                "hostname": "example.test", "technology": "nginx", "confidence": "high",
                "evidence": ["Server header identified nginx."],
                "endpoint_url": "https://example.test/"}], "events": [{
                    "event": "fingerprint_detected", "technology": "nginx",
                    "confidence": "high", "evidence_count": 1}]}
        async def fake_inspect(_adapter, target, timeout, authorize):
            self.assertEqual(target, "https://example.test/")
            self.assertEqual(timeout, 5)
            for endpoint in body["endpoints"]:
                allowed, reason = await authorize("example.test", endpoint["url"])
                self.assertTrue(allowed, reason)
            return body

        payload = {"profile_id": profile["id"], "target": "example.test",
                   "asset_id": asset_id, "module_ids": [module["id"]],
                   "tool_ids": [tool["id"]], "parameters": {"timeout": 5}}
        created = await self.client.post(f"/projects/{project_id}/security-jobs", json=payload)
        self.assertEqual(created.status_code, 201, created.text)
        job_id = created.json()["id"]
        self.assertEqual(created.json()["status"], "pending_approval")
        with patch.object(WebSurfaceAdapter, "inspect", new=AsyncMock(side_effect=PermissionError("must not run"))) as blocked:
            before_approval = await self.client.post(
                f"/projects/{project_id}/security-jobs/{job_id}/run")
            self.assertEqual(before_approval.status_code, 409)
            blocked.assert_not_awaited()
        approved = await self.client.post(
            f"/projects/{project_id}/security-jobs/{job_id}/approve", json={"approved_by": "reviewer"})
        self.assertEqual(approved.json()["status"], "approved")
        with patch.object(WebSurfaceAdapter, "inspect", new=fake_inspect):
            started = await self.client.post(f"/projects/{project_id}/security-jobs/{job_id}/run")
            self.assertEqual(started.status_code, 200)
            for _ in range(50):
                execution = await self.client.get(
                    f"/projects/{project_id}/security-jobs/{job_id}/execution")
                if execution.json()["status"] not in {"queued", "running"}:
                    break
                await asyncio.sleep(.02)
        result_rows = execution.json()["results"]
        self.assertEqual({item["result_type"] for item in result_rows}, {"endpoint", "technology"},
                         repr(execution.json()))
        technology = next(item for item in result_rows if item["result_type"] == "technology")
        self.assertEqual(technology["normalized_data"]["asset_id"], asset_id)
        self.assertEqual(technology["normalized_data"]["evidence"], ["Server header identified nginx."])
        self.assertTrue(execution.json()["evidence"])
        filtered = await self.client.get(
            f"/projects/{project_id}/security-results?job_id={job_id}&asset_id={asset_id}")
        self.assertEqual(len(filtered.json()), 2)
        audit_actions = {row["action"] for row in
                         (await self.client.get(f"/projects/{project_id}/security-audit")).json()}
        self.assertTrue({"web_surface_discovery_requested", "web_surface_authorization_accepted",
                         "web_surface_approval_accepted", "web_surface_execution_started",
                         "web_surface_endpoint_requested", "web_surface_fingerprint_detected",
                         "web_surface_results_processed", "web_surface_execution_completed"}
                        <= audit_actions)
        job = await self.client.get(f"/projects/{project_id}/security-jobs/{job_id}")
        self.assertEqual(job.json()["status"], "completed")
        self.assertIsNotNone(job.json()["started_at"])
        self.assertIsNotNone(job.json()["completed_at"])

    async def test_missing_or_wrong_project_asset_is_blocked(self):
        project_id, asset_id, profile, module, tool = await self._workspace()
        payload = {"profile_id": profile["id"], "target": "example.test",
                   "module_ids": [module["id"]], "tool_ids": [tool["id"]]}
        no_asset = await self.client.post(f"/projects/{project_id}/security-jobs", json=payload)
        self.assertEqual(no_asset.json()["status"], "blocked")
        self.assertIn("existing asset", no_asset.json()["error"])
        other = await self.client.post("/projects", json={"name": f"Other {uuid4()}"})
        payload["asset_id"] = asset_id
        wrong_project = await self.client.post(
            f"/projects/{other.json()['id']}/security-jobs", json=payload)
        self.assertEqual(wrong_project.json()["status"], "blocked")

        payload["target"] = "outside.test"
        mismatch = await self.client.post(
            f"/projects/{project_id}/security-jobs", json=payload)
        self.assertEqual(mismatch.json()["status"], "blocked")

        await self.client.post(f"/projects/{project_id}/scopes", json={
            "value": "example.test", "scope_type": "domain", "included": False})
        payload["target"] = "example.test"
        payload["asset_id"] = asset_id
        out_of_scope = await self.client.post(
            f"/projects/{project_id}/security-jobs", json=payload)
        self.assertEqual(out_of_scope.json()["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
