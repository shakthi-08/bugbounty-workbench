import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.services.recon_execution import MAX_OUTPUT_BYTES, parse_output, run_process
from app.services.tool_adapters import CurlHeadAdapter, ExecutionPlan, NslookupAdapter, SubfinderAdapter


class ReconProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_successful_process_captures_stdout_stderr_and_timestamps(self):
        plan = ExecutionPlan("test", sys.executable, ("-c", "import sys; print('ok'); print('note', file=sys.stderr)"), timeout=5)
        result = await run_process(plan, 801)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("ok", result.stdout)
        self.assertIn("note", result.stderr)
        self.assertLessEqual(result.started_at, result.ended_at)

    async def test_nonzero_process_is_a_failure(self):
        result = await run_process(
            ExecutionPlan("test", sys.executable, ("-c", "raise SystemExit(7)"), timeout=5), 802)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.exit_code, 7)

    async def test_process_timeout_kills_child_and_reports_timed_out(self):
        result = await run_process(
            ExecutionPlan("test", sys.executable, ("-c", "import time; time.sleep(2)"), timeout=0.1), 803)
        self.assertEqual(result.status, "timed_out")

    async def test_process_output_is_capped_while_pipe_is_drained(self):
        result = await run_process(
            ExecutionPlan("test", sys.executable,
                          ("-c", "print('x' * 2500000)"), timeout=5), 805)
        self.assertEqual(result.status, "completed")
        self.assertLessEqual(len(result.stdout.encode("utf-8")), MAX_OUTPUT_BYTES + 64)
        self.assertIn("output truncated", result.stdout)

    async def test_cancellation_kills_child_process(self):
        task = asyncio.create_task(run_process(
            ExecutionPlan("test", sys.executable, ("-c", "import time; time.sleep(5)"), timeout=10), 804))
        await asyncio.sleep(0.1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    def test_dns_and_http_output_are_normalized(self):
        dns = parse_output("windows_nslookup", "example.test", """Server: resolver
Address: 192.0.2.1
Name: example.test
Address: 198.51.100.2
""")
        self.assertEqual(dns[0]["result_type"], "dns_record")
        self.assertEqual(dns[0]["data"]["ip"], "198.51.100.2")
        http = parse_output("curl_head", "https://example.test", "HTTP/1.1 200 OK\r\nServer: nginx\r\nBBWB_STATUS:200")
        self.assertEqual(http[0]["result_type"], "endpoint")
        self.assertEqual(http[0]["data"]["http_status"], 200)
        self.assertEqual(http[1]["data"]["technology"], "nginx")

    def test_dns_enrichment_parses_supported_types_and_ignores_malformed_answers(self):
        samples = {
            "A": "Server: resolver\nAddress: 192.0.2.53\nName: example.test\nAddress: 198.51.100.2\n",
            "AAAA": "Server: resolver\nAddress: 192.0.2.53\nName: example.test\nAddress: 2001:db8::1\n",
            "CNAME": "example.test canonical name = alias.example.test.\n",
            "MX": "example.test MX preference = 10, mail exchanger = mx.example.test.\n",
            "NS": "example.test nameserver = ns1.example.test.\n",
            "TXT": 'example.test text = "v=spf1 include:mail.example.test ~all"\n',
        }
        expected = {
            "A": "198.51.100.2", "AAAA": "2001:db8::1",
            "CNAME": "alias.example.test", "MX": "mx.example.test",
            "NS": "ns1.example.test", "TXT": "v=spf1 include:mail.example.test ~all",
        }
        for record_type, output in samples.items():
            with self.subTest(record_type=record_type):
                parsed = parse_output("windows_nslookup", "example.test", output,
                                      {"record_type": record_type})
                self.assertEqual(len(parsed), 1)
                self.assertEqual(parsed[0]["data"]["record_type"], record_type)
                self.assertEqual(parsed[0]["data"]["value"], expected[record_type])
        self.assertEqual(parse_output("windows_nslookup", "example.test",
                                      "Name: example.test\nAddress: not-an-ip\n",
                                      {"record_type": "A"}), [])
        plans = NslookupAdapter().build_execution_plans("example.test", {
            "record_types": ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
        })
        self.assertEqual([plan.metadata["record_type"] for plan in plans],
                         ["A", "AAAA", "CNAME", "MX", "NS", "TXT"])

    def test_bounded_http_parser_captures_safe_headers_redirect_and_title(self):
        output = (
            "HTTP/1.1 302 Found\r\nServer: nginx\r\nLocation: https://next.example.test/private?token=secret\r\n"
            "Set-Cookie: session=secret\r\nContent-Type: text/html\r\nX-Powered-By: example\r\n\r\n"
            "<html><head><title>Example &amp; Status</title></head></html>\n"
            "BBWB_HTTP_META:302\thttps://next.example.test/private?token=secret\thttps://start.example.test/\n"
        )
        parsed = parse_output("curl_head", "https://start.example.test", output,
                              {"http_mode": "bounded_get"})
        endpoint = next(row for row in parsed if row["result_type"] == "endpoint")
        self.assertEqual(endpoint["data"]["http_status"], 302)
        self.assertEqual(endpoint["data"]["title"], "Example & Status")
        self.assertEqual(endpoint["data"]["redirect_url"], "https://next.example.test")
        self.assertIn("nginx", {row["data"].get("technology") for row in parsed})
        self.assertIn("x-powered-by", {row["data"].get("header") for row in parsed})
        self.assertEqual(parse_output("curl_head", "https://start.example.test", "not HTTP output",
                                      {"http_mode": "bounded_get"}), [])
        plan = CurlHeadAdapter().build_execution_plan(
            "https://start.example.test", {"http_mode": "bounded_get", "timeout": 20})
        self.assertIn("--max-filesize", plan.structured_args)
        self.assertIn("--range", plan.structured_args)
        self.assertNotIn("--location", plan.structured_args)
        self.assertEqual(plan.metadata["http_mode"], "bounded_get")

    def test_curl_adapter_builds_fixed_non_redirecting_arguments(self):
        plan = CurlHeadAdapter().build_execution_plan("https://example.test", {"timeout": 20})
        self.assertEqual(plan.executable, "curl.exe")
        self.assertIn("--head", plan.structured_args)
        self.assertIn("--disable", plan.structured_args)
        self.assertIn("--noproxy", plan.structured_args)
        self.assertNotIn("--location", plan.structured_args)
        self.assertEqual(plan.structured_args[-1], "https://example.test")
        with self.assertRaises(ValueError):
            CurlHeadAdapter().build_execution_plan("https://user@example.test", {})
        with self.assertRaises(ValueError):
            NslookupAdapter().build_execution_plan("-debug", {})

    def test_subfinder_is_passive_and_hostname_output_is_normalized(self):
        adapter = SubfinderAdapter()
        plan = adapter.build_execution_plan("Example.test", {"executable": "fake-subfinder"})
        self.assertEqual(plan.executable, "fake-subfinder")
        self.assertEqual(plan.structured_args, ("-silent", "-d", "example.test"))
        self.assertEqual(plan.metadata["mode"], "passive")
        parsed = parse_output("subfinder", "example.test", """
API.Example.test.
api.example.test
bad..example.test
https://example.test/path
""")
        self.assertEqual([row["data"]["hostname"] for row in parsed], ["api.example.test"])
        self.assertEqual(parsed[0]["result_type"], "subdomain")
        self.assertEqual(parsed[0]["data"]["source_tool"], "subfinder")
        with self.assertRaises(ValueError):
            adapter.build_execution_plan("https://example.test", {})


if __name__ == "__main__":
    unittest.main()
