import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from io import BytesIO


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from desktop.api_client import ApiClient, ApiClientError, DEFAULT_API_BASE_URL


class FakeResponse:
    status = 200

    def __init__(self, body: bytes):
        self.body = body
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self.body


class ApiClientTests(unittest.TestCase):
    def test_default_url_is_localhost(self):
        self.assertEqual(ApiClient().base_url, DEFAULT_API_BASE_URL)

    def test_get_parses_json_and_uses_configured_base_url(self):
        with patch("desktop.api_client.urlopen", return_value=FakeResponse(b'{"ok":true}')) as open_url:
            result = ApiClient("http://localhost:8123", timeout=2).get_json("/health")

        self.assertEqual(result, {"ok": True})
        request = open_url.call_args.args[0]
        self.assertEqual(request.full_url, "http://localhost:8123/health")
        self.assertEqual(open_url.call_args.kwargs["timeout"], 2)

    def test_request_encodes_json_payload(self):
        with patch("desktop.api_client.urlopen", return_value=FakeResponse(b'{"created":true}')) as open_url:
            result = ApiClient().request_json("POST", "/projects", {"name": "Local"})

        request = open_url.call_args.args[0]
        self.assertEqual(json.loads(request.data.decode("utf-8")), {"name": "Local"})
        self.assertEqual(result, {"created": True})

    def test_request_text_returns_export_content(self):
        with patch("desktop.api_client.urlopen", return_value=FakeResponse(b"# Assessment Report")):
            result = ApiClient().request_text("GET", "/projects/1/assessments/2/export/markdown")
        self.assertEqual(result["content"], "# Assessment Report")
        self.assertEqual(result["status_code"], 200)

    def test_http_error_includes_status_and_detail(self):
        error = HTTPError(
            "http://127.0.0.1:8000/projects",
            404,
            "Not Found",
            None,
            BytesIO(b'{"detail":"Project not found."}'),
        )
        with patch("desktop.api_client.urlopen", side_effect=error):
            with self.assertRaises(ApiClientError) as raised:
                ApiClient().get_json("/projects")

        self.assertEqual(raised.exception.status_code, 404)
        self.assertIn("Project not found", str(raised.exception))

    def test_connection_error_is_clear(self):
        with patch("desktop.api_client.urlopen", side_effect=URLError("connection refused")):
            with self.assertRaisesRegex(ApiClientError, "Cannot reach the local API"):
                ApiClient().get_json("/health")

    def test_non_loopback_base_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            ApiClient("http://example.com:8000")


if __name__ == "__main__":
    unittest.main()
