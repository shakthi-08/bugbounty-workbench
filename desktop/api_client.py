"""Small HTTP-only client for the local Bug Bounty Workbench API."""

import ipaddress
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DEFAULT_API_BASE_URL = "http://127.0.0.1:8000"
API_BASE_URL_ENV = "BUGBOUNTY_API_BASE_URL"


class ApiClientError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class ApiClient:
    def __init__(self, base_url: str | None = None, timeout: float = 4.0):
        configured_url = base_url or os.environ.get(
            API_BASE_URL_ENV,
            DEFAULT_API_BASE_URL,
        )
        self.base_url = self._validate_base_url(configured_url)
        self.timeout = timeout

    @staticmethod
    def _validate_base_url(base_url: str) -> str:
        parsed = urlparse(base_url.strip())
        if (
            parsed.scheme != "http"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("API base URL must be a plain localhost HTTP URL.")

        hostname = parsed.hostname.lower()
        is_loopback = hostname == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            raise ValueError("The desktop client only connects to a loopback API host.")

        return base_url.strip().rstrip("/")

    def get_json(self, path: str):
        return self.request_json("GET", path)

    def request_json(self, method: str, path: str, payload=None):
        if not path.startswith("/"):
            path = "/" + path

        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            method=method.upper(),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw_body = response.read()
                status_code = response.status
        except HTTPError as error:
            raw_body = error.read()
            message = self._error_message(raw_body, error.reason)
            raise ApiClientError(
                f"API returned HTTP {error.code}: {message}",
                status_code=error.code,
            ) from error
        except (URLError, TimeoutError, OSError) as error:
            reason = getattr(error, "reason", error)
            raise ApiClientError(
                f"Cannot reach the local API at {self.base_url}: {reason}"
            ) from error

        if not raw_body:
            return None
        try:
            return json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ApiClientError(
                f"API returned an invalid JSON response (HTTP {status_code}).",
                status_code=status_code,
            ) from error

    def request_text(self, method: str, path: str):
        """Fetch a local API export without trying to parse it as JSON."""
        if not path.startswith("/"):
            path = "/" + path
        request = Request(self.base_url + path, method=method.upper(),
                          headers={"Accept": "application/json, text/markdown, text/html"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                content = response.read().decode("utf-8")
                status_code = response.status
                filename = (response.headers.get_filename()
                            if hasattr(response.headers, "get_filename") else None)
        except HTTPError as error:
            message = self._error_message(error.read(), error.reason)
            raise ApiClientError(f"API returned HTTP {error.code}: {message}",
                                 status_code=error.code) from error
        except (URLError, TimeoutError, OSError) as error:
            reason = getattr(error, "reason", error)
            raise ApiClientError(
                f"Cannot reach the local API at {self.base_url}: {reason}"
            ) from error
        return {"content": content, "filename": filename, "status_code": status_code}

    @staticmethod
    def _error_message(raw_body: bytes, fallback: str) -> str:
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return raw_body.decode("utf-8", errors="replace").strip() or str(fallback)

        if isinstance(body, dict):
            detail = body.get("detail")
            if isinstance(detail, str):
                return detail
        return str(body)
