"""Local backend connection and explicitly owned process lifecycle."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from .api_client import ApiClient, ApiClientError


class BackendManager:
    """Probe the configured API and optionally manage only a child it starts.

    The desktop shell only calls ``check_connection``. Starting a backend is an
    explicit operation and is never performed automatically by the UI.
    """

    def __init__(self, api_client: ApiClient, backend_directory: Path | None = None):
        self.api_client = api_client
        self.backend_directory = (
            backend_directory or Path(__file__).resolve().parents[1] / "backend"
        ).resolve()
        self._process: subprocess.Popen | None = None

    def check_connection(self) -> dict:
        health = self.api_client.get_json("/health")
        if not isinstance(health, dict) or health.get("status") != "healthy":
            raise ApiClientError("The local backend returned an unhealthy status.")
        return health

    def start_local_backend(self, wait_seconds: float = 8.0) -> bool:
        """Explicitly start the bundled development backend only if unreachable.

        Returns True when this manager started a process and False when an API
        was already available. The app does not call this method automatically.
        """
        try:
            self.check_connection()
            return False
        except ApiClientError:
            pass

        host, port = self._api_host_port()
        try:
            with socket.create_connection((host, port), timeout=0.25):
                raise ApiClientError(
                    f"A service is already listening at {host}:{port}, but its "
                    "health endpoint is unavailable. Refusing to start a second backend."
                )
        except (ConnectionRefusedError, TimeoutError, OSError):
            pass

        if self._process is not None and self._process.poll() is None:
            return True

        python_executable = self.backend_directory / ".venv" / "Scripts" / "python.exe"
        if not python_executable.is_file():
            python_executable = Path(sys.executable)

        environment = os.environ.copy()
        environment.setdefault("BUGBOUNTY_DATA_DIR", str(self.backend_directory))
        command = [
            str(python_executable),
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ]
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._process = subprocess.Popen(
            command,
            cwd=self.backend_directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )

        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise ApiClientError("The backend process exited during startup.")
            try:
                self.check_connection()
                return True
            except ApiClientError:
                time.sleep(0.2)

        self.stop_local_backend()
        raise ApiClientError("The backend did not become healthy before the timeout.")

    def stop_local_backend(self) -> None:
        """Stop only the backend process created by this manager."""
        if self._process is None or self._process.poll() is not None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=3)
        self._process = None

    def _api_host_port(self) -> tuple[str, int]:
        from urllib.parse import urlparse

        parsed = urlparse(self.api_client.base_url)
        return parsed.hostname or "127.0.0.1", parsed.port or 8000
