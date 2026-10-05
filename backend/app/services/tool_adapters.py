from abc import ABC, abstractmethod
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import ssl
import socket
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ExecutionPlan:
    tool_key: str
    executable: str
    structured_args: tuple[str, ...]
    environment: dict[str, str] = field(default_factory=dict)
    working_directory: Path | None = None
    timeout: int = 300
    target: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolAdapter(ABC):
    adapter_key: str
    tool_key: str
    supported_capabilities: frozenset[str] = frozenset()

    @abstractmethod
    def validate_parameters(self, parameters: dict[str, Any]) -> None:
        """Validate structured, adapter-defined parameters; never parse shell text."""

    @abstractmethod
    def build_execution_plan(
        self, target: str, parameters: dict[str, Any]
    ) -> ExecutionPlan:
        """Build a structured plan. Phase 3 does not execute plans."""

    def build_execution_plans(
        self, target: str, parameters: dict[str, Any]
    ) -> tuple[ExecutionPlan, ...]:
        return (self.build_execution_plan(target, parameters),)

    def check_availability(self, executable: str) -> tuple[bool, str]:
        if not executable or Path(executable).name != executable:
            return False, "The registered executable name is invalid."
        if shutil.which(executable) is None:
            return False, f"Registered tool executable '{executable}' is not installed."
        return True, "Registered executable is available."


class AdapterRegistry:
    def __init__(self):
        self._adapters: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        if adapter.adapter_key in self._adapters:
            raise ValueError(f"Adapter already registered: {adapter.adapter_key}")
        self._adapters[adapter.adapter_key] = adapter

    def get_for_tool(self, tool_key: str) -> ToolAdapter | None:
        return next(
            (adapter for adapter in self._adapters.values() if adapter.tool_key == tool_key),
            None,
        )

    def check_tool(self, tool_key: str, executable: str | None) -> tuple[bool, str]:
        adapter = self.get_for_tool(tool_key)
        if adapter is None:
            return False, "No execution adapter is registered in Phase 3."
        return adapter.check_availability(executable or "")


class ToolRegistry:
    """Metadata registry facade; persistent tool metadata remains in SQLAlchemy."""

    @staticmethod
    def key_for_record(tool: Any) -> str:
        return tool.key


class TestModuleRegistry:
    """Registry facade for stable, database-backed test-module keys."""

    @staticmethod
    def key_for_record(module: Any) -> str:
        return module.key


adapter_registry = AdapterRegistry()
tool_registry = ToolRegistry()
test_module_registry = TestModuleRegistry()


class NslookupAdapter(ToolAdapter):
    adapter_key = "windows_nslookup"
    tool_key = "windows_nslookup"
    supported_capabilities = frozenset({"network.asset_discovery"})

    def validate_parameters(self, parameters: dict[str, Any]) -> None:
        _validate_timeout(parameters)
        record_types = parameters.get("record_types", ["A"])
        allowed = {"A", "AAAA", "CNAME", "MX", "NS", "TXT"}
        if (not isinstance(record_types, (list, tuple)) or not record_types
                or len(record_types) > len(allowed)
                or any(not isinstance(item, str) or item.upper() not in allowed for item in record_types)):
            raise ValueError("record_types must contain one or more of A, AAAA, CNAME, MX, NS, TXT.")
        if len({item.upper() for item in record_types}) != len(record_types):
            raise ValueError("record_types must not contain duplicates.")

    def build_execution_plan(self, target: str, parameters: dict[str, Any]) -> ExecutionPlan:
        self.validate_parameters(parameters)
        hostname = _target_host(target)
        record_type = str(parameters.get("record_type", "A")).upper()
        if record_type not in {"A", "AAAA", "CNAME", "MX", "NS", "TXT"}:
            raise ValueError("Unsupported DNS record type.")
        return ExecutionPlan(self.tool_key, "nslookup.exe", (f"-type={record_type}", hostname),
                             timeout=parameters.get("timeout", 60), target=target,
                             metadata={"record_type": record_type})

    def build_execution_plans(self, target: str, parameters: dict[str, Any]) -> tuple[ExecutionPlan, ...]:
        self.validate_parameters(parameters)
        return tuple(self.build_execution_plan(target, {
            "timeout": parameters.get("timeout", 60), "record_type": record_type,
        }) for record_type in parameters.get("record_types", ["A"]))


class CurlHeadAdapter(ToolAdapter):
    adapter_key = "curl_head"
    tool_key = "curl_head"
    supported_capabilities = frozenset({"web.discovery"})

    def validate_parameters(self, parameters: dict[str, Any]) -> None:
        _validate_timeout(parameters)
        if parameters.get("http_mode", "head") not in {"head", "bounded_get"}:
            raise ValueError("http_mode must be 'head' or 'bounded_get'.")

    def build_execution_plan(self, target: str, parameters: dict[str, Any]) -> ExecutionPlan:
        self.validate_parameters(parameters)
        parsed = urlsplit(target if "://" in target else "https://" + target)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or any(ord(c) < 32 for c in target)):
            raise ValueError("Target must be a plain HTTP(S) URL without credentials or a fragment.")
        try:
            parsed.port
        except ValueError as error:
            raise ValueError("Target URL contains an invalid port.") from error
        url = parsed.geturl()
        timeout = parameters.get("timeout", 60)
        if parameters.get("http_mode", "head") == "bounded_get":
            # Do not follow redirects. The response body is bounded and later
            # discarded from evidence after title extraction.
            args = ("--disable", "--noproxy", "*", "--silent", "--show-error",
                    "--connect-timeout", str(min(timeout, 10)), "--max-time", str(timeout),
                    "--max-filesize", "262144", "--range", "0-65535",
                    "--dump-header", "-", "--write-out",
                    "\\nBBWB_HTTP_META:%{http_code}\\t%{redirect_url}\\t%{url_effective}\\n",
                    "--", url)
        else:
            # Redirect following is deliberately disabled.
            args = ("--disable", "--noproxy", "*", "--head", "--silent", "--show-error",
                    "--connect-timeout", str(min(timeout, 10)), "--max-time", str(timeout),
                    "--write-out", "\\nBBWB_STATUS:%{http_code}\\n", "--", url)
        return ExecutionPlan(self.tool_key, "curl.exe", args,
                             timeout=timeout + 5, target=target,
                             metadata={"http_mode": parameters.get("http_mode", "head")})


class WebSurfaceAdapter(ToolAdapter):
    """Built-in, fixed-path HTTP discovery for one selected host."""
    adapter_key = "web_surface_discovery"
    tool_key = "web_surface_discovery"
    supported_capabilities = frozenset({"web.discovery", "web.technology_fingerprinting"})

    def check_availability(self, executable: str) -> tuple[bool, str]:
        if executable != "builtin:python-http":
            return False, "Web surface adapter configuration is invalid."
        return True, "Built-in bounded Python HTTP inspector is available."

    def validate_parameters(self, parameters: dict[str, Any]) -> None:
        timeout = parameters.get("timeout", 5)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 8:
            raise ValueError("Web surface timeout must be an integer between 1 and 8 seconds.")
        max_paths = parameters.get("max_paths", 5)
        if isinstance(max_paths, bool) or not isinstance(max_paths, int) or not 1 <= max_paths <= 12:
            raise ValueError("Endpoint discovery is limited to 1–12 fixed candidate paths.")

    def build_execution_plan(self, target: str, parameters: dict[str, Any]) -> ExecutionPlan:
        self.validate_parameters(parameters)
        from app.services.web_surface_inspection import canonical_base_url
        base_url = canonical_base_url(target)
        return ExecutionPlan(self.tool_key, "builtin:python-http", (),
                             timeout=parameters.get("timeout", 5), target=base_url,
                             metadata={"fixed_paths": True})

    async def inspect(self, target: str, timeout: int, authorize, max_paths: int = 5):
        from app.services.web_surface_inspection import web_surface_inspection
        self.validate_parameters({"timeout": timeout, "max_paths": max_paths})
        return await web_surface_inspection.inspect(target, timeout, authorize, max_paths=max_paths)


class TcpServiceAwarenessAdapter(ToolAdapter):
    """Small TCP reachability check restricted to explicitly authorized IP assets."""
    adapter_key = "tcp_service_awareness"
    tool_key = "tcp_service_awareness"
    supported_capabilities = frozenset({"network.service_awareness"})
    ALLOWED_PORTS = (22, 80, 443, 445, 8080, 8443)

    def check_availability(self, executable: str) -> tuple[bool, str]:
        return (executable == "builtin:python-tcp",
                "Built-in bounded TCP service awareness is available." if executable == "builtin:python-tcp"
                else "Service awareness adapter configuration is invalid.")

    def validate_parameters(self, parameters: dict[str, Any]) -> None:
        timeout = parameters.get("timeout", 2)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 3:
            raise ValueError("TCP connection timeout must be between 1 and 3 seconds.")
        ports = parameters.get("ports", list(self.ALLOWED_PORTS))
        if (not isinstance(ports, (list, tuple)) or not ports or len(ports) > len(self.ALLOWED_PORTS)
                or any(isinstance(port, bool) or not isinstance(port, int) or port not in self.ALLOWED_PORTS
                       for port in ports) or len(set(ports)) != len(ports)):
            raise ValueError("Ports must be unique members of the fixed common-port allowlist.")

    def build_execution_plan(self, target: str, parameters: dict[str, Any]) -> ExecutionPlan:
        self.validate_parameters(parameters)
        try:
            address = ipaddress.ip_address(target.strip())
        except ValueError as error:
            raise ValueError("TCP service awareness requires an explicitly authorized IP asset.") from error
        return ExecutionPlan(self.tool_key, "builtin:python-tcp", (), timeout=parameters.get("timeout", 2),
                             target=str(address), metadata={"ports": list(parameters.get("ports", self.ALLOWED_PORTS))})

    async def inspect(self, target: str, timeout: int, ports: list[int], authorize=None):
        self.build_execution_plan(target, {"timeout": timeout, "ports": ports})
        observations = []
        for port in ports:
            if authorize is not None and not await authorize(target, port):
                observations.append({"host": target, "port": port, "protocol": "tcp",
                                    "state": "blocked", "service": None,
                                    "duration_ms": 0, "error_class": "authorization_rejected"})
                continue
            started = asyncio.get_running_loop().time()
            try:
                _reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout)
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), 0.25)
                except (OSError, asyncio.TimeoutError):
                    pass
                state, error = "reachable", None
            except asyncio.TimeoutError:
                state, error = "not_reachable", "timeout"
            except OSError as exc:
                state = "not_reachable"
                error = "refused" if getattr(exc, "winerror", None) == 10061 or getattr(exc, "errno", None) == 111 else "connection_error"
            observations.append({"host": target, "port": port, "protocol": "tcp",
                                 "state": state, "service": {22: "ssh", 80: "http", 443: "https",
                                 445: "smb", 8080: "http-alt", 8443: "https-alt"}[port],
                                 "duration_ms": round((asyncio.get_running_loop().time() - started) * 1000),
                                 "error_class": error})
        return {"target": target, "observations": observations}


class SubfinderAdapter(ToolAdapter):
    """Passive-only ProjectDiscovery Subfinder invocation."""
    adapter_key = "subfinder"
    tool_key = "subfinder"
    supported_capabilities = frozenset({"network.passive_subdomain_discovery"})

    def check_availability(self, executable: str) -> tuple[bool, str]:
        if not executable:
            return False, "Subfinder is unavailable; install it manually and configure its executable path."
        candidate = Path(executable).expanduser()
        found = candidate.is_file() if (candidate.is_absolute() or candidate.parent != Path(".")) else shutil.which(executable)
        if not found:
            return False, f"Subfinder executable '{executable}' is unavailable; install it manually."
        return True, "ProjectDiscovery Subfinder is available."

    def validate_parameters(self, parameters: dict[str, Any]) -> None:
        _validate_timeout(parameters)
        max_results = parameters.get("max_results", 100)
        if isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= 100:
            raise ValueError("Subdomain result limit must be between 1 and 100.")

    def build_execution_plan(self, target: str, parameters: dict[str, Any]) -> ExecutionPlan:
        self.validate_parameters(parameters)
        if "://" in target or "/" in target or ":" in target:
            raise ValueError("Subfinder requires a plain authorized DNS domain target.")
        hostname = _target_host(target)
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("Subfinder requires a DNS domain, not an IP address.")
        executable = parameters.get("executable") or "subfinder.exe"
        return ExecutionPlan(self.tool_key, executable,
                             ("-silent", "-d", hostname),
                             timeout=parameters.get("timeout", 60) + 5,
                             target=target, metadata={"mode": "passive"})


class TlsInspectionAdapter(ToolAdapter):
    """Bounded, certificate-validating HTTPS metadata inspection via Python ssl."""
    adapter_key = "tls_inspector"
    tool_key = "tls_inspector"
    supported_capabilities = frozenset({"network.tls_inspection"})

    def check_availability(self, executable: str) -> tuple[bool, str]:
        if executable != "builtin:python-ssl":
            return False, "TLS inspection configuration is invalid; expected the built-in Python SSL adapter."
        return True, "Built-in Python TLS inspection adapter is available."

    def validate_parameters(self, parameters: dict[str, Any]) -> None:
        timeout = parameters.get("timeout", 15)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30:
            raise ValueError("TLS timeout must be an integer between 1 and 30 seconds.")

    def build_execution_plan(self, target: str, parameters: dict[str, Any]) -> ExecutionPlan:
        self.validate_parameters(parameters)
        host = _target_host(target)
        if "://" in target or "/" in target or "@" in target or ":" in target:
            raise ValueError("TLS inspection requires a plain authorized hostname on HTTPS port 443.")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("TLS inspection requires a DNS hostname, not an IP address.")
        return ExecutionPlan(self.tool_key, "builtin:python-ssl", (),
                             timeout=parameters.get("timeout", 15), target=host,
                             metadata={"port": 443, "verification": "required"})

    async def inspect(self, target: str, timeout: int) -> dict[str, Any]:
        """Connect only to hostname:443 with default CA and hostname validation."""
        host = _target_host(target).lower().rstrip(".")
        self.build_execution_plan(host, {"timeout": timeout})
        context = ssl.create_default_context()
        writer = None
        metadata: dict[str, Any] = {
            "hostname": host, "port": 443, "verification_status": False,
            "hostname_verification": "not_verified",
            "tls_version": None, "cipher": None, "subject": None, "issuer": None,
            "serial_number": None, "valid_from": None, "valid_until": None,
            "fingerprint_sha256": None, "signature_algorithm": None,
            "certificate_expired": None, "certificate_not_yet_valid": None,
            "sans": [], "resolved_endpoint": None, "connection_error": None,
        }
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=context, server_hostname=host), timeout
            )
            del reader
            ssl_object = writer.get_extra_info("ssl_object")
            peer = writer.get_extra_info("peername")
            metadata["resolved_endpoint"] = peer[0] if isinstance(peer, tuple) and peer else None
            if ssl_object is None:
                raise ssl.SSLError("TLS connection did not provide SSL metadata.")
            cert = ssl_object.getpeercert()
            cert_der = ssl_object.getpeercert(binary_form=True)
            now = datetime.now(timezone.utc).timestamp()
            not_before = ssl.cert_time_to_seconds(cert["notBefore"]) if cert.get("notBefore") else None
            not_after = ssl.cert_time_to_seconds(cert["notAfter"]) if cert.get("notAfter") else None
            metadata.update({
                "tls_version": ssl_object.version(),
                "cipher": (ssl_object.cipher() or (None,))[0],
                "subject": _certificate_name(cert.get("subject", ())),
                "issuer": _certificate_name(cert.get("issuer", ())),
                "valid_from": cert.get("notBefore"),
                "valid_until": cert.get("notAfter"),
                "serial_number": cert.get("serialNumber"),
                "fingerprint_sha256": hashlib.sha256(cert_der).hexdigest() if cert_der else None,
                "signature_algorithm": cert.get("signatureAlgorithm"),
                "certificate_expired": bool(not_after is not None and now > not_after),
                "certificate_not_yet_valid": bool(not_before is not None and now < not_before),
                "sans": sorted({value.lower().rstrip(".") for kind, value in cert.get("subjectAltName", ())
                                 if kind == "DNS" and isinstance(value, str)}),
                "verification_status": True,
                "hostname_verification": "passed",
            })
        except asyncio.TimeoutError:
            metadata["connection_error"] = "TLS connection timed out."
        except (OSError, ssl.SSLError, ValueError) as error:
            # Do not retry with verification disabled: failure metadata is sufficient.
            metadata["connection_error"] = _safe_tls_error(error)
            metadata["hostname_verification"] = (
                "failed" if isinstance(error, ssl.SSLCertVerificationError) else "not_verified"
            )
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except (asyncio.TimeoutError, OSError, ssl.SSLError):
                    pass
        return metadata


def _certificate_name(parts) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for rdn in parts:
        for key, value in rdn:
            if key in {"commonName", "organizationName", "organizationalUnitName", "countryName"}:
                result.setdefault(key, []).append(str(value))
    return result


def _safe_tls_error(error: BaseException) -> str:
    if isinstance(error, ssl.SSLCertVerificationError):
        return "Certificate verification failed: " + str(error)[:300]
    return f"{type(error).__name__}: {str(error)[:300]}"


def _validate_timeout(parameters: dict[str, Any]) -> None:
    timeout = parameters.get("timeout", 60)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        raise ValueError("timeout must be an integer between 1 and 300 seconds.")


def _target_host(target: str) -> str:
    parsed = urlsplit(target if "://" in target else "//" + target)
    hostname = parsed.hostname
    if (not hostname or parsed.username is not None or parsed.password is not None
            or any(ord(c) < 32 for c in target)):
        raise ValueError("Target must contain a valid hostname without credentials.")
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        ascii_host = hostname.encode("idna").decode("ascii")
        if len(ascii_host) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in ascii_host.rstrip(".").split(".")
        ):
            raise ValueError("Target must contain a valid DNS hostname.")
        return ascii_host


adapter_registry.register(NslookupAdapter())
adapter_registry.register(CurlHeadAdapter())
adapter_registry.register(WebSurfaceAdapter())
adapter_registry.register(SubfinderAdapter())
adapter_registry.register(TlsInspectionAdapter())
adapter_registry.register(TcpServiceAwarenessAdapter())
