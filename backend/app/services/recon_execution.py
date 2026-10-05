"""Authorized, adapter-controlled subprocess execution for recon jobs."""
import asyncio
import hashlib
import html
import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from html.parser import HTMLParser

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.config import get_data_dir
from app.core.database import AsyncSessionLocal
from app.models.evidence import Evidence
from app.models.asset import Asset
from app.models.security_job import SecurityJob
from app.models.assessment_taxonomy import TestModule
from app.models.scan_profile import ScanProfile, scan_profile_modules
from app.models.security_result import SecurityResult
from app.models.tool import Tool
from app.services.security_audit import write_audit_log
from app.services.security_authorization import security_authorization
from app.services.tool_adapters import ExecutionPlan, adapter_registry


MAX_OUTPUT_BYTES = 2_000_000
_tasks: dict[int, asyncio.Task] = {}
_processes: dict[int, asyncio.subprocess.Process] = {}


class ProcessResult:
    def __init__(self, stdout: str, stderr: str, exit_code: int, started_at: datetime,
                 ended_at: datetime, status: str):
        self.stdout, self.stderr, self.exit_code = stdout, stderr, exit_code
        self.started_at, self.ended_at, self.status = started_at, ended_at, status


async def run_process(plan: ExecutionPlan, job_id: int) -> ProcessResult:
    started = datetime.now(timezone.utc)
    process_options = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    process = await asyncio.create_subprocess_exec(
        plan.executable, *plan.structured_args,
        cwd=str(plan.working_directory) if plan.working_directory else None,
        env={**os.environ, **plan.environment},
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        **process_options,
    )
    _processes[job_id] = process
    stdout_task = asyncio.create_task(_read_capped(process.stdout))
    stderr_task = asyncio.create_task(_read_capped(process.stderr))
    try:
        try:
            await asyncio.wait_for(process.wait(), plan.timeout)
            state = "completed" if process.returncode == 0 else "failed"
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            state = "timed_out"
        stdout_b, stderr_b = await asyncio.gather(stdout_task, stderr_task)
        return ProcessResult(_decode_limited(stdout_b), _decode_limited(stderr_b),
                             process.returncode if process.returncode is not None else -1,
                             started, datetime.now(timezone.utc), state)
    except asyncio.CancelledError:
        if process.returncode is None:
            process.kill()
            await process.wait()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        raise
    finally:
        _processes.pop(job_id, None)


async def _read_capped(stream, limit: int = MAX_OUTPUT_BYTES) -> bytes:
    captured = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        room = limit - len(captured)
        if room > 0:
            captured.extend(chunk[:room])
        if len(chunk) > room:
            truncated = True
    if truncated:
        captured.extend(b"\n[output truncated at 2 MB]")
    return bytes(captured)


def _decode_limited(value: bytes) -> str:
    if len(value) > MAX_OUTPUT_BYTES:
        value = value[:MAX_OUTPUT_BYTES] + b"\n[output truncated at 2 MB]"
    return value.decode("utf-8", errors="replace")


def _normalize_dns(target: str, stdout: str, tool_key: str,
                   record_type: str = "A") -> list[dict[str, Any]]:
    from app.services.tool_adapters import _target_host
    query_host = _target_host(target).lower().rstrip(".")
    record_type = record_type.upper()
    values: list[str] = []
    answer_section = False
    for line in stdout.splitlines():
        stripped = line.strip()
        if re.match(r"(?i)^name\s*:", stripped) or "non-authoritative answer" in stripped.lower():
            answer_section = True
        if record_type in {"A", "AAAA"}:
            if not answer_section:
                continue  # Ignore the resolver's own address.
            match = re.match(r"(?i)^address(?:es)?\s*:\s*(.+?)\s*$", stripped)
            if match:
                for candidate in re.split(r"[,\s]+", match.group(1)):
                    try:
                        address = ipaddress.ip_address(candidate)
                    except ValueError:
                        continue
                    if (record_type == "A" and address.version == 4) or (
                            record_type == "AAAA" and address.version == 6):
                        values.append(str(address))
        elif record_type == "CNAME":
            match = re.search(r"(?i)canonical name\s*=\s*([A-Za-z0-9.-]+)\.?$", stripped)
            if match:
                values.append(_valid_dns_name(match.group(1)))
        elif record_type == "MX":
            match = re.search(r"(?i)mail exchanger\s*=\s*([A-Za-z0-9.-]+)\.?$", stripped)
            if match:
                values.append(_valid_dns_name(match.group(1)))
        elif record_type == "NS":
            match = re.search(r"(?i)nameserver\s*=\s*([A-Za-z0-9.-]+)\.?$", stripped)
            if match:
                values.append(_valid_dns_name(match.group(1)))
        elif record_type == "TXT":
            match = re.match(r"(?i)^(?:[A-Za-z0-9.-]+\s+)?text\s*=\s*(.*)$", stripped)
            if match and match.group(1):
                txt = match.group(1).strip()
                if len(txt) >= 2 and txt[0] == txt[-1] == '"':
                    txt = txt[1:-1]
                values.append(txt)
    normalized = []
    for value in dict.fromkeys(item for item in values if item):
        normalized.append({
            "result_type": "dns_record",
            "title": f"DNS {record_type} record for {query_host}",
            "summary": f"Resolved {record_type} data for {query_host}.",
            "data": {"hostname": query_host, "record_type": record_type,
                     "value": value, "source_tool": tool_key,
                     "discovered_at": datetime.now(timezone.utc).isoformat(),
                     **({"ip": value} if record_type in {"A", "AAAA"} else {}),
                     **({"candidate_hostname": value} if record_type in {"CNAME", "MX", "NS"} else {})},
        })
    return normalized


def _valid_dns_name(value: str) -> str:
    from app.services.tool_adapters import _target_host
    try:
        hostname = _target_host(value).lower().rstrip(".")
    except (ValueError, UnicodeError):
        return ""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    return ""


class _TitleParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.in_title = tag.lower() == "title"

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.parts.append(data)


def _safe_redirect(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = parsed.hostname.lower() + (f":{port}" if port else "")
    return f"{parsed.scheme}://{netloc}"


def _normalize_curl(target: str, stdout: str, tool_key: str,
                    http_mode: str = "head") -> list[dict[str, Any]]:
    meta_match = re.search(r"BBWB_HTTP_META:(\d{3})\t([^\t\r\n]*)\t([^\t\r\n]*)", stdout)
    status_match = re.search(r"BBWB_STATUS:(\d{3})", stdout)
    status = int(meta_match.group(1)) if meta_match else int(status_match.group(1)) if status_match else None
    if status is not None and not 100 <= status <= 599:
        status = None
    header_text, body = _split_http_response(stdout)
    headers = _http_headers(header_text)
    location = headers.get("location")
    redirect_url = (_safe_redirect(meta_match.group(2)) if meta_match else None) or _safe_redirect(location)
    server = headers.get("server")
    title_parser = _TitleParser()
    if http_mode == "bounded_get":
        try:
            title_parser.feed(body[:262144])
        except Exception:
            pass
    title = re.sub(r"\s+", " ", html.unescape(" ".join(title_parser.parts))).strip()[:300] or None
    parsed = urlsplit(target if "://" in target else "https://" + target)
    host = parsed.hostname or target
    records = []
    if status is not None:
        records.append({"result_type": "endpoint", "title": f"HTTP endpoint {status} {host}",
                        "summary": f"HTTP {http_mode} response captured.", "data": {
                            "hostname": host, "url": parsed.geturl(), "http_status": status,
                            "title": title, "redirect_url": redirect_url,
                            "http_mode": http_mode, "source_tool": tool_key,
                        }})
    if server:
        records.append({"result_type": "technology", "title": f"HTTP server: {server}",
                        "summary": "Server response header observed.", "data": {
                            "hostname": host, "technology": server, "source_tool": tool_key,
                        }})
    for name in ("x-powered-by", "content-type", "strict-transport-security",
                 "x-frame-options", "content-security-policy", "x-content-type-options"):
        if headers.get(name):
            records.append({"result_type": "technology", "title": f"HTTP {name}: {headers[name]}",
                            "summary": "HTTP response header observed.", "data": {
                                "hostname": host, "header": name, "value": headers[name],
                                "source_tool": tool_key,
                            }})
    return records


def _split_http_response(stdout: str) -> tuple[str, str]:
    clean = re.sub(r"\n?BBWB_HTTP_META:.*", "", stdout, flags=re.S)
    clean = re.sub(r"\n?BBWB_STATUS:\d{3}.*", "", clean, flags=re.S)
    lines = clean.splitlines()
    starts = [index for index, line in enumerate(lines)
              if re.match(r"(?i)^HTTP/\d(?:\.\d)?\s+\d{3}", line)]
    for start in reversed(starts):
        end = next((index for index in range(start + 1, len(lines)) if not lines[index].strip()), None)
        if end is None:
            return "\n".join(lines[start:]), ""
        block = lines[start:end]
        if len(block) > 1 and any(re.match(r"(?i)^HTTP/", line) for line in block[1:]):
            continue
        return "\n".join(block), "\n".join(lines[end + 1:])
    return "", ""


def _http_headers(block: str) -> dict[str, str]:
    allowed = {"server", "location", "content-type", "content-length", "x-powered-by",
               "strict-transport-security", "x-frame-options", "content-security-policy",
               "x-content-type-options", "referrer-policy", "permissions-policy"}
    headers = {}
    for line in block.splitlines()[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()[:1000]
        if key in allowed and key not in headers:
            headers[key] = _safe_redirect(value) if key == "location" else value
    return {key: value for key, value in headers.items() if value}


def _sanitize_evidence_output(tool_key: str, planned_results: list[tuple[ExecutionPlan, ProcessResult]]) -> str:
    sections = []
    for plan, result in planned_results:
        if tool_key == "tls_inspector":
            sections.append(result.stdout)
        elif tool_key == "web_surface_discovery":
            # The adapter returns normalized metadata only; page bodies are never
            # included in its output or written to evidence.
            sections.append(result.stdout[:MAX_OUTPUT_BYTES])
        elif tool_key == "curl_head":
            block, _ = _split_http_response(result.stdout)
            safe_headers = _http_headers(block)
            status_match = re.search(r"BBWB_(?:HTTP_META:|STATUS:)(\d{3})", result.stdout)
            lines = [block.splitlines()[0]] if block.splitlines() else []
            for name, value in safe_headers.items():
                lines.append(f"{name}: {value}")
            if status_match:
                lines.append(f"captured_status: {status_match.group(1)}")
            if result.stderr:
                lines.append("stderr: [captured but omitted from evidence]")
            sections.append("\n".join(lines))
        elif tool_key == "windows_nslookup":
            safe_stdout = re.sub(r'(?im)(\btext\s*=).+$', r'\1 [TXT value omitted from evidence]',
                                 result.stdout)
            sections.append(f"[DNS {plan.metadata.get('record_type', 'A')}]\n{safe_stdout}\n{result.stderr}")
        else:
            sections.append(f"[stdout]\n{result.stdout}\n[stderr]\n{result.stderr}")
    return "\n".join(sections)


def parse_output(tool_key: str, target: str, stdout: str,
                 metadata: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    metadata = metadata or {}
    if tool_key == "windows_nslookup":
        return _normalize_dns(target, stdout, tool_key, metadata.get("record_type", "A"))
    if tool_key == "curl_head":
        return _normalize_curl(target, stdout, tool_key, metadata.get("http_mode", "head"))
    if tool_key == "subfinder":
        return _normalize_subfinder(stdout, tool_key)
    if tool_key == "tls_inspector":
        try:
            from app.services.tool_adapters import _target_host
            value = json.loads(stdout)
            if not isinstance(value, dict) or value.get("hostname") != _target_host(target).lower().rstrip("."):
                return []
            return [{"result_type": "certificate", "title": f"TLS inspection: {value['hostname']}",
                     "summary": "Bounded HTTPS TLS and peer certificate metadata.", "data": value}]
        except (ValueError, KeyError, TypeError):
            return []
    if tool_key == "web_surface_discovery":
        try:
            from app.services.web_surface_inspection import _canonical_host
            payload = json.loads(stdout)
            host = _canonical_host(target)
            if not isinstance(payload, dict) or payload.get("hostname") != host:
                return []
            records = []
            for endpoint in payload.get("endpoints", []):
                if not isinstance(endpoint, dict) or endpoint.get("hostname") != host:
                    continue
                if endpoint.get("http_status") is not None:
                    records.append({
                        "result_type": "endpoint", "title": f"HTTP {endpoint['http_status']}: {endpoint.get('url', '')[:300]}",
                        "summary": "Bounded web surface endpoint inspection.", "data": endpoint,
                    })
                if endpoint.get("error"):
                    records.append({
                        "result_type": "configuration", "title": "Web endpoint inspection event",
                        "summary": str(endpoint["error"])[:500],
                        "data": {"hostname": host, "url": endpoint.get("url"),
                                 "inspection_error": str(endpoint["error"])[:500],
                                 "redirect_chain": endpoint.get("redirect_chain", [])},
                    })
            for technology in payload.get("technologies", []):
                if not isinstance(technology, dict) or technology.get("hostname") != host:
                    continue
                if technology.get("confidence") not in {"high", "medium", "low"}:
                    continue
                records.append({
                    "result_type": "technology",
                    "title": f"Technology detected: {str(technology.get('technology', ''))[:150]}",
                    "summary": f"Conservative HTTP fingerprint ({technology['confidence']} confidence).",
                    "data": technology,
                })
            for event in payload.get("events", []):
                if isinstance(event, dict) and event.get("event") == "redirect_blocked":
                    records.append({
                        "result_type": "configuration", "title": "Out-of-scope redirect blocked",
                        "summary": "A redirect outside the selected host was not requested.",
                        "data": {"hostname": host, "observation_type": "redirect_blocked",
                                 "from_url": event.get("from_url"), "to_host": event.get("to_host"),
                                 "reason": event.get("reason")},
                    })
            return records
        except (ValueError, KeyError, TypeError):
            return []
    if tool_key == "tcp_service_awareness":
        try:
            payload = json.loads(stdout)
            if not isinstance(payload, dict) or payload.get("target") != target:
                return []
            return [{"result_type": "service", "title": f"TCP {item['port']} {item['state']}",
                     "summary": "Bounded TCP reachability observation.", "data": item}
                    for item in payload.get("observations", [])[:6]
                    if isinstance(item, dict) and item.get("host") == target]
        except (ValueError, TypeError, KeyError):
            return []
    raise ValueError("No output parser is registered for this tool.")


def _normalize_subfinder(stdout: str, tool_key: str) -> list[dict[str, Any]]:
    return _parse_subfinder_output(stdout, tool_key)[0]


def _parse_subfinder_output(stdout: str, tool_key: str, max_results: int = 100) -> tuple[list[dict[str, Any]], list[str]]:
    from app.services.tool_adapters import _target_host
    hosts = []
    malformed = []
    for line in stdout.splitlines():
        raw = line.strip()
        if not raw:
            continue
        try:
            host = _target_host(raw).lower().rstrip(".")
        except (ValueError, UnicodeError):
            malformed.append(raw[:500])
            continue
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            malformed.append(raw[:500])
            continue
        # Subfinder's line protocol is hostnames only, never URLs, ports, or paths.
        if any(mark in raw for mark in ("/", ":", "@", "\\")):
            malformed.append(raw[:500])
            continue
        if host not in hosts and len(hosts) < max_results:
            hosts.append(host)
    parsed = [{"result_type": "subdomain", "title": f"Discovered subdomain: {host}",
             "summary": f"Passive subdomain result returned by {tool_key}.",
             "data": {"hostname": host, "source_tool": tool_key,
                      "discovered_at": datetime.now(timezone.utc).isoformat()}}
              for host in dict.fromkeys(hosts)]
    return parsed, malformed


async def start_job(job_id: int) -> None:
    if job_id in _tasks and not _tasks[job_id].done():
        return
    task = asyncio.create_task(_execute_job_guarded(job_id), name=f"recon-job-{job_id}")
    _tasks[job_id] = task
    task.add_done_callback(lambda _: _tasks.pop(job_id, None))


async def _execute_job_guarded(job_id: int) -> None:
    try:
        await _execute_job(job_id)
    except asyncio.CancelledError:
        await _mark_cancelled(job_id)
        raise


async def cancel_job(job_id: int) -> bool:
    task = _tasks.get(job_id)
    if task is None or task.done():
        return False
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    return True


async def stop_all_jobs() -> None:
    job_ids = list(_tasks)
    if job_ids:
        await asyncio.gather(*(cancel_job(job_id) for job_id in job_ids), return_exceptions=True)


async def recover_interrupted_jobs() -> None:
    async with AsyncSessionLocal() as db:
        rows = list((await db.scalars(select(SecurityJob).where(
            SecurityJob.status.in_(["queued", "running"])))).all())
        for job in rows:
            job.status = "failed"
            job.completed_at = datetime.now(timezone.utc)
            job.error = "Backend restarted before reconnaissance execution completed."
            await write_audit_log(
                db, project_id=job.project_id, user=job.approved_by or job.requested_by,
                action="execution_failed", entity_type="security_job", entity_id=job.id,
                target=job.target_snapshot.get("target"),
                details={"reason": job.error, "process_status": "interrupted"},
            )
        if rows:
            await db.commit()


async def _execute_job(job_id: int) -> None:
    async with AsyncSessionLocal() as db:
        job = await db.get(SecurityJob, job_id)
        if job is None or job.status != "queued":
            return
        target = job.target_snapshot["target"]
        decision = await security_authorization.validate_target(
            db, job.project_id, target, job.asset_id)
        await write_audit_log(db, project_id=job.project_id, user=job.requested_by,
                              action="authorization_checked", entity_type="security_job",
                              entity_id=job.id, target=target,
                              details={"allowed": decision.allowed, "reason": decision.reason,
                                       "phase": "execution"})
        if not decision.allowed:
            job.status, job.error = "blocked", decision.reason
            await write_audit_log(db, project_id=job.project_id, user=job.requested_by,
                                  action="scope_rejected", entity_type="security_job",
                                  entity_id=job.id, target=target, details={"reason": decision.reason})
            if any(item.get("key") == "tls_inspector"
                   for item in job.profile_snapshot.get("tools", [])):
                await write_audit_log(
                    db, project_id=job.project_id, user=job.requested_by,
                    action="tls_authorization_rejected", entity_type="security_job",
                    entity_id=job.id, target=target,
                    details={"allowed": False, "reason": decision.reason},
                )
            if any(item.get("key") == "web_surface_discovery"
                   for item in job.profile_snapshot.get("tools", [])):
                await write_audit_log(
                    db, project_id=job.project_id, user=job.requested_by,
                    action="web_surface_authorization_rejected", entity_type="security_job",
                    entity_id=job.id, target=target,
                    details={"allowed": False, "reason": decision.reason},
                )
            await db.commit()
            return
        profile = await db.get(ScanProfile, job.profile_id)
        saved_module_ids = {item["id"] for item in job.profile_snapshot.get("modules", [])}
        current_module_ids = set((await db.scalars(select(scan_profile_modules.c.module_id).where(
            scan_profile_modules.c.profile_id == job.profile_id))).all())
        selected_modules = list((await db.scalars(select(TestModule).where(
            TestModule.id.in_(saved_module_ids)))).all()) if saved_module_ids else []
        catalog_error = None
        if profile is None or not profile.enabled or (profile.project_id not in (None, job.project_id)):
            catalog_error = "Selected profile is no longer enabled for this project."
        elif current_module_ids.intersection(saved_module_ids) != saved_module_ids:
            catalog_error = "Selected profile modules changed after approval."
        elif len(selected_modules) != len(saved_module_ids) or any(not item.enabled for item in selected_modules):
            catalog_error = "A selected module was removed or disabled after approval."
        if catalog_error:
            job.status, job.error, job.completed_at = "blocked", catalog_error, datetime.now(timezone.utc)
            await write_audit_log(db, project_id=job.project_id, user=job.approved_by or job.requested_by,
                                  action="execution_failed", entity_type="security_job",
                                  entity_id=job.id, target=target, details={"reason": catalog_error})
            await db.commit()
            return
        chosen = job.profile_snapshot.get("tools", [])
        tool_rows = list((await db.scalars(select(Tool).options(selectinload(Tool.modules)).where(
            Tool.id.in_([item["id"] for item in chosen])))).all()) if chosen else []
        if not chosen or len(tool_rows) != len(chosen):
            job.status, job.error = "failed", "No registered recon tool is selected."
            await write_audit_log(db, project_id=job.project_id, user=job.requested_by,
                                  action="execution_failed", entity_type="security_job",
                                  entity_id=job.id, target=target, details={"reason": job.error})
            await db.commit()
            return
        module_id = (job.profile_snapshot.get("modules") or [{}])[0].get("id")
        profile_timeout = min(300, max(1, int(job.profile_snapshot.get("default_timeout", 60))))
        requested_timeout = job.parameters.get("timeout", profile_timeout)
        timeout = min(profile_timeout, max(1, int(requested_timeout)))
        job.status, job.started_at = "running", datetime.now(timezone.utc)
        await write_audit_log(db, project_id=job.project_id, user=job.approved_by or job.requested_by,
                              action="execution_started", entity_type="security_job",
                              entity_id=job.id, target=target,
                              details={"tool_keys": [row.key for row in tool_rows]})
        operation_limits = {
            "tls_inspector": ("tls_execution_started", {"port": 443}),
            "web_surface_discovery": ("web_surface_execution_started", {
                "fixed_paths": True, "max_paths": job.parameters.get("max_paths", 5)}),
            "tcp_service_awareness": ("service_awareness_execution_started", {
                "ports": job.parameters.get("ports", [22, 80, 443, 445, 8080, 8443]),
                "per_connection_timeout": min(timeout, 3)}),
        }
        for operation_tool in tool_rows:
            if operation_tool.key in operation_limits:
                action, limits = operation_limits[operation_tool.key]
                await write_audit_log(
                    db, project_id=job.project_id, user=job.approved_by or job.requested_by,
                    action=action, entity_type="security_job", entity_id=job.id,
                    target=target, details=limits,
                )
        await db.commit()

        final_state = "completed"
        failure = None
        run_metadata = []
        for tool in tool_rows:
            adapter = adapter_registry.get_for_tool(tool.key)
            available, reason = adapter_registry.check_tool(tool.key, tool.executable)
            supported_ids = {module.id for module in tool.modules}
            tool_module_id = next(iter(sorted(supported_ids.intersection(saved_module_ids))), None)
            if not tool.enabled or not tool.local_only or adapter is None or not available or (
                    supported_ids and tool_module_id is None):
                final_state = "failed"
                failure = reason if adapter is not None else f"No execution adapter is registered for '{tool.key}'."
                if not tool.enabled:
                    failure = f"Selected tool '{tool.key}' is disabled."
                elif not tool.local_only:
                    failure = f"Selected tool '{tool.key}' is not local-only."
                elif supported_ids and tool_module_id is None:
                    failure = f"Selected tool '{tool.key}' no longer supports the selected modules."
                break
            try:
                if tool.key == "web_surface_discovery":
                    tool_timeout = min(timeout, 8)
                elif tool.key == "tcp_service_awareness":
                    tool_timeout = min(timeout, 3)
                else:
                    tool_timeout = timeout
                adapter_parameters = {**job.parameters, "timeout": tool_timeout,
                                      "executable": tool.executable}
                plans = adapter.build_execution_plans(target, adapter_parameters)
                planned_results: list[tuple[ExecutionPlan, ProcessResult]] = []
                batch_started = asyncio.get_running_loop().time()
                if tool.key == "tls_inspector":
                    plan = plans[0]
                    started = datetime.now(timezone.utc)
                    metadata = await adapter.inspect(plan.target, min(timeout, plan.timeout))
                    ended = datetime.now(timezone.utc)
                    tls_error = metadata.get("connection_error")
                    tls_status = "timed_out" if tls_error == "TLS connection timed out." else (
                        "failed" if tls_error else "completed")
                    planned_results.append((plan, ProcessResult(
                        json.dumps(metadata, sort_keys=True), tls_error or "", 0 if not tls_error else 1,
                        started, ended, tls_status)))
                elif tool.key == "web_surface_discovery":
                    plan = plans[0]

                    async def authorize_web_request(request_host: str, request_url: str):
                        async with AsyncSessionLocal() as auth_db:
                            request_decision = await security_authorization.validate_derived_target(
                                auth_db, job.project_id, request_host)
                            await write_audit_log(
                                auth_db, project_id=job.project_id,
                                user=job.approved_by or job.requested_by,
                                action="authorization_checked", entity_type="security_job",
                                entity_id=job.id, target=request_url,
                                details={"allowed": request_decision.allowed,
                                         "reason": request_decision.reason,
                                         "phase": "web_surface_request"},
                            )
                            if request_decision.allowed:
                                await write_audit_log(
                                    auth_db, project_id=job.project_id,
                                    user=job.approved_by or job.requested_by,
                                    action="web_surface_endpoint_requested",
                                    entity_type="security_job", entity_id=job.id,
                                    target=request_url,
                                    details={"hostname": request_host},
                                )
                            else:
                                await write_audit_log(
                                    auth_db, project_id=job.project_id,
                                    user=job.approved_by or job.requested_by,
                                    action="web_surface_authorization_rejected",
                                    entity_type="security_job", entity_id=job.id,
                                    target=request_url,
                                    details={"reason": request_decision.reason},
                                )
                            await auth_db.commit()
                            return request_decision.allowed, request_decision.reason

                    started = datetime.now(timezone.utc)
                    max_paths = job.parameters.get("max_paths", 5)
                    if max_paths == 5:
                        metadata = await adapter.inspect(plan.target, tool_timeout, authorize_web_request)
                    else:
                        metadata = await adapter.inspect(plan.target, tool_timeout, authorize_web_request,
                                                         max_paths=max_paths)
                    ended = datetime.now(timezone.utc)
                    successful = any(item.get("http_status") is not None
                                     for item in metadata.get("endpoints", []))
                    process_status = "completed" if successful else "failed"
                    errors = [item.get("error") for item in metadata.get("endpoints", [])
                              if item.get("error")]
                    planned_results.append((plan, ProcessResult(
                        json.dumps(metadata, sort_keys=True), "\n".join(errors)[:2000],
                        0 if successful else 1, started, ended, process_status)))
                elif tool.key == "tcp_service_awareness":
                    plan = plans[0]

                    async def authorize_tcp_port(request_target: str, port: int):
                        async with AsyncSessionLocal() as auth_db:
                            decision = await security_authorization.validate_target(
                                auth_db, job.project_id, request_target, job.asset_id)
                            await write_audit_log(
                                auth_db, project_id=job.project_id,
                                user=job.approved_by or job.requested_by,
                                action="authorization_checked", entity_type="security_job",
                                entity_id=job.id, target=request_target,
                                details={"allowed": decision.allowed, "reason": decision.reason,
                                         "port": port, "phase": "service_port_request"})
                            if decision.allowed:
                                await write_audit_log(
                                    auth_db, project_id=job.project_id,
                                    user=job.approved_by or job.requested_by,
                                    action="service_port_requested", entity_type="security_job",
                                    entity_id=job.id, target=request_target,
                                    details={"port": port, "protocol": "tcp"})
                            await auth_db.commit()
                            return decision.allowed

                    started = datetime.now(timezone.utc)
                    metadata = await adapter.inspect(
                        plan.target, tool_timeout, job.parameters.get("ports", list(adapter.ALLOWED_PORTS)),
                        authorize_tcp_port)
                    ended = datetime.now(timezone.utc)
                    planned_results.append((plan, ProcessResult(
                        json.dumps(metadata, sort_keys=True), "", 0, started, ended, "completed")))
                else:
                 for plan in plans:
                    remaining = min(plan.timeout, timeout - (asyncio.get_running_loop().time() - batch_started))
                    if remaining <= 0:
                        now = datetime.now(timezone.utc)
                        planned_results.append((plan, ProcessResult(
                            "", "Overall tool timeout reached.", -1, now, now, "timed_out")))
                        break
                    result = await run_process(replace(plan, timeout=max(0.1, remaining)), job_id)
                    planned_results.append((plan, result))
                    if result.status in {"timed_out", "cancelled"} or (
                            result.status == "failed" and tool.key != "windows_nslookup"):
                        break
                if not planned_results:
                    raise RuntimeError("The registered adapter generated no execution plans.")
                stdout = "\n".join(
                    f"[plan {index + 1}: {plan.metadata}]\n{result.stdout}"
                    for index, (plan, result) in enumerate(planned_results))
                stderr = "\n".join(result.stderr for _, result in planned_results if result.stderr)
                statuses = [result.status for _, result in planned_results]
                process_status = next((item for item in statuses if item != "completed"), "completed")
                first = planned_results[0][1]
                last = planned_results[-1][1]
                exit_code = next((item.exit_code for _, item in planned_results if item.status != "completed"), 0)
                result = ProcessResult(stdout, stderr, exit_code, first.started_at, last.ended_at,
                                       process_status)
                combined = _sanitize_evidence_output(tool.key, planned_results)
                data_dir = get_data_dir()
                data_root = data_dir.resolve()
                artifact_dir = (data_root / "evidence" / "recon").resolve()
                if artifact_dir == data_root or data_root not in artifact_dir.parents:
                    raise RuntimeError("Evidence directory escaped the configured application data directory.")
                artifact_dir.mkdir(parents=True, exist_ok=True)
                artifact = (artifact_dir / f"job-{job_id}-{tool.key}.txt").resolve()
                if artifact_dir not in artifact.parents:
                    raise RuntimeError("Evidence path escaped the configured data directory.")
                with artifact.open("xb") as artifact_file:
                    artifact_file.write(combined[:MAX_OUTPUT_BYTES].encode("utf-8"))
                digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
                parsed = []
                malformed_lines = []
                for plan, process_result in planned_results:
                    if tool.key == "subfinder":
                        current_parsed, malformed = _parse_subfinder_output(
                            process_result.stdout, tool.key, job.parameters.get("max_results", 100))
                        malformed_lines.extend(malformed)
                    else:
                        current_parsed = parse_output(tool.key, target, process_result.stdout, plan.metadata)
                    parsed.extend(current_parsed)
                # Preserve deterministic unique results when DNS replies repeat a value.
                unique_parsed = []
                seen_result_keys = set()
                for item in parsed:
                    if tool.key == "web_surface_discovery":
                        key = (item["result_type"], item["data"].get("url"),
                               item["data"].get("endpoint_url"), item["data"].get("technology"),
                               item["data"].get("observation_type"), item["title"])
                    else:
                        key = (item["result_type"], item["data"].get("record_type"),
                               item["data"].get("hostname"), item["data"].get("value"),
                               item["data"].get("ip"), item["title"])
                    if key not in seen_result_keys:
                        seen_result_keys.add(key)
                        unique_parsed.append(item)
                parsed = unique_parsed
                async with AsyncSessionLocal() as write_db:
                    current = await write_db.get(SecurityJob, job_id)
                    accepted = []
                    rejected = []
                    for item in parsed:
                        hostname = (item["data"].get("hostname") if item["result_type"] == "subdomain"
                                    else item["data"].get("candidate_hostname"))
                        if hostname:
                            decision = await security_authorization.validate_derived_target(
                                write_db, current.project_id, hostname)
                            parent_host = target.lower().rstrip(".")
                            normalized_hostname = hostname.lower().rstrip(".")
                            child_only = (item["result_type"] != "subdomain" or
                                          normalized_hostname == parent_host or
                                          normalized_hostname.endswith("." + parent_host))
                            if decision.allowed and child_only:
                                item["data"]["authorization_status"] = "authorized"
                                if item["result_type"] == "subdomain":
                                    item["data"]["parent_target"] = target
                                accepted.append(item)
                            else:
                                reason = decision.reason if not decision.allowed else "Candidate is not a subdomain of the selected root domain."
                                rejected.append({"hostname": hostname, "reason": reason})
                                await write_audit_log(
                                    write_db, project_id=current.project_id,
                                    user=current.approved_by or current.requested_by,
                                    action="derived_result_scope_rejected",
                                    entity_type="security_job", entity_id=current.id,
                                    target=hostname,
                                    details={"reason": reason, "parent_target": target,
                                             "source_tool": tool.key},
                                )
                        else:
                            accepted.append(item)
                    for item in accepted:
                        if tool.key == "web_surface_discovery":
                            item["data"]["asset_id"] = current.asset_id
                        if item["result_type"] == "subdomain":
                            hostname = item["data"]["hostname"]
                            current_assets = list((await write_db.scalars(select(Asset).where(
                                Asset.project_id == current.project_id))).all())
                            existing_asset = next((asset for asset in current_assets
                                if asset.value.strip().lower().rstrip(".") == hostname), None)
                            if existing_asset is None:
                                existing_asset = Asset(project_id=current.project_id, value=hostname,
                                                       asset_type="domain", source=f"security_job:{current.id}")
                                write_db.add(existing_asset)
                                await write_db.flush()
                            item["data"]["asset_id"] = existing_asset.id
                        record = SecurityResult(
                            project_id=current.project_id, job_id=current.id,
                            tool_id=tool.id, module_id=tool_module_id or module_id, target=target,
                            result_type=item["result_type"], title=item["title"],
                            summary=item["summary"], raw_reference=str(artifact),
                            normalized_data=item["data"],
                        )
                        write_db.add(record)
                    write_db.add(Evidence(
                        project_id=current.project_id, job_id=current.id,
                        evidence_type="tool_output", title=f"{tool.name} output",
                        description="Captured stdout/stderr from the registered adapter.",
                        path_reference=str(artifact), content_hash=digest,
                        metadata_json={"tool_key": tool.key, "exit_code": result.exit_code,
                                      "status": result.status,
                                      "started_at": result.started_at.isoformat(),
                                      "ended_at": result.ended_at.isoformat(),
                                      "stdout_bytes": len(stdout.encode()),
                                      "stderr_bytes": len(stderr.encode()),
                                      "discovered_hosts": len(parsed),
                                      "accepted_hosts": len(accepted),
                                      "rejected_by_scope": rejected},
                    ))
                    await write_audit_log(
                        write_db, project_id=current.project_id,
                        user=current.approved_by or current.requested_by,
                        action=("subfinder_results_processed" if tool.key == "subfinder" else
                                "tls_inspection_results_processed" if tool.key == "tls_inspector" else
                                "service_awareness_results_processed" if tool.key == "tcp_service_awareness" else
                                "web_surface_results_processed" if tool.key == "web_surface_discovery" else
                                "tool_results_processed"),
                        entity_type="security_job", entity_id=current.id, target=target,
                        details={"discovered": len(parsed), "accepted": len(accepted),
                                 "rejected_by_scope": len(rejected), "rejections": rejected,
                                 "malformed_lines": len(malformed_lines),
                                 "malformed_examples": malformed_lines[:100]},
                    )
                    if tool.key == "web_surface_discovery":
                        surface_payload = json.loads(planned_results[0][1].stdout)
                        for event in surface_payload.get("events", []):
                            event_name = event.get("event")
                            if event_name == "redirect_blocked":
                                await write_audit_log(
                                    write_db, project_id=current.project_id,
                                    user=current.approved_by or current.requested_by,
                                    action="web_surface_redirect_blocked",
                                    entity_type="security_job", entity_id=current.id,
                                    target=event.get("from_url"),
                                    details={"to_host": event.get("to_host"),
                                             "reason": event.get("reason")},
                                )
                            elif event_name == "fingerprint_detected":
                                await write_audit_log(
                                    write_db, project_id=current.project_id,
                                    user=current.approved_by or current.requested_by,
                                    action="web_surface_fingerprint_detected",
                                    entity_type="security_job", entity_id=current.id,
                                    target=target,
                                    details={"technology": event.get("technology"),
                                             "confidence": event.get("confidence"),
                                             "evidence_count": event.get("evidence_count")},
                                )
                    if malformed_lines:
                        await write_audit_log(
                            write_db, project_id=current.project_id,
                            user=current.approved_by or current.requested_by,
                            action="tool_output_malformed", entity_type="security_job",
                            entity_id=current.id, target=target,
                            details={"tool_key": tool.key, "count": len(malformed_lines),
                                     "examples": malformed_lines[:100]},
                        )
                    await write_db.commit()
                run_metadata.append({"tool_key": tool.key, "status": result.status,
                                     "exit_code": result.exit_code, "evidence": str(artifact),
                                     "started_at": result.started_at.isoformat(),
                                     "ended_at": result.ended_at.isoformat(),
                                     "discovered": len(parsed), "accepted": len(accepted),
                                     "rejected_by_scope": len(rejected),
                                     "malformed_lines": len(malformed_lines)})
                if result.status != "completed":
                    final_state = result.status
                    failure = f"{tool.name} exited with status {result.status} (code {result.exit_code})."
                    break
            except asyncio.CancelledError:
                raise
            except Exception as error:
                final_state, failure = "failed", f"{tool.name}: {error}"
                break
        async with AsyncSessionLocal() as finish_db:
            job = await finish_db.get(SecurityJob, job_id)
            if job is None:
                return
            job.status, job.completed_at, job.error = final_state, datetime.now(timezone.utc), failure
            await write_audit_log(
                finish_db, project_id=job.project_id, user=job.approved_by or job.requested_by,
                action="execution_completed" if final_state == "completed" else
                       "execution_timed_out" if final_state == "timed_out" else "execution_failed",
                entity_type="security_job", entity_id=job.id, target=target,
                details={"status": final_state, "error": failure, "tools": run_metadata})
            if any(item.get("key") == "tls_inspector"
                   for item in job.profile_snapshot.get("tools", [])):
                await write_audit_log(
                    finish_db, project_id=job.project_id,
                    user=job.approved_by or job.requested_by,
                    action=("tls_execution_completed" if final_state == "completed"
                            else "tls_execution_failed"),
                    entity_type="security_job", entity_id=job.id, target=target,
                    details={"status": final_state, "error": failure},
                )
            if any(item.get("key") == "web_surface_discovery"
                   for item in job.profile_snapshot.get("tools", [])):
                await write_audit_log(
                    finish_db, project_id=job.project_id,
                    user=job.approved_by or job.requested_by,
                    action=("web_surface_execution_completed" if final_state == "completed"
                            else "web_surface_execution_failed"),
                    entity_type="security_job", entity_id=job.id, target=target,
                    details={"status": final_state, "error": failure},
                )
            if any(item.get("key") == "tcp_service_awareness"
                   for item in job.profile_snapshot.get("tools", [])):
                await write_audit_log(
                    finish_db, project_id=job.project_id,
                    user=job.approved_by or job.requested_by,
                    action=("service_awareness_execution_completed" if final_state == "completed"
                            else "service_awareness_execution_failed"),
                    entity_type="security_job", entity_id=job.id, target=target,
                    details={"status": final_state, "error": failure},
                )
            await finish_db.commit()


async def _mark_cancelled(job_id: int) -> None:
    async with AsyncSessionLocal() as db:
        job = await db.get(SecurityJob, job_id)
        if job is not None and job.status in {"queued", "running"}:
            job.status, job.completed_at = "cancelled", datetime.now(timezone.utc)
            await write_audit_log(db, project_id=job.project_id, user=job.approved_by or job.requested_by,
                                  action="execution_cancelled", entity_type="security_job",
                                  entity_id=job.id, target=job.target_snapshot.get("target"), details={})
            await db.commit()
