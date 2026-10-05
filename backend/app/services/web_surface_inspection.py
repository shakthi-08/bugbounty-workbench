"""Bounded, same-host HTTP surface inspection and conservative fingerprinting."""
import asyncio
from datetime import datetime, timezone
from html.parser import HTMLParser
import ipaddress
import re
import ssl
import time
from typing import Awaitable, Callable
from urllib.parse import urljoin, urlsplit, urlunsplit


DISCOVERY_PATHS = ("/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/security.txt")
# Additional fixed candidates for the explicitly selected Phase 13 endpoint mode.
# This remains a static allowlist; callers cannot provide arbitrary paths.
EXTENDED_DISCOVERY_PATHS = DISCOVERY_PATHS + (
    "/.well-known/change-password", "/openapi.json", "/swagger.json",
    "/api/", "/health", "/status", "/login",
)
MAX_REDIRECTS = 2
MAX_RESPONSE_BYTES = 65_536
MAX_HEADER_BYTES = 32_768
MAX_TOTAL_SECONDS = 60
MAX_TIMEOUT_SECONDS = 8
USER_AGENT = "BugBountyWorkbench/1.0 (bounded authorized assessment)"


class _MetaParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.generators: list[str] = []
        self.scripts: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = {str(key).lower(): value for key, value in attrs}
        if tag.lower() == "meta" and (attrs.get("name") or "").lower() == "generator":
            content = attrs.get("content")
            if content:
                self.generators.append(str(content)[:200])
        elif tag.lower() == "script" and attrs.get("src"):
            self.scripts.append(str(attrs["src"])[:500])
        elif tag.lower() == "link" and attrs.get("href"):
            self.links.append(str(attrs["href"])[:500])


def _canonical_host(url: str) -> str:
    parsed = urlsplit(url if "://" in url else "https://" + url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or any(ord(char) < 32 for char in url)):
        raise ValueError("Web surface target must be a plain HTTP(S) host or URL.")
    try:
        hostname = str(ipaddress.ip_address(parsed.hostname))
    except ValueError:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if len(hostname) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in hostname.split(".")
        ):
            raise ValueError("Web surface target hostname is invalid.")
    return hostname


def canonical_base_url(target: str) -> str:
    parsed = urlsplit(target if "://" in target else "https://" + target)
    host = _canonical_host(target)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Web surface target contains an invalid port.") from error
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Web surface target contains an invalid port.")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "/", "", ""))


async def _within_deadline(awaitable, deadline: float):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise asyncio.TimeoutError
    return await asyncio.wait_for(awaitable, timeout=remaining)


def _response_headers(block: bytes) -> tuple[int, dict[str, str]]:
    lines = block.decode("iso-8859-1", errors="replace").split("\r\n")
    match = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})\b", lines[0] if lines else "")
    if not match:
        raise ValueError("HTTP response status line is invalid.")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()[:1000]
        if name in {"content-type", "content-length", "server", "x-powered-by", "location",
                    "strict-transport-security", "x-frame-options", "content-security-policy",
                    "x-content-type-options", "referrer-policy", "permissions-policy",
                    "set-cookie", "transfer-encoding"}:
            if name == "set-cookie":
                cookie_name = value.split("=", 1)[0].strip()[:100]
                if cookie_name:
                    headers.setdefault("cookie_names", "")
                    names = [part for part in headers["cookie_names"].split(",") if part]
                    if cookie_name not in names:
                        names.append(cookie_name)
                    headers["cookie_names"] = ",".join(names)[:500]
                # Preserve only parsed attributes; cookie values never leave this parser.
                parts = [part.strip() for part in value.split(";")]
                attrs = {part.split("=", 1)[0].strip().lower():
                         (part.split("=", 1)[1].strip() if "=" in part else True)
                         for part in parts[1:] if part}
                if cookie_name:
                    headers.setdefault("cookie_security", []).append({
                        "name": cookie_name, "secure": "secure" in attrs,
                        "httponly": "httponly" in attrs,
                        "samesite": str(attrs.get("samesite", "")).lower() or None,
                    })
            elif name in {"server", "x-powered-by", "content-type", "content-length", "location"}:
                headers.setdefault(name, value)
            else:
                headers.setdefault(name, value)
    return int(match.group(1)), headers


async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str], deadline: float):
    captured = bytearray()
    content_length = None
    raw_length = headers.get("content-length")
    if raw_length is not None:
        try:
            content_length = max(0, int(raw_length))
        except ValueError:
            content_length = None
    truncated = content_length is not None and content_length > MAX_RESPONSE_BYTES
    transfer = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer:
        while len(captured) < MAX_RESPONSE_BYTES:
            line = await _within_deadline(reader.readline(), deadline)
            size_text = line.split(b";", 1)[0].strip()
            if not size_text or len(size_text) > 16:
                raise ValueError("Chunked HTTP response has an invalid chunk length.")
            size = int(size_text, 16)
            if size == 0:
                break
            take = min(size, MAX_RESPONSE_BYTES - len(captured))
            captured.extend(await _within_deadline(reader.readexactly(take), deadline))
            if take < size:
                truncated = True
                break
            await _within_deadline(reader.readexactly(2), deadline)
    elif content_length is not None:
        take = min(content_length, MAX_RESPONSE_BYTES)
        if take:
            captured.extend(await _within_deadline(reader.readexactly(take), deadline))
    else:
        while len(captured) < MAX_RESPONSE_BYTES:
            chunk = await _within_deadline(reader.read(min(8192, MAX_RESPONSE_BYTES - len(captured))), deadline)
            if not chunk:
                break
            captured.extend(chunk)
        if len(captured) == MAX_RESPONSE_BYTES:
            truncated = True
    # If the cap is exactly filled, the inspector does not read ahead to learn
    # whether the peer had more bytes; report the conservative bounded state.
    if len(captured) >= MAX_RESPONSE_BYTES:
        truncated = True
    return bytes(captured), content_length, truncated


async def _single_request(url: str, timeout: int):
    parsed = urlsplit(url)
    host = parsed.hostname
    if host is None:
        raise ValueError("HTTP URL has no hostname.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    deadline = time.monotonic() + timeout
    context = ssl.create_default_context() if parsed.scheme == "https" else None
    reader = writer = None
    started = time.monotonic()
    try:
        reader, writer = await _within_deadline(asyncio.open_connection(
            host, port, ssl=context, server_hostname=host if context else None,
            limit=MAX_HEADER_BYTES,
        ), deadline)
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        host_header = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            host_header += f":{parsed.port}"
        request = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                   f"User-Agent: {USER_AGENT}\r\nAccept: text/html,application/xhtml+xml,*/*;q=0.1\r\n"
                   "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii")
        writer.write(request)
        await _within_deadline(writer.drain(), deadline)
        block = await _within_deadline(reader.readuntil(b"\r\n\r\n"), deadline)
        if len(block) > MAX_HEADER_BYTES:
            raise ValueError("HTTP response headers exceeded the size limit.")
        status, headers = _response_headers(block[:-4])
        body, content_length, truncated = await _read_body(reader, headers, deadline)
        return {"status": status, "headers": headers, "body": body,
                "content_length": content_length, "truncated": truncated,
                "response_bytes": len(body), "duration_ms": round((time.monotonic() - started) * 1000)}
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.25)
            except (asyncio.TimeoutError, OSError, ssl.SSLError):
                pass


def _normalize_redirect(current_url: str, location: str) -> tuple[str | None, str]:
    candidate = urljoin(current_url, location)
    parsed = urlsplit(candidate)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None or parsed.query):
        return None, "unsupported_or_query_redirect"
    try:
        host = _canonical_host(candidate)
    except (UnicodeError, ValueError):
        return None, "invalid_redirect_host"
    try:
        port = parsed.port
    except ValueError:
        return None, "invalid_redirect_port"
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if parsed.scheme == "https" else 80):
        netloc += f":{port}"
    normalized = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))
    return normalized, "ok"


def _fingerprints(url: str, host: str, headers: dict[str, str], body: bytes,
                  content_type: str | None = None) -> list[dict]:
    found: dict[str, dict] = {}

    def add(name: str, confidence: str, evidence: str):
        row = found.setdefault(name, {"technology": name, "confidence": confidence, "evidence": []})
        if row["confidence"] != "high" and confidence == "high":
            row["confidence"] = "high"
        elif row["confidence"] == "low" and confidence == "medium":
            row["confidence"] = "medium"
        if evidence not in row["evidence"]:
            row["evidence"].append(evidence[:300])

    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    for pattern, technology in ((r"nginx", "nginx"), (r"apache", "Apache"),
                                (r"\biis\b|microsoft-iis", "IIS"), (r"caddy", "Caddy"),
                                (r"litespeed", "LiteSpeed")):
        if re.search(pattern, server, re.I):
            add(technology, "high", f"Server header identified {server[:160]}.")
    for pattern, technology in ((r"express", "Express"), (r"php", "PHP"),
                                (r"asp\.net", "ASP.NET"), (r"django", "Django"),
                                (r"flask", "Flask"), (r"laravel", "Laravel")):
        if re.search(pattern, powered, re.I):
            add(technology, "high", f"X-Powered-By header identified {powered[:160]}.")
    cookies = headers.get("cookie_names", "").split(",")
    for cookie, technology, evidence in (
        ("PHPSESSID", "PHP", "PHPSESSID cookie name observed."),
        ("laravel_session", "Laravel", "laravel_session cookie name observed."),
        ("connect.sid", "Express", "connect.sid cookie name observed."),
        ("csrftoken", "Django", "csrftoken cookie name observed."),
        ("sessionid", "Django", "sessionid cookie name observed."),
        ("ASP.NET_SessionId", "ASP.NET", "ASP.NET_SessionId cookie name observed."),
    ):
        if cookie.lower() in {value.lower() for value in cookies}:
            add(technology, "medium", evidence)

    if content_type and "html" in content_type.lower():
        sample = body.decode("utf-8", errors="replace")[:MAX_RESPONSE_BYTES]
        parser = _MetaParser()
        try:
            parser.feed(sample)
        except Exception:
            pass
        for generator in parser.generators:
            for pattern, technology in ((r"wordpress", "WordPress"), (r"drupal", "Drupal"),
                                        (r"joomla", "Joomla")):
                if re.search(pattern, generator, re.I):
                    add(technology, "high", f"HTML generator marker: {generator}.")
        if re.search(r"/(?:wp-content|wp-includes)/", sample, re.I):
            add("WordPress", "medium", "HTML referenced a /wp-content/ or /wp-includes/ asset.")
        if "__NEXT_DATA__" in sample or any("/_next/" in item for item in parser.scripts + parser.links):
            add("Next.js", "medium", "HTML contained a __NEXT_DATA__ or /_next/ marker.")
        if re.search(r"\bdata-reactroot\b", sample, re.I):
            add("React", "medium", "HTML contained a data-reactroot marker.")
        if re.search(r"\bng-version\s*=", sample, re.I):
            add("Angular", "medium", "HTML contained an ng-version marker.")
        if re.search(r"\bdata-v-[0-9a-f]{4,}\b", sample, re.I):
            add("Vue.js", "low", "HTML contained a Vue-style scoped data-v marker.")
        if any(re.search(r"(?:^|/)jquery(?:[-.]|/)", item, re.I) for item in parser.scripts + parser.links):
            add("jQuery", "medium", "HTML referenced a jQuery-named script or asset.")
    return [dict(row, endpoint_url=url, hostname=host) for row in found.values()]


class WebSurfaceInspectionService:
    async def inspect(self, target: str, timeout: int, authorize: Callable[[str, str], Awaitable[tuple[bool, str]]],
                      max_paths: int = len(DISCOVERY_PATHS)):
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"Web surface timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds.")
        if isinstance(max_paths, bool) or not isinstance(max_paths, int) or not 1 <= max_paths <= len(EXTENDED_DISCOVERY_PATHS):
            raise ValueError(f"Endpoint path limit must be between 1 and {len(EXTENDED_DISCOVERY_PATHS)}.")
        base_url = canonical_base_url(target)
        selected_host = _canonical_host(base_url)
        timeout = min(timeout, MAX_TIMEOUT_SECONDS)
        total_deadline = time.monotonic() + MAX_TOTAL_SECONDS
        endpoints = []
        technologies = []
        events = []
        path_list = (DISCOVERY_PATHS if max_paths <= len(DISCOVERY_PATHS) else EXTENDED_DISCOVERY_PATHS)[:max_paths]
        for path in path_list:
            current_url = urljoin(base_url, path.lstrip("/"))
            redirects = []
            response = None
            outcome = None
            for redirect_count in range(MAX_REDIRECTS + 1):
                if time.monotonic() >= total_deadline:
                    outcome = "Overall web surface time limit reached."
                    break
                parsed = urlsplit(current_url)
                host = _canonical_host(current_url)
                if host != selected_host:
                    outcome = "Redirect blocked because it left the selected authorized host."
                    events.append({"event": "redirect_blocked", "from_url": redirects[-1]["to_url"] if redirects else None,
                                   "to_host": host, "reason": "different_host"})
                    break
                allowed, reason = await authorize(host, current_url)
                if not allowed:
                    outcome = f"Request blocked by current scope authorization: {reason}"
                    events.append({"event": "authorization_rejected", "url": current_url, "reason": reason})
                    break
                events.append({"event": "endpoint_requested", "url": current_url,
                               "request_type": "redirect" if redirects else "discovery_path"})
                try:
                    response = await asyncio.wait_for(_single_request(current_url, timeout),
                                                       timeout=min(timeout + 0.5, max(0.1, total_deadline - time.monotonic())))
                except asyncio.TimeoutError:
                    outcome = "HTTP request timed out."
                    break
                except (OSError, ssl.SSLError, ValueError, asyncio.IncompleteReadError,
                        asyncio.LimitOverrunError) as error:
                    outcome = f"{type(error).__name__}: {str(error)[:250]}"
                    break
                location = response["headers"].get("location")
                if response["status"] not in {301, 302, 303, 307, 308} or not location:
                    break
                normalized, redirect_error = _normalize_redirect(current_url, location)
                if normalized is None:
                    outcome = f"Redirect blocked: {redirect_error}."
                    events.append({"event": "redirect_blocked", "from_url": current_url,
                                   "to_host": None, "reason": redirect_error})
                    break
                next_host = _canonical_host(normalized)
                if next_host != selected_host:
                    outcome = "Redirect blocked because it left the selected authorized host."
                    events.append({"event": "redirect_blocked", "from_url": current_url,
                                   "to_host": next_host, "reason": "different_host"})
                    break
                base_port = urlsplit(base_url).port or (443 if urlsplit(base_url).scheme == "https" else 80)
                next_port = urlsplit(normalized).port or (443 if urlsplit(normalized).scheme == "https" else 80)
                if next_port not in {base_port, 80, 443}:
                    outcome = "Redirect blocked because it changed to an unapproved service port."
                    events.append({"event": "redirect_blocked", "from_url": current_url,
                                   "to_host": next_host, "reason": "different_service_port"})
                    break
                if redirect_count >= MAX_REDIRECTS:
                    outcome = "Redirect limit reached; no further request was made."
                    break
                redirects.append({"status": response["status"], "from_url": current_url,
                                  "to_url": normalized})
                current_url = normalized
            if response is not None:
                headers = response["headers"]
                endpoint = {
                    "hostname": selected_host, "url": urljoin(base_url, path.lstrip("/")),
                    "final_url": current_url, "http_status": response["status"],
                    "content_type": headers.get("content-type"),
                    "content_length": response["content_length"],
                    "response_bytes": response["response_bytes"], "truncated": response["truncated"],
                    "server": headers.get("server"), "powered_by": headers.get("x-powered-by"),
                    "security_headers": {key: headers[key] for key in (
                        "strict-transport-security", "x-frame-options", "content-security-policy",
                        "x-content-type-options", "referrer-policy", "permissions-policy") if key in headers},
                    "cookie_names": [item for item in headers.get("cookie_names", "").split(",") if item],
                    "cookie_security": headers.get("cookie_security", []),
                    "redirect_chain": redirects, "duration_ms": response["duration_ms"],
                    "inspected_at": datetime.now(timezone.utc).isoformat(),
                }
                endpoints.append(endpoint)
                technologies.extend(_fingerprints(current_url, selected_host, headers, response["body"],
                                                  headers.get("content-type")))
            if outcome:
                endpoints.append({"hostname": selected_host, "url": urljoin(base_url, path.lstrip("/")),
                                  "error": outcome, "redirect_chain": redirects})

        unique = {}
        for technology in technologies:
            current = unique.setdefault(technology["technology"], technology)
            if current is not technology:
                current["evidence"] = list(dict.fromkeys(current["evidence"] + technology["evidence"]))
                current["confidence"] = max((current["confidence"], technology["confidence"]),
                                             key={"low": 0, "medium": 1, "high": 2}.get)
                current.setdefault("observed_endpoints", [current["endpoint_url"]])
                if technology["endpoint_url"] not in current["observed_endpoints"]:
                    current["observed_endpoints"].append(technology["endpoint_url"])
        technologies = list(unique.values())
        for row in technologies:
            events.append({"event": "fingerprint_detected", "technology": row["technology"],
                           "confidence": row["confidence"], "evidence_count": len(row["evidence"])})
        return {"hostname": selected_host, "base_url": base_url, "endpoints": endpoints,
                "technologies": technologies, "events": events}


web_surface_inspection = WebSurfaceInspectionService()
