"""Deterministic bounded analysis of already stored, authorized HTTP observations."""
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

MAX_ENDPOINTS = 100
MAX_PARAMETERS = 50
MAX_FINDINGS = 100
MAX_SPEC_BYTES = 65536

def safe_endpoint(value):
    parsed = urlsplit(str(value))
    host = parsed.hostname or ""
    try:
        if parsed.port: host += f":{parsed.port}"
    except ValueError:
        pass
    return urlunsplit((parsed.scheme, host, parsed.path[:1000], "", ""))[:1200]


def extract_api_surface(spec, endpoint, *, max_parameters=MAX_PARAMETERS):
    """Normalize a bounded OpenAPI/Swagger document without resolving references."""
    if isinstance(spec, (str, bytes)):
        raw = spec.encode() if isinstance(spec, str) else spec
        if len(raw) > MAX_SPEC_BYTES:
            return {"error": "specification exceeds size limit", "endpoints": [], "parameters": []}
        try:
            spec = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return {"error": "malformed JSON specification", "endpoints": [], "parameters": []}
    if not isinstance(spec, dict):
        return {"error": "specification must be an object", "endpoints": [], "parameters": []}
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return {"error": "specification has no paths object", "endpoints": [], "parameters": []}
    methods = {"get", "head", "post", "put", "patch", "delete", "options"}
    rows, params = [], []
    for path, operations in list(paths.items())[:MAX_ENDPOINTS]:
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in methods or not isinstance(operation, dict):
                continue
            rows.append({"path": path[:1000], "method": method.upper(),
                         "security_required": bool(operation.get("security", spec.get("security", []))),
                         "operation_id": str(operation.get("operationId", ""))[:200]})
            for item in operation.get("parameters", [])[:max_parameters]:
                if isinstance(item, dict) and item.get("name"):
                    params.append({"endpoint": path[:1000], "method": method.upper(),
                        "name": str(item["name"])[:200], "location": str(item.get("in", "unknown"))[:30],
                        "source": "openapi", "authentication_required": bool(operation.get("security", spec.get("security", [])))})
    servers = []
    for item in (spec.get("servers", [])[:10] if isinstance(spec.get("servers", []), list) else []):
        if isinstance(item, dict) and item.get("url"):
            servers.append(safe_endpoint(item["url"]))
    return {"title": str(spec.get("info", {}).get("title", ""))[:200],
            "version": str(spec.get("info", {}).get("version", ""))[:100],
            "servers": servers,
            "security_schemes": list((spec.get("components", {}).get("securitySchemes", {}) or {}).keys())[:50],
            "endpoints": rows, "parameters": params[:MAX_ENDPOINTS * max_parameters]}


def assess_observation(data, project_id, asset_id, endpoint):
    """Return candidate findings from compact stored metadata; no network access."""
    headers = {str(k).lower(): v for k, v in (data.get("security_headers") or {}).items()}
    for key in ("access-control-allow-origin", "access-control-allow-credentials", "allow"):
        if key in data: headers[key] = data[key]
    out = []
    def add(category, title, severity, confidence, evidence, remediation):
        payload = {"project": project_id, "asset": asset_id, "endpoint": endpoint,
                   "category": category, "title": title}
        fp = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        out.append({"category": category, "title": title, "severity": severity,
            "confidence": confidence, "endpoint": endpoint,
            "description": title + ". Candidate based on an authorized stored observation; validate manually.",
            "evidence": evidence, "remediation": remediation, "fingerprint": fp})
    cookies = data.get("cookie_security") or []
    for cookie in cookies[:50]:
        name = str(cookie.get("name", "cookie"))[:100]
        sensitive = bool(re.search(r"session|auth|token|sid", name, re.I))
        missing = [x for x in ("secure", "httponly") if not cookie.get(x)]
        if sensitive and missing:
            add("cookie", f"Session cookie {name} lacks recommended attributes", "low", "medium",
                {"name": name, "missing": missing, "samesite": cookie.get("samesite")},
                "Set Secure and HttpOnly where applicable, and choose an appropriate SameSite policy.")
    origin = str(headers.get("access-control-allow-origin", ""))[:200]
    credentials = str(headers.get("access-control-allow-credentials", "")).lower()
    if origin == "*":
        add("cors", "CORS allows every origin", "low", "high", {"allow_origin": "*", "credentials": credentials == "true"},
            "Restrict allowed origins to trusted application origins.")
    if credentials == "true" and origin == "*":
        add("cors", "CORS combines wildcard origin with credentials", "medium", "high", {"allow_origin": "*", "credentials": True},
            "Use an explicit trusted origin allowlist and review credentialed cross-origin access.")
    for key, label in (("server", "Server"), ("powered_by", "X-Powered-By")):
        value = data.get(key)
        if value:
            add("information_disclosure", f"{label} header discloses technology information", "informational", "high",
                {"header": label, "value": str(value)[:120]}, "Remove unnecessary product and version details.")
    allow = str(data.get("allow") or headers.get("allow", "")).upper()
    dangerous = sorted({method.strip() for method in allow.split(",")} & {"TRACE", "CONNECT"})
    if dangerous:
        add("http_methods", "Unusual HTTP methods are advertised", "low", "medium", {"methods": dangerous},
            "Disable methods that the application does not require.")
    url = str(data.get("url") or endpoint)
    if urlsplit(url).scheme.lower() == "http" and data.get("final_url", "").startswith("https://") is False:
        add("transport_policy", "HTTP endpoint has no observed HTTPS upgrade", "low", "medium",
            {"url": url[:500], "status": data.get("http_status")}, "Redirect HTTP traffic to HTTPS and enable HSTS.")
    return out[:MAX_FINDINGS]


def extract_input_surface(data, endpoint):
    rows = []
    for name, _ in parse_qsl(urlsplit(str(endpoint)).query, keep_blank_values=True)[:MAX_PARAMETERS]:
        rows.append({"endpoint": safe_endpoint(endpoint), "method": "GET", "name": name[:200], "location": "query",
                     "source": "observed_url", "authentication_required": None})
    for param in (data.get("parameters") or [])[:MAX_PARAMETERS]:
        if isinstance(param, dict) and param.get("name"):
            rows.append({"endpoint": safe_endpoint(endpoint), "method": str(param.get("method", "GET"))[:10].upper(),
                "name": str(param["name"])[:200], "location": str(param.get("location", "unknown"))[:30],
                "source": str(param.get("source", "stored_metadata"))[:40],
                "authentication_required": param.get("authentication_required")})
    return rows[:MAX_PARAMETERS]
