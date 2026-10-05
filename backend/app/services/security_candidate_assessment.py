"""Conservative authentication, authorization, and vulnerability candidates.

This module analyzes previously stored observations only. It performs no I/O and
does not execute or send test payloads.
"""
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlsplit

MAX_SURFACES = 100
MAX_PARAMETERS = 50
MAX_EXCERPT = 2048

_SENSITIVE = re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?|bearer\s+)[^\s,;]+|"
    r"(?:api[_-]?key|token|password|secret|client_secret|access_token|refresh_token)[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?[^\s&;,\"'}]+|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_INTERNAL_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:internal|corp|local|lan|intranet)\b", re.I)
_PATH = re.compile(r"(?i)(?:[a-z]:\\[^\s\"']+|/(?:var|etc|home|usr|opt|srv)/[^\s\"']+)")


def sanitize_excerpt(value, limit=MAX_EXCERPT):
    text = str(value or "")[:limit]
    text = _SENSITIVE.sub("[REDACTED]", text)
    text = _INTERNAL_HOST.sub("[INTERNAL_HOST]", text)
    text = _PATH.sub("[PATH]", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def detect_excerpt_indicators(value):
    """Return only safe indicator labels so redacted secrets remain detectable."""
    text=str(value or "")[:MAX_EXCERPT]
    checks={
        "secret_like":r"(?i)(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|(?:api[_-]?key|token|password|secret|access_token)[\"']?\s*[:=])",
        "internal_hostname":_INTERNAL_HOST,
        "filesystem_path":_PATH,
        "stack_trace":r"(?i)(?:Traceback \(most recent call last\)| at [\w.$]+\([^\n]+:\d+\)|Exception in thread|stack trace)",
        "database_error":r"(?i)(?:SQLSTATE\[[0-9A-Z]+\]|\b(?:mysql|postgresql|sqlite|oracle)\b.{0,50}\b(?:error|exception)\b|syntax error.{0,60}(?:SQL|query))",
    }
    return [name for name,pattern in checks.items() if re.search(pattern,text)]


def _safe_url(url):
    parsed = urlsplit(str(url))
    host = parsed.hostname or ""
    try:
        if parsed.port: host += f":{parsed.port}"
    except ValueError:
        pass
    return f"{parsed.scheme}://{host}{parsed.path[:800]}" if parsed.scheme else parsed.path[:800]


def _fingerprint(project_id, asset_id, endpoint, category, detection, parameter=None):
    source = {"project":project_id,"asset":asset_id,"endpoint":_safe_url(endpoint),
              "category":category,"detection":detection,"parameter":parameter}
    return hashlib.sha256(json.dumps(source, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def analyze_security_observation(data, *, project_id, asset_id, endpoint, kind):
    """Return bounded normalized auth surfaces and evidence-backed candidates."""
    endpoint = _safe_url(endpoint)
    path = urlsplit(endpoint).path.lower()
    params = []
    for name, _ in parse_qsl(urlsplit(str(data.get("url") or endpoint)).query, keep_blank_values=True)[:MAX_PARAMETERS]:
        params.append({"name":name[:150],"location":"query"})
    api = data.get("api_spec_observation") or {}
    api_endpoints = api.get("endpoints", []) if isinstance(api, dict) else []
    for param in (api.get("parameters", []) if isinstance(api,dict) else [])[:MAX_PARAMETERS]:
        if isinstance(param,dict):
            params.append({"name":str(param.get("name", ""))[:150],
                "location":str(param.get("location", "unknown"))[:30],
                "endpoint":str(param.get("endpoint", ""))[:800],
                "authentication_required":param.get("authentication_required")})
    out=[]; surfaces=[]

    def add(category, detection, title, severity, confidence, reason, remediation,
            parameter=None, excerpt=None):
        if parameter:
            title = f"{title} ({str(parameter)[:100]})"
        evidence={"endpoint":endpoint,"method":data.get("method"),"status":data.get("http_status"),
            "parameter":parameter,"reason":reason,"source_result_id":data.get("source_result_id"),
            "excerpt":sanitize_excerpt(excerpt) if excerpt else None,
            "classification":"candidate requiring manual verification"}
        out.append({"category":category,"detection":detection,"title":title,"severity":severity,
            "confidence":confidence,"endpoint":endpoint,"description":reason +
            " This is an observation candidate requiring manual verification.","evidence":evidence,
            "remediation":remediation,"manual_verification":"Review the behavior using an explicitly authorized test account and non-destructive requests.",
            "fingerprint":_fingerprint(project_id,asset_id,endpoint,category,detection,parameter)})

    auth_match = re.search(r"login|log[-_]?in|sign[-_]?in|auth|oauth|token|session|logout|password|reset|recover|mfa|two[-_]?factor", path, re.I)
    if auth_match:
        surface_type = ("logout" if "logout" in path else "session" if "session" in path else
            "recovery" if any(x in path for x in ("reset","recover","password")) else
            "mfa" if re.search(r"mfa|two[-_]?factor", path) else "token" if "token" in path else "authentication")
        surfaces.append({"type":surface_type,"endpoint":endpoint,"method":str(data.get("method") or "GET").upper(),
            "status":data.get("http_status"),"source":"observed_endpoint"})
    for row in api_endpoints[:MAX_SURFACES]:
        if isinstance(row,dict) and re.search(r"login|auth|oauth|token|session|logout|password|reset|recover|mfa",str(row.get("path", "")),re.I):
            surfaces.append({"type":"api_authentication","endpoint":str(row.get("path", ""))[:800],
                "method":str(row.get("method", "GET"))[:10].upper(),
                "authentication_required":row.get("security_required"),"source":"openapi"})
    for scheme in (api.get("security_schemes",[]) if isinstance(api,dict) else [])[:50]:
        surfaces.append({"type":"authentication_scheme","scheme":str(scheme)[:100],"source":"openapi"})

    # Authentication/session findings are limited to observations, never credential tests.
    cookies=data.get("cookie_security") or []
    for cookie in cookies[:50]:
        if not isinstance(cookie,dict): continue
        name=str(cookie.get("name","cookie"))[:100]
        if re.search(r"session|auth|token|sid",name,re.I):
            missing=[x for x in ("secure","httponly") if not cookie.get(x)]
            same=str(cookie.get("samesite") or "").lower()
            if not same: missing.append("samesite")
            if missing:
                add("Session Management","weak_session_cookie",f"Session cookie {name} has weak observed attributes",
                    "low","medium",f"Observed session cookie metadata is missing: {', '.join(missing)}.",
                    "Set Secure, HttpOnly, and an appropriate SameSite attribute for session cookies.",excerpt=None)
    if urlsplit(endpoint).scheme.lower()=="http" and auth_match:
        add("Authentication","authentication_over_http","Authentication-related endpoint uses HTTP","medium","high",
            "An authentication-related endpoint was observed over unencrypted HTTP.",
            "Serve authentication endpoints only over HTTPS and redirect HTTP to HTTPS.")
    for name, _ in parse_qsl(urlsplit(str(data.get("url") or endpoint)).query, keep_blank_values=True)[:MAX_PARAMETERS]:
        if re.search(r"token|api[_-]?key|password|secret|auth",name,re.I):
            add("Authentication","sensitive_query_parameter","Sensitive-looking value is carried in a URL parameter",
                "medium","medium",f"Query parameter name '{name[:100]}' suggests authentication material in a URL; its value was not retained.",
                "Avoid placing credentials or bearer material in URLs; use protected headers or request bodies.",parameter=name[:150])

    if kind == "authorization":
        if isinstance(api,dict):
            for row in api_endpoints[:MAX_SURFACES]:
                if not isinstance(row,dict): continue
                operation_path=str(row.get("path", ""))
                operation_params=[p for p in api.get("parameters",[]) if isinstance(p,dict) and p.get("endpoint")==operation_path]
                resource_param=next((p for p in operation_params if
                    re.search(r"(?i)(?:^|_)(?:id|user_id|account_id|tenant_id|object_id|resource_id)(?:$|_)",str(p.get("name","")))),None)
                if resource_param:
                    param_name=str(resource_param["name"])[:150]
                    add("Authorization","resource_identifier_parameter",
                        "Potential horizontal access-control weakness requiring manual verification","informational","low",
                        f"Documented operation {operation_path[:300]} accepts resource identifier parameter '{param_name}'. No alternate identifier was requested.",
                        "Verify object-level authorization with approved test accounts and objects; enforce authorization on every resource access.",parameter=param_name)
                if not row.get("security_required") and re.search(r"user|account|admin|profile|billing|private|order",operation_path,re.I):
                    add("Authorization","sensitive_endpoint_without_security_metadata",
                        "Potential sensitive API operation lacks documented authentication","low","low",
                        f"API metadata for {operation_path[:300]} does not declare an authentication requirement; this does not prove the operation is unauthenticated.",
                        "Confirm intended access policy and document/enforce authentication and object-level authorization.")
    if kind == "vulnerabilities":
        # Analyze only compact response excerpts already stored by an authorized observer.
        raw_excerpt=str(data.get("response_excerpt") or data.get("body_excerpt") or "")[:MAX_EXCERPT]
        body=sanitize_excerpt(raw_excerpt)
        sql=re.search(r"(?i)(SQLSTATE\[[0-9A-Z]+\]|\b(?:mysql|postgresql|sqlite|oracle)\b.{0,50}\b(?:error|exception)\b|syntax error.{0,60}(?:SQL|query))",body)
        if sql:
            add("Injection","database_error_signature","Database error signature in observed response","medium","medium",
                "Stored response excerpt contains a database/parser error signature associated with the observed endpoint.",
                "Return generic errors to clients and validate input using parameterized queries.",excerpt=body[max(0,sql.start()-80):sql.end()+80])
        stack=re.search(r"(?i)(Traceback \(most recent call last\)| at [\w.$]+\([^\n]+:\d+\)|Exception in thread|stack trace)",body)
        indicators=set(data.get("response_indicators") or [])
        if stack or "stack_trace" in indicators:
            add("Information Disclosure","stack_trace","Stack-trace-like content observed","low","medium",
                "A bounded stored response excerpt contains stack-trace-like text.","Disable detailed error output in production and log diagnostics server-side.",excerpt=body[max(0,stack.start()-60):stack.end()+60])
        for name, observed_value in parse_qsl(urlsplit(str(data.get("url") or endpoint)).query, keep_blank_values=True)[:MAX_PARAMETERS]:
            if observed_value and len(observed_value)<=120 and observed_value in raw_excerpt and re.search(r"(?i)<(?:html|script|div|span|img|a|input)\b",raw_excerpt):
                pos=raw_excerpt.find(observed_value)
                add("XSS","reflected_input_in_html","Reflected input appears in observed HTML","informational","low",
                    f"An already observed query value for '{name[:100]}' appears in an HTML response excerpt. No payload was sent and execution was not demonstrated.",
                    "Review context-aware output encoding and verify safely with an approved manual test.",parameter=name[:150],
                    excerpt=raw_excerpt[max(0,pos-80):pos+len(observed_value)+80])
        if re.search(r"(?i)(?:template syntax error|undefined variable|cannot read property|expression parse error|command not found|/bin/(?:sh|bash))",raw_excerpt):
            add("Injection","template_or_interpreter_error","Template or interpreter error signature observed","low","low",
                "A stored response excerpt contains a template or interpreter error signature; no expression or command was executed.",
                "Return generic errors and review safe template and process invocation patterns.",excerpt=body[:500])
        if "secret_like" in indicators or re.search(r"(?i)(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})",raw_excerpt):
            add("Information Disclosure","secret_like_response_content","Secret-like material appears in an observed response","high","medium",
                "A bounded response excerpt matched a common secret or private-key pattern; the matching value was redacted.",
                "Remove exposed secret material, rotate affected credentials, and prevent secrets from entering responses.",excerpt=body[:500])
        if re.search(r"(?i)(?:no such file or directory|permission denied|invalid path|file not found)",raw_excerpt):
            add("Path Traversal","filesystem_error_signature","Filesystem error signature observed","low","low",
                "A bounded response excerpt contains a filesystem error signature associated with the observed endpoint.",
                "Avoid exposing filesystem errors and constrain file access to approved directories.",excerpt=body[:500])
        if re.search(r"(?:\.\./|%2e%2e(?:%2f|/))",raw_excerpt,re.I):
            add("Path Traversal","traversal_indicator_in_observed_response","Traversal-like path indicator observed","informational","low",
                "A stored response excerpt contains a traversal-like path indicator; no traversal request was sent.",
                "Canonicalize and constrain file paths, and avoid echoing sensitive path input.",excerpt=body[:500])
        if "internal_hostname" in indicators or _INTERNAL_HOST.search(raw_excerpt):
            add("Information Disclosure","internal_hostname","Internal-looking hostname observed in response","low","medium",
                "A bounded response excerpt contains an internal-looking hostname; the hostname was redacted from evidence.",
                "Review whether internal naming information needs to be returned to clients.",excerpt=body[:500])
        if "filesystem_path" in indicators or _PATH.search(raw_excerpt):
            add("Information Disclosure","filesystem_path","Filesystem path observed in response","low","medium",
                "A bounded response excerpt contains a filesystem path; the path was redacted from evidence.",
                "Avoid exposing server filesystem layout in client-visible responses.",excerpt=body[:500])
        for item in params:
            name=item["name"]
            lname=name.lower()
            if re.search(r"(?:^|_)(?:url|uri|link|callback|redirect|return|next|dest)(?:$|_)",lname):
                category="Open Redirect" if re.search(r"redirect|return|next|dest",lname) else "SSRF"
                detection="redirect_parameter" if category=="Open Redirect" else "server_fetch_parameter"
                add(category,detection,f"Potential {category.lower()} surface requires manual verification","informational","low",
                    f"Observed parameter name '{name[:100]}' may influence a redirect or server-side fetch; no destination was supplied.",
                    "Validate destinations against strict allowlists and avoid reflecting untrusted redirect targets.",parameter=name[:150])
            if re.search(r"(?i)(?:^|_)(?:file|path|filepath|filename|document)(?:$|_)",lname):
                add("Path Traversal","filesystem_parameter","Potential filesystem path input requires manual verification","informational","low",
                    f"Observed parameter name '{name[:100]}' suggests a file or path input; no traversal values were tested.",
                    "Constrain file access to approved directories and use canonicalized identifiers.",parameter=name[:150])
            if re.search(r"(?i)(?:^|_)(?:id|user_id|account_id|tenant_id|object_id|resource_id)(?:$|_)",lname):
                add("Authorization","resource_identifier_parameter","Potential horizontal access-control weakness requiring manual verification",
                    "informational","low",f"Observed resource identifier parameter '{name[:100]}'. No alternate identifier was requested.",
                    "Verify object-level authorization using approved test accounts and enforce checks per resource.",parameter=name[:150])
        if re.search(r"(?i)/(?:upload|attachments?|files?)(?:/|$)",path):
            surfaces.append({"type":"file_upload_candidate","endpoint":endpoint,"source":"observed_path"})
    return {"surfaces":surfaces[:MAX_SURFACES],"candidates":out[:MAX_SURFACES],
            "parameters":params[:MAX_SURFACES*MAX_PARAMETERS]}
