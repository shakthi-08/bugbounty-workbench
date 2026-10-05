"""Passive assessment of normalized, already collected Phase 8 observations."""
import hashlib


SECURITY_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-frame-options": "X-Frame-Options",
}


def assess_observation(data: dict, *, project_id: int, asset_id: int, endpoint: str,
                       tls_observation: dict | None = None) -> list[dict]:
    headers = {str(k).lower(): str(v) for k, v in (data.get("security_headers") or {}).items()}
    https = str(data.get("final_url") or endpoint).lower().startswith("https://")
    out = []

    def add(kind, title, severity, confidence, observed, remediation, category="security_header"):
        out.append({"category": category, "type": kind, "title": title, "severity": severity,
                    "confidence": confidence, "endpoint": endpoint,
                    "description": f"{title}. Observed: {observed}.",
                    "evidence": {"header": kind, "observed": observed,
                                 "statement": f"Authorized HTTP observation at {endpoint} showed {observed}."},
                    "remediation": remediation})

    for key, name in SECURITY_HEADERS.items():
        value = headers.get(key)
        if key == "strict-transport-security" and not value and https:
            add(name, "HSTS is absent from an HTTPS response", "low", "high", "missing",
                "Enable HSTS after validating HTTPS deployment.")
        elif key == "content-security-policy":
            if not value:
                add(name, "Content Security Policy is absent", "informational", "high", "missing",
                    "Review and configure an appropriate Content-Security-Policy.")
            elif "*" in value or "unsafe-inline" in value.lower() or "unsafe-eval" in value.lower():
                add(name, "Content Security Policy contains permissive directives", "low", "medium", "weak",
                    "Review directives and remove broad sources and unsafe allowances where practical.")
        elif key == "x-content-type-options" and (not value or value.lower() != "nosniff"):
            add(name, "X-Content-Type-Options is missing or weak", "low", "high",
                "missing" if not value else "weak", "Configure X-Content-Type-Options: nosniff.")
        elif key == "referrer-policy" and not value:
            add(name, "Referrer Policy is absent", "informational", "high", "missing",
                "Set a Referrer-Policy appropriate for the application.")
        elif key == "referrer-policy" and value and not all(
                token.strip().lower() in {"no-referrer", "no-referrer-when-downgrade", "origin",
                    "origin-when-cross-origin", "same-origin", "strict-origin",
                    "strict-origin-when-cross-origin", "unsafe-url"}
                for token in value.split(",")):
            add(name, "Referrer Policy value is unrecognized", "informational", "medium", "malformed",
                "Set a valid Referrer-Policy appropriate for the application.")
        elif key == "permissions-policy" and not value:
            add(name, "Permissions Policy is absent", "informational", "high", "missing",
                "Review and configure Permissions-Policy for browser features used by the application.")
        elif key == "x-frame-options" and not value and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
            add(name, "No observed framing restriction", "low", "high", "missing",
                "Configure CSP frame-ancestors or X-Frame-Options if framing is not intended.")
        elif key == "x-frame-options" and value and value.strip().lower() not in {"deny", "sameorigin"}:
            add(name, "X-Frame-Options value is malformed or permissive", "low", "medium", "malformed",
                "Configure X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors.")
        elif key == "strict-transport-security" and value:
            if not https:
                continue
            match = __import__("re").search(r"max-age\s*=\s*(\d+)", value, __import__("re").I)
            if not match:
                add(name, "HSTS value is malformed", "low", "medium", "malformed",
                    "Use a valid HSTS max-age after validating HTTPS deployment.")
            elif int(match.group(1)) < 15552000:
                add(name, "HSTS max-age is short", "low", "medium", "weak",
                    "Consider a longer HSTS max-age after validating HTTPS deployment.")

    for cookie in data.get("cookie_security", []):
        name = str(cookie.get("name", "cookie"))[:100]
        sensitive = any(term in name.lower() for term in ("session", "auth", "token", "sid"))
        missing = [flag for flag in ("secure", "httponly") if not cookie.get(flag)]
        same = cookie.get("samesite")
        if not same or str(same).lower() not in {"strict", "lax", "none"}:
            missing.append("samesite")
        if missing:
            sev = "low" if sensitive else "informational"
            add("cookie_attributes", f"Cookie {name} lacks recommended attributes", sev,
                "medium" if sensitive else "low", "missing " + ", ".join(missing),
                "Configure Secure, HttpOnly, and SameSite appropriately for session cookies.", "cookie")

    for header, value in (("Server", data.get("server")), ("X-Powered-By", data.get("powered_by"))):
        if value:
            out.append({"category": "information_disclosure", "type": header.lower(),
                "title": f"{header} header discloses technology information", "severity": "informational",
                "confidence": "high", "endpoint": endpoint,
                "description": f"The authorized response disclosed {header}: {str(value)[:160]}.",
                "evidence": {"header": header, "observed": str(value)[:160]},
                "remediation": "Remove unnecessary server and version disclosure."})
    # attach a deterministic stable key at endpoint and issue granularity
    for item in out:
        if item["type"] == "Strict-Transport-Security" and tls_observation:
            item["evidence"]["phase7_tls_observation"] = {
                key: tls_observation.get(key) for key in
                ("hostname", "port", "tls_version", "hostname_verified", "certificate_valid")
                if key in tls_observation
            }
        raw = f"{project_id}:{asset_id}:{endpoint}:{item['category']}:{item['type']}"
        item["fingerprint"] = hashlib.sha256(raw.encode()).hexdigest()
    return out
