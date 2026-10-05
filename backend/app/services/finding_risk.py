"""Deterministic normalization, correlation, and explainable risk scoring."""
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit

SEVERITY_BASE = {"informational": 0, "info": 0, "low": 25, "medium": 50, "high": 75, "critical": 95}
CONFIDENCE_FACTOR = {"low": 0.5, "medium": 0.75, "high": 1.0}
PRIORITY_BANDS = ((20, "low"), (40, "medium"), (60, "high"), (80, "critical"))

def normalize_endpoint(value: str | None) -> str:
    if not value:
        return ""
    raw = str(value).strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else "https://" + raw)
    if not parsed.hostname:
        return re.sub(r"\s+", "", raw).rstrip("/").lower()
    host = parsed.hostname.lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        port = None
    default = (parsed.scheme.lower() == "https" and port == 443) or (parsed.scheme.lower() == "http" and port == 80)
    netloc = host if port is None or default else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    # Query and fragment are omitted to avoid unstable and potentially sensitive identity parts.
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))

def normalize_category(value: str | None) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", str(value or "general").strip().lower()).strip("_")
    return cleaned or "general"

def _condition(title: str, category: str) -> str:
    text = re.sub(r"\s+", " ", title.strip().lower())
    if re.search(r"\bhsts\b", text):
        return "strict-transport-security"
    for token in ("strict-transport-security", "content-security-policy", "x-content-type-options",
                  "referrer-policy", "permissions-policy", "x-frame-options"):
        if token in text:
            return token
    if "cookie" in category or "cookie" in text:
        name = re.search(r"cookie\s+([^\s]+)", text)
        return f"cookie:{name.group(1)}" if name else "cookie_security"
    if "server" in text and "header" in text:
        return "server_disclosure"
    if "powered-by" in text or "powered by" in text:
        return "powered_by_disclosure"
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")[:180] or category

def normalize_finding(finding) -> dict:
    """Return normalized fields while retaining original display values."""
    row = finding if isinstance(finding, dict) else {key: getattr(finding, key, None) for key in (
        "id", "project_id", "asset_id", "job_id", "title", "severity", "confidence", "category",
        "status", "endpoint", "description", "evidence", "remediation", "created_at", "updated_at")}
    title = re.sub(r"\s+", " ", str(row.get("title") or "").strip())
    category = normalize_category(row.get("category"))
    endpoint = normalize_endpoint(row.get("endpoint"))
    severity = str(row.get("severity") or "informational").strip().lower()
    if severity == "info":
        severity = "informational"
    confidence = str(row.get("confidence") or "medium").strip().lower()
    if confidence not in CONFIDENCE_FACTOR:
        confidence = "low"
    condition = _condition(title, category)
    identity_source = {"project_id": row.get("project_id"), "asset_id": row.get("asset_id"),
                       "endpoint": endpoint or f"asset:{row.get('asset_id') or 'unknown'}",
                       "category": category, "condition": condition}
    identity = hashlib.sha256(json.dumps(identity_source, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"id": row.get("id"), "project_id": row.get("project_id"), "asset_id": row.get("asset_id"),
        "job_id": row.get("job_id"), "title": title, "severity": severity, "confidence": confidence,
        "category": category, "status": str(row.get("status") or "open").strip().lower(),
        "endpoint": endpoint, "description": row.get("description") or "", "evidence": row.get("evidence"),
        "remediation": re.sub(r"\s+", " ", str(row.get("remediation") or "").strip()) or None,
        "condition": condition, "identity_fingerprint": identity,
        "original": {"title": row.get("title"), "severity": row.get("severity"),
                     "category": row.get("category"), "endpoint": row.get("endpoint"),
                     "evidence": row.get("evidence"), "remediation": row.get("remediation")}}

def risk_for(finding: dict, correlation_groups: list[str] | None = None) -> dict:
    severity = finding.get("severity", "informational")
    confidence = finding.get("confidence", "low")
    base = SEVERITY_BASE.get(severity, 0)
    factor = CONFIDENCE_FACTOR.get(confidence, 0.5)
    score = int(base * factor + 0.5)
    priority = "informational"
    for threshold, label in PRIORITY_BANDS:
        if score >= threshold:
            priority = label
    reason = (f"{severity.title()}-severity {finding.get('category', 'general').replace('_', ' ')} finding "
              f"with {confidence}-confidence observation scores {score}/100. "
              f"Confidence factor {factor:g} applied to base severity score {base}.")
    groups = correlation_groups or []
    if groups:
        reason += " Related context: " + ", ".join(groups) + ". Correlation does not increase severity or score."
    return {"severity": severity, "confidence": confidence, "risk_score": score,
            "priority": priority, "risk_explanation": reason, "base_score": base,
            "confidence_factor": factor, "correlation_groups": groups}

def correlation_family(finding: dict) -> str | None:
    cat = finding["category"]
    condition = finding.get("condition") or _condition(finding.get("title", ""), cat)
    if condition == "strict-transport-security": return "transport_security"
    if "cookie" in cat or condition.startswith("cookie:"): return "cookie_security"
    if cat in {"security_header", "security_headers"} or condition in {
        "content-security-policy", "x-content-type-options", "referrer-policy",
        "permissions-policy", "x-frame-options"}: return "security_headers"
    if cat in {"information_disclosure", "technology_disclosure"} or "disclosure" in condition:
        return "information_disclosure"
    return None

def correlate_findings(findings: list[dict]) -> dict:
    """Group only same-asset, same-endpoint findings within a known related family."""
    buckets: dict[tuple, list[dict]] = {}
    for row in findings:
        family = correlation_family(row)
        if family:
            key = (row.get("project_id"), row.get("asset_id"), row.get("endpoint") or "", family)
            buckets.setdefault(key, []).append(row)
    output = {row.get("id"): [] for row in findings}
    groups = []
    for key, rows in sorted(buckets.items(), key=lambda item: str(item[0])):
        # Keep singleton groups visible: their context still explains their family.
        fingerprint = hashlib.sha256(json.dumps(key, separators=(",", ":")).encode()).hexdigest()[:20]
        group = {"id": f"{key[3]}:{fingerprint}", "group": key[3], "project_id": key[0],
                 "asset_id": key[1], "endpoint": key[2],
                 "finding_ids": sorted(row["id"] for row in rows if row.get("id") is not None),
                 "count": len(rows), "context": f"{len(rows)} related {key[3].replace('_', ' ')} observation(s)."}
        groups.append(group)
        for row in rows:
            if row.get("id") is not None:
                output[row["id"]].append(group["id"])
    return {"groups": groups, "by_finding": output}

def summarize_findings(findings: list[dict], *, assets: dict[int, dict] | None = None) -> dict:
    canonical = []
    seen_identity = set()
    for row in sorted(findings, key=lambda item: (item.get("id") is None, item.get("id") or 0)):
        if row.get("canonical_finding_id") or row.get("status") == "duplicate":
            continue
        identity = row.get("identity_fingerprint")
        if identity and identity in seen_identity:
            continue
        if identity:
            seen_identity.add(identity)
        canonical.append(row)
    severity_names = ("informational", "low", "medium", "high", "critical")
    severity_counts = {name: sum(row.get("severity", "informational") == name for row in canonical)
                       for name in severity_names}
    priority_counts = {name: sum(row.get("priority", "informational") == name for row in canonical)
                       for name in severity_names}
    scores = [int(row.get("risk_score") or 0) for row in canonical]
    top = sorted(canonical, key=lambda row: (-int(row.get("risk_score") or 0), str(row.get("title") or ""), row.get("id") or 0))[:5]
    categories: dict[str, int] = {}
    affected = set()
    for row in canonical:
        categories[row.get("category") or "general"] = categories.get(row.get("category") or "general", 0) + 1
        if row.get("asset_id") is not None: affected.add(row["asset_id"])
    groups = correlate_findings(canonical)["groups"]
    return {"total_findings": len(canonical), "severity_distribution": severity_counts,
        "priority_distribution": priority_counts, "affected_assets": sorted(affected),
        "affected_asset_count": len(affected), "highest_risk_score": max(scores, default=0),
        "average_risk_score": round(sum(scores) / len(scores), 1) if scores else 0,
        "top_remediation_priorities": [{"id": row.get("id"), "title": row.get("title"),
            "risk_score": row.get("risk_score"), "priority": row.get("priority"),
            "remediation": row.get("remediation"), "asset_id": row.get("asset_id")} for row in top],
        "top_categories": sorted(({"category": key, "count": value} for key, value in categories.items()),
                                  key=lambda item: (-item["count"], item["category"])),
        "correlation_groups": groups}
