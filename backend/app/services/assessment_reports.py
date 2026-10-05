"""Build and render reports from existing project-scoped Workbench records."""
from collections import Counter
from datetime import datetime, timezone
from html import escape
import json
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.assessment import Assessment
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.scope import Scope
from app.models.project import Project
from app.models.security_audit import SecurityAuditLog
from app.models.security_job import SecurityJob
from app.models.security_result import SecurityResult
from app.services.finding_risk import correlate_findings, normalize_finding, risk_for, summarize_findings
from app.services.security_authorization import security_authorization
from app.services.security_audit import redact_audit_value, sanitize_audit_target


METHODOLOGY = [
    "Scope and asset authorization use the project's saved scope rules and current backend authorization checks.",
    "DNS reconnaissance reports stored DNS enrichment and subdomain observations; report generation performs no DNS lookups.",
    "HTTP reconnaissance reports stored bounded HTTP observations; report generation sends no HTTP requests.",
    "TLS/certificate inspection reports stored Phase 7 metadata; report generation makes no TLS connections.",
    "Web surface discovery reports stored observations from the bounded fixed-path Phase 8 workflow.",
    "Technology fingerprinting reports stored conservative indicators and their recorded confidence/evidence.",
    "Security header/configuration assessment reports Phase 9 findings derived from stored observations.",
    "Finding normalization, canonical identity, correlation, and risk use the deterministic Phase 10 implementation.",
    "Evidence consists of safe references to existing Evidence records; report generation does not read evidence files.",
    "Phase 13 includes stored results from bounded subdomain, fixed-path HTTP, and selected TCP service checks.",
    "Phase 14 web and API observations use authorized stored surfaces; report generation performs no new requests.",
    "Phase 15 authentication, session, authorization, and vulnerability records are heuristic candidates requiring manual verification.",
]

LIMITATIONS = [
    "This report is based on observations already stored in the Workbench.",
    "Findings are deterministic observations and analysis, not proof of exploitability.",
    "No exploitation was performed by report generation; exploitability may require manual validation.",
    "Risk score is a prioritization aid and does not replace the recorded severity.",
    "The report is limited to assets authorized by the selected project's current scope.",
    "Absence of a reportable finding does not prove absence of a vulnerability.",
    "Report generation and export do not perform new network activity.",
]

_SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|authorization|cookie|credential|session(?:[_-]?id)?)")
_SECRET_TEXT = re.compile(r"(?i)\b(authorization|proxy-authorization|set-cookie|cookie|password|passwd|secret|token|access[_-]?token|refresh[_-]?token|session(?:[_-]?id)?|api[_-]?key)\s*[:=]\s*[^\r\n]+")

def _safe_text(value):
    if value is None:
        return None
    value = str(redact_audit_value(value))
    value = _SECRET_TEXT.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)
    value = re.sub(r"(?i)(https?://[^\s/?#]+)[^\s]*[?&](?:token|key|password|secret)=[^&\s]+", r"\1?[REDACTED]", value)
    return value[:10000]

def _safe_json(value):
    if isinstance(value, dict):
        return {str(key): _safe_json(child) for key, child in value.items() if not _SECRET_KEY.search(str(key))}
    if isinstance(value, (list, tuple)):
        return [_safe_json(item) for item in value]
    if isinstance(value, str):
        return _safe_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _safe_text(value)

def _iso(value):
    return value.isoformat() if value else None

async def _authorized_jobs(db: AsyncSession, project_id: int):
    jobs = list((await db.scalars(select(SecurityJob).where(SecurityJob.project_id == project_id).order_by(SecurityJob.id))).all())
    approved = {}
    for job in jobs:
        target = (job.target_snapshot or {}).get("target")
        if not target:
            continue
        decision = await security_authorization.validate_target(db, project_id, target, job.asset_id)
        if decision.allowed:
            approved[job.id] = job
    return approved

async def build_report_snapshot(db: AsyncSession, assessment: Assessment) -> dict:
    """Assemble a safe, deterministic report payload from authorized stored data."""
    project_id = assessment.project_id
    project = await db.get(Project, project_id)
    scope_rows = list((await db.scalars(select(Scope).where(Scope.project_id == project_id).order_by(Scope.id))).all())
    scope = [{"value": _safe_text(row.value), "type": row.scope_type, "included": row.included}
             for row in scope_rows]

    project_assets = list((await db.scalars(select(Asset).where(Asset.project_id == project_id).order_by(Asset.id))).all())
    authorized_assets = []
    for asset in project_assets:
        decision = await security_authorization.validate_target(db, project_id, asset.value, asset.id)
        if decision.allowed:
            authorized_assets.append(asset)
    asset_by_id = {row.id: row for row in authorized_assets}
    jobs = await _authorized_jobs(db, project_id)

    result_rows = list((await db.scalars(select(SecurityResult).where(SecurityResult.project_id == project_id).order_by(SecurityResult.id))).all())
    usable_results = [row for row in result_rows if row.job_id in jobs]
    result_ids = {row.id for row in usable_results}
    observations = []
    for result in usable_results:
        job = jobs[result.job_id]
        data = result.normalized_data or {}
        observations.append({
            "id": result.id, "job_id": result.job_id, "asset_id": job.asset_id,
            "type": result.result_type, "title": _safe_text(result.title),
            "summary": _safe_text(result.summary), "target": _safe_text(result.target),
            "severity": result.severity,
            "data": _safe_json(data), "created_at": _iso(result.created_at),
        })

    finding_rows = list((await db.scalars(select(Finding).where(Finding.project_id == project_id).order_by(Finding.id))).all())
    eligible = [(row, normalize_finding(row)) for row in finding_rows
                if row.asset_id is None or row.asset_id in asset_by_id]
    # Honor Phase 10's explicit canonical links first, even if an alias has a
    # slightly different title/identity. Then collapse unlinked repeated
    # canonical identities as a deterministic fallback.
    roots = {}
    for pair in eligible:
        row = pair[0]
        root_id = row.canonical_finding_id or row.id
        roots.setdefault(root_id, []).append(pair)
    collapsed = {}
    for root_id, members in roots.items():
        members.sort(key=lambda pair: pair[0].id)
        canonical = next((pair for pair in members if pair[0].id == root_id), None)
        if canonical is None:
            canonical = next((pair for pair in members if pair[0].status != "duplicate"), members[0])
        identity = canonical[1]["identity_fingerprint"]
        group = collapsed.setdefault(identity, {"canonical": canonical, "related": []})
        group["related"].extend(members)
    canonical_groups = []
    for identity, group in collapsed.items():
        # De-duplicate joined rows if a malformed link graph points into an
        # already represented root; keep the oldest canonical row stable.
        related_by_id = {pair[0].id: pair for pair in group["related"]}
        canonical_groups.append((group["canonical"], list(related_by_id.values()), identity))
    canonical_groups.sort(key=lambda item: item[0][0].id)

    canonical_normalized = [pair[0][1] for pair in canonical_groups]
    correlations = correlate_findings(canonical_normalized)
    evidence_rows = list((await db.scalars(select(Evidence).where(Evidence.project_id == project_id).order_by(Evidence.id))).all())
    report_findings = []
    used_evidence_ids = set()
    for (canonical, related, identity) in canonical_groups:
        row, normalized = canonical
        groups = correlations["by_finding"].get(row.id, [])
        calculated = risk_for(normalized, groups)
        evidence_ids = {item[0].id for item in related}
        refs = []
        related_jobs = {item[0].job_id for item in related if item[0].job_id}
        for evidence in evidence_rows:
            if (evidence.finding_id in evidence_ids or
                    evidence.job_id in related_jobs and evidence.finding_id is None):
                provenance = {key: (evidence.metadata_json or {}).get(key) for key in
                    ("tool_key", "source", "module_key") if (evidence.metadata_json or {}).get(key)}
                refs.append({"id": evidence.id, "title": _safe_text(evidence.title),
                    "type": evidence.evidence_type, "description": _safe_text(evidence.description),
                    "finding_id": evidence.finding_id, "result_id": evidence.result_id,
                    "job_id": evidence.job_id, "provenance": _safe_json(provenance),
                    "content_hash": evidence.content_hash if evidence.content_hash and re.fullmatch(r"[a-fA-F0-9]{32,128}", evidence.content_hash) else None,
                    "created_at": _iso(evidence.created_at)})
                used_evidence_ids.add(evidence.id)
        # Phase 10's stored score/groups win when available; otherwise invoke its same engine.
        risk_score = row.risk_score if row.risk_score is not None else calculated["risk_score"]
        priority = row.priority or calculated["priority"]
        explanation = row.risk_explanation or calculated["risk_explanation"]
        report_findings.append({
            "id": row.id, "identity": row.identity_fingerprint or identity,
            "title": _safe_text(row.title), "condition": normalized["condition"],
            "category": normalized["category"], "severity": row.severity,
            "confidence": row.confidence, "risk_score": risk_score, "priority": priority,
            "asset_id": row.asset_id,
            "asset": _safe_text(asset_by_id[row.asset_id].value) if row.asset_id in asset_by_id else None,
            "endpoint": _safe_text(normalized["endpoint"]) or None,
            "correlation_groups": row.correlation_groups or groups,
            "description": _safe_text(row.description), "evidence": _safe_text(row.evidence),
            "verification_status": (
                "Candidate requiring manual verification"
                if re.search(r"candidate requiring manual verification|manual verification required", row.description or "", re.I)
                else "Recorded observation"
            ),
            "remediation": _safe_text(row.remediation), "risk_explanation": _safe_text(explanation),
            "occurrence_count": max(row.occurrence_count or 1, len(related)),
            # This list already contains only canonical rows. Do not pass the
            # Phase 10 alias marker into summarize_findings, which intentionally
            # filters aliases from mixed raw finding sets.
            "evidence_references": refs,
            "created_at": _iso(row.created_at),
        })

    # Add safe evidence attached to accepted observations/jobs, even if not tied to a finding.
    authorized_job_ids = set(jobs)
    for evidence in evidence_rows:
        if evidence.id in used_evidence_ids:
            continue
        if evidence.result_id in result_ids or evidence.job_id in authorized_job_ids:
            used_evidence_ids.add(evidence.id)
    all_evidence = []
    for evidence in evidence_rows:
        if evidence.id not in used_evidence_ids:
            continue
        all_evidence.append({"id": evidence.id, "title": _safe_text(evidence.title),
            "type": evidence.evidence_type, "description": _safe_text(evidence.description),
            "finding_id": evidence.finding_id, "result_id": evidence.result_id,
            "job_id": evidence.job_id,
            "provenance": _safe_json({key: (evidence.metadata_json or {}).get(key) for key in
                ("tool_key", "source", "module_key") if (evidence.metadata_json or {}).get(key)}),
            "content_hash": evidence.content_hash if evidence.content_hash and re.fullmatch(r"[a-fA-F0-9]{32,128}", evidence.content_hash) else None,
            "created_at": _iso(evidence.created_at)})

    summary = summarize_findings(report_findings)
    severity_distribution = summary["severity_distribution"]
    confidence_distribution = dict(Counter(str(row["confidence"]).lower() for row in report_findings))
    priority_distribution = summary["priority_distribution"]
    category_distribution = dict(Counter(row["category"] for row in report_findings))
    group_distribution = dict(Counter(group for row in report_findings for group in row["correlation_groups"]))
    risk_summary = {
        "total_canonical_findings": len(report_findings),
        "total_occurrences": sum(row["occurrence_count"] for row in report_findings),
        "duplicate_occurrences": sum(max(0, row["occurrence_count"] - 1) for row in report_findings),
        "severity_distribution": severity_distribution,
        "confidence_distribution": confidence_distribution,
        "priority_distribution": priority_distribution,
        "category_distribution": category_distribution,
        "correlation_group_distribution": group_distribution,
        "affected_asset_count": len({row["asset_id"] for row in report_findings if row["asset_id"] is not None}),
        "evidence_count": len(all_evidence),
        "highest_risk_score": summary["highest_risk_score"],
        "average_risk_score": summary["average_risk_score"],
        "top_remediation_priorities": summary["top_remediation_priorities"],
    }
    rank = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    highest_severity = max((row["severity"].lower() for row in report_findings), key=lambda val: rank.get(val, 0), default=None)
    priority_rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    highest_priority = max((row["priority"] for row in report_findings), key=lambda val: priority_rank.get(val, 0), default=None)
    assets_by_id = {row.id: {"id": row.id, "value": _safe_text(row.value), "type": row.asset_type,
        "finding_count": sum(item["asset_id"] == row.id for item in report_findings),
        "highest_risk_score": max((item["risk_score"] for item in report_findings if item["asset_id"] == row.id), default=0)}
        for row in authorized_assets}
    affected_assets = sorted((value for value in assets_by_id.values() if value["finding_count"]),
                             key=lambda value: (-value["highest_risk_score"], value["value"]))
    top_categories = sorted(category_distribution.items(), key=lambda pair: (-pair[1], pair[0]))[:3]
    remediation_themes = list(dict.fromkeys(row["remediation"] for row in sorted(
        report_findings, key=lambda item: (-item["risk_score"], item["id"])) if row["remediation"]))[:5]
    if not report_findings:
        executive = (f"Assessment '{_safe_text(assessment.name)}' is {assessment.status}. "
            f"{len(authorized_assets)} authorized assets are in scope. No reportable findings are currently recorded; "
            "this does not establish the absence of vulnerabilities.")
    else:
        executive = (f"Assessment '{_safe_text(assessment.name)}' is {assessment.status} and covers "
            f"{len(authorized_assets)} currently authorized assets. {len(report_findings)} canonical reportable "
            f"findings ({risk_summary['total_occurrences']} occurrences) are recorded. Highest severity is "
            f"{highest_severity}; highest remediation priority is {highest_priority}; highest risk score is "
            f"{risk_summary['highest_risk_score']}/100.")
        if affected_assets:
            executive += " Major affected assets: " + ", ".join(row["value"] for row in affected_assets[:3]) + "."
        if top_categories:
            executive += " Leading categories: " + ", ".join(f"{name} ({count})" for name, count in top_categories) + "."
        if remediation_themes:
            executive += " Remediation themes: " + "; ".join(remediation_themes[:3]) + "."

    audits = list((await db.scalars(select(SecurityAuditLog).where(
        SecurityAuditLog.project_id == project_id,
        SecurityAuditLog.entity_type == "assessment",
    ).order_by(SecurityAuditLog.id.desc()).limit(500))).all())
    audits.reverse()
    audit_summary = [{"id": row.id, "action": row.action, "entity_type": row.entity_type,
        "entity_id": row.entity_id, "target": sanitize_audit_target(row.target),
        "details": _safe_json(redact_audit_value(row.details_json or {})),
        "created_at": _iso(row.created_at)} for row in audits]

    return {
        "assessment": {"id": assessment.id, "project_id": project_id, "name": _safe_text(assessment.name),
            "description": _safe_text(assessment.description), "status": assessment.status,
            "created_at": _iso(assessment.created_at), "updated_at": _iso(assessment.updated_at),
            "completed_at": _iso(assessment.completed_at)},
        "project": {"id": project_id, "name": _safe_text(project.name) if project else None},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": executive,
        "scope": {"scopes": scope, "authorized_assets": [assets_by_id[key] for key in sorted(assets_by_id)],
                  "asset_count": len(authorized_assets)},
        "reconnaissance": observations,
        "risk_overview": risk_summary,
        "findings": report_findings,
        "affected_assets": affected_assets,
        "evidence": all_evidence,
        "methodology": METHODOLOGY,
        "remediation_themes": remediation_themes,
        "audit_summary": audit_summary,
        "limitations": LIMITATIONS,
    }

def _md(value):
    value = str(value if value is not None else "-").replace("\r", " ").replace("\n", "<br>")
    return re.sub(r"([\\`*_{}\[\]()#+.!<>|~-])", r"\\\1", value)

def render_markdown(report: dict) -> str:
    assessment = report["assessment"]
    risk = report["risk_overview"]
    lines = ["# Assessment Report", "", "## Assessment Overview", "",
        f"- **Assessment:** {_md(assessment['name'])} (#{assessment['id']})",
        f"- **Project:** #{report['project']['id']}", f"- **Status:** {_md(assessment['status'])}",
        f"- **Created:** {_md(assessment['created_at'])}", f"- **Updated:** {_md(assessment['updated_at'])}",
        f"- **Completed:** {_md(assessment['completed_at'])}", f"- **Generated:** {_md(report['generated_at'])}", "",
        "## Executive Summary", "", _md(report["executive_summary"]), "", "## Scope", "",
        f"Authorized assets: {report['scope']['asset_count']}", "", "| Asset | Type | Findings | Highest risk |", "|---|---|---:|---:|"]
    for asset in report["scope"]["authorized_assets"]:
        lines.append(f"| {_md(asset['value'])} | {_md(asset['type'])} | {asset['finding_count']} | {asset['highest_risk_score']} |")
    if not report["scope"]["authorized_assets"]: lines.append("| None | — | 0 | 0 |")
    lines += ["", "## Reconnaissance", ""]
    if report["reconnaissance"]:
        for observation in report["reconnaissance"]:
            lines.append(f"- **{_md(observation['type'])}:** {_md(observation['title'])}; target={_md(observation['target'])}; {_md(observation['summary'])}")
            if observation["data"]:
                lines.append(f"  - Stored details: {_md(json.dumps(observation['data'], sort_keys=True, ensure_ascii=False))}")
    else:
        lines.append("No authorized stored reconnaissance observations are currently available.")
    lines += ["", "## Methodology", ""] + [f"- {_md(item)}" for item in report["methodology"]]
    lines += ["", "## Risk Overview", "", f"- Canonical findings: {risk['total_canonical_findings']}",
        f"- Occurrences: {risk['total_occurrences']} ({risk['duplicate_occurrences']} duplicates)",
        f"- Severity distribution: {_md(json.dumps(risk['severity_distribution'], sort_keys=True))}",
        f"- Confidence distribution: {_md(json.dumps(risk['confidence_distribution'], sort_keys=True))}",
        f"- Priority distribution: {_md(json.dumps(risk['priority_distribution'], sort_keys=True))}",
        f"- Category distribution: {_md(json.dumps(risk['category_distribution'], sort_keys=True))}",
        f"- Correlation groups: {_md(json.dumps(risk['correlation_group_distribution'], sort_keys=True))}",
        f"- Highest risk: {risk['highest_risk_score']}/100", f"- Average risk: {risk['average_risk_score']}", "", "## Findings", ""]
    if not report["findings"]: lines.append("No reportable findings are currently recorded.")
    for finding in report["findings"]:
        lines += [f"### {_md(finding['title'])}", "", f"- Severity: {_md(finding['severity'])} | Confidence: {_md(finding['confidence'])}",
            f"- Risk: {finding['risk_score']}/100 | Priority: {_md(finding['priority'])}",
            f"- Verification: {_md(finding['verification_status'])}",
            f"- Category: {_md(finding['category'])} | Asset: {_md(finding['asset'])} | Endpoint: {_md(finding['endpoint'])}",
            f"- Correlation: {_md(', '.join(finding['correlation_groups']) or 'none')} | Occurrences: {finding['occurrence_count']}",
            f"- Condition: {_md(finding['condition'])}", f"- Evidence: {_md(finding['evidence'])}",
            f"- Risk explanation: {_md(finding['risk_explanation'])}", f"- Remediation: {_md(finding['remediation'])}", ""]
    lines += ["## Affected Assets", ""]
    if report["affected_assets"]:
        for asset in report["affected_assets"]: lines.append(f"- {_md(asset['value'])} ({asset['finding_count']} findings, highest risk {asset['highest_risk_score']})")
    else: lines.append("No affected assets are associated with reportable findings.")
    lines += ["", "## Evidence", ""]
    if report["evidence"]:
        for item in report["evidence"]:
            lines.append(f"- Evidence #{item['id']}: {_md(item['title'])} ({_md(item['type'])}); source={_md(json.dumps(item['provenance'], sort_keys=True))}; finding={item['finding_id'] or '-'}, result={item['result_id'] or '-'}, job={item['job_id'] or '-'}, hash={item['content_hash'] or '-'}")
    else: lines.append("No evidence references are currently recorded for this report.")
    lines += ["", "## Remediation", ""]
    lines += [f"- {_md(item)}" for item in report["remediation_themes"]] or ["No remediation items are currently recorded."]
    lines += ["", "## Audit Summary", ""]
    lines += [f"- {item['created_at']}: {_md(item['action'])} ({_md(item['entity_type'])} {_md(item['entity_id'])})" for item in report["audit_summary"]] or ["No project audit events are recorded."]
    lines += ["", "## Limitations", ""] + [f"- {_md(item)}" for item in report["limitations"]] + [""]
    return "\n".join(lines)

def render_html(report: dict) -> str:
    """Render the structured Markdown without allowing dynamic HTML markup."""
    blocks = []
    in_list = False
    for raw_line in render_markdown(report).splitlines():
        # Undo Markdown punctuation escaping only, then HTML-escape the full line.
        raw_line = re.sub(r"\\([\\`*_{}\[\]()#+.!<>|~-])", r"\1", raw_line)
        line = escape(raw_line)
        if not line:
            if in_list:
                blocks.append("</ul>")
                in_list = False
            continue
        if line.startswith("# ") or line.startswith("## ") or line.startswith("### "):
            if in_list:
                blocks.append("</ul>")
                in_list = False
            level = len(line) - len(line.lstrip("#"))
            blocks.append(f"<h{level}>{line[level + 1:]}</h{level}>")
        elif line.startswith("- "):
            if not in_list:
                blocks.append("<ul>")
                in_list = True
            item = line[2:]
            item = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", item)
            blocks.append(f"<li>{item}</li>")
        elif line.startswith("|"):
            if in_list:
                blocks.append("</ul>")
                in_list = False
            blocks.append(f"<pre>{line}</pre>")
        else:
            if in_list:
                blocks.append("</ul>")
                in_list = False
            blocks.append(f"<p>{line}</p>")
    if in_list:
        blocks.append("</ul>")
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Assessment Report</title>" \
        "<style>body{font:15px Segoe UI,Arial,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#202938}" \
        "h1,h2{color:#17365d}pre{white-space:pre-wrap;background:#f4f6f8;padding:.5rem}</style></head><body>" \
        + "\n".join(blocks) + "</body></html>"
