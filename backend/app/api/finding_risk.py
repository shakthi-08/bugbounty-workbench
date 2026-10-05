from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.asset import Asset
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.project import Project
from app.services.finding_risk import (correlate_findings, normalize_finding, risk_for,
                                       summarize_findings)
from app.services.security_audit import write_audit_log
from app.services.security_authorization import security_authorization
from app.services.security_audit import redact_audit_value, sanitize_audit_target

router = APIRouter(prefix="/projects/{project_id}", tags=["Finding Risk"])

async def _project_findings(db: AsyncSession, project_id: int, asset_id: int | None = None):
    if await db.get(Project, project_id) is None:
        raise HTTPException(404, "Project not found.")
    statement = select(Finding).where(Finding.project_id == project_id)
    if asset_id is not None:
        statement = statement.where(Finding.asset_id == asset_id)
    rows = list((await db.scalars(statement.order_by(Finding.id))).all())
    for current_asset_id in {row.asset_id for row in rows if row.asset_id is not None}:
        await _require_asset_authorized(db, project_id, current_asset_id)
    normalized = [normalize_finding(row) for row in rows]
    correlation = correlate_findings(normalized)
    for row in normalized:
        row.update(risk_for(row, correlation["by_finding"].get(row["id"], [])))
    return rows, normalized, correlation["groups"]

async def _require_asset_authorized(db: AsyncSession, project_id: int, asset_id: int):
    asset = await db.get(Asset, asset_id)
    if asset is None or asset.project_id != project_id:
        raise HTTPException(404, "Asset not found in this project.")
    decision = await security_authorization.validate_target(db, project_id, asset.value, asset.id)
    if not decision.allowed:
        raise HTTPException(403, f"Asset authorization failed: {decision.reason}")
    return asset

async def _evidence_map(db: AsyncSession, findings: list[Finding]):
    ids = {row.id for row in findings}
    ids.update(row.canonical_finding_id for row in findings if row.canonical_finding_id)
    if not ids:
        return {}
    evidences = list((await db.scalars(select(Evidence).where(Evidence.finding_id.in_(ids)).order_by(Evidence.id))).all())
    result = {}
    for evidence in evidences:
        result.setdefault(evidence.finding_id, []).append({"id": evidence.id, "title": redact_audit_value(evidence.title),
            "evidence_type": evidence.evidence_type, "job_id": evidence.job_id,
            "result_id": evidence.result_id, "path_reference": redact_audit_value(evidence.path_reference),
            "content_hash": evidence.content_hash})
    return result

def _evidence_for(row: Finding, rows: list[Finding], evidence_map: dict):
    ids = {row.id}
    if row.canonical_finding_id:
        ids.add(row.canonical_finding_id)
    ids.update(item.id for item in rows if item.canonical_finding_id == row.id)
    return {key: evidence_map.get(key, []) for key in ids}

def _public(row: Finding, normalized: dict, evidence_map: dict):
    related = [item for item in evidence_map.values() for item in item]
    return {"id": row.id, "project_id": row.project_id, "asset_id": row.asset_id, "job_id": row.job_id,
        "title": redact_audit_value(row.title), "severity": row.severity, "status": row.status,
        "endpoint": sanitize_audit_target(row.endpoint),
        "description": redact_audit_value(row.description), "evidence": redact_audit_value(row.evidence),
        "evidence_references": related,
        "category": row.category, "confidence": row.confidence,
        "remediation": redact_audit_value(row.remediation),
        "fingerprint": row.fingerprint, "identity_fingerprint": normalized["identity_fingerprint"],
        "canonical_finding_id": row.canonical_finding_id, "occurrence_count": row.occurrence_count,
        "risk_score": row.risk_score if row.risk_score is not None else normalized["risk_score"],
        "priority": row.priority or normalized["priority"],
        "risk_explanation": row.risk_explanation or normalized["risk_explanation"],
        "correlation_groups": row.correlation_groups or normalized["correlation_groups"],
        "normalized": redact_audit_value({key: normalized[key] for key in
            ("category", "condition", "endpoint", "severity", "confidence", "original")}),
        "condition": normalized["condition"],
        "created_at": row.created_at, "updated_at": row.updated_at}

@router.get("/findings/analysis")
async def list_finding_analysis(project_id: int, db: AsyncSession = Depends(get_db)):
    rows, normalized, _ = await _project_findings(db, project_id)
    evidence = await _evidence_map(db, rows)
    return [_public(row, data, _evidence_for(row, rows, evidence)) for row, data in zip(rows, normalized)]

@router.get("/findings/{finding_id}/risk")
async def get_finding_risk(project_id: int, finding_id: int, db: AsyncSession = Depends(get_db)):
    rows, normalized, _ = await _project_findings(db, project_id)
    for row, data in zip(rows, normalized):
        if row.id == finding_id:
            evidence = await _evidence_map(db, rows)
            return _public(row, data, _evidence_for(row, rows, evidence))
    raise HTTPException(404, "Finding not found in this project.")

@router.get("/risk-summary/assets/{asset_id}")
async def get_asset_risk_summary(project_id: int, asset_id: int, db: AsyncSession = Depends(get_db)):
    asset = await _require_asset_authorized(db, project_id, asset_id)
    rows, normalized, groups = await _project_findings(db, project_id, asset_id)
    items = [_public(row, data, {}) for row, data in zip(rows, normalized)]
    summary = summarize_findings(items)
    return {"project_id": project_id, "asset_id": asset_id, "asset": asset.value,
            **summary, "correlation_groups": [group for group in groups if group["asset_id"] == asset_id]}

@router.get("/risk-summary")
async def get_project_risk_summary(project_id: int, db: AsyncSession = Depends(get_db)):
    rows, normalized, groups = await _project_findings(db, project_id)
    assets = {row.asset_id for row in rows if row.asset_id is not None}
    for asset_id in assets:
        await _require_asset_authorized(db, project_id, asset_id)
    items = [_public(row, data, {}) for row, data in zip(rows, normalized)]
    summary = summarize_findings(items)
    return {"project_id": project_id, **summary, "correlation_groups": groups}

@router.post("/findings/correlate")
async def correlate_project_findings(project_id: int, db: AsyncSession = Depends(get_db)):
    rows, normalized, _ = await _project_findings(db, project_id)
    try:
        for asset_id in {row.asset_id for row in rows if row.asset_id is not None}:
            await _require_asset_authorized(db, project_id, asset_id)
    except HTTPException as error:
        await write_audit_log(db, project_id=project_id, user="local-user",
            action="finding_correlation_authorization_rejected", entity_type="project",
            entity_id=project_id, details={"status_code": error.status_code, "reason": error.detail})
        await db.commit()
        raise
    await write_audit_log(db, project_id=project_id, user="local-user", action="finding_correlation_requested",
        entity_type="project", entity_id=project_id, details={"finding_count": len(rows)})
    await write_audit_log(db, project_id=project_id, user="local-user", action="finding_correlation_authorization_accepted",
        entity_type="project", entity_id=project_id, details={"asset_count": len({r.asset_id for r in rows if r.asset_id})})
    await write_audit_log(db, project_id=project_id, user="local-user", action="finding_risk_calculation_started",
        entity_type="project", entity_id=project_id, details={"finding_count": len(rows)})
    by_identity = {}
    norm_by_id = {data["id"]: data for data in normalized}
    for row in rows:
        row.identity_fingerprint = norm_by_id[row.id]["identity_fingerprint"]
        by_identity.setdefault(row.identity_fingerprint, []).append(row)
    duplicate_count = 0
    for identity, members in by_identity.items():
        members.sort(key=lambda row: (row.created_at or datetime.min.replace(tzinfo=timezone.utc), row.id))
        existing_canonical = next((row for row in members if row.canonical_finding_id is None and row.status != "duplicate"), None)
        canonical = existing_canonical or members[0]
        canonical.canonical_finding_id = None
        canonical.status = "open" if canonical.status == "duplicate" else canonical.status
        canonical.occurrence_count = len(members)
        for duplicate in members:
            if duplicate.id == canonical.id: continue
            if duplicate.canonical_finding_id != canonical.id:
                duplicate_count += 1
                await write_audit_log(db, project_id=project_id, user="local-user", action="finding_duplicate_suppressed",
                    entity_type="finding", entity_id=duplicate.id, target=duplicate.endpoint,
                    details={"canonical_finding_id": canonical.id, "identity_fingerprint": identity,
                             "evidence_preserved": True})
            duplicate.canonical_finding_id = canonical.id
            duplicate.status = "duplicate"
            duplicate.identity_fingerprint = identity
    normalized = [normalize_finding(row) for row in rows]
    canonical_ids = {row.id for row in rows if row.canonical_finding_id is None}
    correlation = correlate_findings([data for data in normalized if data["id"] in canonical_ids])
    for row, data in zip(rows, normalized):
        groups = correlation["by_finding"].get(row.id, [])
        risk = risk_for(data, groups)
        row.risk_score = risk["risk_score"]
        row.priority = risk["priority"]
        row.risk_explanation = risk["risk_explanation"]
        row.correlation_groups = groups
    await write_audit_log(db, project_id=project_id, user="local-user", action="finding_correlations_created",
        entity_type="project", entity_id=project_id, details={"group_count": len(correlation["groups"])})
    await write_audit_log(db, project_id=project_id, user="local-user", action="finding_risk_calculated",
        entity_type="project", entity_id=project_id, details={"canonical_count": len(by_identity), "duplicate_count": duplicate_count})
    await write_audit_log(db, project_id=project_id, user="local-user", action="finding_correlation_completed",
        entity_type="project", entity_id=project_id, details={"canonical_count": len(by_identity), "duplicate_count": duplicate_count})
    await db.commit()
    return {"project_id": project_id, "findings_processed": len(rows), "canonical_findings": len(by_identity),
            "duplicates_suppressed": duplicate_count, "correlation_groups": correlation["groups"]}
