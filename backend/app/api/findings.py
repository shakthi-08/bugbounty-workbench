from datetime import datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.project import Project
from app.services.security_audit import redact_audit_value, sanitize_audit_target, write_audit_log
from app.services.security_authorization import security_authorization

router = APIRouter(
    prefix="/projects/{project_id}/findings",
    tags=["Findings"],
)


def _finding_response(row: Finding) -> dict:
    return {
        "id": row.id, "project_id": row.project_id, "asset_id": row.asset_id,
        "title": redact_audit_value(row.title), "severity": row.severity, "status": row.status,
        "endpoint": sanitize_audit_target(row.endpoint),
        "description": redact_audit_value(row.description), "evidence": redact_audit_value(row.evidence),
        "category": row.category, "confidence": row.confidence,
        "remediation": redact_audit_value(row.remediation), "fingerprint": row.fingerprint,
        "job_id": row.job_id, "identity_fingerprint": row.identity_fingerprint,
        "canonical_finding_id": row.canonical_finding_id, "occurrence_count": row.occurrence_count,
        "risk_score": row.risk_score, "priority": row.priority,
        "risk_explanation": redact_audit_value(row.risk_explanation),
        "correlation_groups": row.correlation_groups or [],
        "created_at": row.created_at, "updated_at": row.updated_at,
    }


class FindingCreate(BaseModel):
    asset_id: int | None = None
    title: str = Field(min_length=1, max_length=500)
    severity: str = Field(min_length=1, max_length=50)
    status: str = Field(default="open", min_length=1, max_length=50)
    endpoint: str | None = Field(default=None, max_length=2000)
    description: str = Field(min_length=1, max_length=20000)
    evidence: str | None = Field(default=None, max_length=20000)


class FindingResponse(BaseModel):
    id: int
    project_id: int
    asset_id: int | None
    title: str
    severity: str
    status: str
    endpoint: str | None
    description: str
    evidence: str | None
    category: str = "general"
    confidence: str = "medium"
    remediation: str | None = None
    fingerprint: str | None = None
    job_id: int | None = None
    identity_fingerprint: str | None = None
    canonical_finding_id: int | None = None
    occurrence_count: int = 1
    risk_score: float | None = None
    priority: str | None = None
    risk_explanation: str | None = None
    correlation_groups: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post("", response_model=FindingResponse, status_code=201)
async def create_finding(
    project_id: int,
    data: FindingCreate,
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)

    if project is None:
        raise HTTPException(
            status_code=404,
            detail="Project not found.",
        )

    if data.asset_id is not None:
        asset = await db.get(Asset, data.asset_id)

        if asset is None or asset.project_id != project_id:
            raise HTTPException(
                status_code=404,
                detail="Asset not found in this project.",
            )
        authorization = await security_authorization.validate_target(
            db, project_id, asset.value, data.asset_id
        )
        if not authorization.allowed:
            await write_audit_log(db, project_id=project_id, user="local-user",
                                  action="finding_scope_validation_failure", entity_type="finding",
                                  target=asset.value, details={"reason": authorization.reason})
            await db.commit()
            raise HTTPException(status_code=403, detail=f"Finding asset blocked by scope: {authorization.reason}")
    if data.endpoint and urlsplit(data.endpoint.strip()).scheme.lower() in {"http", "https"}:
        authorization = await security_authorization.validate_derived_target(db, project_id, data.endpoint)
        if not authorization.allowed:
            await write_audit_log(db, project_id=project_id, user="local-user",
                                  action="finding_scope_validation_failure", entity_type="finding",
                                  target=data.endpoint, details={"reason": authorization.reason})
            await db.commit()
            raise HTTPException(status_code=403, detail=f"Finding endpoint blocked by scope: {authorization.reason}")

    finding = Finding(
        project_id=project_id,
        asset_id=data.asset_id,
        title=redact_audit_value(data.title),
        severity=data.severity,
        status=data.status,
        endpoint=sanitize_audit_target(redact_audit_value(data.endpoint)),
        description=redact_audit_value(data.description),
        evidence=redact_audit_value(data.evidence),
    )

    db.add(finding)
    await db.flush()
    await write_audit_log(db, project_id=project_id, user="local-user", action="finding_created",
                          entity_type="finding", entity_id=finding.id, target=finding.endpoint,
                          details={"title": finding.title, "severity": finding.severity})
    await db.commit()
    await db.refresh(finding)

    return _finding_response(finding)


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    project_id: int,
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)

    if project is None:
        raise HTTPException(
            status_code=404,
            detail="Project not found.",
        )

    result = await db.scalars(
        select(Finding)
        .where(Finding.project_id == project_id)
        .order_by(Finding.id)
    )

    return [_finding_response(row) for row in result.all()]
