from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.project import Project
from app.models.security_audit import SecurityAuditLog
from app.models.security_job import SecurityJob
from app.models.security_result import SecurityResult
from app.services.security_audit import write_audit_log
from app.services.security_authorization import security_authorization

router = APIRouter(tags=["Security Data"])

ResultType = Literal[
    "asset", "service", "endpoint", "technology", "finding_candidate",
    "configuration", "certificate", "dns_record", "subdomain", "secret_candidate",
    "dependency", "cloud_resource", "mobile_component", "binary_artifact", "generic",
]
EvidenceType = Literal[
    "screenshot", "http_exchange", "json", "text", "tool_output", "file", "log", "other",
]


class SecurityResultCreate(BaseModel):
    job_id: int = Field(ge=1)
    tool_id: int | None = Field(default=None, ge=1)
    module_id: int | None = Field(default=None, ge=1)
    target: str = Field(min_length=1, max_length=2000)
    result_type: ResultType
    severity: str | None = Field(default=None, max_length=30)
    title: str = Field(min_length=1, max_length=500)
    summary: str | None = Field(default=None, max_length=20000)
    raw_reference: str | None = Field(default=None, max_length=2000)
    normalized_data: dict[str, Any] = Field(default_factory=dict)


class SecurityResultResponse(BaseModel):
    id: int
    project_id: int
    job_id: int
    tool_id: int | None
    module_id: int | None
    target: str
    result_type: str
    severity: str | None
    title: str
    summary: str | None
    raw_reference: str | None
    normalized_data: dict
    created_at: Any

    model_config = {"from_attributes": True}


class EvidenceCreate(BaseModel):
    job_id: int | None = Field(default=None, ge=1)
    result_id: int | None = Field(default=None, ge=1)
    finding_id: int | None = Field(default=None, ge=1)
    evidence_type: EvidenceType
    title: str = Field(min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=20000)
    path_reference: str | None = Field(default=None, max_length=2000)
    content_hash: str | None = Field(default=None, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceResponse(BaseModel):
    id: int
    project_id: int
    job_id: int | None
    result_id: int | None
    finding_id: int | None
    evidence_type: str
    title: str
    description: str | None
    path_reference: str | None
    content_hash: str | None
    metadata: dict = Field(validation_alias="metadata_json", serialization_alias="metadata")
    created_at: Any

    model_config = {"from_attributes": True}


class AuditResponse(BaseModel):
    id: int
    project_id: int | None
    user: str
    action: str
    entity_type: str
    entity_id: str | None
    target: str | None
    details: dict
    created_at: Any

    model_config = {"from_attributes": True}


def _require_local_reference(value: str | None) -> None:
    if value is None:
        return
    parsed = urlsplit(value)
    windows_drive = len(parsed.scheme) == 1 and len(value) > 2 and value[1] == ":"
    if parsed.netloc or value.startswith(("\\\\", "//")) or (parsed.scheme and not windows_drive):
        raise HTTPException(status_code=422, detail="Evidence references must be local paths or identifiers.")


async def _project_exists(db: AsyncSession, project_id: int) -> None:
    if await db.get(Project, project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")


@router.post("/projects/{project_id}/security-results", response_model=SecurityResultResponse,
             status_code=status.HTTP_201_CREATED)
async def create_security_result(project_id: int, data: SecurityResultCreate,
                                 db: AsyncSession = Depends(get_db)):
    await _project_exists(db, project_id)
    job = await db.scalar(select(SecurityJob).where(
        SecurityJob.id == data.job_id, SecurityJob.project_id == project_id))
    if job is None:
        raise HTTPException(status_code=404, detail="Security job not found.")
    if job.status != "approved":
        raise HTTPException(status_code=409, detail="Results can only be attached to an approved job in Phase 3.")
    if data.module_id is not None and data.module_id not in {
        item["id"] for item in job.profile_snapshot.get("modules", [])
    }:
        raise HTTPException(status_code=422, detail="Module was not selected for this job.")
    if data.tool_id is not None and data.tool_id not in job.profile_snapshot.get("tool_ids", []):
        raise HTTPException(status_code=422, detail="Tool was not selected for this job.")
    authorization = await security_authorization.validate_derived_target(db, project_id, data.target)
    if not authorization.allowed:
        await write_audit_log(db, project_id=project_id, user="local-user",
                              action="scope_validation_failure", entity_type="security_result",
                              target=data.target, details={"reason": authorization.reason})
        await db.commit()
        raise HTTPException(status_code=403, detail=f"Result target blocked by scope: {authorization.reason}")
    result = SecurityResult(project_id=project_id, job_id=job.id, tool_id=data.tool_id,
                            module_id=data.module_id, target=data.target.strip(),
                            result_type=data.result_type, severity=data.severity,
                            title=data.title.strip(), summary=data.summary,
                            raw_reference=data.raw_reference, normalized_data=data.normalized_data)
    db.add(result)
    await db.flush()
    await write_audit_log(db, project_id=project_id, user="local-user",
                          action="result_imported", entity_type="security_result",
                          entity_id=result.id, target=result.target,
                          details={"result_type": result.result_type, "title": result.title})
    await db.commit()
    await db.refresh(result)
    return result


@router.get("/projects/{project_id}/security-results", response_model=list[SecurityResultResponse])
async def list_security_results(project_id: int, limit: int = Query(100, ge=1, le=500),
                                job_id: int | None = Query(default=None, ge=1),
                                asset_id: int | None = Query(default=None, ge=1),
                                db: AsyncSession = Depends(get_db)):
    await _project_exists(db, project_id)
    statement = select(SecurityResult).where(SecurityResult.project_id == project_id)
    if job_id is not None:
        statement = statement.where(SecurityResult.job_id == job_id)
    if asset_id is not None:
        statement = statement.join(SecurityJob, SecurityJob.id == SecurityResult.job_id).where(
            SecurityJob.asset_id == asset_id, SecurityJob.project_id == project_id)
    return list((await db.scalars(statement.order_by(SecurityResult.id).limit(limit))).all())


@router.get("/projects/{project_id}/security-results/{result_id}", response_model=SecurityResultResponse)
async def get_security_result(project_id: int, result_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.scalar(select(SecurityResult).where(
        SecurityResult.id == result_id, SecurityResult.project_id == project_id))
    if result is None:
        raise HTTPException(status_code=404, detail="Security result not found.")
    return result


@router.post("/projects/{project_id}/evidence", response_model=EvidenceResponse,
             status_code=status.HTTP_201_CREATED)
async def create_evidence(project_id: int, data: EvidenceCreate, db: AsyncSession = Depends(get_db)):
    await _project_exists(db, project_id)
    _require_local_reference(data.path_reference)
    job = None
    result = None
    if data.job_id is not None:
        job = await db.scalar(select(SecurityJob).where(
            SecurityJob.id == data.job_id, SecurityJob.project_id == project_id))
        if job is None:
            raise HTTPException(status_code=404, detail="Security job not found.")
    if data.result_id is not None:
        result = await db.scalar(select(SecurityResult).where(
            SecurityResult.id == data.result_id, SecurityResult.project_id == project_id))
        if result is None:
            raise HTTPException(status_code=404, detail="Security result not found.")
        if job is not None and result.job_id != job.id:
            raise HTTPException(status_code=422, detail="Evidence job and result do not match.")
        if job is None:
            job = await db.get(SecurityJob, result.job_id)
    if data.finding_id is not None:
        finding = await db.scalar(select(Finding).where(
            Finding.id == data.finding_id, Finding.project_id == project_id))
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found.")
    if job is None and result is None and data.finding_id is None:
        raise HTTPException(status_code=422, detail="Evidence must be associated with a job, result, or finding.")
    evidence = Evidence(project_id=project_id, job_id=job.id if job else None,
                        result_id=result.id if result else None, finding_id=data.finding_id,
                        evidence_type=data.evidence_type, title=data.title.strip(),
                        description=data.description, path_reference=data.path_reference,
                        content_hash=data.content_hash, metadata_json=data.metadata)
    db.add(evidence)
    await db.flush()
    await write_audit_log(db, project_id=project_id, user="local-user",
                          action="evidence_created", entity_type="evidence", entity_id=evidence.id,
                          target=result.target if result else (job.target_snapshot.get("target") if job else None),
                          details={"evidence_type": evidence.evidence_type, "title": evidence.title})
    await db.commit()
    await db.refresh(evidence)
    return evidence


@router.get("/projects/{project_id}/evidence", response_model=list[EvidenceResponse])
async def list_evidence(project_id: int, limit: int = Query(100, ge=1, le=500),
                        db: AsyncSession = Depends(get_db)):
    await _project_exists(db, project_id)
    return list((await db.scalars(select(Evidence).where(Evidence.project_id == project_id)
                                  .order_by(Evidence.id).limit(limit))).all())


@router.get("/projects/{project_id}/security-audit", response_model=list[AuditResponse])
async def list_security_audit(project_id: int, limit: int = Query(200, ge=1, le=1000),
                              db: AsyncSession = Depends(get_db)):
    await _project_exists(db, project_id)
    rows = (await db.scalars(select(SecurityAuditLog).where(
        SecurityAuditLog.project_id == project_id).order_by(SecurityAuditLog.id.desc()).limit(limit))).all()
    return [{"id": row.id, "project_id": row.project_id, "user": row.user,
             "action": row.action, "entity_type": row.entity_type,
             "entity_id": row.entity_id, "target": row.target,
             "details": row.details_json, "created_at": row.created_at} for row in rows]
