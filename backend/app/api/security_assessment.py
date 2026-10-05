from datetime import datetime, timezone
from urllib.parse import urlsplit
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.models.asset import Asset
from app.models.project import Project
from app.models.security_job import SecurityJob
from app.models.security_result import SecurityResult
from app.models.finding import Finding
from app.models.evidence import Evidence
from app.models.scan_profile import ScanProfile
from app.services.security_authorization import security_authorization
from app.services.security_audit import write_audit_log
from app.services.security_header_assessment import assess_observation

router = APIRouter(tags=["Security Assessment"])

class Request(BaseModel):
    asset_id: int = Field(ge=1)
    observation_id: int = Field(ge=1)
    requested_by: str = Field(default="local-user", min_length=1, max_length=200)

class Approval(BaseModel):
    approved_by: str = Field(min_length=1, max_length=200)

@router.post("/projects/{project_id}/security-header-assessments")
async def request_assessment(project_id: int, data: Request, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    asset = await db.get(Asset, data.asset_id)
    source = await db.get(SecurityResult, data.observation_id)
    if project is None: raise HTTPException(404, "Project not found.")
    if asset is None or asset.project_id != project_id: raise HTTPException(404, "Asset not found in this project.")
    if source is None or source.project_id != project_id or source.result_type != "endpoint":
        raise HTTPException(404, "Authorized web observation not found in this project.")
    srcjob = await db.get(SecurityJob, source.job_id)
    if (srcjob is None or srcjob.status != "completed" or srcjob.asset_id != asset.id
            or source.normalized_data.get("asset_id") != asset.id
            or not source.normalized_data.get("url")):
        raise HTTPException(422, "Observation is not a completed web observation for this asset.")
    target = asset.value
    authorization = await security_authorization.validate_target(db, project_id, target, asset.id)
    await write_audit_log(db, project_id=project_id, user=data.requested_by,
        action="security_header_assessment_requested", entity_type="asset", entity_id=asset.id,
        target=target, details={"observation_id": source.id})
    if not authorization.allowed:
        await write_audit_log(db, project_id=project_id, user=data.requested_by,
            action="security_header_authorization_rejected", entity_type="asset", entity_id=asset.id,
            target=target, details={"reason": authorization.reason})
        await db.commit()
        raise HTTPException(403, f"Asset authorization failed: {authorization.reason}")
    profile = await db.scalar(select(ScanProfile).where(ScanProfile.key == "web_baseline"))
    if profile is None: raise HTTPException(500, "Web assessment profile is unavailable.")
    job = SecurityJob(project_id=project_id, profile_id=profile.id, asset_id=asset.id,
        status="pending_approval", requested_by=data.requested_by,
        target_snapshot={"target": target, "authorization": authorization.scope_snapshot.get("authorization")},
        scope_snapshot=authorization.scope_snapshot,
        profile_snapshot={"modules": [], "tool_ids": [], "tools": [], "assessment": "security_headers"},
        parameters={"source_result_id": source.id, "assessment": "security_headers"})
    db.add(job); await db.flush()
    await write_audit_log(db, project_id=project_id, user=data.requested_by,
        action="security_header_assessment_authorization_accepted", entity_type="security_job", entity_id=job.id,
        target=target, details={"observation_id": source.id})
    await db.commit(); await db.refresh(job)
    return {"id": job.id, "project_id": project_id, "asset_id": asset.id, "observation_id": source.id,
            "status": job.status, "authorization": authorization.scope_snapshot}

@router.post("/projects/{project_id}/security-header-assessments/{job_id}/approve")
async def approve_assessment(project_id: int, job_id: int, data: Approval, db: AsyncSession = Depends(get_db)):
    job = await db.scalar(select(SecurityJob).where(SecurityJob.id == job_id, SecurityJob.project_id == project_id,
        SecurityJob.parameters["assessment"].as_string() == "security_headers"))
    if job is None: raise HTTPException(404, "Assessment job not found.")
    if job.status != "pending_approval": raise HTTPException(409, "Only pending assessments can be approved.")
    decision = await security_authorization.validate_target(db, project_id, job.target_snapshot["target"], job.asset_id)
    if not decision.allowed:
        job.status="blocked"; job.error=decision.reason
        await write_audit_log(db, project_id=project_id, user=data.approved_by, action="security_header_approval_rejected",
            entity_type="security_job", entity_id=job.id, target=job.target_snapshot["target"], details={"reason":decision.reason})
    else:
        job.status="approved"; job.approved_by=data.approved_by; job.approval_timestamp=datetime.now(timezone.utc)
        await write_audit_log(db, project_id=project_id, user=data.approved_by, action="security_header_approval_accepted",
            entity_type="security_job", entity_id=job.id, target=job.target_snapshot["target"], details={})
    await db.commit(); return {"id":job.id,"status":job.status,"error":job.error}

@router.post("/projects/{project_id}/security-header-assessments/{job_id}/run")
async def run_assessment(project_id: int, job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.scalar(select(SecurityJob).where(SecurityJob.id == job_id, SecurityJob.project_id == project_id,
        SecurityJob.parameters["assessment"].as_string() == "security_headers"))
    if job is None: raise HTTPException(404, "Assessment job not found.")
    if job.status != "approved": raise HTTPException(409, "Assessment requires approval.")
    decision = await security_authorization.validate_target(db, project_id, job.target_snapshot["target"], job.asset_id)
    source = await db.scalar(select(SecurityResult).where(SecurityResult.id == job.parameters.get("source_result_id"),
        SecurityResult.project_id == project_id))
    if not decision.allowed or source is None or source.result_type != "endpoint":
        job.status="blocked"; job.error=decision.reason if not decision.allowed else "Source observation is unavailable."
        await write_audit_log(db, project_id=project_id, user=job.approved_by or job.requested_by,
            action="security_header_authorization_rejected", entity_type="security_job", entity_id=job.id,
            target=job.target_snapshot.get("target"), details={"reason":job.error})
        await db.commit(); raise HTTPException(403, job.error)
    job.status="running"; job.started_at=datetime.now(timezone.utc)
    await write_audit_log(db, project_id=project_id, user=job.approved_by or job.requested_by,
        action="security_header_assessment_started", entity_type="security_job", entity_id=job.id,
        target=source.normalized_data.get("url"), details={})
    findings=[]
    await write_audit_log(db, project_id=project_id, user=job.approved_by or job.requested_by,
        action="security_header_observation_evaluated", entity_type="security_result", entity_id=source.id,
        target=source.normalized_data.get("url"), details={"observation_type": "phase8_endpoint"})
    source_host = (urlsplit(source.normalized_data["url"]).hostname or "").lower()
    tls_row = await db.scalar(select(SecurityResult).join(SecurityJob, SecurityJob.id == SecurityResult.job_id).where(
        SecurityResult.project_id == project_id, SecurityResult.result_type == "certificate",
        SecurityJob.asset_id == job.asset_id, SecurityJob.status == "completed"
    ).order_by(SecurityResult.id.desc()))
    tls_data = tls_row.normalized_data if tls_row and str(tls_row.normalized_data.get("hostname", "")).lower() == source_host else None
    for item in assess_observation(source.normalized_data, project_id=project_id, asset_id=job.asset_id,
                                   endpoint=source.normalized_data["url"], tls_observation=tls_data):
        existing=await db.scalar(select(Finding).where(Finding.fingerprint == item["fingerprint"]))
        if existing:
            await write_audit_log(db, project_id=project_id, user=job.approved_by or job.requested_by,
                action="security_header_duplicate_suppressed", entity_type="finding", entity_id=existing.id,
                target=item["endpoint"], details={"fingerprint":item["fingerprint"]}); continue
        finding=Finding(project_id=project_id, asset_id=job.asset_id, job_id=job.id, title=item["title"],
            severity=item["severity"], status="open", endpoint=item["endpoint"], description=item["description"],
            evidence=str(item["evidence"]), category=item["category"], confidence=item["confidence"],
            remediation=item["remediation"], fingerprint=item["fingerprint"])
        db.add(finding); await db.flush()
        db.add(Evidence(project_id=project_id,job_id=job.id,finding_id=finding.id,evidence_type="json",
            title=item["title"],description=item["description"],path_reference=item["endpoint"],
            metadata_json={"header":item["evidence"],"confidence":item["confidence"],"remediation":item["remediation"]}))
        findings.append({"id":finding.id,"title":finding.title,"severity":finding.severity,
            "confidence":finding.confidence,"evidence":item["evidence"],"remediation":finding.remediation})
        await write_audit_log(db, project_id=project_id,user=job.approved_by or job.requested_by,
            action="security_header_finding_created",entity_type="finding",entity_id=finding.id,
            target=item["endpoint"],details={"fingerprint":item["fingerprint"],"severity":item["severity"]})
    job.status="completed"; job.completed_at=datetime.now(timezone.utc)
    await write_audit_log(db,project_id=project_id,user=job.approved_by or job.requested_by,
        action="security_header_assessment_completed",entity_type="security_job",entity_id=job.id,
        target=source.normalized_data.get("url"),details={"findings":len(findings)})
    await db.commit()
    return {"job_id":job.id,"status":job.status,"findings":findings}
