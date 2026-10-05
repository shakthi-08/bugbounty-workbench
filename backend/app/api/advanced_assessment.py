"""Approved, project-scoped analysis of stored authorized web observations."""
from datetime import datetime, timezone
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
from app.services.advanced_web_assessment import assess_observation, extract_api_surface, extract_input_surface, safe_endpoint, MAX_ENDPOINTS

router = APIRouter(tags=["Advanced Security Assessment"])

class Request(BaseModel):
    asset_id: int = Field(ge=1)
    requested_by: str = Field(default="local-user", min_length=1, max_length=200)

class Approval(BaseModel):
    approved_by: str = Field(min_length=1, max_length=200)

async def _job(db, project_id, job_id, kind):
    row = await db.scalar(select(SecurityJob).where(SecurityJob.id == job_id,
        SecurityJob.project_id == project_id, SecurityJob.parameters["assessment"].as_string() == kind))
    if row is None: raise HTTPException(404, "Assessment job not found.")
    return row

@router.post("/projects/{project_id}/security-assessments/{kind}", description="Queue bounded analysis of stored, project-owned web observations. No arbitrary URL is accepted.")
async def request_assessment(project_id: int, kind: str, data: Request, db: AsyncSession = Depends(get_db)):
    if kind not in {"web", "api"}: raise HTTPException(404, "Assessment type not found.")
    project, asset = await db.get(Project, project_id), await db.get(Asset, data.asset_id)
    if project is None: raise HTTPException(404, "Project not found.")
    if asset is None or asset.project_id != project_id: raise HTTPException(404, "Asset not found in this project.")
    auth = await security_authorization.validate_target(db, project_id, asset.value, asset.id)
    await write_audit_log(db, project_id=project_id, user=data.requested_by, action="advanced_assessment_requested",
        entity_type="asset", entity_id=asset.id, target=asset.value, details={"assessment":kind})
    if not auth.allowed:
        await db.commit(); raise HTTPException(403, f"Asset authorization failed: {auth.reason}")
    profile = await db.scalar(select(ScanProfile).where(ScanProfile.key == "web_baseline"))
    job = SecurityJob(project_id=project_id, profile_id=profile.id, asset_id=asset.id,
        status="pending_approval", requested_by=data.requested_by,
        target_snapshot={"target":asset.value}, scope_snapshot=auth.scope_snapshot,
        profile_snapshot={"assessment":kind}, parameters={"assessment":kind})
    db.add(job); await db.flush()
    await write_audit_log(db, project_id=project_id, user=data.requested_by, action="advanced_assessment_job_created",
        entity_type="security_job", entity_id=job.id, target=asset.value, details={"assessment":kind})
    await db.commit()
    return {"id":job.id,"project_id":project_id,"asset_id":asset.id,"assessment":kind,"status":job.status}

@router.post("/projects/{project_id}/security-assessments/{kind}/{job_id}/approve")
async def approve(project_id: int, kind: str, job_id: int, data: Approval, db: AsyncSession = Depends(get_db)):
    job = await _job(db, project_id, job_id, kind)
    if job.status != "pending_approval": raise HTTPException(409, "Only pending assessments can be approved.")
    auth = await security_authorization.validate_target(db, project_id, job.target_snapshot["target"], job.asset_id)
    if auth.allowed:
        job.status="approved"; job.approved_by=data.approved_by; job.approval_timestamp=datetime.now(timezone.utc)
    else:
        job.status="blocked"; job.error=auth.reason
    await write_audit_log(db, project_id=project_id, user=data.approved_by,
        action="advanced_assessment_approval_" + ("accepted" if auth.allowed else "rejected"),
        entity_type="security_job", entity_id=job.id, target=job.target_snapshot["target"], details={"reason":auth.reason})
    await db.commit(); return {"id":job.id,"status":job.status,"error":job.error}

@router.post("/projects/{project_id}/security-assessments/{kind}/{job_id}/run")
async def run(project_id: int, kind: str, job_id: int, db: AsyncSession = Depends(get_db)):
    job = await _job(db, project_id, job_id, kind)
    if job.status != "approved": raise HTTPException(409, "Assessment requires approval.")
    auth = await security_authorization.validate_target(db, project_id, job.target_snapshot["target"], job.asset_id)
    if not auth.allowed:
        job.status="blocked"; job.error=auth.reason; await db.commit(); raise HTTPException(403, auth.reason)
    observations = list((await db.scalars(select(SecurityResult).where(SecurityResult.project_id == project_id,
        SecurityResult.result_type == "endpoint",
        SecurityResult.normalized_data["asset_id"].as_integer() == job.asset_id)
        .order_by(SecurityResult.id.desc()).limit(MAX_ENDPOINTS))).all())
    job.status="running"; job.started_at=datetime.now(timezone.utc)
    await write_audit_log(db, project_id=project_id, user=job.approved_by or job.requested_by,
        action="advanced_assessment_started", entity_type="security_job", entity_id=job.id,
        target=job.target_snapshot["target"], details={"assessment":kind,"endpoints":len(observations)})
    findings=[]; api_specs=[]; parameters=[]
    for observation in observations:
        data=observation.normalized_data or {}; url=data.get("url", observation.target)
        evidence_url=safe_endpoint(url)
        parameters.extend(extract_input_surface(data, url))
        selected_headers = {key:value for key,value in (data.get("security_headers") or {}).items()
                            if str(key).lower() in {"content-security-policy", "strict-transport-security",
                                "x-content-type-options", "referrer-policy", "permissions-policy",
                                "access-control-allow-origin", "access-control-allow-credentials"}}
        safe_cookies=[{key:cookie.get(key) for key in ("name","secure","httponly","samesite") if key in cookie}
                      for cookie in (data.get("cookie_security") or [])[:50] if isinstance(cookie,dict)]
        observation_result=SecurityResult(project_id=project_id,job_id=job.id,target=evidence_url,
            result_type="generic",title="Phase 14 stored web observation assessment",
            summary="Bounded analysis of an existing authorized endpoint observation.",
            normalized_data={"assessment":kind,"asset_id":job.asset_id,"url":evidence_url,
                "http_status":data.get("http_status"),"server":str(data.get("server") or "")[:120],
                "security_headers":selected_headers,"cookie_security":safe_cookies})
        db.add(observation_result); await db.flush()
        db.add(Evidence(project_id=project_id,job_id=job.id,result_id=observation_result.id,
            evidence_type="json",title=observation_result.title,path_reference=evidence_url,
            metadata_json=observation_result.normalized_data))
        if kind == "web":
            safe_data={**data,"url":evidence_url,"final_url":safe_endpoint(data.get("final_url", evidence_url))}
            candidates=assess_observation(safe_data, project_id, job.asset_id, evidence_url)
        else:
            spec=data.get("api_spec_observation") or data.get("openapi_spec") or data.get("api_spec")
            path=str(url).lower()
            if spec is not None or any(x in path for x in ("openapi", "swagger", "api-docs")):
                normalized=spec if isinstance(spec, dict) and "endpoints" in spec else extract_api_surface(spec, evidence_url)
                api_specs.append(normalized)
                result=SecurityResult(project_id=project_id, job_id=job.id, target=evidence_url,
                    result_type="generic", title="Normalized API specification observation",
                    summary="Bounded API metadata extracted from a stored authorized observation.",
                    normalized_data={"assessment":"api","asset_id":job.asset_id,"endpoint":evidence_url,"api":normalized})
                db.add(result); await db.flush()
                db.add(Evidence(project_id=project_id,job_id=job.id,result_id=result.id,evidence_type="json",
                    title=result.title,path_reference=evidence_url,metadata_json=normalized))
                candidates=[]
                if normalized.get("endpoints") and not normalized.get("security_schemes"):
                    candidates.append({"category":"api_security","title":"API specification has no security schemes",
                        "severity":"low","confidence":"medium","endpoint":evidence_url,
                        "description":"The stored API specification does not declare authentication schemes; this is a candidate requiring manual validation.",
                        "evidence":{"title":normalized.get("title"),"endpoint_count":len(normalized["endpoints"]),"security_schemes":[]},
                        "remediation":"Document and enforce authentication requirements for protected API operations.",
                        "fingerprint":__import__("hashlib").sha256(f"{project_id}:{job.asset_id}:{evidence_url}:api_no_security".encode()).hexdigest()})
            else:
                candidates=[]
        for item in candidates[:max(0, 100-len(findings))]:
            if await db.scalar(select(Finding.id).where(Finding.fingerprint == item["fingerprint"])): continue
            finding=Finding(project_id=project_id,asset_id=job.asset_id,job_id=job.id,title=item["title"],
                severity=item["severity"],status="open",endpoint=item["endpoint"],description=item["description"],
                evidence=str(item["evidence"]),category=item["category"],confidence=item["confidence"],
                remediation=item["remediation"],fingerprint=item["fingerprint"])
            db.add(finding); await db.flush()
            db.add(Evidence(project_id=project_id,job_id=job.id,result_id=observation_result.id,finding_id=finding.id,evidence_type="json",
                title=item["title"],description=item["description"],path_reference=item["endpoint"],metadata_json=item["evidence"]))
            findings.append({"id":finding.id,"title":finding.title,"severity":finding.severity,"confidence":finding.confidence})
    job.status="completed"; job.completed_at=datetime.now(timezone.utc)
    await write_audit_log(db, project_id=project_id,user=job.approved_by or job.requested_by,
        action="advanced_assessment_completed",entity_type="security_job",entity_id=job.id,
        target=job.target_snapshot["target"],details={"findings":len(findings),"api_documents":len(api_specs),"parameters":len(parameters)})
    await db.commit()
    return {"job_id":job.id,"status":job.status,"endpoints_inspected":len(observations),
            "api_documents":api_specs,"parameters":parameters[:MAX_ENDPOINTS*50],"findings":findings}

@router.get("/projects/{project_id}/security-assessments/{kind}")
async def list_assessments(project_id: int, kind: str, db: AsyncSession = Depends(get_db)):
    if kind not in {"web","api"}: raise HTTPException(404,"Assessment type not found.")
    rows=list((await db.scalars(select(SecurityJob).where(SecurityJob.project_id==project_id,
        SecurityJob.parameters["assessment"].as_string()==kind).order_by(SecurityJob.id.desc()).limit(100))).all())
    return [{"id":r.id,"asset_id":r.asset_id,"status":r.status,"created_at":r.created_at,
        "completed_at":r.completed_at} for r in rows]
