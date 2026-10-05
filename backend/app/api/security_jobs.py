import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.config import get_data_dir
from app.models.assessment_taxonomy import TestModule
from app.models.project import Project
from app.models.scan_profile import ScanProfile
from app.models.security_job import SecurityJob
from app.models.tool import Tool
from app.models.evidence import Evidence
from app.models.security_result import SecurityResult
from app.services.security_audit import write_audit_log
from app.services.security_authorization import TargetAuthorization, security_authorization
from app.services.tool_adapters import adapter_registry
from app.services.tool_adapters import _target_host
from app.services import recon_execution

router = APIRouter(tags=["Security Jobs"])

def _reject_command_fields(value: Any, path: str = "parameters") -> None:
    forbidden = {"command", "shell", "shell_command", "executable", "argv", "working_directory"}
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in forbidden:
                raise ValueError(f"{path}.{key} is not an accepted structured parameter.")
            _reject_command_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_command_fields(child, f"{path}[{index}]")


class SecurityJobCreate(BaseModel):
    profile_id: int = Field(ge=1)
    target: str = Field(min_length=1, max_length=2000)
    module_ids: list[int] = Field(min_length=1, max_length=100)
    tool_ids: list[int] = Field(default_factory=list, max_length=50)
    asset_id: int | None = Field(default=None, ge=1)
    requested_by: str = Field(default="local-user", min_length=1, max_length=200)
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("parameters")
    @classmethod
    def structured_parameters_only(cls, value):
        _reject_command_fields(value)
        return value


class ApprovalRequest(BaseModel):
    approved_by: str = Field(min_length=1, max_length=200)


class SecurityJobResponse(BaseModel):
    id: int
    project_id: int
    profile_id: int
    asset_id: int | None
    status: str
    requested_by: str
    approved_by: str | None
    approval_timestamp: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    target_snapshot: dict
    scope_snapshot: dict
    profile_snapshot: dict
    parameters: dict
    error: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DerivedTargetCheck(BaseModel):
    target: str = Field(min_length=1, max_length=2000)


class DerivedTargetDecision(BaseModel):
    allowed: bool
    reason: str
    scope_snapshot: dict


class SelectedHostsRequest(BaseModel):
    hostnames: list[str] = Field(min_length=1, max_length=100)

    @field_validator("hostnames")
    @classmethod
    def normalized_unique_hostnames(cls, values):
        normalized = []
        for value in values:
            if not isinstance(value, str) or any(mark in value for mark in (":", "/", "@", "\\")):
                raise ValueError("Selected hosts must be plain DNS hostnames.")
            host = _target_host(value).lower().rstrip(".")
            if host not in normalized:
                normalized.append(host)
        return normalized


async def _get_job(db: AsyncSession, project_id: int, job_id: int) -> SecurityJob:
    job = await db.scalar(
        select(SecurityJob).where(
            SecurityJob.id == job_id, SecurityJob.project_id == project_id
        )
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Security job not found.")
    return job


def _job_modules_snapshot(modules: list[TestModule]) -> list[dict]:
    return [
        {
            "id": module.id,
            "key": module.key,
            "name": module.name,
            "enabled": module.enabled,
            "requires_approval": module.requires_approval,
        }
        for module in sorted(modules, key=lambda item: item.id)
    ]


async def _block_for_changed_catalog(
    db: AsyncSession, job: SecurityJob
) -> str | None:
    profile = await db.scalar(
        select(ScanProfile)
        .options(selectinload(ScanProfile.modules))
        .where(ScanProfile.id == job.profile_id)
    )
    if profile is None:
        return "Selected scan profile no longer exists."
    if not profile.enabled:
        return "Selected scan profile is disabled."
    saved_module_ids = [item["id"] for item in job.profile_snapshot.get("modules", [])]
    current_modules = [module for module in profile.modules if module.id in saved_module_ids]
    if {module.id for module in current_modules} != set(saved_module_ids):
        return "Selected profile modules changed after job creation."
    if any(not module.enabled for module in current_modules):
        return "A selected test module is disabled."

    tool_ids = job.profile_snapshot.get("tool_ids", [])
    if tool_ids:
        tools = list((await db.scalars(select(Tool).where(Tool.id.in_(tool_ids)))).all())
        if {tool.id for tool in tools} != set(tool_ids):
            return "A selected tool no longer exists."
        for tool in tools:
            if not tool.enabled or not tool.local_only:
                return f"Selected tool '{tool.key}' is disabled or not local-only."
            available, reason = adapter_registry.check_tool(tool.key, tool.executable)
            await write_audit_log(
                db, project_id=job.project_id, user=job.requested_by,
                action="adapter_availability_checked", entity_type="tool",
                entity_id=tool.id, target=job.target_snapshot.get("target"),
                details={"tool_key": tool.key, "available": available, "reason": reason},
            )
            if not available:
                return f"Tool adapter unavailable for '{tool.key}': {reason}"
    return None


@router.post(
    "/projects/{project_id}/security-jobs",
    response_model=SecurityJobResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_security_job(
    project_id: int,
    data: SecurityJobCreate,
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")

    profile = await db.scalar(
        select(ScanProfile)
        .options(selectinload(ScanProfile.modules))
        .where(ScanProfile.id == data.profile_id)
    )
    if profile is None or (profile.project_id is not None and profile.project_id != project_id):
        raise HTTPException(status_code=404, detail="Scan profile not found for this project.")

    requested_module_ids = list(dict.fromkeys(data.module_ids))
    modules = list((await db.scalars(
        select(TestModule).where(TestModule.id.in_(requested_module_ids))
    )).all())
    if {module.id for module in modules} != set(requested_module_ids):
        raise HTTPException(status_code=404, detail="One or more test modules do not exist.")
    profile_module_ids = {module.id for module in profile.modules}
    if not set(requested_module_ids) <= profile_module_ids:
        raise HTTPException(status_code=422, detail="Selected modules are not part of this profile.")

    tool_ids = list(dict.fromkeys(data.tool_ids))
    tools = list((await db.scalars(select(Tool).options(selectinload(Tool.modules)).where(
        Tool.id.in_(tool_ids)))).all()) if tool_ids else []
    if {tool.id for tool in tools} != set(tool_ids):
        raise HTTPException(status_code=404, detail="One or more tools do not exist.")

    authorization = await security_authorization.validate_target(
        db, project_id, data.target, data.asset_id
    )
    reasons = []
    tls_requested = any(tool.key == "tls_inspector" for tool in tools)
    web_surface_requested = any(tool.key == "web_surface_discovery" for tool in tools)
    service_requested = any(tool.key == "tcp_service_awareness" for tool in tools)
    if (tls_requested or web_surface_requested) and data.asset_id is None:
        operation = "Web surface discovery" if web_surface_requested else "TLS inspection"
        reasons.append(f"{operation} requires selecting an existing asset in this project.")
    if service_requested and data.asset_id is None:
        reasons.append("TCP service awareness requires selecting an existing project asset.")
    if not profile.enabled:
        reasons.append("Selected scan profile is disabled.")
    if any(not module.enabled for module in modules):
        reasons.append("One or more selected test modules are disabled.")
    if any(not tool.enabled or not tool.local_only for tool in tools):
        reasons.append("One or more selected tools are disabled or not local-only.")
    if not authorization.allowed:
        reasons.append(authorization.reason)
    for tool in tools:
        compatible_module_ids = {module.id for module in tool.modules}
        if compatible_module_ids and not compatible_module_ids.intersection(requested_module_ids):
            reasons.append(f"Selected tool '{tool.key}' does not support the selected modules.")
        available, reason = adapter_registry.check_tool(tool.key, tool.executable)
        await write_audit_log(
            db, project_id=project_id, user=data.requested_by,
            action="adapter_availability_checked", entity_type="tool", entity_id=tool.id,
            target=data.target,
            details={"tool_key": tool.key, "available": available, "reason": reason},
        )
        if not available:
            reasons.append(f"Tool adapter unavailable for '{tool.key}': {reason}")
        if tool.key == "subfinder":
            adapter = adapter_registry.get_for_tool(tool.key)
            try:
                if adapter is None:
                    raise ValueError("Subfinder adapter is not registered.")
                adapter.build_execution_plan(
                    data.target, {**data.parameters, "executable": tool.executable}
                )
            except (TypeError, ValueError) as error:
                reasons.append(f"Subfinder target or parameters are invalid: {error}")
        elif tool.key in {"windows_nslookup", "curl_head", "tls_inspector", "web_surface_discovery", "tcp_service_awareness"}:
            adapter = adapter_registry.get_for_tool(tool.key)
            try:
                if adapter is None:
                    raise ValueError("Registered adapter is unavailable.")
                adapter.build_execution_plans(
                    data.target, {**data.parameters, "executable": tool.executable}
                )
            except (TypeError, ValueError) as error:
                reasons.append(f"{tool.name} target or parameters are invalid: {error}")

    status_value = "blocked" if reasons else "pending_approval"
    tool_snapshot = [
        {
            "id": tool.id, "key": tool.key, "name": tool.name,
            "enabled": tool.enabled, "local_only": tool.local_only,
        }
        for tool in sorted(tools, key=lambda item: item.id)
    ]
    job = SecurityJob(
        project_id=project_id,
        profile_id=profile.id,
        asset_id=data.asset_id,
        status=status_value,
        requested_by=data.requested_by.strip(),
        target_snapshot={
            "target": data.target.strip(),
            "asset_id": data.asset_id,
            "authorization": authorization.scope_snapshot.get("authorization"),
        },
        scope_snapshot=authorization.scope_snapshot,
        profile_snapshot={
            "id": profile.id, "key": profile.key, "name": profile.name,
            "enabled": profile.enabled, "passive_only": profile.passive_only,
            "active_testing": profile.active_testing,
            "default_timeout": profile.default_timeout,
            "modules": _job_modules_snapshot(modules),
            "tool_ids": [tool.id for tool in sorted(tools, key=lambda item: item.id)],
            "tools": tool_snapshot,
        },
        parameters=data.parameters,
        error="; ".join(reasons) if reasons else None,
    )
    db.add(job)
    await db.flush()
    await write_audit_log(
        db, project_id=project_id, user=data.requested_by,
        action="job_created" if not reasons else "job_blocked",
        entity_type="security_job", entity_id=job.id, target=data.target,
        details={"status": status_value, "profile_id": profile.id,
                 "module_ids": requested_module_ids, "tool_ids": tool_ids,
                 "blocked_reasons": reasons},
    )
    await write_audit_log(
        db, project_id=project_id, user=data.requested_by,
        action="authorization_checked", entity_type="security_job", entity_id=job.id,
        target=data.target, details={"allowed": authorization.allowed,
                                     "reason": authorization.reason, "phase": "creation"},
    )
    if not authorization.allowed:
        await write_audit_log(
            db, project_id=project_id, user=data.requested_by,
            action="scope_validation_failure", entity_type="security_job",
            entity_id=job.id, target=data.target,
            details={"reason": authorization.reason},
        )
    if tls_requested:
        await write_audit_log(
            db, project_id=project_id, user=data.requested_by,
            action="tls_inspection_requested", entity_type="security_job",
            entity_id=job.id, target=data.target,
            details={"asset_id": data.asset_id, "status": status_value},
        )
        await write_audit_log(
            db, project_id=project_id, user=data.requested_by,
            action=("tls_authorization_accepted" if authorization.allowed and data.asset_id is not None
                    else "tls_authorization_rejected"),
            entity_type="security_job", entity_id=job.id, target=data.target,
            details={"allowed": authorization.allowed and data.asset_id is not None,
                     "reason": authorization.reason if data.asset_id is not None else
                     "TLS inspection requires selecting an existing project asset."},
        )
    if web_surface_requested:
        await write_audit_log(
            db, project_id=project_id, user=data.requested_by,
            action="web_surface_discovery_requested", entity_type="security_job",
            entity_id=job.id, target=data.target,
            details={"asset_id": data.asset_id, "status": status_value},
        )
        await write_audit_log(
            db, project_id=project_id, user=data.requested_by,
            action=("web_surface_authorization_accepted"
                    if authorization.allowed and data.asset_id is not None
                    else "web_surface_authorization_rejected"),
            entity_type="security_job", entity_id=job.id, target=data.target,
            details={"allowed": authorization.allowed and data.asset_id is not None,
                     "reason": authorization.reason if data.asset_id is not None else
                     "Web surface discovery requires selecting an existing project asset."},
        )
    await db.commit()
    await db.refresh(job)
    return job


@router.post(
    "/projects/{project_id}/security-jobs/{job_id}/probe-selected",
    response_model=list[SecurityJobResponse], status_code=status.HTTP_201_CREATED,
)
async def create_selected_host_probes(
    project_id: int,
    job_id: int,
    data: SelectedHostsRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create separate approval-gated HTTP jobs for explicitly selected results."""
    source_job = await _get_job(db, project_id, job_id)
    if source_job.status != "completed":
        raise HTTPException(status_code=409, detail="Hosts can be selected only from a completed recon job.")
    result_rows = list((await db.scalars(select(SecurityResult).where(
        SecurityResult.project_id == project_id, SecurityResult.job_id == job_id
    ).order_by(SecurityResult.id))).all())
    candidates = set()
    for row in result_rows:
        normalized = row.normalized_data or {}
        if row.result_type == "subdomain" and normalized.get("authorization_status") == "authorized":
            candidates.add(normalized.get("hostname", "").lower().rstrip("."))
        elif (row.result_type == "dns_record"
              and normalized.get("authorization_status") == "authorized"
              and normalized.get("candidate_hostname")):
            candidates.add(normalized["candidate_hostname"].lower().rstrip("."))
    not_discovered = [host for host in data.hostnames if host not in candidates]
    if not_discovered:
        await write_audit_log(
            db, project_id=project_id, user="local-user", action="host_selection_rejected",
            entity_type="security_job", entity_id=job_id,
            details={"reason": "Hosts were not present as probe candidates in source results.",
                     "hostnames": not_discovered},
        )
        await db.commit()
        raise HTTPException(status_code=422, detail="One or more selected hosts are not discovered probe candidates.")

    decisions = []
    for hostname in data.hostnames:
        decision = await security_authorization.validate_derived_target(db, project_id, hostname)
        decisions.append((hostname, decision))
    rejected = [(host, decision) for host, decision in decisions if not decision.allowed]
    if rejected:
        for hostname, decision in rejected:
            await write_audit_log(
                db, project_id=project_id, user="local-user",
                action="host_selection_scope_rejected", entity_type="security_job",
                entity_id=job_id, target=hostname,
                details={"reason": decision.reason, "source_job_id": job_id},
            )
        await db.commit()
        raise HTTPException(status_code=403, detail="A selected host is outside the project's current scope.")

    profile = await db.scalar(select(ScanProfile).options(selectinload(ScanProfile.modules)).where(
        ScanProfile.project_id.is_(None), ScanProfile.key == "web_baseline"))
    module = await db.scalar(select(TestModule).where(TestModule.key == "web_discovery_review"))
    tool = await db.scalar(select(Tool).options(selectinload(Tool.modules)).where(Tool.key == "curl_head"))
    if profile is None or module is None or tool is None or module.id not in {m.id for m in profile.modules}:
        raise HTTPException(status_code=503, detail="Registered HTTP probing catalog is incomplete.")
    available, availability_reason = adapter_registry.check_tool(tool.key, tool.executable)
    if not tool.enabled:
        availability_reason = "Registered HTTP probing tool is disabled."
    elif not tool.local_only:
        availability_reason = "HTTP probing tool is not local-only."
    created_jobs = []
    for hostname, decision in decisions:
        status_value = "pending_approval" if tool.enabled and tool.local_only and available else "blocked"
        reason = None if status_value == "pending_approval" else availability_reason
        job = SecurityJob(
            project_id=project_id, profile_id=profile.id, asset_id=None,
            status=status_value, requested_by="local-user",
            target_snapshot={"target": hostname, "asset_id": None,
                             "authorization": decision.scope_snapshot.get("authorization"),
                             "selected_from_job_id": job_id},
            scope_snapshot=decision.scope_snapshot,
            profile_snapshot={
                "id": profile.id, "key": profile.key, "name": profile.name,
                "enabled": profile.enabled, "passive_only": profile.passive_only,
                "active_testing": profile.active_testing, "default_timeout": 20,
                "modules": _job_modules_snapshot([module]),
                "tool_ids": [tool.id],
                "tools": [{"id": tool.id, "key": tool.key, "name": tool.name,
                           "enabled": tool.enabled, "local_only": tool.local_only}],
            },
            parameters={"http_mode": "bounded_get", "timeout": 20,
                        "source_job_id": job_id},
            error=reason,
        )
        db.add(job)
        await db.flush()
        await write_audit_log(
            db, project_id=project_id, user="local-user", action="job_created" if not reason else "job_blocked",
            entity_type="security_job", entity_id=job.id, target=hostname,
            details={"status": status_value, "source_job_id": job_id,
                     "tool_key": tool.key, "http_mode": "bounded_get",
                     "availability_reason": availability_reason},
        )
        await write_audit_log(
            db, project_id=project_id, user="local-user", action="authorization_checked",
            entity_type="security_job", entity_id=job.id, target=hostname,
            details={"allowed": True, "reason": decision.reason,
                     "phase": "explicit_host_selection", "source_job_id": job_id},
        )
        created_jobs.append(job)
    await write_audit_log(
        db, project_id=project_id, user="local-user", action="hosts_selected_for_http_probe",
        entity_type="security_job", entity_id=job_id,
        details={"hostnames": data.hostnames, "created_job_ids": [job.id for job in created_jobs]},
    )
    await db.commit()
    for job in created_jobs:
        await db.refresh(job)
    return created_jobs


@router.post(
    "/projects/{project_id}/security-jobs/{job_id}/inspect-tls-selected",
    response_model=list[SecurityJobResponse], status_code=status.HTTP_201_CREATED,
)
async def create_selected_host_tls_jobs(
    project_id: int, job_id: int, data: SelectedHostsRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create approval-gated TLS jobs for explicitly selected authorized discovery results."""
    source_job = await _get_job(db, project_id, job_id)
    await write_audit_log(
        db, project_id=project_id, user="local-user",
        action="tls_inspection_requested", entity_type="security_job", entity_id=job_id,
        details={"hostnames": data.hostnames, "source_job_id": job_id},
    )
    if source_job.status != "completed":
        await db.commit()
        raise HTTPException(status_code=409, detail="Hosts can be selected only from a completed recon job.")
    rows = list((await db.scalars(select(SecurityResult).where(
        SecurityResult.project_id == project_id, SecurityResult.job_id == job_id))).all())
    candidates = set()
    for row in rows:
        normalized = row.normalized_data or {}
        host = normalized.get("hostname") if row.result_type == "subdomain" else (
            normalized.get("candidate_hostname") if row.result_type == "dns_record" else None)
        if host and normalized.get("authorization_status") == "authorized":
            candidates.add(host.lower().rstrip("."))
    if any(host not in candidates for host in data.hostnames):
        await write_audit_log(db, project_id=project_id, user="local-user",
                              action="host_selection_rejected", entity_type="security_job",
                              entity_id=job_id, details={"tool_key": "tls_inspector",
                              "hostnames": data.hostnames, "reason": "not an authorized source result"})
        await write_audit_log(
            db, project_id=project_id, user="local-user",
            action="tls_authorization_rejected", entity_type="security_job", entity_id=job_id,
            details={"hostnames": data.hostnames,
                     "reason": "not an authorized discovery result"},
        )
        await db.commit()
        raise HTTPException(status_code=422, detail="One or more selected hosts are not authorized discovery results.")
    decisions = [(host, await security_authorization.validate_derived_target(db, project_id, host))
                 for host in data.hostnames]
    if any(not decision.allowed for _, decision in decisions):
        for host, decision in decisions:
            if not decision.allowed:
                await write_audit_log(db, project_id=project_id, user="local-user",
                                      action="host_selection_scope_rejected", entity_type="security_job",
                                      entity_id=job_id, target=host,
                                      details={"tool_key": "tls_inspector", "reason": decision.reason})
                await write_audit_log(
                    db, project_id=project_id, user="local-user",
                    action="tls_authorization_rejected", entity_type="security_job",
                    entity_id=job_id, target=host,
                    details={"allowed": False, "reason": decision.reason},
                )
        await db.commit()
        raise HTTPException(status_code=403, detail="A selected host is outside the project's current scope.")
    profile = await db.scalar(select(ScanProfile).options(selectinload(ScanProfile.modules)).where(
        ScanProfile.project_id.is_(None), ScanProfile.key == "web_baseline"))
    module = await db.scalar(select(TestModule).where(TestModule.key == "web_discovery_review"))
    tool = await db.scalar(select(Tool).options(selectinload(Tool.modules)).where(Tool.key == "tls_inspector"))
    if profile is None or module is None or tool is None or module.id not in {m.id for m in profile.modules}:
        raise HTTPException(status_code=503, detail="Registered TLS inspection catalog is incomplete.")
    available, reason = adapter_registry.check_tool(tool.key, tool.executable)
    jobs = []
    for host, decision in decisions:
        job = SecurityJob(
            project_id=project_id, profile_id=profile.id, asset_id=None,
            status="pending_approval" if available and tool.enabled and tool.local_only else "blocked",
            requested_by="local-user",
            target_snapshot={"target": host, "asset_id": None,
                             "authorization": decision.scope_snapshot.get("authorization"),
                             "selected_from_job_id": job_id},
            scope_snapshot=decision.scope_snapshot,
            profile_snapshot={"id": profile.id, "key": profile.key, "name": profile.name,
                              "enabled": profile.enabled, "passive_only": profile.passive_only,
                              "active_testing": profile.active_testing, "default_timeout": 15,
                              "modules": _job_modules_snapshot([module]), "tool_ids": [tool.id],
                              "tools": [{"id": tool.id, "key": tool.key, "name": tool.name,
                                         "enabled": tool.enabled, "local_only": tool.local_only}]},
            parameters={"timeout": 15, "source_job_id": job_id},
            error=None if available and tool.enabled and tool.local_only else reason,
        )
        db.add(job)
        await db.flush()
        await write_audit_log(db, project_id=project_id, user="local-user",
                              action="job_created" if job.status == "pending_approval" else "job_blocked",
                              entity_type="security_job", entity_id=job.id, target=host,
                              details={"tool_key": tool.key, "status": job.status,
                                       "source_job_id": job_id})
        await write_audit_log(db, project_id=project_id, user="local-user",
                              action="authorization_checked", entity_type="security_job",
                              entity_id=job.id, target=host,
                              details={"allowed": decision.allowed, "reason": decision.reason,
                                       "phase": "explicit_tls_host_selection"})
        await write_audit_log(
            db, project_id=project_id, user="local-user",
            action="tls_inspection_requested", entity_type="security_job",
            entity_id=job.id, target=host,
            details={"source_job_id": job_id, "status": job.status},
        )
        await write_audit_log(
            db, project_id=project_id, user="local-user",
            action="tls_authorization_accepted", entity_type="security_job",
            entity_id=job.id, target=host,
            details={"allowed": decision.allowed, "reason": decision.reason},
        )
        jobs.append(job)
    await write_audit_log(db, project_id=project_id, user="local-user",
                          action="hosts_selected_for_tls_inspection", entity_type="security_job",
                          entity_id=job_id, details={"hostnames": data.hostnames,
                                                    "created_job_ids": [job.id for job in jobs]})
    await db.commit()
    for job in jobs:
        await db.refresh(job)
    return jobs


@router.get("/projects/{project_id}/security-jobs", response_model=list[SecurityJobResponse])
async def list_security_jobs(
    project_id: int,
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    if await db.get(Project, project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return list((await db.scalars(
        select(SecurityJob).where(SecurityJob.project_id == project_id)
        .order_by(SecurityJob.id.desc()).limit(limit)
    )).all())


@router.get(
    "/projects/{project_id}/security-jobs/{job_id}", response_model=SecurityJobResponse
)
async def get_security_job(project_id: int, job_id: int, db: AsyncSession = Depends(get_db)):
    return await _get_job(db, project_id, job_id)


@router.get("/projects/{project_id}/security-jobs/{job_id}/execution")
async def get_security_job_execution(project_id: int, job_id: int, db: AsyncSession = Depends(get_db)):
    job = await _get_job(db, project_id, job_id)
    evidence = list((await db.scalars(select(Evidence).where(
        Evidence.project_id == project_id, Evidence.job_id == job_id
    ).order_by(Evidence.id))).all())
    results = list((await db.scalars(select(SecurityResult).where(
        SecurityResult.project_id == project_id, SecurityResult.job_id == job_id
    ).order_by(SecurityResult.id))).all())
    evidence_payload = []
    allowed_dir = (get_data_dir() / "evidence" / "recon").resolve()
    for row in evidence:
        output = None
        if row.path_reference:
            path = Path(row.path_reference).resolve()
            if path.parent == allowed_dir and path.is_file():
                # Read a bounded prefix rather than loading a potentially
                # oversized local artifact before slicing it.
                with path.open("rb") as artifact_file:
                    output = artifact_file.read(2_000_001).decode("utf-8", errors="replace")[:2_000_000]
        evidence_payload.append({"id": row.id, "evidence_type": row.evidence_type,
                                 "title": row.title, "path_reference": row.path_reference,
                                 "content_hash": row.content_hash, "metadata": row.metadata_json,
                                 "output": output, "created_at": row.created_at})
    return {
        "job_id": job.id,
        "status": job.status,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "error": job.error,
        "results": [{"id": row.id, "result_type": row.result_type, "target": row.target,
                     "title": row.title, "summary": row.summary,
                     "raw_reference": row.raw_reference, "normalized_data": row.normalized_data,
                     "created_at": row.created_at} for row in results],
        "evidence": evidence_payload,
    }


@router.post(
    "/projects/{project_id}/security-jobs/{job_id}/approve",
    response_model=SecurityJobResponse,
)
async def approve_security_job(
    project_id: int,
    job_id: int,
    data: ApprovalRequest,
    db: AsyncSession = Depends(get_db),
):
    job = await _get_job(db, project_id, job_id)
    if job.status != "pending_approval":
        if any(item.get("key") == "tls_inspector"
               for item in job.profile_snapshot.get("tools", [])):
            await write_audit_log(
                db, project_id=project_id, user=data.approved_by,
                action="tls_approval_rejected", entity_type="security_job", entity_id=job.id,
                target=job.target_snapshot.get("target"),
                details={"status": job.status, "reason": "Only pending jobs can be approved."},
            )
        if any(item.get("key") == "web_surface_discovery"
               for item in job.profile_snapshot.get("tools", [])):
            await write_audit_log(
                db, project_id=project_id, user=data.approved_by,
                action="web_surface_approval_rejected", entity_type="security_job",
                entity_id=job.id, target=job.target_snapshot.get("target"),
                details={"status": job.status, "reason": "Only pending jobs can be approved."},
            )
            await db.commit()
        raise HTTPException(status_code=409, detail="Only pending jobs can be approved.")

    changed_catalog_reason = await _block_for_changed_catalog(db, job)
    authorization = await security_authorization.validate_target(
        db, project_id, job.target_snapshot["target"], job.asset_id
    )
    reasons = [reason for reason in (changed_catalog_reason,) if reason]
    if not authorization.allowed:
        reasons.append(authorization.reason)
    if reasons:
        job.status = "blocked"
        job.error = "; ".join(reasons)
        job.scope_snapshot = authorization.scope_snapshot
        if any(item.get("key") == "tls_inspector"
               for item in job.profile_snapshot.get("tools", [])):
            await write_audit_log(
                db, project_id=project_id, user=data.approved_by,
                action="tls_approval_rejected", entity_type="security_job", entity_id=job.id,
                target=job.target_snapshot.get("target"),
                details={"status": "blocked", "reasons": reasons},
            )
        if any(item.get("key") == "web_surface_discovery"
               for item in job.profile_snapshot.get("tools", [])):
            await write_audit_log(
                db, project_id=project_id, user=data.approved_by,
                action="web_surface_approval_rejected", entity_type="security_job",
                entity_id=job.id, target=job.target_snapshot.get("target"),
                details={"status": "blocked", "reasons": reasons},
            )
        await write_audit_log(
            db, project_id=project_id, user=data.approved_by,
            action="job_blocked", entity_type="security_job", entity_id=job.id,
            target=job.target_snapshot.get("target"), details={"reasons": reasons},
        )
        await write_audit_log(
            db, project_id=project_id, user=data.approved_by,
            action="authorization_checked", entity_type="security_job", entity_id=job.id,
            target=job.target_snapshot.get("target"),
            details={"allowed": authorization.allowed, "reason": authorization.reason,
                     "phase": "approval"},
        )
        if not authorization.allowed:
            await write_audit_log(
                db, project_id=project_id, user=data.approved_by,
                action="scope_validation_failure", entity_type="security_job",
                entity_id=job.id, target=job.target_snapshot.get("target"),
                details={"reason": authorization.reason},
            )
        await db.commit()
        await db.refresh(job)
        return job

    # Capture current authorization at approval time. Future scope edits never
    # mutate this immutable JSON snapshot on the approved job.
    job.scope_snapshot = authorization.scope_snapshot
    job.target_snapshot = {
        **job.target_snapshot,
        "authorization": authorization.scope_snapshot.get("authorization"),
    }
    job.status = "approved"
    job.approved_by = data.approved_by.strip()
    job.approval_timestamp = datetime.now(timezone.utc)
    snapshot = {
        "target": job.target_snapshot,
        "scope": job.scope_snapshot,
        "profile": job.profile_snapshot,
        "parameters": job.parameters,
    }
    snapshot_hash = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    await write_audit_log(
        db, project_id=project_id, user=job.approved_by,
        action="job_approved", entity_type="security_job", entity_id=job.id,
        target=job.target_snapshot.get("target"),
        details={"profile_id": job.profile_id,
                 "module_ids": [item["id"] for item in job.profile_snapshot["modules"]],
                 "tool_ids": job.profile_snapshot["tool_ids"],
                 "snapshot_sha256": snapshot_hash},
    )
    if any(item.get("key") == "tls_inspector"
           for item in job.profile_snapshot.get("tools", [])):
        await write_audit_log(
            db, project_id=project_id, user=job.approved_by,
            action="tls_approval_accepted", entity_type="security_job", entity_id=job.id,
            target=job.target_snapshot.get("target"), details={"approved": True},
        )
    if any(item.get("key") == "web_surface_discovery"
           for item in job.profile_snapshot.get("tools", [])):
        await write_audit_log(
            db, project_id=project_id, user=job.approved_by,
            action="web_surface_approval_accepted", entity_type="security_job",
            entity_id=job.id, target=job.target_snapshot.get("target"),
            details={"approved": True},
        )
    await write_audit_log(
        db, project_id=project_id, user=job.approved_by,
        action="authorization_checked", entity_type="security_job", entity_id=job.id,
        target=job.target_snapshot.get("target"),
        details={"allowed": True, "reason": authorization.reason, "phase": "approval"},
    )
    await db.commit()
    await db.refresh(job)
    return job


@router.post(
    "/projects/{project_id}/security-jobs/{job_id}/cancel",
    response_model=SecurityJobResponse,
)
async def cancel_security_job(
    project_id: int, job_id: int, db: AsyncSession = Depends(get_db)
):
    job = await _get_job(db, project_id, job_id)
    if job.status == "running":
        await recon_execution.cancel_job(job.id)
        await db.refresh(job)
        if job.status == "cancelled":
            return job
    if job.status == "queued":
        await recon_execution.cancel_job(job.id)
        await db.refresh(job)
        if job.status == "queued":
            job.status, job.completed_at = "cancelled", datetime.now(timezone.utc)
            await write_audit_log(
                db, project_id=project_id, user=job.approved_by or job.requested_by,
                action="execution_cancelled", entity_type="security_job", entity_id=job.id,
                target=job.target_snapshot.get("target"), details={"phase": "queued"},
            )
            await db.commit()
            await db.refresh(job)
            return job
        if job.status == "cancelled":
            return job
    if job.status not in {"draft", "pending_approval", "approved", "queued"}:
        raise HTTPException(status_code=409, detail="This security job cannot be cancelled.")
    previous_status = job.status
    job.status = "cancelled"
    await write_audit_log(
        db, project_id=project_id, user="local-user", action="job_cancelled",
        entity_type="security_job", entity_id=job.id,
        target=job.target_snapshot.get("target"), details={"previous_status": previous_status},
    )
    await db.commit()
    await db.refresh(job)
    return job


@router.post("/projects/{project_id}/security-jobs/{job_id}/run")
async def run_security_job(
    project_id: int, job_id: int, db: AsyncSession = Depends(get_db)
):
    job = await _get_job(db, project_id, job_id)
    if job.status != "approved" or not job.approved_by or not job.approval_timestamp:
        raise HTTPException(status_code=409, detail="Security job requires explicit approval.")
    if not job.profile_snapshot.get("tool_ids"):
        raise HTTPException(status_code=409, detail="Select an available registered recon tool before execution.")
    target = job.target_snapshot["target"]
    authorization = await security_authorization.validate_target(db, project_id, target, job.asset_id)
    await write_audit_log(
        db, project_id=project_id, user=job.approved_by,
        action="authorization_checked", entity_type="security_job", entity_id=job.id,
        target=target, details={"allowed": authorization.allowed,
                                "reason": authorization.reason, "phase": "execution_request"},
    )
    if not authorization.allowed:
        job.status, job.error = "blocked", authorization.reason
        await write_audit_log(
            db, project_id=project_id, user=job.approved_by,
            action="scope_rejected", entity_type="security_job", entity_id=job.id,
            target=target, details={"reason": authorization.reason},
        )
        if any(item.get("key") == "tls_inspector"
               for item in job.profile_snapshot.get("tools", [])):
            await write_audit_log(
                db, project_id=project_id, user=job.approved_by,
                action="tls_authorization_rejected", entity_type="security_job",
                entity_id=job.id, target=target,
                details={"allowed": False, "reason": authorization.reason},
            )
        if any(item.get("key") == "web_surface_discovery"
               for item in job.profile_snapshot.get("tools", [])):
            await write_audit_log(
                db, project_id=project_id, user=job.approved_by,
                action="web_surface_authorization_rejected", entity_type="security_job",
                entity_id=job.id, target=target,
                details={"allowed": False, "reason": authorization.reason},
            )
        await db.commit()
        raise HTTPException(status_code=403, detail=f"Execution blocked by scope: {authorization.reason}")
    job.status, job.error = "queued", None
    await write_audit_log(
        db, project_id=project_id, user=job.approved_by,
        action="execution_queued", entity_type="security_job", entity_id=job.id,
        target=target, details={"tool_ids": job.profile_snapshot["tool_ids"]},
    )
    await db.commit()
    await db.refresh(job)
    await recon_execution.start_job(job.id)
    return job


@router.post(
    "/projects/{project_id}/security-jobs/{job_id}/derived-target-check",
    response_model=DerivedTargetDecision,
)
async def check_derived_target(
    project_id: int,
    job_id: int,
    data: DerivedTargetCheck,
    db: AsyncSession = Depends(get_db),
):
    await _get_job(db, project_id, job_id)
    decision: TargetAuthorization = await security_authorization.validate_derived_target(
        db, project_id, data.target
    )
    if not decision.allowed:
        await write_audit_log(
            db, project_id=project_id, user="local-user",
            action="scope_validation_failure", entity_type="derived_target",
            entity_id=job_id, target=data.target, details={"reason": decision.reason},
        )
        await db.commit()
    return DerivedTargetDecision(
        allowed=decision.allowed, reason=decision.reason,
        scope_snapshot=decision.scope_snapshot,
    )
