from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.assessment_taxonomy import AssessmentCategory, AssessmentDomain, TestModule
from app.models.scan_profile import ScanProfile
from app.models.project import Project
from app.models.tool import Tool
from app.services.tool_adapters import adapter_registry

router = APIRouter(tags=["Assessment Catalog"])


class DomainResponse(BaseModel):
    id: int
    key: str
    name: str
    description: str | None
    enabled: bool
    created_at: datetime
    model_config = {"from_attributes": True}


class CategoryResponse(BaseModel):
    id: int
    domain_id: int
    domain_key: str
    key: str
    name: str
    description: str | None
    enabled: bool
    created_at: datetime


class ModuleResponse(BaseModel):
    id: int
    category_id: int
    category_key: str
    domain_key: str
    key: str
    name: str
    description: str | None
    risk_level: str
    requires_approval: bool
    enabled: bool
    created_at: datetime


class ToolResponse(BaseModel):
    id: int
    key: str
    name: str
    version: str | None
    description: str | None
    vendor: str | None
    domain_id: int | None
    category_id: int | None
    executable: str | None
    installation_hint: str | None
    capabilities: list[str]
    enabled: bool
    local_only: bool
    requires_explicit_approval: bool
    adapter_available: bool
    availability_reason: str
    created_at: datetime
    updated_at: datetime


class ProfileResponse(BaseModel):
    id: int
    project_id: int | None
    key: str
    name: str
    description: str | None
    enabled: bool
    passive_only: bool
    active_testing: bool
    default_timeout: int
    module_ids: list[int]
    created_at: datetime
    updated_at: datetime


@router.get("/assessment-domains", response_model=list[DomainResponse])
async def list_domains(db: AsyncSession = Depends(get_db)):
    return list((await db.scalars(select(AssessmentDomain).order_by(AssessmentDomain.key))).all())


@router.get("/assessment-domains/{domain_id}", response_model=DomainResponse)
async def get_domain(domain_id: int, db: AsyncSession = Depends(get_db)):
    domain = await db.get(AssessmentDomain, domain_id)
    if domain is None:
        raise HTTPException(status_code=404, detail="Assessment domain not found.")
    return domain


@router.get("/assessment-categories", response_model=list[CategoryResponse])
async def list_categories(
    domain_id: int | None = Query(default=None, ge=1),
    db: AsyncSession = Depends(get_db),
):
    statement = (
        select(AssessmentCategory, AssessmentDomain.key)
        .join(AssessmentDomain, AssessmentCategory.domain_id == AssessmentDomain.id)
        .order_by(AssessmentDomain.key, AssessmentCategory.key)
    )
    if domain_id is not None:
        statement = statement.where(AssessmentCategory.domain_id == domain_id)
    rows = (await db.execute(statement)).all()
    return [
        CategoryResponse(
            id=category.id, domain_id=category.domain_id, domain_key=domain_key,
            key=category.key, name=category.name, description=category.description,
            enabled=category.enabled, created_at=category.created_at,
        )
        for category, domain_key in rows
    ]


@router.get("/assessment-categories/{category_id}", response_model=CategoryResponse)
async def get_category(category_id: int, db: AsyncSession = Depends(get_db)):
    row = await db.execute(
        select(AssessmentCategory, AssessmentDomain.key)
        .join(AssessmentDomain, AssessmentCategory.domain_id == AssessmentDomain.id)
        .where(AssessmentCategory.id == category_id)
    )
    result = row.first()
    if result is None:
        raise HTTPException(status_code=404, detail="Assessment category not found.")
    category, domain_key = result
    return CategoryResponse(
        id=category.id, domain_id=category.domain_id, domain_key=domain_key,
        key=category.key, name=category.name, description=category.description,
        enabled=category.enabled, created_at=category.created_at,
    )


@router.get("/assessment-modules", response_model=list[ModuleResponse])
async def list_modules(
    category_id: int | None = Query(default=None, ge=1),
    db: AsyncSession = Depends(get_db),
):
    statement = (
        select(TestModule, AssessmentCategory.key, AssessmentDomain.key)
        .join(AssessmentCategory, TestModule.category_id == AssessmentCategory.id)
        .join(AssessmentDomain, AssessmentCategory.domain_id == AssessmentDomain.id)
        .order_by(AssessmentDomain.key, AssessmentCategory.key, TestModule.key)
    )
    if category_id is not None:
        statement = statement.where(TestModule.category_id == category_id)
    rows = (await db.execute(statement)).all()
    return [
        ModuleResponse(
            id=module.id, category_id=module.category_id, category_key=category_key,
            domain_key=domain_key, key=module.key, name=module.name,
            description=module.description, risk_level=module.risk_level,
            requires_approval=module.requires_approval, enabled=module.enabled,
            created_at=module.created_at,
        )
        for module, category_key, domain_key in rows
    ]


@router.get("/assessment-modules/{module_id}", response_model=ModuleResponse)
async def get_module(module_id: int, db: AsyncSession = Depends(get_db)):
    row = await db.execute(
        select(TestModule, AssessmentCategory.key, AssessmentDomain.key)
        .join(AssessmentCategory, TestModule.category_id == AssessmentCategory.id)
        .join(AssessmentDomain, AssessmentCategory.domain_id == AssessmentDomain.id)
        .where(TestModule.id == module_id)
    )
    result = row.first()
    if result is None:
        raise HTTPException(status_code=404, detail="Test module not found.")
    module, category_key, domain_key = result
    return ModuleResponse(
        id=module.id, category_id=module.category_id, category_key=category_key,
        domain_key=domain_key, key=module.key, name=module.name,
        description=module.description, risk_level=module.risk_level,
        requires_approval=module.requires_approval, enabled=module.enabled,
        created_at=module.created_at,
    )


def _tool_response(tool: Tool) -> ToolResponse:
    available, reason = adapter_registry.check_tool(tool.key, tool.executable)
    return ToolResponse(
        id=tool.id, key=tool.key, name=tool.name, version=tool.version,
        description=tool.description, vendor=tool.vendor, domain_id=tool.domain_id,
        category_id=tool.category_id, executable=tool.executable,
        installation_hint=tool.installation_hint, capabilities=tool.capabilities,
        enabled=tool.enabled, local_only=tool.local_only,
        requires_explicit_approval=tool.requires_explicit_approval,
        adapter_available=available, availability_reason=reason,
        created_at=tool.created_at, updated_at=tool.updated_at,
    )


@router.get("/tools", response_model=list[ToolResponse])
async def list_tools(db: AsyncSession = Depends(get_db)):
    tools = (await db.scalars(select(Tool).order_by(Tool.key))).all()
    return [_tool_response(tool) for tool in tools]


@router.get("/tools/subfinder/status")
async def subfinder_status(db: AsyncSession = Depends(get_db)):
    tool = await db.scalar(select(Tool).where(Tool.key == "subfinder"))
    if tool is None:
        return {"available": False, "reason": "Subfinder is not registered; apply the Phase 5 migration."}
    available, reason = adapter_registry.check_tool(tool.key, tool.executable)
    return {"available": available, "reason": reason, "executable": tool.executable,
            "passive_only": True}


@router.get("/tools/tls/status")
async def tls_status(db: AsyncSession = Depends(get_db)):
    tool = await db.scalar(select(Tool).where(Tool.key == "tls_inspector"))
    if tool is None:
        return {"available": False, "reason": "TLS inspection is not registered; apply the Phase 7 migration."}
    available, reason = adapter_registry.check_tool(tool.key, tool.executable)
    return {"available": available, "reason": reason, "port": 443,
            "certificate_validation": "required"}


@router.get("/tools/web-surface/status")
async def web_surface_status(db: AsyncSession = Depends(get_db)):
    tool = await db.scalar(select(Tool).where(Tool.key == "web_surface_discovery"))
    if tool is None:
        return {"available": False, "reason": "Web surface discovery is not registered; apply the Phase 8 migration."}
    available, reason = adapter_registry.check_tool(tool.key, tool.executable)
    from app.services.web_surface_inspection import (
        DISCOVERY_PATHS, MAX_REDIRECTS, MAX_RESPONSE_BYTES, MAX_TOTAL_SECONDS,
    )
    return {"available": available, "reason": reason, "paths": list(DISCOVERY_PATHS),
            "max_redirects_per_path": MAX_REDIRECTS,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "max_total_seconds": MAX_TOTAL_SECONDS,
            "same_host_only": True}


@router.get("/tools/{tool_id}", response_model=ToolResponse)
async def get_tool(tool_id: int, db: AsyncSession = Depends(get_db)):
    tool = await db.get(Tool, tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found.")
    return _tool_response(tool)


def _profile_response(profile: ScanProfile) -> ProfileResponse:
    return ProfileResponse(
        id=profile.id, project_id=profile.project_id, key=profile.key,
        name=profile.name, description=profile.description, enabled=profile.enabled,
        passive_only=profile.passive_only, active_testing=profile.active_testing,
        default_timeout=profile.default_timeout,
        module_ids=sorted(module.id for module in profile.modules),
        created_at=profile.created_at, updated_at=profile.updated_at,
    )


@router.get("/scan-profiles", response_model=list[ProfileResponse])
async def list_profiles(
    project_id: int | None = Query(default=None, ge=1),
    db: AsyncSession = Depends(get_db),
):
    if project_id is not None and await db.get(Project, project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    statement = select(ScanProfile).options(selectinload(ScanProfile.modules)).order_by(ScanProfile.key)
    if project_id is not None:
        statement = statement.where(
            (ScanProfile.project_id.is_(None)) | (ScanProfile.project_id == project_id)
        )
    else:
        statement = statement.where(ScanProfile.project_id.is_(None))
    profiles = (await db.scalars(statement)).all()
    return [_profile_response(profile) for profile in profiles]


@router.get("/scan-profiles/{profile_id}", response_model=ProfileResponse)
async def get_profile(profile_id: int, db: AsyncSession = Depends(get_db)):
    profile = await db.scalar(
        select(ScanProfile)
        .options(selectinload(ScanProfile.modules))
        .where(ScanProfile.id == profile_id)
    )
    if profile is None:
        raise HTTPException(status_code=404, detail="Scan profile not found.")
    return _profile_response(profile)
