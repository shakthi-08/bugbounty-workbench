from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.project import Project

router = APIRouter(
    prefix="/projects/{project_id}/findings",
    tags=["Findings"],
)


class FindingCreate(BaseModel):
    asset_id: int | None = None
    title: str = Field(min_length=1, max_length=500)
    severity: str = Field(min_length=1, max_length=50)
    status: str = Field(default="open", min_length=1, max_length=50)
    endpoint: str | None = Field(default=None, max_length=2000)
    description: str = Field(min_length=1)
    evidence: str | None = None


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

    finding = Finding(
        project_id=project_id,
        asset_id=data.asset_id,
        title=data.title,
        severity=data.severity,
        status=data.status,
        endpoint=data.endpoint,
        description=data.description,
        evidence=data.evidence,
    )

    db.add(finding)
    await db.commit()
    await db.refresh(finding)

    return finding


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

    return list(result.all())
