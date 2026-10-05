from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.asset import Asset
from app.models.project import Project
from app.services.scope_validator import check_scope

router = APIRouter(
    prefix="/projects/{project_id}/assets",
    tags=["Assets"],
)


class AssetCreate(BaseModel):
    value: str = Field(min_length=1, max_length=1000)
    asset_type: str = Field(min_length=1, max_length=50)
    source: str | None = Field(default=None, max_length=100)


class AssetResponse(BaseModel):
    id: int
    project_id: int
    value: str
    asset_type: str
    source: str | None
    http_status: int | None
    title: str | None
    technologies: str | None
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


@router.post("", response_model=AssetResponse, status_code=201)
async def create_asset(
    project_id: int,
    data: AssetCreate,
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)

    if project is None:
        raise HTTPException(
            status_code=404,
            detail="Project not found.",
        )

    decision = await check_scope(
        db=db,
        project_id=project_id,
        target=data.value,
    )

    if not decision.allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Asset rejected by scope policy: {decision.reason}",
        )

    existing = await db.scalar(
        select(Asset).where(
            Asset.project_id == project_id,
            Asset.value == data.value,
        )
    )

    if existing:
        return existing

    now = datetime.now(timezone.utc)

    asset = Asset(
        project_id=project_id,
        value=data.value,
        asset_type=data.asset_type,
        source=data.source,
        first_seen=now,
        last_seen=now,
    )

    db.add(asset)
    await db.commit()
    await db.refresh(asset)

    return asset


@router.get("", response_model=list[AssetResponse])
async def list_assets(
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
        select(Asset)
        .where(Asset.project_id == project_id)
        .order_by(Asset.id)
    )

    return list(result.all())
