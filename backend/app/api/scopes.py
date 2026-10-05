from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.project import Project
from app.models.scope import Scope

router = APIRouter(
    prefix="/projects/{project_id}/scopes",
    tags=["Scopes"],
)


class ScopeCreate(BaseModel):
    value: str = Field(min_length=1, max_length=500)
    scope_type: str = Field(
        description="Examples: domain, subdomain, url, api, ip"
    )
    included: bool = True


class ScopeResponse(BaseModel):
    id: int
    project_id: int
    value: str
    scope_type: str
    included: bool

    model_config = {"from_attributes": True}


@router.post("", response_model=ScopeResponse, status_code=201)
async def create_scope(
    project_id: int,
    data: ScopeCreate,
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)

    if project is None:
        raise HTTPException(
            status_code=404,
            detail="Project not found.",
        )

    scope = Scope(
        project_id=project_id,
        value=data.value.strip(),
        scope_type=data.scope_type.lower().strip(),
        included=data.included,
    )

    db.add(scope)
    await db.commit()
    await db.refresh(scope)

    return scope


@router.get("", response_model=list[ScopeResponse])
async def list_scopes(
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
        select(Scope)
        .where(Scope.project_id == project_id)
        .order_by(Scope.id)
    )

    return list(result.all())
