from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.services.scope_validator import check_scope

router = APIRouter(
    prefix="/projects/{project_id}/scope-check",
    tags=["Scope Validation"],
)


class ScopeCheckRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2000)


class ScopeCheckResponse(BaseModel):
    allowed: bool
    reason: str


@router.post("", response_model=ScopeCheckResponse)
async def scope_check(
    project_id: int,
    data: ScopeCheckRequest,
    db: AsyncSession = Depends(get_db),
):
    decision = await check_scope(
        db=db,
        project_id=project_id,
        target=data.target,
    )

    return ScopeCheckResponse(
        allowed=decision.allowed,
        reason=decision.reason,
    )
