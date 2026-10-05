from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scope import Scope


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    matched_scope: Scope | None = None


def normalize_target(target: str) -> str:
    target = target.strip().lower()

    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or ""

    target = target.rstrip(".")
    return target


async def check_scope(
    db: AsyncSession,
    project_id: int,
    target: str,
) -> ScopeDecision:

    normalized_target = normalize_target(target)

    if not normalized_target:
        return ScopeDecision(
            allowed=False,
            reason="Invalid target.",
        )

    result = await db.scalars(
        select(Scope)
        .where(Scope.project_id == project_id)
        .order_by(Scope.id)
    )

    scopes = list(result.all())

    included_scopes = [
        scope for scope in scopes
        if scope.included
    ]

    excluded_scopes = [
        scope for scope in scopes
        if not scope.included
    ]

    # Explicit exclusions always take priority.
    for scope in excluded_scopes:
        scope_value = normalize_target(scope.value)

        if (
            normalized_target == scope_value
            or normalized_target.endswith("." + scope_value)
        ):
            return ScopeDecision(
                allowed=False,
                reason=f"Target matches excluded scope: {scope.value}",
                matched_scope=scope,
            )

    # Check included scopes.
    for scope in included_scopes:
        scope_value = normalize_target(scope.value)

        if (
            normalized_target == scope_value
            or normalized_target.endswith("." + scope_value)
        ):
            return ScopeDecision(
                allowed=True,
                reason=f"Target matches included scope: {scope.value}",
                matched_scope=scope,
            )

    return ScopeDecision(
        allowed=False,
        reason="Target does not match any included scope.",
    )
