from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.scope import Scope
from app.services.scope_validator import ScopeDecision, check_scope, normalize_target


@dataclass
class TargetAuthorization:
    allowed: bool
    reason: str
    scope_snapshot: dict
    asset: Asset | None = None


class SecurityAuthorizationService:
    """Backend authorization shared by every security-job entry point."""

    async def validate_target(
        self,
        db: AsyncSession,
        project_id: int,
        target: str,
        asset_id: int | None = None,
    ) -> TargetAuthorization:
        scope_rows = list(
            (await db.scalars(
                select(Scope).where(Scope.project_id == project_id).order_by(Scope.id)
            )).all()
        )
        snapshot = {
            "project_id": project_id,
            "scopes": [
                {
                    "id": row.id,
                    "value": row.value,
                    "scope_type": row.scope_type,
                    "included": row.included,
                }
                for row in scope_rows
            ],
        }
        asset = None
        if asset_id is not None:
            asset = await db.get(Asset, asset_id)
            if asset is None or asset.project_id != project_id:
                return TargetAuthorization(False, "Asset not found in this project.", snapshot)
            if normalize_target(asset.value) != normalize_target(target):
                return TargetAuthorization(
                    False, "Target does not match the selected project asset.", snapshot, asset
                )

        decision = await check_scope(db, project_id, target)
        snapshot["authorization"] = self._decision_snapshot(decision)
        if not decision.allowed:
            return TargetAuthorization(False, decision.reason, snapshot, asset)

        if asset is not None and normalize_target(asset.value) != normalize_target(target):
            return TargetAuthorization(False, "Asset target mismatch.", snapshot, asset)
        return TargetAuthorization(True, decision.reason, snapshot, asset)

    async def validate_derived_target(
        self, db: AsyncSession, project_id: int, derived_target: str
    ) -> TargetAuthorization:
        # Derived targets are always checked independently by the existing scope engine.
        return await self.validate_target(db, project_id, derived_target)

    @staticmethod
    def _decision_snapshot(decision: ScopeDecision) -> dict:
        return {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "matched_scope_id": decision.matched_scope.id if decision.matched_scope else None,
            "matched_scope_value": decision.matched_scope.value if decision.matched_scope else None,
        }


security_authorization = SecurityAuthorizationService()
