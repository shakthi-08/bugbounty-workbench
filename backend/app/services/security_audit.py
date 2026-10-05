import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_audit import SecurityAuditLog


_SENSITIVE_KEY = re.compile(r"(secret|password|token|api[_-]?key|private[_-]?key|authorization)", re.I)
_SENSITIVE_TEXT = re.compile(
    r"(?i)(api[_-]?key|token|password|secret|authorization)=([^&\s]+)"
)


def redact_audit_value(value: Any, key: str = "") -> Any:
    if _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_audit_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_audit_value(item) for item in value]
    if isinstance(value, str):
        return _SENSITIVE_TEXT.sub(r"\1=[REDACTED]", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def sanitize_audit_target(target: str | None) -> str | None:
    if target is None:
        return None
    cleaned = _SENSITIVE_TEXT.sub(r"\1=[REDACTED]", target)
    if "://" not in cleaned:
        return cleaned
    parsed = urlsplit(cleaned)
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, parsed.query, ""))


async def write_audit_log(
    db: AsyncSession,
    *,
    project_id: int | None,
    user: str,
    action: str,
    entity_type: str,
    entity_id: int | str | None = None,
    target: str | None = None,
    details: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    record = SecurityAuditLog(
        project_id=project_id,
        user=(str(redact_audit_value(user, "user")).strip()[:200] or "local-user"),
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        target=sanitize_audit_target(target),
        details_json=redact_audit_value(details or {}),
    )
    db.add(record)
    return record
