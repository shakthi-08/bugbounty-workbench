from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import URL, engine_from_config, pool

from app.core.database import Base, DATABASE_PATH
from app.models.asset import Asset
from app.models.assessment import Assessment
from app.models.assessment_taxonomy import AssessmentCategory, AssessmentDomain, TestModule
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan_profile import ScanProfile
from app.models.scope import Scope
from app.models.security_audit import SecurityAuditLog
from app.models.security_job import SecurityJob
from app.models.security_result import SecurityResult
from app.models.tool import Tool, tool_modules


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _sync_database_url() -> str:
    return URL.create("sqlite", database=str(DATABASE_PATH)).render_as_string(
        hide_password=False
    )


def run_migrations_offline() -> None:
    raise RuntimeError(
        "Offline migrations are not supported. Run 'alembic upgrade head' "
        "with the application's configured data directory."
    )


def run_migrations_online() -> None:
    database_path = Path(DATABASE_PATH)
    database_path.parent.mkdir(parents=True, exist_ok=True)

    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _sync_database_url()

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
