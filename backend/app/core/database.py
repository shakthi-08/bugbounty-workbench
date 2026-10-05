from sqlalchemy import URL, event, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_data_dir


DATABASE_PATH = get_data_dir() / "bugbounty.db"
DATABASE_URL = URL.create(
    "sqlite+aiosqlite",
    database=str(DATABASE_PATH),
)
EXPECTED_SCHEMA_REVISION = "d6249ab317e1"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


@event.listens_for(engine.sync_engine, "connect")
def _enable_sqlite_foreign_keys(connection, connection_record) -> None:
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def verify_database_schema() -> None:
    """Fail startup when the database is absent or not at the app's schema revision."""
    if not DATABASE_PATH.is_file():
        raise RuntimeError(
            f"Database not found at {DATABASE_PATH}. Apply migrations first with "
            "'python -m alembic -c alembic.ini upgrade head' from the backend "
            "directory and the same BUGBOUNTY_DATA_DIR used by the application."
        )

    try:
        async with engine.connect() as connection:
            revision_result = await connection.execute(
                text("SELECT version_num FROM alembic_version")
            )
            revisions = list(revision_result.scalars())
            table_result = await connection.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
            tables = set(table_result.scalars())
    except SQLAlchemyError as exc:
        raise RuntimeError(
            f"Database at {DATABASE_PATH} is not initialized with Alembic. "
            "Apply migrations with 'python -m alembic -c alembic.ini upgrade head' "
            "from the backend directory and the same BUGBOUNTY_DATA_DIR."
        ) from exc

    if revisions != [EXPECTED_SCHEMA_REVISION]:
        current = ", ".join(revisions) if revisions else "no revision"
        raise RuntimeError(
            f"Database schema revision is {current}; expected "
            f"{EXPECTED_SCHEMA_REVISION}. Apply migrations with "
            "'python -m alembic -c alembic.ini upgrade head' from the backend "
            "directory and the same BUGBOUNTY_DATA_DIR."
        )

    required_tables = {
        "projects", "scopes", "assets", "findings",
        "assessment_domains", "assessment_categories", "test_modules",
        "tools", "tool_modules", "scan_profiles", "scan_profile_modules",
        "security_jobs", "security_results", "evidence", "security_audit_logs", "assessments",
    }
    missing_tables = required_tables - tables
    if missing_tables:
        raise RuntimeError(
            f"Database schema is missing tables {sorted(missing_tables)}. "
            "Apply migrations with 'python -m alembic -c alembic.ini upgrade head' "
            "from the backend directory and the same BUGBOUNTY_DATA_DIR."
        )
