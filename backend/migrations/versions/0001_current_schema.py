"""Create any missing tables from the current application schema.

Revision ID: 0001_current_schema
Revises:
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0001_current_schema"
down_revision = None
branch_labels = None
depends_on = None


def _ensure_existing_table_has_columns(
    bind,
    table_name: str,
    expected_columns: set[str],
) -> bool:
    """Validate a legacy table before leaving it untouched; return if it exists."""
    inspector = inspect(bind)
    if table_name not in inspector.get_table_names():
        return False

    existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
    missing_columns = expected_columns - existing_columns
    if missing_columns:
        raise RuntimeError(
            f"Existing table '{table_name}' is missing columns "
            f"{sorted(missing_columns)}. No table was altered; create a reviewed "
            "data-preserving migration for this schema before upgrading."
        )
    return True


def upgrade() -> None:
    bind = op.get_bind()

    projects_exists = _ensure_existing_table_has_columns(
        bind,
        "projects",
        {"id", "name", "description", "created_at"},
    )
    if not projects_exists:
        op.create_table(
            "projects",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )

    scopes_exists = _ensure_existing_table_has_columns(
        bind,
        "scopes",
        {"id", "project_id", "value", "scope_type", "included", "created_at"},
    )
    if not scopes_exists:
        op.create_table(
            "scopes",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("project_id", sa.Integer(), nullable=False),
            sa.Column("value", sa.String(length=500), nullable=False),
            sa.Column("scope_type", sa.String(length=50), nullable=False),
            sa.Column("included", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    assets_exists = _ensure_existing_table_has_columns(
        bind,
        "assets",
        {
            "id", "project_id", "value", "asset_type", "source", "http_status",
            "title", "technologies", "first_seen", "last_seen",
        },
    )
    if not assets_exists:
        op.create_table(
            "assets",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("project_id", sa.Integer(), nullable=False),
            sa.Column("value", sa.String(length=1000), nullable=False),
            sa.Column("asset_type", sa.String(length=50), nullable=False),
            sa.Column("source", sa.String(length=100), nullable=True),
            sa.Column("http_status", sa.Integer(), nullable=True),
            sa.Column("title", sa.String(length=500), nullable=True),
            sa.Column("technologies", sa.Text(), nullable=True),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    findings_exists = _ensure_existing_table_has_columns(
        bind,
        "findings",
        {
            "id", "project_id", "asset_id", "title", "severity", "status",
            "endpoint", "description", "evidence", "created_at", "updated_at",
        },
    )
    if not findings_exists:
        op.create_table(
            "findings",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("project_id", sa.Integer(), nullable=False),
            sa.Column("asset_id", sa.Integer(), nullable=True),
            sa.Column("title", sa.String(length=500), nullable=False),
            sa.Column("severity", sa.String(length=50), nullable=False),
            sa.Column("status", sa.String(length=50), nullable=False),
            sa.Column("endpoint", sa.String(length=2000), nullable=True),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("evidence", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    # Ensure indexes represented by the current models exist, including on
    # databases whose tables predate the index declarations.
    existing_indexes = {
        (table, index["name"])
        for table in ("assets", "findings")
        for index in inspect(bind).get_indexes(table)
    }
    for table, name, column in (
        ("assets", "ix_assets_project_id", "project_id"),
        ("findings", "ix_findings_project_id", "project_id"),
        ("findings", "ix_findings_asset_id", "asset_id"),
    ):
        if (table, name) not in existing_indexes:
            op.create_index(name, table, [column], unique=False)


def downgrade() -> None:
    raise RuntimeError(
        "This baseline migration cannot be downgraded automatically because "
        "dropping application tables would destroy local project data."
    )
