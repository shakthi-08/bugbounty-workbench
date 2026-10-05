"""Register bounded built-in TLS inspection adapter.

Revision ID: c4f872a16b03
Revises: b5e7104c92ad
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "c4f872a16b03"
down_revision = "b5e7104c92ad"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    table = sa.table(
        "tools", sa.column("id", sa.Integer), sa.column("key", sa.String),
        sa.column("name", sa.String), sa.column("version", sa.String),
        sa.column("description", sa.String), sa.column("vendor", sa.String),
        sa.column("domain_id", sa.Integer), sa.column("category_id", sa.Integer),
        sa.column("executable", sa.String), sa.column("installation_hint", sa.String),
        sa.column("capabilities", sa.JSON), sa.column("enabled", sa.Boolean),
        sa.column("local_only", sa.Boolean), sa.column("requires_explicit_approval", sa.Boolean),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    domains = sa.table("assessment_domains", sa.column("id", sa.Integer), sa.column("key", sa.String))
    categories = sa.table("assessment_categories", sa.column("id", sa.Integer),
                          sa.column("domain_id", sa.Integer), sa.column("key", sa.String))
    modules = sa.table("test_modules", sa.column("id", sa.Integer),
                       sa.column("category_id", sa.Integer), sa.column("key", sa.String))
    links = sa.table("tool_modules", sa.column("tool_id", sa.Integer), sa.column("module_id", sa.Integer))
    domain_id = bind.scalar(sa.select(domains.c.id).where(domains.c.key == "web"))
    category_id = bind.scalar(sa.select(categories.c.id).where(
        categories.c.domain_id == domain_id, categories.c.key == "discovery"))
    module_id = bind.scalar(sa.select(modules.c.id).where(
        modules.c.category_id == category_id, modules.c.key == "web_discovery_review"))
    tool_id = bind.scalar(sa.select(table.c.id).where(table.c.key == "tls_inspector"))
    now = datetime.now(timezone.utc)
    values = dict(
        key="tls_inspector", name="TLS Certificate Inspector", version=None,
        description="Bounded HTTPS certificate inspection with normal certificate validation.",
        vendor="Python standard library", domain_id=domain_id, category_id=category_id,
        executable="builtin:python-ssl", installation_hint="Built into Python; no separate tool installation required.",
        capabilities=["network.tls_inspection"], enabled=True, local_only=True,
        requires_explicit_approval=True, updated_at=now,
    )
    if tool_id is None:
        bind.execute(table.insert().values(**values, created_at=now))
        tool_id = bind.scalar(sa.select(table.c.id).where(table.c.key == "tls_inspector"))
    else:
        bind.execute(table.update().where(table.c.id == tool_id).values(**values))
    if module_id and not bind.execute(sa.select(links.c.tool_id).where(
            links.c.tool_id == tool_id, links.c.module_id == module_id)).first():
        bind.execute(links.insert().values(tool_id=tool_id, module_id=module_id))


def downgrade() -> None:
    bind = op.get_bind()
    table = sa.table("tools", sa.column("id", sa.Integer), sa.column("key", sa.String))
    tool_id = bind.scalar(sa.select(table.c.id).where(table.c.key == "tls_inspector"))
    if tool_id:
        bind.execute(sa.text("UPDATE security_results SET tool_id=NULL WHERE tool_id=:id"), {"id": tool_id})
        bind.execute(sa.text("DELETE FROM tool_modules WHERE tool_id=:id"), {"id": tool_id})
        bind.execute(table.delete().where(table.c.id == tool_id))
