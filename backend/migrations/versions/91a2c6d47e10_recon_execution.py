"""Register safe Windows recon adapters and allow timed out jobs.

Revision ID: 91a2c6d47e10
Revises: f438b4b9161f
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = "91a2c6d47e10"
down_revision = "f438b4b9161f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("security_jobs") as batch:
        batch.drop_constraint("ck_security_job_status", type_="check")
        batch.create_check_constraint(
            "ck_security_job_status",
            "status IN ('draft','pending_approval','approved','queued','running','completed','failed','cancelled','blocked','timed_out')",
        )

    bind = op.get_bind()
    tools = sa.table(
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
    definitions = [
        ("windows_nslookup", "Windows nslookup", "Microsoft Windows", "network", "asset_discovery",
         "nslookup.exe", "Windows optional feature: DNS Client Tools", "network.asset_discovery"),
        ("curl_head", "curl HTTP HEAD", "curl project", "web", "discovery",
         "curl.exe", "Windows 10/11 includes curl.exe", "web.discovery"),
    ]
    now = datetime.now(timezone.utc)
    for key, name, vendor, domain_key, category_key, executable, hint, capability in definitions:
        domain_id = bind.scalar(sa.select(domains.c.id).where(domains.c.key == domain_key))
        category_id = bind.scalar(sa.select(categories.c.id).where(
            categories.c.domain_id == domain_id, categories.c.key == category_key))
        module_id = bind.scalar(sa.select(modules.c.id).where(
            modules.c.category_id == category_id, modules.c.key == f"{domain_key}_{category_key}_review"))
        tool_id = bind.scalar(sa.select(tools.c.id).where(tools.c.key == key))
        if tool_id is None:
            result = bind.execute(tools.insert().values(
                key=key, name=name, version=None,
                description=f"Scope-authorized {name} reconnaissance adapter.", vendor=vendor,
                domain_id=domain_id, category_id=category_id, executable=executable,
                installation_hint=hint, capabilities=[capability], enabled=True,
                local_only=True, requires_explicit_approval=True, created_at=now, updated_at=now,
            ))
            tool_id = bind.scalar(sa.select(tools.c.id).where(tools.c.key == key))
        if not bind.execute(sa.select(links.c.tool_id).where(
                links.c.tool_id == tool_id, links.c.module_id == module_id)).first():
            bind.execute(links.insert().values(tool_id=tool_id, module_id=module_id))


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("UPDATE security_jobs SET status='failed' WHERE status='timed_out'"))
    tools = sa.table("tools", sa.column("id", sa.Integer), sa.column("key", sa.String))
    ids = list(bind.scalars(sa.select(tools.c.id).where(
        tools.c.key.in_(["windows_nslookup", "curl_head"]))))
    if ids:
        bind.execute(sa.text("UPDATE security_results SET tool_id=NULL WHERE tool_id IN :ids").bindparams(
            sa.bindparam("ids", expanding=True)), {"ids": ids})
        bind.execute(sa.text("DELETE FROM tool_modules WHERE tool_id IN :ids").bindparams(
            sa.bindparam("ids", expanding=True)), {"ids": ids})
        bind.execute(tools.delete().where(tools.c.id.in_(ids)))
    with op.batch_alter_table("security_jobs") as batch:
        batch.drop_constraint("ck_security_job_status", type_="check")
        batch.create_check_constraint(
            "ck_security_job_status",
            "status IN ('draft','pending_approval','approved','queued','running','completed','failed','cancelled','blocked')",
        )
