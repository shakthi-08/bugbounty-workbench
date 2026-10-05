"""Add passive Subfinder registration and subdomain result type.

Revision ID: b5e7104c92ad
Revises: 91a2c6d47e10
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "b5e7104c92ad"
down_revision = "91a2c6d47e10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("security_results") as batch:
        batch.drop_constraint("ck_security_result_type", type_="check")
        batch.create_check_constraint(
            "ck_security_result_type",
            "result_type IN ('asset','service','endpoint','technology','finding_candidate','configuration','certificate','dns_record','subdomain','secret_candidate','dependency','cloud_resource','mobile_component','binary_artifact','generic')",
        )

    bind = op.get_bind()
    tools = sa.table("tools", sa.column("id", sa.Integer), sa.column("key", sa.String),
                     sa.column("name", sa.String), sa.column("version", sa.String),
                     sa.column("description", sa.String), sa.column("vendor", sa.String),
                     sa.column("domain_id", sa.Integer), sa.column("category_id", sa.Integer),
                     sa.column("executable", sa.String), sa.column("installation_hint", sa.String),
                     sa.column("capabilities", sa.JSON), sa.column("enabled", sa.Boolean),
                     sa.column("local_only", sa.Boolean),
                     sa.column("requires_explicit_approval", sa.Boolean),
                     sa.column("created_at", sa.DateTime(timezone=True)),
                     sa.column("updated_at", sa.DateTime(timezone=True)))
    domains = sa.table("assessment_domains", sa.column("id", sa.Integer), sa.column("key", sa.String))
    categories = sa.table("assessment_categories", sa.column("id", sa.Integer),
                          sa.column("domain_id", sa.Integer), sa.column("key", sa.String))
    modules = sa.table("test_modules", sa.column("id", sa.Integer),
                       sa.column("category_id", sa.Integer), sa.column("key", sa.String))
    links = sa.table("tool_modules", sa.column("tool_id", sa.Integer), sa.column("module_id", sa.Integer))
    domain_id = bind.scalar(sa.select(domains.c.id).where(domains.c.key == "network"))
    category_id = bind.scalar(sa.select(categories.c.id).where(
        categories.c.domain_id == domain_id, categories.c.key == "asset_discovery"))
    module_id = bind.scalar(sa.select(modules.c.id).where(
        modules.c.category_id == category_id, modules.c.key == "network_asset_discovery_review"))
    tool_id = bind.scalar(sa.select(tools.c.id).where(tools.c.key == "subfinder"))
    if tool_id is None:
        now = datetime.now(timezone.utc)
        bind.execute(tools.insert().values(
            key="subfinder", name="ProjectDiscovery Subfinder", version=None,
            description="Passive subdomain reconnaissance through Subfinder.",
            vendor="ProjectDiscovery", domain_id=domain_id, category_id=category_id,
            executable="subfinder.exe", installation_hint="Install Subfinder manually, then configure its executable path.",
            capabilities=["network.passive_subdomain_discovery"], enabled=True,
            local_only=True, requires_explicit_approval=True, created_at=now, updated_at=now,
        ))
        tool_id = bind.scalar(sa.select(tools.c.id).where(tools.c.key == "subfinder"))
    bind.execute(tools.update().where(tools.c.id == tool_id).values(
        name="ProjectDiscovery Subfinder",
        description="Registered passive-only ProjectDiscovery Subfinder adapter.",
        vendor="ProjectDiscovery", domain_id=domain_id, category_id=category_id,
        executable="subfinder.exe",
        installation_hint="Install Subfinder manually and configure the registered executable path.",
        capabilities=["network.passive_subdomain_discovery"], enabled=True,
        local_only=True, requires_explicit_approval=True, updated_at=datetime.now(timezone.utc),
    ))
    if module_id and not bind.execute(sa.select(links.c.tool_id).where(
            links.c.tool_id == tool_id, links.c.module_id == module_id)).first():
        bind.execute(links.insert().values(tool_id=tool_id, module_id=module_id))


def downgrade() -> None:
    bind = op.get_bind()
    tool = sa.table("tools", sa.column("id", sa.Integer), sa.column("key", sa.String),
                    sa.column("domain_id", sa.Integer), sa.column("category_id", sa.Integer),
                    sa.column("executable", sa.String), sa.column("description", sa.String),
                    sa.column("vendor", sa.String), sa.column("installation_hint", sa.String),
                    sa.column("capabilities", sa.JSON), sa.column("updated_at", sa.DateTime(timezone=True)))
    tool_id = bind.scalar(sa.select(tool.c.id).where(tool.c.key == "subfinder"))
    if tool_id:
        domains = sa.table("assessment_domains", sa.column("id", sa.Integer), sa.column("key", sa.String))
        categories = sa.table("assessment_categories", sa.column("id", sa.Integer),
                              sa.column("domain_id", sa.Integer), sa.column("key", sa.String))
        modules = sa.table("test_modules", sa.column("id", sa.Integer),
                           sa.column("category_id", sa.Integer), sa.column("key", sa.String))
        links = sa.table("tool_modules", sa.column("tool_id", sa.Integer),
                         sa.column("module_id", sa.Integer))
        network_id = bind.scalar(sa.select(domains.c.id).where(domains.c.key == "network"))
        asset_id = bind.scalar(sa.select(categories.c.id).where(
            categories.c.domain_id == network_id, categories.c.key == "asset_discovery"))
        module_id = bind.scalar(sa.select(modules.c.id).where(
            modules.c.category_id == asset_id, modules.c.key == "network_asset_discovery_review"))
        if module_id:
            bind.execute(links.delete().where(links.c.tool_id == tool_id, links.c.module_id == module_id))
        web_id = bind.scalar(sa.select(domains.c.id).where(domains.c.key == "web"))
        recon_id = bind.scalar(sa.select(categories.c.id).where(
            categories.c.domain_id == web_id, categories.c.key == "reconnaissance"))
        bind.execute(tool.update().where(tool.c.id == tool_id).values(
            domain_id=web_id, category_id=recon_id, executable="subfinder",
            description="Registry metadata only for Subfinder; not executed in Phase 3.",
            vendor="ProjectDiscovery", installation_hint="Install Subfinder separately if needed.",
            capabilities=["web.reconnaissance"], updated_at=datetime.now(timezone.utc),
        ))
    with op.batch_alter_table("security_results") as batch:
        batch.drop_constraint("ck_security_result_type", type_="check")
        batch.create_check_constraint(
            "ck_security_result_type",
            "result_type IN ('asset','service','endpoint','technology','finding_candidate','configuration','certificate','dns_record','secret_candidate','dependency','cloud_resource','mobile_component','binary_artifact','generic')",
        )
