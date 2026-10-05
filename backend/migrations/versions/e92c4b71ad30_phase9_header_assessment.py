"""Add Phase 9 finding metadata and stable de-duplication.

Revision ID: e92c4b71ad30
Revises: d817a4b6c930
"""
from alembic import op
import sqlalchemy as sa

revision = "e92c4b71ad30"
down_revision = "d817a4b6c930"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("category", sa.String(100), nullable=False, server_default="general"))
        batch.add_column(sa.Column("confidence", sa.String(20), nullable=False, server_default="medium"))
        batch.add_column(sa.Column("remediation", sa.Text(), nullable=True))
        batch.add_column(sa.Column("fingerprint", sa.String(64), nullable=True))
        batch.add_column(sa.Column("job_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_findings_job_id_security_jobs", "security_jobs", ["job_id"], ["id"], ondelete="SET NULL")
        batch.create_index("ix_findings_job_id", ["job_id"])
        batch.create_unique_constraint("uq_findings_fingerprint", ["fingerprint"])

def downgrade():
    with op.batch_alter_table("findings") as batch:
        batch.drop_constraint("uq_findings_fingerprint", type_="unique")
        batch.drop_index("ix_findings_job_id")
        batch.drop_constraint("fk_findings_job_id_security_jobs", type_="foreignkey")
        batch.drop_column("job_id")
        batch.drop_column("fingerprint")
        batch.drop_column("remediation")
        batch.drop_column("confidence")
        batch.drop_column("category")
