"""Persist normalized finding identity, correlation, and risk.

Revision ID: f1a8c6d30b42
Revises: e92c4b71ad30
"""
from alembic import op
import sqlalchemy as sa

revision = "f1a8c6d30b42"
down_revision = "e92c4b71ad30"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("identity_fingerprint", sa.String(64), nullable=True))
        batch.add_column(sa.Column("canonical_finding_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("risk_score", sa.Float(), nullable=True))
        batch.add_column(sa.Column("priority", sa.String(30), nullable=True))
        batch.add_column(sa.Column("risk_explanation", sa.Text(), nullable=True))
        batch.add_column(sa.Column("correlation_groups", sa.JSON(), nullable=False, server_default="[]"))
        batch.create_foreign_key("fk_findings_canonical_finding_id", "findings", ["canonical_finding_id"], ["id"], ondelete="SET NULL")
        batch.create_index("ix_findings_identity_fingerprint", ["identity_fingerprint"])
        batch.create_index("ix_findings_canonical_finding_id", ["canonical_finding_id"])

def downgrade():
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_canonical_finding_id")
        batch.drop_index("ix_findings_identity_fingerprint")
        batch.drop_constraint("fk_findings_canonical_finding_id", type_="foreignkey")
        for column in ("correlation_groups", "risk_explanation", "priority", "risk_score",
                       "occurrence_count", "canonical_finding_id", "identity_fingerprint"):
            batch.drop_column(column)
