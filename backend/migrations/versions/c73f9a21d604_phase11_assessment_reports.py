"""Add project-scoped assessment lifecycle records.

Revision ID: c73f9a21d604
Revises: f1a8c6d30b42
"""
from alembic import op
import sqlalchemy as sa

revision = "c73f9a21d604"
down_revision = "f1a8c6d30b42"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "assessments",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="draft"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('draft','in_progress','completed','archived')", name="ck_assessment_status"),
    )
    op.create_index("ix_assessments_project_id", "assessments", ["project_id"])

def downgrade():
    op.drop_index("ix_assessments_project_id", table_name="assessments")
    op.drop_table("assessments")
