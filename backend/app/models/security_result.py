from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SecurityResult(Base):
    __tablename__ = "security_results"
    __table_args__ = (
        CheckConstraint(
            "result_type IN ('asset','service','endpoint','technology','finding_candidate','configuration','certificate','dns_record','subdomain','secret_candidate','dependency','cloud_resource','mobile_component','binary_artifact','generic')",
            name="ck_security_result_type",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    job_id: Mapped[int] = mapped_column(
        ForeignKey("security_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_id: Mapped[int | None] = mapped_column(ForeignKey("tools.id"), nullable=True)
    module_id: Mapped[int | None] = mapped_column(ForeignKey("test_modules.id"), nullable=True)
    target: Mapped[str] = mapped_column(String(2000), nullable=False)
    result_type: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(30), nullable=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_reference: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    normalized_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
