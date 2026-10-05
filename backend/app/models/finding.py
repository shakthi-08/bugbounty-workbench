from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"),
        nullable=False,
        index=True,
    )

    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id"),
        nullable=True,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="open",
        nullable=False,
    )

    endpoint: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    evidence: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    category: Mapped[str] = mapped_column(String(100), default="general", nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("security_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    identity_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    canonical_finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    priority: Mapped[str | None] = mapped_column(String(30), nullable=True)
    risk_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_groups: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    identity_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    canonical_finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    priority: Mapped[str | None] = mapped_column(String(30), nullable=True)
    risk_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_groups: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
