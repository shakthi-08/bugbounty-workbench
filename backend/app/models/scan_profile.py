from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Table, Column, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


scan_profile_modules = Table(
    "scan_profile_modules",
    Base.metadata,
    Column("profile_id", ForeignKey("scan_profiles.id", ondelete="CASCADE"), primary_key=True),
    Column("module_id", ForeignKey("test_modules.id", ondelete="CASCADE"), primary_key=True),
)


class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    __table_args__ = (UniqueConstraint("project_id", "key", name="uq_profile_project_key"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True
    )
    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    passive_only: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    active_testing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    default_timeout: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc), nullable=False
    )
    modules: Mapped[list["TestModule"]] = relationship(secondary=scan_profile_modules)
