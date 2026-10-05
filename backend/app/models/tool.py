from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Table, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


tool_modules = Table(
    "tool_modules",
    Base.metadata,
    Column("tool_id", ForeignKey("tools.id", ondelete="CASCADE"), primary_key=True),
    Column("module_id", ForeignKey("test_modules.id", ondelete="CASCADE"), primary_key=True),
)


class Tool(Base):
    __tablename__ = "tools"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(200), nullable=True)
    domain_id: Mapped[int | None] = mapped_column(
        ForeignKey("assessment_domains.id", ondelete="SET NULL"), nullable=True
    )
    category_id: Mapped[int | None] = mapped_column(
        ForeignKey("assessment_categories.id", ondelete="SET NULL"), nullable=True
    )
    executable: Mapped[str | None] = mapped_column(String(200), nullable=True)
    installation_hint: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    local_only: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    requires_explicit_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc), nullable=False
    )
    modules: Mapped[list["TestModule"]] = relationship(secondary=tool_modules)
