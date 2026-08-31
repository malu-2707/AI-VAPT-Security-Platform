from datetime import datetime
from sqlalchemy import String, Text, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.models.user import Base

class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False
    )

    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id"),
        nullable=False
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="generated",
        nullable=False
    )

    overall_risk: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    risk_score: Mapped[int] = mapped_column(
        default=0,
        nullable=False
    )

    total_findings: Mapped[int] = mapped_column(
        default=0,
        nullable=False
    )

    critical_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False
    )

    high_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False
    )

    medium_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False
    )

    low_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False
    )

    info_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False
    )

    executive_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    recommendations: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

