from datetime import datetime
from sqlalchemy import String, Text, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.models.user import Base

class Finding(Base):
    __tablename__ = "findings"

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

    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    scanner: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    template_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    host: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    port: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True
    )

    matched_at: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    evidence: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    cwe: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    # AI-generated analysis
    ai_explanation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    ai_impact: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    ai_exploitability: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    ai_recommendation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    ai_risk_reasoning: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    ai_priority: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    ai_analyzed: Mapped[bool] = mapped_column(
        default=False,
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

