from datetime import datetime
from sqlalchemy import String, Text, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.models.user import Base

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )

    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id"),
        nullable=False
    )

    scanner: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="completed",
        nullable=False
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True
    )

    return_code: Mapped[int | None] = mapped_column(
        nullable=True
    )

    output: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )
