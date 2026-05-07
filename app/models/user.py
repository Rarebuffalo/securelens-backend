import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    scans = relationship("ScanResult", back_populates="user", lazy="selectin")
    code_scans = relationship("CodeScanResult", back_populates="user", lazy="selectin", cascade="all, delete")
    scheduled_scans = relationship("ScheduledScan", back_populates="user", lazy="selectin", cascade="all, delete")
    api_keys = relationship("ApiKey", back_populates="user", lazy="selectin", cascade="all, delete")
    webhooks = relationship("Webhook", back_populates="user", lazy="selectin", cascade="all, delete")

