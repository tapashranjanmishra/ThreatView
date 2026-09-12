import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"


class ThreatType(str, enum.Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    BOTNET = "botnet"
    SCANNING = "scanning"
    OTHER = "other"


class ThreatModel(Base):
    __tablename__ = "threats"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    ioc_type: Mapped[IOCType] = mapped_column(
        Enum(IOCType, name="ioc_type"),
        nullable=False,
    )

    ioc_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
    )

    threat_type: Mapped[ThreatType] = mapped_column(
        Enum(ThreatType, name="threat_type"),
        nullable=False,
        default=ThreatType.OTHER,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    country: Mapped[str | None] = mapped_column(
        String(2),
        nullable=True,
    )

    industry: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    confidence_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    raw_data: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        Index(
            "uq_threat_ioc_source",
            "ioc_value",
            "source",
            unique=True,
        ),
    )