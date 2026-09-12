import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models import IOCType, ThreatType


class ThreatCreate(BaseModel):
    ioc_type: IOCType
    ioc_value: str
    threat_type: ThreatType = ThreatType.OTHER
    source: str
    country: str | None = None
    industry: str | None = None
    confidence_score: float | None = None
    raw_data: dict = {}


class ThreatResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ioc_type: IOCType
    ioc_value: str
    threat_type: ThreatType
    source: str
    country: str | None
    industry: str | None
    confidence_score: float | None
    first_seen: datetime
    last_seen: datetime
    raw_data: dict


class ThreatListResponse(BaseModel):
    items: list[ThreatResponse]
    total: int