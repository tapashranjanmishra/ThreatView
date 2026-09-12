from datetime import datetime

from pydantic import BaseModel, Field


class AlertRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    conditions: dict = Field(default_factory=dict)
    is_active: bool = True


class AlertRuleUpdate(BaseModel):
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )
    conditions: dict | None = None
    is_active: bool | None = None


class AlertRuleResponse(BaseModel):
    id: str
    name: str
    conditions: dict
    is_active: bool
    created_at: datetime


class AlertNotificationResponse(BaseModel):
    id: str
    rule_id: str
    threat_id: str
    dedup_key: str
    sent_at: datetime

    rule_name: str
    ioc_value: str
    ioc_type: str
    threat_type: str
    source: str

    # Some existing threat records have NULL confidence scores.
    confidence_score: int | float | None = None