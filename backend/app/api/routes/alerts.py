import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.database import get_db
from app.models import AlertNotification, AlertRule, User
from app.schemas import (
      AlertNotificationResponse,
    AlertRuleCreate,
    AlertRuleResponse,
    AlertRuleUpdate,
)


router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts"],
)


@router.post(
    "",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_alert_rule(
    payload: AlertRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rule = AlertRule(
        user_id=current_user.id,
        name=payload.name,
        conditions=payload.conditions,
        is_active=payload.is_active,
    )

    db.add(rule)
    db.commit()
    db.refresh(rule)

    return AlertRuleResponse(
        id=str(rule.id),
        name=rule.name,
        conditions=rule.conditions,
        is_active=rule.is_active,
        created_at=rule.created_at,
    )


@router.get(
    "",
    response_model=list[AlertRuleResponse],
)
def list_alert_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rules = db.scalars(
        select(AlertRule)
        .where(AlertRule.user_id == current_user.id)
        .order_by(AlertRule.created_at.desc())
    ).all()

    return [
        AlertRuleResponse(
            id=str(rule.id),
            name=rule.name,
            conditions=rule.conditions,
            is_active=rule.is_active,
            created_at=rule.created_at,
        )
        for rule in rules
    ]

@router.get(
    "/notifications",
    response_model=list[AlertNotificationResponse],
)
def list_alert_notifications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    notifications = db.scalars(
        select(AlertNotification)
        .join(AlertRule, AlertNotification.rule_id == AlertRule.id)
        .where(AlertRule.user_id == current_user.id)
        .order_by(AlertNotification.sent_at.desc())
    ).all()

    return [
        AlertNotificationResponse(
            id=str(notification.id),
            rule_id=str(notification.rule_id),
            threat_id=str(notification.threat_id),
            dedup_key=notification.dedup_key,
            sent_at=notification.sent_at,
            rule_name=notification.rule.name,
            ioc_value=notification.threat.ioc_value,
            ioc_type=notification.threat.ioc_type.value,
            threat_type=notification.threat.threat_type.value,
            source=notification.threat.source,
            confidence_score=notification.threat.confidence_score,
        )
        for notification in notifications
    ]

@router.get(
    "/{rule_id}",
    response_model=AlertRuleResponse,
)
def get_alert_rule(
    rule_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rule = db.scalar(
        select(AlertRule).where(
            AlertRule.id == rule_id,
            AlertRule.user_id == current_user.id,
        )
    )

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert rule not found",
        )

    return AlertRuleResponse(
        id=str(rule.id),
        name=rule.name,
        conditions=rule.conditions,
        is_active=rule.is_active,
        created_at=rule.created_at,
    )


@router.put(
    "/{rule_id}",
    response_model=AlertRuleResponse,
)
def update_alert_rule(
    rule_id: uuid.UUID,
    payload: AlertRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rule = db.scalar(
        select(AlertRule).where(
            AlertRule.id == rule_id,
            AlertRule.user_id == current_user.id,
        )
    )

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert rule not found",
        )

    if payload.name is not None:
        rule.name = payload.name

    if payload.conditions is not None:
        rule.conditions = payload.conditions

    if payload.is_active is not None:
        rule.is_active = payload.is_active

    db.commit()
    db.refresh(rule)

    return AlertRuleResponse(
        id=str(rule.id),
        name=rule.name,
        conditions=rule.conditions,
        is_active=rule.is_active,
        created_at=rule.created_at,
    )


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_alert_rule(
    rule_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rule = db.scalar(
        select(AlertRule).where(
            AlertRule.id == rule_id,
            AlertRule.user_id == current_user.id,
        )
    )

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert rule not found",
        )

    db.delete(rule)
    db.commit()

    return None

