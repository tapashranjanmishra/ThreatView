from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AlertNotification, AlertRule, ThreatModel


def threat_matches_rule(
    threat: ThreatModel,
    rule: AlertRule,
) -> bool:
    """
    Check whether a threat satisfies an alert rule's conditions.
    """

    conditions = rule.conditions or {}

    # Threat type
    threat_type = conditions.get("threat_type")
    if threat_type and threat.threat_type.value != threat_type:
        return False

    # IOC type
    ioc_type = conditions.get("ioc_type")
    if ioc_type and threat.ioc_type.value != ioc_type:
        return False

    # Source
    source = conditions.get("source")
    if source and threat.source.lower() != str(source).lower():
        return False

    # Country
    country = conditions.get("country")
    if country:
        if not threat.country:
            return False

        if threat.country.lower() != str(country).lower():
            return False

    # Industry
    industry = conditions.get("industry")
    if industry:
        if not threat.industry:
            return False

        if threat.industry.lower() != str(industry).lower():
            return False

    # Minimum confidence score
    min_confidence_score = conditions.get("min_confidence_score")
    if min_confidence_score is not None:
        if threat.confidence_score is None:
            return False

        if threat.confidence_score < float(min_confidence_score):
            return False

    return True


def create_alerts_for_threat(
    db: Session,
    threat: ThreatModel,
) -> list[AlertNotification]:
    """
    Evaluate a threat against all active alert rules
    and create notifications for matching rules.
    """

    rules = db.scalars(
        select(AlertRule).where(
            AlertRule.is_active.is_(True)
        )
    ).all()

    created_notifications: list[AlertNotification] = []

    for rule in rules:
        if not threat_matches_rule(threat, rule):
            continue

        dedup_key = f"{rule.id}:{threat.id}"

        existing_notification = db.scalar(
            select(AlertNotification).where(
                AlertNotification.dedup_key == dedup_key
            )
        )

        if existing_notification:
            continue

        notification = AlertNotification(
            rule_id=rule.id,
            threat_id=threat.id,
            dedup_key=dedup_key,
        )

        db.add(notification)
        created_notifications.append(notification)

    if created_notifications:
        db.commit()

        for notification in created_notifications:
            db.refresh(notification)

    return created_notifications