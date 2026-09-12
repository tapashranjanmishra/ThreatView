import uuid

from app.models import (
    AlertNotification,
    AlertRule,
    IOCType,
    ThreatModel,
    ThreatType,
    User,
    UserTier,
)
from app.services.alert_engine import create_alerts_for_threat


def test_alert_creation_and_deduplication(db):
    user = User(
        id=uuid.uuid4(),
        email=f"integration-test-{uuid.uuid4()}@threatview.com",
        hashed_password="test-hash",
        tier=UserTier.FREE,
    )

    db.add(user)
    db.flush()

    rule = AlertRule(
        user_id=user.id,
        name="OpenPhish Test Rule",
        conditions={
            "source": "openphish",
            "threat_type": "phishing",
            "ioc_type": "url",
        },
        is_active=True,
    )

    db.add(rule)
    db.flush()

    threat = ThreatModel(
        ioc_type=IOCType.URL,
       ioc_value=f"https://integration-test-threatview.example/{uuid.uuid4()}",
        threat_type=ThreatType.PHISHING,
        source="openphish",
        country=None,
        industry=None,
        confidence_score=None,
        raw_data={"test": True},
    )

    db.add(threat)
    db.flush()

    notifications = create_alerts_for_threat(db, threat)

    assert len(notifications) == 1

    notification = notifications[0]

    assert notification.rule_id == rule.id
    assert notification.threat_id == threat.id
    assert notification.dedup_key == f"{rule.id}:{threat.id}"

    # Running the alert engine again for the same threat
    # must not create a duplicate notification.
    notifications_again = create_alerts_for_threat(db, threat)

    assert len(notifications_again) == 0

    count = (
        db.query(AlertNotification)
        .filter(AlertNotification.threat_id == threat.id)
        .count()
    )

    assert count == 1