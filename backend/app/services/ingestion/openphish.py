from __future__ import annotations

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import IOCType, ThreatModel, ThreatType
from app.services.alert_engine import create_alerts_for_threat


OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"


def ingest_openphish(
    db: Session,
    limit: int = 100,
) -> int:
    headers = {
        "User-Agent": "ThreatView/1.0",
    }

    response = requests.get(
        OPENPHISH_FEED_URL,
        headers=headers,
        timeout=60,
    )

    response.raise_for_status()

    urls = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip()
    ]

    created = 0

    for url in urls[:limit]:
        existing = db.scalar(
            select(ThreatModel).where(
                ThreatModel.ioc_value == url,
                ThreatModel.source == "openphish",
            )
        )

        if existing:
            continue

        threat = ThreatModel(
            ioc_type=IOCType.URL,
            ioc_value=url,
            threat_type=ThreatType.PHISHING,
            source="openphish",
            confidence_score=None,
            raw_data={
                "feed": "OpenPhish Community Feed",
                "url": url,
            },
        )

        db.add(threat)

        # Generate the UUID before evaluating alert rules.
        db.flush()

        create_alerts_for_threat(
            db=db,
            threat=threat,
        )

        created += 1

    db.commit()

    return created
