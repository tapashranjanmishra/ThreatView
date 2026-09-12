from __future__ import annotations

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import IOCType, ThreatModel, ThreatType
from app.services.alert_engine import create_alerts_for_threat


OTX_PULSES_URL = (
    "https://otx.alienvault.com/api/v1/pulses/subscribed"
)


def _map_indicator_type(
    indicator_type: str,
) -> IOCType | None:
    mapping = {
        "IPv4": IOCType.IP,
        "IPv6": IOCType.IP,
        "domain": IOCType.DOMAIN,
        "hostname": IOCType.DOMAIN,
        "URL": IOCType.URL,
        "FileHash-MD5": IOCType.FILE_HASH,
        "FileHash-SHA1": IOCType.FILE_HASH,
        "FileHash-SHA256": IOCType.FILE_HASH,
        "email": IOCType.EMAIL,
    }

    return mapping.get(indicator_type)


def ingest_otx(
    db: Session,
    limit: int = 100,
) -> int:
    if not settings.OTX_API_KEY:
        raise RuntimeError(
            "OTX_API_KEY is not configured"
        )

    headers = {
        "X-OTX-API-KEY": settings.OTX_API_KEY,
        "User-Agent": "ThreatView/1.0",
    }

    response = requests.get(
        OTX_PULSES_URL,
        headers=headers,
        params={
            "limit": limit,
        },
        timeout=60,
    )

    response.raise_for_status()

    data = response.json()

    pulses = data.get("results", [])

    created = 0

    for pulse in pulses:
        pulse_name = pulse.get(
            "name",
            "OTX Pulse",
        )

        for indicator in pulse.get(
            "indicators",
            [],
        ):
            ioc_value = indicator.get("indicator")
            indicator_type = indicator.get("type")

            if not ioc_value or not indicator_type:
                continue

            ioc_type = _map_indicator_type(
                indicator_type
            )

            if ioc_type is None:
                continue

            existing = db.scalar(
                select(ThreatModel).where(
                    ThreatModel.ioc_value == ioc_value,
                    ThreatModel.source == "otx",
                )
            )

            if existing:
                continue

            threat = ThreatModel(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                threat_type=ThreatType.OTHER,
                source="otx",
                confidence_score=None,
                raw_data={
                    "pulse_name": pulse_name,
                    "pulse_id": pulse.get("id"),
                    "indicator": indicator,
                },
            )

            db.add(threat)

            # Get the generated UUID before creating alerts.
            db.flush()

            create_alerts_for_threat(
                db=db,
                threat=threat,
            )

            created += 1

    db.commit()

    return created