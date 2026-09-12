import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.database import get_db
from app.models import IOCType, ThreatModel, ThreatType, User
from app.schemas import ThreatCreate, ThreatListResponse, ThreatResponse
from app.services.alert_engine import create_alerts_for_threat


router = APIRouter(
    prefix="/api/threats",
    tags=["Threats"],
)


@router.get(
    "",
    response_model=ThreatListResponse,
)
def list_threats(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatListResponse:
    total = db.scalar(
        select(func.count()).select_from(ThreatModel)
    )

    threats = db.scalars(
        select(ThreatModel)
        .order_by(ThreatModel.last_seen.desc())
        .offset(skip)
        .limit(limit)
    ).all()

    return {
        "items": threats,
        "total": total or 0,
    }

@router.get(
    "/stats",
)
def threat_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total = db.scalar(
        select(func.count()).select_from(ThreatModel)
    )

    otx = db.scalar(
        select(func.count())
        .select_from(ThreatModel)
        .where(ThreatModel.source == "otx")
    )

    openphish = db.scalar(
        select(func.count())
        .select_from(ThreatModel)
        .where(ThreatModel.source == "openphish")
    )

    phishing = db.scalar(
        select(func.count())
        .select_from(ThreatModel)
        .where(ThreatModel.threat_type == "PHISHING")
    )

    return {
        "total": total or 0,
        "otx": otx or 0,
        "openphish": openphish or 0,
        "phishing": phishing or 0,
    }

@router.get(
    "/filter",
    response_model=ThreatListResponse,
)
def filter_threats(
    ioc: str | None = Query(default=None),
    source: str | None = Query(default=None),
    threat_type: ThreatType | None = Query(default=None),
    ioc_type: IOCType | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatListResponse:

    query = select(ThreatModel)

    if ioc:
        query = query.where(
            ThreatModel.ioc_value.ilike(f"%{ioc}%")
        )

    if source:
        query = query.where(
            ThreatModel.source == source
        )

    if threat_type:
        query = query.where(
            ThreatModel.threat_type == threat_type
        )

    if ioc_type:
        query = query.where(
            ThreatModel.ioc_type == ioc_type
        )

    total = db.scalar(
        select(func.count())
        .select_from(query.subquery())
    )

    threats = db.scalars(
        query
        .order_by(ThreatModel.last_seen.desc())
        .offset(skip)
        .limit(limit)
    ).all()

    return {
        "items": threats,
        "total": total or 0,
    }

@router.get(
    "/search",
    response_model=list[ThreatResponse],
)
def search_threats(
    ioc: str = Query(min_length=1),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    threats = db.scalars(
        select(ThreatModel)
        .where(ThreatModel.ioc_value == ioc)
        .order_by(ThreatModel.last_seen.desc())
    ).all()

    return threats


@router.get(
    "/{threat_id}",
    response_model=ThreatResponse,
)
def get_threat(
    threat_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    threat = db.get(ThreatModel, threat_id)

    if threat is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found",
        )

    return threat


@router.post(
    "",
    response_model=ThreatResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_threat(
    payload: ThreatCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    existing = db.scalar(
        select(ThreatModel).where(
            ThreatModel.ioc_value == payload.ioc_value,
            ThreatModel.source == payload.source,
        )
    )

    if existing:
        existing.last_seen = func.now()
        db.commit()
        db.refresh(existing)

        create_alerts_for_threat(
            db=db,
            threat=existing,
        )

        return existing

    threat = ThreatModel(
        ioc_type=payload.ioc_type,
        ioc_value=payload.ioc_value,
        threat_type=payload.threat_type,
        source=payload.source,
        country=payload.country,
        industry=payload.industry,
        confidence_score=payload.confidence_score,
        raw_data=payload.raw_data,
    )

    db.add(threat)
    db.commit()
    db.refresh(threat)

    create_alerts_for_threat(
        db=db,
        threat=threat,
    )

    return threat