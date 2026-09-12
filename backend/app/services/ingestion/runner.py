from sqlalchemy.orm import Session

from app.services.ingestion.otx import ingest_otx
from app.services.ingestion.openphish import ingest_openphish


def run_ingestion(db: Session) -> dict:
    results = {
        "otx": 0,
        "openphish": 0,
    }

    results["otx"] = ingest_otx(db)
    results["openphish"] = ingest_openphish(db)

    return results