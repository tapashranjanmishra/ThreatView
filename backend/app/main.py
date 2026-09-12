import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.auth import router as auth_router
from app.api.routes.threats import router as threats_router
from app.api.routes.alerts import router as alerts_router
from app.database import SessionLocal
from app.config import settings
from app.services.ingestion.runner import run_ingestion


# =========================================================
# Configuration
# =========================================================

INGESTION_INTERVAL_SECONDS = (
    settings.INGESTION_INTERVAL_MINUTES * 60
)


# =========================================================
# Logging
# =========================================================

logging.basicConfig(
    level=logging.INFO,
)

logger = logging.getLogger("threatview")

ingestion_status = {
    "status": "starting",
    "last_run": None,
    "last_result": {
        "otx": 0,
        "openphish": 0,
    },
    "last_error": None,
}
# =========================================================
# Automatic Ingestion
# =========================================================

async def scheduled_ingestion():
    while True:
        db = None

        try:
            ingestion_status["status"] = "running"
            ingestion_status["last_error"] = None

            logger.info("Starting scheduled threat ingestion...")

            db = SessionLocal()

            result = await asyncio.to_thread(
                run_ingestion,
                db,
            )

            ingestion_status["status"] = "healthy"
            ingestion_status["last_run"] = (
                datetime.now(timezone.utc).isoformat()
            )
            ingestion_status["last_result"] = result

            logger.info(
                "Scheduled ingestion completed: %s",
                result,
            )

        except Exception as exc:
            ingestion_status["status"] = "error"
            ingestion_status["last_error"] = str(exc)

            logger.exception(
                "Scheduled threat ingestion failed"
            )

        finally:
            if db is not None:
                db.close()

        await asyncio.sleep(
            INGESTION_INTERVAL_SECONDS
        )

# =========================================================
# FastAPI Lifecycle
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.info(
        "Starting ThreatView automatic ingestion scheduler"
    )

    ingestion_task = asyncio.create_task(
        scheduled_ingestion()
    )

    yield

    logger.info(
        "Stopping ThreatView automatic ingestion scheduler"
    )

    ingestion_task.cancel()

    try:
        await ingestion_task
    except asyncio.CancelledError:
        pass


# =========================================================
# FastAPI Application
# =========================================================

app = FastAPI(
    title="ThreatView API",
    description="Threat intelligence aggregation and monitoring API",
    version="1.0.0",
    lifespan=lifespan,
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# Health Check
# =========================================================

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "threatview-api",
    }

@app.get("/api/ingestion/status")
def ingestion_status_endpoint():
    return {
        **ingestion_status,
        "interval_minutes": settings.INGESTION_INTERVAL_MINUTES,
    }
    
# =========================================================
# API Routes
# =========================================================

app.include_router(auth_router)
app.include_router(threats_router)
app.include_router(alerts_router)