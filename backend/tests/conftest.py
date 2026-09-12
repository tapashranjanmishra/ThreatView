import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest
from sqlalchemy import text

# Read the main DATABASE_URL from .env
env_database_url = None

for line in Path(".env").read_text(encoding="utf-8").splitlines():
    if line.startswith("DATABASE_URL="):
        env_database_url = line.split("=", 1)[1].strip()
        break

if not env_database_url:
    raise RuntimeError("DATABASE_URL not found in .env")

# Change ONLY the database name.
# Username, password, host, and port remain unchanged.
parsed = urlsplit(env_database_url)

os.environ["DATABASE_URL"] = urlunsplit(
    (
        parsed.scheme,
        parsed.netloc,
        "/threatview_test",
        parsed.query,
        parsed.fragment,
    )
)

from app.database import SessionLocal


@pytest.fixture
def db():
    session = SessionLocal()

    session.execute(
        text(
            "TRUNCATE alert_notifications, alert_rules, threats, users CASCADE"
        )
    )
    session.commit()

    try:
        yield session
    finally:
        session.execute(
            text(
                "TRUNCATE alert_notifications, alert_rules, threats, users CASCADE"
            )
        )
        session.commit()
        session.close()
