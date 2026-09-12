from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_ingestion_status():
    response = client.get("/api/ingestion/status")

    assert response.status_code == 200

    data = response.json()

    assert "status" in data
    assert "last_run" in data
    assert "last_result" in data
    assert "last_error" in data
    assert "interval_minutes" in data

    assert data["status"] in {
        "starting",
        "running",
        "healthy",
        "error",
    }

    assert isinstance(data["last_result"], dict)
    assert "otx" in data["last_result"]
    assert "openphish" in data["last_result"]
    assert isinstance(data["interval_minutes"], int)


def test_ingestion_status_does_not_expose_secrets():
    response = client.get("/api/ingestion/status")

    assert response.status_code == 200

    data = response.json()

    response_text = str(data).lower()

    assert "api_key" not in response_text
    assert "secret_key" not in response_text
    assert "password" not in response_text
