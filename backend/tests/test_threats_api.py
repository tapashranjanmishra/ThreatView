import uuid

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def unique_email():
    return f"threat-api-test-{uuid.uuid4()}@threatview.com"


def get_token():
    email = unique_email()
    password = "TestPassword123"

    register = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
        },
    )

    assert register.status_code == 201

    login = client.post(
        "/api/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert login.status_code == 200

    return login.json()["access_token"]


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_create_threat():
    token = get_token()

    ioc = f"192.0.2.{uuid.uuid4().int % 255}"

    response = client.post(
        "/api/threats",
        headers=headers(token),
        json={
            "ioc_type": "ip",
            "ioc_value": ioc,
            "threat_type": "scanning",
            "source": "test",
            "country": "IN",
            "industry": "Cybersecurity",
            "confidence_score": 85,
            "raw_data": {
                "test": True,
            },
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["ioc_value"] == ioc
    assert data["ioc_type"] == "ip"
    assert data["threat_type"] == "scanning"
    assert data["source"] == "test"
    assert data["country"] == "IN"
    assert data["industry"] == "Cybersecurity"
    assert data["confidence_score"] == 85
    assert "id" in data


def test_create_duplicate_threat_updates_existing_threat():
    token = get_token()

    ioc = f"192.0.2.{uuid.uuid4().int % 255}"

    payload = {
        "ioc_type": "ip",
        "ioc_value": ioc,
        "threat_type": "scanning",
        "source": "test",
        "confidence_score": 60,
        "raw_data": {
            "first": True,
        },
    }

    first = client.post(
        "/api/threats",
        headers=headers(token),
        json=payload,
    )

    assert first.status_code == 201

    first_data = first.json()

    payload["confidence_score"] = 90
    payload["raw_data"] = {
        "second": True,
    }

    second = client.post(
        "/api/threats",
        headers=headers(token),
        json=payload,
    )

    assert second.status_code == 201

    second_data = second.json()

    assert second_data["id"] == first_data["id"]
    assert second_data["confidence_score"] == 60


def test_get_threat():
    token = get_token()

    ioc = f"192.0.2.{uuid.uuid4().int % 255}"

    create = client.post(
        "/api/threats",
        headers=headers(token),
        json={
            "ioc_type": "ip",
            "ioc_value": ioc,
            "threat_type": "scanning",
            "source": "test",
        },
    )

    assert create.status_code == 201

    threat_id = create.json()["id"]

    response = client.get(
        f"/api/threats/{threat_id}",
        headers=headers(token),
    )

    assert response.status_code == 200
    assert response.json()["id"] == threat_id
    assert response.json()["ioc_value"] == ioc


def test_get_nonexistent_threat():
    token = get_token()

    fake_id = str(uuid.uuid4())

    response = client.get(
        f"/api/threats/{fake_id}",
        headers=headers(token),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat not found"


def test_search_threat():
    token = get_token()

    ioc = f"search-{uuid.uuid4()}.example.com"

    create = client.post(
        "/api/threats",
        headers=headers(token),
        json={
            "ioc_type": "domain",
            "ioc_value": ioc,
            "threat_type": "phishing",
            "source": "test",
        },
    )

    assert create.status_code == 201

    response = client.get(
        "/api/threats/search",
        headers=headers(token),
        params={"ioc": ioc},
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) >= 1
    assert data[0]["ioc_value"] == ioc


def test_threat_list_pagination():
    token = get_token()

    response = client.get(
        "/api/threats",
        headers=headers(token),
        params={
            "skip": 0,
            "limit": 5,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "items" in data
    assert "total" in data
    assert len(data["items"]) <= 5


def test_threat_stats():
    token = get_token()

    response = client.get(
        "/api/threats/stats",
        headers=headers(token),
    )

    assert response.status_code == 200

    data = response.json()

    assert "total" in data
    assert "otx" in data
    assert "openphish" in data
    assert "phishing" in data

    assert isinstance(data["total"], int)
    assert isinstance(data["otx"], int)
    assert isinstance(data["openphish"], int)
    assert isinstance(data["phishing"], int)
