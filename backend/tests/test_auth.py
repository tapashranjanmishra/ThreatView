import uuid

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def unique_email():
    return f"auth-test-{uuid.uuid4()}@threatview.com"


def test_register_success():
    email = unique_email()

    response = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": "TestPassword123",
            "company_name": "ThreatView Test",
            "industry": "Cybersecurity",
            "monitored_domain": "example.com",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["email"] == email
    assert data["company_name"] == "ThreatView Test"
    assert data["industry"] == "Cybersecurity"
    assert data["monitored_domain"] == "example.com"
    assert data["tier"] == "free"
    assert "id" in data


def test_register_duplicate_email():
    email = unique_email()

    payload = {
        "email": email,
        "password": "TestPassword123",
    }

    first_response = client.post(
        "/api/auth/register",
        json=payload,
    )

    assert first_response.status_code == 201

    second_response = client.post(
        "/api/auth/register",
        json=payload,
    )

    assert second_response.status_code == 409
    assert second_response.json()["detail"] == "Email already registered"


def test_register_rejects_short_password():
    response = client.post(
        "/api/auth/register",
        json={
            "email": unique_email(),
            "password": "short",
        },
    )

    assert response.status_code == 422


def test_register_rejects_invalid_email():
    response = client.post(
        "/api/auth/register",
        json={
            "email": "not-an-email",
            "password": "TestPassword123",
        },
    )

    assert response.status_code == 422


def test_login_success():
    email = unique_email()
    password = "TestPassword123"

    register_response = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
        },
    )

    assert register_response.status_code == 201

    response = client.post(
        "/api/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["token_type"] == "bearer"
    assert data["access_token"]
    assert data["user"]["email"] == email
    assert data["user"]["tier"] == "free"


def test_login_rejects_wrong_password():
    email = unique_email()

    register_response = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": "CorrectPassword123",
        },
    )

    assert register_response.status_code == 201

    response = client.post(
        "/api/auth/login",
        json={
            "email": email,
            "password": "WrongPassword123",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_login_rejects_unknown_user():
    response = client.post(
        "/api/auth/login",
        json={
            "email": unique_email(),
            "password": "TestPassword123",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"