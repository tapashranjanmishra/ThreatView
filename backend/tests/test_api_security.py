import uuid

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def unique_email():
    return f"security-test-{uuid.uuid4()}@threatview.com"


def register_and_login(email=None):
    email = email or unique_email()
    password = "TestPassword123"

    register_response = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
        },
    )

    assert register_response.status_code == 201

    login_response = client.post(
        "/api/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert login_response.status_code == 200

    return login_response.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_threats_rejects_missing_token():
    response = client.get("/api/threats")

    assert response.status_code == 401


def test_alerts_rejects_missing_token():
    response = client.get("/api/alerts")

    assert response.status_code == 401


def test_threats_rejects_invalid_token():
    response = client.get(
        "/api/threats",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


def test_alerts_rejects_invalid_token():
    response = client.get(
        "/api/alerts",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


def test_threats_accepts_valid_token():
    token = register_and_login()

    response = client.get(
        "/api/threats",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    data = response.json()

    assert "items" in data
    assert "total" in data


def test_alerts_accepts_valid_token():
    token = register_and_login()

    response = client.get(
        "/api/alerts",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_user_cannot_access_another_users_alert_rule():
    token_a = register_and_login()
    token_b = register_and_login()

    create_response = client.post(
        "/api/alerts",
        headers=auth_headers(token_a),
        json={
            "name": "Private Security Rule",
            "conditions": {
                "source": "openphish",
            },
            "is_active": True,
        },
    )

    assert create_response.status_code == 201

    rule_id = create_response.json()["id"]

    response = client.get(
        f"/api/alerts/{rule_id}",
        headers=auth_headers(token_b),
    )

    assert response.status_code == 404


def test_user_cannot_modify_another_users_alert_rule():
    token_a = register_and_login()
    token_b = register_and_login()

    create_response = client.post(
        "/api/alerts",
        headers=auth_headers(token_a),
        json={
            "name": "Private Security Rule",
            "conditions": {
                "source": "openphish",
            },
            "is_active": True,
        },
    )

    assert create_response.status_code == 201

    rule_id = create_response.json()["id"]

    response = client.put(
        f"/api/alerts/{rule_id}",
        headers=auth_headers(token_b),
        json={
            "name": "Hacked Rule",
        },
    )

    assert response.status_code == 404


def test_user_cannot_delete_another_users_alert_rule():
    token_a = register_and_login()
    token_b = register_and_login()

    create_response = client.post(
        "/api/alerts",
        headers=auth_headers(token_a),
        json={
            "name": "Private Security Rule",
            "conditions": {
                "source": "openphish",
            },
            "is_active": True,
        },
    )

    assert create_response.status_code == 201

    rule_id = create_response.json()["id"]

    response = client.delete(
        f"/api/alerts/{rule_id}",
        headers=auth_headers(token_b),
    )

    assert response.status_code == 404
