import uuid

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def unique_email():
    return f"alerts-api-test-{uuid.uuid4()}@threatview.com"


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


def create_rule(token, name="API Test Rule"):
    response = client.post(
        "/api/alerts",
        headers=headers(token),
        json={
            "name": name,
            "conditions": {
                "source": "openphish",
                "threat_type": "phishing",
            },
            "is_active": True,
        },
    )

    assert response.status_code == 201

    return response.json()


def test_create_alert_rule():
    token = get_token()

    rule = create_rule(token)

    assert rule["name"] == "API Test Rule"
    assert rule["conditions"]["source"] == "openphish"
    assert rule["conditions"]["threat_type"] == "phishing"
    assert rule["is_active"] is True
    assert "id" in rule
    assert "created_at" in rule


def test_list_alert_rules():
    token = get_token()

    create_rule(token, "Rule One")
    create_rule(token, "Rule Two")

    response = client.get(
        "/api/alerts",
        headers=headers(token),
    )

    assert response.status_code == 200

    rules = response.json()

    assert len(rules) >= 2
    assert all("id" in rule for rule in rules)


def test_get_alert_rule():
    token = get_token()

    rule = create_rule(token)
    rule_id = rule["id"]

    response = client.get(
        f"/api/alerts/{rule_id}",
        headers=headers(token),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == rule_id
    assert data["name"] == "API Test Rule"


def test_update_alert_rule():
    token = get_token()

    rule = create_rule(token)
    rule_id = rule["id"]

    response = client.put(
        f"/api/alerts/{rule_id}",
        headers=headers(token),
        json={
            "name": "Updated API Rule",
            "conditions": {
                "source": "otx",
                "threat_type": "other",
            },
            "is_active": False,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == rule_id
    assert data["name"] == "Updated API Rule"
    assert data["conditions"]["source"] == "otx"
    assert data["conditions"]["threat_type"] == "other"
    assert data["is_active"] is False


def test_update_alert_rule_partially():
    token = get_token()

    rule = create_rule(token)
    rule_id = rule["id"]

    response = client.put(
        f"/api/alerts/{rule_id}",
        headers=headers(token),
        json={
            "is_active": False,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == rule_id
    assert data["is_active"] is False
    assert data["name"] == "API Test Rule"


def test_delete_alert_rule():
    token = get_token()

    rule = create_rule(token)
    rule_id = rule["id"]

    response = client.delete(
        f"/api/alerts/{rule_id}",
        headers=headers(token),
    )

    assert response.status_code == 204

    get_response = client.get(
        f"/api/alerts/{rule_id}",
        headers=headers(token),
    )

    assert get_response.status_code == 404


def test_get_nonexistent_alert_rule():
    token = get_token()

    fake_id = str(uuid.uuid4())

    response = client.get(
        f"/api/alerts/{fake_id}",
        headers=headers(token),
    )

    assert response.status_code == 404


def test_list_notifications():
    token = get_token()

    response = client.get(
        "/api/alerts/notifications",
        headers=headers(token),
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)
