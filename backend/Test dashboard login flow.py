"""
Regression tests: reviewer login -> protected dashboard request.

Bug being guarded against: protected routes declared `authorization` as a plain
Header(...) parameter. Swagger UI does not send a header parameter named
"Authorization", so every protected call from Swagger arrived with NO header and
got 401 "Reviewer authentication required." even with a valid session token.
"""
from __future__ import annotations

import os

# Never let importing dashboard_auth create/overwrite a real backend/.env.
os.environ.setdefault("REVIEWER_PASSWORD_HASH", "test-placeholder")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import dashboard_api
import dashboard_auth

EVENT_ID = "cf363698-46e3-44bf-b35c-3c4918398f3a"
TEST_USER = "reviewer"
TEST_PASSWORD = "unit-test-password-not-real"


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(dashboard_auth, "REVIEWER_USERNAME", TEST_USER)
    monkeypatch.setattr(
        dashboard_auth,
        "REVIEWER_PASSWORD_HASH",
        dashboard_auth.hash_password(TEST_PASSWORD),
    )
    dashboard_auth._sessions.clear()

    event = {"id": EVENT_ID, "state": "BLOCKED", "username": "local-user"}
    monkeypatch.setattr(
        dashboard_api,
        "get_security_event",
        lambda event_id: event if event_id == EVENT_ID else None,
    )

    def fake_update(*, event_id, new_state, actor, reviewed_by, detail):
        event["state"] = new_state

    monkeypatch.setattr(dashboard_api, "update_event_state", fake_update)

    app = FastAPI()
    app.include_router(dashboard_api.router)
    yield TestClient(app)
    dashboard_auth._sessions.clear()


def _login(client) -> str:
    response = client.post(
        "/dashboard/login",
        json={"username": TEST_USER, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    return response.json()["token"]


def test_login_then_get_event_and_approve(client):
    headers = {"Authorization": f"Bearer {_login(client)}"}

    assert client.get("/dashboard/me", headers=headers).status_code == 200

    got = client.get(f"/dashboard/events/{EVENT_ID}", headers=headers)
    assert got.status_code == 200
    assert got.json()["id"] == EVENT_ID

    approved = client.post(f"/dashboard/events/{EVENT_ID}/approve", headers=headers)
    assert approved.status_code == 200
    assert approved.json()["state"] == "APPROVED"


def test_missing_header_is_rejected(client):
    response = client.get(f"/dashboard/events/{EVENT_ID}")
    assert response.status_code == 401
    assert response.json()["detail"] == "Reviewer authentication required."


def test_unknown_token_is_rejected(client):
    response = client.get(
        f"/dashboard/events/{EVENT_ID}",
        headers={"Authorization": "Bearer not-a-real-session-token"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Session expired or invalid."


def test_malformed_header_is_rejected(client):
    token = _login(client)
    response = client.get(
        f"/dashboard/events/{EVENT_ID}",
        headers={"Authorization": f"Token {token}"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication header."


def test_logout_revokes_the_token(client):
    headers = {"Authorization": f"Bearer {_login(client)}"}
    assert client.post("/dashboard/logout", headers=headers).status_code == 200
    assert client.get("/dashboard/me", headers=headers).status_code == 401


def test_swagger_can_send_the_token(client):
    """
    TestClient can't emulate Swagger UI, so check the OpenAPI document instead:
    Swagger only attaches Authorization when it is declared as a SECURITY SCHEME,
    never as a plain header parameter.
    """
    spec = client.get("/openapi.json").json()

    schemes = spec["components"]["securitySchemes"]
    assert any(
        s.get("type") == "apiKey"
        and s.get("in") == "header"
        and s.get("name") == "Authorization"
        for s in schemes.values()
    ), "No Authorization header security scheme declared for Swagger"

    protected = [
        ("get", "/dashboard/me"),
        ("post", "/dashboard/logout"),
        ("get", "/dashboard/summary"),
        ("get", "/dashboard/cache/status"),
        ("delete", "/dashboard/cache"),
        ("get", "/dashboard/events"),
        ("get", "/dashboard/events/{event_id}"),
        ("post", "/dashboard/events/{event_id}/approve"),
        ("post", "/dashboard/events/{event_id}/reject"),
    ]
    for method, path in protected:
        operation = spec["paths"][path][method]
        assert operation.get("security"), f"{method.upper()} {path} has no security scheme"
        plain_auth_params = [
            p for p in operation.get("parameters", [])
            if p["in"] == "header" and p["name"].lower() == "authorization"
        ]
        assert not plain_auth_params, (
            f"{method.upper()} {path} still declares Authorization as a plain "
            "header parameter, which Swagger UI will not send"
        )

    assert not spec["paths"]["/dashboard/login"]["post"].get("security")