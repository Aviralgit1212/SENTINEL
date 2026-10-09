"""
Release endpoint tests (/release/*).

These use the real release_store / dashboard_store code with a throw-away
SQLite file, so your real guardian.db is never touched.

Known-bug guard: POST /release/clear used to be registered AFTER
POST /release/{event_id}, so FastAPI treated "clear" as an event id and returned
401 "Release credentials required." even for a valid reviewer.
"""
from __future__ import annotations

import os

# Never let importing dashboard_auth create/overwrite a real backend/.env.
os.environ.setdefault("REVIEWER_PASSWORD_HASH", "test-placeholder")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import dashboard_auth
import dashboard_store
import release_api
import release_store

LOCAL = ("127.0.0.1", 50000)
REMOTE = ("203.0.113.9", 50000)  # documentation-range address, not loopback
ORIGINAL_TEXT = "synthetic-original-that-must-never-be-returned"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard_store, "DB_PATH", tmp_path / "guardian.db")
    dashboard_store.init_db()
    release_store.clear_held_payloads()
    dashboard_auth._sessions.clear()

    app = FastAPI()
    app.include_router(release_api.router)
    yield app

    release_store.clear_held_payloads()
    dashboard_auth._sessions.clear()


@pytest.fixture()
def client(env):
    return TestClient(env, client=LOCAL)


def _blocked_event(token: str = "release-token-for-tests") -> tuple[str, str]:
    event_id = dashboard_store.create_security_event(
        username="local-user", site="example.test", input_type="TEXT",
        filename=None, risk="HIGH", decision="BLOCK", state="BLOCKED",
        entities=[{"entity_type": "US_SSN"}],
    )
    release_store.create_held_payload(
        event_id=event_id, release_token=token,
        payload_type="text", raw_text=ORIGINAL_TEXT,
    )
    return event_id, token


def _release_headers(token: str) -> dict[str, str]:
    return {"X-Guardian-Release-Token": token}


def _reviewer_headers() -> dict[str, str]:
    session = dashboard_auth.create_session(username="reviewer", role="reviewer")
    return {"Authorization": f"Bearer {session}"}


def _set_state(event_id: str, state: str) -> None:
    dashboard_store.update_event_state(
        event_id=event_id, new_state=state,
        actor="test-reviewer", reviewed_by="test-reviewer",
    )


# ---------------------------------------------------------------- status ----

def test_status_pending_with_valid_release_token(client):
    event_id, token = _blocked_event()
    response = client.get(f"/release/{event_id}/status", headers=_release_headers(token))
    assert response.status_code == 200
    assert response.json() == {"event_id": event_id, "state": "PENDING"}


def test_status_requires_release_token(client):
    event_id, _ = _blocked_event()
    response = client.get(f"/release/{event_id}/status")
    assert response.status_code == 401
    assert response.json()["detail"] == "Release credentials required."


def test_status_rejects_wrong_release_token(client):
    event_id, _ = _blocked_event()
    response = client.get(f"/release/{event_id}/status", headers=_release_headers("wrong"))
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid release credentials."


def test_status_unknown_event_is_gone(client):
    response = client.get(
        "/release/00000000-0000-0000-0000-000000000000/status",
        headers=_release_headers("anything"),
    )
    assert response.status_code == 410


def test_status_reports_approved(client):
    event_id, token = _blocked_event()
    _set_state(event_id, "APPROVED")
    response = client.get(f"/release/{event_id}/status", headers=_release_headers(token))
    assert response.status_code == 200
    assert response.json()["state"] == "APPROVED"


def test_status_rejected_purges_the_original(client):
    event_id, token = _blocked_event()
    _set_state(event_id, "REJECTED")
    first = client.get(f"/release/{event_id}/status", headers=_release_headers(token))
    assert first.status_code == 200
    assert first.json()["state"] == "REJECTED"
    assert release_store.memory_status() == {"items": 0, "bytes": 0}
    again = client.get(f"/release/{event_id}/status", headers=_release_headers(token))
    assert again.status_code == 410


def test_expired_payload_is_gone_for_status_and_release(client, monkeypatch):
    event_id, token = _blocked_event()
    _set_state(event_id, "APPROVED")
    monkeypatch.setattr(release_store, "IDLE_TIMEOUT_SECONDS", 0)
    status = client.get(f"/release/{event_id}/status", headers=_release_headers(token))
    assert status.status_code == 410
    release = client.post(f"/release/{event_id}", headers=_release_headers(token))
    assert release.status_code == 410


# --------------------------------------------------------------- release ----

def test_release_requires_release_token(client):
    event_id, _ = _blocked_event()
    response = client.post(f"/release/{event_id}")
    assert response.status_code == 401
    assert response.json()["detail"] == "Release credentials required."


def test_release_wrong_token_keeps_the_payload(client):
    event_id, _ = _blocked_event()
    _set_state(event_id, "APPROVED")
    response = client.post(f"/release/{event_id}", headers=_release_headers("wrong"))
    assert response.status_code == 401
    assert response.json()["detail"] == "Release not authorized."
    assert release_store.memory_status()["items"] == 1


def test_release_before_approval_is_refused_and_keeps_payload(client):
    event_id, token = _blocked_event()
    response = client.post(f"/release/{event_id}", headers=_release_headers(token))
    assert response.status_code == 401
    assert response.json()["detail"] == "Release not authorized."
    assert release_store.memory_status()["items"] == 1


def test_release_after_reject_is_refused(client):
    event_id, token = _blocked_event()
    _set_state(event_id, "REJECTED")
    response = client.post(f"/release/{event_id}", headers=_release_headers(token))
    assert response.status_code == 401


def test_approved_release_returns_no_sensitive_content_and_is_single_use(client):
    event_id, token = _blocked_event()
    _set_state(event_id, "APPROVED")

    response = client.post(f"/release/{event_id}", headers=_release_headers(token))
    assert response.status_code == 200
    assert response.json() == {"event_id": event_id, "state": "RELEASED"}
    assert ORIGINAL_TEXT not in response.text
    assert release_store.memory_status() == {"items": 0, "bytes": 0}

    second = client.post(f"/release/{event_id}", headers=_release_headers(token))
    assert second.status_code == 410


# ------------------------------------------------------------- localhost ----

@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/release/some-event/status"),
        ("post", "/release/some-event"),
        ("post", "/release/clear"),
    ],
)
def test_non_loopback_clients_are_refused_before_any_credential_check(env, method, path):
    remote = TestClient(env, client=REMOTE)
    headers = {**_release_headers("t"), **_reviewer_headers()}
    response = getattr(remote, method)(path, headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Local access required."


# ----------------------------------------------------------------- clear ----

def test_clear_route_is_not_swallowed_by_the_event_id_route(client):
    """The regression: valid reviewer + POST /release/clear must reach the clear handler."""
    _blocked_event("t1")
    _blocked_event("t2")
    response = client.post("/release/clear", headers=_reviewer_headers())
    assert response.status_code == 200
    assert response.json() == {"cleared": 2, "storage": "process-memory"}
    assert release_store.memory_status() == {"items": 0, "bytes": 0}


def test_clear_requires_reviewer_authentication(client):
    _blocked_event()
    response = client.post("/release/clear")
    assert response.status_code == 401
    assert response.json()["detail"] == "Reviewer authentication required."
    assert release_store.memory_status()["items"] == 1


def test_clear_rejects_unknown_reviewer_token(client):
    _blocked_event()
    response = client.post("/release/clear", headers={"Authorization": "Bearer nope"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Session expired or invalid."
    assert release_store.memory_status()["items"] == 1


def test_a_release_token_is_not_reviewer_authority_for_clear(client):
    event_id, token = _blocked_event()
    response = client.post("/release/clear", headers=_release_headers(token))
    assert response.status_code == 401
    assert release_store.memory_status()["items"] == 1


def test_clear_declares_the_swagger_authorization_scheme(env):
    spec = TestClient(env, client=LOCAL).get("/openapi.json").json()
    operation = spec["paths"]["/release/clear"]["post"]
    assert operation.get("security"), "POST /release/clear has no security scheme for Swagger"
    plain = [
        p for p in operation.get("parameters", [])
        if p["in"] == "header" and p["name"].lower() == "authorization"
    ]
    assert not plain, "Authorization is a plain header parameter; Swagger UI will not send it"