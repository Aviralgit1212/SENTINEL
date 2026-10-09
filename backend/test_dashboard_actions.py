from __future__ import annotations

import os
import tempfile
from pathlib import Path
import pytest


TEST_USERNAME = "test-reviewer"

TEST_PASSWORD_HASH = (
    "pbkdf2_sha256$200000$"
    "00112233445566778899aabbccddeeff$"
    "a15b1928b32ad3cc5f197b164f3cf777"
    "e7d8a951f3ecf7e8d162c525be8be52b"
)

os.environ[
    "REVIEWER_USERNAME"
] = TEST_USERNAME

os.environ[
    "REVIEWER_PASSWORD_HASH"
] = TEST_PASSWORD_HASH


from fastapi.testclient import TestClient

import dashboard_store
import dashboard_auth

from main import app


client = TestClient(
    app
)


@pytest.fixture(scope="module", autouse=True)
def configure_test_reviewer():
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(dashboard_auth, "REVIEWER_USERNAME", TEST_USERNAME)
        patch.setattr(
            dashboard_auth,
            "REVIEWER_PASSWORD_HASH",
            dashboard_auth.hash_password("test-password", salt=b"test-reviewer-salt"),
        )
        yield


def setup_test_database() -> Path:
    directory = Path(
        tempfile.mkdtemp()
    )

    dashboard_store.DB_PATH = (
        directory / "dashboard_actions_test.db"
    )

    dashboard_store.init_db()

    return directory


def login() -> str:
    response = client.post(
        "/dashboard/login",
        json={
            "username":
                TEST_USERNAME,
            "password":
                "test-password",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["authenticated"] is True
    assert body["role"] == "reviewer"

    token = body["token"]

    assert isinstance(
        token,
        str,
    )

    return token


def headers(
    token: str,
) -> dict[str, str]:
    return {
        "Authorization":
            f"Bearer {token}"
    }


def create_pending_event(
    username: str = "local-user",
) -> str:
    return dashboard_store.create_security_event(
        username=username,
        site="chatgpt.com",
        input_type="TEXT",
        filename=None,
        risk="CRITICAL",
        decision="BLOCK",
        state="PENDING_APPROVAL",
        entities=[
            {
                "entity_type":
                    "CREDIT_CARD"
            }
        ],
    )


def test_approve() -> None:
    setup_test_database()

    token = login()

    event_id = create_pending_event()

    response = client.post(
        f"/dashboard/events/{event_id}/approve",
        headers=headers(token),
    )

    assert response.status_code == 200

    body = response.json()

    assert body["id"] == event_id
    assert body["state"] == "APPROVED"
    assert body["reviewed_by"] == TEST_USERNAME
    assert body["reviewed_at"]

    assert any(
        item["action"] == "state_change"
        and "APPROVED" in (
            item["detail"] or ""
        )
        for item in body["audit"]
    )

    print(
        "7.7 approve event: PASS"
    )


def test_reject() -> None:
    setup_test_database()

    token = login()

    event_id = create_pending_event()

    response = client.post(
        f"/dashboard/events/{event_id}/reject",
        headers=headers(token),
    )

    assert response.status_code == 200

    body = response.json()

    assert body["id"] == event_id
    assert body["state"] == "REJECTED"
    assert body["reviewed_by"] == TEST_USERNAME
    assert body["reviewed_at"]

    assert any(
        item["action"] == "state_change"
        and "REJECTED" in (
            item["detail"] or ""
        )
        for item in body["audit"]
    )

    print(
        "7.7 reject event: PASS"
    )


def test_unauthenticated_action() -> None:
    setup_test_database()

    event_id = create_pending_event()

    response = client.post(
        f"/dashboard/events/{event_id}/approve"
    )

    assert response.status_code == 401

    print(
        "7.7 unauthenticated action rejection: PASS"
    )


def test_self_approval_rejection() -> None:
    setup_test_database()

    token = login()

    event_id = create_pending_event(
        username=TEST_USERNAME
    )

    response = client.post(
        f"/dashboard/events/{event_id}/approve",
        headers=headers(token),
    )

    assert response.status_code == 403

    assert (
        "own event"
        in response.json()["detail"]
    )

    event = (
        dashboard_store.get_security_event(
            event_id
        )
    )

    assert event is not None

    assert (
        event["state"]
        == "PENDING_APPROVAL"
    )

    print(
        "7.7 self-approval rejection: PASS"
    )


def test_invalid_state_rejection() -> None:
    setup_test_database()

    token = login()

    event_id = dashboard_store.create_security_event(
        username="local-user",
        site="chatgpt.com",
        input_type="TEXT",
        filename=None,
        risk="LOW",
        decision="ALLOW",
        state="ALLOWED",
        entities=[],
    )

    response = client.post(
        f"/dashboard/events/{event_id}/approve",
        headers=headers(token),
    )

    assert response.status_code == 409

    print(
        "7.7 invalid-state protection: PASS"
    )


def test_missing_event() -> None:
    setup_test_database()

    token = login()

    response = client.post(
        "/dashboard/events/"
        "does-not-exist/approve",
        headers=headers(token),
    )

    assert response.status_code == 404

    print(
        "7.7 missing-event handling: PASS"
    )


def main() -> None:
    test_approve()

    test_reject()

    test_unauthenticated_action()

    test_self_approval_rejection()

    test_invalid_state_rejection()

    test_missing_event()

    print(
        "7.7 REVIEWER ACTIONS: PASS"
    )


if __name__ == "__main__":
    main()
