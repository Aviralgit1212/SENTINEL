from __future__ import annotations

import os
import pytest


TEST_USERNAME = "test-reviewer"

TEST_PASSWORD_HASH = (
    "pbkdf2_sha256$200000$"
    "00112233445566778899aabbccddeeff$"
    "a15b1928b32ad3cc5f197b164f3cf777"
    "e7d8a951f3ecf7e8d162c525be8be52b"
)


os.environ["REVIEWER_USERNAME"] = TEST_USERNAME

os.environ[
    "REVIEWER_PASSWORD_HASH"
] = TEST_PASSWORD_HASH


from fastapi.testclient import TestClient

import dashboard_auth
from dashboard_auth import get_session

from main import app


client = TestClient(app)


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


@pytest.fixture(scope="module")
def token() -> str:
    response = login(TEST_USERNAME, "test-password")
    assert response.status_code == 200
    return response.json()["token"]


def login(
    username: str,
    password: str,
):
    return client.post(
        "/dashboard/login",
        json={
            "username": username,
            "password": password,
        },
    )


def auth_headers(
    token: str,
) -> dict[str, str]:

    return {
        "Authorization":
            f"Bearer {token}"
    }


def test_wrong_password() -> None:

    response = login(
        TEST_USERNAME,
        "wrong-password",
    )

    assert response.status_code == 401

    print(
        "7.5 wrong password rejection: PASS"
    )


def test_missing_credentials() -> None:

    response = client.get(
        "/dashboard/summary"
    )

    assert response.status_code == 401

    print(
        "7.5 unauthenticated dashboard rejection: PASS"
    )


def test_successful_login() -> None:

    response = login(
        TEST_USERNAME,
        "test-password",
    )

    assert response.status_code == 200

    body = response.json()

    assert body["authenticated"] is True

    assert body["username"] == TEST_USERNAME

    assert body["role"] == "reviewer"

    token = body["token"]

    assert isinstance(
        token,
        str,
    )

    assert len(token) > 20

    assert (
        get_session(token)
        is not None
    )

    print(
        "7.5 reviewer login: PASS"
    )

    assert get_session(token) is not None


def test_authenticated_me(
    token: str,
) -> None:

    response = client.get(
        "/dashboard/me",
        headers=auth_headers(
            token
        ),
    )

    assert response.status_code == 200

    body = response.json()

    assert body["authenticated"] is True

    assert body["username"] == TEST_USERNAME

    assert body["role"] == "reviewer"

    print(
        "7.5 authenticated session: PASS"
    )


def test_authenticated_summary(
    token: str,
) -> None:

    response = client.get(
        "/dashboard/summary",
        headers=auth_headers(
            token
        ),
    )

    assert response.status_code == 200

    body = response.json()

    assert "total" in body

    assert "allowed" in body

    assert "redacted" in body

    assert "blocked" in body

    assert "pending" in body

    print(
        "7.5 protected dashboard API: PASS"
    )


def test_cache_administration_requires_reviewer(token: str) -> None:
    assert client.get("/dashboard/cache/status").status_code == 401
    assert client.delete("/dashboard/cache").status_code == 401
    assert client.get(
        "/dashboard/cache/status", headers=auth_headers(token)
    ).status_code == 200


def test_authenticated_events(
    token: str,
) -> None:

    response = client.get(
        "/dashboard/events",
        headers=auth_headers(
            token
        ),
    )

    assert response.status_code == 200

    assert isinstance(
        response.json(),
        list,
    )

    print(
        "7.5 authenticated event access: PASS"
    )


def test_logout(
    token: str,
) -> None:

    response = client.post(
        "/dashboard/logout",
        headers=auth_headers(
            token
        ),
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["authenticated"]
        is False
    )

    assert (
        body["username"]
        == TEST_USERNAME
    )

    # Critical check:
    # logout must actually remove
    # this exact session token.
    assert (
        get_session(token)
        is None
    )

    print(
        "7.5 reviewer logout: PASS"
    )


def test_revoked_token(
    token: str,
) -> None:

    # Confirm the token is already
    # revoked before making the API call.
    assert (
        get_session(token)
        is None
    )

    response = client.get(
        "/dashboard/summary",
        headers=auth_headers(
            token
        ),
    )

    assert response.status_code == 401

    print(
        "7.5 revoked session rejection: PASS"
    )


def test_invalid_token_format() -> None:

    response = client.get(
        "/dashboard/summary",
        headers={
            "Authorization":
                "Bearer invalid-token"
        },
    )

    assert response.status_code == 401

    print(
        "7.5 invalid token rejection: PASS"
    )


def main() -> None:

    test_wrong_password()

    test_missing_credentials()

    token = (
        test_successful_login()
    )

    test_authenticated_me(
        token
    )

    test_authenticated_summary(
        token
    )

    test_authenticated_events(
        token
    )

    test_logout(
        token
    )

    test_revoked_token(
        token
    )

    test_invalid_token_format()

    print(
        "7.5 REVIEWER AUTHENTICATION: PASS"
    )


if __name__ == "__main__":
    main()
