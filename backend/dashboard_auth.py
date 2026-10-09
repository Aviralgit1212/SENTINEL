from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from getpass import getpass
from pathlib import Path

from fastapi import Header, HTTPException, Security
from fastapi.security import APIKeyHeader


ENV_PATH = Path(__file__).resolve().parent / ".env"

SESSION_TTL = timedelta(hours=8)

_sessions: dict[str, "Session"] = {}


@dataclass
class Session:
    username: str
    role: str
    expires_at: datetime


def _now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(
    password: str,
    salt: bytes | None = None,
) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000,
    )

    return (
        "pbkdf2_sha256$200000$"
        f"{salt.hex()}$"
        f"{digest.hex()}"
    )


def verify_password(
    password: str,
    stored_hash: str,
) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = (
            stored_hash.split("$")
        )

        if algorithm != "pbkdf2_sha256":
            return False

        expected_iterations = int(
            iterations
        )

        salt = bytes.fromhex(
            salt_hex
        )

        expected_digest = bytes.fromhex(
            digest_hex
        )

        actual_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            expected_iterations,
        )

        return hmac.compare_digest(
            actual_digest,
            expected_digest,
        )

    except (
        ValueError,
        TypeError,
    ):
        return False


def _read_env_file() -> dict[str, str]:
    values: dict[str, str] = {}

    if not ENV_PATH.exists():
        return values

    for raw_line in ENV_PATH.read_text(
        encoding="utf-8"
    ).splitlines():

        line = raw_line.strip()

        if (
            not line
            or line.startswith("#")
            or "=" not in line
        ):
            continue

        key, value = line.split(
            "=",
            1,
        )

        values[key.strip()] = (
            value.strip()
        )

    return values


def _write_env_file(
    username: str,
    password_hash: str,
) -> None:
    content = (
        "# AI Guardian local reviewer configuration\n"
        "# Do not share this file publicly.\n"
        f"REVIEWER_USERNAME={username}\n"
        f"REVIEWER_PASSWORD_HASH={password_hash}\n"
    )

    ENV_PATH.write_text(
        content,
        encoding="utf-8",
    )


def _load_or_create_config() -> tuple[str, str]:
    file_values = _read_env_file()

    username = (
        os.getenv(
            "REVIEWER_USERNAME"
        )
        or file_values.get(
            "REVIEWER_USERNAME"
        )
        or "reviewer"
    )

    password_hash = (
        os.getenv(
            "REVIEWER_PASSWORD_HASH"
        )
        or file_values.get(
            "REVIEWER_PASSWORD_HASH"
        )
    )

    if password_hash:
        os.environ[
            "REVIEWER_USERNAME"
        ] = username

        os.environ[
            "REVIEWER_PASSWORD_HASH"
        ] = password_hash

        return (
            username,
            password_hash,
        )


    generated_password = (
        secrets.token_urlsafe(12)
    )

    password_hash = hash_password(
        generated_password
    )

    _write_env_file(
        username,
        password_hash,
    )

    os.environ[
        "REVIEWER_USERNAME"
    ] = username

    os.environ[
        "REVIEWER_PASSWORD_HASH"
    ] = password_hash

    print("")
    print("=" * 64)
    print("AI GUARDIAN — REVIEWER CREDENTIALS INITIALIZED")
    print("=" * 64)
    print(f"Username: {username}")
    print(
        f"Password: {generated_password}"
    )
    print("")
    print(
        "SAVE THIS PASSWORD."
    )
    print(
        "Only the password hash is stored in backend/.env."
    )
    print("=" * 64)
    print("")

    return (
        username,
        password_hash,
    )


REVIEWER_USERNAME, REVIEWER_PASSWORD_HASH = (
    _load_or_create_config()
)


def authenticate_reviewer(
    username: str,
    password: str,
) -> str | None:
    if not hmac.compare_digest(
        username,
        REVIEWER_USERNAME,
    ):
        return None

    if not verify_password(
        password,
        REVIEWER_PASSWORD_HASH,
    ):
        return None

    return create_session(
        username=username,
        role="reviewer",
    )


def create_session(
    *,
    username: str,
    role: str,
) -> str:
    token = secrets.token_urlsafe(
        32
    )

    _sessions[token] = Session(
        username=username,
        role=role,
        expires_at=(
            _now() + SESSION_TTL
        ),
    )

    return token


def get_session(
    token: str,
) -> Session | None:
    session = _sessions.get(
        token
    )

    if session is None:
        return None

    if _now() >= session.expires_at:
        _sessions.pop(
            token,
            None,
        )
        return None

    return session


def revoke_session(
    token: str,
) -> None:
    _sessions.pop(
        token,
        None,
    )


# Declares the Authorization header as an OpenAPI *security scheme*.
# Swagger UI only attaches Authorization to requests when it is declared this
# way (a plain Header(...) parameter named "authorization" is silently dropped
# by Swagger UI). Behaviour for real clients is unchanged: the full header value
# ("Bearer <token>") is passed to require_reviewer exactly as before.
_authorization_scheme = APIKeyHeader(
    name="Authorization",
    scheme_name="ReviewerBearer",
    description='Paste the full value: "Bearer <token from /dashboard/login>"',
    auto_error=False,
)


def get_authorization(
    authorization: str | None = Security(
        _authorization_scheme,
    ),
) -> str | None:
    return authorization


def require_reviewer(
    authorization: str | None = Header(
        default=None,
    ),
) -> str:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Reviewer authentication required.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    scheme, _, token = (
        authorization.partition(" ")
    )

    if (
        scheme.lower() != "bearer"
        or not token
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication header.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    session = get_session(
        token
    )

    if session is None:
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    if session.role != "reviewer":
        raise HTTPException(
            status_code=403,
            detail="Reviewer role required.",
        )

    return session.username


def extract_bearer_token(
    authorization: str | None,
) -> str | None:
    if not authorization:
        return None

    scheme, _, token = (
        authorization.partition(" ")
    )

    if (
        scheme.lower() != "bearer"
        or not token
    ):
        return None

    return token