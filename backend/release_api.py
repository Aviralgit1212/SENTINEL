from __future__ import annotations

import ipaddress

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
)
from pydantic import BaseModel
from dashboard_auth import get_authorization, require_reviewer

from release_store import (
    PayloadUnavailableError,
    clear_held_payloads,
    consume_release,
    get_release_status,
)
from override_store import (
    request_override,
    get_override_status,
    consume_override,
    cancel_override,
    normalize_sha256,
    OverrideAuthError,
    OverrideMismatchError,
    OverrideStateError,
    OverrideExpiredError,
    OverrideError,
)


router = APIRouter(
    prefix="/release",
    tags=["release"],
)


class OverrideRequestBody(BaseModel):
    sha256: str
    risk_acknowledged: bool


class OverrideConsumeBody(BaseModel):
    sha256: str


def _require_localhost(
    request: Request,
) -> None:
    """
    Release operations are intentionally restricted
    to the local machine.

    The browser extension and backend communicate
    through 127.0.0.1.
    """

    client = request.client

    if client is None:
        raise HTTPException(
            status_code=403,
            detail="Local access required.",
        )

    try:
        address = ipaddress.ip_address(
            client.host
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=403,
            detail="Local access required.",
        ) from exc

    if not address.is_loopback:
        raise HTTPException(
            status_code=403,
            detail="Local access required.",
        )


def _get_release_token(
    request: Request,
) -> str:
    token = request.headers.get(
        "X-Guardian-Release-Token"
    )

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Release credentials required.",
        )

    return token


def _get_override_token(
    request: Request,
) -> str:
    token = request.headers.get(
        "X-Sentinel-Override-Token"
    )

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Override credentials required.",
        )

    return token


def _raise_override_http(
    exc: Exception,
) -> None:
    """
    Map override_store errors to HTTP errors.

    Detail strings are intentionally generic: they never reveal
    whether the event or the token was the wrong part, and never
    echo any value supplied by the caller.
    Anything unrecognised fails closed with a generic 400.
    """

    if isinstance(exc, OverrideAuthError):
        raise HTTPException(
            status_code=401,
            detail="Invalid override credentials.",
        ) from exc

    if isinstance(exc, OverrideMismatchError):
        raise HTTPException(
            status_code=403,
            detail="Override not permitted.",
        ) from exc

    if isinstance(exc, OverrideExpiredError):
        raise HTTPException(
            status_code=410,
            detail="Override is no longer available.",
        ) from exc

    if isinstance(exc, OverrideStateError):
        raise HTTPException(
            status_code=409,
            detail="Override not available in the current state.",
        ) from exc

    if isinstance(exc, (ValueError, OverrideError)):
        raise HTTPException(
            status_code=400,
            detail="Invalid override request.",
        ) from exc

    raise HTTPException(
        status_code=400,
        detail="Invalid override request.",
    ) from exc


@router.get(
    "/{event_id}/status"
)
def release_status(
    event_id: str,
    request: Request,
):
    """
    Return the reviewer approval state for one
    specific blocked event.

    The event-specific release token is required.
    """

    _require_localhost(
        request
    )

    release_token = _get_release_token(
        request
    )

    try:
        return get_release_status(
            event_id=event_id,
            release_token=release_token,
        )

    except PayloadUnavailableError as exc:
        raise HTTPException(
            status_code=410,
            detail="The original is no longer available in memory; submit and scan it again.",
        ) from exc

    except PermissionError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid release credentials.",
        ) from exc


# NOTE: static routes such as "/clear" must be registered BEFORE the dynamic
# "/{event_id}" route, otherwise FastAPI treats "clear" as an event id.
@router.post("/clear")
def clear_temporary_payloads(
    request: Request,
    authorization: str | None = Depends(get_authorization),
):
    """Manually discard every blocked original currently held in RAM."""
    _require_localhost(request)
    require_reviewer(authorization)
    return {"cleared": clear_held_payloads(), "storage": "process-memory"}


# Redaction-override routes. Like "/clear", these are registered BEFORE the
# dynamic "/{event_id}" route.
@router.post("/override/{event_id}/request")
def override_request(
    event_id: str,
    body: OverrideRequestBody,
    request: Request,
):
    """
    Ask a reviewer to approve releasing the ORIGINAL of a REDACTED file.

    The override token is required and the file fingerprint must match.
    """

    _require_localhost(request)

    override_token = _get_override_token(request)

    try:
        sha256 = normalize_sha256(body.sha256)
        return request_override(
            event_id,
            override_token,
            sha256,
            body.risk_acknowledged,
        )

    except (OverrideError, ValueError) as exc:
        _raise_override_http(exc)


@router.get("/override/{event_id}/status")
def override_status(
    event_id: str,
    request: Request,
):
    """Return the override state for one event (override token required)."""

    _require_localhost(request)

    override_token = _get_override_token(request)

    try:
        return get_override_status(
            event_id,
            override_token,
        )

    except (OverrideError, ValueError) as exc:
        _raise_override_http(exc)


@router.post("/override/{event_id}/consume")
def override_consume(
    event_id: str,
    body: OverrideConsumeBody,
    request: Request,
):
    """
    Consume a reviewer-approved override (single use).

    This endpoint only authorizes the release.
    It does NOT return the original file.
    """

    _require_localhost(request)

    override_token = _get_override_token(request)

    try:
        sha256 = normalize_sha256(body.sha256)
        return consume_override(
            event_id,
            override_token,
            sha256,
        )

    except (OverrideError, ValueError) as exc:
        _raise_override_http(exc)


@router.post("/override/{event_id}/cancel")
def override_cancel(
    event_id: str,
    request: Request,
):
    """Cancel a pending or offered override (override token required)."""

    _require_localhost(request)

    override_token = _get_override_token(request)

    try:
        return cancel_override(
            event_id,
            override_token,
        )

    except (OverrideError, ValueError) as exc:
        _raise_override_http(exc)


@router.post(
    "/{event_id}"
)
def release_event(
    event_id: str,
    request: Request,
):
    """
    Consume a reviewer-approved release.

    This endpoint only authorizes the release.
    It does NOT return the original sensitive payload.

    The extension already retains the original content
    and will re-submit/re-inject it only after approval.
    """

    _require_localhost(
        request
    )

    release_token = _get_release_token(
        request
    )

    try:
        result = consume_release(
            event_id=event_id,
            release_token=release_token,
        )

    except PayloadUnavailableError as exc:
        raise HTTPException(
            status_code=410,
            detail="The original is no longer available in memory; submit and scan it again.",
        ) from exc

    except PermissionError as exc:
        raise HTTPException(
            status_code=401,
            detail="Release not authorized.",
        ) from exc

    return {
        "event_id": result[
            "event_id"
        ],
        "state": result[
            "state"
        ],
    }