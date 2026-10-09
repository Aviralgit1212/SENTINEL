from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)
from pydantic import BaseModel

from dashboard_auth import (
    authenticate_reviewer,
    extract_bearer_token,
    get_authorization,
    require_reviewer,
    revoke_session,
)

from dashboard_store import (
    get_event_summary,
    get_security_event,
    list_security_events,
    update_event_state,
)
from release_store import purge_held_payload
from cache_store import cache_status, clear_cache

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)


class LoginRequest(BaseModel):
    username: str
    password: str


class ReviewActionRequest(BaseModel):
    detail: str | None = None


@router.post("/login")
def dashboard_login(
    request: LoginRequest,
) -> dict:
    """
    Authenticate the dashboard reviewer.
    """

    token = authenticate_reviewer(
        request.username,
        request.password,
    )

    if token is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid reviewer credentials.",
        )

    return {
        "authenticated": True,
        "username": request.username,
        "role": "reviewer",
        "token": token,
    }


@router.post("/logout")
def dashboard_logout(
    authorization: str | None = Depends(
        get_authorization,
    ),
) -> dict:
    """
    Revoke the exact reviewer session
    supplied in the Authorization header.
    """

    username = require_reviewer(
        authorization
    )

    token = extract_bearer_token(
        authorization
    )

    if token is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication header.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    revoke_session(
        token
    )

    return {
        "authenticated": False,
        "message": "Reviewer session ended.",
        "username": username,
    }


@router.get("/me")
def dashboard_me(
    authorization: str | None = Depends(
        get_authorization,
    ),
) -> dict:
    """
    Return the authenticated reviewer identity.
    """

    username = require_reviewer(
        authorization
    )

    return {
        "authenticated": True,
        "username": username,
        "role": "reviewer",
    }


@router.get("/summary")
def dashboard_summary(
    authorization: str | None = Depends(
        get_authorization,
    ),
) -> dict:
    """
    Return aggregate security-event counts.
    """

    require_reviewer(
        authorization
    )

    return get_event_summary()


@router.get("/cache/status")
def dashboard_cache_status(
    authorization: str | None = Depends(get_authorization),
) -> dict:
    require_reviewer(authorization)
    return cache_status()


@router.delete("/cache")
def dashboard_clear_cache(
    authorization: str | None = Depends(get_authorization),
) -> dict:
    require_reviewer(authorization)
    return {"cleared": clear_cache(), "audit_history_preserved": True}


@router.get("/events")
def dashboard_events(
    limit: int = Query(
        default=100,
        ge=1,
        le=250,
    ),
    state: str | None = Query(
        default=None,
    ),
    authorization: str | None = Depends(
        get_authorization,
    ),
) -> list[dict]:
    """
    Return recent security events.

    Optional state filter supports the
    dashboard Pending view.
    """

    require_reviewer(
        authorization
    )

    try:
        return list_security_events(
            limit=limit,
            state=state,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@router.get("/events/{event_id}")
def dashboard_event(
    event_id: str,
    authorization: str | None = Depends(
        get_authorization,
    ),
) -> dict:
    """
    Return one event with audit history.
    """

    require_reviewer(
        authorization
    )

    event = get_security_event(
        event_id
    )

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Security event not found.",
        )

    return event


def _review_event(
    *,
    event_id: str,
    new_state: str,
    reviewer: str,
    detail: str | None,
) -> dict:
    """
    Apply one explicit reviewer decision.

    Guardian remains authoritative over the
    event state machine. Dashboard actions only
    request the approved state transition.
    """

    event = get_security_event(
        event_id
    )

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Security event not found.",
        )

    current_state = event.get(
        "state"
    )

    if current_state not in {
        "BLOCKED",
        "PENDING_APPROVAL",
    }:
        raise HTTPException(
            status_code=409,
            detail=(
                "This event cannot be reviewed "
                f"from state {current_state}."
            ),
        )

    event_owner = event.get(
        "username"
    )

    if (
        event_owner
        and event_owner == reviewer
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "A reviewer cannot approve or "
                "reject their own event."
            ),
        )

    action_detail = detail

    if not action_detail:
        if new_state == "APPROVED":
            action_detail = (
                "Approved for this specific event."
            )
        else:
            action_detail = (
                "Rejected for this specific event."
            )

    try:
        update_event_state(
            event_id=event_id,
            new_state=new_state,
            actor=reviewer,
            reviewed_by=reviewer,
            detail=action_detail,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    updated_event = get_security_event(
        event_id
    )

    if updated_event is None:
        raise HTTPException(
            status_code=500,
            detail=(
                "Event disappeared after "
                "state transition."
            ),
        )

    return updated_event


@router.post(
    "/events/{event_id}/approve"
)
def approve_event(
    event_id: str,
    request: ReviewActionRequest | None = None,
    authorization: str | None = Depends(
        get_authorization,
    ),
) -> dict:
    """
    Approve one blocked/pending event.
    """

    reviewer = require_reviewer(
        authorization
    )

    detail = (
        request.detail
        if request is not None
        else None
    )

    return _review_event(
        event_id=event_id,
        new_state="APPROVED",
        reviewer=reviewer,
        detail=detail,
    )


@router.post(
    "/events/{event_id}/reject"
)
def reject_event(
    event_id: str,
    request: ReviewActionRequest | None = None,
    authorization: str | None = Depends(
        get_authorization,
    ),
) -> dict:
    """
    Reject one blocked/pending event.
    """

    reviewer = require_reviewer(
        authorization
    )

    detail = (
        request.detail
        if request is not None
        else None
    )

    result=_review_event(
        event_id=event_id,
        new_state="REJECTED",
        reviewer=reviewer,
        detail=detail,
    )

    purge_held_payload(event_id)

    return result