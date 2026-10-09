from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
)
from pydantic import BaseModel

from dashboard_auth import (
    authenticate_reviewer,
    extract_bearer_token,
    require_reviewer,
    revoke_session,
)

from dashboard_store import (
    get_event_summary,
    get_security_event,
    list_security_events,
)


router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)


class LoginRequest(BaseModel):
    username: str
    password: str


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
    username: str = Depends(
        require_reviewer
    ),
    authorization: str | None = Header(
        default=None,
    ),
) -> dict:
    """
    Revoke the current reviewer session.
    """

    token = extract_bearer_token(
        authorization
    )

    if token:
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
    username: str = Depends(
        require_reviewer
    ),
) -> dict:
    """
    Return the authenticated reviewer identity.
    """

    return {
        "authenticated": True,
        "username": username,
        "role": "reviewer",
    }


@router.get("/summary")
def dashboard_summary(
    _: str = Depends(
        require_reviewer
    ),
) -> dict:
    """
    Return aggregate security-event counts.
    """

    return get_event_summary()


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
    _: str = Depends(
        require_reviewer
    ),
) -> list[dict]:
    """
    Return recent security events.

    Optional state filter supports the
    Dashboard Pending view.
    """

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
    _: str = Depends(
        require_reviewer
    ),
) -> dict:
    """
    Return one event with audit history.
    """

    event = get_security_event(
        event_id
    )

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Security event not found.",
        )

    return event