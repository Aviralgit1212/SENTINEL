from __future__ import annotations

import hashlib
import hmac
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from dashboard_store import _connect

# --- TTLs -------------------------------------------------------------------
OFFER_TTL = timedelta(minutes=20)      # time to ask for the override after the scan
REQUEST_TTL = timedelta(minutes=20)    # time for a reviewer to answer the request
APPROVAL_TTL = timedelta(minutes=5)    # time to consume an approval

_AUTH_MESSAGE = "Invalid override credentials."
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_REASON_MAX = 300

# override row status -> event state (security_events.state)
_EVENT_STATE = {
    "PENDING": "OVERRIDE_PENDING",
    "APPROVED": "OVERRIDE_APPROVED",
    "REJECTED": "OVERRIDE_REJECTED",
    "RELEASED": "OVERRIDE_RELEASED",
    "EXPIRED": "OVERRIDE_EXPIRED",
    "CANCELLED": "OVERRIDE_CANCELLED",
}


# --- Exceptions -------------------------------------------------------------
class OverrideError(Exception):
    """Base class for override errors."""


class OverrideAuthError(OverrideError):
    """401: unknown event or wrong token (indistinguishable)."""


class OverrideMismatchError(OverrideError):
    """403: file fingerprint mismatch."""


class OverrideStateError(OverrideError):
    """409: wrong state or replay."""


class OverrideExpiredError(OverrideError):
    """410: override expired."""


class OverrideNotFoundError(OverrideError):
    """404: reviewer side, no reviewable override request."""


class OverrideForbiddenError(OverrideError):
    """403: reviewer side, self-review is not allowed."""


# --- Helpers ----------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat()


def _parse(value: Any) -> datetime:
    """Parse a stored timestamp. Anything unparsable counts as long past (fail closed)."""
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _token_hash(token: Any) -> str | None:
    if not isinstance(token, str) or not token:
        return None
    try:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
    except UnicodeError:
        return None


def _same(a: Any, b: Any) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except (TypeError, ValueError):
        return False


def _prefix(sha256: Any) -> str:
    return str(sha256)[:12] if sha256 else ""


@contextmanager
def _tx() -> Iterator[sqlite3.Connection]:
    """One BEGIN IMMEDIATE transaction: COMMIT on success, ROLLBACK on any exception."""
    db = _connect()
    try:
        db.isolation_level = None
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
            db.execute("COMMIT")
        except BaseException:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
    finally:
        db.close()


def _audit(db: sqlite3.Connection, event_id: str, actor: str, action: str,
           detail: str | None, ts: str) -> None:
    db.execute(
        "INSERT INTO audit_events(id,event_id,actor,action,timestamp,detail) VALUES (?,?,?,?,?,?)",
        (str(uuid.uuid4()), event_id, actor, action, ts, detail),
    )


def _set_event_state(db: sqlite3.Connection, event_id: str, state: str, ts: str,
                     reviewer: str | None = None) -> None:
    """Only touches state (and reviewed_by/reviewed_at on review). Never decision/status_detail."""
    if reviewer is not None:
        db.execute(
            "UPDATE security_events SET state=?, reviewed_by=?, reviewed_at=? WHERE id=?",
            (state, reviewer, ts, event_id),
        )
    else:
        db.execute("UPDATE security_events SET state=? WHERE id=?", (state, event_id))


def _expire_locked(db: sqlite3.Connection, now: datetime) -> int:
    """Mark overdue rows EXPIRED. Must run inside an open transaction."""
    ts = _iso(now)
    rows = db.execute(
        "SELECT event_id, status, expires_at, approval_expires_at, sha256 "
        "FROM redaction_overrides WHERE status IN ('OFFERED','PENDING','APPROVED')"
    ).fetchall()
    count = 0
    for row in rows:
        status = row["status"]
        deadline = _parse(row["approval_expires_at"] if status == "APPROVED" else row["expires_at"])
        if now < deadline:
            continue
        cur = db.execute(
            "UPDATE redaction_overrides SET status='EXPIRED' WHERE event_id=? AND status=?",
            (row["event_id"], status),
        )
        if cur.rowcount != 1:
            continue
        count += 1
        if status in ("PENDING", "APPROVED"):
            _set_event_state(db, row["event_id"], _EVENT_STATE["EXPIRED"], ts)
            _audit(db, row["event_id"], "system", "override_expired",
                   f"{status} override expired; fingerprint {_prefix(row['sha256'])}", ts)
    return count


def _load(db: sqlite3.Connection, event_id: Any, token: Any):
    """Return (event_row, override_row) or None. Unknown event and wrong token look identical."""
    supplied = _token_hash(token)
    if not isinstance(event_id, str) or supplied is None:
        return None
    event = db.execute(
        "SELECT id, username, decision, state FROM security_events WHERE id=?", (event_id,)
    ).fetchone()
    row = db.execute(
        "SELECT * FROM redaction_overrides WHERE event_id=?", (event_id,)
    ).fetchone()
    if event is None or row is None:
        return None
    if not _same(supplied, row["token_hash"]):
        return None
    return event, row


def normalize_sha256(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid sha256.")
    normalized = value.strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise ValueError("Invalid sha256.")
    return normalized


# --- Public API -------------------------------------------------------------
def offer_override(event_id: str, token: str, sha256: str) -> None:
    sha256 = normalize_sha256(sha256)
    token_hash = _token_hash(token)
    if token_hash is None or not isinstance(event_id, str) or not event_id:
        raise ValueError("Invalid override offer.")
    with _tx() as db:
        now = _now()
        _expire_locked(db, now)
        event = db.execute(
            "SELECT decision, state FROM security_events WHERE id=?", (event_id,)
        ).fetchone()
        if event is None or event["decision"] != "REDACT" or event["state"] != "REDACTED":
            raise ValueError("Override can only be offered for a REDACTED file.")
        if db.execute(
            "SELECT 1 FROM redaction_overrides WHERE event_id=?", (event_id,)
        ).fetchone() is not None:
            raise ValueError("Override already offered for this event.")
        db.execute(
            "INSERT INTO redaction_overrides(event_id,token_hash,sha256,status,offered_at,expires_at) "
            "VALUES (?,?,?,?,?,?)",
            (event_id, token_hash, sha256, "OFFERED", _iso(now), _iso(now + OFFER_TTL)),
        )


def request_override(event_id: str, token: str, sha256: str, risk_acknowledged: bool) -> dict[str, Any]:
    sha256 = normalize_sha256(sha256)
    error: Exception | None = None
    result: dict[str, Any] | None = None
    with _tx() as db:
        now = _now()
        ts = _iso(now)
        _expire_locked(db, now)
        loaded = _load(db, event_id, token)
        if loaded is None:
            error = OverrideAuthError(_AUTH_MESSAGE)
        else:
            event, row = loaded
            if row["status"] == "EXPIRED":
                error = OverrideExpiredError("Override expired.")
            elif (row["status"] != "OFFERED" or event["decision"] != "REDACT"
                  or event["state"] != "REDACTED"):
                error = OverrideStateError("Override cannot be requested in this state.")
            elif not _same(sha256, row["sha256"]):
                _audit(db, event_id, "extension", "override_denied",
                       f"fingerprint mismatch at request; stored {_prefix(row['sha256'])}, "
                       f"presented {_prefix(sha256)}", ts)
                error = OverrideMismatchError("Fingerprint mismatch.")
            elif risk_acknowledged is not True:
                error = ValueError("Risk acknowledgement is required.")
            else:
                expires_at = _iso(now + REQUEST_TTL)
                cur = db.execute(
                    "UPDATE redaction_overrides SET status='PENDING', requested_at=?, expires_at=?, "
                    "risk_acknowledged_at=? WHERE event_id=? AND status='OFFERED'",
                    (ts, expires_at, ts, event_id),
                )
                if cur.rowcount != 1:
                    error = OverrideStateError("Override cannot be requested in this state.")
                else:
                    _set_event_state(db, event_id, _EVENT_STATE["PENDING"], ts)
                    _audit(db, event_id, "extension", "override_requested",
                           f"fingerprint {_prefix(row['sha256'])}; risk acknowledged", ts)
                    result = {"event_id": event_id, "state": "PENDING", "expires_at": expires_at}
    if error is not None:
        raise error
    assert result is not None
    return result


def get_override_status(event_id: str, token: str) -> dict[str, Any]:
    error: Exception | None = None
    result: dict[str, Any] | None = None
    with _tx() as db:
        _expire_locked(db, _now())
        loaded = _load(db, event_id, token)
        if loaded is None:
            error = OverrideAuthError(_AUTH_MESSAGE)
        else:
            _event, row = loaded
            state = "AVAILABLE" if row["status"] == "OFFERED" else row["status"]
            result = {"event_id": event_id, "state": state, "expires_at": row["expires_at"]}
            if row["status"] == "APPROVED":
                result["approval_expires_at"] = row["approval_expires_at"]
                result["reviewed_by"] = row["reviewed_by"]
    if error is not None:
        raise error
    assert result is not None
    return result


def consume_override(event_id: str, token: str, sha256: str) -> dict[str, Any]:
    sha256 = normalize_sha256(sha256)
    error: Exception | None = None
    result: dict[str, Any] | None = None
    with _tx() as db:
        now = _now()
        ts = _iso(now)
        _expire_locked(db, now)
        loaded = _load(db, event_id, token)
        if loaded is None:
            error = OverrideAuthError(_AUTH_MESSAGE)
        else:
            event, row = loaded
            if row["status"] == "EXPIRED":
                error = OverrideExpiredError("Override expired.")
            elif (row["status"] != "APPROVED" or row["consumed_at"] is not None
                  or event["decision"] != "REDACT" or event["state"] != "OVERRIDE_APPROVED"):
                # includes RELEASED (replay) and every other non-approved status
                error = OverrideStateError("Override cannot be released in this state.")
            elif not _same(sha256, row["sha256"]):
                # mismatch is audited but the approval is NOT consumed
                _audit(db, event_id, "extension", "override_denied",
                       f"fingerprint mismatch at release; stored {_prefix(row['sha256'])}, "
                       f"presented {_prefix(sha256)}", ts)
                error = OverrideMismatchError("Fingerprint mismatch.")
            else:
                cur = db.execute(
                    "UPDATE redaction_overrides SET status='RELEASED', consumed_at=? "
                    "WHERE event_id=? AND status='APPROVED' AND consumed_at IS NULL",
                    (ts, event_id),
                )
                if cur.rowcount != 1:
                    error = OverrideStateError("Override cannot be released in this state.")
                else:
                    _set_event_state(db, event_id, _EVENT_STATE["RELEASED"], ts)
                    _audit(db, event_id, "extension", "override_released",
                           f"approved by {row['reviewed_by']}; fingerprint {_prefix(row['sha256'])}", ts)
                    result = {"event_id": event_id, "state": "RELEASED",
                              "reviewed_by": row["reviewed_by"]}
    if error is not None:
        raise error
    assert result is not None
    return result


def cancel_override(event_id: str, token: str) -> dict[str, Any]:
    error: Exception | None = None
    result: dict[str, Any] | None = None
    with _tx() as db:
        now = _now()
        ts = _iso(now)
        _expire_locked(db, now)
        loaded = _load(db, event_id, token)
        if loaded is None:
            error = OverrideAuthError(_AUTH_MESSAGE)
        else:
            _event, row = loaded
            status = row["status"]
            if status == "EXPIRED":
                error = OverrideExpiredError("Override expired.")
            elif status not in ("OFFERED", "PENDING", "APPROVED"):
                error = OverrideStateError("Override cannot be cancelled in this state.")
            else:
                cur = db.execute(
                    "UPDATE redaction_overrides SET status='CANCELLED' WHERE event_id=? AND status=?",
                    (event_id, status),
                )
                if cur.rowcount != 1:
                    error = OverrideStateError("Override cannot be cancelled in this state.")
                else:
                    # An OFFERED override was never requested, so (like OFFERED expiry)
                    # it leaves the event state and audit trail untouched.
                    if status in ("PENDING", "APPROVED"):
                        _set_event_state(db, event_id, _EVENT_STATE["CANCELLED"], ts)
                        _audit(db, event_id, "extension", "override_cancelled",
                               f"cancelled from {status}; fingerprint {_prefix(row['sha256'])}", ts)
                    result = {"event_id": event_id, "state": "CANCELLED"}
    if error is not None:
        raise error
    assert result is not None
    return result


def review_override(*, event_id: str, approve: bool, reviewer: str, reason: str) -> None:
    if not isinstance(reason, str):
        raise ValueError("A reason is required.")
    reason = reason.strip()
    if not reason or len(reason) > _REASON_MAX:
        raise ValueError(f"Reason must be between 1 and {_REASON_MAX} characters.")
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise ValueError("A reviewer is required.")
    error: Exception | None = None
    with _tx() as db:
        now = _now()
        ts = _iso(now)
        _expire_locked(db, now)
        event = db.execute(
            "SELECT id, username, decision, state FROM security_events WHERE id=?", (event_id,)
        ).fetchone() if isinstance(event_id, str) else None
        row = db.execute(
            "SELECT * FROM redaction_overrides WHERE event_id=?", (event_id,)
        ).fetchone() if event is not None else None
        if event is None or row is None or row["status"] == "OFFERED":
            error = OverrideNotFoundError("Override request not found.")
        elif row["status"] == "EXPIRED":
            error = OverrideExpiredError("Override request expired.")
        elif (row["status"] != "PENDING" or event["decision"] != "REDACT"
              or event["state"] != "OVERRIDE_PENDING"):
            error = OverrideStateError("Override cannot be reviewed in this state.")
        elif event["username"] == reviewer:
            error = OverrideForbiddenError("A reviewer cannot review their own event.")
        else:
            if approve:
                new_status, action = "APPROVED", "override_approved"
                approval_expires_at = _iso(now + APPROVAL_TTL)
            else:
                new_status, action = "REJECTED", "override_rejected"
                approval_expires_at = None
            cur = db.execute(
                "UPDATE redaction_overrides SET status=?, reviewed_by=?, review_reason=?, "
                "reviewed_at=?, approval_expires_at=? WHERE event_id=? AND status='PENDING'",
                (new_status, reviewer, reason, ts, approval_expires_at, event_id),
            )
            if cur.rowcount != 1:
                error = OverrideStateError("Override cannot be reviewed in this state.")
            else:
                _set_event_state(db, event_id, _EVENT_STATE[new_status], ts, reviewer=reviewer)
                _audit(db, event_id, reviewer, action,
                       f"reason: {reason}; fingerprint {_prefix(row['sha256'])}", ts)
    if error is not None:
        raise error


def expire_overrides() -> int:
    with _tx() as db:
        return _expire_locked(db, _now())


def get_override_info(event_id: str) -> dict[str, Any] | None:
    with _tx() as db:
        _expire_locked(db, _now())
        row = db.execute(
            "SELECT * FROM redaction_overrides WHERE event_id=?", (event_id,)
        ).fetchone() if isinstance(event_id, str) else None
        if row is None or row["requested_at"] is None:
            return None  # never requested
        return {
            "status": row["status"],
            "requested_at": row["requested_at"],
            "expires_at": row["expires_at"],
            "approval_expires_at": row["approval_expires_at"],
            "risk_acknowledged_at": row["risk_acknowledged_at"],
            "reviewed_by": row["reviewed_by"],
            "review_reason": row["review_reason"],
            "reviewed_at": row["reviewed_at"],
            "consumed_at": row["consumed_at"],
            "fingerprint_prefix": _prefix(row["sha256"]),
        }