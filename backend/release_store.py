from __future__ import annotations

import base64
import hashlib
import hmac
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any

from dashboard_store import DB_PATH, get_security_event

RELEASE_TTL_MINUTES = 20
IDLE_TIMEOUT_SECONDS = RELEASE_TTL_MINUTES * 60
MAX_HELD_ITEMS = 128
MAX_HELD_BYTES = 64 * 1024 * 1024


class PayloadUnavailableError(PermissionError):
    """The original is no longer available in this process's RAM."""


class PayloadCapacityError(RuntimeError):
    """Bounded in-memory capacity is exhausted; no disk spill is used."""


@dataclass
class _HeldPayload:
    token_hash: str
    payload_type: str
    raw_text: str | None
    raw_file: bytes | None
    original_filename: str | None
    mime_type: str | None
    last_access: float
    size: int
    consumed: bool = False


_LOCK = threading.RLock()
_PAYLOADS: dict[str, _HeldPayload] = {}
_HELD_BYTES = 0
_CLEANUP_STOP = threading.Event()
_CLEANUP_THREAD: threading.Thread | None = None


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _remove_locked(event_id: str) -> bool:
    global _HELD_BYTES
    item = _PAYLOADS.pop(event_id, None)
    if item is None:
        return False
    _HELD_BYTES = max(0, _HELD_BYTES - item.size)
    item.raw_text = None
    item.raw_file = None
    item.original_filename = None
    item.mime_type = None
    item.consumed = True
    return True


def init_release_store() -> None:
    """Remove the legacy persistent payload table, preserving audit events."""
    if DB_PATH.exists():
        try:
            with sqlite3.connect(DB_PATH, timeout=5) as db:
                db.execute("PRAGMA secure_delete=ON")
                tables = {row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
                if "held_payloads" in tables:
                    db.execute("UPDATE held_payloads SET raw_text=NULL, raw_file_base64=NULL, original_filename=NULL, mime_type=NULL")
                    db.execute("DELETE FROM held_payloads")
                    db.execute("DROP TABLE held_payloads")
                    db.commit()
                    db.execute("VACUUM")
        except sqlite3.Error:
            # Never recreate persistent payload storage; the failure is surfaced
            # only through diagnostics, without echoing database contents.
            pass
    cleanup_expired_payloads()


def create_held_payload(
    *, event_id: str, release_token: str, payload_type: str,
    raw_text: str | None = None, raw_file_base64: str | None = None,
    original_filename: str | None = None, mime_type: str | None = None,
) -> None:
    """Hold an original only in bounded process-local memory (never SQLite/disk)."""
    global _HELD_BYTES
    if payload_type not in {"text", "file"}:
        raise ValueError("Unsupported payload type.")
    if payload_type == "text":
        if raw_text is None:
            raise ValueError("raw_text is required for text payloads.")
        raw_file = None
        size = len(raw_text.encode("utf-8"))
        original_filename = None
        mime_type = None
    else:
        if raw_file_base64 is None:
            raise ValueError("raw_file_base64 is required for file payloads.")
        try:
            raw_file = base64.b64decode(raw_file_base64, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid in-memory file payload encoding.") from exc
        raw_text = None
        size = len(raw_file)

    if size > MAX_HELD_BYTES:
        raise PayloadCapacityError("Held payload exceeds the in-memory capacity limit.")

    cleanup_expired_payloads()
    with _LOCK:
        if event_id in _PAYLOADS:
            _remove_locked(event_id)
        if len(_PAYLOADS) >= MAX_HELD_ITEMS or _HELD_BYTES + size > MAX_HELD_BYTES:
            raise PayloadCapacityError("Temporary release memory is full; rescan after pending items expire.")
        _PAYLOADS[event_id] = _HeldPayload(
            token_hash=_hash_token(release_token), payload_type=payload_type,
            raw_text=raw_text, raw_file=raw_file,
            original_filename=original_filename, mime_type=mime_type,
            last_access=time.monotonic(), size=size,
        )
        _HELD_BYTES += size


def _get_authorized_item(event_id: str, release_token: str) -> _HeldPayload:
    with _LOCK:
        item = _PAYLOADS.get(event_id)
        if item is None:
            raise PayloadUnavailableError("The original payload is unavailable; submit and scan it again.")
        if not hmac.compare_digest(item.token_hash, _hash_token(release_token)):
            raise PermissionError("Invalid release credentials.")
        if time.monotonic() - item.last_access >= IDLE_TIMEOUT_SECONDS:
            _remove_locked(event_id)
            raise PayloadUnavailableError("The held payload expired; submit and scan it again.")
        # Status polling is automated background activity, not user activity;
        # it must not extend the 20-minute idle retention window.
        return item


def get_release_status(*, event_id: str, release_token: str) -> dict[str, Any]:
    item = _get_authorized_item(event_id, release_token)
    event = get_security_event(event_id)
    if event is None:
        with _LOCK:
            _remove_locked(event_id)
        raise PayloadUnavailableError("The original payload is unavailable; submit and scan it again.")
    state = event.get("state") or "PENDING"
    if state == "REJECTED":
        purge_held_payload(event_id)
    return {"event_id": event_id, "state": "APPROVED" if state == "APPROVED" else "REJECTED" if state == "REJECTED" else "PENDING" if state in {"BLOCKED", "PENDING_APPROVAL"} else state}


def consume_release(*, event_id: str, release_token: str) -> dict[str, Any]:
    global _HELD_BYTES
    # Validate the token and expiry, then serialize release/consume under one lock.
    with _LOCK:
        item = _PAYLOADS.get(event_id)
        if item is None:
            raise PayloadUnavailableError("The original payload is unavailable; submit and scan it again.")
        if not hmac.compare_digest(item.token_hash, _hash_token(release_token)):
            raise PermissionError("Invalid release credentials.")
        if item.consumed:
            raise PermissionError("Release has already been consumed.")
        if time.monotonic() - item.last_access >= IDLE_TIMEOUT_SECONDS:
            _remove_locked(event_id)
            raise PayloadUnavailableError("The held payload expired; submit and scan it again.")
        event = get_security_event(event_id)
        if event is None or event.get("state") != "APPROVED":
            raise PermissionError("Release has not been approved.")
        result = {
            "event_id": event_id, "state": "RELEASED", "payload_type": item.payload_type,
            "raw_text": item.raw_text,
            "raw_file_base64": base64.b64encode(item.raw_file).decode("ascii") if item.raw_file is not None else None,
            "original_filename": item.original_filename, "mime_type": item.mime_type,
        }
        _remove_locked(event_id)
        return result


def purge_held_payload(event_id: str) -> None:
    with _LOCK:
        _remove_locked(event_id)


def clear_held_payloads() -> int:
    """Explicitly discard every retained original from RAM."""
    with _LOCK:
        count = len(_PAYLOADS)
        for event_id in list(_PAYLOADS):
            _remove_locked(event_id)
        return count


def cleanup_expired_payloads() -> int:
    now = time.monotonic()
    with _LOCK:
        expired = [event_id for event_id, item in _PAYLOADS.items() if now - item.last_access >= IDLE_TIMEOUT_SECONDS]
        for event_id in expired:
            _remove_locked(event_id)
        return len(expired)


def memory_status() -> dict[str, int]:
    """Return aggregate counters only; never expose payload contents."""
    with _LOCK:
        return {"items": len(_PAYLOADS), "bytes": _HELD_BYTES}


def _cleanup_worker() -> None:
    while not _CLEANUP_STOP.wait(30):
        cleanup_expired_payloads()


def start_cleanup_worker() -> None:
    global _CLEANUP_THREAD
    if _CLEANUP_THREAD and _CLEANUP_THREAD.is_alive():
        return
    _CLEANUP_STOP.clear()
    _CLEANUP_THREAD = threading.Thread(target=_cleanup_worker, name="sentinel-payload-cleaner", daemon=True)
    _CLEANUP_THREAD.start()


def stop_cleanup_worker() -> None:
    _CLEANUP_STOP.set()


init_release_store()
