from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent / "guardian.db"
DECISIONS = {"ALLOW", "REDACT", "BLOCK", "INCOMPLETE"}
STATES = {
    "ALLOWED", "REDACTED", "BLOCKED", "INCOMPLETE", "PENDING_APPROVAL",
    "APPROVED", "REJECTED", "EXPIRED", "RELEASED",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db


def init_db() -> None:
    with _connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS security_events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            site TEXT NOT NULL,
            input_type TEXT NOT NULL,
            filename TEXT,
            risk TEXT NOT NULL,
            decision TEXT NOT NULL,
            state TEXT NOT NULL,
            status_detail TEXT,
            entities_json TEXT NOT NULL DEFAULT '[]',
            sha256_fingerprint TEXT,
            byte_count INTEGER,
            scan_mode TEXT,
            enforcement_mode TEXT,
            report_source TEXT,
            analysis_timestamp TEXT,
            coverage_json TEXT,
            corsair_token TEXT,
            reviewed_by TEXT,
            reviewed_at TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            detail TEXT,
            FOREIGN KEY(event_id) REFERENCES security_events(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_state ON security_events(state);
        CREATE INDEX IF NOT EXISTS idx_events_decision ON security_events(decision);
        CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_events(event_id, timestamp DESC);
        """)
        existing = {row[1] for row in db.execute("PRAGMA table_info(security_events)").fetchall()}
        additions = {
            "sha256_fingerprint": "TEXT", "byte_count": "INTEGER", "scan_mode": "TEXT", "enforcement_mode": "TEXT",
            "report_source": "TEXT", "analysis_timestamp": "TEXT", "coverage_json": "TEXT",
        }
        for column, kind in additions.items():
            if column not in existing:
                db.execute(f"ALTER TABLE security_events ADD COLUMN {column} {kind}")


def _safe_entities(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for entity in entities:
        kind = entity.get("entity_type")
        if isinstance(kind, str) and kind.strip():
            kind = kind.strip()
            detector = entity.get("detector") if isinstance(entity.get("detector"), str) else ""
            layer = entity.get("source_layer") if isinstance(entity.get("source_layer"), str) else ""
            field = entity.get("metadata_field") if isinstance(entity.get("metadata_field"), str) else ""
            key = (kind, detector, layer, field)
            item = grouped.setdefault(key, {"entity_type": kind, "count": 0, "_confidence_sum": 0.0, "_confidence_count": 0})
            item["count"] += 1
            confidence = entity.get("confidence")
            if isinstance(confidence, (int, float)):
                item["_confidence_sum"] += float(confidence)
                item["_confidence_count"] += 1
    safe = []
    for (kind, detector, layer, field), item in sorted(grouped.items()):
        result = {"entity_type": kind, "count": item["count"]}
        if detector:
            result["detector"] = detector
        if layer:
            result["source_layer"] = layer
        if field:
            result["metadata_field"] = field
        if item["_confidence_count"]:
            result["average_confidence"] = round(item["_confidence_sum"] / item["_confidence_count"], 4)
        safe.append(result)
    return safe


def _check(decision: str, state: str) -> None:
    if decision not in DECISIONS:
        raise ValueError(f"Invalid decision: {decision}")
    if state not in STATES:
        raise ValueError(f"Invalid state: {state}")


def create_security_event(
    *,
    username: str,
    site: str,
    input_type: str,
    filename: str | None,
    risk: str,
    decision: str,
    state: str,
    entities: list[dict[str, Any]] | None = None,
    status_detail: str | None = None,
    sha256_fingerprint: str | None = None,
    byte_count: int | None = None,
    scan_mode: str | None = None,
    enforcement_mode: str | None = None,
    report_source: str | None = None,
    analysis_timestamp: str | None = None,
    coverage: dict[str, Any] | None = None,
) -> str:
    _check(decision, state)
    ts = _now()
    event_id = str(uuid.uuid4())
    safe_entities = _safe_entities(entities or [])
    with _connect() as db:
        db.execute("""
            INSERT INTO security_events
            (id,timestamp,username,site,input_type,filename,risk,decision,state,status_detail,entities_json,sha256_fingerprint,byte_count,scan_mode,enforcement_mode,report_source,analysis_timestamp,coverage_json,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            event_id, ts, username or "local-user", site or "unknown", input_type,
            filename, risk, decision, state, status_detail,
            json.dumps(safe_entities, separators=(",", ":")), sha256_fingerprint,
            int(byte_count) if byte_count is not None else None, scan_mode, enforcement_mode, report_source,
            analysis_timestamp, json.dumps(coverage, separators=(",", ":")) if coverage is not None else None, ts,
        ))
        db.execute("""
            INSERT INTO audit_events(id,event_id,actor,action,timestamp,detail)
            VALUES (?,?,?,?,?,?)
        """, (str(uuid.uuid4()), event_id, username or "local-user", decision.lower(), ts, status_detail))
    return event_id


def _decode(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    try:
        result["entities"] = json.loads(result.pop("entities_json"))
    except (TypeError, json.JSONDecodeError):
        result["entities"] = []
        result.pop("entities_json", None)
    try:
        raw_coverage = result.pop("coverage_json", None)
        result["coverage"] = json.loads(raw_coverage) if raw_coverage else None
    except (TypeError, json.JSONDecodeError):
        result["coverage"] = None
        result.pop("coverage_json", None)
    return result


def list_security_events(*, limit: int = 100, state: str | None = None) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 250))
    if state is not None and state not in STATES:
        raise ValueError(f"Invalid state: {state}")
    sql = "SELECT * FROM security_events"
    params: tuple[Any, ...]
    if state is None:
        params = (limit,)
        sql += " ORDER BY timestamp DESC LIMIT ?"
    elif state == "PENDING_APPROVAL":
        params = ("BLOCKED", "PENDING_APPROVAL", limit)
        sql += " WHERE state IN (?,?) ORDER BY timestamp DESC LIMIT ?"
    else:
        params = (state, limit)
        sql += " WHERE state=? ORDER BY timestamp DESC LIMIT ?"
    with _connect() as db:
        return [_decode(row) for row in db.execute(sql, params).fetchall()]


def get_security_event(event_id: str) -> dict[str, Any] | None:
    with _connect() as db:
        row = db.execute("SELECT * FROM security_events WHERE id=?", (event_id,)).fetchone()
        if row is None:
            return None
        result = _decode(row)
        result["audit"] = [dict(item) for item in db.execute(
            "SELECT actor,action,timestamp,detail FROM audit_events WHERE event_id=? ORDER BY timestamp DESC",
            (event_id,),
        ).fetchall()]
        return result


def add_audit_event(*, event_id: str, actor: str, action: str, detail: str | None = None) -> None:
    if not actor or not action:
        raise ValueError("actor and action are required")
    with _connect() as db:
        if db.execute("SELECT 1 FROM security_events WHERE id=?", (event_id,)).fetchone() is None:
            raise ValueError("Security event does not exist")
        db.execute("""
            INSERT INTO audit_events(id,event_id,actor,action,timestamp,detail)
            VALUES (?,?,?,?,?,?)
        """, (str(uuid.uuid4()), event_id, actor, action, _now(), detail))


def update_event_state(
    *,
    event_id: str,
    new_state: str,
    actor: str,
    detail: str | None = None,
    reviewed_by: str | None = None,
    corsair_token: str | None = None,
) -> None:
    if new_state not in STATES:
        raise ValueError(f"Invalid state: {new_state}")
    with _connect() as db:
        row = db.execute("SELECT state FROM security_events WHERE id=?", (event_id,)).fetchone()
        if row is None:
            raise ValueError("Security event does not exist")
        old_state = row["state"]
        if old_state == new_state:
            raise ValueError(f"Event is already in state {new_state}")
        ts = _now()
        fields = ["state=?", "status_detail=?"]
        values: list[Any] = [new_state, detail]
        if reviewed_by is not None:
            fields += ["reviewed_by=?", "reviewed_at=?"]
            values += [reviewed_by, ts]
        if corsair_token is not None:
            fields.append("corsair_token=?")
            values.append(corsair_token)
        values.append(event_id)
        db.execute(f"UPDATE security_events SET {','.join(fields)} WHERE id=?", values)
        db.execute("""
            INSERT INTO audit_events(id,event_id,actor,action,timestamp,detail)
            VALUES (?,?,?,?,?,?)
        """, (
            str(uuid.uuid4()), event_id, actor, "state_change", ts,
            f"{old_state} -> {new_state}" + (f": {detail}" if detail else ""),
        ))


def get_event_summary() -> dict[str, int]:
    summary = {"total": 0, "allowed": 0, "redacted": 0, "blocked": 0, "incomplete": 0, "pending": 0}
    with _connect() as db:
        for row in db.execute("SELECT decision,COUNT(*) count FROM security_events GROUP BY decision").fetchall():
            count = int(row["count"])
            summary["total"] += count
            if row["decision"] == "ALLOW":
                summary["allowed"] += count
            elif row["decision"] == "REDACT":
                summary["redacted"] += count
            elif row["decision"] == "BLOCK":
                summary["blocked"] += count
            elif row["decision"] == "INCOMPLETE":
                summary["incomplete"] += count
        summary["pending"] = int(db.execute(
            "SELECT COUNT(*) count FROM security_events WHERE state IN ('BLOCKED','PENDING_APPROVAL')"
        ).fetchone()["count"])
    return summary


init_db()
