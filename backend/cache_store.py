from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CACHE_DB_PATH = Path(__file__).resolve().parent / "privacy_cache.db"
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
PIPELINE_INPUTS = (
    Path(__file__).resolve().parent / "main.py",
    Path(__file__).resolve().parent / "scanner" / "scanner.py",
    Path(__file__).resolve().parent / "policy" / "policy.py",
    Path(__file__).resolve().parent / "policy" / "policy.json",
    Path(__file__).resolve().parent / "risk" / "risk.py",
    Path(__file__).resolve().parent / "decision" / "decision.py",
    Path(__file__).resolve().parent / "extraction" / "extraction.py",
    Path(__file__).resolve().parent / "extraction" / "image_ocr.py",
    Path(__file__).resolve().parent / "redact" / "pdf_redact.py",
    Path(__file__).resolve().parent / "redact" / "docx_redact.py",
    Path(__file__).resolve().parent / "redact" / "image_redact.py",
)


def pipeline_version() -> str:
    digest = hashlib.sha256()
    for path in PIPELINE_INPUTS:
        digest.update(path.name.encode("utf-8"))
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"missing")
    return digest.hexdigest()


def _connect() -> sqlite3.Connection:
    db = sqlite3.connect(CACHE_DB_PATH, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    return db


def init_cache() -> None:
    with _connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS cached_reports (
                fingerprint TEXT PRIMARY KEY,
                file_type TEXT NOT NULL,
                byte_count INTEGER NOT NULL,
                pipeline_version TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                expires_at REAL NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_cache_expiry ON cached_reports(expires_at)")
        db.execute("DELETE FROM cached_reports WHERE expires_at <= ?", (time.time(),))


def sha256_fingerprint(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def get_cached_report(fingerprint: str) -> dict[str, Any] | None:
    if len(fingerprint) != 64 or any(ch not in "0123456789abcdef" for ch in fingerprint):
        return None
    now = time.time()
    version = pipeline_version()
    with _connect() as db:
        db.execute("DELETE FROM cached_reports WHERE expires_at <= ?", (now,))
        row = db.execute("SELECT * FROM cached_reports WHERE fingerprint=?", (fingerprint,)).fetchone()
    if row is None:
        return None
    if row["pipeline_version"] != version:
        # Stale reports cannot be offered as reusable results.
        with _connect() as db:
            db.execute("DELETE FROM cached_reports WHERE fingerprint=?", (fingerprint,))
        return None
    try:
        report = json.loads(row["report_json"])
    except (json.JSONDecodeError, TypeError):
        with _connect() as db:
            db.execute("DELETE FROM cached_reports WHERE fingerprint=?", (fingerprint,))
        return None
    return {
        "fingerprint": row["fingerprint"], "file_type": row["file_type"],
        "byte_count": int(row["byte_count"]), "pipeline_version": row["pipeline_version"],
        "analyzed_at": row["analyzed_at"], "expires_at": float(row["expires_at"]),
        "report": report,
    }


def put_cached_report(*, fingerprint: str, file_type: str, byte_count: int, report: dict[str, Any]) -> str:
    if len(fingerprint) != 64 or any(ch not in "0123456789abcdef" for ch in fingerprint):
        raise ValueError("Invalid SHA-256 fingerprint.")
    # Reject accidental payload fields at the cache boundary.
    forbidden = {"text", "raw_text", "raw_file", "raw_file_base64", "redacted_file_base64", "bytes", "data"}
    if forbidden.intersection(report):
        raise ValueError("Raw payload fields are not allowed in privacy-cache reports.")
    now = time.time()
    analyzed_at = datetime.fromtimestamp(now, timezone.utc).isoformat()
    with _connect() as db:
        db.execute("""
            INSERT INTO cached_reports(fingerprint,file_type,byte_count,pipeline_version,analyzed_at,expires_at,report_json)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                file_type=excluded.file_type,
                byte_count=excluded.byte_count,
                pipeline_version=excluded.pipeline_version,
                analyzed_at=excluded.analyzed_at,
                expires_at=excluded.expires_at,
                report_json=excluded.report_json
        """, (
            fingerprint, file_type.upper(), int(byte_count), pipeline_version(), analyzed_at,
            now + CACHE_TTL_SECONDS, json.dumps(report, separators=(",", ":"), ensure_ascii=False),
        ))
    return analyzed_at


def clear_cache() -> int:
    with _connect() as db:
        cursor = db.execute("DELETE FROM cached_reports")
        cleared = int(cursor.rowcount)
    with _connect() as db:
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return cleared


def cache_status() -> dict[str, Any]:
    with _connect() as db:
        db.execute("DELETE FROM cached_reports WHERE expires_at <= ?", (time.time(),))
        row = db.execute("SELECT COUNT(*) AS items, COALESCE(SUM(byte_count),0) AS source_bytes FROM cached_reports").fetchone()
    return {"items": int(row["items"]), "source_bytes_not_stored": int(row["source_bytes"]), "ttl_seconds": CACHE_TTL_SECONDS}


init_cache()
