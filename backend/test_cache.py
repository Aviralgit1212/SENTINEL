from __future__ import annotations

import io
import sqlite3
import time

import fitz
import pytest
from fastapi.testclient import TestClient

import cache_store
import dashboard_store
import main


@pytest.fixture
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_store, "CACHE_DB_PATH", tmp_path / "privacy-cache.db")
    cache_store.init_cache()
    yield
    cache_store.clear_cache()


def _pdf(text: str = "Synthetic cache test document") -> bytes:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), text)
    content = document.tobytes()
    document.close()
    return content


def _report(decision="ALLOW", risk="LOW"):
    return {
        "decision": decision,
        "risk": risk,
        "entities": [{"entity_type": "EMAIL_ADDRESS", "count": 1, "detector": "presidio"}] if decision == "REDACT" else [],
        "coverage": {"format": "PDF", "complete": True, "layers_inspected": ["selectable_text"]},
        "status_detail": None,
    }


def test_cache_is_sha256_keyed_and_expires_after_seven_days(isolated_cache, monkeypatch):
    content = b"synthetic file bytes"
    fingerprint = cache_store.sha256_fingerprint(content)
    analyzed_at = cache_store.put_cached_report(
        fingerprint=fingerprint, file_type="pdf", byte_count=len(content), report=_report()
    )
    cached = cache_store.get_cached_report(fingerprint)
    assert cached is not None
    assert cached["report"]["decision"] == "ALLOW"
    assert cached["analyzed_at"] == analyzed_at
    assert cached["expires_at"] - time.time() <= cache_store.CACHE_TTL_SECONDS
    assert cache_store.get_cached_report(cache_store.sha256_fingerprint(b"different bytes")) is None

    with sqlite3.connect(cache_store.CACHE_DB_PATH) as db:
        db.execute("UPDATE cached_reports SET expires_at=? WHERE fingerprint=?", (time.time() - 1, fingerprint))
    assert cache_store.get_cached_report(fingerprint) is None


def test_cache_rejects_incompatible_pipeline_version(isolated_cache, monkeypatch):
    content = b"synthetic versioned file"
    fingerprint = cache_store.sha256_fingerprint(content)
    cache_store.put_cached_report(fingerprint=fingerprint, file_type="pdf", byte_count=len(content), report=_report())
    monkeypatch.setattr(cache_store, "pipeline_version", lambda: "different-pipeline-version")
    assert cache_store.get_cached_report(fingerprint) is None


def test_cache_rejects_raw_payload_fields(isolated_cache):
    with pytest.raises(ValueError):
        cache_store.put_cached_report(
            fingerprint=cache_store.sha256_fingerprint(b"synthetic"),
            file_type="pdf", byte_count=9,
            report={**_report(), "raw_text": "synthetic private text"},
        )


def test_cache_clear_does_not_delete_audit_history(isolated_cache):
    event_id = dashboard_store.create_security_event(
        username="test", site="localhost", input_type="TEXT", filename=None,
        risk="LOW", decision="ALLOW", state="ALLOWED", entities=[],
    )
    fingerprint = cache_store.sha256_fingerprint(b"synthetic cached data")
    cache_store.put_cached_report(fingerprint=fingerprint, file_type="pdf", byte_count=20, report=_report())
    assert cache_store.clear_cache() == 1
    assert cache_store.get_cached_report(fingerprint) is None
    assert dashboard_store.get_security_event(event_id) is not None


def test_file_scan_requires_explicit_cache_choice_and_rescan_replaces_report(isolated_cache, monkeypatch):
    calls = []

    def fake_scan(_text):
        calls.append(True)
        decision = "ALLOW" if len(calls) == 1 else "BLOCK"
        return {"entities": [], "risk": "LOW" if decision == "ALLOW" else "HIGH", "decision": decision, "redacted_text": None}

    monkeypatch.setattr(main, "run_security_pipeline", fake_scan)
    client = TestClient(main.app)
    content = _pdf("Synthetic cache integration file A")
    files = {"file": ("synthetic-a.pdf", content, "application/pdf")}
    extension_headers = {"Origin": "chrome-extension://abcdefghijklmnopabcdefghijklmnop"}

    first = client.post("/scan-file", files=files, headers=extension_headers)
    assert first.status_code == 200
    first_payload = first.json()
    assert first_payload["decision"] == "ALLOW"
    assert first_payload["scan_mode"] == "extension_enforced"
    assert first_payload["enforcement_mode"] == "ENFORCED"
    assert first_payload["cache_hit"] is False

    offer = client.post("/scan-file", files=files, headers=extension_headers)
    assert offer.status_code == 200
    assert offer.json()["decision"] == "CACHE_CHOICE_REQUIRED"
    assert offer.json()["cache_offer"]["reuse_allowed"] is True
    assert len(calls) == 1

    reused = client.post("/scan-file", files=files, headers={**extension_headers, "X-Sentinel-Cache-Choice": "reuse"})
    assert reused.status_code == 200
    reused_payload = reused.json()
    assert reused_payload["cache_hit"] is True
    assert reused_payload["report_source"] == "cache"
    assert reused_payload["original_analysis_timestamp"] == first_payload["analysis_timestamp"]
    event = dashboard_store.get_security_event(reused_payload["event_id"])
    assert event["sha256_fingerprint"] == first_payload["sha256"]
    assert event["scan_mode"] == "extension_enforced"
    assert event["enforcement_mode"] == "ENFORCED"

    rescanned = client.post("/scan-file", files=files, headers={**extension_headers, "X-Sentinel-Cache-Choice": "rescan"})
    assert rescanned.status_code == 200
    assert rescanned.json()["decision"] == "BLOCK"
    assert rescanned.json()["cache_hit"] is False
    assert len(calls) == 2
    replacement_offer = client.post("/scan-file", files=files).json()
    assert replacement_offer["cache_offer"]["decision"] == "BLOCK"


def test_cached_redact_report_requires_a_fresh_scan(isolated_cache):
    content = _pdf("Synthetic cached redact test")
    fingerprint = cache_store.sha256_fingerprint(content)
    cache_store.put_cached_report(fingerprint=fingerprint, file_type="pdf", byte_count=len(content), report=_report("REDACT", "MEDIUM"))
    client = TestClient(main.app)
    files = {"file": ("cached-redact.pdf", content, "application/pdf")}
    offer = client.post("/scan-file", files=files).json()
    assert offer["decision"] == "CACHE_CHOICE_REQUIRED"
    assert offer["cache_offer"]["reuse_allowed"] is False
    response = client.post("/scan-file", files=files, headers={"X-Sentinel-Cache-Choice": "reuse"})
    assert response.status_code == 409


def test_manual_text_scan_is_report_only(monkeypatch):
    monkeypatch.setattr(main, "run_security_pipeline", lambda text: {"entities": [], "risk": "LOW", "decision": "ALLOW", "redacted_text": None})
    response = TestClient(main.app).post("/scan", json={"text": "Synthetic manual scan"})
    assert response.status_code == 200
    assert response.json()["scan_mode"] == "manual"
    assert response.json()["enforcement_mode"] == "REPORT_ONLY"
    event = dashboard_store.get_security_event(response.json()["event_id"])
    assert event["scan_mode"] == "manual"
    assert event["enforcement_mode"] == "REPORT_ONLY"
    assert event["report_source"] == "new_scan"
