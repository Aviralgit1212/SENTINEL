from __future__ import annotations

import json
import tempfile
from pathlib import Path

import dashboard_store


def use_temp_database() -> Path:
    directory = Path(tempfile.mkdtemp())
    dashboard_store.DB_PATH = directory / "guardian_test.db"
    dashboard_store.init_db()
    return directory


def test_metadata_only_event_storage() -> None:
    use_temp_database()

    event_id = dashboard_store.create_security_event(
        username="demo-user",
        site="chatgpt.com",
        input_type="IMAGE",
        filename="secret.png",
        risk="CRITICAL",
        decision="BLOCK",
        state="BLOCKED",
        entities=[
            {
                "entity_type": "CREDIT_CARD",
                "text": "4111 1111 1111 1111",
                "start": 10,
                "end": 29,
            },
            {
                "entity_type": "CREDIT_CARD",
                "text": "5555 5555 5555 4444",
            },
        ],
    )

    event = dashboard_store.get_security_event(event_id)

    assert event is not None
    assert event["state"] == "BLOCKED"
    assert event["entities"] == [
        {"entity_type": "CREDIT_CARD", "count": 2}
    ]

    serialized = json.dumps(event)

    assert "4111 1111 1111 1111" not in serialized
    assert "5555 5555 5555 4444" not in serialized

    print("7.1 metadata-only storage: PASS")


def test_event_listing_and_pending_filter() -> None:
    use_temp_database()

    dashboard_store.create_security_event(
        username="demo-user",
        site="chatgpt.com",
        input_type="TEXT",
        filename=None,
        risk="LOW",
        decision="ALLOW",
        state="ALLOWED",
        entities=[],
    )

    pending_id = dashboard_store.create_security_event(
        username="demo-user",
        site="chatgpt.com",
        input_type="DOCX",
        filename="test.docx",
        risk="CRITICAL",
        decision="BLOCK",
        state="PENDING_APPROVAL",
        entities=[
            {"entity_type": "CREDIT_CARD"}
        ],
    )

    all_events = dashboard_store.list_security_events()
    pending = dashboard_store.list_security_events(
        state="PENDING_APPROVAL"
    )

    assert len(all_events) == 2
    assert len(pending) == 1
    assert pending[0]["id"] == pending_id

    print("7.1 event listing/filter: PASS")


def test_state_change_and_audit() -> None:
    use_temp_database()

    event_id = dashboard_store.create_security_event(
        username="demo-user",
        site="chatgpt.com",
        input_type="IMAGE",
        filename="blocked.png",
        risk="CRITICAL",
        decision="BLOCK",
        state="PENDING_APPROVAL",
        entities=[
            {"entity_type": "CREDIT_CARD"}
        ],
    )

    dashboard_store.update_event_state(
        event_id=event_id,
        new_state="APPROVED",
        actor="reviewer",
        reviewed_by="reviewer",
        detail="Approved for this specific event.",
    )

    event = dashboard_store.get_security_event(event_id)

    assert event is not None
    assert event["state"] == "APPROVED"
    assert event["reviewed_by"] == "reviewer"
    assert event["reviewed_at"]
    assert any(
        item["action"] == "state_change"
        for item in event["audit"]
    )

    print("7.1 state transition + audit: PASS")


def test_summary() -> None:
    use_temp_database()

    for decision, state in [
        ("ALLOW", "ALLOWED"),
        ("REDACT", "REDACTED"),
        ("BLOCK", "BLOCKED"),
        ("BLOCK", "PENDING_APPROVAL"),
    ]:
        dashboard_store.create_security_event(
            username="demo-user",
            site="chatgpt.com",
            input_type="TEXT",
            filename=None,
            risk="LOW" if decision == "ALLOW" else "MEDIUM",
            decision=decision,
            state=state,
            entities=[],
        )

    summary = dashboard_store.get_event_summary()

    assert summary == {
        "total": 4,
        "allowed": 1,
        "redacted": 1,
        "blocked": 2,
        "incomplete": 0,
        "pending": 2,
    }

    print("7.1 dashboard summary counts: PASS")


def main() -> None:
    test_metadata_only_event_storage()
    test_event_listing_and_pending_filter()
    test_state_change_and_audit()
    test_summary()
    print("7.1 DASHBOARD STORE: PASS")


if __name__ == "__main__":
    main()
