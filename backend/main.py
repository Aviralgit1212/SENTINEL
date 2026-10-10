from __future__ import annotations

from dashboard_api import router as dashboard_router
from release_api import router as release_router
import asyncio
import base64
import hashlib
import json
import mimetypes
import re
import secrets
import threading
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.formparsers import MultiPartParser

from dashboard_store import (
    add_audit_event,
    create_security_event,
)
from override_store import offer_override
from release_store import (
    PayloadCapacityError,
    create_held_payload,
    start_cleanup_worker,
    stop_cleanup_worker,
)
from scanner.scanner import Scanner
from cache_store import get_cached_report, put_cached_report, sha256_fingerprint
from policy.policy import PolicyEngine
from risk.risk import RiskEngine
from decision.decision import DecisionEngine
from redact.redact import Redactor
from redact.pdf_redact import (
    RedactionError,
    redact_pdf,
)
from redact.image_redact import (
    ImageRedactionError,
    redact_and_verify_image,
)
from redact.docx_redact import (
    DocxRedactionError,
    redact_docx,
)
from extraction.extraction import (
    extract_pages,
    extract_pdf_analysis,
    extract_text,
    inspect_docx_coverage,
)
from extraction.image_ocr import (
    extract_image,
)


MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_MULTIPART_BODY_BYTES = MAX_FILE_BYTES + 1024 * 1024
MAX_CONCURRENT_UPLOADS = 2
_upload_slots = threading.BoundedSemaphore(MAX_CONCURRENT_UPLOADS)
# FastAPI/Starlette normally spills large multipart files to a temporary file.
# Keep accepted uploads (<=25 MiB plus bounded multipart overhead) in RAM.
MultiPartParser.spool_max_size = MAX_MULTIPART_BODY_BYTES + 1


class _UploadTooLarge(Exception):
    pass


class UploadBodyLimitMiddleware:
    """Bound multipart request bytes before FastAPI parses the upload."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != "/scan-file":
            await self.app(scope, receive, send)
            return
        await asyncio.to_thread(_upload_slots.acquire)
        started = False
        total = 0
        async def limited_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > MAX_MULTIPART_BODY_BYTES:
                    raise _UploadTooLarge()
            return message
        async def tracked_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)
        try:
            headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
            declared = headers.get("content-length")
            if declared:
                try:
                    if int(declared) > MAX_MULTIPART_BODY_BYTES:
                        await JSONResponse(status_code=413, content={"detail": "Upload exceeds the 25 MB file limit."})(scope, receive, send)
                        return
                except ValueError:
                    await JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})(scope, receive, send)
                    return
            try:
                await self.app(scope, limited_receive, tracked_send)
            except _UploadTooLarge:
                if not started:
                    await JSONResponse(status_code=413, content={"detail": "Upload exceeds the 25 MB file limit."})(scope, receive, send)
        finally:
            _upload_slots.release()


from starlette.responses import JSONResponse


app = FastAPI()
app.add_middleware(UploadBodyLimitMiddleware)

app.include_router(
    dashboard_router
)

app.include_router(
    release_router
)


app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension://[a-p]{32}|http://(127\.0\.0\.1|localhost):(5173|5500|8000))$",
    allow_credentials=False,
    allow_methods=[
        "GET",
        "POST",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=["Content-Type", "Authorization", "X-Guardian-Release-Token", "X-Sentinel-Site", "X-Sentinel-Mode", "X-Sentinel-Cache-Choice", "X-Sentinel-Override-Token"],
)


@app.on_event("startup")
def _start_payload_cleanup() -> None:
    start_cleanup_worker()


@app.on_event("shutdown")
def _stop_payload_cleanup() -> None:
    stop_cleanup_worker()


scanner = Scanner()
policy_engine = PolicyEngine()
risk_engine = RiskEngine()
decision_engine = DecisionEngine()
redactor = Redactor()


class ScanRequest(BaseModel):
    text: str = Field(max_length=1_000_000)


def run_security_pipeline(
    text: str,
) -> dict:
    """
    Run the existing security pipeline for
    plain text or extracted file text.
    """

    try:
        entities = scanner.scan(text)
        flagged_entities = policy_engine.evaluate(entities)
        risk = risk_engine.calculate(flagged_entities)
        decision = decision_engine.decide(risk)
    except Exception:
        # Invalid detector/policy state must never silently weaken the result.
        return {
            "entities": [], "risk": "UNKNOWN", "decision": "INCOMPLETE",
            "redacted_text": None,
            "status_detail": "Sensitive-content detection or policy evaluation failed; inspection is incomplete.",
        }

    redacted_text = None

    if decision == "REDACT":
        try:
            redacted_text = redactor.redact(text, flagged_entities)
        except Exception:
            return {
                "entities": _public_entities(flagged_entities), "risk": risk,
                "decision": "INCOMPLETE", "redacted_text": None,
                "status_detail": "Text redaction failed; a verified safe replacement was not produced.",
            }

    return {
        "entities": flagged_entities,
        "risk": risk,
        "decision": decision,
        "redacted_text": redacted_text,
    }


def _public_entities(entities: list[dict]) -> list[dict]:
    """Expose detector labels only; matched source values remain transient."""
    public = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        item = {"entity_type": entity.get("entity_type", "UNKNOWN")}
        for key in ("detector", "source_layer", "metadata_field"):
            if isinstance(entity.get(key), str):
                item[key] = entity[key]
        confidence = entity.get("confidence")
        if isinstance(confidence, (int, float)):
            item["confidence"] = round(float(confidence), 4)
        public.append(item)
    return public


def _notify_corsair_block(
    *,
    event_id: str,
    risk: str,
    entities: list[dict],
) -> None:
    """
    Notify the reviewer through the Corsair sidecar.

    Only metadata is sent. Raw sensitive values are
    never sent to Slack.
    """

    detection_types: list[str] = []

    for entity in entities:
        entity_type = entity.get(
            "entity_type"
        )

        if (
            isinstance(
                entity_type,
                str,
            )
            and entity_type
        ):
            detection_types.append(
                entity_type
            )

    detection = (
        ", ".join(
            sorted(
                set(detection_types)
            )
        )
        or "Sensitive data"
    )

    payload = {
        "event_id": event_id,
        "risk": risk,
        "detection": detection,
        "dashboard_url": (
            "http://127.0.0.1:5173"
        ),
    }

    try:
        request = urllib.request.Request(
            "http://127.0.0.1:9000/notify",
            data=json.dumps(
                payload
            ).encode("utf-8"),
            headers={
                "Content-Type":
                    "application/json",
            },
            method="POST",
        )

        with urllib.request.urlopen(
            request,
            timeout=3,
        ) as response:

            if response.status != 200:
                print(
                    "[AI Guardian] Corsair notification "
                    f"returned HTTP {response.status}"
                )

            else:
                print(
                    "[AI Guardian] Corsair BLOCK notification: PASS"
                )

    except Exception as exc:
        # Notification failure must NEVER weaken
        # the underlying BLOCK decision.
        print(
            "[AI Guardian] Corsair notification failed:",
            exc,
        )


def _record_dashboard_event(
    *,
    request: Request,
    input_type: str,
    filename: str | None,
    security_result: dict,
    held_payload: dict | None = None,
    scan_metadata: dict | None = None,
) -> tuple[str, str | None]:
    """
    Record Dashboard metadata only, and — for BLOCK
    decisions — mint a release token and (optionally)
    hand the original payload to release_store for
    later reviewer-gated release.

    Raw text, file bytes, and matched sensitive
    values are never stored or sent to Slack. The
    release token is only ever returned to the caller
    that made the original request, never to Corsair/Slack.
    """

    origin = request.headers.get("X-Sentinel-Site") or request.headers.get("origin")

    if origin:
        try:
            site = (urlparse(origin).hostname or "unknown").lower()
            if not re.fullmatch(r"[a-z0-9.-]{1,253}", site):
                site = "unknown"
        except ValueError:
            site = "unknown"
    else:
        site = "unknown"

    decision = security_result.get(
        "decision",
        "BLOCK",
    )
    scan_mode = "extension_enforced" if (request.headers.get("origin") or "").startswith("chrome-extension://") else "manual"
    enforcement_mode = "ENFORCED" if scan_mode == "extension_enforced" else "REPORT_ONLY"

    if decision == "ALLOW":
        state = "ALLOWED"

    elif decision == "REDACT":
        state = "REDACTED"

    elif decision == "INCOMPLETE":
        state = "INCOMPLETE"

    else:
        state = "BLOCKED"

    safe_filename = None
    if filename:
        suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        safe_filename = f"uploaded.{suffix}" if suffix in {"pdf", "docx", "png", "jpg", "jpeg"} else "uploaded"

    event_id = create_security_event(
        username="local-user",
        site=site,
        input_type=input_type,
        filename=safe_filename,
        risk=security_result.get(
            "risk",
            "UNKNOWN",
        ),
        decision=decision,
        state=state,
        entities=security_result.get(
            "entities",
            [],
        ),
        status_detail=security_result.get(
            "status_detail"
        ),
        sha256_fingerprint=(scan_metadata or {}).get("sha256"),
        byte_count=(scan_metadata or {}).get("byte_count"),
        scan_mode=scan_mode,
        enforcement_mode=enforcement_mode,
        report_source=(scan_metadata or {}).get("report_source"),
        analysis_timestamp=(scan_metadata or {}).get("analysis_timestamp"),
        coverage=(scan_metadata or {}).get("coverage"),
    )

    release_token = None

    if decision == "BLOCK":

        release_token = secrets.token_urlsafe(
            32
        )

        if held_payload is not None:
            try:
                create_held_payload(
                    event_id=event_id,
                    release_token=release_token,
                    **held_payload,
                )
            except PayloadCapacityError:
                # Preserve the block and audit event; never spill originals to disk.
                release_token = None
                add_audit_event(
                    event_id=event_id,
                    actor="system",
                    action="payload_not_retained",
                    detail="RAM-only retention capacity unavailable; a new scan is required for review.",
                )

        _notify_corsair_block(
            event_id=event_id,
            risk=security_result.get(
                "risk",
                "UNKNOWN",
            ),
            entities=security_result.get(
                "entities",
                [],
            ),
        )

    return event_id, release_token


def _held_payload_for_text(
    text: str,
) -> dict:
    """
    Build the held_payload kwargs for a
    BLOCKed plain-text /scan request.
    """

    return {
        "payload_type": "text",
        "raw_text": text,
    }


def _held_payload_for_file(
    file_bytes: bytes,
    filename: str,
    content_type: str | None,
) -> dict:
    """
    Build the held_payload kwargs for a
    BLOCKed /scan-file request.

    Prefers the browser-supplied content type;
    falls back to guessing from the filename,
    then to a generic binary type.
    """

    guessed_type, _ = mimetypes.guess_type(
        filename
    )

    resolved_type = (
        content_type
        or guessed_type
        or "application/octet-stream"
    )

    return {
        "payload_type": "file",
        "raw_file_base64": base64.b64encode(
            file_bytes
        ).decode("ascii"),
        "original_filename": filename,
        "mime_type": resolved_type,
    }


def _fail_closed_response(
    filename: str,
    byte_count: int,
    security_result: dict,
    error: str,
) -> dict:
    """
    Return the common fail-closed file response.

    The original file is never returned.
    """

    return {
        "filename": filename,
        "byte_count": byte_count,
        "entities": _public_entities(security_result["entities"]),
        "risk": security_result[
            "risk"
        ],
        "decision": "BLOCK",
        "redacted_text": None,
        "redacted_file_base64": None,
        "redacted_filename": None,
        "redacted_mime_type": None,
        "error": error,
        "redaction_status": "FAILED",
    }


@app.post("/ping")
def ping():
    return {
        "status": "got it"
    }


@app.post("/scan")
def scan(
    request: ScanRequest,
    http_request: Request,
):
    security_result = (
        run_security_pipeline(
            request.text
        )
    )

    held_payload = (
        _held_payload_for_text(
            request.text
        )
        if security_result["decision"] == "BLOCK"
        else None
    )
    scan_timestamp = datetime.now(timezone.utc).isoformat()
    scan_mode = "extension_enforced" if (http_request.headers.get("origin") or "").startswith("chrome-extension://") else "manual"

    event_id, release_token = _record_dashboard_event(
        request=http_request,
        input_type="TEXT",
        filename=None,
        security_result=security_result,
        held_payload=held_payload,
        scan_metadata={
            "report_source": "new_scan", "analysis_timestamp": scan_timestamp,
            "coverage": {"format": "TEXT", "complete": security_result.get("decision") != "INCOMPLETE"},
        },
    )

    return {
        **security_result,
        "entities": _public_entities(security_result["entities"]),
        "event_id": event_id,
        "release_token": release_token,
        "analysis_timestamp": scan_timestamp,
        "report_source": "new_scan",
        "scan_mode": scan_mode,
        "enforcement_mode": "ENFORCED" if scan_mode == "extension_enforced" else "REPORT_ONLY",
    }


def _reuse_cached_file_report(*, request: Request, filename: str, file_bytes: bytes, content_type: str | None, cached: dict) -> dict:
    report = cached["report"]
    decision = report.get("decision")
    if decision not in {"ALLOW", "BLOCK"}:
        raise HTTPException(status_code=409, detail="This cached result cannot be safely reused; request a fresh scan.")
    detail = report.get("status_detail")
    provenance = f"Cached report reused; originally analyzed at {cached['analyzed_at']}."
    event_detail = f"{detail} {provenance}".strip() if detail else provenance
    security_result = {
        "decision": decision, "risk": report.get("risk", "UNKNOWN"),
        "entities": report.get("entities", []), "status_detail": event_detail,
    }
    event_id, release_token = _record_dashboard_event(
        request=request,
        input_type=cached["file_type"],
        filename=filename,
        security_result=security_result,
        held_payload=(
            _held_payload_for_file(file_bytes, filename, content_type)
            if decision == "BLOCK" else None
        ),
        scan_metadata={
            "sha256": cached["fingerprint"], "byte_count": len(file_bytes),
            "report_source": "cache", "analysis_timestamp": cached["analyzed_at"],
            "coverage": report.get("coverage", {}),
        },
    )
    return {
        "filename": filename, "byte_count": len(file_bytes),
        "sha256": cached["fingerprint"], "scan_mode": "extension_enforced" if (request.headers.get("origin") or "").startswith("chrome-extension://") else "manual",
        "enforcement_mode": "ENFORCED" if (request.headers.get("origin") or "").startswith("chrome-extension://") else "REPORT_ONLY",
        **security_result, "scan_status": "COMPLETE", "coverage": report.get("coverage", {}),
        "redacted_file_base64": None, "redacted_filename": None, "redacted_mime_type": None,
        "cache_hit": True, "report_source": "cache",
        "original_analysis_timestamp": cached["analyzed_at"], "analysis_timestamp": cached["analyzed_at"],
        "event_id": event_id, "release_token": release_token,
    }


@app.post("/scan-file")
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
):
    filename = file.filename or ""
    filename_lower = filename.lower()
    suffix = filename_lower.rsplit(".", 1)[-1] if "." in filename_lower else ""
    supported_suffixes = {"pdf", "docx", "png", "jpg", "jpeg"}
    if suffix not in supported_suffixes:
        raise HTTPException(status_code=415, detail="Supported formats are PDF, DOCX, PNG, JPG, and JPEG. XLSX is not supported.")

    file_bytes = await file.read(MAX_FILE_BYTES + 1)
    if len(file_bytes) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds the 25 MB file limit.")

    fingerprint = sha256_fingerprint(file_bytes)
    cached = get_cached_report(fingerprint)
    cache_choice = (request.headers.get("X-Sentinel-Cache-Choice") or "").strip().lower()
    if cache_choice not in {"", "reuse", "rescan"}:
        raise HTTPException(status_code=400, detail="Invalid cache choice.")
    if cached is not None and not cache_choice:
        cached_decision = cached["report"].get("decision", "UNKNOWN")
        return {
            "decision": "CACHE_CHOICE_REQUIRED", "scan_status": "NOT_SCANNED",
            "sha256": fingerprint, "byte_count": len(file_bytes), "file_type": suffix.upper(),
            "cache_offer": {
                "decision": cached_decision, "risk": cached["report"].get("risk", "UNKNOWN"),
                "analysis_timestamp": cached["analyzed_at"],
                "reuse_allowed": cached_decision in {"ALLOW", "BLOCK"},
                "message": "Reuse is available only for compatible ALLOW/BLOCK reports. Cached REDACT results require a fresh scan and verified output generation.",
            },
        }
    if cache_choice == "reuse":
        if cached is None:
            raise HTTPException(status_code=409, detail="No compatible unexpired cached report is available; request a fresh scan.")
        return _reuse_cached_file_report(
            request=request, filename=filename, file_bytes=file_bytes,
            content_type=file.content_type, cached=cached,
        )

    image_input = (
        filename_lower.endswith(
            (
                ".png",
                ".jpg",
                ".jpeg",
            )
        )
    )

    coverage: dict = {"format": suffix.upper(), "complete": True}
    ocr_ranges: list[tuple[int, int]] = []
    incomplete_reasons: list[str] = []
    document_metadata_values: dict[str, str] = {}
    metadata_source_layer = ""
    metadata_entities: list[dict] = []
    try:
        if image_input:

            # IMAGE/OCR — 6.4.5
            # One OCR pass produces the text used by
            # the common security pipeline.
            # The same image is reprocessed only
            # inside the format-specific redaction
            # adapter when REDACT is required.

            image_ocr_result = extract_image(
                file_bytes
            )

            extracted_text = (
                image_ocr_result.full_text
            )
            confidences = [region.confidence for region in image_ocr_result.regions if region.confidence >= 0]
            average_confidence = (sum(confidences) / len(confidences)) if confidences else None
            coverage = {
            "format": suffix.upper(), "complete": bool(extracted_text.strip()) and (average_confidence is None or average_confidence >= 40),
                "layers_inspected": ["image_ocr"], "ocr_confidence_average": round(average_confidence, 2) if average_confidence is not None else None,
            }
            if not extracted_text.strip() or average_confidence is None or average_confidence < 40:
                coverage["complete"] = False
                incomplete_reasons.append("Image OCR was empty, uncertain, or missing reliable confidence data.")

        elif suffix == "pdf":
            pdf_analysis = extract_pdf_analysis(file_bytes)
            extracted_text = pdf_analysis["text"]
            coverage = {
                "format": "PDF", "complete": pdf_analysis["complete"],
                "layers_inspected": ["selectable_text", "image_ocr", "info_dictionary_metadata"],
                "page_count": pdf_analysis["page_count"],
                "ocr_pages_processed": min(pdf_analysis["scanned_page_count"], pdf_analysis["ocr_page_limit"]),
                "ocr_page_limit": pdf_analysis["ocr_page_limit"],
                "pages": pdf_analysis["pages"],
                "metadata_fields_present": pdf_analysis["metadata_fields_present"],
                "xml_metadata_present": pdf_analysis["xml_metadata_present"],
            }
            document_metadata_values = pdf_analysis.get("metadata_values", {})
            metadata_source_layer = "pdf_info_dictionary"
            ocr_ranges = pdf_analysis["ocr_ranges"]
            incomplete_reasons.extend(pdf_analysis["incomplete_reasons"])

        else:
            docx_coverage = inspect_docx_coverage(file_bytes)
            extracted_text = extract_text(
                file_bytes,
                filename,
            )
            document_metadata_values = docx_coverage.get("metadata_values", {})
            metadata_source_layer = "docx_core_properties"
            unsupported_docx = docx_coverage["unsupported_layers"]
            coverage = {
                "format": "DOCX", "complete": bool(extracted_text.strip()) and not unsupported_docx,
                "layers_inspected": ["paragraphs", "tables", "headers", "footers", "core_properties"],
                "metadata_fields_present": docx_coverage["metadata_fields_present"],
                "unsupported_layers": unsupported_docx,
            }
            if unsupported_docx:
                incomplete_reasons.append("Uninspected DOCX layers are present: " + ", ".join(unsupported_docx) + ".")
            if not extracted_text.strip():
                incomplete_reasons.append("No supported text content was extracted from the DOCX.")

    except ValueError:
        extracted_text = ""
        coverage = {"format": suffix.upper(), "complete": False, "layers_inspected": []}
        incomplete_reasons.append("Extraction or OCR failed; the file was not treated as clean.")


    security_result = run_security_pipeline(
        extracted_text
    )

    if document_metadata_values:
        try:
            for field_name, field_value in document_metadata_values.items():
                if not isinstance(field_value, str) or not field_value.strip():
                    continue
                field_result = run_security_pipeline(field_value)
                if field_result.get("decision") == "INCOMPLETE":
                    incomplete_reasons.append("Document metadata could not be inspected reliably.")
                    continue
                for entity in field_result.get("entities", []):
                    metadata_entities.append({
                        **entity,
                        "source_layer": metadata_source_layer,
                        "metadata_field": field_name,
                    })
            if metadata_entities:
                combined_entities = security_result.get("entities", []) + metadata_entities
                combined_risk = risk_engine.calculate(combined_entities)
                combined_decision = decision_engine.decide(combined_risk)
                if security_result.get("decision") == "INCOMPLETE":
                    combined_decision = "INCOMPLETE"
                elif combined_decision == "ALLOW":
                    combined_decision = "REDACT"
                security_result.update({
                    "entities": combined_entities,
                    "risk": combined_risk,
                    "decision": combined_decision,
                })
                coverage["metadata_findings"] = len(metadata_entities)
                coverage["metadata_findings_by_type"] = sorted({e.get("entity_type", "UNKNOWN") for e in metadata_entities})
        except Exception:
            # Never include exception text: third-party errors may echo content.
            incomplete_reasons.append("Document metadata inspection failed.")

    if not extracted_text.strip():
        incomplete_reasons.append("No readable content was available for policy scanning.")
    if incomplete_reasons:
        security_result["decision"] = "INCOMPLETE"
        security_result["risk"] = security_result.get("risk") or "UNKNOWN"
        security_result["status_detail"] = " ".join(dict.fromkeys(incomplete_reasons))
    elif security_result["decision"] == "REDACT" and ocr_ranges:
        for entity in security_result["entities"]:
            start, end = entity.get("start"), entity.get("end")
            if isinstance(start, int) and isinstance(end, int) and any(start < range_end and end > range_start for range_start, range_end in ocr_ranges):
                security_result["decision"] = "INCOMPLETE"
                security_result["status_detail"] = "Sensitive content was found in a PDF image layer, but verified pixel-level PDF redaction is not available in this release. Submission is blocked."
                incomplete_reasons.append("Image-layer-sensitive-content-cannot-be-redacted")
                break


    response = {
        "filename": filename,
        "byte_count": len(file_bytes),
        "sha256": fingerprint,
        "scan_mode": "extension_enforced" if (request.headers.get("origin") or "").startswith("chrome-extension://") else "manual",
        "enforcement_mode": "ENFORCED" if (request.headers.get("origin") or "").startswith("chrome-extension://") else "REPORT_ONLY",
        "cache_hit": False,
        "report_source": "new_scan",
        **security_result,
        "scan_status": "INCOMPLETE" if security_result["decision"] == "INCOMPLETE" else "COMPLETE",
        "coverage": coverage,
        "redacted_file_base64": None,
        "redacted_filename": None,
        "redacted_mime_type": None,
        "redaction_status": "NOT_REQUIRED" if security_result["decision"] == "ALLOW" else "NOT_PERFORMED",
    }


    # --------------------------------------------------
    # REDACT — FORMAT-SPECIFIC ADAPTER DISPATCH
    # --------------------------------------------------

    if security_result[
        "decision"
    ] == "REDACT":

        try:

            # --------------------------------------------------
            # PDF — EXISTING 5H PATH, KEPT INTACT
            # --------------------------------------------------

            if filename_lower.endswith(".pdf"):

                page_texts = extract_pages(
                    file_bytes
                )

                entities_by_page: dict[
                    int,
                    list[str],
                ] = {}


                for (
                    page_number,
                    page_text,
                ) in enumerate(
                    page_texts
                ):

                    page_entities = scanner.scan(
                        page_text
                    )

                    flagged_page_entities = (
                        policy_engine.evaluate(
                            page_entities
                        )
                    )

                    page_strings: list[
                        str
                    ] = []


                    for entity in (
                        flagged_page_entities
                    ):

                        entity_text = entity.get(
                            "text"
                        )


                        if (
                            isinstance(
                                entity_text,
                                str,
                            )
                            and entity_text
                        ):

                            page_strings.append(
                                entity_text
                            )


                    if page_strings:

                        entities_by_page[
                            page_number
                        ] = page_strings


                redacted_bytes = redact_pdf(
                    file_bytes,
                    entities_by_page,
                    metadata_entities=metadata_entities,
                )


                response[
                    "redacted_text"
                ] = None


                response[
                    "redacted_file_base64"
                ] = base64.b64encode(
                    redacted_bytes
                ).decode(
                    "ascii"
                )


                response[
                    "redacted_filename"
                ] = (
                    f"redacted_{filename}"
                )


                response[
                    "redacted_mime_type"
                ] = (
                    "application/pdf"
                )
                response["redaction_status"] = "VERIFIED_SUPPORTED_TEXT_AND_INFO_METADATA"


            # --------------------------------------------------
            # DOCX — NEW 6.3 PATH
            # --------------------------------------------------

            elif filename_lower.endswith(
                ".docx"
            ):

                redacted_bytes = redact_docx(
                    file_bytes,
                    [entity for entity in security_result["entities"] if entity.get("source_layer") != "docx_core_properties"],
                    metadata_entities=metadata_entities,
                )


                response[
                    "redacted_text"
                ] = None


                response[
                    "redacted_file_base64"
                ] = base64.b64encode(
                    redacted_bytes
                ).decode(
                    "ascii"
                )


                response[
                    "redacted_filename"
                ] = (
                    f"redacted_{filename}"
                )


                response[
                    "redacted_mime_type"
                ] = (
                    "application/"
                    "vnd.openxmlformats-officedocument."
                    "wordprocessingml.document"
                )
                response["redaction_status"] = "VERIFIED_SUPPORTED_TEXT_AND_CORE_PROPERTIES"


            # --------------------------------------------------
            # IMAGE — 6.4 PATH
            # --------------------------------------------------

            elif filename_lower.endswith(
                (
                    ".png",
                    ".jpg",
                    ".jpeg",
                )
            ):

                entity_matches: list[
                    tuple[int, int, str]
                ] = []


                for entity in (
                    security_result[
                        "entities"
                    ]
                ):

                    entity_text = entity.get(
                        "text"
                    )

                    entity_start = entity.get(
                        "start"
                    )

                    entity_end = entity.get(
                        "end"
                    )


                    if not isinstance(
                        entity_text,
                        str,
                    ) or not entity_text:

                        raise ImageRedactionError(
                            "Sensitive image entity "
                            "has no valid text."
                        )


                    if (
                        not isinstance(
                            entity_start,
                            int,
                        )
                        or not isinstance(
                            entity_end,
                            int,
                        )
                    ):

                        raise ImageRedactionError(
                            "Sensitive image entity "
                            "has invalid offsets."
                        )


                    entity_matches.append(
                        (
                            entity_start,
                            entity_end,
                            entity_text,
                        )
                    )


                redacted_result = (
                    redact_and_verify_image(
                        file_bytes,
                        entity_matches,
                    )
                )


                response[
                    "redacted_text"
                ] = None


                response[
                    "redacted_file_base64"
                ] = base64.b64encode(
                    redacted_result.redacted_bytes
                ).decode(
                    "ascii"
                )


                response[
                    "redacted_filename"
                ] = (
                    f"redacted_{filename}"
                )


                response[
                    "redacted_mime_type"
                ] = (
                    redacted_result.mime_type
                )
                response["redaction_status"] = "VERIFIED_OCR_MAPPED_PIXELS"


            # --------------------------------------------------
            # UNSUPPORTED REDACTION FORMAT
            # --------------------------------------------------

            else:

                failed_response = (
                    _fail_closed_response(
                        filename,
                        len(file_bytes),
                        security_result,
                        "Could not generate a "
                        "safe version of "
                        "this file — blocked.",
                    )
                )


                _record_dashboard_event(
                    request=request,
                    input_type=(
                        filename_lower.rsplit(
                            ".",
                            1,
                        )[-1].upper()
                        if "."
                        in filename_lower
                        else "FILE"
                    ),
                    filename=filename,
                    security_result={
                        "entities":
                            failed_response[
                                "entities"
                            ],
                        "risk":
                            failed_response[
                                "risk"
                            ],
                        "decision":
                            failed_response[
                                "decision"
                            ],
                        "status_detail":
                            failed_response.get(
                                "error"
                            ),
                    },
                )


                return failed_response


            response["coverage"]["redaction_verification"] = response["redaction_status"]
            response["coverage"]["metadata_redaction_status"] = "verified" if metadata_entities else "not_required"

        except (
            ValueError,
            RedactionError,
            DocxRedactionError,
            ImageRedactionError,
        ):

            # FAIL CLOSED:
            # Never return the original file after
            # a failed redaction attempt.
            # Never return an unverified redacted file.

            failed_response = (
                _fail_closed_response(
                    filename,
                    len(file_bytes),
                    security_result,
                    "Could not generate a "
                    "safe version of "
                    "this file — blocked.",
                )
            )


            _record_dashboard_event(
                request=request,
                input_type=(
                    filename_lower.rsplit(
                        ".",
                        1,
                    )[-1].upper()
                    if "."
                    in filename_lower
                    else "FILE"
                ),
                filename=filename,
                security_result={
                    "entities":
                        failed_response[
                            "entities"
                        ],
                    "risk":
                        failed_response[
                            "risk"
                        ],
                    "decision":
                        failed_response[
                            "decision"
                        ],
                    "status_detail":
                        failed_response.get(
                            "error"
                        ),
                },
            )


            return failed_response


    # Persist only public entity labels in the event and cache report.
    response["entities"] = _public_entities(response["entities"])
    response["sha256"] = fingerprint
    response["scan_mode"] = "extension_enforced" if (request.headers.get("origin") or "").startswith("chrome-extension://") else "manual"
    response["cache_hit"] = False
    response["report_source"] = "new_scan"
    cacheable = (
        response.get("scan_status") == "COMPLETE"
        and not response.get("error")
        and response.get("decision") in {"ALLOW", "BLOCK", "REDACT"}
    )
    if cacheable:
        response["analysis_timestamp"] = put_cached_report(
            fingerprint=fingerprint, file_type=suffix, byte_count=len(file_bytes),
            report={
                "decision": response["decision"], "risk": response.get("risk", "UNKNOWN"),
                "entities": response["entities"], "status_detail": response.get("status_detail"),
                "coverage": response.get("coverage", {}),
            },
        )
    else:
        response["analysis_timestamp"] = datetime.now(timezone.utc).isoformat()

    # --------------------------------------------------
    # DASHBOARD EVENT — FINAL DECISION
    # --------------------------------------------------

    event_id, release_token = _record_dashboard_event(
        request=request,
        input_type=(
            filename_lower.rsplit(
                ".",
                1,
            )[-1].upper()
            if "."
            in filename_lower
            else "FILE"
        ),
        filename=filename,
        security_result={
            "entities": response[
                "entities"
            ],
            "risk": response[
                "risk"
            ],
            "decision": response[
                "decision"
            ],
            "status_detail": response.get("status_detail"),
        },
        scan_metadata={
            "sha256": fingerprint, "byte_count": len(file_bytes),
            "report_source": "new_scan", "analysis_timestamp": response["analysis_timestamp"],
            "coverage": coverage,
        },
        held_payload=(
            _held_payload_for_file(
                file_bytes,
                filename,
                file.content_type,
            )
            if response["decision"] == "BLOCK"
            else None
        ),
    )

    response["event_id"] = event_id

    if release_token is not None:
        response["release_token"] = release_token

    # --------------------------------------------------
    # REDACT OVERRIDE OFFER
    # --------------------------------------------------
    # Only for a COMPLETE REDACT that produced a redacted file.
    # The token is returned once; only its SHA-256 hash is stored.
    # Any failure fails closed: no token, override_available False.
    if (
        response["decision"] == "REDACT"
        and response.get("scan_status") == "COMPLETE"
        and not response.get("error")
        and response.get("redacted_file_base64")
    ):
        try:
            override_fingerprint = hashlib.sha256(file_bytes).hexdigest()
            override_token = secrets.token_urlsafe(32)
            offer_override(event_id, override_token, override_fingerprint)
            response["override_token"] = override_token
            response["override_available"] = True
        except Exception:
            response.pop("override_token", None)
            response["override_available"] = False

    return response