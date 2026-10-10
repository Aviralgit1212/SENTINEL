"""
SENTINEL Privacy Shield service.

Standalone FastAPI wrapper around the proven AI Guardian pipeline:

    scanner (Presidio) -> policy -> risk -> decision -> redact

Boundaries with the main Node server:
- POST /scan/json            { text }                      -> entities, risk, decision, redacted_text
- POST /privacy/scan-file    multipart file                -> entities, risk, decision (no redaction)
- POST /privacy/redact-file  multipart file + entities JSON -> output_b64, redacted_filename, verified
- POST /privacy/extract-text multipart file                -> { text }

Inputs arrive from the local Sentinel server, which owns uploads,
hashing, type detection and persistence. This service never writes
user files to disk; everything is processed in memory.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json as jsonlib
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from scanner import Scanner
from policy import PolicyEngine
from risk import RiskEngine
from decision import DecisionEngine
from redact import Redactor
from redact.pdf_redact import RedactionError, redact_pdf
from redact.docx_redact import DocxRedactionError, redact_docx
from extraction import extract_text, extract_pages
from extraction.image_ocr import extract_image
from limits import TextLimitExceeded, enforce_text_limit
from redact.image_redact import ImageRedactionError, redact_and_verify_image

logger = logging.getLogger("sentinel-privacy")
logging.basicConfig(level=logging.INFO)

MAX_TEXT_CHARS = 200_000
MAX_FILE_BYTES = 50 * 1024 * 1024

app = FastAPI(title="SENTINEL Privacy Shield")

# Single-user local service: same-origin calls from the Sentinel server.
scanner = Scanner()
policy_engine = PolicyEngine()
risk_engine = RiskEngine()
decision_engine = DecisionEngine()
redactor = Redactor()


class TextScanRequest(BaseModel):
    text: str


class RedactRequest(BaseModel):
    entities: list[dict[str, Any]]


def run_entity_pipeline(text: str, entities: list[dict]) -> dict:
    """Apply policy/risk/decision to already extracted entity observations."""
    flagged = policy_engine.evaluate(entities)
    risk = risk_engine.calculate(flagged)
    decision = decision_engine.decide(risk)
    redacted_text = None
    if decision == "REDACT":
        redacted_text = redactor.redact(text, flagged)
    return {
        "entities": flagged,
        "risk": risk,
        "decision": decision,
        "redacted_text": redacted_text,
    }


def run_text_pipeline(text: str) -> dict:
    return run_entity_pipeline(text, scanner.scan(text))


def _validate_redaction_entities(entities: Any) -> list[dict[str, Any]]:
    if not isinstance(entities, list) or not entities or len(entities) > 1000:
        raise HTTPException(status_code=400, detail="entities must be a non-empty list of at most 1000 items.")
    validated: list[dict[str, Any]] = []
    for entity in entities:
        if not isinstance(entity, dict):
            raise HTTPException(status_code=400, detail="Each entity must be an object.")
        value = entity.get("text")
        start = entity.get("start")
        end = entity.get("end")
        entity_type = entity.get("entity_type")
        page = entity.get("page")
        if (not isinstance(value, str) or not value or len(value) > MAX_TEXT_CHARS or
                not isinstance(entity_type, str) or not entity_type or
                isinstance(start, bool) or not isinstance(start, int) or start < 0 or
                isinstance(end, bool) or not isinstance(end, int) or end <= start or
                end - start != len(value) or
                (page is not None and (isinstance(page, bool) or not isinstance(page, int) or page < 0))):
            raise HTTPException(status_code=400, detail="Entity text, type, offsets, or page are invalid.")
        validated.append({**entity, "text": value, "entity_type": entity_type, "start": start, "end": end})
    return validated


def _read_upload(file: UploadFile) -> tuple[bytes, str]:
    data = file.file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 50 MB limit.")
    name = os.path.basename(file.filename or "upload.bin")
    return data, name


def _kind_for(name: str, data: bytes) -> str:
    lower = name.lower()
    if lower.endswith(".pdf"):
        return "pdf"
    if lower.endswith((".docx", ".docm")):
        return "docx"
    if lower.endswith((".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff")):
        return "image"
    if data[:8] == b"%PDF-\x1e" or data[:5] == b"%PDF-":
        return "pdf"
    if data[:2] == b"PK":
        return "docx"
    return "text"


@app.get("/ping")
def ping() -> dict:
    try:
        scanner.scan("ping")
        return {"ok": True, "service": "sentinel-privacy", "scanner": "ready"}
    except Exception as exc:  # pragma: no cover - safety net
        return {"ok": False, "service": "sentinel-privacy", "error": str(exc)[:200]}


@app.post("/scan/json")
def scan_json(req: TextScanRequest) -> dict:
    try:
        text = enforce_text_limit(req.text, MAX_TEXT_CHARS, field="Submitted text")
    except TextLimitExceeded as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    return run_text_pipeline(text)


@app.post("/privacy/scan-file")
async def scan_file(file: UploadFile = File(...)) -> dict:
    data, name = _read_upload(file)
    kind = _kind_for(name, data)
    try:
        pdf_page_texts: list[str] | None = None
        if kind == "pdf":
            pdf_page_texts = extract_pages(data)
            text = "\n".join(pdf_page_texts)
            text = enforce_text_limit(text, MAX_TEXT_CHARS, field="Extracted document text")
            # Preserve page identity for PDF redaction. A global flattened
            # offset is not a valid page-local locator and can redact the wrong page.
            entities = []
            for page_number, page_text in enumerate(pdf_page_texts):
                for entity in scanner.scan(page_text):
                    entities.append({**entity, "page": page_number})
            result = run_entity_pipeline(text, entities)
        elif kind == "docx":
            text = enforce_text_limit(extract_text(data, name) or "", MAX_TEXT_CHARS, field="Extracted document text")
            result = run_text_pipeline(text)
        elif kind == "image":
            ocr_result = extract_image(data)
            text = enforce_text_limit(ocr_result.full_text or "", MAX_TEXT_CHARS, field="OCR text")
            result = run_text_pipeline(text)
        else:
            raise HTTPException(status_code=415, detail="File scan currently supports PDF, DOCX and images.")
        result["kind"] = kind
        result["filename"] = name
        result["extracted_char_count"] = len(text)
        return result
    except HTTPException:
        raise
    except TextLimitExceeded as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)[:300])
    except Exception as exc:  # pragma: no cover - logs with no content leak
        logger.exception("File privacy scan failed")
        raise HTTPException(status_code=500, detail="Privacy scan failed.")


@app.post("/privacy/redact-file")
async def redact_file(file: UploadFile = File(...), entities_json: str | None = Form(None)) -> dict:
    """Entities come from a prior /privacy/scan-file response and carry
    entity_type, text, start, end, and for PDFs an optional page field."""
    import json as jsonlib

    if not entities_json:
        raise HTTPException(status_code=400, detail="entities_json is required.")
    try:
        entities = jsonlib.loads(entities_json)
    except ValueError:
        raise HTTPException(status_code=400, detail="entities_json must be valid JSON.")
    entities = _validate_redaction_entities(entities)

    data, name = _read_upload(file)
    kind = _kind_for(name, data)

    try:
        if kind == "pdf":
            by_page: dict[int, list[str]] = {}
            for entity in entities:
                page = entity.get("page")
                if page is None:
                    raise HTTPException(status_code=422, detail="PDF redaction targets must include a page from a fresh file scan.")
                by_page.setdefault(page, []).append(entity["text"])
            output = redact_pdf(data, by_page)
            out_name = (name[:-4] if name.lower().endswith(".pdf") else name) + "-redacted.pdf"
        elif kind == "docx":
            # DOCX redaction needs scanner offsets as well as values so it can
            # map each entity to the correct paragraph/run, including split runs.
            output = redact_docx(data, entities)
            out_name = name.rsplit(".", 1)[0] + "-redacted.docx"
        elif kind == "image":
            # received entity matches carry entity_type/text/start/end;
            # image redaction needs (start, end, original_value) tuples.
            matches = [
                (int(entity.get("start", 0) or 0),
                 int(entity.get("end", 0) or 0),
                 str(entity.get("text", "")))
                for entity in entities
                if entity.get("text")
            ]
            if not matches:
                raise ImageRedactionError("No sensitive entity matches supplied.")
            redaction_result = redact_and_verify_image(data, matches)
            output = redaction_result.redacted_bytes
            out_name = name.rsplit(".", 1)[0] + "-redacted" + (Path(name).suffix or ".png")
        else:
            raise HTTPException(status_code=415, detail="Redaction currently supports PDF, DOCX and images.")

        return {
            "output_b64": base64.b64encode(output).decode("ascii"),
            "output_filename": out_name,
            "output_sha256": __import__("hashlib").sha256(output).hexdigest(),
            "output_size": len(output),
            "verified": True,
            "kind": kind,
        }
    except (RedactionError, DocxRedactionError, ImageRedactionError) as exc:
        # Post-redaction verification failed: fail closed, return no output.
        raise HTTPException(status_code=422, detail=f"Redaction failed: {exc}")
    except HTTPException:
        raise
    except binascii.Error:
        raise HTTPException(status_code=400, detail="Invalid base64 output encoding.")
    except Exception:
        logger.exception("Redaction failed unexpectedly")
        raise HTTPException(status_code=500, detail="Redaction failed.")


@app.post("/privacy/extract-text")
async def extract_only(file: UploadFile = File(...)) -> dict:
    data, name = _read_upload(file)
    kind = _kind_for(name, data)
    try:
        if kind == "pdf":
            pages = extract_pages(data)
            text = "\n".join(pages)
        elif kind == "docx":
            text = extract_text(data, name)
        elif kind == "image":
            text = extract_image(data).full_text
        else:
            raise HTTPException(status_code=415, detail="Extraction currently supports PDF, DOCX and images.")
        bounded_text = enforce_text_limit(text or "", MAX_TEXT_CHARS, field="Extracted document text")
        return {"kind": kind, "text": bounded_text, "complete": True, "character_count": len(bounded_text)}
    except TextLimitExceeded as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)[:300])
    except HTTPException:
        raise
    except Exception:
        logger.exception("Extraction failed")
        raise HTTPException(status_code=500, detail="Extraction failed.")
