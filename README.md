# Sentinel Privacy Security

**Sentinel Privacy Security** is a local-first privacy scanner built from the supplied Chrome-extension and FastAPI project. It inspects text and supported files before an extension-mediated submission on configured sites. It is a defense-in-depth aid, not a guarantee of complete protection.

## V1 scope

- **Supported files:** PDF, DOCX, PNG, JPG, and JPEG. XLSX is not supported.
- **Upload limit:** 25 MiB per file; request bodies and concurrent uploads are bounded, with no intentional disk spillover.
- **PDF OCR:** at most 15 scanned/image pages per PDF. OCR failures, uncertain confidence, unprocessed pages, or sensitive PDF image-layer content that cannot be safely redacted yield `INCOMPLETE`/fail-closed behavior.
- **DOCX:** ordinary paragraphs, tables, headers, footers, and selected core properties are inspected. Sensitive core-property spans are selectively redacted and rechecked. Comments, tracked changes, embedded media, footnotes/endnotes, nested or header/footer tables, text boxes, external relationships, and other unsupported package layers cause an `INCOMPLETE` result rather than being called clean.
- **Images:** Tesseract OCR and pixel-level redaction are used where confidence and coordinate mapping support it; post-redaction OCR is used for verification. Unreadable/uncertain OCR is not treated as clean.
- **Detected categories:** Presidio email, phone, credit card, US SSN, and person recognizers; custom checksum-validated Aadhaar candidates with cautious OCR-confusion normalization; structural PAN and IFSC patterns; and limited OpenAI-/Google-/AWS-like credential-token patterns. These patterns are not exhaustive and can produce false positives/negatives.
- **Policy defaults:** low risk → ALLOW, medium → REDACT, high/critical → BLOCK. Sensitive DOCX metadata is redacted even when the general low-risk decision would otherwise allow it. A failed detection, extraction, OCR, redaction, or verification is never represented as a successful clean scan.

Text-only PDFs and reliably addressable DOCX/image content can be redacted and verified by the current adapters. Scanned PDF content that requires pixel-level PDF redaction is not released as a redacted output; when a sensitive OCR finding affects that layer, Sentinel marks the inspection incomplete and blocks it. PDF metadata is not currently separately scanned. Verification covers the checks named in the report, not every possible parser or hidden-content channel.

## Privacy and retained state

- Original blocked payloads are retained only in bounded process memory for the existing reviewer workflow. Idle expiry is 20 minutes; a reviewer-authenticated local clear action is available at `POST /release/clear`. A backend restart or expiry may make release unavailable; the user must submit and scan the file again. No persistent payload fallback or disk-backed cache is used.
- Approval/audit metadata is stored in `backend/guardian.db`; additive schema migration preserves existing audit history.
- Cached reports are stored separately in `backend/privacy_cache.db` for seven days and matched by SHA-256. The cache keeps only decision/risk, detector labels and counts, safe coverage metadata, file type/size, and timestamps—not the source bytes, Base64, raw text, or matched values. A dynamic compatibility fingerprint hashes the relevant scanning, policy, extraction, and redaction source files; incompatible records are discarded and a fresh scan is required.
- On a cache hit, the extension offers **Reuse previous report** or **Run fresh scan**. Cached `REDACT` results are not reused: the extension offers a fresh scan because the current build does not replay cached redaction mappings. Rescans update the cached report without deleting audit events. Clear reports from the dashboard, or call reviewer-authenticated `DELETE /dashboard/cache`; this does not clear audit history.
- SHA-256 is a matching fingerprint, not encryption or a secrecy guarantee.
- The dashboard uses a local reviewer session. The default first-run setup generates a password, prints it once in the backend terminal, and writes only its password hash to the ignored `backend/.env`. A configured self-declared username is not proof of real-world identity.

## Install and run

Tested with Python 3.11, Ubuntu 24.04, Tesseract OCR, and the English spaCy model. Install system OCR support first (for Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install -y tesseract-ocr
```

Then install Python dependencies and the spaCy English model:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

Start the local API in one terminal:

```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

On first startup, save the reviewer password printed in that terminal. The backend initializes `guardian.db` and `privacy_cache.db` as needed; do not copy populated local databases into a distributable.

Serve the existing dashboard from a second terminal:

```bash
python3 -m http.server 5173 --bind 127.0.0.1 --directory frontend
```

Open <http://127.0.0.1:5173/dashboard/> and sign in with the first-run reviewer credentials. API documentation is available locally at <http://127.0.0.1:8000/docs>.

## Load the Chrome extension

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose the repository's `extension/` folder.
4. Review Chrome's site-access prompt before enabling the extension.

The extension contains site-specific text selectors for `chatgpt.com`, legacy `chat.openai.com`, `claude.ai`, and `gemini.google.com`; file inputs are intercepted through the existing generic file-input/drop path. Gmail integration is not included. The static unsupported-site notice needs no backend request and is shown once per tab session using `sessionStorage`.

**Permission tradeoff:** the unsupported-site notice on arbitrary HTTP/HTTPS pages requires a content script matching those pages. Consequently, Chrome may request broad site access. The script displays the static notice on unsupported pages and runs supported-site interception only for its explicit site configuration. Inspect the manifest and grant site access only if acceptable. A notice is not proof that a site is protected.

## Manual versus enforced scans

- Requests made directly to the local API (including `/scan` and `/scan-file`) are **manual/report-only** unless they originate from the extension. They report a decision; they do not independently stop an unrelated website submission.
- Extension-origin requests are labelled `extension_enforced` and `ENFORCED` in API/audit metadata. The content script holds intercepted text/files pending a decision and fails closed when it cannot establish one. A `REDACT` file result produces a verified replacement where supported; the extension shows the result and the user must attach/use the sanitized file as instructed rather than Sentinel silently sending the original.
- Gemini selectors and the shared file interception path are present. This repository release was statically/unit/integration checked; a live Gemini browser session was not available for an end-to-end upload verification. Site DOM changes can invalidate selectors.

## Dashboard and local API

The existing dashboard retains sign-in, event history, review actions, and audit history, and now shows decision, risk, type, SHA-256, file size, scan mode/enforcement, cache source/timestamp, safe detector metadata, and coverage details. Cache clearing requires a reviewer session and preserves audit records.

Useful routes:

- `POST /scan` — text report/decision.
- `POST /scan-file` — supported-file report/decision, upload bounded at 25 MiB; cache choices use `X-Sentinel-Cache-Choice: reuse|rescan`.
- `GET /dashboard/summary`, `/dashboard/events`, `/dashboard/cache/status` — reviewer authenticated.
- `DELETE /dashboard/cache` — reviewer-authenticated cache clear.
- `POST /release/clear` — loopback-only, reviewer-authenticated RAM payload clear.
- `GET /release/{event_id}/status`, `POST /release/{event_id}` — loopback-only and event-token authenticated; unavailable originals cannot be reconstructed.

CORS is restricted to the extension origin and local dashboard development ports. CORS is not authentication and does not protect against every local process or attacker.

## Tests

Run from the project root with the OCR dependencies installed:

```bash
python3 -m pytest -q backend --disable-warnings
```

The suite uses generated in-memory/synthetic documents and detector test strings. It does not use real personal documents or credentials. See `TEST_REPORT.md` for the final observed results and any environment or browser limitations.

## Optional Corsair sidecar

The existing `corsair-sidecar/` remains separate and optional. A sidecar notification failure does not change an underlying block. It requires its own `CORSAIR_KEK` and provider integration configuration and should not be started with sample credentials. Do not run `test_corsair.ts` unless you intentionally want to post to a configured Slack destination.

## Known limitations

- This is not universal DLP and does not guarantee detection, complete document inspection, or safe redaction for every file.
- Gemini was not browser-tested end to end in this environment; selectors may change.
- Unsupported-site banners are static notices, not protection.
- Content-script injection cannot guarantee detection of every custom upload mechanism or site-side behavior; users should not assume interception if the site flow or extension hook fails.
- Cached `REDACT` reports require a full rescan; cached redacted bytes/mappings are intentionally not stored.
- PDF metadata scanning, OCR on embedded DOCX media, and all listed DOCX secondary structures are not implemented; affected unsupported DOCX layers yield `INCOMPLETE`.
- Custom Aadhaar/PAN/IFSC and credential detectors are pattern-based, limited recognizers and are not authoritative identity or credential validators.
- Manual API scans are reports only. Reviewer approval does not prove content safe and applies only to a specific blocked event.
