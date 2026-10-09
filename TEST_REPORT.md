# Test Report — Sentinel Privacy Security

## Final backend suite

Command:

```bash
python3 -m pytest -q backend
```

**Observed:** 82 passed, 0 failed, 0 skipped; 4 warnings; 18.20 seconds.

Warnings are FastAPI `on_event` deprecations from the existing startup/shutdown lifecycle hooks. No test failures were suppressed. An additional run with `--disable-warnings` also completed with 82 passed.

## Focused regression run

```bash
python3 -m pytest -q backend/test_detection_policy.py backend/test_sentinel_security.py --disable-warnings
```

**Observed:** 18 passed, 0 failed, 0 skipped. This includes synthetic custom-detector examples, DOCX core-property redaction, PDF info-dictionary metadata redaction, OCR uncertainty, OCR page cap, payload lifecycle, and extension coverage assertions.

## Coverage represented in the suite

The full suite covers reviewer authentication/actions, release authorization and RAM retention/expiry/manual clearing, synthetic PDF/DOCX/image processing and redaction checks, upload bounds and incomplete outcomes, synthetic custom detectors with negative lookalikes, cache SHA-256/TTL/versioning/privacy/reuse/rescan/audit preservation, manual-versus-extension provenance, and extension manifest/notice source checks.

## Static checks

Executed successfully:

```bash
python3 -m compileall -q backend
node --check extension/background.js
node --check extension/content.js
python3 -m json.tool extension/manifest.json >/dev/null
```

## Local integration smoke check

Started the backend bound to `127.0.0.1:8000` and the existing frontend static server on `127.0.0.1:5173`, then stopped both. Observed:

- FastAPI `/docs` and `POST /ping`: **PASS**.
- Dashboard `/dashboard/` HTTP serving: **PASS**.
- Chrome extension `/scan-file` CORS preflight with scan/cache headers: **PASS**.
- Local dashboard authenticated `DELETE /dashboard/cache` CORS preflight: **PASS**.

API decision, redaction, cache, reviewer and release behaviors are additionally exercised through FastAPI `TestClient` in the pytest suite.

## Not run / limitations

- **Live Chrome/Gemini end-to-end test:** not run because no browser session was available. Static coverage and automated backend integration tests are not substitutes for a live site-flow test.
- **Optional Corsair/Slack integration:** not run because its test can post externally to a real Slack channel; it is not required for core scanning.
- No test was skipped by pytest. OCR dependencies were installed and synthetic OCR tests ran.
