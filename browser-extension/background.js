const MAX_TEXT_CHARS = 200000;
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== 'SENTINEL_INSPECT_TEXT' && message?.type !== 'SENTINEL_INSPECT_FILE') return false;
  (async () => {
    const settings = await chrome.storage.local.get(['gateway', 'pairingToken']);
    const gateway = typeof settings.gateway === 'string' ? settings.gateway.replace(/\/$/, '') : 'http://127.0.0.1:5001';
    const pairingToken = typeof settings.pairingToken === 'string' ? settings.pairingToken : '';
    if (!pairingToken) throw new Error('SENTINEL pairing token is not configured. Payload remains held.');
    if (message.type === 'SENTINEL_INSPECT_TEXT') {
      if (typeof message.text !== 'string' || !message.text.trim() || message.text.length > MAX_TEXT_CHARS) throw new Error('Composer text is empty or exceeds the local inspection limit.');
      const response = await fetch(`${gateway}/api/extension/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sentinel-Pairing-Token': pairingToken },
        body: JSON.stringify({ text: message.text, origin: message.origin }), cache: 'no-store',
      });
      if (!response.ok) throw new Error(`Local SENTINEL inspection failed (HTTP ${response.status}). Payload remains held.`);
      sendResponse({ ok: true, result: await response.json() });
      return;
    }
    if (message.type === 'SENTINEL_INSPECT_FILE') {
      if (typeof message.filename !== 'string' || !(message.bytes instanceof ArrayBuffer) || message.bytes.byteLength < 1 || message.bytes.byteLength > 25 * 1024 * 1024) throw new Error('File is missing or exceeds the 25MB browser inspection limit.');
      const form = new FormData();
      form.append('file', new Blob([message.bytes], { type: typeof message.mimeType === 'string' ? message.mimeType : 'application/octet-stream' }), message.filename);
      const response = await fetch(`${gateway}/api/extension/inspect-file`, { method: 'POST', headers: { 'X-Sentinel-Pairing-Token': pairingToken }, body: form, cache: 'no-store' });
      if (!response.ok) throw new Error(`Local file inspection failed (HTTP ${response.status}). Payload remains held.`);
      const report = await response.json();
      sendResponse({ ok: true, result: { verdict: report.verdict, verdictReason: report.verdictReason, scanId: report.scanId, sha256: report.sha256 } });
    }
  })().catch((error) => sendResponse({ ok: false, error: String(error?.message ?? 'Inspection failed') }));
  return true;
});
