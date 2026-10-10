(() => {
  const sendSelectors = [
    'button[data-testid="send-button"]',
    'button[aria-label*="Send" i]',
    'button[aria-label*="Submit" i]',
    'button[data-testid*="send" i]',
  ].join(',');
  let bypassButton = null;
  let busy = false;
  const approvedFileKeys = new Set();
  const statusId = 'sentinel-local-inspection-status';

  function status(message, bad = false) {
    let node = document.getElementById(statusId);
    if (!node) {
      node = document.createElement('div');
      node.id = statusId;
      node.setAttribute('role', 'status');
      Object.assign(node.style, { position: 'fixed', zIndex: '2147483647', right: '16px', bottom: '16px', maxWidth: '360px', padding: '12px 14px', borderRadius: '8px', background: '#111827', color: '#fff', font: '13px/1.4 system-ui', boxShadow: '0 4px 18px #0005' });
      document.documentElement.appendChild(node);
    }
    node.textContent = `SENTINEL: ${message}`;
    node.style.border = bad ? '2px solid #ef4444' : '2px solid #22c55e';
  }

  function composerFor(button) {
    const form = button?.closest('form');
    return form?.querySelector('textarea, [contenteditable="true"], [role="textbox"]') ||
      document.querySelector('textarea, [contenteditable="true"][role="textbox"], [contenteditable="true"]');
  }
  function readText(editor) {
    return editor instanceof HTMLTextAreaElement || editor instanceof HTMLInputElement ? editor.value : editor?.innerText || editor?.textContent || '';
  }
  function setText(editor, value) {
    if (editor instanceof HTMLTextAreaElement || editor instanceof HTMLInputElement) {
      const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(editor), 'value')?.set;
      setter?.call(editor, value);
      editor.dispatchEvent(new Event('input', { bubbles: true }));
    } else if (editor) {
      editor.focus();
      editor.textContent = value;
      editor.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: value }));
    }
  }

  function selectedFiles(button) {
    const form = button?.closest('form');
    const inputs = [...(form || document).querySelectorAll('input[type="file"]')];
    return inputs.flatMap(input => [...(input.files || [])]);
  }
  async function inspectFilesAndRelease(button, files) {
    if (busy) return;
    busy = true;
    try {
      for (const file of files) {
        if (file.size > 25 * 1024 * 1024) throw new Error(`${file.name} exceeds the 25MB local inspection limit.`);
        status(`Inspecting attachment ${file.name} locally…`);
        const bytes = await file.arrayBuffer();
        const reply = await chrome.runtime.sendMessage({ type: 'SENTINEL_INSPECT_FILE', filename: file.name, mimeType: file.type, bytes });
        if (!reply?.ok) throw new Error(reply?.error || 'Attachment inspection failed. Nothing was sent.');
        if (reply.result?.verdict !== 'allow') throw new Error(`${file.name}: ${reply.result?.verdict || 'unknown'} — ${reply.result?.verdictReason || 'review required'}. Nothing was sent.`);
      }
      status('All selected attachments passed applicable local checks. Review the message and click Send again.');
      for (const file of files) approvedFileKeys.add(`${file.name}:${file.size}:${file.lastModified}`);
      // Require a new user gesture; never auto-submit after scanning attachments.
    } catch (error) { status(`${String(error?.message || error)} Nothing was sent.`, true); }
    finally { busy = false; }
  }

  async function inspectAndRelease(button, editor) {
    if (busy) return;
    busy = true;
    const text = readText(editor);
    status('Checking locally before sending…');
    try {
      const reply = await chrome.runtime.sendMessage({ type: 'SENTINEL_INSPECT_TEXT', text, origin: location.origin });
      if (!reply?.ok) throw new Error(reply?.error || 'Local inspection failed; payload remains held.');
      const result = reply.result;
      if (result.decision === 'ALLOW' && result.extractionState === 'completed_no_detections') {
        status('Inspection completed. Releasing this send.');
        bypassButton = button;
        button.click();
        setTimeout(() => { if (bypassButton === button) bypassButton = null; }, 1000);
      } else if (result.decision === 'REDACT' && typeof result.redactedText === 'string' && result.redactedText.length > 0) {
        setText(editor, result.redactedText);
        status('Sensitive content was redacted in the composer. Review the changed text, then click Send again.', true);
      } else {
        status(`Blocked or needs review (${result.decision || 'UNKNOWN'}). Nothing was sent.`, true);
      }
    } catch (error) {
      status(`${String(error?.message || error)} Nothing was sent.`, true);
    } finally {
      busy = false;
    }
  }

  document.addEventListener('click', (event) => {
    const button = event.target instanceof Element ? event.target.closest(sendSelectors) : null;
    if (!button) return;
    if (bypassButton === button) { bypassButton = null; return; }
    const files = selectedFiles(button);
    const unapprovedFiles = files.filter(file => !approvedFileKeys.has(`${file.name}:${file.size}:${file.lastModified}`));
    if (unapprovedFiles.length) { event.preventDefault(); event.stopImmediatePropagation(); void inspectFilesAndRelease(button, unapprovedFiles); return; }
    const editor = composerFor(button);
    if (!editor || !readText(editor).trim()) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    void inspectAndRelease(button, editor);
  }, true);

  // Do not let drag-and-drop bypass the selected-file inspection path. This
  // preview blocks drops and asks the user to choose the file through a picker.
  document.addEventListener('drop', (event) => {
    const files = event.dataTransfer?.files;
    if (!files || files.length === 0) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    status('Drag-and-drop attachments are blocked in this preview. Choose the file using the site picker so SENTINEL can inspect it.', true);
  }, true);

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
    const editor = event.target instanceof Element ? event.target.closest('textarea, [contenteditable="true"], [role="textbox"]') : null;
    const button = document.querySelector(sendSelectors);
    const files = selectedFiles(button);
    const unapprovedFiles = files.filter(file => !approvedFileKeys.has(`${file.name}:${file.size}:${file.lastModified}`));
    if (unapprovedFiles.length) { event.preventDefault(); event.stopImmediatePropagation(); void inspectFilesAndRelease(button, unapprovedFiles); return; }
    if (!editor || !readText(editor).trim()) return;
    if (!button) {
      event.preventDefault(); event.stopImmediatePropagation();
      status('Could not identify the send control. Payload remains held.', true);
      return;
    }
    event.preventDefault(); event.stopImmediatePropagation();
    void inspectAndRelease(button, editor);
  }, true);
  status('Local hold-before-send preview active. Selected attachments are scanned fail-closed; verify site behavior before relying on it.');
})();
