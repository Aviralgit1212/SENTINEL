// Uninvited-site notice: this script's sole job is a one-time-per-page notice.
(() => {
  if (window.location.protocol !== 'http:' && window.location.protocol !== 'https:') return;
  // Never run on the gateway itself or the dev dashboard.
  const host = window.location.hostname;
  if (host === '127.0.0.1' || host === 'localhost') return;

  const key = 'sentinelUnsupportedNoticeShown';
  try {
    if (sessionStorage.getItem(key) === '1') return;
    sessionStorage.setItem(key, '1');
  } catch (_) {
    // If page storage is unavailable, still show this one notice.
  }

  function showBanner() {
    const banner = document.createElement('aside');
    banner.setAttribute('role', 'status');
    banner.style.cssText = 'position:fixed;top:12px;left:50%;transform:translateX(-50%);z-index:2147483647;max-width:min(620px,calc(100vw - 24px));padding:12px 16px;border-radius:12px;background:rgba(5,8,13,.78);border:1px solid rgba(148,190,240,.2);backdrop-filter:blur(16px) saturate(1.4);-webkit-backdrop-filter:blur(16px) saturate(1.4);color:#eaf2fc;font:13.5px/1.45 system-ui,sans-serif;box-shadow:0 14px 36px rgba(2,6,14,.5),inset 0 1px 0 rgba(255,255,255,.06);display:flex;gap:14px;align-items:center;color:#ffd479';
    const text = document.createElement('span');
    text.textContent = 'Sentinel: This website is outside the protected AI chat sites. Hold-before-send protection may not be active here.';
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = 'Dismiss';
    close.setAttribute('aria-label', 'Dismiss Sentinel unsupported-site notice');
    close.style.cssText = 'border:1px solid rgba(148,190,240,.25);border-radius:7px;padding:6px 11px;background:rgba(148,190,240,.08);color:#eaf2fc;cursor:pointer;white-space:nowrap;font-size:12.5px';
    close.addEventListener('click', () => banner.remove());
    banner.append(text, close);
    (document.body || document.documentElement).appendChild(banner);
    setTimeout(() => { if (banner.isConnected) banner.remove(); }, 10000);
  }

  if (document.body || document.documentElement) {
    showBanner();
  } else {
    document.addEventListener('DOMContentLoaded', showBanner, { once: true });
  }
})();
