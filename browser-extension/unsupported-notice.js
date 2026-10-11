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
    banner.style.cssText = 'position:fixed;top:12px;left:50%;transform:translateX(-50%);z-index:2147483647;max-width:min(620px,calc(100vw - 24px));padding:12px 16px;border-radius:10px;background:#78350f;color:#fff;font:14px/1.45 system-ui,sans-serif;box-shadow:0 4px 20px rgba(0,0,0,.28);display:flex;gap:14px;align-items:center';
    const text = document.createElement('span');
    text.textContent = 'Sentinel: This website is outside the protected AI chat sites. Hold-before-send protection may not be active here.';
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = 'Dismiss';
    close.setAttribute('aria-label', 'Dismiss Sentinel unsupported-site notice');
    close.style.cssText = 'border:0;border-radius:5px;padding:6px 9px;background:#fff;color:#422006;cursor:pointer;white-space:nowrap';
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
