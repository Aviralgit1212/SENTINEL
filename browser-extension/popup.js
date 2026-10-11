const gatewayEl = document.getElementById('gateway');
const dot = document.getElementById('dot');
const statusEl = document.getElementById('status');
const pairing = document.getElementById('pairing');
const privacy = document.getElementById('privacy');
const clamav = document.getElementById('clamav');
const msg = document.getElementById('msg');
const activeBadge = document.getElementById('active-badge');

async function refresh() {
  const settings = await chrome.storage.local.get(['gateway', 'pairingToken', 'extensionEnabled']);
  const gateway = typeof settings.gateway === 'string' && settings.gateway
    ? settings.gateway.replace(/\/$/, '')
    : 'http://127.0.0.1:5001';
  const token = typeof settings.pairingToken === 'string' ? settings.pairingToken : '';
  const enabled = settings.extensionEnabled !== false;
  gatewayEl.textContent = gateway;

  activeBadge.textContent = enabled ? 'active' : 'paused';
  activeBadge.className = 'badge ' + (enabled ? 'on' : 'off');

  if (token) {
    pairing.textContent = 'configured';
    pairing.className = 'badge on';
  } else {
    pairing.textContent = 'not set';
    pairing.className = 'badge off';
  }

  dot.className = 'dot wait';
  statusEl.textContent = 'checking…';
  privacy.textContent = '…';
  clamav.textContent = '…';
  msg.textContent = '';

  try {
    const response = await fetch(`${gateway}/api/health`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    dot.className = 'dot ok';
    statusEl.textContent = 'connected';
    if (data.privacyService === 'ok' || data.privacyService === 'ready' || data.privacyService === true) {
      privacy.textContent = 'ready';
      privacy.style.color = '#4ade80';
    } else {
      privacy.textContent = String(data.privacyService ?? 'unknown');
      privacy.style.color = '#fbbf24';
    }
    const clam = data.clamav;
    const clamState = clam === true || clam?.available === true;
    clamav.textContent = clamState ? 'loaded' : 'unavailable';
    clamav.style.color = clamState ? '#4ade80' : '#9ca3af';
  } catch (error) {
    dot.className = 'dot bad';
    statusEl.textContent = 'not connected';
    privacy.textContent = '—';
    clamav.textContent = '—';
    msg.textContent = `Cannot reach ${gateway} — start the Sentinel server first.`;
  }
}

document.getElementById('btn-recheck').addEventListener('click', refresh);
document.getElementById('btn-options').addEventListener('click', () => chrome.runtime.openOptionsPage());

function openPage(url) {
  chrome.tabs.create({ url });
  window.close();
}

document.getElementById('go-options').addEventListener('click', (event) => {
  event.preventDefault();
  chrome.runtime.openOptionsPage();
});
document.getElementById('go-history').addEventListener('click', (event) => {
  event.preventDefault();
  openPage('http://127.0.0.1:5173/');
});
document.getElementById('go-health').addEventListener('click', (event) => {
  event.preventDefault();
  chrome.storage.local.get('gateway').then((settings) => {
    const gateway = typeof settings.gateway === 'string' && settings.gateway
      ? settings.gateway.replace(/\/$/, '')
      : 'http://127.0.0.1:5001';
    openPage(`${gateway}/api/health`);
  });
});

refresh();
