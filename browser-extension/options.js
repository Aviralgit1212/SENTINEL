const gateway = document.getElementById('gateway');
const token = document.getElementById('token');
const status = document.getElementById('status');
chrome.storage.local.get(['gateway', 'pairingToken']).then((settings) => {
  if (settings.gateway) gateway.value = settings.gateway;
  if (settings.pairingToken) token.value = settings.pairingToken;
});
document.getElementById('save').addEventListener('click', async () => {
  const url = gateway.value.trim().replace(/\/$/, '');
  if (!/^http:\/\/(?:127\.0\.0\.1|localhost):\d+$/.test(url)) { status.textContent = 'Only an explicit localhost HTTP gateway is permitted.'; return; }
  if (token.value.length < 32) { status.textContent = 'Use a pairing token of at least 32 characters.'; return; }
  await chrome.storage.local.set({ gateway: url, pairingToken: token.value });
  status.textContent = 'Saved.';
});
