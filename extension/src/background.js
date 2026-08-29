// PromptShield — service worker (minimal, keeps extension alive, proxies if needed)
chrome.runtime.onInstalled.addListener(() => {
  console.log('[PromptShield] installed v2.0');
});
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'PS_PING') sendResponse({ ok: true, version: '2.0' });
  return true;
});
