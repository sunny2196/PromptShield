 * Ultron — Content Script (Manifest V3)
 * Injected into: claude.ai, chat.openai.com, gemini.google.com
 *
 * Responsibility:
 *  1. Intercept textarea keyup / input events on the AI composer
 *  2. Run the local DLP scan (Layer 1 regex + contextual)
 *  3. Post results to the background service worker for policy evaluation
 *  4. Show inline risk indicator beside the submit button
 *
 * NOTE: The heavy detection engine (detection.ts) is bundled separately
 * and imported as a module. This stub shows the integration pattern.
 */

'use strict';

// ── Platform adapters ────────────────────────────────────────────────────────
// Each platform has a different selector for the prompt composer textarea.

const PLATFORM_SELECTORS = {
  'claude.ai':          '[data-testid="composer-input"], .ProseMirror',
  'chat.openai.com':    '#prompt-textarea',
  'gemini.google.com':  '.ql-editor, [contenteditable="true"]',
};

// ── Find the active prompt composer ─────────────────────────────────────────

function findComposer() {
  const host = window.location.hostname;
  const selector = PLATFORM_SELECTORS[host] || 'textarea';
  return document.querySelector(selector);
}

// ── Risk badge injection ─────────────────────────────────────────────────────

function getRiskBadge() {
  let badge = document.getElementById('ultron-badge');
  if (!badge) {
    badge = document.createElement('div');
    badge.id = 'ultron-badge';
    badge.style.cssText = [
      'position:fixed', 'bottom:80px', 'right:20px', 'z-index:99999',
      'background:#171719', 'border:1px solid #2E2E32', 'border-radius:24px',
      'padding:6px 12px', 'font-family:Inter,sans-serif', 'font-size:12px',
      'font-weight:650', 'color:#A1A1AA', 'cursor:pointer',
      'box-shadow:0 4px 16px rgba(0,0,0,0.5)', 'transition:all .2s',
    ].join(';');
    badge.textContent = '🛡 Ultron — Watching';
    document.body.appendChild(badge);
  }
  return badge;
}

function updateBadge(riskLevel, detectionCount) {
  const badge = getRiskBadge();
  const styles = {
    CRITICAL: { bg: '#5A0000', border: '#FF4C4C', color: '#FF8389', text: `🔴 CRITICAL — ${detectionCount} risks detected` },
    HIGH:     { bg: '#7A1A1A', border: '#FF8389', color: '#FCA5A5', text: `🟠 HIGH — ${detectionCount} detected` },
    MEDIUM:   { bg: '#5E4A1A', border: '#FEC57E', color: '#FDE68A', text: `🟡 MEDIUM — ${detectionCount} detected` },
    LOW:      { bg: '#0F3020', border: '#42BE65', color: '#A7F0BA', text: `🟢 LOW — ${detectionCount} detected` },
    SAFE:     { bg: '#171719', border: '#2E2E32', color: '#A1A1AA', text: '🛡 Ultron — Safe' },
  };
  const s = styles[riskLevel] || styles.SAFE;
  badge.style.background = s.bg;
  badge.style.borderColor = s.border;
  badge.style.color = s.color;
  badge.textContent = s.text;
}

// ── Main scan loop ───────────────────────────────────────────────────────────

let debounceTimer;

function onInput(event) {
  const text = event.target.value || event.target.innerText || '';
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    // Send text to service worker for DLP evaluation
    chrome.runtime.sendMessage(
      { type: 'SCAN_PROMPT', text },
      (response) => {
        if (chrome.runtime.lastError) return;
        if (response) {
          updateBadge(response.riskLevel, response.detectionCount);
        }
      }
    );
  }, 280);
}

// ── Attach listeners ─────────────────────────────────────────────────────────

function attach() {
  const composer = findComposer();
  if (composer) {
    composer.addEventListener('input', onInput);
    composer.addEventListener('keyup', onInput);
    getRiskBadge(); // initialise badge
    console.log('[Ultron] Attached to composer:', composer);
  } else {
    // Composer not yet in DOM — watch for it
    const observer = new MutationObserver(() => {
      const el = findComposer();
      if (el) {
        observer.disconnect();
        el.addEventListener('input', onInput);
        el.addEventListener('keyup', onInput);
        getRiskBadge();
        console.log('[Ultron] Attached to composer (delayed):', el);
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }
}

attach();
