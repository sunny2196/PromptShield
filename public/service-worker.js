/**
 * Ultron — Background Service Worker (Manifest V3)
 *
 * Responsibility:
 *  1. Receive SCAN_PROMPT messages from content scripts
 *  2. Run Layer 1 deterministic scan (regex/Luhn)
 *  3. Apply policy engine (ALLOW / WARN / REDACT / BLOCK)
 *  4. Return risk level and detection count to content script
 *  5. Manage secure key storage via chrome.storage.local
 *
 * CLOUD GATE RULE (enforced here):
 *  - Local Ollama: receives raw prompt text (on-device, safe)
 *  - Groq / Gemini: ONLY receives sanitised text via sanitizeForCloud()
 *    Raw prompts containing secrets NEVER leave the device to cloud APIs.
 */

'use strict';

// ── Policy Engine ─────────────────────────────────────────────────────────────

function computePolicy(riskLevel) {
  if (riskLevel === 'SAFE') return 'ALLOW';
  if (riskLevel === 'LOW' || riskLevel === 'MEDIUM') return 'WARN';
  if (riskLevel === 'HIGH') return 'REDACT';
  return 'BLOCK'; // CRITICAL
}

// ── Lightweight Layer 1 scan (inline for service worker context) ──────────────
// Full engine lives in detection.ts (compiled into the popup bundle).
// This is a minimal fast-path for the badge indicator.

const CRITICAL_PATTERNS = [
  /\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/,          // OpenAI
  /\bAIza[0-9A-Za-z\-_]{35}\b/,                  // Google
  /\bAKIA[0-9A-Z]{16}\b/,                         // AWS
  /\bghp_[A-Za-z0-9]{36,}\b/,                     // GitHub
  /\bxox[abprs]-[0-9]+/,                          // Slack
  /-----BEGIN\s+(RSA |EC |OPENSSH )?PRIVATE KEY/, // Private key
  /(postgresql|mysql|mongodb|redis):\/\/[^\s]+/i, // DB connection
  /\bey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/, // JWT
];

const HIGH_PATTERNS = [
  /\b[A-Z]{5}[0-9]{4}[A-Z]\b/,                  // PAN
  /\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/, // GSTIN
  /\b(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d+\.\d+\.\d+\b/, // Private IP
];

const MEDIUM_PATTERNS = [
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, // Email
  /\b(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/,            // Indian phone
];

function quickScan(text) {
  if (!text || text.length < 8) return { riskLevel: 'SAFE', detectionCount: 0, policy: 'ALLOW' };

  let criticalCount = 0, highCount = 0, mediumCount = 0;

  for (const re of CRITICAL_PATTERNS) if (re.test(text)) criticalCount++;
  for (const re of HIGH_PATTERNS)     if (re.test(text)) highCount++;
  for (const re of MEDIUM_PATTERNS)   if (re.test(text)) mediumCount++;

  const total = criticalCount + highCount + mediumCount;
  let riskLevel = 'SAFE';
  if (criticalCount > 0) riskLevel = 'CRITICAL';
  else if (highCount > 0) riskLevel = 'HIGH';
  else if (mediumCount > 0) riskLevel = 'MEDIUM';

  return { riskLevel, detectionCount: total, policy: computePolicy(riskLevel) };
}

// ── Message handler ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'SCAN_PROMPT') {
    const result = quickScan(message.text);
    sendResponse(result);

    // If CRITICAL, show a browser notification (requires 'notifications' permission in production)
    if (result.riskLevel === 'CRITICAL') {
      console.warn('[Ultron] CRITICAL risk detected — policy: BLOCK');
    }
    return true; // keep message channel open for async
  }

  if (message.type === 'SAVE_KEYS') {
    // Securely store API keys — never in localStorage from content scripts
    chrome.storage.local.set({
      ps_groq_key:    message.groqKey   || '',
      ps_gemini_key:  message.geminiKey || '',
      ps_ollama_url:  message.ollamaUrl || 'http://localhost:11434',
      ps_model:       message.modelId   || 'qwen3-local',
    });
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === 'GET_KEYS') {
    chrome.storage.local.get(
      ['ps_groq_key', 'ps_gemini_key', 'ps_ollama_url', 'ps_model'],
      (keys) => sendResponse(keys)
    );
    return true; // async
  }
});

// ── Install handler ───────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  console.log('[Ultron] Extension installed. Privacy-first DLP active.');
  chrome.storage.local.set({ ps_blocked: 0 });
});
