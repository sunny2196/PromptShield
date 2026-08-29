# PromptShield Extension v2 — Real Chrome Extension

Same engine as the Claude simulation, now as a **real Manifest V3 extension** you can load on live public AIs.

### Install (Developer Mode)
1. Open `chrome://extensions`
2. Turn on **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select this folder: `extension/` (the folder containing `manifest.json`)
   - If you cloned from GitHub: `.../PromptShield/extension`
   - If local: `.../promptshield-extension`
5. Pin PromptShield (puzzle icon → pin)

### Where it runs
- `https://claude.ai/*`
- `https://chat.openai.com/*` + `https://chatgpt.com/*`
- `https://gemini.google.com/*`
- `https://perplexity.ai/*`
- `https://copilot.microsoft.com/*`

You will see a **movable shield card** beside the prompt box (drag header to move). Works at 100% zoom without clipping.

### Keys (same as simulation)
- Click the extension popup (toolbar icon) → set **Groq** (`gsk_...`) for Llama 3.2 3B contextual scan + **Gemini** (`AIza...`) for fallback & PromptCowboy boost.
- Toggle **Vault mode** there. Keys stored in `chrome.storage.local` only.

### Demo flow (2 min)
1. Clean prompt → 🟢 Safe
2. Paste `arjun@gmail.com` + `ABCDE1234F` + Tamil `Enoda Aadhaar 1234 5678 9012 da` → 🔴  High-entropy + PAN/Aadhaar + email
3. Click **Vault** → shows `user_4f9k@example.com` format-preserving fake → **Apply safe rewrite**
4. Paste clean prompt again → **Session contaminated** banner (Score 72/100) → Start new chat
5. Drag a **PDF with PAN** onto ChatGPT box → file scan → block
6. `Turn into great prompt` → Groq/Gemini boost

### Files
- `manifest.json` — MV3, host_permissions for AIs + Groq/Gemini
- `src/content.js` — Shadow DOM injection, MutationObserver, paste/file/entropy, session/vault, Groq/Gemini fetch
- `src/popup.html` + `src/popup.js` — settings
- `src/background.js` — service worker
- `public/icons/` — shield icons

No build needed — plain JS. To load, just select the `extension` folder.

### Verify Zero Exfil
Open `chrome://net-internals` or DevTools Network → type in prompt → see no requests unless you added a Groq/Gemini key and triggered LLM scan (then only Groq/Gemini). Offline regex + entropy always local.

