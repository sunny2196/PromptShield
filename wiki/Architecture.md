# Architecture — Ultron v2.1

![Arch](https://raw.githubusercontent.com/sunny2196/PromptShield/extension/docs/images/ultron-arch.png)

## Text-only red highlight
Not whole box — only sensitive spans get `background:rgba(255,77,79,.18); border-bottom:1.5px solid #FF4D4F`.
- `textarea` → preview div `ps-sim-highlight` below prompt box
- `contenteditable` → wraps spans in Shadow DOM
- Injected via `findPromptBox()` scoring (size + bottom proximity + placeholder/aria-label)

## Any prompt box
`manifest.json` now:
- `claude.ai`, `chat.openai.com`, `chatgpt.com`, `gemini.google.com`, `aistudio.google.com`, `perplexity.ai`, `poe.com`, `character.ai`, `you.com`, `huggingface.co`
- plus `*://*/*` generic — scores any `textarea`/`[contenteditable]`/`input` with `placeholder`/`aria-label` containing `prompt|ask|message`.

## Stack
- **Regex + entropy** (<50ms): Stripe/AWS/GitHub/Slack, Aadhaar, PAN, UPI, Tamil/Hinglish, `shannonEntropy()>4.5`
- **Presidio heuristics** (<200ms)
- **Groq Llama 3.2 3B / Gemini 2.0 Flash** (on-demand, only if keys set)
- **Session**: `session_id → leaks` in `chrome.storage.local`, `Score=Sensitivity×Exploitability`, `>15` → tainted
- **Vault**: `user_4f9k@example.com`, `sk_live_XXXX_MOCKKEY`, `btoa` vault, `taskPreservationScore()`
- **File**: `dragover`/`drop` on prompt box → `pdf.js`/`Tesseract.js` hooks (offline)

## Movable
`fixed` card at `pos` (`x: w-414, y:96`), `onPointerDown/Move/Up` with `setPointerCapture`, clamped to viewport, `minimized=true` by default (just header red/green).
