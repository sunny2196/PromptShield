# API Keys — Groq + Gemini

Ultron is **local-first**. Add keys only for contextual LLM + perfect prompt.

## Groq (Recommended — sub-500ms)
1. https://console.groq.com/keys → Create → copy `gsk_...`
2. Extension popup → paste in **Groq** → Save
3. Model `Qwen 2.5 3B` or `Llama 3.2 3B` via Groq `llama-3.2-3b-preview`

## Gemini (Fallback + Boost)
1. https://aistudio.google.com/app/apikey → Create → `AIza...`
2. Paste in **Gemini** → Save
3. Used for `Make prompt perfect` if Groq not set, and as fallback scan.

## Storage
`chrome.storage.local: ps_groq_key, ps_gemini_key, ps_model, ps_vault_mode` — also mirrored to `localStorage` for `http://localhost:3000` sim.

## Verify Zero Exfil
- Without keys: DevTools Network → 0 requests while typing.
- With keys: only `api.groq.com` or `generativelanguage.googleapis.com` when you trigger scan/boost.

