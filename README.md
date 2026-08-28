# PromptShield — Prompt Data-Leak Guard for Public AI Tools (T5.1)

> Grammarly fixed your grammar. PromptShield fixes your privacy before AI remembers you forever.

Browser extension simulation that sits **beside Claude's typing area** as a **movable popup** — scans prompts in real-time before they leave your device. Built on the pixel-perfect Claude dark UI (untouched), with a single draggable extension card.

**Live demo:** `http://localhost:3000` after `npm run dev`

## Why better than Nightfall DLP
[Nightfall DLP for Browser](https://chromewebstore.google.com/detail/nightfall-dlp-for-browser/jgmgecncmjklkabkejnjfgfkglapfgek) scans **after** send with regex only. PromptShield scans **before** send with 3 layers: Regex (<50ms) + Presidio heuristics + **Groq Llama 3.2 3B / Qwen 2.5 3B + Gemini 2.0 Flash via API** for contextual leaks like *“my manager at Infosys said my salary is 12LPA”*. Plus one-click **Redact/Pseudonymize** + **PromptCowboy boost** (“Turn lazy prompts into great ones”).

## Features
- **12 detection types:** Stripe/OpenAI/AWS/GitHub/Slack keys, Aadhaar, PAN, card (Luhn), password, email, phone, internal links, address, salary, medical, person+role
- **Movable single popup:** drag by header, stays in viewport at 100% zoom. Header = green/red status + minimize + settings + hide. No Muse UI tags — feels like installed extension.
- **Before → After diff** with placeholders (`[REDACTED_EMAIL]`) + `Apply safe rewrite`
- **PromptCowboy boost:** Groq + Gemini enhance scrubbed prompt (adds role/goal/format) — `Turn into great prompt` → `Use this`
- **Local-first:** Offline regex works without keys. Add Groq/Gemini keys in gear (or `.env.local`) for AI layer.

## Stack
- Vite + React + Tailwind + Framer Motion (`@google/genai` + Groq `openai/v1/chat/completions`)
- Detection: `src/lib/detection.ts` (scanLocal, scanWithGroq, scanWithLLM, redactText, enhancePrompt)
- Extension UI: `src/components/PromptShield.tsx` (draggable fixed card, settings inline)

## Run Locally
**Prerequisites:** Node.js 18+

```bash
npm install
# add keys (optional but enables AI scan + boost)
cp .env.example .env.local
# VITE_GROQ_API_KEY=gsk_...
# VITE_GEMINI_API_KEY=AIza...
npm run dev    # http://localhost:3000
npm run build
```

Top header stays as **Claude** — extension is strictly beside the composer.

## PRD
See `../PromptShield-PRD.md` for full T5.1 PRD (goals, 3-layer engine, 12 types, architecture, roadmap).

---
Built for Hackathon T5.1 — 100% simulation, no Muse UI mutated.
