# Ultron — Related Solutions & Adjacent Market Map

> **Why Ultron isn't "just an extension".** The engine is a *trust layer between any human and any AI*. The same scanner, vault, and session graph solve 5 adjacent problems at $3.5B+ adjacent TAM. Shipped feature first, ship the rest 2–12 months later from the same codebase.

---

## The Engine (one codebase, six products)

```
┌────────────────────────────────────────────────────────────────────┐
│  Ultron Core (this repo)                                           │
│  ├─ Detection: regex + entropy + Presidio + LLM (Groq/Gemini)     │
│  ├─ Session Contamination Graph (session_id → leaks, score)        │
│  ├─ Vault: format-preserving tokenization + AES-obscured store     │
│  ├─ File: Tesseract.js / pdf.js WASM hooks (offline OCR)           │
│  └─ UI: Shadow DOM draggable pill + sidecar (no host page edit)   │
└────────────────────────────────────────────────────────────────────┘
              ↓ ships into 6 surfaces, no engine rewrite
```

---

## 1. Ultron for Individuals (Shipped — `extension/` v2.1)

**Surface:** Chrome extension. Any prompt box (`*://*/*` + claude.ai/chatgpt.com/gemini.google.com/aistudio.google.com/perplexity.ai/poe/character.ai/you.com/huggingface.co).

**Solves:** Samsung-style leaks, DPDP Act 2023 compliance for individuals, student Aadhaar paste.

**Pricing:** Free forever for vault OFF + regex. **Pro ₹99/mo** for vault ON + session alerts + Make perfect prompt + file drop.

**TAM:** 100M+ AI users in India. ₹2,000–₹3,000 cr/yr.

**Status:** ✅ Shipped. README + wiki + docs in `extension/` branch.

---

## 2. Ultron for Teams (Next — Month 3–4)

**Surface:** Admin dashboard. Browser extension + Slack/Teams alert when a team member has a session contamination event.

**Solves:** Manager sees: "Ranjith pasted `OPENAI_API_KEY=sk-...` 3 times today in `chatgpt.com`. Session 78/100 tainted." Drift-style dashboard for AI hygiene.

**Pricing:** ₹999/mo per seat (min 5 seats). Annual ₹10k/yr per seat.

**Differentiator:** No enterprise DLP catches this — they scan post-send network traffic. We catch at the *typing boundary* on the *client*.

**Build:** Same extension + Firebase/Supabase backend for leak metadata (anonymized), Slack incoming webhook, dashboard at `app.ultron.so`.

---

## 3. Ultron Compliance Mode (Month 5–6 — for regulated industries)

**Surface:** Same extension + audit log + signed receipts.

**Solves:** DPDP Act 2023 §8, EU AI Act Art. 12, HIPAA — prove consent before personal data enters AI.

**Differentiator:** **Hashed audit trail** — when user pastes PII, log a signed receipt (timestamp + hash of span + type) to `chrome.storage.local` AND optional encrypted cloud. Auditors can verify *what data was attempted to leave, when, and by whom*. No other tool does this for AI specifically.

**Pricing:** ₹50k–₹2L/yr per org. SOC2 Type I by month 9.

**Industries:**
- **Health**: Dr. Meera, dermatologist, 200k+ clinics in India. Packs: ICD-10, MRN, prescription drug names.
- **Legal**: Indian law firms. Packs: case numbers, court orders, client names.
- **Finance**: CA/CFA/CS. Packs: PAN, GSTIN, IFSC, account numbers.
- **BPO/KPO**: 5M+ employees, regulated by RBI/MeitY. Packs: customer PII patterns.

---

## 4. Ultron for Source Code (Month 4–5 — VS Code / JetBrains / Cursor)

**Surface:** IDE plugin. Scans as you type, before commit. Same engine, new adapter.

**Solves:** Hardcoded API keys in `.env` files. Existing tools (GitGuardian, TruffleHog) only catch *after* `git push`. We catch *as you type* — like spell-check for secrets.

**Differentiator:** **Real-time at write-time** + India pack (`AKIA`+PAN combos, internal `atlassian.net/wiki/...` URLs).

**Pricing:** Free for OSS. ₹99/mo per dev for pro. Team plan ₹4,999/mo per org (50 seats).

**Build:** VS Code extension manifest.json + TreeView for live scanner. Same `scanLocal()` engine, different UI.

---

## 5. Ultron Local (Month 7–9 — for on-prem)

**Surface:** Desktop agent (Electron or Tauri). All inference local, no network.

**Solves:** Banks, defence, healthcare orgs that ban cloud. Same UI, vault, session contamination — but everything stays on the device. Bundle Llama 3B (Q4) WASM or Ollama backend.

**Differentiator:** **Zero network calls by architecture, not by promise.** Network tab shows 0 even with developer tools open.

**Pricing:** ₹2L–₹10L/yr per org depending on seats. Plus per-seat.

**Build:** Electron wrapper around existing extension, default to local-only inference, optional audit log sync.

---

## 6. Ultron for LLM Providers (Month 10–12 — API)

**Surface:** 1-line SDK at the inference boundary. Server-side.

**Solves:** LLM providers (OpenAI, Anthropic, Google) need to give enterprise customers a "this prompt was scanned" guarantee. Today they can't.

**Differentiator:** **Embedded at inference** — provider charges customer for the "AI prompt hygiene" guarantee. We become B2B2C. Every ChatGPT call from a regulated industry can route through Ultron.

**Pricing:** $0.001 per scan. At 10B queries/day global, $10M/day TAM. We take 50% of that.

**Build:** FastAPI service, model-agnostic, latency <50ms, on-device PII hashing for the receipt.

---

## 7. Ultron for Open Source (Free, Forever)

**Surface:** `git pre-commit` hook (`pip install ultron-hook`). Free, open-source.

**Solves:** Vendor repos leak internal URLs, Aadhaar, customer names during dev. We strip before commit.

**Differentiator:** `vaultTokenize()` on `git diff` before commit. Catches what humans forget.

**Pricing:** Free. Drive brand awareness. Every OSS dev who uses it = future enterprise buyer.

**Build:** Python wrapper around `src/lib/vault.ts` logic. PyPI: `ultron-vault`.

---

## 8. The 6-Surface Build Sequence

| Quarter | Surface | Goal | Revenue target |
|---|---|---|---|
| Q1 | Individual extension (Pro) | 10k users, 100 paying | ₹1.2L/mo |
| Q2 | Teams + IDE | 50 teams, 1k paid | ₹2L/mo |
| Q3 | Compliance mode | 25 enterprise | ₹25L/mo |
| Q4 | Local + API + OSS | 500k users, 1M ARR | ₹85L/mo |

---

## 9. What we DO NOT build (anti-roadmap)

To stay sharp:
- ❌ Generic enterprise DLP (Nightfall wins here, no moat)
- ❌ Network-only scanning (we're better at client)
- ❌ Output-side content moderation (Guardrails, Lakera win)
- ❌ Cloud-only deployment (our moat is local-first)
- ❌ Generic AI security (we focus on *prompt leak*)

---

## 10. The Thesis

> **The next 100M+ Indians will use AI daily. 1% of them will accidentally leak Aadhaar, PAN, or a key every month. Existing tools don't help individuals. Ultron does — for free.**
>
> **Solved today in `extension/` v2.1. Build the 6 adjacent products in 12 months. ₹2,000–₹3,000 cr TAM in India alone, $3.5B+ globally.**

See [MARKET-VALIDATION.md](./MARKET-VALIDATION.md), [Architecture](https://github.com/sunny2196/PromptShield/wiki/Architecture).
