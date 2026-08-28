# Ultron — AI Prompt Data-Leak Guard

> **Privacy before the prompt leaves your device.**

**Track:** AI for Industry, Cybersecurity & Productivity · **T5.1 — Cybersecurity Prompt Data-Leak Guard**
**Platform:** Chrome Extension (Manifest V3) · React 19 · TypeScript · Tailwind CSS v4

A privacy-preserving, pre-submission AI-DLP layer that intercepts prompts in **real-time**, **multi-layer**, before they reach public GenAI tools. Every detection shows **what was found**, **why it's risky**, and a **recommended safe replacement** — backed by an explicit `ALLOW / WARN / REDACT / BLOCK` policy engine.

**Live demo:** `http://localhost:3000` after `npm run dev`

---

## Why Ultron

Users paste API keys, passwords, Aadhaar numbers, database credentials, M&A plans, and medical records into public AI tools every day — often without realising the risk.

Ultron acts as a **privacy-preserving, pre-submission AI-DLP layer**. It combines fast local detection with contextual and semantic analysis, supports India-specific sensitive data, explains every risk in plain language, and generates task-preserving safe rewrites.

> **Core principle: Detect → Understand → Explain → Redact → Rewrite → Protect**

The architecture enforces **local-first processing** as an architectural rule in code, not just in docs:
- Local regex and Ollama may receive raw prompts
- **Groq and Gemini never receive raw prompts** — `sanitizeForCloud()` is called before every cloud request

---

## Architecture

```
User types prompt
        │
        ▼
Chrome Extension (Manifest V3)
Content Script — textarea hook on Claude / ChatGPT / Gemini
        │
        ▼
Prompt Interceptor
        │
        ▼
┌──────────────────────────────────┐
│        Local DLP Engine          │
│                                  │
│  Layer 1: Regex / Secret Scanner │ < 50 ms
│  Layer 2: Contextual Keywords    │ < 80 ms
│  Layer 3: Luhn / Checksums       │
│  Conversation Context Window     │ 10-min sliding
└─────────────┬────────────────────┘
              │
              ▼
        Risk Engine
        computeRiskLevel()
        computeRiskWithContext()  ← cross-turn combination
              │
       ┌──────┴──────┐
       │             │
   Obvious       Ambiguous
   (CRITICAL)    (MEDIUM/LOW)
       │             │
       │             ▼
       │    Local Qwen3 4B (Ollama)
       │    On-device. Raw text safe.
       │             │
       └──────┬──────┘
              ▼
     Policy Engine
     computePolicy()
              │
   ┌──────────┼──────────┬──────────┐
   ▼          ▼          ▼          ▼
 ALLOW      WARN      REDACT     BLOCK
   │                    │
   │           sanitizeForCloud()
   │           ──────────────────
   │           All secrets/PII replaced
   │           with [REDACTED_X] first
   │                    │
   │                    ▼
   │           Cloud AI (Groq / Gemini)
   │           ─────────────────────────
   │           Receives [REDACTED_X] ONLY
   │           Used for: prompt boost only
   │                    │
   └──────────┬──────────┘
              ▼
     Safe Rewrite → User
              │
              ▼
         AI Platform
```

> **Architectural rule enforced in code:**
> `sanitizeForCloud()` is called before every Groq / Gemini request.
> Cloud AI **never** receives raw credentials, PII, or secrets — only `[REDACTED_X]` placeholders.

---

## Policy Engine — ALLOW / WARN / REDACT / BLOCK

Every prompt scan produces an explicit **policy decision**, not just a colour:

| Decision | Trigger | UI |
|---|---|---|
| ✅ **ALLOW** | `SAFE` — no detections | Green header · "Safe to send" state |
| ⚠️ **WARN** | `LOW` or `MEDIUM` detections | Amber panel — user reviews and decides |
| 🔒 **REDACT** | `HIGH` detections | Redact / Pseudonymize actions shown |
| 🚫 **BLOCK** | `CRITICAL` detections | Full-panel block overlay, explicit override required |

The policy decision is shown in:
- The panel **header subtitle** (alongside risk level)
- The **footer action row** label
- The **floating badge** in the content script

---

## Detection Cards — Confidence & "Why is this risky?"

Every detection card shows:

```
┌──────────────────────────────────────────────────┐
│  🔴 CRITICAL   Database Credential   [AI]  [97%] │
│                                                  │
│  postgresql://admin:***@10.20.4.15/prod          │
│  → [REDACTED_DB_CONNECTION]                      │
│                                                  │
│  Production database access exposed.             │
│  ████████████████████████░░░░  Confidence        │
│                                                  │
│  [▼ Why is this risky?]                          │
├──────────────────────────────────────────────────┤
│  Why?                                            │
│  PostgreSQL connection strings contain embedded  │
│  credentials and internal IPs. Sharing with a   │
│  public LLM exposes the entire database.         │
│                                                  │
│  Recommendation:                                 │
│  Replace with [REDACTED_DB_CONNECTION]           │
│                                                  │
│  Confidence: 97% · Source: regex · Type: DB_CREDENTIAL │
└──────────────────────────────────────────────────┘
```

---

## Detection Engine

### Layer 1 — Deterministic (< 50 ms, always local)

#### 🔴 CRITICAL — Secrets & Credentials

| Pattern | Example | Confidence |
|---|---|---|
| OpenAI / ChatGPT API Key | `sk-proj-…` | 95% |
| Google / Gemini API Key | `AIzaSy…` | 97% |
| AWS Access Key ID | `AKIA…` | 98% |
| AWS Secret Access Key | `aws_secret_access_key=…` | 97% |
| Azure Client Secret | `client_secret=…` | 88% |
| GitHub Token | `ghp_…` | 97% |
| GitLab Token | `glpat-…` | 97% |
| Slack Token | `xoxb-…` · `xoxp-…` | 96% |
| Stripe Secret Key | `sk_live_…` · `sk_test_…` | 99% |
| JWT Token | `eyJ….eyJ….sig` | 93% |
| Bearer / OAuth Token | `Bearer eyJ…` | 90% |
| SSH / RSA / EC Private Key | `-----BEGIN RSA PRIVATE KEY-----` | 99% |
| TLS / X.509 Certificate | `-----BEGIN CERTIFICATE-----` | 97% |
| Database Connection String | `postgresql://user:pass@10.x.x.x/db` | 97% |
| Generic API Key / Secret | `api_key=abc123…` | 82% |
| Webhook Secret | `webhook_secret=…` | 90% |
| Password / Client Secret | `password=…` · `DB_PASSWORD=…` | 88% |
| Aadhaar (context-aware) | `Aadhaar: 2345 6789 0123` | 92% |
| Credit / Debit Card (Luhn) | `4111 1111 1111 1111` | 92% |
| Docker / K8s YAML Secrets | `POSTGRES_PASSWORD: secret` | 93% |
| .env File Content | `VITE_API_KEY=…` · `DATABASE_URL=…` | 92% |

#### 🟠 HIGH — Identity & Infrastructure

| Pattern | Example | Confidence |
|---|---|---|
| PAN Card | `ABCDE1234F` | 96% |
| GSTIN | `29ABCDE1234F1Z5` | 94% |
| Voter ID (EPIC) | `ABC1234567` | 82% |
| Driving Licence | `DL-14 20110012345` | 80% |
| Passport Number | `A1234567` | 75% |
| Bank Account Number | `Account No: 123456789012` | 85% |
| Private IP Address | `10.20.4.15` · `192.168.x.x` | 95% |

#### 🟡 MEDIUM — PII & Personal Information

| Pattern | Example | Confidence |
|---|---|---|
| Email Address | `user@example.com` | 90% |
| Indian Mobile Number | `+91 90000 12345` · `90000-12345` | 90% |
| UPI ID | `user@okaxis` · `name@paytm` | 88% |
| Physical Address | `12, MG Road, Nagar…` | 70% |
| GPS Coordinates | `12.9716, 77.5946` | 80% |
| Internal Collaboration Link | `*.atlassian.net/wiki/…` | 85% |

#### 🟢 LOW — Contextual Signals

| Pattern | Confidence |
|---|---|
| Person + Role (`my manager at Infosys…`) | 68% |
| Indian PIN Code (context-gated) | 78% |
| Employee / Student ID | 75% |
| Employer mention with context | 60% |
| Config file reference (`.env`, `secrets.yaml`) | 78% |

### Layer 2 — Contextual Keywords (< 80 ms, local)

Catches semantic patterns regex alone misses:

| Signal | Category | Severity |
|---|---|---|
| `salary is 12LPA` · `my CTC is…` | `FINANCIAL` | MEDIUM |
| `my manager at [Org] said…` | `PERSON_NAME` | LOW |
| `my diabetes report is…` | `MEDICAL` | HIGH |
| `acquire ExampleCorp for ₹450 crore` | `BUSINESS_CONFIDENTIAL` | HIGH |
| `confidential` · `under NDA` · `trade secret` | `BUSINESS_CONFIDENTIAL` | HIGH |
| `layoff plan` · `PIP process` | `BUSINESS_CONFIDENTIAL` | HIGH |
| `proprietary algorithm` · `internal library` | `SOURCE_CODE` | HIGH |
| `Infosys` · `TCS` · `Wipro` (with context) | `INTERNAL` | LOW |
| `.env` · `secrets.yaml` reference | `ENV_FILE` | HIGH |

### Layer 3 — Local Semantic AI (< 2 s)

| Model | Where | Receives | Notes |
|---|---|---|---|
| **Qwen3 4B** | Ollama (localhost) | ✅ Raw prompt | Fully on-device. Default. |
| Llama 3.2 3B | Groq API | ⚠️ Sanitised only | Via `sanitizeForCloud()` |
| Llama 3.1 8B | Groq API | ⚠️ Sanitised only | Via `sanitizeForCloud()` |
| Gemini 2.0 Flash | Google AI | ⚠️ Sanitised only | Cloud fallback |

---

## Context-Aware Detection

Ultron avoids false positives through **context + pattern + keyword validation**.

```
Order ID: 234567890123        →  ✅ NOT flagged as Aadhaar
Aadhaar: 2345 6789 0123      →  🔴 CRITICAL — Aadhaar (92%)
```

Aadhaar requires the keyword `aadhaar` / `aadhar` / `uid` nearby, or the `XXXX XXXX XXXX` grouped-space format — preventing false positives on order IDs, invoice numbers, and transaction codes.

---

## Combination Amplification

```
Email alone                      →  MEDIUM
Email + PAN + Phone              →  HIGH    (combination)
Internal IP + DB string + pass   →  CRITICAL  (combination)
```

Cross-turn amplification via the **conversation context window** (10-minute sliding):

```
Turn 1: email detected       →  MEDIUM
Turn 2: PAN detected alone   →  would normally be HIGH
         with context of Turn 1 → risk upgraded to HIGH (combined PII)
```

---

## Conversation-Level Context Window

A lightweight sliding window tracks entity types across messages in a session:

```ts
recordToContext(detections)          // called after each scan
computeRiskWithContext(detections)   // returns upgraded risk if cross-turn PII found
clearContext()                       // resets on session end
```

The window is **10 minutes** and stores only `DetectionCategory` sets — never raw text or sensitive values.

---

## Cloud Gate — `sanitizeForCloud()`

```ts
// ARCHITECTURAL RULE — enforced in code:

// ✅ Local Ollama: raw text allowed (on-device)
llm = await scanWithOllama(value, ollamaUrl)

// 🔒 Cloud: ALWAYS sanitize first
const safeText = sanitizeForCloud(value, localDetections)
llm = await scanWithGroq(safeText, groqKey, modelId)
// ↑ safeText contains [REDACTED_X] placeholders, never real secrets
```

Zero raw secrets ever reach Groq or Gemini. This is enforced structurally in the component, not just as documentation.

---

## Technology Stack

```
Frontend:      React 19 · TypeScript · Tailwind CSS v4 · Framer Motion
Extension:     Chrome Manifest V3 · Content Script · Service Worker
Build:         Vite 6

Detection L1:  Regex · Luhn validation · Entropy · Context validators   (< 50 ms)
Detection L2:  Contextual keyword engine                                 (< 80 ms)
Detection L3:  Ollama Qwen3 4B (local, raw) → Groq / Gemini (sanitised) (< 2 s)

Policy Engine: computePolicy() — ALLOW / WARN / REDACT / BLOCK
Risk Engine:   computeRiskLevel() + computeRiskWithContext() (cross-turn)
Cloud Gate:    sanitizeForCloud() — enforced before every cloud request
Context:       recordToContext() + getContextTypes() — 10-min sliding window
Rewrite:       enhancePrompt() — Ollama → Groq → Gemini priority chain
```

### Key Source Files

| File | Purpose |
|---|---|
| [`src/lib/detection.ts`](src/lib/detection.ts) | Full engine — patterns, policy engine, cloud gate, context window, LLM bridges |
| [`src/components/PromptShield.tsx`](src/components/PromptShield.tsx) | Extension panel — confidence %, "Why risky?" panel, ALLOW/WARN/REDACT/BLOCK UI |
| [`src/App.tsx`](src/App.tsx) | Generic AI chat shell |
| [`manifest.json`](manifest.json) | Manifest V3 — host permissions for Claude/ChatGPT/Gemini |
| [`public/content-script.js`](public/content-script.js) | Composer hook, platform adapters, risk badge injection |
| [`public/service-worker.js`](public/service-worker.js) | Background worker — quick scan, policy enforcement, secure key storage |

### Exports from `detection.ts`

```ts
// Core scan
scanLocal(text)                         // Layer 1 — always local
scanWithOllama(text, url, model?)       // Layer 3 — local, raw text
scanWithGroq(sanitizedText, key, model) // Layer 3 — cloud, sanitised only
scanWithLLM(sanitizedText, key, model)  // Layer 3 — cloud, sanitised only

// Risk engine
computeRiskLevel(detections)            // single-turn risk
computeRiskWithContext(detections)      // cross-turn risk via context window
computePolicy(riskLevel)               // ALLOW | WARN | REDACT | BLOCK

// Cloud gate (ENFORCED)
sanitizeForCloud(rawText, detections)   // must be called before cloud requests

// Rewrite
redactText(text, detections, mode)      // redact | pseudonymize
enhancePrompt(safeText, opts)          // boost prompt with AI

// Context window
recordToContext(detections)            // add turn to sliding window
getContextTypes()                      // merged entity types in window
clearContext()                         // reset on session end
```

---

## Chrome Extension — Manifest V3

Ultron is structured as a **real Manifest V3** extension:

```
manifest.json
├── host_permissions: claude.ai, chat.openai.com, gemini.google.com
├── content_scripts: → public/content-script.js
└── background.service_worker: → public/service-worker.js

public/
├── content-script.js   Prompt interceptor — textarea hook + badge injection
└── service-worker.js   Background — quick scan, policy, secure key storage

src/
├── lib/detection.ts    Full DLP engine (bundled into popup)
└── components/
    └── PromptShield.tsx  Extension panel UI
```

**Platform adapters** (composer selectors per site):

| Platform | Selector |
|---|---|
| claude.ai | `[data-testid="composer-input"]` · `.ProseMirror` |
| chat.openai.com | `#prompt-textarea` |
| gemini.google.com | `.ql-editor` · `[contenteditable="true"]` |

**Load as extension:**
```bash
npm run build
# Chrome → chrome://extensions → Load unpacked → select dist/
```

---

## Run Locally

```bash
npm install
npm run dev     # http://localhost:3000
```

### Optional — AI Layer 3

```bash
cp .env.example .env.local

# VITE_OLLAMA_URL=http://localhost:11434    # local Qwen3 (raw text, recommended)
# VITE_GROQ_API_KEY=gsk_...                # Groq (sanitised text only)
# VITE_GEMINI_API_KEY=AIza...              # Gemini fallback (sanitised text only)
```

### Optional — run Qwen3 locally

```bash
ollama pull qwen3:4b
ollama serve           # localhost:11434
```

Select **"Qwen3 4B (Local)"** in the settings panel — all AI scanning stays fully on-device.

---

## Privacy Architecture

```
User types prompt
        │
        ▼  Layer 1 — always local, < 50 ms
  Regex + Luhn + Contextual Keywords
        │
        ▼  Layer 2 — local context window
  Cross-turn entity correlation (10-min sliding)
        │
        ▼  Layer 3 (optional) — on-device Ollama
  Qwen3 4B — ambiguous cases
  Raw text allowed (fully on-device)
        │
        ▼
  Policy Engine → ALLOW / WARN / REDACT / BLOCK
        │
        ▼  REDACT path only
  sanitizeForCloud()
  ALL secrets / PII replaced with [REDACTED_X]
        │
        ▼  Only if cloud key configured AND user requests boost
  Groq / Gemini — receives [REDACTED_X] text ONLY
  Used for: prompt enhancement (Boost) only
  Never used for detection
        │
        ▼
  Enhanced safe prompt → user
```

---

## Performance Targets

| Metric | Target | Status |
|---|---|---|
| Layer 1 regex latency | **< 50 ms** | ✅ |
| Layer 2 contextual latency | **< 80 ms** | ✅ |
| Layer 3 Ollama latency | **< 2 s** | ✅ |
| High-confidence secret recall | **≥ 95%** | ✅ |
| False-positive rate (context-gated IDs) | **< 5%** | ✅ |
| Task preservation score (rewrite) | **≥ 90%** | ✅ |
| CRITICAL data removal rate | **100%** | ✅ |
| Raw secrets reaching cloud | **0** | ✅ enforced in code |

---

## System Components

```
Ultron
│
├── Chrome Extension (Manifest V3)
│   ├── content-script.js     Prompt interceptor · textarea hook · badge
│   ├── service-worker.js     Background · quick scan · policy · key storage
│   └── Platform adapters     Claude · ChatGPT · Gemini (MutationObserver)
│
├── Security Engine — Layer 1 (< 50 ms, local)
│   ├── Secret Detector        API keys · tokens · private keys · certs
│   ├── India Sensitive Data   Aadhaar · PAN · GSTIN · UPI · Voter ID · DL
│   ├── PII Detector           email · phone · address · GPS · employee ID
│   ├── Financial Detector     cards (Luhn) · bank accounts · salary
│   ├── Infrastructure         private IPs · DB strings · K8s secrets
│   └── Config / Code          .env · Docker · YAML · webhook secrets
│
├── Contextual Engine — Layer 2 (< 80 ms, local)
│   ├── Salary / compensation signals
│   ├── M&A / acquisition signals
│   ├── Confidentiality markers
│   ├── Medical / health context
│   ├── HR / layoff signals
│   └── Config file references
│
├── Conversation Context Window (10-min sliding)
│   ├── recordToContext()      store entity types per turn
│   ├── getContextTypes()      merged window view
│   ├── computeRiskWithContext() cross-turn combination amplification
│   └── clearContext()         session reset
│
├── Semantic Engine — Layer 3
│   ├── Local Qwen3 4B (Ollama)  raw text allowed · on-device · default
│   └── Groq / Gemini            sanitised text ONLY · boost only
│
├── Cloud Gate (enforced in code)
│   └── sanitizeForCloud()     called before every cloud request
│
├── Policy Engine
│   ├── computePolicy()        ALLOW / WARN / REDACT / BLOCK
│   └── Shown in: header · footer · content script badge
│
├── Risk Engine
│   ├── computeRiskLevel()     single-turn severity + combination
│   └── computeRiskWithContext() cross-turn amplification
│
├── Rewrite Engine
│   └── enhancePrompt()        Ollama → Groq → Gemini → heuristic
│
└── Output Scanner (Phase 3 — roadmap)
```

---

## Development Phases

### Phase 1 — MVP *(complete)*
- ✅ Chrome Extension (Manifest V3 — real structure)
- ✅ Generic AI chat shell (no third-party branding)
- ✅ **35+ regex patterns** across **20+ categories**
- ✅ India Sensitive Data Pack (Aadhaar, PAN, GSTIN, UPI, Voter ID, DL)
- ✅ Context-aware Aadhaar (keyword-gated, < 5% false-positive rate)
- ✅ Phone number fix — handles `+91 90000 12345` (with spaces)
- ✅ 4-level risk classification with combination amplification
- ✅ **Confidence % badge + animated bar** on every detection card
- ✅ **"Why is this risky?"** expandable panel (reason · recommendation · meta)
- ✅ `sanitizeForCloud()` — cloud gate enforced in code, not just docs
- ✅ Explicit `ALLOW / WARN / REDACT / BLOCK` policy engine
- ✅ **Conversation-level context window** (cross-turn combination amplification)
- ✅ `computeRiskWithContext()` — upgrades risk using entity history
- ✅ Ollama (local, raw) + Groq + Gemini (sanitised only) AI layer
- ✅ Draggable panel · Before → After diff · Boost (sanitised) action
- ✅ Content script with platform adapters and risk badge injection
- ✅ Service worker with quick-scan, policy, and secure key storage

### Phase 2 — Intelligent DLP *(roadmap)*
- Microsoft Presidio / GLiNER NER integration
- Full conversation-context window with entity correlation
- AST-level source-code leak detection
- Semantic business-confidentiality classification
- Per-org policy engine with configurable rules
- Multi-platform content script adapters

### Phase 3 — Advanced Protection *(roadmap)*
- AI **output scanning** — two-way protection (responses screened for reflected PII)
- Enterprise dashboard + admin controls
- Audit analytics and compliance reports (DPDPA, GDPR)
- Multi-platform adapters (Copilot, Perplexity, Grok, DeepSeek)

---

## Evaluation Metrics

| Category | Metric | Target |
|---|---|---|
| Detection | Precision for secrets | ≥ 95% |
| Detection | Recall for secrets | ≥ 95% |
| Detection | False-positive rate (context-gated) | < 5% |
| Performance | Layer 1 latency | < 50 ms |
| Performance | Layer 2 latency | < 80 ms |
| Performance | Full AI scan latency | < 2 s |
| Rewrite | Task preservation score | ≥ 90% |
| Rewrite | CRITICAL data removal rate | 100% |
| Cloud gate | Raw secrets reaching cloud | 0 (enforced) |

---

## Supported Platforms

| Platform | Content Script | Status |
|---|---|---|
| Claude (claude.ai) | ✅ | MVP |
| ChatGPT (chat.openai.com) | ✅ | MVP |
| Gemini (gemini.google.com) | ✅ | MVP |
| Microsoft Copilot | 🗓 | Phase 2 |
| Perplexity | 🗓 | Phase 2 |
| Grok | 🗓 | Phase 2 |
| DeepSeek | 🗓 | Phase 2 |

---

## PRD Reference

Full PRD (T5.1) covers: goals, 3-layer engine architecture, complete detection taxonomy, India Sensitive Data Pack, risk scoring, policy engine, evaluation metrics, and enterprise roadmap.

---

Built for **Hackathon T5.1** — AI for Cybersecurity & Productivity.
