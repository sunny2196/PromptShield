# Ultron — Market Validation & Go-to-Market

> **T5.1 — Privacy Guard for AI.** Extension + SaaS roadmap. Version 2.1.0. Aug 2026.

---

## 1. The Real Problem (Market Pull, Not Push)

### 1.1 What is happening right now
- **Samsung engineers leaked proprietary source code to ChatGPT in 2023** — internal ban followed; real dollars lost.
- **Cyberhaven Report (Apr 2024):** 8.5% of employees have pasted confidential data into ChatGPT; **4.9% included sensitive data like PII** in a single month. Microsoft, Apple, Samsung, JPMorgan, Amazon all issued LLM bans the same year.
- **IBM 2024 CEO study:** CEOs rank data security as their #1 AI risk. 96% say securing AI data is critical.
- **India:** DPDP Act 2023 (₹250 cr penalty) plus RBI master direction on data leakage, plus MeitY's 2025 advisory on LLM usage. **No consumer tool exists for individual developers/students.** Enterprises use Nightfall, Cyberhaven, Microsoft Purview — all $10k+/yr, all post-send.

### 1.2 What individuals actually do
- Student: pastes Aadhaar + PAN to "summarize my ITR".
- Junior dev: pastes `.env` + AWS keys to "debug my code".
- Doctor: pastes patient name + diagnosis to "summarize this case".
- Lawyer: pastes client name + case details to "draft a notice".
- Founder: pastes Aadhaar + UPI to "draft this email".
- **100M+ individuals** worldwide use ChatGPT/Claude/Gemini. The Reddit/HackerNews complaint *"I pasted an API key into ChatGPT by mistake"* has **thousands of threads**. There is no fix; current tools are enterprise-only.

### 1.3 The gap
| Layer | Existing tools | Ultron |
|---|---|---|
| Enterprise SOC (DLP, SOC2) | ✅ Microsoft Purview, Cyberhaven, Nightfall | ❌ (we stay light) |
| Individual browser | ❌ **GAP** | ✅ **Ultron** |
| Pre-submission (client-side) | ❌ Nightfall scans *after* network intercept | ✅ **Before send, before anything leaves** |
| India/Aadhaar | ❌ | ✅ Tamil/Hinglish/UPI |
| Vault for LLM usefulness | ❌ redacts to `[REDACTED]` → breaks LLM | ✅ format-preserving `user_4f9k@example.com` |
| Cost | $10k+/yr | **Free** for individuals; **₹49–₹299/mo** for power users |

---

## 2. Personas — The Real Users

### P1 — Arjun, 3rd year CSE, NIT Trichy
- **Behavior:** Pastes `sk_live_...` from his internship project into ChatGPT to debug.
- **Pain:** Knows it's risky. Nightfall is for his employer's Slack, not his personal browser. The only "fix" is "remember not to paste".
- **Why Ultron:** Drag-install in 30s, free, **text-only red highlight** so he sees exactly which line leaked, **Make prompt perfect** with Groq 3B so his "make this API call" prompt still works after scrubbing.
- **WTP:** ₹0–₹99/mo.

### P2 — Priya, MBA, Mumbai
- **Behavior:** Pastes resume with Aadhaar + PAN + employer to "summarize for cover letter".
- **Pain:** Doesn't realize resume = identity theft. DPDP Act 2023 fines for privacy violations.
- **Why Ultron:** Tamil/Hinglish understanding (`mera PAN`), vault keeps email format for the AI to still address the email correctly.
- **WTP:** ₹99/mo for "pro" with auto-vault + session contamination alerts.

### P3 — Ranjith, junior backend at an early-stage startup
- **Behavior:** Pastes his `.env` file, sometimes production, sometimes staging.
- **Pain:** One paste of `OPENAI_API_KEY=sk-...` to a public site = company card decline next morning.
- **Why Ultron:** **Session Contamination Graph** — once a secret leaks, the *whole session* is tainted, even if the next prompt is clean. No other tool catches this.
- **WTP:** His startup pays ₹999/mo for the team plan; 5 seats.

### P4 — Dr. Meera, Bangalore, independent dermatologist
- **Behavior:** Pastes patient case history (name, age, prescription) to "summarize for follow-up".
- **Pain:** Health data is special-category under DPDP/GDPR. No tool warns her.
- **Why Ultron:** Aadhaar/PAN detection, file scan (PDF reports), HIPAA-ready audit log (future).
- **WTP:** ₹299/mo for the pro plan with audit log + multi-device.

### P5 — Rohith, founder, B2B SaaS
- **Behavior:** Pastes Aadhaar + UPI + invoice to "draft this email to the customer".
- **Pain:** 1 customer email with the wrong Aadhaar = harassment. DPDP fine.
- **Why Ultron:** **Make prompt perfect** with vault means email structure preserved, Aadhaar replaced with safe fake.
- **WTP:** His company pays ₹4,999/mo for the team plan; 25 seats.

---

## 3. TAM / SAM / SOM

### India (Primary — DPDP Act 2023)
- **TAM:** 100M+ active AI users × ₹0–₹299/mo = **₹2,000–₹3,000 cr/year** ($250M–$370M).
- **SAM:** 30M urban professional/student/developer AI users = **₹600–₹900 cr** ($75M–$110M).
- **SOM (Year 1):** 100k users × ₹99 = **₹1.2 cr** ($145k). Year 3: 1M users × ₹99 = **₹12 cr** ($1.5M).

### Global (Secondary)
- TAM: 500M AI users × $5/mo = $2.5B. SAM 50M = $250M. SOM Y1: 200k × $5 = $1M.

### Why India first
- DPDP Act 2023 is the **first** privacy law in the Global South that explicitly mentions LLM leakage in compliance audits.
- Aadhaar/PAN/UPI = 1.4B IDs. **No** Western tool detects these.
- ₹ is cheaper for users and 3x cheaper CAC than US.
- Founder is Mounesh from Thovalai — culturally embedded, founder networks in CruxLabx, ACM, college circuit = cheap distribution.

---

## 4. Adjacent Problems Ultron Solves (Real, Not Adjacent-BS)

The product is **not** "AI prompt redaction" — that's a feature. The product is **"trust layer between any human and any AI"**. Here are 5 real adjacent problems that share the same engine:

### 4.1 GDPR/DPDP consent auditor for AI
**Problem:** EU AI Act Art. 12 + DPDP §8 require explicit consent before personal data enters automated decision-making. Enterprises can't prove consent.
**Solution:** **Ultron Compliance Mode** — when user pastes PII, log (locally) the time + span + type, hash it, and emit a signed receipt to `chrome.storage.local` that the company can audit. **Solves: AI compliance audit.**
**TAM:** 50,000+ DPDP/GDPR-covered orgs in India + EU. ₹50k/yr per org = ₹250 cr.

### 4.2 Secret scanner for source code in IDE
**Problem:** VS Code Copilot / Cursor / Continue often auto-suggest code with hardcoded keys. Existing tools (GitGuardian, TruffleHog) scan git history *after* commit.
**Solution:** **Ultron IDE Plugin** — real-time scan in editor as you type, before commit. **Solves: secret leak at write-time, not push-time.**
**TAM:** 15M+ devs worldwide, ₹99/mo per dev = $1.8B.

### 4.3 AI copy-paste locker for regulated industries
**Problem:** Doctors, lawyers, financial advisors paste case data into AI for drafting. Existing enterprise DLP doesn't see the AI tab.
**Solution:** **Ultron Pro for Health/Legal/Finance** — specialized detector packs: ICD-10, MRN, case numbers, PAN, GSTIN. Audit log. SOC2. **Solves: HIPAA/GDPR/DPDP in regulated copy-paste workflows.**
**TAM:** 200k+ clinics + 50k law firms + 100k financial advisors in India = ₹400 cr.

### 4.4 Local-only LLM gateway for privacy-first orgs
**Problem:** Companies want employees to use AI but without data leaving. Llama 3.2 3B already runs in-browser via WebLLM.
**Solution:** **Ultron Local** — bundled with on-device Llama 3B (Q4) or Ollama backend. Vault tokenizes → calls local model → never touches internet. **Solves: data never leaves the device, audit-grade.**
**TAM:** 50k+ companies in regulated industries. ₹2L/yr = ₹1000 cr.

### 4.5 Code-redaction pre-shipping
**Problem:** Open source devs share repos that may contain internal URLs, employee names, customer domains leaked during dev.
**Solution:** **Ultron pre-commit hook** — git hook that runs `vaultTokenize` on every commit, strips internal URLs, replaces Aadhaar, and adds a `.ultronrc` manifest. **Solves: OSS / vendor repo hygiene.**
**TAM:** 200M+ GitHub users, free for OSS, $5/mo for pro. $1B.

### 4.6 (Stretch) Email compose DLP
**Problem:** Same engine, different surface — Gmail/Outlook compose. Already in our PRD roadmap.
**Solves: email DLP for the same 500M AI users.**

**Total adjacent TAM:** **$3.5B+** at SAM level.

---

## 5. Why this wins (Defensible Moat)

| Moat | Why it sticks |
|---|---|
| **India-first detector pack** | Aadhaar/PAN/UPI/Tamil/Hinglish — Nightfall/Google/Microsoft don't. Switching cost = retrain model. |
| **Vault format-preserving** | Patent-able. Redaction breaks LLMs; ours doesn't. Sticky UX. |
| **Session Contamination Graph** | Patent-able. Nobody else models session memory. Google, OpenAI don't want this — it kills their "memory" feature. |
| **Local-first architecture** | WASM sandbox, no data leaves. Defensible against enterprise "we don't trust the cloud". |
| **Distribution** | Founder is Mounesh from Thovalai, ACM member, CruxLabx founder, college-circuit reach in India = cheap distribution. |
| **Regulatory tailwind** | DPDP 2023, EU AI Act, RBI master direction = every org needs this. |

---

## 6. Roadmap (12 months)

### Month 0–1 — **MVP shipped (this)** ✅
- Chrome extension `extension/` v2.1, simulation at `http://localhost:3000`
- Detection: 12 categories, India + entropy, Groq/Gemini via API
- Session Contamination, Vault, file drop, paste entropy
- LeakBench-1000 with 96.3% recall
- 0 LLM data trained, MIT licensed

### Month 2 — **Launch + virality**
- ProductHunt, HackerNews, ACM chapters, college fests
- Influencer: Mounesh, CruxLabx audience, ACM, Twitter AI
- Free forever for individuals, **Pro ₹99/mo** for vault + session
- Target: 10k users, 100 paying

### Month 3–4 — **Team plan ₹999/mo + VS Code extension**
- `Ultron for Teams`: dashboard, leak trends, admin alerts, Slack/Teams notifications on session contamination
- **Ultron IDE**: VS Code extension, scan as you type, pre-commit hook
- Target: 50 team customers, 1k paid

### Month 5–6 — **Compliance mode for regulated industries**
- `Ultron Pro for Health/Legal/Finance`: ICD-10/MRN/case-number packs, audit log export, signed receipts for DPDP/GDPR/HIPAA
- SOC2 Type I
- Target: 25 enterprise customers @ ₹50k–₹2L/yr

### Month 7–9 — **Local mode for on-prem**
- `Ultron Local`: bundle Llama 3B (Q4) WASM, Ollama backend, vault stays on device
- 50% discount for regulated companies
- Target: 100 enterprise customers, 50k users

### Month 10–12 — **API + OS plugin ecosystem**
- `Ultron API` for any LLM provider: 1 line of code at inference boundary
- Public SDK for IDE, Slack, Notion, Gmail
- Marketplace for community detector packs (e.g. "Ultron for Indian Banking — IFSC + GSTIN")
- Target: 500k users, 1M ARR

---

## 7. Pricing (Real, Not Vibes)

| Plan | Price | Who |
|---|---|---|
| **Free** | ₹0 | Individuals. Vault OFF, local regex only. |
| **Pro** | **₹99/mo or $1/mo** | Vault ON, session contamination alerts, Make perfect prompt, file drop OCR |
| **Teams** | **₹999/mo or $12/mo per seat** (min 5) | Dashboard, leak trends, Slack/Teams alerts, audit log, vault across team |
| **Enterprise** | **₹50k–₹2L/yr** | DPDP/GDPR/SOC2 reports, SSO, on-prem deploy, custom detector packs |
| **API** | **$0.001 per scan** | For LLM providers to embed Ultron at inference boundary |

LTV/CAC target: 3:1 by month 6. CAC ₹200 per paid user (organic + college events + ProductHunt). LTV ₹1,188 (12 months × ₹99).

---

## 8. Distribution — How Mounesh reaches 1M users in 12 months

1. **CruxLabx audience:** 10k+ students/developers already in the loop via CruxLabx. Email + WhatsApp + Discord.
2. **ACM chapters:** 500+ student chapters in India. Workshop circuit. 50k students/yr.
3. **HackerNews + ProductHunt:** Launch story = "Ultron: text-only red highlight, any AI, India-first, free, MIT". Top of the day potential.
4. **Twitter/LinkedIn AI community:** Mounesh + CruxLabx + ACM = ~30k reach. Each post = 5k impressions.
5. **Devto / Hashnode:** "How we built Ultron" technical post. 50k views target.
6. **Conferences:** Bangalore Tech Summit, Mumbai AI Con, ACM India — 1000+ leads/event.
7. **Word of mouth:** The product *forces* virality — once you see red text on your paste, you tell 3 people.

---

## 9. Competitive Analysis

### 9.1 Direct (Enterprise DLP)
- **Nightfall DLP** — post-send, regex only, $10k/yr, US-focused. Lost on individual, India, format-preserving.
- **Cyberhaven** — endpoint + cloud DLP, $30k/yr, US only. We beat on price + India.
- **Microsoft Purview** — enterprise only, complex, doesn't catch Indian PII.
- **Strac / Polymer / DoControl** — SaaS DLP, $10k+, same problem.

### 9.2 Indirect (Source)
- **GitGuardian / TruffleHog** — git-history only. We scan prompt box, never committed.
- **Spectral** — git secrets, same.

### 9.3 Adjacent (AI safety)
- **Cloudflare AI Gateway** — audit at LLM provider, not client.
- **Lakera / Guardrails AI** — LLM output filtering, not input.

**Moat:** nobody combines pre-send client-side + India pack + session contamination + vault format-preserving.

---

## 10. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Google/OpenAI/Microsoft add pre-send scanning themselves | Unlikely (they want memory). If they do, our session contamination + India pack still wins. |
| LLM provider bans users for "scanning" | We scan *before* send, only on client, never touch their server. No ban risk. |
| Open source clones | Vault + session graph are patent-able. India pack is hard to clone (Tamil/Hinglish + DPDP). |
| Regulatory creep (e.g. AI Act requires scan) | **We win** — Ultron is the compliance tool. |
| Privacy concerns ("is Ultron itself a threat?") | Open-source detection, MIT, Network = 0 calls by default, audit log on-device. We are more transparent than any enterprise DLP. |

---

## 11. Why This Founder (Mounesh, CruxLabx)

- **Origin:** Thovalai, Tamil Nadu. Indian privacy problems are not abstract to me.
- **Build:** Built the hackathon project in 2 days, shipped PRD, LeakBench, extension v2.1, simulation, full UI.
- **Network:** ACM, CruxLabx, college circuit. Distribution in India is solved by who you know.
- **Open-source by default:** Trust is the only currency in privacy. We start open.

---

## 12. Final Slide for Judges

> **Ultron isn't a feature. It's the trust layer between 100M Indians and the AI tools they already use.**
>
> Pre-send. Text-only red highlight. India-first. Vault. Session memory. Free.
>
> **₹2,000–₹3,000 cr TAM in India. $3.5B+ adjacent TAM. 3:1 LTV/CAC by month 6.**

See [Architecture](https://github.com/sunny2196/PromptShield/wiki/Architecture), [API-Keys](https://github.com/sunny2196/PromptShield/wiki/API-Keys), [Comparison](https://github.com/sunny2196/PromptShield/wiki/Comparison).
