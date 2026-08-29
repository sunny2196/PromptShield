# Demo — 2-min winning flow

![UI](https://raw.githubusercontent.com/sunny2196/PromptShield/extension/docs/images/ultron-ui.png)

## Video
![Demo GIF](https://raw.githubusercontent.com/sunny2196/PromptShield/extension/docs/images/ultron-demo.gif)

> If you need video: record 2 min with OBS — steps below. Placeholder GIF above.

## Steps
1. **Clean** — type `Explain quantum computing` → header 🟢 `Safe`
2. **Leak** — paste `my email arjun@gmail.com and PAN ABCDE1234F and Enoda Aadhaar 1234 5678 9012 da` → 🔴 `2 sensitive` — **only those spans red underlined**, not whole box
3. **Vault** — `Use safe version` → `user_4f9k@example.com` + `[REDACTED_PAN]` — `Make prompt perfect` → Ultron rewrites with Role+Goal+Context+Steps+Constraints+Output
4. **Session** — paste clean `Hello` again → `Session tainted` banner (Score 72/100) → `New chat`
5. **File** — drag `Aadhaar.pdf` onto prompt box → `File scan: 1 sensitive` → block
6. **Network** — DevTools Network shows 0 calls unless Groq/Gemini key triggers LLM

## Script for judges
> "We didn't build a feature, we built a seatbelt for Bharat's AI. Text-only highlight, works on any prompt box, vault keeps format, session remembers."

