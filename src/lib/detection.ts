export type Severity = 'HIGH' | 'MEDIUM' | 'LOW'
export type DetectionCategory =
  | 'API_KEY' | 'AADHAAR' | 'PAN' | 'PASSWORD' | 'CARD'
  | 'EMAIL' | 'PHONE' | 'PASSPORT' | 'INTERNAL' | 'FINANCIAL'
  | 'MEDICAL' | 'PERSON_NAME' | 'ADDRESS'

export type Detection = {
  id: string
  span: string
  type: DetectionCategory
  label: string
  severity: Severity
  risk: string
  reason: string
  placeholder: string
  start: number
  end: number
  confidence: number
  source: 'regex' | 'presidio' | 'llm'
}

type Pattern = {
  type: DetectionCategory; label: string; severity: Severity; risk: string; reason: string; placeholder: string;
  regex: RegExp; validator?: (m: string) => boolean; confidence: number; source: Detection['source']
}

const luhn = (s: string) => {
  const d = s.replace(/[\s-]/g,'')
  if(!/^\d{13,19}$/.test(d)) return false
  let sum=0, alt=false
  for(let i=d.length-1;i>=0;i--){ let n=parseInt(d[i]); if(alt){ n*=2; if(n>9)n-=9} sum+=n; alt=!alt}
  return sum%10===0
}

const PATTERNS: Pattern[] = [
  { type:'API_KEY', label:'Stripe Secret Key', severity:'HIGH', risk:'Can charge customers & drain funds', reason:'Stripe secret keys grant full API access to payments. If leaked to a public LLM, it may be logged, cached or used for training.', placeholder:'[REDACTED_STRIPE_KEY]', regex:/\bsk_(live|test|proj)_[A-Za-z0-9]{16,}\b/g, confidence:0.99, source:'regex'},
  { type:'API_KEY', label:'OpenAI API Key', severity:'HIGH', risk:'Exposes billed AI usage', reason:'OpenAI project keys are billed to your org. Sharing them lets anyone consume your quota.', placeholder:'[REDACTED_OPENAI_KEY]', regex:/\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/g, confidence:0.95, source:'regex'},
  { type:'API_KEY', label:'AWS Access Key', severity:'HIGH', risk:'Full cloud account takeover', reason:'AKIA keys give programmatic access to AWS. Combined with secret they can spin up costly resources.', placeholder:'[REDACTED_AWS_KEY]', regex:/\bAKIA[0-9A-Z]{16}\b/g, confidence:0.98, source:'regex'},
  { type:'API_KEY', label:'AWS Secret Key', severity:'HIGH', risk:'Cloud credential leak', reason:'Matches aws_secret_access_key pattern. Used with AKIA to authenticate.', placeholder:'[REDACTED_AWS_SECRET]', regex:/aws_secret_access_key\s*=\s*[A-Za-z0-9\/+]{30,}/gi, confidence:0.96, source:'regex'},
  { type:'API_KEY', label:'GitHub Token', severity:'HIGH', risk:'Code repository takeover', reason:'ghp_/github_pat_ tokens grant repo access. Leaked tokens can push malicious code.', placeholder:'[REDACTED_GITHUB_TOKEN]', regex:/\b(ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g, confidence:0.97, source:'regex'},
  { type:'API_KEY', label:'Slack Token', severity:'HIGH', risk:'Workspace data exfiltration', reason:'Slack tokens (xoxb/xoxp) give bot/user scope to read messages and files.', placeholder:'[REDACTED_SLACK_TOKEN]', regex:/\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9-]+\b/g, confidence:0.96, source:'regex'},
  { type:'API_KEY', label:'Bearer Token', severity:'HIGH', risk:'Session hijack', reason:'Bearer tokens authenticate API calls. Anyone with it can impersonate the user.', placeholder:'[REDACTED_BEARER]', regex:/Bearer\s+[A-Za-z0-9\-_\.=]{20,}/g, confidence:0.9, source:'regex'},
  { type:'AADHAAR', label:'Aadhaar Number', severity:'HIGH', risk:'Identity theft · Govt ID', reason:'12-digit Aadhaar is a permanent government identifier. Never share into public AI - irreversible privacy loss.', placeholder:'[REDACTED_AADHAAR]', regex:/\b\d{4}\s?\d{4}\s?\d{4}\b/g, validator:(m)=> m.replace(/\s/g,'').length===12, confidence:0.88, source:'regex'},
  { type:'PAN', label:'PAN Card', severity:'HIGH', risk:'Financial identity theft', reason:'PAN is linked to tax & bank accounts. Exposure enables fraudulent financial activity.', placeholder:'[REDACTED_PAN]', regex:/\b[A-Z]{5}[0-9]{4}[A-Z]\b/g, confidence:0.96, source:'regex'},
  { type:'CARD', label:'Credit Card', severity:'HIGH', risk:'Direct financial fraud', reason:'Card number with Luhn pass. Sharing even without CVV still violates PCI and enables brute-force.', placeholder:'[REDACTED_CARD]', regex:/\b(?:\d[ -]*?){13,19}\b/g, validator:luhn, confidence:0.92, source:'regex'},
  { type:'PASSWORD', label:'Password / Secret', severity:'HIGH', risk:'Account takeover', reason:'Plaintext password or secret assignment. LLMs never need your real password to debug.', placeholder:'[REDACTED_PASSWORD]', regex:/\b(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{4,}/gi, confidence:0.88, source:'regex'},
  { type:'EMAIL', label:'Personal Email', severity:'MEDIUM', risk:'Phishing & spam targeting', reason:'Personal emails enable targeted phishing and linkage across data breaches.', placeholder:'[REDACTED_EMAIL]', regex:/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, confidence:0.9, source:'regex'},
  { type:'PHONE', label:'Indian Mobile', severity:'MEDIUM', risk:'SIM swap & spam', reason:'Phone numbers are used for OTPs and identity verification. Sharing increases SIM-swap risk.', placeholder:'[REDACTED_PHONE]', regex:/\b(?:\+91[\s-]?)?[6-9]\d{9}\b/g, confidence:0.9, source:'regex'},
  { type:'INTERNAL', label:'Internal Link', severity:'MEDIUM', risk:'Corp data leakage', reason:'Internal Notion/Confluence/Jira links reveal org structure & may expose auth-gated docs to AI review queue.', placeholder:'[REDACTED_INT_LINK]', regex:/https?:\/\/(?:[a-z0-9-]+\.)*atlassian\.net\/wiki\/\S+|https?:\/\/.*\.notion\.site\/\S+|https?:\/\/.*\.slack\.com\/\S+/gi, confidence:0.85, source:'regex'},
  { type:'ADDRESS', label:'Home Address', severity:'MEDIUM', risk:'Physical privacy loss', reason:'Full addresses enable doxxing. AI should work with city/region only.', placeholder:'[REDACTED_ADDRESS]', regex:/\b\d{1,4}[\/,]?\s*[A-Za-z ]+(Street|St|Road|Rd|Nagar|Colony|Layout|Phase)\b/gi, confidence:0.7, source:'regex'},
]

const CONTEXTUAL_KEYWORDS: Array<{test: RegExp, make: (m: string, idx:number)=> Detection}> = [
  { test:/my salary is\s*₹?\s*[\d.,]+\s*(LPA|lakh|lac|per annum)?/gi, make:(span, i)=>({ id:`ctx-fin-${i}`, span, type:'FINANCIAL', label:'Salary Disclosure', severity:'MEDIUM', risk:'Compensation leakage', reason:'Salary figures are sensitive HR data. The model can generalize: "my salary in the 12LPA bracket".', placeholder:'[REDACTED_SALARY]', start:-1, end:-1, confidence:0.82, source:'llm' as const })},
  { test:/Infosys|TCS|Wipro|Google|Microsoft|Amazon/gi, make:(span,i)=>({ id:`ctx-org-${i}`, span, type:'INTERNAL', label:'Org Mention + Context', severity:'LOW', risk:'Org inference', reason:'Mentioning employer with sensitive detail lets AI correlate you to an org. Consider generalizing.', placeholder:'[REDACTED_ORG]', start:-1,end:-1, confidence:0.6, source:'llm' as const})},
  { test:/my (manager|lead) (at |is )?([A-Z][a-z]+)/g, make:(span,i)=>({ id:`ctx-pname-${i}`, span, type:'PERSON_NAME', label:'Person + Role', severity:'LOW', risk:'Social graph leakage', reason:'Naming individuals with roles leaks workplace relationships.', placeholder:'[REDACTED_NAME]', start:-1,end:-1, confidence:0.68, source:'llm' as const})},
  { test:/my (sugar|bp|thyroid|medical) (report|is|level).{0,40}/gi, make:(span,i)=>({ id:`ctx-med-${i}`, span, type:'MEDICAL', label:'Medical Info', severity:'MEDIUM', risk:'Health privacy', reason:'Health data is special-category personal data under DPDP/GDPR.', placeholder:'[REDACTED_MEDICAL]', start:-1,end:-1, confidence:0.75, source:'llm' as const})},
]

export function scanLocal(text: string): Detection[] {
  const out: Detection[] = []
  let id=0
  for(const p of PATTERNS){
    const re = new RegExp(p.regex.source, p.regex.flags)
    let m: RegExpExecArray | null
    while((m=re.exec(text))!==null){
      const span=m[0]
      if(p.validator && !p.validator(span)) continue
      if(p.type==='CARD' && !luhn(span)) continue
      if(p.type==='AADHAAR' && span.replace(/\D/g,'').length!==12) continue
      if(p.type==='CARD' && span.includes('@')) continue
      const start=m.index
      const end=start+span.length
      if(out.some(d=> !(end<=d.start || start>=d.end))) continue
      out.push({ id:`d-${id++}`, span, type:p.type, label:p.label, severity:p.severity, risk:p.risk, reason:p.reason, placeholder:p.placeholder, start, end, confidence:p.confidence, source:p.source })
      if(m[0].length===0) re.lastIndex++
    }
  }
  CONTEXTUAL_KEYWORDS.forEach(k=>{
    const re=new RegExp(k.test.source, k.test.flags)
    let m: RegExpExecArray|null
    let j=0
    while((m=re.exec(text))!==null){
      const span=m[0]
      const d=k.make(span, j++)
      const idx=text.indexOf(span)
      if(idx>=0){ d.start=idx; d.end=idx+span.length}
      if(!out.some(o=> o.span===span)) out.push(d)
      if(m[0].length===0) re.lastIndex++
    }
  })
  return out.sort((a,b)=> a.start-b.start)
}

export function redactText(text: string, detections: Detection[], mode:'redact'|'pseudonymize'='redact'): string {
  if(!detections.length) return text
  const sorted=[...detections].sort((a,b)=> b.start-a.start)
  let out=text
  const pseudoMap: Record<string,string>={
    'EMAIL':'user@example.com',
    'PHONE':'+91 90000 00000',
    'PERSON_NAME':'Person A',
    'ADDRESS':'[City, State]',
  }
  for(const d of sorted){
    if(d.start<0 || d.end<0) continue
    const rep = mode==='pseudonymize' && pseudoMap[d.type] ? pseudoMap[d.type] : d.placeholder
    out = out.slice(0,d.start) + rep + out.slice(d.end)
  }
  return out
}

// --- Groq API for Llama 3B / Qwen 3B via API ---
export async function scanWithGroq(text: string, groqKey: string, modelHint: string): Promise<Detection[]> {
  if(!groqKey || !text.trim() || text.length<12) return []
  const hasSensitiveHint = /api|key|secret|aadhaar|pan|salary|manager|medical|password|token|confluence|notion|email|phone/i.test(text)
  if(!hasSensitiveHint && scanLocal(text).length===0) return []
  const groqModel = modelHint==='qwen3b' ? 'llama-3.2-3b-preview' : modelHint==='llama3b' ? 'llama-3.2-3b-preview' : 'llama-3.1-8b-instant'
  try{
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method:'POST',
      headers:{ 'Content-Type':'application/json', 'Authorization':`Bearer ${groqKey}` },
      body: JSON.stringify({
        model: groqModel,
        temperature: 0.1,
        max_tokens: 700,
        messages:[
          { role:'system', content:'You are PromptShield, a privacy auditor. Return ONLY valid JSON array, no markdown.'},
          { role:'user', content: `Analyze this user prompt for sensitive spans regex missed. Focus on salary/org/medical/person+role/internal IDs.\nUSER PROMPT:\n"""${text.slice(0,4000)}"""\n\nReturn JSON array of {"span": exact substring, "label": short label, "type": one of [FINANCIAL,MEDICAL,INTERNAL,PERSON_NAME,ADDRESS,PASSWORD], "severity": HIGH|MEDIUM|LOW, "risk": short, "reason": one sentence, "placeholder": like [REDACTED_SALARY]}. Return [] if none. Example: "my manager at Infosys said my salary is 12LPA" -> [{"span":"my manager at Infosys","label":"Manager + Org","type":"PERSON_NAME","severity":"LOW","risk":"Workplace graph","reason":"Links you to org via manager.","placeholder":"[REDACTED_NAME]"},{"span":"my salary is 12LPA","label":"Salary","type":"FINANCIAL","severity":"MEDIUM","risk":"Comp leakage","reason":"Salary is sensitive HR data.","placeholder":"[REDACTED_SALARY]"}]` }
        ]
      })
    })
    if(!res.ok) throw new Error(`Groq ${res.status}`)
    const json:any = await res.json()
    const txt: string = json.choices?.[0]?.message?.content || ''
    const cleaned = txt.replace(/```json|```/g,'').trim()
    const s = cleaned.indexOf('['); const e = cleaned.lastIndexOf(']')
    if(s===-1||e===-1) return []
    const arr = JSON.parse(cleaned.slice(s, e+1))
    if(!Array.isArray(arr)) return []
    return arr.map((o:any,i:number)=>{
      const span: string = String(o.span||'').slice(0,200)
      const idx = span ? text.indexOf(span) : -1
      return { id:`groq-${i}-${Date.now()}`, span: span || o.label || 'sensitive span', type: (o.type as DetectionCategory) || 'INTERNAL', label: String(o.label||'Contextual risk'), severity: (o.severity as Severity) || 'MEDIUM', risk: String(o.risk||'Contextual leakage'), reason: String(o.reason||'Detected by 3B LLM via Groq.'), placeholder: String(o.placeholder||'[REDACTED_CONTEXT]'), start: idx, end: idx>=0 ? idx+span.length : -1, confidence: 0.78, source: 'llm' as const }
    }).filter((d:Detection)=> d.span && d.span.length>1)
  }catch(e){
    console.warn('[PromptShield] Groq scan failed', e)
    return []
  }
}

// LLM contextual scan via Gemini (Qwen3B / Llama3B fallback) - kept for backup
export async function scanWithLLM(text: string, apiKey: string, modelHint: string): Promise<Detection[]> {
  if(!apiKey || !text.trim() || text.length<12) return []
  const hasSensitiveHint = /api|key|secret|aadhaar|pan|salary|manager|medical|password|token|confluence|notion/i.test(text)
  if(!hasSensitiveHint && scanLocal(text).length===0) return []
  try{
    const { GoogleGenAI } = await import('@google/genai')
    const ai = new GoogleGenAI({ apiKey })
    const prompt = `You are PromptShield, a privacy auditor emulating a small 3B on-device model (Qwen2.5-3B). Analyze the user prompt that will be sent to a public LLM.

USER PROMPT:
"""${text.slice(0, 4000)}"""

Task: Find sensitive spans the regex missed. Focus on:
- salary/compensation, org + role, person names with context, medical, internal project names, financial figures, indirect identifiers.
- DO NOT flag generic greetings or harmless code.
- For each finding return JSON array with exactly: {"span": exact substring from prompt, "label": short label, "type": one of [FINANCIAL,MEDICAL,INTERNAL,PERSON_NAME,ADDRESS,PASSWORD], "severity": HIGH|MEDIUM|LOW, "risk": short risk, "reason": 1 sentence, "placeholder": like [REDACTED_SALARY]}
- Return [] if none. Return ONLY valid JSON array, no markdown, no explanation.

Example: prompt "my manager at Infosys said my salary is 12LPA" -> [{"span":"my manager at Infosys","label":"Manager + Org","type":"PERSON_NAME","severity":"LOW","risk":"Workplace graph","reason":"Links you to org via manager.","placeholder":"[REDACTED_NAME]"},{"span":"my salary is 12LPA","label":"Salary","type":"FINANCIAL","severity":"MEDIUM","risk":"Comp leakage","reason":"Salary is sensitive HR data.","placeholder":"[REDACTED_SALARY]"}]`

    const res = await ai.models.generateContent({
      model: 'gemini-2.0-flash',
      contents: prompt,
      config: { temperature: 0.1, maxOutputTokens: 700 }
    })
    const txt: string = (res as any).text || (res as any).response?.text?.() || (res as any).candidates?.[0]?.content?.parts?.[0]?.text || ''
    if(!txt) return []
    const cleaned = txt.replace(/```json|```/g,'').trim()
    const start = cleaned.indexOf('['); const end = cleaned.lastIndexOf(']')
    if(start===-1||end===-1) return []
    const arr = JSON.parse(cleaned.slice(start, end+1))
    if(!Array.isArray(arr)) return []
    return arr.map((o:any,i:number)=>{
      const span: string = String(o.span||'').slice(0,200)
      const idx = span ? text.indexOf(span) : -1
      return {
        id:`llm-${i}-${Date.now()}`,
        span: span || o.label || 'sensitive span',
        type: (o.type as DetectionCategory) || 'INTERNAL',
        label: String(o.label||'Contextual risk'),
        severity: (o.severity as Severity) || 'MEDIUM',
        risk: String(o.risk||'Contextual leakage'),
        reason: String(o.reason||'Detected by contextual model beyond regex.'),
        placeholder: String(o.placeholder||'[REDACTED_CONTEXT]'),
        start: idx, end: idx>=0 ? idx+span.length : -1,
        confidence: 0.78,
        source: 'llm' as const
      }
    }).filter((d:Detection)=> d.span && d.span.length>1)
  }catch(e){
    console.warn('[PromptShield] LLM scan failed, falling back to local', e)
    return []
  }
}

// --- PromptCowboy-style enhancement: turn lazy prompt into great prompt ---
export async function enhancePrompt(safePrompt: string, opts:{ geminiKey?:string, groqKey?: string }): Promise<string>{
  if(!safePrompt.trim()) return safePrompt
  const system = `You are PromptCowboy + PromptShield. Turn lazy prompts into great prompts while keeping privacy placeholders intact (like [REDACTED_EMAIL], [REDACTED_KEY]).

Rules:
- Keep ALL placeholders exactly as they are — never invent real data.
- Rewrite to be clear, specific, and effective: add role, goal, constraints, output format.
- Keep it concise (1-2 sentences if original is short, or structured bullets if complex).
- Do not add warnings. Return ONLY the enhanced prompt text, no quotes, no preamble.`

  const user = `Lazy prompt:\n"""${safePrompt.slice(0,3000)}"""\n\nEnhance it into a great prompt.`
  // Prefer Groq for speed, fallback to Gemini
  if(opts.groqKey){
    try{
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${opts.groqKey}`},
        body: JSON.stringify({ model:'llama-3.1-8b-instant', temperature:0.4, max_tokens:700, messages:[{role:'system',content:system},{role:'user',content:user}] })
      })
      if(r.ok){
        const j:any = await r.json()
        const t = j.choices?.[0]?.message?.content?.trim()
        if(t) return t.replace(/^"|"$/g,'')
      }
    }catch{}
  }
  if(opts.geminiKey){
    try{
      const { GoogleGenAI } = await import('@google/genai')
      const ai = new GoogleGenAI({ apiKey: opts.geminiKey })
      const res = await ai.models.generateContent({ model:'gemini-2.0-flash', contents:`${system}\n\n${user}`, config:{temperature:0.4, maxOutputTokens:700}})
      const t: string = (res as any).text || (res as any).candidates?.[0]?.content?.parts?.[0]?.text || ''
      if(t) return t.replace(/^"|"$/g,'').trim()
    }catch{}
  }
  // heuristic fallback
  return safePrompt.trim().replace(/\s+/g,' ').replace(/^./, c=> c.toUpperCase())
}
