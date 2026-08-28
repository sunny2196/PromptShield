// Ultron Detection Engine
// Layers: 1-Deterministic (regex/entropy/Luhn) | 2-Contextual keywords | 3-LLM (Groq/Gemini/Ollama)

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export type DetectionCategory =
  | 'API_KEY'
  | 'PRIVATE_KEY'
  | 'CERTIFICATE'
  | 'TOKEN'
  | 'AADHAAR'
  | 'PAN'
  | 'GSTIN'
  | 'UPI'
  | 'VOTER_ID'
  | 'DL'
  | 'PASSPORT'
  | 'BANK_ACCOUNT'
  | 'PASSWORD'
  | 'CARD'
  | 'EMAIL'
  | 'PHONE'
  | 'USERNAME'
  | 'INTERNAL'
  | 'INFRASTRUCTURE'
  | 'DB_CREDENTIAL'
  | 'FINANCIAL'
  | 'MEDICAL'
  | 'PERSON_NAME'
  | 'ADDRESS'
  | 'GPS'
  | 'BUSINESS_CONFIDENTIAL'
  | 'SOURCE_CODE'
  | 'ENV_FILE'
  | 'EMPLOYEE_ID'

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
  type: DetectionCategory
  label: string
  severity: Severity
  risk: string
  reason: string
  placeholder: string
  regex: RegExp
  validator?: (m: string) => boolean
  confidence: number
  source: Detection['source']
}

// ─── Validators ──────────────────────────────────────────────────────────────

const luhn = (s: string) => {
  const d = s.replace(/[\s-]/g, '')
  if (!/^\d{13,19}$/.test(d)) return false
  let sum = 0, alt = false
  for (let i = d.length - 1; i >= 0; i--) {
    let n = parseInt(d[i])
    if (alt) { n *= 2; if (n > 9) n -= 9 }
    sum += n; alt = !alt
  }
  return sum % 10 === 0
}

const isPrivateIP = (ip: string) => {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4) return false
  return (
    parts[0] === 10 ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
  )
}

// ─── Pattern Library ─────────────────────────────────────────────────────────
// Ordered: CRITICAL first so they appear first in the UI.

const PATTERNS: Pattern[] = [

  // ════════════════════════════════════════════════════════════════════════════
  // CRITICAL — Secrets & Credentials
  // ════════════════════════════════════════════════════════════════════════════

  {
    type: 'API_KEY', label: 'Stripe Secret Key', severity: 'CRITICAL',
    risk: 'Can charge customers & drain funds',
    reason: 'Stripe secret keys grant full API access to payments. Public LLMs may log or cache API keys from prompts.',
    placeholder: '[REDACTED_STRIPE_KEY]',
    regex: /\bsk_(live|test|proj)_[A-Za-z0-9]{16,}\b/g, confidence: 0.99, source: 'regex'
  },
  {
    type: 'API_KEY', label: 'OpenAI / ChatGPT API Key', severity: 'CRITICAL',
    risk: 'Exposes billed AI usage — quota abuse',
    reason: 'OpenAI project keys are billed to your org. Anyone with this key can consume your quota or access fine-tuned models.',
    placeholder: '[REDACTED_OPENAI_KEY]',
    regex: /\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/g, confidence: 0.95, source: 'regex'
  },
  {
    type: 'API_KEY', label: 'Google / Gemini API Key', severity: 'CRITICAL',
    risk: 'Google Cloud billing & data exposure',
    reason: 'Google API keys starting with AIza grant access to Gemini, Maps, Vision and other billed Google Cloud APIs.',
    placeholder: '[REDACTED_GOOGLE_API_KEY]',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g, confidence: 0.97, source: 'regex'
  },
  {
    type: 'API_KEY', label: 'AWS Access Key ID', severity: 'CRITICAL',
    risk: 'Full cloud account takeover',
    reason: 'AKIA keys give programmatic access to AWS. Combined with a secret key they can spin up resources or exfiltrate data.',
    placeholder: '[REDACTED_AWS_KEY]',
    regex: /\bAKIA[0-9A-Z]{16}\b/g, confidence: 0.98, source: 'regex'
  },
  {
    type: 'API_KEY', label: 'AWS Secret Access Key', severity: 'CRITICAL',
    risk: 'Cloud credential leak — account takeover',
    reason: 'Matches aws_secret_access_key pattern. Used with AKIA key to authenticate all AWS API calls.',
    placeholder: '[REDACTED_AWS_SECRET]',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9\/+]{30,}/gi, confidence: 0.97, source: 'regex'
  },
  {
    type: 'API_KEY', label: 'Azure Client Secret', severity: 'CRITICAL',
    risk: 'Azure account takeover — cloud services exposure',
    reason: 'Azure client secrets authenticate service principals. Leaked secrets allow full access to Azure subscriptions.',
    placeholder: '[REDACTED_AZURE_SECRET]',
    regex: /(?:client[_-]?secret|AZURE[_-]CLIENT[_-]SECRET)\s*[=:]\s*[A-Za-z0-9~._\-!]{8,}/gi, confidence: 0.88, source: 'regex'
  },
  {
    type: 'API_KEY', label: 'GitHub / GitLab Token', severity: 'CRITICAL',
    risk: 'Code repository takeover — supply chain risk',
    reason: 'GitHub/GitLab tokens grant repository access. Leaked tokens allow pushing malicious code or reading private repos.',
    placeholder: '[REDACTED_GIT_TOKEN]',
    regex: /\b(ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9\-_]{20,})\b/g, confidence: 0.97, source: 'regex'
  },
  {
    type: 'API_KEY', label: 'Slack Token', severity: 'CRITICAL',
    risk: 'Workspace data exfiltration',
    reason: 'Slack tokens (xoxb/xoxp) give bot/user scope to read messages, files and direct messages.',
    placeholder: '[REDACTED_SLACK_TOKEN]',
    regex: /\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9-]+\b/g, confidence: 0.96, source: 'regex'
  },
  {
    type: 'TOKEN', label: 'Bearer / OAuth Token', severity: 'CRITICAL',
    risk: 'Session hijack — full API impersonation',
    reason: 'Bearer tokens authenticate API calls. Anyone with this token can impersonate the authenticated user until it expires.',
    placeholder: '[REDACTED_BEARER]',
    regex: /Bearer\s+[A-Za-z0-9\-_\.=]{20,}/g, confidence: 0.90, source: 'regex'
  },
  {
    type: 'TOKEN', label: 'JWT Token', severity: 'CRITICAL',
    risk: 'Session hijack — identity forgery',
    reason: 'JSON Web Tokens carry identity claims. A leaked JWT can be used to impersonate users until expiry.',
    placeholder: '[REDACTED_JWT]',
    regex: /\bey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g, confidence: 0.93, source: 'regex'
  },
  {
    type: 'PRIVATE_KEY', label: 'SSH / RSA / EC Private Key', severity: 'CRITICAL',
    risk: 'Cryptographic identity compromise — server access',
    reason: 'PEM private keys (RSA, EC, OPENSSH, DSA) decrypt traffic, sign code, or authenticate to servers. Irreversible exposure.',
    placeholder: '[REDACTED_PRIVATE_KEY]',
    regex: /-----BEGIN\s+(RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g, confidence: 0.99, source: 'regex'
  },
  {
    type: 'CERTIFICATE', label: 'TLS / X.509 Certificate', severity: 'HIGH',
    risk: 'Certificate chain exposure — MITM risk',
    reason: 'TLS certificates reveal server identity and signing chain. Private certs should never be pasted into public AI tools.',
    placeholder: '[REDACTED_CERTIFICATE]',
    regex: /-----BEGIN CERTIFICATE-----/g, confidence: 0.97, source: 'regex'
  },
  {
    type: 'DB_CREDENTIAL', label: 'Database Connection String', severity: 'CRITICAL',
    risk: 'Production database access — data breach risk',
    reason: 'Database URIs often embed credentials and internal IPs. Sharing with public AI exposes entire databases.',
    placeholder: '[REDACTED_DB_CONNECTION]',
    regex: /(postgresql|postgres|mysql|mongodb|redis|mssql|mariadb|oracle|cassandra):\/\/[^\s"'<>\n]+/gi,
    confidence: 0.97, source: 'regex'
  },
  {
    type: 'PASSWORD', label: 'Password / Secret', severity: 'CRITICAL',
    risk: 'Account or system takeover',
    reason: 'Plaintext password or secret assignment detected. LLMs never need your real password to debug code.',
    placeholder: '[REDACTED_PASSWORD]',
    regex: /\b(password|passwd|pwd|secret|api_secret|client_secret|app_secret|db_password|DB_PASSWORD)\s*[:=]\s*['"]?[^\s'">\n]{4,}/gi,
    confidence: 0.88, source: 'regex'
  },
  {
    type: 'ENV_FILE', label: '.env File Content', severity: 'CRITICAL',
    risk: 'All app secrets exposed at once',
    reason: '.env file content exposes every credential in your application at once — the highest-impact single leak possible.',
    placeholder: '[REDACTED_ENV_CONTENT]',
    regex: /^(VITE_|REACT_APP_|NEXT_PUBLIC_|DATABASE_|SECRET_|API_KEY_)[A-Z_]+=.+$/gm,
    confidence: 0.92, source: 'regex'
  },
  {
    type: 'API_KEY', label: 'Generic API Key / Secret', severity: 'CRITICAL',
    risk: 'Third-party service credential exposure',
    reason: 'Matches generic API key assignment patterns. Any service API key shared with a public LLM may be logged or cached.',
    placeholder: '[REDACTED_API_KEY]',
    regex: /\b(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9\-_]{16,}['"]?/gi,
    confidence: 0.82, source: 'regex'
  },
  {
    type: 'API_KEY', label: 'Webhook Secret', severity: 'CRITICAL',
    risk: 'Webhook endpoint hijack — request forgery',
    reason: 'Webhook secrets validate incoming events. Leaking allows attackers to send forged webhooks to your endpoints.',
    placeholder: '[REDACTED_WEBHOOK_SECRET]',
    regex: /\bwebhook[_-]?secret\s*[:=]\s*['"]?[A-Za-z0-9\-_]{16,}['"]?/gi,
    confidence: 0.90, source: 'regex'
  },

  // ════════════════════════════════════════════════════════════════════════════
  // CRITICAL / HIGH — India Government IDs & Financial
  // ════════════════════════════════════════════════════════════════════════════

  {
    type: 'AADHAAR', label: 'Aadhaar Number', severity: 'CRITICAL',
    risk: 'Government ID — irreversible identity theft risk',
    reason: 'Aadhaar is India\'s primary 12-digit biometric ID. Exposure violates DPDPA and enables identity fraud. Context keywords increase confidence.',
    placeholder: '[REDACTED_AADHAAR]',
    // Requires context keyword nearby (aadhaar/uid/aadhar) OR grouped spacing pattern
    regex: /\b(?:aadhaar|aadhar|uid)[:\s#]*\d{4}[\s-]?\d{4}[\s-]?\d{4}\b|\b\d{4}\s\d{4}\s\d{4}\b/gi,
    validator: (m) => m.replace(/\D/g, '').length === 12,
    confidence: 0.92, source: 'regex'
  },
  {
    type: 'PAN', label: 'PAN Card', severity: 'HIGH',
    risk: 'Financial identity theft — tax fraud',
    reason: 'PAN is linked to tax and bank accounts. Exposure enables fraudulent financial activity and impersonation with the IT department.',
    placeholder: '[REDACTED_PAN]',
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g, confidence: 0.96, source: 'regex'
  },
  {
    type: 'GSTIN', label: 'GSTIN', severity: 'HIGH',
    risk: 'Business tax identity exposure',
    reason: 'GSTIN reveals a business\'s GST registration, linked to returns and financial records.',
    placeholder: '[REDACTED_GSTIN]',
    regex: /\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/g, confidence: 0.94, source: 'regex'
  },
  {
    type: 'VOTER_ID', label: 'Voter ID (EPIC)', severity: 'HIGH',
    risk: 'Government ID — identity exposure',
    reason: 'Voter ID (EPIC) is a government-issued identity document. Exposure can enable identity fraud.',
    placeholder: '[REDACTED_VOTER_ID]',
    regex: /\b[A-Z]{3}\d{7}\b/g, confidence: 0.82, source: 'regex'
  },
  {
    type: 'DL', label: 'Driving Licence', severity: 'HIGH',
    risk: 'Government ID — identity exposure',
    reason: 'Indian driving licence numbers identify individuals in government records and enable identity fraud.',
    placeholder: '[REDACTED_DL]',
    regex: /\b[A-Z]{2}[\s-]?\d{2}[\s-]?\d{4}[\s-]?\d{7}\b/g, confidence: 0.80, source: 'regex'
  },
  {
    type: 'PASSPORT', label: 'Passport Number', severity: 'HIGH',
    risk: 'International identity fraud risk',
    reason: 'Passport numbers are primary international identity documents. Leaking enables identity theft and travel fraud.',
    placeholder: '[REDACTED_PASSPORT]',
    regex: /\b[A-Z][0-9]{7}\b/g, confidence: 0.75, source: 'regex'
  },
  {
    type: 'UPI', label: 'UPI ID', severity: 'MEDIUM',
    risk: 'Payment identity — targeted fraud',
    reason: 'UPI IDs are linked to bank accounts. Sharing can enable phishing or fraudulent payment requests.',
    placeholder: '[REDACTED_UPI_ID]',
    regex: /\b[\w.\-]{3,}@(okaxis|okicici|oksbi|okhdfcbank|paytm|ybl|upi|apl|ibl|axl|barodampay|cnrb|dbs|equitas|fbl|federal|hdfcbank|icici|idbi|idfc|idfcbank|indus|kotak|pnb|rbl|sib|slice|ucobank)\b/gi,
    confidence: 0.88, source: 'regex'
  },
  {
    type: 'BANK_ACCOUNT', label: 'Bank Account Number', severity: 'HIGH',
    risk: 'Direct banking fraud — fund theft',
    reason: 'Bank account numbers can be used for fraudulent transfers. Never share with public AI tools.',
    placeholder: '[REDACTED_BANK_ACCOUNT]',
    regex: /\b(?:account[\s_-]?(?:no|num|number)[:\s]+)\d{9,18}\b/gi,
    confidence: 0.85, source: 'regex'
  },
  {
    type: 'CARD', label: 'Credit / Debit Card', severity: 'CRITICAL',
    risk: 'Direct financial fraud — PCI violation',
    reason: 'Card number passes Luhn validation. Sharing even without CVV still violates PCI-DSS and enables fraud.',
    placeholder: '[REDACTED_CARD]',
    regex: /\b(?:\d[ -]*?){13,19}\b/g, validator: luhn, confidence: 0.92, source: 'regex'
  },

  // ════════════════════════════════════════════════════════════════════════════
  // HIGH / MEDIUM — Personal Information & PII
  // ════════════════════════════════════════════════════════════════════════════

  {
    type: 'EMAIL', label: 'Email Address', severity: 'MEDIUM',
    risk: 'Phishing & spam targeting',
    reason: 'Personal emails enable targeted phishing and linkage across data breaches.',
    placeholder: '[REDACTED_EMAIL]',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, confidence: 0.90, source: 'regex'
  },
  {
    // BUG FIX: original regex /[6-9]\d{9}/ missed spaces inside the number like "+91 90000 12345"
    // Fixed: allow optional space/dash between the two 5-digit groups
    type: 'PHONE', label: 'Indian Mobile Number', severity: 'MEDIUM',
    risk: 'SIM swap & identity verification abuse',
    reason: 'Phone numbers are used for OTPs and identity verification. Sharing increases SIM-swap and targeted phishing risk.',
    placeholder: '[REDACTED_PHONE]',
    regex: /\b(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/g, confidence: 0.90, source: 'regex'
  },
  {
    type: 'ADDRESS', label: 'Physical Address', severity: 'MEDIUM',
    risk: 'Physical privacy loss — doxxing risk',
    reason: 'Full addresses enable doxxing. AI should work with city/region only, not street-level details.',
    placeholder: '[REDACTED_ADDRESS]',
    regex: /\b\d{1,4}[\/,]?\s*[A-Za-z ]+(Street|St|Road|Rd|Nagar|Colony|Layout|Phase|Marg|Sector|Block)\b/gi,
    confidence: 0.70, source: 'regex'
  },
  {
    type: 'ADDRESS', label: 'Indian PIN Code', severity: 'LOW',
    risk: 'Location disclosure',
    reason: 'PIN codes narrow location to a specific post office area. Combined with name it identifies a person\'s locality.',
    placeholder: '[REDACTED_PINCODE]',
    regex: /\b(?:pin|pincode|zip)[\s:]*[1-9]\d{5}\b/gi, confidence: 0.78, source: 'regex'
  },
  {
    type: 'GPS', label: 'GPS Coordinates', severity: 'MEDIUM',
    risk: 'Precise physical location disclosure',
    reason: 'GPS coordinates pinpoint exact physical location, enabling tracking, stalking, or geofencing attacks.',
    placeholder: '[REDACTED_GPS]',
    regex: /\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b/g,
    confidence: 0.80, source: 'regex'
  },
  {
    type: 'EMPLOYEE_ID', label: 'Employee / Student ID', severity: 'LOW',
    risk: 'Org identity disclosure',
    reason: 'Employee and student IDs can be used to impersonate someone within an organization.',
    placeholder: '[REDACTED_EMP_ID]',
    regex: /\b(?:emp(?:loyee)?[\s_-]?(?:id|no|code)[:\s]+|student[\s_-]?(?:id|no)[:\s]+)[A-Z0-9\-]{4,16}\b/gi,
    confidence: 0.75, source: 'regex'
  },

  // ════════════════════════════════════════════════════════════════════════════
  // HIGH — Infrastructure & Internal
  // ════════════════════════════════════════════════════════════════════════════

  {
    type: 'INFRASTRUCTURE', label: 'Private IP Address', severity: 'HIGH',
    risk: 'Internal network topology exposure',
    reason: 'Private IP addresses reveal internal network structure. Combined with credentials, they enable targeted infrastructure attacks.',
    placeholder: '[INTERNAL_IP]',
    regex: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g,
    validator: isPrivateIP, confidence: 0.95, source: 'regex'
  },
  {
    type: 'INTERNAL', label: 'Internal Collaboration Link', severity: 'MEDIUM',
    risk: 'Corporate data leakage',
    reason: 'Internal Notion/Confluence/Jira/Slack links reveal org structure and may expose auth-gated docs to AI review queues.',
    placeholder: '[REDACTED_INT_LINK]',
    regex: /https?:\/\/(?:[a-z0-9-]+\.)*atlassian\.net\/\S+|https?:\/\/[a-z0-9-]*\.notion\.site\/\S+|https?:\/\/[a-z0-9-]*\.slack\.com\/\S+|https?:\/\/internal\.[a-z0-9.-]+\/\S+/gi,
    confidence: 0.85, source: 'regex'
  },
  {
    type: 'SOURCE_CODE', label: 'Docker / K8s Secret in YAML', severity: 'CRITICAL',
    risk: 'Infrastructure credential exposure',
    reason: 'Docker-compose or Kubernetes YAML with embedded passwords exposes infrastructure credentials to public AI.',
    placeholder: '[REDACTED_INFRA_SECRET]',
    regex: /\b(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD)\s*:\s*\S+/g,
    confidence: 0.93, source: 'regex'
  },
]

// ─── Context-Aware Keyword Signals ────────────────────────────────────────────
// These catch semantic patterns that pure regex misses, including
// context-boosted Aadhaar detection (PRD §9 "context-aware validation")

const CONTEXTUAL_KEYWORDS: Array<{
  test: RegExp
  make: (m: string, idx: number) => Detection
}> = [

  // ── Salary / compensation ────────────────────────────────────────────────
  {
    test: /(?:my |our )?(?:salary|ctc|package|compensation|hike|appraisal)\s*(?:is|of|:)?\s*₹?\s*[\d.,]+\s*(?:LPA|lakh|lac|per annum|CTC|k\/month|per month)?/gi,
    make: (span, i) => ({
      id: `ctx-fin-${i}`, span, type: 'FINANCIAL', label: 'Salary / Compensation',
      severity: 'MEDIUM', risk: 'Compensation leakage',
      reason: 'Salary figures are sensitive HR data under most employment contracts. Consider generalising.',
      placeholder: '[REDACTED_SALARY]', start: -1, end: -1, confidence: 0.82, source: 'llm' as const
    })
  },

  // ── Org + role (social graph) ────────────────────────────────────────────
  {
    test: /my\s+(?:manager|lead|director|CTO|CEO|VP|boss)\s+(?:at\s+|is\s+)?[A-Z][a-zA-Z]+/g,
    make: (span, i) => ({
      id: `ctx-pname-${i}`, span, type: 'PERSON_NAME', label: 'Person + Role', severity: 'LOW',
      risk: 'Social graph leakage',
      reason: 'Naming individuals with roles leaks workplace relationships and org hierarchy.',
      placeholder: '[REDACTED_NAME]', start: -1, end: -1, confidence: 0.68, source: 'llm' as const
    })
  },

  // ── Medical / health ─────────────────────────────────────────────────────
  {
    test: /(?:my|patient(?:'s)?)\s+(?:sugar|bp|blood pressure|thyroid|medical|diabetes|cancer|HIV|diagnosis|prescription|diagnosis)\s+(?:report|is|level|test|result).{0,50}/gi,
    make: (span, i) => ({
      id: `ctx-med-${i}`, span, type: 'MEDICAL', label: 'Medical Information', severity: 'HIGH',
      risk: 'Health privacy — special category data',
      reason: 'Health data is special-category personal data under DPDPA and GDPR. Requires explicit consent to process.',
      placeholder: '[REDACTED_MEDICAL]', start: -1, end: -1, confidence: 0.75, source: 'llm' as const
    })
  },

  // ── M&A / acquisition ───────────────────────────────────────────────────
  {
    test: /\b(?:acquire|acquisition|merger|takeover|buyout)\b.{0,80}/gi,
    make: (span, i) => ({
      id: `ctx-ma-${i}`, span, type: 'BUSINESS_CONFIDENTIAL', label: 'M&A / Acquisition',
      severity: 'HIGH', risk: 'Confidential — securities-sensitive information',
      reason: 'M&A information is highly sensitive and may constitute insider information under SEBI regulations.',
      placeholder: '[REDACTED_BUSINESS_INFO]', start: -1, end: -1, confidence: 0.78, source: 'llm' as const
    })
  },

  // ── Confidentiality markers ──────────────────────────────────────────────
  {
    test: /\b(?:unreleased|confidential|internal[\s-]only|non[\s-]public|trade[\s-]secret|not[\s-]yet[\s-]announced|under[\s-]NDA|proprietary)\b/gi,
    make: (span, i) => ({
      id: `ctx-conf-${i}`, span, type: 'BUSINESS_CONFIDENTIAL', label: 'Confidential Marker',
      severity: 'HIGH', risk: 'Confidential business information',
      reason: 'Explicit confidentiality markers detected. Public LLMs may cache or log this content.',
      placeholder: '[REDACTED_CONFIDENTIAL]', start: -1, end: -1, confidence: 0.80, source: 'llm' as const
    })
  },

  // ── Layoff / HR ──────────────────────────────────────────────────────────
  {
    test: /\b(?:layoff|retrenchment|termination[\s-]plan|headcount[\s-]reduction|pip[\s-]plan|pip[\s-]process)\b/gi,
    make: (span, i) => ({
      id: `ctx-hr-${i}`, span, type: 'BUSINESS_CONFIDENTIAL', label: 'Internal HR / Layoff',
      severity: 'HIGH', risk: 'Sensitive internal HR information',
      reason: 'Internal HR decisions should not be shared with public AI tools. Risk of premature disclosure.',
      placeholder: '[REDACTED_HR_INFO]', start: -1, end: -1, confidence: 0.75, source: 'llm' as const
    })
  },

  // ── Proprietary IP / source code ─────────────────────────────────────────
  {
    test: /\b(?:proprietary algorithm|internal library|internal class|patent-pending|our secret sauce|trade[-\s]secret algorithm)\b/gi,
    make: (span, i) => ({
      id: `ctx-ip-${i}`, span, type: 'SOURCE_CODE', label: 'Proprietary IP / Algorithm',
      severity: 'HIGH', risk: 'Intellectual property disclosure',
      reason: 'Sharing proprietary algorithms or internal libraries with public AI may constitute IP disclosure.',
      placeholder: '[REDACTED_IP]', start: -1, end: -1, confidence: 0.72, source: 'llm' as const
    })
  },

  // ── Org mentions with context ────────────────────────────────────────────
  {
    test: /\b(?:Infosys|TCS|Wipro|Accenture|Cognizant|HCL|Capgemini|Tech Mahindra)\b/gi,
    make: (span, i) => ({
      id: `ctx-org-${i}`, span, type: 'INTERNAL', label: 'Employer Mention',
      severity: 'LOW', risk: 'Org inference',
      reason: 'Mentioning employer with sensitive detail lets AI correlate you to an org. Consider generalising.',
      placeholder: '[REDACTED_ORG]', start: -1, end: -1, confidence: 0.60, source: 'llm' as const
    })
  },

  // ── .env / config dump signals ───────────────────────────────────────────
  {
    test: /\b(?:\.env|env\.local|env\.production|config\.yml|secrets\.yaml|application\.properties)\b/gi,
    make: (span, i) => ({
      id: `ctx-env-${i}`, span, type: 'ENV_FILE', label: 'Config / Secret File Reference',
      severity: 'HIGH', risk: 'All app secrets at risk',
      reason: 'Referencing .env or secret config files suggests credentials may follow. Review entire prompt.',
      placeholder: '[REDACTED_CONFIG_FILE]', start: -1, end: -1, confidence: 0.78, source: 'llm' as const
    })
  },
]

// ─── Layer 1: Local Deterministic Scan ───────────────────────────────────────

export function scanLocal(text: string): Detection[] {
  const out: Detection[] = []
  let id = 0

  for (const p of PATTERNS) {
    const re = new RegExp(p.regex.source, p.regex.flags)
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const span = m[0]
      if (p.validator && !p.validator(span)) continue
      if (p.type === 'CARD' && !luhn(span)) continue
      if (p.type === 'CARD' && span.includes('@')) continue
      const start = m.index
      const end = start + span.length
      // de-duplicate overlapping spans
      if (out.some(d => !(end <= d.start || start >= d.end))) continue
      out.push({
        id: `d-${id++}`, span, type: p.type, label: p.label,
        severity: p.severity, risk: p.risk, reason: p.reason,
        placeholder: p.placeholder, start, end,
        confidence: p.confidence, source: p.source
      })
      if (m[0].length === 0) re.lastIndex++
    }
  }

  // Contextual keyword layer
  CONTEXTUAL_KEYWORDS.forEach(k => {
    const re = new RegExp(k.test.source, k.test.flags)
    let m: RegExpExecArray | null
    let j = 0
    while ((m = re.exec(text)) !== null) {
      const span = m[0]
      const d = k.make(span, j++)
      const idx = text.indexOf(span)
      if (idx >= 0) { d.start = idx; d.end = idx + span.length }
      if (!out.some(o => o.span === span)) out.push(d)
      if (m[0].length === 0) re.lastIndex++
    }
  })

  return out.sort((a, b) => a.start - b.start)
}

// ─── Risk Level Computation (PRD §20 combination logic) ──────────────────────

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE'

export function computeRiskLevel(detections: Detection[]): RiskLevel {
  if (detections.length === 0) return 'SAFE'

  const hasCritical = detections.some(d => d.severity === 'CRITICAL')
  const hasHigh = detections.some(d => d.severity === 'HIGH')
  const hasMedium = detections.some(d => d.severity === 'MEDIUM')

  // Combination amplification: infra + credential → CRITICAL
  const hasInfra = detections.some(d => d.type === 'INFRASTRUCTURE' || d.type === 'DB_CREDENTIAL')
  const hasCredential = detections.some(d =>
    d.type === 'PASSWORD' || d.type === 'API_KEY' || d.type === 'TOKEN'
  )
  if (hasInfra && hasCredential) return 'CRITICAL'

  // Email alone → MEDIUM, but email + personal record → HIGH
  const hasEmail = detections.some(d => d.type === 'EMAIL')
  const hasOtherPII = detections.some(d =>
    ['PAN', 'AADHAAR', 'PHONE', 'ADDRESS', 'PERSON_NAME', 'BANK_ACCOUNT'].includes(d.type)
  )
  if (hasEmail && hasOtherPII && !hasCritical && !hasHigh) return 'HIGH'

  if (hasCritical) return 'CRITICAL'
  if (hasHigh) return 'HIGH'
  if (hasMedium) return 'MEDIUM'
  return 'LOW'
}

// ─── Policy Decision Engine ──────────────────────────────────────────────────
// ALLOW / WARN / REDACT / BLOCK — explicit 4-state policy machine

export type PolicyDecision = 'ALLOW' | 'WARN' | 'REDACT' | 'BLOCK'

export function computePolicy(riskLevel: RiskLevel): PolicyDecision {
  if (riskLevel === 'SAFE') return 'ALLOW'
  if (riskLevel === 'LOW' || riskLevel === 'MEDIUM') return 'WARN'
  if (riskLevel === 'HIGH') return 'REDACT'
  return 'BLOCK' // CRITICAL
}

// ─── Cloud Gate — sanitizeForCloud() ─────────────────────────────────────────
// ARCHITECTURAL RULE: Cloud AI (Groq / Gemini) MUST NEVER receive raw text
// containing secrets, PII, credentials, or CRITICAL detections.
// Always call sanitizeForCloud() before any cloud LLM request.
// Local Ollama (on-device) may receive the raw prompt.

export function sanitizeForCloud(
  rawText: string,
  detections: Detection[]
): string {
  if (!detections.length) return rawText
  return redactText(rawText, detections, 'redact')
}

// ─── Conversation-Level Context Window ────────────────────────────────────────
// Lightweight sliding window — tracks entity types from recent messages.
// Enables combination amplification across turns (e.g. email in turn 1,
// PAN in turn 2 → both are now HIGH risk together).

type ContextEntry = { ts: number; types: Set<DetectionCategory> }
const CONTEXT_WINDOW_MS = 10 * 60 * 1000 // 10 minutes
const conversationContext: ContextEntry[] = []

export function recordToContext(detections: Detection[]): void {
  if (!detections.length) return
  const now = Date.now()
  // Prune old entries outside the window
  while (conversationContext.length && now - conversationContext[0].ts > CONTEXT_WINDOW_MS) {
    conversationContext.shift()
  }
  conversationContext.push({ ts: now, types: new Set(detections.map(d => d.type)) })
}

export function getContextTypes(): Set<DetectionCategory> {
  const now = Date.now()
  const merged = new Set<DetectionCategory>()
  for (const e of conversationContext) {
    if (now - e.ts <= CONTEXT_WINDOW_MS) e.types.forEach(t => merged.add(t))
  }
  return merged
}

// Recalculate risk level considering cross-turn context
export function computeRiskWithContext(detections: Detection[]): RiskLevel {
  const ctxTypes = getContextTypes()
  // Merge current detection types with recent context
  const allTypes = new Set([...detections.map(d => d.type), ...ctxTypes])
  const hasEmail = allTypes.has('EMAIL')
  const hasOtherPII = ['PAN', 'AADHAAR', 'PHONE', 'BANK_ACCOUNT'].some(t => allTypes.has(t as DetectionCategory))
  // If context adds PII that creates a combination, upgrade
  if (hasEmail && hasOtherPII && detections.length > 0) {
    const base = computeRiskLevel(detections)
    if (base === 'MEDIUM') return 'HIGH'
  }
  return computeRiskLevel(detections)
}

export function clearContext(): void {
  conversationContext.length = 0
}

// ─── Redaction / Pseudonymisation ────────────────────────────────────────────

export function redactText(
  text: string,
  detections: Detection[],
  mode: 'redact' | 'pseudonymize' = 'redact'
): string {
  if (!detections.length) return text
  const sorted = [...detections].sort((a, b) => b.start - a.start)
  let out = text
  const pseudoMap: Record<string, string> = {
    EMAIL: 'user@example.com',
    PHONE: '+91 90000 00000',
    PERSON_NAME: 'Person A',
    ADDRESS: '[City, State]',
    UPI: 'user@bank',
  }
  for (const d of sorted) {
    if (d.start < 0 || d.end < 0) continue
    const rep = mode === 'pseudonymize' && pseudoMap[d.type] ? pseudoMap[d.type] : d.placeholder
    out = out.slice(0, d.start) + rep + out.slice(d.end)
  }
  return out
}

// ─── Layer 3A: Groq API (Llama 3.1 / 3.2) ────────────────────────────────────

export async function scanWithGroq(
  text: string, groqKey: string, modelHint: string
): Promise<Detection[]> {
  if (!groqKey || !text.trim() || text.length < 12) return []
  const hasSensitiveHint = /api|key|secret|aadhaar|pan|salary|manager|medical|password|token|confluence|notion|email|phone|gstin|upi|acquire|confidential|private key/i.test(text)
  if (!hasSensitiveHint && scanLocal(text).length === 0) return []
  const groqModel = modelHint === 'qwen3b' ? 'llama-3.2-3b-preview'
    : modelHint === 'llama3b' ? 'llama-3.2-3b-preview'
    : 'llama-3.1-8b-instant'
  try {
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${groqKey}` },
      body: JSON.stringify({
        model: groqModel, temperature: 0.1, max_tokens: 700,
        messages: [
          { role: 'system', content: 'You are Ultron, a privacy auditor. Return ONLY valid JSON array, no markdown.' },
          {
            role: 'user',
            content: `Find sensitive spans in this prompt that regex missed. Focus on: salary, org+role, medical, M&A, confidential business, proprietary code, username, employee IDs, GPS, social media handles.\nPROMPT:\n"""${text.slice(0, 4000)}"""\n\nReturn JSON: [{"span":..., "label":..., "type": FINANCIAL|MEDICAL|INTERNAL|PERSON_NAME|ADDRESS|PASSWORD|BUSINESS_CONFIDENTIAL|SOURCE_CODE|USERNAME|EMPLOYEE_ID|GPS, "severity": CRITICAL|HIGH|MEDIUM|LOW, "risk":..., "reason":..., "placeholder":...}]. Return [] if none.`
          }
        ]
      })
    })
    if (!res.ok) throw new Error(`Groq ${res.status}`)
    const json: any = await res.json()
    const txt: string = json.choices?.[0]?.message?.content || ''
    const cleaned = txt.replace(/```json|```/g, '').trim()
    const s = cleaned.indexOf('['); const e = cleaned.lastIndexOf(']')
    if (s === -1 || e === -1) return []
    const arr = JSON.parse(cleaned.slice(s, e + 1))
    if (!Array.isArray(arr)) return []
    return arr.map((o: any, i: number) => {
      const span: string = String(o.span || '').slice(0, 200)
      const idx = span ? text.indexOf(span) : -1
      return {
        id: `groq-${i}-${Date.now()}`, span: span || o.label || 'sensitive span',
        type: (o.type as DetectionCategory) || 'INTERNAL',
        label: String(o.label || 'Contextual risk'),
        severity: (o.severity as Severity) || 'MEDIUM',
        risk: String(o.risk || 'Contextual leakage'),
        reason: String(o.reason || 'Detected by Groq LLM.'),
        placeholder: String(o.placeholder || '[REDACTED_CONTEXT]'),
        start: idx, end: idx >= 0 ? idx + span.length : -1,
        confidence: 0.78, source: 'llm' as const
      }
    }).filter((d: Detection) => d.span && d.span.length > 1)
  } catch (e) {
    console.warn('[Ultron] Groq scan failed', e)
    return []
  }
}

// ─── Layer 3B: Gemini API (cloud fallback) ────────────────────────────────────

export async function scanWithLLM(
  text: string, apiKey: string, modelHint: string
): Promise<Detection[]> {
  if (!apiKey || !text.trim() || text.length < 12) return []
  const hasSensitiveHint = /api|key|secret|aadhaar|pan|salary|manager|medical|password|token|gstin|upi|confidential/i.test(text)
  if (!hasSensitiveHint && scanLocal(text).length === 0) return []
  try {
    const { GoogleGenAI } = await import('@google/genai')
    const ai = new GoogleGenAI({ apiKey })
    const prompt = `You are Ultron, a privacy auditor. Find sensitive spans in this user prompt that regex missed.\nFocus on: salary, org+role, medical, M&A, confidential business, proprietary code, username, employee IDs, GPS coordinates.\nDO NOT flag generic greetings or harmless code.\n\nPROMPT:\n"""${text.slice(0, 4000)}"""\n\nReturn JSON array: [{"span":..., "label":..., "type": FINANCIAL|MEDICAL|INTERNAL|PERSON_NAME|ADDRESS|PASSWORD|BUSINESS_CONFIDENTIAL|SOURCE_CODE|USERNAME|EMPLOYEE_ID|GPS, "severity": CRITICAL|HIGH|MEDIUM|LOW, "risk":..., "reason": 1 sentence, "placeholder":...}]. Return [] if none. ONLY JSON, no markdown.`
    const res = await ai.models.generateContent({
      model: 'gemini-2.0-flash', contents: prompt,
      config: { temperature: 0.1, maxOutputTokens: 700 }
    })
    const txt: string = (res as any).text || (res as any).response?.text?.() || (res as any).candidates?.[0]?.content?.parts?.[0]?.text || ''
    if (!txt) return []
    const cleaned = txt.replace(/```json|```/g, '').trim()
    const start = cleaned.indexOf('['); const end = cleaned.lastIndexOf(']')
    if (start === -1 || end === -1) return []
    const arr = JSON.parse(cleaned.slice(start, end + 1))
    if (!Array.isArray(arr)) return []
    return arr.map((o: any, i: number) => {
      const span: string = String(o.span || '').slice(0, 200)
      const idx = span ? text.indexOf(span) : -1
      return {
        id: `llm-${i}-${Date.now()}`, span: span || o.label || 'sensitive span',
        type: (o.type as DetectionCategory) || 'INTERNAL',
        label: String(o.label || 'Contextual risk'),
        severity: (o.severity as Severity) || 'MEDIUM',
        risk: String(o.risk || 'Contextual leakage'),
        reason: String(o.reason || 'Detected by Gemini contextual model.'),
        placeholder: String(o.placeholder || '[REDACTED_CONTEXT]'),
        start: idx, end: idx >= 0 ? idx + span.length : -1,
        confidence: 0.78, source: 'llm' as const
      }
    }).filter((d: Detection) => d.span && d.span.length > 1)
  } catch (e) {
    console.warn('[Ultron] LLM scan failed, falling back to local', e)
    return []
  }
}

// ─── Layer 3C: Ollama Local (Qwen3 4B — privacy-first, no network) ────────────

export async function scanWithOllama(
  text: string, ollamaUrl: string, model = 'qwen3:4b'
): Promise<Detection[]> {
  const baseUrl = ollamaUrl || 'http://localhost:11434'
  if (!text.trim() || text.length < 12) return []
  const hasSensitiveHint = /api|key|secret|aadhaar|pan|salary|manager|medical|password|token|email|phone|gstin|confidential|acquire/i.test(text)
  if (!hasSensitiveHint && scanLocal(text).length === 0) return []
  try {
    const res = await fetch(`${baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model, stream: false,
        options: { temperature: 0.1, num_predict: 700 },
        messages: [
          { role: 'system', content: 'You are Ultron, a local privacy auditor running on-device. Return ONLY valid JSON array, no markdown.' },
          {
            role: 'user',
            content: `Find sensitive spans regex missed. Focus on: salary, medical, M&A, confidential business, proprietary code, username, GPS.\nPROMPT:\n"""${text.slice(0, 3000)}"""\n\nReturn JSON: [{"span":..., "label":..., "type":..., "severity": CRITICAL|HIGH|MEDIUM|LOW, "risk":..., "reason":..., "placeholder":...}]. Return [] if none.`
          }
        ]
      })
    })
    if (!res.ok) throw new Error(`Ollama ${res.status}`)
    const json: any = await res.json()
    const txt: string = json.message?.content || ''
    if (!txt) return []
    const cleaned = txt.replace(/```json|```/g, '').replace(/<think>[\s\S]*?<\/think>/g, '').trim()
    const s = cleaned.indexOf('['); const e = cleaned.lastIndexOf(']')
    if (s === -1 || e === -1) return []
    const arr = JSON.parse(cleaned.slice(s, e + 1))
    if (!Array.isArray(arr)) return []
    return arr.map((o: any, i: number) => {
      const span: string = String(o.span || '').slice(0, 200)
      const idx = span ? text.indexOf(span) : -1
      return {
        id: `ollama-${i}-${Date.now()}`, span: span || o.label || 'sensitive span',
        type: (o.type as DetectionCategory) || 'INTERNAL',
        label: String(o.label || 'Contextual risk'),
        severity: (o.severity as Severity) || 'MEDIUM',
        risk: String(o.risk || 'Contextual leakage'),
        reason: String(o.reason || 'Detected by local Qwen3 model.'),
        placeholder: String(o.placeholder || '[REDACTED_CONTEXT]'),
        start: idx, end: idx >= 0 ? idx + span.length : -1,
        confidence: 0.80, source: 'llm' as const
      }
    }).filter((d: Detection) => d.span && d.span.length > 1)
  } catch (e) {
    console.warn('[Ultron] Ollama scan failed (is Ollama running?)', e)
    return []
  }
}

// ─── Prompt Enhancement ───────────────────────────────────────────────────────

export async function enhancePrompt(
  safePrompt: string,
  opts: { geminiKey?: string; groqKey?: string; ollamaUrl?: string }
): Promise<string> {
  if (!safePrompt.trim()) return safePrompt
  const system = `You are PromptCowboy + Ultron. Turn lazy prompts into great prompts while keeping ALL privacy placeholders intact (like [REDACTED_EMAIL], [REDACTED_KEY]). Never invent real data for placeholders. Add role, goal, constraints and output format. Return ONLY the enhanced prompt text, no quotes, no preamble.`
  const user = `Lazy prompt:\n"""${safePrompt.slice(0, 3000)}"""\n\nEnhance it into a great prompt.`

  // Try Ollama first (fully local, no network)
  if (opts.ollamaUrl) {
    try {
      const r = await fetch(`${opts.ollamaUrl}/api/chat`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'qwen3:4b', stream: false,
          options: { temperature: 0.4, num_predict: 700 },
          messages: [{ role: 'system', content: system }, { role: 'user', content: user }]
        })
      })
      if (r.ok) {
        const j: any = await r.json()
        const t = j.message?.content?.replace(/<think>[\s\S]*?<\/think>/g, '').trim()
        if (t) return t.replace(/^"|"$/g, '')
      }
    } catch { /* fall through */ }
  }

  // Groq (fast cloud)
  if (opts.groqKey) {
    try {
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${opts.groqKey}` },
        body: JSON.stringify({ model: 'llama-3.1-8b-instant', temperature: 0.4, max_tokens: 700, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] })
      })
      if (r.ok) {
        const j: any = await r.json()
        const t = j.choices?.[0]?.message?.content?.trim()
        if (t) return t.replace(/^"|"$/g, '')
      }
    } catch { /* fall through */ }
  }

  // Gemini fallback
  if (opts.geminiKey) {
    try {
      const { GoogleGenAI } = await import('@google/genai')
      const ai = new GoogleGenAI({ apiKey: opts.geminiKey })
      const res = await ai.models.generateContent({
        model: 'gemini-2.0-flash', contents: `${system}\n\n${user}`,
        config: { temperature: 0.4, maxOutputTokens: 700 }
      })
      const t: string = (res as any).text || (res as any).candidates?.[0]?.content?.parts?.[0]?.text || ''
      if (t) return t.replace(/^"|"$/g, '').trim()
    } catch { /* fall through */ }
  }

  // Heuristic fallback
  return safePrompt.trim().replace(/\s+/g, ' ').replace(/^./, c => c.toUpperCase())
}
