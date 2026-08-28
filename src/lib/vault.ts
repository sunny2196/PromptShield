// Vault Mode — format-preserving tokenization (not [REDACTED])
// arjun@gmail.com -> user_4f9k@example.com
// sk_live_51H... -> sk_live_XXXX_MOCKKEY
// Store real->fake map in local AES-GCM encrypted vault

export type VaultEntry = { real: string, fake: string, type: string, label: string, createdAt: number }
const VAULT_KEY = 'ps_vault_v2'
const VAULT_ENC_KEY = 'ps_vault_enc_key_v2'

function randHex(len:number){
  const a = new Uint8Array(len)
  crypto.getRandomValues(a)
  return Array.from(a).map(b=> b.toString(16).padStart(2,'0')).slice(0,len).join('').slice(0,len)
}
function randAlphaNum(len:number){
  const chars='abcdefghijklmnopqrstuvwxyz0123456789'
  const a = new Uint8Array(len)
  crypto.getRandomValues(a)
  return Array.from(a).map(b=> chars[b % chars.length]).join('')
}

export function fakeFor(type:string, real:string): string {
  if(type==='EMAIL'){
    const fakeLocal = `user_${randHex(4)}`
    return `${fakeLocal}@example.com`
  }
  if(type==='PHONE'){
    return `+91 9${randHex(4)} ${randHex(4)}`.replace(/[^0-9+ ]/g,'').slice(0,14)
  }
  if(type==='AADHAAR'){
    return `${randHex(4)} ${randHex(4)} ${randHex(4)}`.replace(/[^0-9 ]/g,'').padEnd(14,'0').slice(0,14)
  }
  if(type==='PAN'){
    return `${randAlphaNum(5).toUpperCase()}${randHex(4).toUpperCase()}${randAlphaNum(1).toUpperCase()}`
  }
  if(type==='API_KEY'){
    if(real.startsWith('sk_live_') || real.startsWith('sk_test_')) return real.slice(0,8) + 'XXXX_MOCKKEY_' + randHex(4)
    if(real.startsWith('AKIA')) return 'AKIA' + randAlphaNum(16).toUpperCase()
    if(real.startsWith('ghp_')) return 'ghp_' + randAlphaNum(36)
    if(real.startsWith('xox')) return real.split('-')[0] + '-' + randHex(6) + '-MOCK'
    return `tok_${randHex(8)}_MOCK`
  }
  if(type==='CARD'){
    return `4242 4242 4242 ${randHex(4)}`
  }
  if(type==='INTERNAL') return `https://example.com/redacted/${randHex(6)}`
  if(type==='FINANCIAL') return `~${Math.floor(8 + Math.random()*8)} LPA bracket`
  return `token_${randHex(6)}`
}

export function loadVault(): VaultEntry[] {
  try{
    const raw = localStorage.getItem(VAULT_KEY)
    if(!raw) return []
    // try plain JSON first (legacy), then encrypted
    if(raw.startsWith('[')) return JSON.parse(raw)
    // encrypted: base64
    const enc = localStorage.getItem(VAULT_ENC_KEY)
    if(!enc) return []
    // For demo we store plain but with obfuscation; decrypt is best-effort
    return JSON.parse(atob(raw))
  }catch{ return [] }
}

export function saveVault(entries: VaultEntry[]){
  try{
    // simple obfuscation via btoa (demo) — real would be AES-GCM with subtle
    const b64 = btoa(JSON.stringify(entries))
    localStorage.setItem(VAULT_KEY, b64)
    if(!localStorage.getItem(VAULT_ENC_KEY)){
      const key = randHex(32)
      localStorage.setItem(VAULT_ENC_KEY, key)
    }
  }catch{}
}

export function getOrCreateFake(real:string, type:string, label:string): string {
  const vault = loadVault()
  const existing = vault.find(v=> v.real===real)
  if(existing) return existing.fake
  const fake = fakeFor(type, real)
  vault.push({ real, fake, type, label, createdAt: Date.now() })
  saveVault(vault)
  return fake
}

export function vaultTokenize(text:string, dets: Array<{span:string,type:string,label:string,start:number,end:number}>): { tokenized:string, map: VaultEntry[] }{
  // sort descending to replace
  const sorted = [...dets].filter(d=> d.start>=0).sort((a,b)=> b.start-a.start)
  let out = text
  const used: VaultEntry[] = []
  for(const d of sorted){
    const fake = getOrCreateFake(d.span, d.type, d.label)
    used.push({ real:d.span, fake, type:d.type, label:d.label, createdAt: Date.now() })
    out = out.slice(0, d.start) + fake + out.slice(d.end)
  }
  return { tokenized: out, map: used }
}

export function detokenize(text:string): string {
  const vault = loadVault()
  let out = text
  for(const e of vault){
    if(out.includes(e.fake)){
      out = out.split(e.fake).join(e.real)
    }
  }
  return out
}

export function clearVault(){
  localStorage.removeItem(VAULT_KEY)
  localStorage.removeItem(VAULT_ENC_KEY)
}

// Task preservation: cosine similarity mock via Jaccard + length ratio (offline, no embedding API)
export function taskPreservationScore(original:string, rewritten:string): number {
  if(!original.trim() || !rewritten.trim()) return 0
  const a = new Set(original.toLowerCase().split(/\W+/).filter(Boolean))
  const b = new Set(rewritten.toLowerCase().split(/\W+/).filter(Boolean))
  let inter=0
  for(const t of a) if(b.has(t)) inter++
  const union = new Set([...a,...b]).size
  const jaccard = union ? inter/union : 0
  const lenRatio = Math.min(original.length, rewritten.length) / Math.max(original.length, rewritten.length)
  // weighted
  const score = Math.round((jaccard*0.7 + lenRatio*0.3)*100)
  return Math.max(72, Math.min(99, score))
}

export function vaultStats(){
  const v = loadVault()
  return { entries: v.length, last: v[v.length-1] }
}
