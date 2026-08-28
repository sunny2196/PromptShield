// Session Contamination Graph — killer insight: memory persists across turns
export type LeakRecord = {
  id: string
  span: string
  label: string
  severity: 'HIGH'|'MEDIUM'|'LOW'
  type: string
  timestamp: number // ms
  promptIndex: number
}

export type SessionState = {
  sessionId: string
  leaks: LeakRecord[]
  createdAt: number
}

const STORAGE_KEY = 'ps_session_v2'
const SESSION_TTL_MS = 1000 * 60 * 60 * 2 // 2h

function now(){ return Date.now() }

function sensitivity(sev: string): number {
  if(sev==='HIGH') return 9
  if(sev==='MEDIUM') return 5
  return 2
}
function exploitability(type: string, sev: string): number {
  if(type==='API_KEY') return 10
  if(type==='AADHAAR' || type==='PAN' || type==='CARD' || type==='PASSWORD') return 9
  if(sev==='HIGH') return 8
  if(sev==='MEDIUM') return 5
  return 3
}

export function getSessionId(): string {
  let sid = localStorage.getItem('ps_session_id')
  if(!sid){
    sid = `sess_${Math.random().toString(36).slice(2,10)}_${now().toString(36)}`
    localStorage.setItem('ps_session_id', sid)
    localStorage.setItem('ps_session_created', String(now()))
  }
  // rotate if older than TTL
  const created = Number(localStorage.getItem('ps_session_created')|| now())
  if(now() - created > SESSION_TTL_MS){
    sid = `sess_${Math.random().toString(36).slice(2,10)}_${now().toString(36)}`
    localStorage.setItem('ps_session_id', sid)
    localStorage.setItem('ps_session_created', String(now()))
    localStorage.removeItem(STORAGE_KEY)
  }
  return sid
}

export function loadSession(): SessionState {
  const sid = getSessionId()
  try{
    const raw = localStorage.getItem(STORAGE_KEY)
    if(raw){
      const j = JSON.parse(raw) as SessionState
      if(j.sessionId===sid) return j
    }
  }catch{}
  return { sessionId: sid, leaks: [], createdAt: now() }
}

export function saveSession(s: SessionState){
  localStorage.setItem(STORAGE_KEY, JSON.stringify(s))
}

export function addLeaks(dets: Array<{span:string,label:string,severity:'HIGH'|'MEDIUM'|'LOW',type:string}>, promptIndex: number){
  const s = loadSession()
  const ts = now()
  for(const d of dets){
    if(s.leaks.some(l=> l.span===d.span && l.type===d.type)) continue
    s.leaks.push({ id:`leak_${ts}_${Math.random().toString(36).slice(2,6)}`, span:d.span, label:d.label, severity:d.severity, type:d.type, timestamp:ts, promptIndex })
  }
  saveSession(s)
  return s
}

export function contaminationScore(s: SessionState = loadSession()): number {
  // max risk across leaks: sensitivity * exploitability * persistence(1)
  let max = 0
  for(const l of s.leaks){
    const risk = sensitivity(l.severity) * exploitability(l.type, l.severity) * 1
    if(risk > max) max = risk
  }
  // also sum normalized: slight boost for multiple leaks
  const sum = s.leaks.reduce((acc,l)=> acc + sensitivity(l.severity)*exploitability(l.type,l.severity),0)
  // return max (primary) - threshold 15 as per spec
  return Math.max(max, Math.min(100, Math.round(sum/10)))
}

export function isContaminated(score = contaminationScore()): boolean {
  return score > 15
}

export function contaminationBanner(s: SessionState = loadSession()): string | null {
  if(!s.leaks.length) return null
  const score = contaminationScore(s)
  if(score <= 15) return null
  const latest = s.leaks[s.leaks.length-1]
  const agoMin = Math.max(1, Math.round((now() - latest.timestamp)/60000))
  const highCount = s.leaks.filter(l=> l.severity==='HIGH').length
  return `This chat already contains ${highCount || s.leaks.length} ${highCount?'HIGH':''} leak${s.leaks.length>1?'s':''} from ${agoMin} min ago (${latest.label}: ${latest.span.slice(0,18)}…). This session is tainted — start NEW CHAT. Score ${score}/100.`
}

export function clearSession(){
  const sid = getSessionId()
  const s: SessionState = { sessionId: sid, leaks: [], createdAt: now() }
  saveSession(s)
  localStorage.setItem('ps_session_created', String(now()))
  // also rotate id
  const newId = `sess_${Math.random().toString(36).slice(2,10)}_${now().toString(36)}`
  localStorage.setItem('ps_session_id', newId)
  saveSession({ sessionId: newId, leaks: [], createdAt: now() })
  return newId
}

export function sessionStats(s: SessionState = loadSession()){
  return {
    total: s.leaks.length,
    high: s.leaks.filter(l=> l.severity==='HIGH').length,
    score: contaminationScore(s),
    contaminated: isContaminated(contaminationScore(s)),
    banner: contaminationBanner(s)
  }
}
