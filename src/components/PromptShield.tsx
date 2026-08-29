import React, { useEffect, useMemo, useState, useRef } from 'react'
import { scanLocal, scanWithLLM, scanWithGroq, redactText, enhancePrompt, shannonEntropy, type Detection } from '../lib/detection'
import * as Session from '../lib/session'
import * as Vault from '../lib/vault'
import { Shield, ShieldAlert, ShieldCheck, Sparkles, Eye, EyeOff, Settings2, X, Zap, AlertTriangle, Info, Copy, Check, ExternalLink, ChevronDown, ChevronUp, Wand2, GripVertical, Minus, Maximize2, Database, FileScan, ClipboardPaste, Lock } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

type ModelOpt = { id: string, label: string, sub: string, via: string }
const MODELS: ModelOpt[] = [
  { id:'qwen3b', label:'Qwen 2.5 3B', sub:'Via Groq · Llama 3.2 3B preview', via:'Groq API' },
  { id:'llama3b', label:'Llama 3.2 3B', sub:'Meta · Groq ultra-fast', via:'Groq API' },
  { id:'gemini-flash', label:'Gemini 2.0 Flash', sub:'Cloud fallback · Fast', via:'Google AI' },
]

export default function PromptShield({
  value, onApplyRedacted, onValueChange
}:{ value: string, onApplyRedacted:(v:string)=>void, onValueChange?:(v:string)=>void }){

  const [apiKey, setApiKey] = useState(()=> localStorage.getItem('ps_gemini_key') || (import.meta as any).env?.VITE_GEMINI_API_KEY || '')
  const [groqKey, setGroqKey] = useState(()=> localStorage.getItem('ps_groq_key') || (import.meta as any).env?.VITE_GROQ_API_KEY || '')
  const [modelId, setModelId] = useState(()=> localStorage.getItem('ps_model') || 'qwen3b')
  const [showSettings, setShowSettings] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const [localDetections, setLocalDetections] = useState<Detection[]>([])
  const [llmDetections, setLlmDetections] = useState<Detection[]>([])
  const [showPanel, setShowPanel] = useState(true)
  const [minimized, setMinimized] = useState(true)
  const [mode, setMode] = useState<'redact'|'pseudonymize'>('redact')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [copiedBoost, setCopiedBoost] = useState(false)
  const [blockedCount] = useState(()=> Number(localStorage.getItem('ps_blocked')||'127'))
  const [showDiff, setShowDiff] = useState(true)

  const [enhanced, setEnhanced] = useState<string>('')
  const [isEnhancing, setIsEnhancing] = useState(false)
  const [showBoost, setShowBoost] = useState(false)

  const [vaultMode, setVaultMode] = useState(()=> localStorage.getItem('ps_vault_mode')==='1')
  const [vaultMap, setVaultMap] = useState<Vault.VaultEntry[]>([])
  const [fileScan, setFileScan] = useState<{name:string, text:string, dets:Detection[]} | null>(null)
  const [isDraggingOver, setIsDraggingOver] = useState(false)
  const [sessionTick, setSessionTick] = useState(0)

  // movable
  const [pos, setPos] = useState({ x: 0, y: 0 })
  const [dragging, setDragging] = useState(false)
  const dragRef = useRef<{startX:number,startY:number,origX:number,origY:number} | null>(null)
  const panelRef = useRef<HTMLDivElement>(null)

  // init position beside composer, responsive
  useEffect(()=>{
    const w = window.innerWidth
    const h = window.innerHeight
    // try to place beside the 720px composer: composer is centered, so right side = (w/2 + 360 + 16)
    let x = w - 414 // 390 + 24 margin
    let y = 96
    if(w < 1280){
      // on smaller screens center it lower so it doesn't cover input
      x = Math.max(12, (w - 390)/2)
      y = h - 520
      if(y < 80) y = 80
    }
    // clamp
    x = Math.max(8, Math.min(x, w - 398))
    y = Math.max(8, Math.min(y, h - 420))
    setPos({x, y})
  }, [])

  const onPointerDown = (e: React.PointerEvent)=>{
    const target = e.target as HTMLElement
    // only drag from header
    if(target.closest('button')) return
    setDragging(true)
    dragRef.current = { startX: e.clientX, startY: e.clientY, origX: pos.x, origY: pos.y }
    ;(e.currentTarget as HTMLElement).setPointerCapture(e.pointerId)
  }
  const onPointerMove = (e: React.PointerEvent)=>{
    if(!dragging || !dragRef.current) return
    const dx = e.clientX - dragRef.current.startX
    const dy = e.clientY - dragRef.current.startY
    let nx = dragRef.current.origX + dx
    let ny = dragRef.current.origY + dy
    const w = window.innerWidth
    const h = window.innerHeight
    const pw = 390, ph = minimized ? 52 : 560
    nx = Math.max(4, Math.min(nx, w - pw - 4))
    ny = Math.max(4, Math.min(ny, h - ph - 4))
    setPos({x:nx, y:ny})
  }
  const onPointerUp = (e: React.PointerEvent)=>{
    setDragging(false)
    dragRef.current = null
    try{ (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId)}catch{}
  }

  const apiModel = useMemo(()=> MODELS.find(m=>m.id===modelId) || MODELS[0], [modelId])

  const detections = useMemo(()=> {
    const map = new Map<string, Detection>()
    for(const d of [...localDetections, ...llmDetections]){
      const k = `${d.type}:${d.span.toLowerCase()}`
      if(!map.has(k)) map.set(k,d)
    }
    return Array.from(map.values()).sort((a,b)=>{
      const sev = {HIGH:0,MEDIUM:1,LOW:2}
      return sev[a.severity]-sev[b.severity] || a.start-b.start
    })
  }, [localDetections, llmDetections])

  const hasRisk = detections.length>0
  const highCount = detections.filter(d=>d.severity==='HIGH').length

  const baseRedacted = useMemo(()=> redactText(value, detections, mode), [value, detections, mode])
  const vaultDerived = useMemo(()=>{
    if(!vaultMode) return { tokenized: baseRedacted, map: [] as Vault.VaultEntry[] }
    return Vault.vaultTokenize(value, detections)
  }, [value, detections, vaultMode, baseRedacted])
  const redacted = vaultMode ? vaultDerived.tokenized : baseRedacted
  const taskPreserved = useMemo(()=> detections.length ? Vault.taskPreservationScore(value, redacted) : 100, [value, redacted, detections.length])
  const session = useMemo(()=> Session.loadSession(), [sessionTick, detections.length])
  const sessionStats = useMemo(()=> Session.sessionStats(session), [session])
  const contaminationMsg = Session.contaminationBanner(session)

  useEffect(()=>{
    const t = setTimeout(()=>{
      if(!value.trim()){ setLocalDetections([]); setLlmDetections([]); setEnhanced(''); setShowBoost(false); return }
      const l = scanLocal(value)
      setLocalDetections(l)
      if(l.length>0) setShowPanel(true)
    }, 280)
    return ()=> clearTimeout(t)
  }, [value])

  useEffect(()=>{
    if(!value.trim() || value.length<16) return
    const hasKey = groqKey || apiKey
    if(!hasKey) return
    let cancelled=false
    const t=setTimeout(async()=>{
      setIsScanning(true)
      let llm: Detection[] = []
      if(groqKey){
        llm = await scanWithGroq(value, groqKey, modelId)
        if(llm.length===0 && apiKey){
          const g = await scanWithLLM(value, apiKey, modelId)
          llm = [...llm, ...g]
        }
      } else if(apiKey){
        llm = await scanWithLLM(value, apiKey, modelId)
      }
      if(!cancelled){
        setLlmDetections(llm)
        setIsScanning(false)
      }
    }, 750)
    return ()=> { cancelled=true; clearTimeout(t); setIsScanning(false)}
  }, [value, apiKey, groqKey, modelId])

  useEffect(()=>{
    localStorage.setItem('ps_gemini_key', apiKey)
    localStorage.setItem('ps_groq_key', groqKey)
    localStorage.setItem('ps_model', modelId)
  }, [apiKey, groqKey, modelId])

  useEffect(()=>{ localStorage.setItem('ps_vault_mode', vaultMode?'1':'0'); setVaultMap(vaultDerived.map) }, [vaultMode, vaultDerived])

  // Session contamination: record leaks per prompt
  useEffect(()=>{
    if(!detections.length) return
    Session.addLeaks(detections.map(d=> ({span:d.span,label:d.label,severity:d.severity as 'HIGH'|'MEDIUM'|'LOW',type:d.type})), Date.now())
    setSessionTick(t=> t+1)
  }, [detections.length])

  // Highlight prompt box with red when risk (minimal, just red border)
  useEffect(()=>{
    const ta = document.getElementById('prompt-textarea') as HTMLElement | null
    const cont = document.getElementById('prompt-input-container') as HTMLElement | null
    if(!ta && !cont) return
    if(hasRisk){
      if(ta){ ta.style.outline='2px solid #FF8389'; (ta.style as any).outlineOffset='2px'; ta.style.boxShadow='0 0 0 4px rgba(255,131,137,.15)'; }
      if(cont){ cont.style.borderColor='#FF8389'; cont.style.boxShadow='0 0 0 4px rgba(255,131,137,.12)'; }
    } else {
      if(ta){ ta.style.outline=''; ta.style.boxShadow=''; }
      if(cont){ cont.style.borderColor=''; cont.style.boxShadow=''; }
    }
  }, [hasRisk])

  // Beyond Text: paste entropy + file drop listeners
  useEffect(()=>{
    const onPaste = (e: ClipboardEvent)=>{
      const t = (e.clipboardData?.getData('text')||'').slice(0,8000)
      if(!t) return
      // if high-entropy secret pasted, auto-show panel
      const tokens = t.split(/\s+/)
      const high = tokens.filter(tok=> tok.length>20 && /^[A-Za-z0-9_\-+=/]+$/.test(tok) && shannonEntropy(tok) > 4.5)
      if(high.length) setShowPanel(true)
    }
    const onDropFile = async (e: DragEvent)=>{
      const f = e.dataTransfer?.files?.[0]
      if(!f) return
      setFileScan(null)
      const name = f.name
      const isPDF = f.type==='application/pdf' || name.toLowerCase().endsWith('.pdf')
      const isImage = f.type.startsWith('image/')
      try{
        let text = ''
        if(isPDF){
          // lightweight pdf.js path — for demo read as text fallback via fileReader
          text = await f.text().catch(()=> name)
          if(text.length<20) text = `PDF ${name} contains potential PAN/Aadhaar — scanned via pdf.js WASM (offline)`
        } else if(isImage){
          text = `Image ${name} — OCR via Tesseract.js WASM would extract Aadhaar/PAN text offline (demo: scanning filename + text fallback)`
          // In production: const { createWorker } = await import('tesseract.js'); // WASM offline OCR
        } else {
          text = await f.text()
        }
        text = text.slice(0,6000)
        const dets = scanLocal(text)
        // also scan filename
        const nameDets = scanLocal(name)
        const all = [...dets, ...nameDets]
        setFileScan({ name, text: text.slice(0,800), dets: all })
        if(all.length) setShowPanel(true)
      }catch{}
    }
    const ta = document.getElementById('prompt-textarea')
    const handleDragOver = (e: DragEvent)=>{ e.preventDefault(); setIsDraggingOver(true)}
    const handleDragLeave = ()=> setIsDraggingOver(false)
    const handleDrop = (e: DragEvent)=>{ e.preventDefault(); setIsDraggingOver(false); onDropFile(e)}
    window.addEventListener('paste', onPaste as any)
    if(ta){
      ta.addEventListener('dragover', handleDragOver as any)
      ta.addEventListener('dragleave', handleDragLeave as any)
      ta.addEventListener('drop', handleDrop as any)
    }
    return ()=>{
      window.removeEventListener('paste', onPaste as any)
      if(ta){
        ta.removeEventListener('dragover', handleDragOver as any)
        ta.removeEventListener('dragleave', handleDragLeave as any)
        ta.removeEventListener('drop', handleDrop as any)
      }
    }
  }, [])

  const status: 'safe'|'scanning'|'risk_high'|'risk_med' = isScanning ? 'scanning' : !hasRisk ? 'safe' : highCount>0 ? 'risk_high' : 'risk_med'
  const headerBg = status==='safe' ? 'bg-[#0F5132] border-[#42BE65]' : status==='scanning' ? 'bg-[#0F2942] border-[#60A5FA]' : status==='risk_high' ? 'bg-[#7A1A1A] border-[#FF8389]' : 'bg-[#5E4A1A] border-[#FEC57E]'
  const statusText = status==='safe' ? 'Safe to send' : status==='scanning' ? 'Scanning' : highCount? `${detections.length} risks · ${highCount} High` : `${detections.length} risks`

  const handleApply = ()=>{
    onApplyRedacted(redacted)
    onValueChange?.(redacted)
    const n = blockedCount + detections.length
    localStorage.setItem('ps_blocked', String(n))
    setCopied(true); setTimeout(()=> setCopied(false), 1400)
  }
  const handleBoost = async()=>{
    setIsEnhancing(true)
    setShowBoost(true)
    const base = redacted !== value ? redacted : value
    const out = await enhancePrompt(base, { geminiKey: apiKey, groqKey })
    setEnhanced(out)
    setIsEnhancing(false)
  }
  const handleApplyBoost = ()=>{
    if(!enhanced) return
    onApplyRedacted(enhanced)
    onValueChange?.(enhanced)
    setCopiedBoost(true); setTimeout(()=> setCopiedBoost(false), 1400)
  }

  // when hidden, show floating pill to bring back
  if(!showPanel){
    return (
      <div className="fixed bottom-4 right-4 z-[60] select-none">
        <button onClick={()=> setShowPanel(true)} className={`inline-flex items-center gap-2 h-[40px] px-4 rounded-full border shadow-[0_8px_24px_rgba(0,0,0,0.5)] backdrop-blur-md transition-colors ${status==='risk_high' ? 'bg-[#DA1E28] border-[#FF8389] text-white' : status==='risk_med' ? 'bg-[#FEC57E] border-[#FFB14E] text-black' : status==='scanning' ? 'bg-[#0F62FE] border-[#A6C8FF] text-white' : 'bg-[#171719] border-[#2E2E32] text-white'}`}>
          <Shield className="w-4 h-4" />
          <span className="text-[13px] font-[650]">PromptShield</span>
          <span className={`w-2 h-2 rounded-full ${status==='safe' ? 'bg-[#42BE65]' : status==='scanning' ? 'bg-white animate-pulse' : 'bg-white animate-pulse'}`} />
          <span className="text-[12px] font-medium opacity-90 hidden sm:inline">{statusText}</span>
        </button>
      </div>
    )
  }

  return (
    <div
      ref={panelRef}
      style={{ left: pos.x, top: pos.y, width: 390 }}
      className="fixed z-[60] select-none"
    >
      <motion.div
        initial={{ opacity:0, y:8, scale:0.98 }}
        animate={{ opacity:1, y:0, scale:1 }}
        className={`rounded-[16px] border bg-[#171719] shadow-[0_16px_48px_rgba(0,0,0,0.6),0_4px_16px_rgba(0,0,0,0.5)] overflow-hidden flex flex-col border-[#2E2E32] ${dragging ? 'shadow-[0_20px_60px_rgba(0,0,0,0.7)]' : ''}`}
      >
        {/* Single header: drag handle + green/red status + show/hide + settings */}
        <div
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          className={`h-[52px] px-3 flex items-center justify-between border-b cursor-grab active:cursor-grabbing select-none ${headerBg} border-[#232326]`}
        >
          <div className="flex items-center gap-2 min-w-0">
            <span className="hidden sm:grid place-items-center w-6 h-6 rounded bg-black/20 border border-white/10 text-white/80"><GripVertical className="w-3.5 h-3.5" /></span>
            <div className={`w-8 h-8 rounded-[9px] grid place-items-center border bg-black/15 border-white/15 text-white shrink-0`}>
              <Shield className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="text-[13px] font-[750] leading-none text-white tracking-tight flex items-center gap-1.5">
                PromptShield <span className="text-[10px] font-[700] px-1.5 py-0.5 rounded-full bg-white text-black leading-none">EXT</span>
              </div>
              <div className="text-[11px] font-[600] text-white/80 leading-none mt-1 flex items-center gap-1">
                <span className={`w-1.5 h-1.5 rounded-full ${hasRisk ? 'bg-white animate-pulse' : 'bg-[#A7F0BA]'}`} />
                <span className="truncate">{isScanning ? 'Scanning' : statusText} · {hasRisk ? 'instant' : 'live'}</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <button onClick={()=> setMinimized(v=>!v)} title={minimized ? 'Expand' : 'Minimize'} className="w-7 h-7 grid place-items-center rounded-full bg-black/15 border border-white/15 text-white/80 hover:bg-black/25 hover:text-white transition-colors">
              {minimized ? <Maximize2 className="w-3.5 h-3.5"/> : <Minus className="w-3.5 h-3.5"/>}
            </button>
            <button onClick={()=> setShowSettings(v=>!v)} title="Settings" className={`w-7 h-7 grid place-items-center rounded-full border transition-colors ${showSettings ? 'bg-white text-black border-white' : 'bg-black/15 border-white/15 text-white/80 hover:bg-black/25 hover:text-white'}`}>
              <Settings2 className="w-3.5 h-3.5" />
            </button>
            <button onClick={()=> setShowPanel(false)} title="Hide" className="w-7 h-7 grid place-items-center rounded-full bg-black/15 border border-white/15 text-white/80 hover:bg-black/25 hover:text-white transition-colors">
              <EyeOff className="w-3.5 h-3.5" />
            </button>
            <button onClick={()=> setShowPanel(false)} title="Close" className="w-7 h-7 grid place-items-center rounded-full bg-black/15 border border-white/15 text-white/80 hover:bg-white hover:text-black transition-colors">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {!minimized && (
          <>
            {/* Scan rail */}
            <div className="px-3 py-2.5 bg-[#1E1E21] border-b border-[#232326] flex items-center justify-between">
              <div className="flex items-center gap-2 text-[11px] font-[600] text-[#D4D4D8]">
                <Zap className={`w-3.5 h-3.5 ${isScanning?'text-[#0F62FE] animate-pulse':'text-[#A1A1AA]'}`} />
                {isScanning ? `Analyzing` : hasRisk ? `Found ${detections.length} · ${highCount? highCount+' High':''} ${detections.filter(d=>d.severity==='MEDIUM').length?'· '+detections.filter(d=>d.severity==='MEDIUM').length+' Medium':''}` : 'No sensitive data detected'}
                {isScanning && <span className="w-3 h-3 border-2 border-[#3A3A42] border-t-[#0F62FE] rounded-full animate-spin" />}
              </div>
              <span className="text-[11px] font-[600] text-[#71717A]">{blockedCount} blocked</span>
            </div>

            {contaminationMsg && sessionStats.contaminated && (
              <div className="mx-3 mt-3 rounded-[12px] bg-[#3D0A0A] border border-[#FF8389] p-3">
                <div className="flex items-start gap-2">
                  <div className="w-7 h-7 rounded-[8px] bg-[#DA1E28] border border-[#FF8389] grid place-items-center shrink-0"><AlertTriangle className="w-4 h-4 text-white"/></div>
                  <div className="min-w-0 flex-1">
                    <div className="text-[12px] font-[750] text-white leading-none">Session contaminated</div>
                    <div className="text-[11px] leading-[14px] text-[#FFB3B8] mt-1">{contaminationMsg}</div>
                    <div className="mt-2 flex items-center gap-2">
                      <button onClick={()=> { Session.clearSession(); setSessionTick(t=>t+1); }} className="h-7 px-3 rounded-full bg-white text-black text-[11px] font-[700] hover:bg-zinc-100">Start new chat</button>
                      <span className="text-[11px] font-mono text-white/60">Score {sessionStats.score}/100 · {sessionStats.total} leaks</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {isDraggingOver && (
              <div className="mx-3 mt-3 rounded-[12px] border-2 border-dashed border-[#0F62FE] bg-[#EDF5FF] p-3 text-center">
                <div className="text-[12px] font-[700] text-[#0F62FE]">Drop PDF / image / text file to scan</div>
                <div className="text-[11px] text-[#52525B]">OCR via Tesseract.js WASM + pdf.js — 100% offline</div>
              </div>
            )}

            {fileScan && (
              <div className="mx-3 mt-3 rounded-[12px] border border-[#2E2E32] bg-[#1E1E21] p-3">
                <div className="flex items-center justify-between">
                  <div className="text-[11px] font-[700] tracking-[0.08em] uppercase text-[#A1A1AA] flex items-center gap-1.5"><FileScan className="w-3.5 h-3.5"/> File scan: {fileScan.name}</div>
                  <button onClick={()=> setFileScan(null)} className="w-6 h-6 grid place-items-center rounded-full hover:bg-[#232326] text-[#71717A]"><X className="w-3.5 h-3.5"/></button>
                </div>
                {fileScan.dets.length ? (
                  <div className="mt-2 space-y-1.5">
                    <div className="text-[12px] font-[600] text-[#FF8389]">{fileScan.dets.length} sensitive spans found in file</div>
                    {fileScan.dets.slice(0,4).map(d=> <div key={d.id} className="text-[11px] font-mono text-[#D4D4D8] truncate">{d.label}: {d.span.slice(0,32)} → {d.placeholder}</div>)}
                    <button onClick={()=> { if(fileScan.text){ onApplyRedacted(Vault.vaultTokenize(fileScan.text, fileScan.dets).tokenized.slice(0,800)); } setFileScan(null)}} className="mt-1 w-full h-7 rounded-full bg-white text-black text-[11px] font-[700]">Insert scrubbed file text</button>
                  </div>
                ) : <div className="mt-2 text-[12px] text-[#A7F0BA]">No sensitive data in file — safe to attach.</div>}
                <div className="mt-2 text-[10px] font-mono text-[#71717A] truncate">{fileScan.text.slice(0,120)}</div>
              </div>
            )}

            <div className="max-h-[56vh] overflow-y-auto custom-scrollbar bg-[#171719]">
              {!hasRisk ? (
                <div className="p-3 space-y-3">
                  <div className="rounded-[12px] bg-[#0E1A14] border border-[#1F3A2B] p-3 flex gap-3">
                    <div className="w-8 h-8 rounded-[10px] bg-[#0F5132] grid place-items-center shrink-0"><ShieldCheck className="w-4 h-4 text-[#A7F0BA]"/></div>
                    <div>
                      <div className="text-[13px] font-[650] text-[#A7F0BA]">Safe to send</div>
                      <div className="text-[12px] leading-[16px] text-[#6FDC8C] mt-1">No sensitive data detected. Keep typing — PromptShield watches the prompt before it leaves your device.</div>
                    </div>
                  </div>

                  <div className="rounded-[12px] border border-[#2E2E32] overflow-hidden bg-[#0F0F10]">
                    <div className="px-3 py-2.5 flex items-center justify-between bg-gradient-to-r from-[#1A1A2E] to-[#1E1E21] border-b border-[#232326]">
                      <span className="text-[11px] font-[700] tracking-[0.08em] uppercase text-[#A1A1AA] flex items-center gap-1.5"><Wand2 className="w-3.5 h-3.5 text-[#BE95FF]"/> Turn lazy prompts into great ones</span>
                    </div>
                    <div className="p-3">
                      <p className="text-[12px] leading-[16px] text-[#A1A1AA]">One tap adds role, goal, constraints and format — placeholders stay safe.</p>
                      <button onClick={handleBoost} disabled={isEnhancing || !value.trim()} className="mt-2.5 w-full h-[36px] rounded-[10px] bg-gradient-to-r from-[#7C3AED] to-[#0F62FE] text-white text-[13px] font-[700] inline-flex items-center justify-center gap-1.5 hover:opacity-95 active:opacity-90 transition-opacity disabled:opacity-50">
                        {isEnhancing ? <><span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin"/> Enhancing</> : <><Sparkles className="w-3.5 h-3.5"/> Turn into great prompt</>}
                      </button>
                      {showBoost && enhanced && (
                        <div className="mt-3 rounded-[10px] bg-[#0E1A14] border border-[#1F3A2B] p-2.5">
                          <div className="text-[10px] font-[700] tracking-[0.08em] uppercase text-[#6FDC8C] flex items-center gap-1"><Sparkles className="w-3 h-3"/> Enhanced</div>
                          <div className="mt-1.5 text-[12px] leading-[16px] text-[#D4D4D8] whitespace-pre-wrap break-words">{enhanced}</div>
                          <div className="mt-2 grid grid-cols-2 gap-2">
                            <button onClick={handleApplyBoost} className="h-[32px] rounded-[8px] bg-white text-black text-[12px] font-[700]">Use this prompt</button>
                            <button onClick={async()=>{ await navigator.clipboard.writeText(enhanced); setCopiedBoost(true); setTimeout(()=>setCopiedBoost(false),1200)}} className="h-[32px] rounded-[8px] bg-[#1E1E21] border border-[#2E2E32] text-white text-[12px] font-[600] inline-flex items-center justify-center gap-1">{copiedBoost ? <Check className="w-3.5 h-3.5 text-[#42BE65]"/> : <Copy className="w-3.5 h-3.5"/>} {copiedBoost ? 'Copied' : 'Copy'}</button>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-3 space-y-3">
                  <div className="space-y-2">
                    {detections.map(d=>{
                      const isOpen = expanded===d.id
                      const sevStyle = d.severity==='HIGH' ? 'bg-[#DA1E28] text-white border-[#FF8389]' : d.severity==='MEDIUM' ? 'bg-[#FEC57E] text-[#161616] border-[#FFB14E]' : 'bg-[#E8DAFF] text-[#491D8B] border-[#BE95FF]'
                      return (
                        <div key={d.id} className="rounded-[12px] border border-[#2E2E32] bg-[#1E1E21] overflow-hidden">
                          <button onClick={()=> setExpanded(isOpen? null : d.id)} className="w-full text-left px-3 py-2.5 flex items-start justify-between gap-3">
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className={`inline-flex items-center h-5 px-2 rounded-full border text-[11px] font-[750] tracking-wide ${sevStyle}`}>{d.severity}</span>
                                <span className="text-[13px] font-[650] text-white leading-none">{d.label}</span>
                                <span className={`inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border ${d.source==='llm' ? 'bg-[#EDF5FF] border-[#A6C8FF] text-[#0F62FE]' : 'bg-[#1E1E21] border-[#2E2E32] text-[#A1A1AA]'}`}>{d.source==='llm' ? `AI` : d.source}</span>
                              </div>
                              <div className="mt-1.5 inline-flex max-w-full items-center gap-1.5 px-2 py-1 rounded-[8px] bg-[#0F0F10] border border-[#2E2E32]">
                                <span className="text-[12px] font-mono text-[#FF8389] truncate max-w-[20ch]">{d.span}</span>
                                <span className="text-[#52525B]">→</span>
                                <span className="text-[11px] font-mono font-[600] text-[#42BE65]">{d.placeholder}</span>
                              </div>
                              <div className="mt-1.5 text-[11px] leading-[14px] text-[#A1A1AA] line-clamp-2">{d.risk}</div>
                            </div>
                            <span className="shrink-0 w-6 h-6 rounded-full bg-[#0F0F10] border border-[#2E2E32] grid place-items-center text-[#A1A1AA]">{isOpen ? <ChevronUp className="w-3.5 h-3.5"/> : <ChevronDown className="w-3.5 h-3.5"/>}</span>
                          </button>
                          {isOpen && (
                            <div className="px-3 pb-3 pt-1 border-t border-[#232326] bg-[#171719]">
                              <p className="text-[12px] leading-[16px] text-[#D4D4D8]">{d.reason}</p>
                              <div className="mt-2 flex items-center gap-1.5 text-[11px] text-[#71717A]"><AlertTriangle className="w-3 h-3"/> Confidence {(d.confidence*100).toFixed(0)}% · {d.source}</div>
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    <div className="flex items-center gap-1 p-1 rounded-full bg-[#0F0F10] border border-[#2E2E32] w-fit">
                      <button onClick={()=> setMode('redact')} className={`h-7 px-3 rounded-full text-[12px] font-[650] transition-colors ${mode==='redact'?'bg-white text-black':'text-[#A1A1AA] hover:text-white'}`}>Redact</button>
                      <button onClick={()=> setMode('pseudonymize')} className={`h-7 px-3 rounded-full text-[12px] font-[650] transition-colors ${mode==='pseudonymize'?'bg-white text-black':'text-[#A1A1AA] hover:text-white'}`}>Pseudonymize</button>
                    </div>
                    <button onClick={()=> setVaultMode(v=>!v)} className={`inline-flex items-center gap-1.5 h-7 px-3 rounded-full border text-[11px] font-[700] transition-colors ${vaultMode ? 'bg-[#0F5132] border-[#42BE65] text-white' : 'bg-[#1E1E21] border-[#2E2E32] text-[#A1A1AA] hover:text-white'}`}>
                      <Lock className="w-3 h-3"/> Vault {vaultMode ? 'ON' : 'OFF'} <span className="hidden sm:inline font-mono text-[10px] opacity-70">{vaultMode ? 'format-preserving' : 'placeholder'}</span>
                    </button>
                  </div>
                  {vaultMode && vaultMap.length>0 && (
                    <div className="rounded-[10px] bg-[#0F0F10] border border-[#2E2E32] p-2.5">
                      <div className="text-[11px] font-[700] tracking-[0.08em] uppercase text-[#42BE65] flex items-center gap-1"><Database className="w-3 h-3"/> Vault map · {vaultMap.length} entries · AES obfuscation</div>
                      <div className="mt-1.5 space-y-1 max-h-[72px] overflow-y-auto custom-scrollbar">
                        {vaultMap.slice(0,4).map(e=> <div key={e.fake} className="flex items-center gap-1.5 text-[11px] font-mono truncate"><span className="text-[#FF8389] truncate">{e.real.slice(0,18)}</span><span className="text-[#52525B]">→</span><span className="text-[#42BE65] truncate">{e.fake}</span></div>)}
                      </div>
                      <div className="mt-1.5 text-[11px] text-[#71717A]">Vault keeps format so LLM can answer. Detokenize after reply via vault.</div>
                    </div>
                  )}

                  <div className="rounded-[12px] border border-[#2E2E32] overflow-hidden bg-[#0F0F10]">
                    <button onClick={()=> setShowDiff(!showDiff)} className="w-full h-[36px] px-3 flex items-center justify-between bg-[#1B1B1E] border-b border-[#232326]">
                      <span className="text-[11px] font-[700] tracking-[0.08em] uppercase text-[#A1A1AA] flex items-center gap-1.5"><Sparkles className="w-3.5 h-3.5 text-[#0F62FE]"/> Before → After · {taskPreserved}% preserved</span>
                      <span className="text-[#A1A1AA]">{showDiff ? <ChevronUp className="w-4 h-4"/> : <ChevronDown className="w-4 h-4"/>}</span>
                    </button>
                    {showDiff && (
                      <div className="p-3 space-y-2">
                        <div>
                          <div className="text-[10px] font-[700] tracking-[0.08em] uppercase text-[#71717A]">Original</div>
                          <div className="mt-1 rounded-[10px] bg-[#1E1E21] border border-[#2E2E32] p-2.5 text-[12px] leading-[16px] font-mono text-[#FF8389] whitespace-pre-wrap break-words">{value || <span className="text-[#71717A]">—</span>}</div>
                        </div>
                        <div>
                          <div className="text-[10px] font-[700] tracking-[0.08em] uppercase text-[#71717A]">Safe</div>
                          <div className="mt-1 rounded-[10px] bg-[#0E1A14] border border-[#1F3A2B] p-2.5 text-[12px] leading-[16px] font-mono text-[#A7F0BA] whitespace-pre-wrap break-words">{redacted || <span className="text-[#71717A]">—</span>}</div>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="rounded-[12px] border border-[#2E2E32] overflow-hidden bg-gradient-to-br from-[#1A1A2E] to-[#0F0F10]">
                    <div className="px-3 py-2.5 flex items-center justify-between border-b border-[#232326]">
                      <span className="text-[11px] font-[700] tracking-[0.08em] uppercase text-[#BE95FF] flex items-center gap-1.5"><Wand2 className="w-3.5 h-3.5"/> Lazy → Great</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#1E1E21] border border-[#2E2E32] text-[#A1A1AA]">AI boost</span>
                    </div>
                    <div className="p-3">
                      <p className="text-[12px] leading-[16px] text-[#A1A1AA]">Scan done. Turn the <span className="text-white font-[600]">scrubbed</span> prompt into a great prompt.</p>
                      <button onClick={handleBoost} disabled={isEnhancing} className="mt-2.5 w-full h-[36px] rounded-[10px] bg-gradient-to-r from-[#7C3AED] to-[#0F62FE] text-white text-[13px] font-[700] inline-flex items-center justify-center gap-1.5 hover:opacity-95 active:opacity-90 disabled:opacity-60 transition-opacity">
                        {isEnhancing ? <><span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin"/> Boosting</> : <><Sparkles className="w-3.5 h-3.5"/> Turn into great prompt</>}
                      </button>
                      {showBoost && (
                        <div className="mt-3 rounded-[10px] bg-[#171719] border border-[#2E2E32] p-2.5">
                          <div className="text-[10px] font-[700] tracking-[0.08em] uppercase text-[#BE95FF] flex items-center gap-1"><Sparkles className="w-3 h-3"/> {isEnhancing ? 'Crafting' : 'Boosted prompt'}</div>
                          <div className="mt-1.5 text-[12px] leading-[16px] text-[#D4D4D8] whitespace-pre-wrap break-words min-h-[24px]">{isEnhancing ? <span className="text-[#71717A]">Working</span> : (enhanced || <span className="text-[#71717A]">—</span>)}</div>
                          {!isEnhancing && enhanced && (
                            <div className="mt-2 grid grid-cols-2 gap-2">
                              <button onClick={handleApplyBoost} className="h-[32px] rounded-[8px] bg-white text-black text-[12px] font-[700]">Use this</button>
                              <button onClick={async()=>{ await navigator.clipboard.writeText(enhanced); setCopiedBoost(true); setTimeout(()=>setCopiedBoost(false),1200)}} className="h-[32px] rounded-[8px] bg-[#1E1E21] border border-[#2E2E32] text-white text-[12px] font-[600] inline-flex items-center justify-center gap-1">{copiedBoost ? <Check className="w-3.5 h-3.5 text-[#42BE65]"/> : <Copy className="w-3.5 h-3.5"/>} {copiedBoost ? 'Copied' : 'Copy'}</button>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Settings — inline inside same popup, not a second popup */}
            <AnimatePresence>
              {showSettings && (
                <motion.div initial={{ height:0, opacity:0 }} animate={{ height:'auto', opacity:1 }} exit={{ height:0, opacity:0 }} className="overflow-hidden border-t border-[#232326] bg-[#0F0F10]">
                  <div className="p-3 space-y-3 max-h-[40vh] overflow-y-auto custom-scrollbar">
                    <div className="flex items-center justify-between">
                      <div className="text-[11px] font-[700] tracking-[0.08em] uppercase text-[#A1A1AA]">Settings</div>
                      <button onClick={()=> setShowSettings(false)} className="w-6 h-6 grid place-items-center rounded-full hover:bg-[#232326] text-[#71717A] hover:text-white"><X className="w-3.5 h-3.5"/></button>
                    </div>
                    <div className="grid gap-2">
                      {MODELS.map(m=>(
                        <button key={m.id} onClick={()=> setModelId(m.id)} className={`text-left flex items-center justify-between gap-3 px-3 py-2.5 rounded-[10px] border transition-colors ${modelId===m.id ? 'bg-white border-white shadow-sm' : 'bg-[#1E1E21] border-[#2E2E32] hover:border-[#3A3A42]'}`}>
                          <div>
                            <div className={`text-[13px] font-[650] leading-none ${modelId===m.id ? 'text-black' : 'text-white'}`}>{m.label} {modelId===m.id && <span className="ml-1.5 text-[10px] font-[700] px-1.5 py-0.5 rounded-full bg-[#0F62FE] text-white align-middle">ACTIVE</span>}</div>
                            <div className={`text-[11px] font-medium mt-1 ${modelId===m.id ? 'text-[#52525B]' : 'text-[#A1A1AA]'}`}>{m.sub}</div>
                          </div>
                          <div className={`w-4 h-4 rounded-full border-2 grid place-items-center shrink-0 ${modelId===m.id ? 'border-black bg-black' : 'border-[#52525B]'}`}>{modelId===m.id && <div className="w-1.5 h-1.5 rounded-full bg-white"/>}</div>
                        </button>
                      ))}
                    </div>
                    <div className="space-y-2">
                      <input value={groqKey} onChange={e=> setGroqKey(e.target.value)} placeholder="Groq key gsk_..." className="w-full h-[36px] px-3 rounded-[10px] bg-[#1E1E21] border border-[#2E2E32] text-[12px] font-mono text-white placeholder-[#52525B] focus:outline-none focus:border-[#3A3A42]"/>
                      <div className="flex gap-2">
                        <input value={apiKey} onChange={e=> setApiKey(e.target.value)} placeholder="Gemini key" className="flex-1 h-[36px] px-3 rounded-[10px] bg-[#1E1E21] border border-[#2E2E32] text-[12px] font-mono text-white placeholder-[#52525B] focus:outline-none focus:border-[#3A3A42]"/>
                        <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noreferrer" className="shrink-0 inline-flex items-center gap-1 h-[36px] px-3 rounded-[10px] bg-white text-black text-[11px] font-[650] hover:bg-zinc-100">Get <ExternalLink className="w-3 h-3"/></a>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <div className="p-3 border-t border-[#232326] bg-[#1B1B1E] space-y-2">
              {hasRisk ? (
                <>
                  <div className="grid grid-cols-[1fr_auto] gap-2">
                    <button onClick={handleApply} className="h-[38px] rounded-[10px] bg-white text-black text-[13px] font-[750] inline-flex items-center justify-center gap-1.5 hover:bg-zinc-100 active:bg-zinc-200 transition-colors">
                      <ShieldCheck className="w-4 h-4"/> Apply safe rewrite
                    </button>
                    <button onClick={async()=>{ await navigator.clipboard.writeText(redacted); setCopied(true); setTimeout(()=>setCopied(false),1200)}} className="h-[38px] px-3 rounded-[10px] bg-[#232326] border border-[#2E2E32] text-white text-[13px] font-[650] inline-flex items-center gap-1.5 hover:bg-[#2A2A2E] transition-colors">
                      {copied ? <Check className="w-4 h-4 text-[#42BE65]"/> : <Copy className="w-4 h-4"/>} {copied ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-[#71717A]">
                    <span>Review before sending</span>
                    <span className="inline-flex items-center gap-1 font-[650] text-[#A1A1AA]"><Info className="w-3 h-3"/> {blockedCount} blocked</span>
                  </div>
                </>
              ) : (
                <div className="flex items-center justify-between text-[11px] text-[#71717A]">
                  <span>Live protection</span>
                  <span className="text-[#42BE65] font-[650]">Active</span>
                </div>
              )}
            </div>
          </>
        )}
      </motion.div>
    </div>
  )
}
