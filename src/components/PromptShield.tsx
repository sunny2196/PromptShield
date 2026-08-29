import React, { useEffect, useMemo, useState, useRef } from 'react'
import { scanLocal, scanWithLLM, scanWithGroq, redactText, enhancePrompt, shannonEntropy, type Detection } from '../lib/detection'
import * as Session from '../lib/session'
import * as Vault from '../lib/vault'
import { Shield, ShieldCheck, ShieldAlert, Sparkles, Settings2, X, Zap, Copy, Check, GripVertical, Minus, Maximize2, Wand2 } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

type ModelOpt = { id: string, label: string, sub: string }
const MODELS: ModelOpt[] = [
  { id:'qwen3b', label:'Qwen 2.5 3B', sub:'Groq · Recommended' },
  { id:'llama3b', label:'Llama 3.2 3B', sub:'Groq · Fast' },
  { id:'gemini-flash', label:'Gemini 2.0 Flash', sub:'Google · Fallback' },
]

export default function PromptShield({ value, onApplyRedacted, onValueChange }:{ value: string, onApplyRedacted:(v:string)=>void, onValueChange?:(v:string)=>void }){
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
  const [copied, setCopied] = useState(false)
  const [copiedBoost, setCopiedBoost] = useState(false)
  const [enhanced, setEnhanced] = useState('')
  const [isEnhancing, setIsEnhancing] = useState(false)
  const [vaultMode, setVaultMode] = useState(()=> localStorage.getItem('ps_vault_mode')==='1')
  const [sessionTick, setSessionTick] = useState(0)
  const [pos, setPos] = useState({ x: 0, y: 0 })
  const [dragging, setDragging] = useState(false)
  const dragRef = useRef<{startX:number,startY:number,origX:number,origY:number} | null>(null)

  useEffect(()=>{
    const w=window.innerWidth, h=window.innerHeight
    let x=w-414, y=96
    if(w<1280){ x=Math.max(12,(w-390)/2); y=h-520; if(y<80) y=80 }
    x=Math.max(8,Math.min(x,w-398)); y=Math.max(8,Math.min(y,h-420))
    setPos({x,y})
  },[])
  const onPointerDown=(e:React.PointerEvent)=>{ if((e.target as HTMLElement).closest('button')) return; setDragging(true); dragRef.current={startX:e.clientX,startY:e.clientY,origX:pos.x,origY:pos.y}; (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId)}
  const onPointerMove=(e:React.PointerEvent)=>{ if(!dragging||!dragRef.current) return; const dx=e.clientX-dragRef.current.startX, dy=e.clientY-dragRef.current.startY; let nx=dragRef.current.origX+dx, ny=dragRef.current.origY+dy; const pw=390, ph=minimized?52:420; nx=Math.max(4,Math.min(nx,window.innerWidth-pw-4)); ny=Math.max(4,Math.min(ny,window.innerHeight-ph-4)); setPos({x:nx,y:ny})}
  const onPointerUp=(e:React.PointerEvent)=>{ setDragging(false); dragRef.current=null; try{(e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId)}catch{} }

  const apiModel = useMemo(()=> MODELS.find(m=>m.id===modelId)||MODELS[0],[modelId])
  const detections = useMemo(()=>{
    const m=new Map<string,Detection>()
    for(const d of [...localDetections,...llmDetections]){ const k=`${d.type}:${d.span.toLowerCase()}`; if(!m.has(k)) m.set(k,d)}
    return [...m.values()].sort((a,b)=> (a.severity==='HIGH'?0:a.severity==='MEDIUM'?1:2)-(b.severity==='HIGH'?0:b.severity==='MEDIUM'?1:2))
  },[localDetections,llmDetections])
  const hasRisk=detections.length>0
  const highCount=detections.filter(d=>d.severity==='HIGH').length
  const baseRedacted=useMemo(()=> redactText(value,detections,mode),[value,detections,mode])
  const vaultDerived=useMemo(()=> vaultMode?Vault.vaultTokenize(value,detections):{tokenized:baseRedacted,map:[] as Vault.VaultEntry[]},[value,detections,vaultMode,baseRedacted])
  const redacted=vaultMode?vaultDerived.tokenized:baseRedacted
  const session=useMemo(()=> Session.loadSession(),[sessionTick,detections.length])
  const contam=Session.contaminationBanner(session)

  useEffect(()=>{
    const t=setTimeout(()=>{ if(!value.trim()){ setLocalDetections([]); setLlmDetections([]); setEnhanced(''); return } const l=scanLocal(value); setLocalDetections(l); if(l.length) setShowPanel(true); if(l.length && minimized) setMinimized(false); },280)
    return ()=>clearTimeout(t)
  },[value])
  useEffect(()=>{
    if(!value.trim()||value.length<16) return; const hasKey=groqKey||apiKey; if(!hasKey) return
    let c=false; const t=setTimeout(async()=>{ setIsScanning(true); let llm:Detection[]=[]; if(groqKey){ llm=await scanWithGroq(value,groqKey,modelId); if(!llm.length&&apiKey) llm=[...llm,...await scanWithLLM(value,apiKey,modelId)]} else if(apiKey) llm=await scanWithLLM(value,apiKey,modelId); if(!c){ setLlmDetections(llm); setIsScanning(false)} },750)
    return()=>{ c=true; clearTimeout(t); setIsScanning(false)}
  },[value,apiKey,groqKey,modelId])
  useEffect(()=>{ localStorage.setItem('ps_gemini_key',apiKey); localStorage.setItem('ps_groq_key',groqKey); localStorage.setItem('ps_model',modelId)},[apiKey,groqKey,modelId])
  useEffect(()=>{ localStorage.setItem('ps_vault_mode',vaultMode?'1':'0')},[vaultMode])
  useEffect(()=>{ if(!detections.length) return; Session.addLeaks(detections.map(d=>({span:d.span,label:d.label,severity:d.severity as any,type:d.type})),Date.now()); setSessionTick(t=>t+1)},[detections.length])
  // text-only red highlight — mark only sensitive spans, not whole box
  useEffect(()=>{
    const cont=document.getElementById('prompt-input-container') as HTMLElement|null
    let hl=document.getElementById('ps-sim-highlight') as HTMLDivElement|null
    if(!hl && cont){
      hl=document.createElement('div'); hl.id='ps-sim-highlight'
      hl.style.cssText='margin:8px 0 0 0;padding:10px 12px;background:#1A0A0A;border:1px solid #4A1A1A;border-radius:10px;font-size:12px;font-family:monospace;line-height:16px;white-space:pre-wrap;word-break:break-word;display:none;max-height:120px;overflow:auto'
      cont.parentElement?.insertBefore(hl, cont.nextSibling)
    }
    if(!hl) return
    const ta=document.getElementById('prompt-textarea') as HTMLElement|null
    if(ta) ta.style.outline=''
    if(cont){ cont.style.borderColor=''; cont.style.boxShadow=''}
    if(hasRisk && value){
      const sorted=[...detections].filter(d=>d.start>=0).sort((a,b)=>a.start-b.start)
      let out=''; let last=0
      for(const d of sorted){
        out+= value.slice(last, d.start).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        const seg=value.slice(d.start,d.end).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        out+= `<span style="background:rgba(255,77,79,.18);color:#FF4D4F;border-bottom:1.5px solid #FF4D4F;border-radius:2px;padding:0 2px">${seg}</span>`
        last=d.end
      }
      out+= value.slice(last).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      hl.innerHTML=out; hl.style.display='block'
    } else {
      hl.style.display='none'
    }
  },[hasRisk, value, detections])
  // paste/file
  useEffect(()=>{
    const onPaste=(e:ClipboardEvent)=>{ const t=(e.clipboardData?.getData('text')||'').slice(0,8000); if(!t) return; const hi=t.split(/\s+/).filter(x=> x.length>20 && /^[A-Za-z0-9_\-+=/]+$/.test(x) && shannonEntropy(x)>4.5); if(hi.length) setShowPanel(true)}
    window.addEventListener('paste', onPaste as any)
    const ta=document.getElementById('prompt-textarea')
    const onDrop=async(e:DragEvent)=>{ const f=(e as any).dataTransfer?.files?.[0]; if(!f) return; e.preventDefault(); let txt=''; try{ txt=await f.text()}catch{ txt=f.name} txt=txt.slice(0,6000); const d=scanLocal(txt); if(d.length){ onApplyRedacted(redactText(txt,d)); setShowPanel(true); setMinimized(false)}}
    const od=(e:DragEvent)=> e.preventDefault()
    if(ta){ ta.addEventListener('dragover', od as any); ta.addEventListener('drop', onDrop as any)}
    return()=>{ window.removeEventListener('paste', onPaste as any); if(ta){ ta.removeEventListener('dragover', od as any); ta.removeEventListener('drop', onDrop as any)}}
  },[redacted])

  const status: 'safe'|'scanning'|'risk_high'|'risk_med' = isScanning?'scanning':!hasRisk?'safe':highCount?'risk_high':'risk_med'
  const headerBg = status==='safe'?'bg-[#0A0A0B] border-[#232326]':status==='scanning'?'bg-[#0A1628] border-[#1E3A5F]':status==='risk_high'?'bg-[#1A0A0A] border-[#4A1A1A]':'bg-[#1A140A] border-[#4A3A1A]'
  const statusDot = status==='safe'?'bg-[#00C950]':status==='scanning'?'bg-[#60A5FA] animate-pulse':'bg-[#FF4D4F] animate-pulse'
  const statusLabel = isScanning?'Scanning':!hasRisk?'Safe':`${detections.length} found`

  const handleApply=()=>{ onApplyRedacted(redacted); onValueChange?.(redacted); setCopied(true); setTimeout(()=>setCopied(false),1200)}
  const handleBoost=async()=>{ setIsEnhancing(true); const base=redacted!==value?redacted:value; const out=await enhancePrompt(base,{geminiKey:apiKey,groqKey}); setEnhanced(out); setIsEnhancing(false)}
  const handleApplyBoost=()=>{ if(!enhanced) return; onApplyRedacted(enhanced); onValueChange?.(enhanced); setCopiedBoost(true); setTimeout(()=>setCopiedBoost(false),1200)}

  if(!showPanel){
    return (
      <div className="fixed bottom-4 right-4 z-[60]">
        <button onClick={()=> setShowPanel(true)} className={`h-9 px-4 rounded-full border flex items-center gap-2 shadow-[0_8px_24px_rgba(0,0,0,.4)] ${status==='risk_high'?'bg-[#FF4D4F] border-[#FF8282] text-white':status==='safe'?'bg-[#0A0A0B] border-[#232326] text-white':'bg-[#0A0A0B] border-[#232326] text-white'}`}>
          <span className={`w-2 h-2 rounded-full ${statusDot}`}></span>
          <span className="text-[13px] font-[700]">Ultron</span>
          <span className="text-[11px] opacity-70">{statusLabel}</span>
        </button>
      </div>
    )
  }

  return (
    <div style={{ left:pos.x, top:pos.y, width:360 }} className="fixed z-[60] select-none">
      <motion.div initial={{opacity:0,y:8,scale:.98}} animate={{opacity:1,y:0,scale:1}} className={`rounded-[16px] border bg-[#0A0A0B] shadow-[0_16px_48px_rgba(0,0,0,.5)] overflow-hidden flex flex-col border-[#232326] ${dragging?'shadow-[0_20px_60px_rgba(0,0,0,.6)]':''}`}>
        <div onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} className={`h-[48px] px-3 flex items-center justify-between cursor-grab active:cursor-grabbing ${headerBg} border-b border-[#232326]`}>
          <div className="flex items-center gap-2.5 min-w-0">
            <span className="w-6 h-6 grid place-items-center rounded bg-white/5 border border-white/10"><GripVertical className="w-3 h-3 text-white/40"/></span>
            <div className="w-8 h-8 rounded-[10px] bg-white text-black grid place-items-center font-[800] text-[14px]">U</div>
            <div className="min-w-0">
              <div className="text-[13px] font-[800] leading-none text-white tracking-tight">Ultron</div>
              <div className="text-[11px] font-[600] text-white/60 flex items-center gap-1 mt-1"><span className={`w-1.5 h-1.5 rounded-full ${statusDot}`}></span>{statusLabel}</div>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <button onClick={()=> setMinimized(v=>!v)} className="w-7 h-7 grid place-items-center rounded-full bg-white/5 border border-white/10 text-white/70 hover:text-white">{minimized?<Maximize2 className="w-3.5 h-3.5"/>:<Minus className="w-3.5 h-3.5"/>}</button>
            <button onClick={()=> setShowSettings(v=>!v)} className={`w-7 h-7 grid place-items-center rounded-full border ${showSettings?'bg-white text-black border-white':'bg-white/5 border-white/10 text-white/70 hover:text-white'}`}><Settings2 className="w-3.5 h-3.5"/></button>
            <button onClick={()=> setShowPanel(false)} className="w-7 h-7 grid place-items-center rounded-full bg-white/5 border border-white/10 text-white/70 hover:text-white"><X className="w-3.5 h-3.5"/></button>
          </div>
        </div>

        {!minimized && (
          <>
            {contam && (
              <div className="mx-3 mt-3 rounded-[12px] bg-[#1A0A0A] border border-[#FF4D4F]/30 p-3 flex items-center justify-between gap-3">
                <div className="text-[12px] font-[600] text-white">Session tainted</div>
                <button onClick={()=>{ Session.clearSession(); setSessionTick(t=>t+1)}} className="h-7 px-3 rounded-full bg-white text-black text-[11px] font-[700]">New chat</button>
              </div>
            )}

            <div className="p-3 space-y-3 max-h-[52vh] overflow-y-auto custom-scrollbar">
              {!hasRisk ? (
                <>
                  <div className="rounded-[12px] bg-[#0F1A0F] border border-[#1A3A1A] p-3 flex items-center gap-3">
                    <ShieldCheck className="w-5 h-5 text-[#00C950] shrink-0"/>
                    <div className="text-[13px] font-[600] text-white">Safe to send</div>
                  </div>
                  <button onClick={handleBoost} disabled={isEnhancing||!value.trim()} className="w-full h-[38px] rounded-[12px] bg-white text-black text-[13px] font-[700] flex items-center justify-center gap-1.5 disabled:opacity-40">
                    {isEnhancing?<span className="w-3.5 h-3.5 border-2 border-black/20 border-t-black rounded-full animate-spin"/>:<Wand2 className="w-4 h-4"/>} Make prompt perfect
                  </button>
                  {enhanced && (
                    <div className="rounded-[12px] bg-[#141416] border border-[#232326] p-3">
                      <div className="text-[12px] leading-[16px] text-white whitespace-pre-wrap">{enhanced}</div>
                      <div className="mt-2 flex gap-2">
                        <button onClick={handleApplyBoost} className="flex-1 h-8 rounded-full bg-white text-black text-[12px] font-[700]">Use</button>
                        <button onClick={async()=>{ await navigator.clipboard.writeText(enhanced); setCopiedBoost(true); setTimeout(()=>setCopiedBoost(false),1200)}} className="flex-1 h-8 rounded-full bg-[#1E1E21] border border-[#232326] text-white text-[12px] font-[600]">{copiedBoost?'Copied':'Copy'}</button>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <>
                  <div className="space-y-1.5">
                    {detections.map(d=> (
                      <div key={d.id} className="flex items-center justify-between px-3 py-2 rounded-[10px] bg-[#141416] border border-[#232326]">
                        <span className="text-[12px] font-mono text-[#FF4D4F] truncate max-w-[150px]">{d.span}</span>
                        <span className="text-[11px] font-mono text-white/50">→</span>
                        <span className="text-[11px] font-mono text-[#00C950] truncate max-w-[120px]">{d.placeholder}</span>
                      </div>
                    ))}
                  </div>
                  <div className="rounded-[12px] bg-[#141416] border border-[#232326] p-2.5">
                    <div className="text-[11px] font-mono text-white/60">Safe preview</div>
                    <div className="mt-1 text-[12px] font-mono text-white whitespace-pre-wrap break-words line-clamp-3">{redacted.slice(0,300)}</div>
                  </div>
                  <button onClick={handleApply} className="w-full h-[38px] rounded-[12px] bg-white text-black text-[13px] font-[700] flex items-center justify-center gap-1.5">
                    <ShieldCheck className="w-4 h-4"/> Use safe version {copied?'✓':''}
                  </button>
                  <button onClick={handleBoost} disabled={isEnhancing} className="w-full h-[38px] rounded-[12px] bg-[#141416] border border-[#232326] text-white text-[13px] font-[700] flex items-center justify-center gap-1.5 disabled:opacity-40">
                    {isEnhancing?<span className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin"/>:<Wand2 className="w-4 h-4"/>} Make prompt perfect
                  </button>
                  {enhanced && (
                    <div className="rounded-[12px] bg-white text-black p-3">
                      <div className="text-[12px] leading-[16px] whitespace-pre-wrap">{enhanced}</div>
                      <div className="mt-2 flex gap-2">
                        <button onClick={handleApplyBoost} className="flex-1 h-8 rounded-full bg-black text-white text-[12px] font-[700]">Use</button>
                        <button onClick={async()=>{ await navigator.clipboard.writeText(enhanced); setCopiedBoost(true); setTimeout(()=>setCopiedBoost(false),1200)}} className="flex-1 h-8 rounded-full bg-zinc-100 text-black text-[12px] font-[600]">{copiedBoost?'Copied':'Copy'}</button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>

            <AnimatePresence>
              {showSettings && (
                <motion.div initial={{height:0,opacity:0}} animate={{height:'auto',opacity:1}} exit={{height:0,opacity:0}} className="overflow-hidden border-t border-[#232326] bg-[#0A0A0B]">
                  <div className="p-3 space-y-2">
                    <select value={modelId} onChange={e=> setModelId(e.target.value)} className="w-full h-9 px-3 rounded-full bg-[#141416] border border-[#232326] text-white text-[12px]">
                      {MODELS.map(m=> <option key={m.id} value={m.id}>{m.label} — {m.sub}</option>)}
                    </select>
                    <input value={groqKey} onChange={e=> setGroqKey(e.target.value)} placeholder="Groq gsk_..." className="w-full h-9 px-3 rounded-full bg-[#141416] border border-[#232326] text-white text-[12px] font-mono"/>
                    <input value={apiKey} onChange={e=> setApiKey(e.target.value)} placeholder="Gemini..." className="w-full h-9 px-3 rounded-full bg-[#141416] border border-[#232326] text-white text-[12px] font-mono"/>
                    <label className="flex items-center gap-2 text-[12px] font-[600] text-white"><input type="checkbox" checked={vaultMode} onChange={e=> setVaultMode(e.target.checked)}/> Vault (keep format)</label>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </>
        )}
      </motion.div>
    </div>
  )
}
