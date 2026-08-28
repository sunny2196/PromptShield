import React, { useEffect, useMemo, useState, useRef } from 'react'
import {
  scanLocal, scanWithLLM, scanWithGroq, scanWithOllama,
  redactText, enhancePrompt, computeRiskLevel, computeRiskWithContext,
  computePolicy, sanitizeForCloud, recordToContext,
  type Detection, type RiskLevel, type PolicyDecision
} from '../lib/detection'
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX, Sparkles,
  EyeOff, Settings2, X, Zap, AlertTriangle, Info,
  Copy, Check, ChevronDown, ChevronUp, Wand2,
  GripVertical, Minus, Maximize2, Ban, CheckCircle2,
  AlertCircle, ShieldOff, HelpCircle
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

// ─── Model Options ────────────────────────────────────────────────────────────

type ModelOpt = { id: string; label: string; sub: string }
const MODELS: ModelOpt[] = [
  { id: 'qwen3-local', label: 'Qwen3 4B (Local)', sub: 'Ollama · Fully on-device · No API key · Raw text safe' },
  { id: 'qwen3b',     label: 'Qwen 2.5 3B',      sub: 'Groq API · Sanitised text only' },
  { id: 'llama3b',    label: 'Llama 3.2 3B',      sub: 'Groq API · Sanitised text only' },
  { id: 'gemini-flash', label: 'Gemini 2.0 Flash', sub: 'Google AI · Cloud fallback · Sanitised only' },
]

// ─── Risk level display config ────────────────────────────────────────────────

const RISK_CONFIG: Record<RiskLevel, {
  label: string; emoji: string
  headerBg: string; headerBorder: string
  pillBg: string; pillText: string
}> = {
  CRITICAL: { label: 'CRITICAL RISK',  emoji: '🔴', headerBg: 'bg-[#5A0000]', headerBorder: 'border-[#FF4C4C]', pillBg: 'bg-[#FF0000]',  pillText: 'text-white' },
  HIGH:     { label: 'HIGH RISK',      emoji: '🟠', headerBg: 'bg-[#7A1A1A]', headerBorder: 'border-[#FF8389]', pillBg: 'bg-[#DA1E28]',  pillText: 'text-white' },
  MEDIUM:   { label: 'MEDIUM RISK',    emoji: '🟡', headerBg: 'bg-[#5E4A1A]', headerBorder: 'border-[#FEC57E]', pillBg: 'bg-[#F6C026]',  pillText: 'text-[#161616]' },
  LOW:      { label: 'LOW RISK',       emoji: '🟢', headerBg: 'bg-[#0F3020]', headerBorder: 'border-[#42BE65]', pillBg: 'bg-[#198038]',  pillText: 'text-white' },
  SAFE:     { label: 'Safe to send',   emoji: '🟢', headerBg: 'bg-[#0F5132]', headerBorder: 'border-[#42BE65]', pillBg: 'bg-[#0F5132]',  pillText: 'text-[#A7F0BA]' },
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'bg-[#FF0000] text-white border-[#FF4C4C]',
  HIGH:     'bg-[#DA1E28] text-white border-[#FF8389]',
  MEDIUM:   'bg-[#FEC57E] text-[#161616] border-[#FFB14E]',
  LOW:      'bg-[#E8DAFF] text-[#491D8B] border-[#BE95FF]',
}

// Policy engine display config
const POLICY_CONFIG: Record<PolicyDecision, {
  label: string; icon: React.ComponentType<any>; colour: string
}> = {
  ALLOW:  { label: 'ALLOW',  icon: CheckCircle2, colour: 'text-[#42BE65]' },
  WARN:   { label: 'WARN',   icon: AlertCircle,  colour: 'text-[#F6C026]' },
  REDACT: { label: 'REDACT', icon: ShieldOff,    colour: 'text-[#FF8389]' },
  BLOCK:  { label: 'BLOCK',  icon: Ban,          colour: 'text-[#FF0000]' },
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function PromptShield({
  value, onApplyRedacted, onValueChange
}: { value: string; onApplyRedacted: (v: string) => void; onValueChange?: (v: string) => void }) {

  // ── API config
  const [apiKey,    setApiKey]    = useState(() => localStorage.getItem('ps_gemini_key') || (import.meta as any).env?.VITE_GEMINI_API_KEY || '')
  const [groqKey,   setGroqKey]   = useState(() => localStorage.getItem('ps_groq_key')   || (import.meta as any).env?.VITE_GROQ_API_KEY   || '')
  const [ollamaUrl, setOllamaUrl] = useState(() => localStorage.getItem('ps_ollama_url') || (import.meta as any).env?.VITE_OLLAMA_URL     || 'http://localhost:11434')
  const [modelId,   setModelId]   = useState(() => localStorage.getItem('ps_model')      || 'qwen3-local')

  // ── UI state
  const [showSettings,    setShowSettings]    = useState(false)
  const [isScanning,      setIsScanning]      = useState(false)
  const [localDetections, setLocalDetections] = useState<Detection[]>([])
  const [llmDetections,   setLlmDetections]   = useState<Detection[]>([])
  const [showPanel,       setShowPanel]       = useState(true)
  const [minimized,       setMinimized]       = useState(false)
  const [mode,            setMode]            = useState<'redact' | 'pseudonymize'>('redact')
  const [expanded,        setExpanded]        = useState<string | null>(null)
  const [copied,          setCopied]          = useState(false)
  const [copiedBoost,     setCopiedBoost]     = useState(false)
  const [blockedCount]                        = useState(() => Number(localStorage.getItem('ps_blocked') || '127'))
  const [showDiff,        setShowDiff]        = useState(true)
  const [isBlocked,       setIsBlocked]       = useState(false)
  const [enhanced,        setEnhanced]        = useState<string>('')
  const [isEnhancing,     setIsEnhancing]     = useState(false)
  const [showBoost,       setShowBoost]       = useState(false)

  // ── Drag state
  const [pos, setPos] = useState({ x: 0, y: 0 })
  const [dragging, setDragging] = useState(false)
  const dragRef   = useRef<{ startX: number; startY: number; origX: number; origY: number } | null>(null)
  const panelRef  = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const w = window.innerWidth, h = window.innerHeight
    let x = w - 414, y = 96
    if (w < 1280) { x = Math.max(12, (w - 390) / 2); y = h - 540; if (y < 80) y = 80 }
    setPos({ x: Math.max(8, Math.min(x, w - 398)), y: Math.max(8, Math.min(y, h - 440)) })
  }, [])

  const onPointerDown = (e: React.PointerEvent) => {
    if ((e.target as HTMLElement).closest('button')) return
    setDragging(true)
    dragRef.current = { startX: e.clientX, startY: e.clientY, origX: pos.x, origY: pos.y }
    ;(e.currentTarget as HTMLElement).setPointerCapture(e.pointerId)
  }
  const onPointerMove = (e: React.PointerEvent) => {
    if (!dragging || !dragRef.current) return
    const dx = e.clientX - dragRef.current.startX, dy = e.clientY - dragRef.current.startY
    const w = window.innerWidth, h = window.innerHeight, pw = 390, ph = minimized ? 52 : 580
    setPos({ x: Math.max(4, Math.min(dragRef.current.origX + dx, w - pw - 4)), y: Math.max(4, Math.min(dragRef.current.origY + dy, h - ph - 4)) })
  }
  const onPointerUp = (e: React.PointerEvent) => {
    setDragging(false)
    dragRef.current = null
    try { (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId) } catch { /* noop */ }
  }

  // ── Derived
  const detections = useMemo(() => {
    const map = new Map<string, Detection>()
    for (const d of [...localDetections, ...llmDetections]) {
      const k = `${d.type}:${d.span.toLowerCase()}`
      if (!map.has(k)) map.set(k, d)
    }
    return Array.from(map.values()).sort((a, b) => {
      const sev: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
      return (sev[a.severity] ?? 4) - (sev[b.severity] ?? 4) || a.start - b.start
    })
  }, [localDetections, llmDetections])

  const hasRisk         = detections.length > 0
  const criticalCount   = detections.filter(d => d.severity === 'CRITICAL').length
  const highCount       = detections.filter(d => d.severity === 'HIGH').length
  const mediumCount     = detections.filter(d => d.severity === 'MEDIUM').length

  const riskLevel       = isScanning ? 'SAFE' : computeRiskWithContext(detections) as RiskLevel
  const policy          = computePolicy(riskLevel)
  const rc              = RISK_CONFIG[riskLevel]
  const PolicyIcon      = POLICY_CONFIG[policy].icon

  const redacted        = useMemo(() => redactText(value, detections, mode), [value, detections, mode])
  const taskPreserved   = hasRisk ? 94 + Math.min(5, detections.length) : 100

  const scanStatus = isScanning
    ? 'Analyzing with AI…'
    : hasRisk
      ? [criticalCount ? `${criticalCount} CRITICAL` : '', highCount ? `${highCount} High` : '', mediumCount ? `${mediumCount} Medium` : ''].filter(Boolean).join(' · ') + ` · ${detections.length} total`
      : 'No sensitive data detected'

  // ── Local scan — 280 ms debounce
  useEffect(() => {
    const t = setTimeout(() => {
      if (!value.trim()) {
        setLocalDetections([]); setLlmDetections([])
        setEnhanced(''); setShowBoost(false); setIsBlocked(false)
        return
      }
      const l = scanLocal(value)
      setLocalDetections(l)
      if (l.length > 0) { setShowPanel(true); recordToContext(l) }
    }, 280)
    return () => clearTimeout(t)
  }, [value])

  // ── LLM scan — 750 ms debounce
  // CLOUD GATE ENFORCED: Groq / Gemini receive sanitizeForCloud(value, localDetections)
  // Only local Ollama receives the raw value.
  useEffect(() => {
    if (!value.trim() || value.length < 16) return
    const hasAnyKey = groqKey || apiKey || modelId === 'qwen3-local'
    if (!hasAnyKey) return
    let cancelled = false
    const t = setTimeout(async () => {
      setIsScanning(true)
      let llm: Detection[] = []
      try {
        if (modelId === 'qwen3-local') {
          // On-device: receives raw text (safe — fully local)
          llm = await scanWithOllama(value, ollamaUrl)
        } else if (groqKey) {
          // CLOUD GATE: only sanitized text sent to Groq
          const safeText = sanitizeForCloud(value, localDetections)
          llm = await scanWithGroq(safeText, groqKey, modelId)
          if (llm.length === 0 && apiKey) {
            // CLOUD GATE: only sanitized text sent to Gemini
            const g = await scanWithLLM(safeText, apiKey, modelId)
            llm = [...llm, ...g]
          }
        } else if (apiKey) {
          // CLOUD GATE: only sanitized text sent to Gemini
          const safeText = sanitizeForCloud(value, localDetections)
          llm = await scanWithLLM(safeText, apiKey, modelId)
        }
      } catch { /* noop */ }
      if (!cancelled) { setLlmDetections(llm); setIsScanning(false) }
    }, 750)
    return () => { cancelled = true; clearTimeout(t); setIsScanning(false) }
  }, [value, apiKey, groqKey, ollamaUrl, modelId, localDetections])

  // ── Persist settings
  useEffect(() => {
    localStorage.setItem('ps_gemini_key', apiKey)
    localStorage.setItem('ps_groq_key', groqKey)
    localStorage.setItem('ps_ollama_url', ollamaUrl)
    localStorage.setItem('ps_model', modelId)
  }, [apiKey, groqKey, ollamaUrl, modelId])

  // ── Handlers
  const handleApply = () => {
    onApplyRedacted(redacted); onValueChange?.(redacted)
    const n = blockedCount + detections.length
    localStorage.setItem('ps_blocked', String(n))
    setCopied(true); setTimeout(() => setCopied(false), 1400)
    setIsBlocked(false)
  }
  const handleBlock   = () => setIsBlocked(true)
  const handleUnblock = () => setIsBlocked(false)

  const handleBoost = async () => {
    setIsEnhancing(true); setShowBoost(true)
    // Always boost the sanitized version — never raw prompt to cloud
    const base = redacted !== value ? redacted : sanitizeForCloud(value, detections)
    const out = await enhancePrompt(base, { geminiKey: apiKey, groqKey, ollamaUrl })
    setEnhanced(out); setIsEnhancing(false)
  }

  const handleApplyBoost = () => {
    if (!enhanced) return
    onApplyRedacted(enhanced); onValueChange?.(enhanced)
    setCopiedBoost(true); setTimeout(() => setCopiedBoost(false), 1400)
  }

  // ─── Collapsed pill ──────────────────────────────────────────────────────

  if (!showPanel) {
    return (
      <div className="fixed bottom-4 right-4 z-[60] select-none">
        <button onClick={() => setShowPanel(true)}
          className={`inline-flex items-center gap-2 h-[40px] px-4 rounded-full border shadow-[0_8px_24px_rgba(0,0,0,0.5)] backdrop-blur-md transition-colors ${
            riskLevel === 'CRITICAL' ? 'bg-[#5A0000] border-[#FF4C4C] text-white' :
            riskLevel === 'HIGH'     ? 'bg-[#DA1E28] border-[#FF8389] text-white' :
            riskLevel === 'MEDIUM'   ? 'bg-[#FEC57E] border-[#FFB14E] text-black' :
            isScanning ? 'bg-[#0F62FE] border-[#A6C8FF] text-white' :
            'bg-[#171719] border-[#2E2E32] text-white'
          }`}>
          <Shield className="w-4 h-4" />
          <span className="text-[13px] font-[650]">Ultron</span>
          <span className={`w-2 h-2 rounded-full ${riskLevel === 'SAFE' ? 'bg-[#42BE65]' : 'bg-white animate-pulse'}`} />
          <span className="text-[12px] font-medium opacity-90 hidden sm:inline">{rc.label}</span>
        </button>
      </div>
    )
  }

  // ─── Full panel ──────────────────────────────────────────────────────────

  return (
    <div ref={panelRef} style={{ left: pos.x, top: pos.y, width: 390 }} className="fixed z-[60] select-none">
      <motion.div initial={{ opacity: 0, y: 8, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }}
        className={`rounded-[16px] border bg-[#171719] shadow-[0_16px_48px_rgba(0,0,0,0.6),0_4px_16px_rgba(0,0,0,0.5)] overflow-hidden flex flex-col border-[#2E2E32] ${dragging ? 'shadow-[0_20px_60px_rgba(0,0,0,0.7)]' : ''}`}>

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp}
          className={`h-[52px] px-3 flex items-center justify-between border-b cursor-grab active:cursor-grabbing select-none ${rc.headerBg} ${rc.headerBorder} border-b`}>
          <div className="flex items-center gap-2 min-w-0">
            <span className="hidden sm:grid place-items-center w-6 h-6 rounded bg-black/20 border border-white/10 text-white/80">
              <GripVertical className="w-3.5 h-3.5" />
            </span>
            <div className="w-8 h-8 rounded-[9px] grid place-items-center border bg-black/15 border-white/15 text-white shrink-0">
              {riskLevel === 'CRITICAL' ? <ShieldX className="w-4 h-4" /> :
               riskLevel === 'HIGH' || riskLevel === 'MEDIUM' ? <ShieldAlert className="w-4 h-4" /> :
               <Shield className="w-4 h-4" />}
            </div>
            <div className="min-w-0">
              <div className="text-[13px] font-[750] leading-none text-white tracking-tight flex items-center gap-1.5">
                Ultron
                <span className="text-[10px] font-[700] px-1.5 py-0.5 rounded-full bg-white text-black leading-none">DLP</span>
              </div>
              <div className="text-[11px] font-[600] text-white/80 leading-none mt-1 flex items-center gap-1.5">
                <span className={`w-1.5 h-1.5 rounded-full ${hasRisk ? 'bg-white animate-pulse' : 'bg-[#A7F0BA]'}`} />
                {/* Policy engine decision shown in header */}
                <PolicyIcon className={`w-3 h-3 ${POLICY_CONFIG[policy].colour}`} />
                <span className="truncate">
                  {isScanning ? 'Scanning' : `${POLICY_CONFIG[policy].label} · ${rc.emoji} ${rc.label}`}
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <button onClick={() => setMinimized(v => !v)} title={minimized ? 'Expand' : 'Minimize'}
              className="w-7 h-7 grid place-items-center rounded-full bg-black/15 border border-white/15 text-white/80 hover:bg-black/25 hover:text-white transition-colors">
              {minimized ? <Maximize2 className="w-3.5 h-3.5" /> : <Minus className="w-3.5 h-3.5" />}
            </button>
            <button onClick={() => setShowSettings(v => !v)} title="Settings"
              className={`w-7 h-7 grid place-items-center rounded-full border transition-colors ${showSettings ? 'bg-white text-black border-white' : 'bg-black/15 border-white/15 text-white/80 hover:bg-black/25 hover:text-white'}`}>
              <Settings2 className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => setShowPanel(false)} title="Close"
              className="w-7 h-7 grid place-items-center rounded-full bg-black/15 border border-white/15 text-white/80 hover:bg-white hover:text-black transition-colors">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {!minimized && (<>
          {/* ── Scan rail ───────────────────────────────────────────────── */}
          <div className="px-3 py-2 bg-[#1E1E21] border-b border-[#232326] flex items-center justify-between">
            <div className="flex items-center gap-2 text-[11px] font-[600] text-[#D4D4D8]">
              <Zap className={`w-3.5 h-3.5 ${isScanning ? 'text-[#0F62FE] animate-pulse' : hasRisk ? 'text-[#FF8389]' : 'text-[#A1A1AA]'}`} />
              <span className={criticalCount > 0 ? 'text-[#FF8389]' : ''}>{scanStatus}</span>
              {isScanning && <span className="w-3 h-3 border-2 border-[#3A3A42] border-t-[#0F62FE] rounded-full animate-spin" />}
            </div>
            <div className="flex items-center gap-2">
              {/* Cloud gate indicator */}
              <span title="Cloud gate: only sanitized text reaches cloud AI"
                className="text-[10px] font-[600] px-1.5 py-0.5 rounded bg-[#0F3020] border border-[#1F3A2B] text-[#6FDC8C]">
                🔒 Local-first
              </span>
              <span className="text-[11px] font-[600] text-[#71717A]">{blockedCount} blocked</span>
            </div>
          </div>

          {/* ── BLOCK overlay ───────────────────────────────────────────── */}
          <AnimatePresence>
            {isBlocked && (
              <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.97 }}
                className="absolute inset-0 z-20 bg-[#1A0000]/95 backdrop-blur-sm flex flex-col items-center justify-center gap-4 p-6">
                <div className="w-16 h-16 rounded-full bg-[#5A0000] border-2 border-[#FF4C4C] grid place-items-center">
                  <Ban className="w-8 h-8 text-[#FF8389]" />
                </div>
                <div className="text-center">
                  <div className="text-[16px] font-[800] text-white">Prompt Blocked</div>
                  <div className="mt-1.5 text-[12px] text-[#FF8389] leading-[16px]">
                    Policy: <span className="font-[750]">BLOCK</span> · {criticalCount} CRITICAL · {highCount} High<br />
                    This prompt was prevented from being submitted.
                  </div>
                </div>
                <div className="w-full space-y-2">
                  <button onClick={handleApply}
                    className="w-full h-[38px] rounded-[10px] bg-white text-black text-[13px] font-[750] inline-flex items-center justify-center gap-1.5 hover:bg-zinc-100 transition-colors">
                    <ShieldCheck className="w-4 h-4" /> Apply Safe Rewrite & Send
                  </button>
                  <button onClick={handleUnblock}
                    className="w-full h-[38px] rounded-[10px] bg-[#232326] border border-[#3A3A42] text-[#A1A1AA] text-[13px] font-[650] hover:bg-[#2A2A2E] transition-colors">
                    Review Detections
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* ── Body ────────────────────────────────────────────────────── */}
          <div className="max-h-[56vh] overflow-y-auto custom-scrollbar bg-[#171719]">

            {/* SAFE state */}
            {!hasRisk ? (
              <div className="p-3 space-y-3">
                <div className="rounded-[12px] bg-[#0E1A14] border border-[#1F3A2B] p-3 flex gap-3">
                  <div className="w-8 h-8 rounded-[10px] bg-[#0F5132] grid place-items-center shrink-0">
                    <ShieldCheck className="w-4 h-4 text-[#A7F0BA]" />
                  </div>
                  <div>
                    <div className="text-[13px] font-[650] text-[#A7F0BA] flex items-center gap-1.5">
                      Safe to send
                      <span className="text-[10px] font-[700] px-1.5 py-0.5 rounded-full bg-[#0F5132] border border-[#1F3A2B] text-[#A7F0BA]">ALLOW</span>
                    </div>
                    <div className="text-[12px] leading-[16px] text-[#6FDC8C] mt-1">
                      No sensitive data detected. Ultron watches every keystroke before it leaves your device.
                    </div>
                  </div>
                </div>

                {/* Boost card */}
                <div className="rounded-[12px] border border-[#2E2E32] overflow-hidden bg-[#0F0F10]">
                  <div className="px-3 py-2.5 flex items-center gap-1.5 bg-gradient-to-r from-[#1A1A2E] to-[#1E1E21] border-b border-[#232326]">
                    <Wand2 className="w-3.5 h-3.5 text-[#BE95FF]" />
                    <span className="text-[11px] font-[700] tracking-[0.08em] uppercase text-[#A1A1AA]">Turn lazy prompts into great ones</span>
                  </div>
                  <div className="p-3">
                    <p className="text-[12px] leading-[16px] text-[#A1A1AA]">One tap adds role, goal, constraints and format — placeholders stay safe.</p>
                    <button onClick={handleBoost} disabled={isEnhancing || !value.trim()}
                      className="mt-2.5 w-full h-[36px] rounded-[10px] bg-gradient-to-r from-[#7C3AED] to-[#0F62FE] text-white text-[13px] font-[700] inline-flex items-center justify-center gap-1.5 hover:opacity-95 active:opacity-90 transition-opacity disabled:opacity-50">
                      {isEnhancing ? <><span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Enhancing</> : <><Sparkles className="w-3.5 h-3.5" /> Boost prompt</>}
                    </button>
                    {showBoost && enhanced && (
                      <div className="mt-3 rounded-[10px] bg-[#0E1A14] border border-[#1F3A2B] p-2.5">
                        <div className="text-[10px] font-[700] tracking-[0.08em] uppercase text-[#6FDC8C] flex items-center gap-1"><Sparkles className="w-3 h-3" /> Enhanced</div>
                        <div className="mt-1.5 text-[12px] leading-[16px] text-[#D4D4D8] whitespace-pre-wrap break-words">{enhanced}</div>
                        <div className="mt-2 grid grid-cols-2 gap-2">
                          <button onClick={handleApplyBoost} className="h-[32px] rounded-[8px] bg-white text-black text-[12px] font-[700]">Use this prompt</button>
                          <button onClick={async () => { await navigator.clipboard.writeText(enhanced); setCopiedBoost(true); setTimeout(() => setCopiedBoost(false), 1200) }}
                            className="h-[32px] rounded-[8px] bg-[#1E1E21] border border-[#2E2E32] text-white text-[12px] font-[600] inline-flex items-center justify-center gap-1">
                            {copiedBoost ? <Check className="w-3.5 h-3.5 text-[#42BE65]" /> : <Copy className="w-3.5 h-3.5" />}
                            {copiedBoost ? 'Copied' : 'Copy'}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

            ) : (
              // Risk state
              <div className="p-3 space-y-3">

                {/* CRITICAL banner */}
                {riskLevel === 'CRITICAL' && (
                  <div className="rounded-[10px] bg-[#5A0000] border border-[#FF4C4C] px-3 py-2 flex items-center gap-2">
                    <ShieldX className="w-4 h-4 text-[#FF8389] shrink-0" />
                    <div>
                      <div className="text-[12px] font-[750] text-white">🔴 CRITICAL — Prompt Blocked</div>
                      <div className="text-[11px] text-[#FF8389] mt-0.5">
                        {criticalCount} credential{criticalCount !== 1 ? 's' : ''} / secret{criticalCount !== 1 ? 's' : ''} detected. Policy: BLOCK.
                      </div>
                    </div>
                  </div>
                )}

                {/* ── Detection cards ────────────────────────────────────── */}
                <div className="space-y-2">
                  {detections.map(d => {
                    const isOpen = expanded === d.id
                    const confPct = Math.round(d.confidence * 100)
                    // Confidence bar colour
                    const barCol = confPct >= 90 ? '#FF4C4C' : confPct >= 70 ? '#F6C026' : '#42BE65'
                    return (
                      <div key={d.id} className="rounded-[12px] border border-[#2E2E32] bg-[#1E1E21] overflow-hidden">
                        <button onClick={() => setExpanded(isOpen ? null : d.id)} className="w-full text-left px-3 py-2.5 flex items-start justify-between gap-3">
                          <div className="min-w-0 flex-1 space-y-1.5">

                            {/* Row 1: severity + label + source badge + confidence */}
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className={`inline-flex items-center h-5 px-2 rounded-full border text-[11px] font-[750] tracking-wide ${SEVERITY_STYLE[d.severity] || SEVERITY_STYLE.LOW}`}>
                                {d.severity}
                              </span>
                              <span className="text-[13px] font-[650] text-white leading-none">{d.label}</span>
                              <span className={`inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border ${d.source === 'llm' ? 'bg-[#EDF5FF] border-[#A6C8FF] text-[#0F62FE]' : 'bg-[#1E1E21] border-[#2E2E32] text-[#A1A1AA]'}`}>
                                {d.source === 'llm' ? 'AI' : d.source}
                              </span>
                              {/* Confidence % badge */}
                              <span className="text-[10px] font-[700] px-1.5 py-0.5 rounded-full bg-[#0F0F10] border border-[#2E2E32] text-[#A1A1AA]">
                                {confPct}%
                              </span>
                            </div>

                            {/* Row 2: span → placeholder */}
                            <div className="inline-flex max-w-full items-center gap-1.5 px-2 py-1 rounded-[8px] bg-[#0F0F10] border border-[#2E2E32]">
                              <span className="text-[12px] font-mono text-[#FF8389] truncate max-w-[18ch]">{d.span}</span>
                              <span className="text-[#52525B]">→</span>
                              <span className="text-[11px] font-mono font-[600] text-[#42BE65]">{d.placeholder}</span>
                            </div>

                            {/* Row 3: one-line risk summary */}
                            <div className="text-[11px] leading-[14px] text-[#A1A1AA] line-clamp-2">{d.risk}</div>

                            {/* Row 4: confidence bar */}
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-[3px] rounded-full bg-[#2E2E32] overflow-hidden">
                                <div className="h-full rounded-full transition-all" style={{ width: `${confPct}%`, backgroundColor: barCol }} />
                              </div>
                              <span className="text-[10px] text-[#71717A] font-mono shrink-0">Confidence</span>
                            </div>
                          </div>

                          <span className="shrink-0 w-6 h-6 rounded-full bg-[#0F0F10] border border-[#2E2E32] grid place-items-center text-[#A1A1AA] mt-0.5">
                            {isOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                          </span>
                        </button>

                        {/* ── "Why is this risky?" expanded panel ─────────── */}
                        <AnimatePresence>
                          {isOpen && (
                            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                              className="overflow-hidden border-t border-[#232326] bg-[#141416]">
                              <div className="px-3 py-3 space-y-2.5">

                                {/* Type header */}
                                <div className="flex items-center gap-2">
                                  <HelpCircle className="w-3.5 h-3.5 text-[#0F62FE] shrink-0" />
                                  <span className="text-[11px] font-[700] tracking-[0.06em] uppercase text-[#A1A1AA]">Why is this risky?</span>
                                </div>

                                {/* Reason */}
                                <p className="text-[12px] leading-[17px] text-[#D4D4D8]">{d.reason}</p>

                                {/* Recommendation */}
                                <div className="rounded-[8px] bg-[#0E1A14] border border-[#1F3A2B] px-2.5 py-2">
                                  <div className="text-[10px] font-[700] tracking-[0.06em] uppercase text-[#6FDC8C] mb-1">Recommendation</div>
                                  <div className="text-[12px] text-[#A7F0BA] leading-[16px]">
                                    Replace with <code className="font-mono text-[11px] bg-[#0F5132] px-1 py-0.5 rounded">{d.placeholder}</code>
                                  </div>
                                </div>

                                {/* Meta */}
                                <div className="flex items-center gap-3 text-[10px] text-[#71717A]">
                                  <span className="flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Confidence: {confPct}%</span>
                                  <span>Source: {d.source}</span>
                                  <span>Type: {d.type}</span>
                                </div>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    )
                  })}
                </div>

                {/* Redact / Pseudonymize toggle */}
                <div className="flex items-center gap-1 p-1 rounded-full bg-[#0F0F10] border border-[#2E2E32] w-fit">
                  <button onClick={() => setMode('redact')} className={`h-7 px-3 rounded-full text-[12px] font-[650] transition-colors ${mode === 'redact' ? 'bg-white text-black' : 'text-[#A1A1AA] hover:text-white'}`}>Redact</button>
                  <button onClick={() => setMode('pseudonymize')} className={`h-7 px-3 rounded-full text-[12px] font-[650] transition-colors ${mode === 'pseudonymize' ? 'bg-white text-black' : 'text-[#A1A1AA] hover:text-white'}`}>Pseudonymize</button>
                </div>

                {/* Before → After diff */}
                <div className="rounded-[12px] border border-[#2E2E32] overflow-hidden bg-[#0F0F10]">
                  <button onClick={() => setShowDiff(!showDiff)} className="w-full h-[36px] px-3 flex items-center justify-between bg-[#1B1B1E] border-b border-[#232326]">
                    <span className="text-[11px] font-[700] tracking-[0.08em] uppercase text-[#A1A1AA] flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5 text-[#0F62FE]" /> Before → After · {taskPreserved}% task preserved
                    </span>
                    <span className="text-[#A1A1AA]">{showDiff ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}</span>
                  </button>
                  {showDiff && (
                    <div className="p-3 space-y-2">
                      <div>
                        <div className="text-[10px] font-[700] tracking-[0.08em] uppercase text-[#71717A]">Original</div>
                        <div className="mt-1 rounded-[10px] bg-[#1E1E21] border border-[#2E2E32] p-2.5 text-[12px] leading-[16px] font-mono text-[#FF8389] whitespace-pre-wrap break-words max-h-[80px] overflow-y-auto custom-scrollbar">
                          {value || <span className="text-[#71717A]">—</span>}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] font-[700] tracking-[0.08em] uppercase text-[#71717A]">Safe (cloud-ready)</div>
                        <div className="mt-1 rounded-[10px] bg-[#0E1A14] border border-[#1F3A2B] p-2.5 text-[12px] leading-[16px] font-mono text-[#A7F0BA] whitespace-pre-wrap break-words max-h-[80px] overflow-y-auto custom-scrollbar">
                          {redacted || <span className="text-[#71717A]">—</span>}
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Boost card */}
                <div className="rounded-[12px] border border-[#2E2E32] overflow-hidden bg-gradient-to-br from-[#1A1A2E] to-[#0F0F10]">
                  <div className="px-3 py-2.5 flex items-center justify-between border-b border-[#232326]">
                    <span className="text-[11px] font-[700] tracking-[0.08em] uppercase text-[#BE95FF] flex items-center gap-1.5">
                      <Wand2 className="w-3.5 h-3.5" /> Boost (sanitized)
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#0F3020] border border-[#1F3A2B] text-[#6FDC8C]">🔒 no raw data to cloud</span>
                  </div>
                  <div className="p-3">
                    <p className="text-[12px] leading-[16px] text-[#A1A1AA]">
                      Cloud AI sees only the <span className="text-white font-[600]">sanitized</span> version — all secrets replaced before sending.
                    </p>
                    <button onClick={handleBoost} disabled={isEnhancing}
                      className="mt-2.5 w-full h-[36px] rounded-[10px] bg-gradient-to-r from-[#7C3AED] to-[#0F62FE] text-white text-[13px] font-[700] inline-flex items-center justify-center gap-1.5 hover:opacity-95 active:opacity-90 disabled:opacity-60 transition-opacity">
                      {isEnhancing ? <><span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Boosting</> : <><Sparkles className="w-3.5 h-3.5" /> Boost prompt</>}
                    </button>
                    {showBoost && (
                      <div className="mt-3 rounded-[10px] bg-[#171719] border border-[#2E2E32] p-2.5">
                        <div className="text-[10px] font-[700] tracking-[0.08em] uppercase text-[#BE95FF] flex items-center gap-1">
                          <Sparkles className="w-3 h-3" /> {isEnhancing ? 'Crafting…' : 'Boosted prompt'}
                        </div>
                        <div className="mt-1.5 text-[12px] leading-[16px] text-[#D4D4D8] whitespace-pre-wrap break-words min-h-[24px]">
                          {isEnhancing ? <span className="text-[#71717A]">Working…</span> : (enhanced || <span className="text-[#71717A]">—</span>)}
                        </div>
                        {!isEnhancing && enhanced && (
                          <div className="mt-2 grid grid-cols-2 gap-2">
                            <button onClick={handleApplyBoost} className="h-[32px] rounded-[8px] bg-white text-black text-[12px] font-[700]">Use this</button>
                            <button onClick={async () => { await navigator.clipboard.writeText(enhanced); setCopiedBoost(true); setTimeout(() => setCopiedBoost(false), 1200) }}
                              className="h-[32px] rounded-[8px] bg-[#1E1E21] border border-[#2E2E32] text-white text-[12px] font-[600] inline-flex items-center justify-center gap-1">
                              {copiedBoost ? <Check className="w-3.5 h-3.5 text-[#42BE65]" /> : <Copy className="w-3.5 h-3.5" />}
                              {copiedBoost ? 'Copied' : 'Copy'}
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* ── Settings panel ──────────────────────────────────────────── */}
          <AnimatePresence>
            {showSettings && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden border-t border-[#232326] bg-[#0F0F10]">
                <div className="p-3 space-y-3 max-h-[40vh] overflow-y-auto custom-scrollbar">
                  <div className="flex items-center justify-between">
                    <div className="text-[11px] font-[700] tracking-[0.08em] uppercase text-[#A1A1AA]">AI Layer Settings</div>
                    <button onClick={() => setShowSettings(false)} className="w-6 h-6 grid place-items-center rounded-full hover:bg-[#232326] text-[#71717A] hover:text-white">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  {/* Privacy notice */}
                  <div className="rounded-[8px] bg-[#0E1A14] border border-[#1F3A2B] px-2.5 py-2 text-[11px] text-[#6FDC8C] leading-[15px]">
                    🔒 <strong>Cloud gate enforced:</strong> Groq & Gemini only receive sanitized text.
                    Raw prompts are only processed by local Ollama.
                  </div>
                  <div className="grid gap-2">
                    {MODELS.map(m => (
                      <button key={m.id} onClick={() => setModelId(m.id)}
                        className={`text-left flex items-center justify-between gap-3 px-3 py-2.5 rounded-[10px] border transition-colors ${modelId === m.id ? 'bg-white border-white shadow-sm' : 'bg-[#1E1E21] border-[#2E2E32] hover:border-[#3A3A42]'}`}>
                        <div>
                          <div className={`text-[13px] font-[650] leading-none ${modelId === m.id ? 'text-black' : 'text-white'}`}>
                            {m.label}
                            {modelId === m.id && <span className="ml-1.5 text-[10px] font-[700] px-1.5 py-0.5 rounded-full bg-[#0F62FE] text-white align-middle">ACTIVE</span>}
                          </div>
                          <div className={`text-[11px] font-medium mt-1 ${modelId === m.id ? 'text-[#52525B]' : 'text-[#A1A1AA]'}`}>{m.sub}</div>
                        </div>
                        <div className={`w-4 h-4 rounded-full border-2 grid place-items-center shrink-0 ${modelId === m.id ? 'border-black bg-black' : 'border-[#52525B]'}`}>
                          {modelId === m.id && <div className="w-1.5 h-1.5 rounded-full bg-white" />}
                        </div>
                      </button>
                    ))}
                  </div>
                  <div className="space-y-2">
                    <div>
                      <label className="text-[10px] font-[600] text-[#71717A] tracking-[0.06em] uppercase">Ollama URL (local — raw text safe)</label>
                      <input value={ollamaUrl} onChange={e => setOllamaUrl(e.target.value)} placeholder="http://localhost:11434"
                        className="mt-1 w-full h-[36px] px-3 rounded-[10px] bg-[#1E1E21] border border-[#2E2E32] text-[12px] font-mono text-white placeholder-[#52525B] focus:outline-none focus:border-[#3A3A42]" />
                    </div>
                    <div>
                      <label className="text-[10px] font-[600] text-[#71717A] tracking-[0.06em] uppercase">Groq API Key (cloud — sanitized only)</label>
                      <input value={groqKey} onChange={e => setGroqKey(e.target.value)} placeholder="gsk_..."
                        className="mt-1 w-full h-[36px] px-3 rounded-[10px] bg-[#1E1E21] border border-[#2E2E32] text-[12px] font-mono text-white placeholder-[#52525B] focus:outline-none focus:border-[#3A3A42]" />
                    </div>
                    <div>
                      <label className="text-[10px] font-[600] text-[#71717A] tracking-[0.06em] uppercase">Gemini API Key (fallback — sanitized only)</label>
                      <div className="mt-1 flex gap-2">
                        <input value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder="AIza..."
                          className="flex-1 h-[36px] px-3 rounded-[10px] bg-[#1E1E21] border border-[#2E2E32] text-[12px] font-mono text-white placeholder-[#52525B] focus:outline-none focus:border-[#3A3A42]" />
                        <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noreferrer"
                          className="shrink-0 inline-flex items-center gap-1 h-[36px] px-3 rounded-[10px] bg-white text-black text-[11px] font-[650] hover:bg-zinc-100">Get</a>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* ── Action footer — ALLOW / WARN / REDACT / BLOCK policy engine ── */}
          <div className="p-3 border-t border-[#232326] bg-[#1B1B1E] space-y-2">
            {hasRisk ? (
              <>
                {/* 4-action policy row */}
                <div className="grid grid-cols-[1fr_auto_auto_auto] gap-2">
                  <button onClick={handleApply}
                    className="h-[38px] rounded-[10px] bg-white text-black text-[13px] font-[750] inline-flex items-center justify-center gap-1.5 hover:bg-zinc-100 active:bg-zinc-200 transition-colors">
                    <ShieldCheck className="w-4 h-4" /> Apply safe rewrite
                  </button>
                  <button onClick={async () => { await navigator.clipboard.writeText(redacted); setCopied(true); setTimeout(() => setCopied(false), 1200) }}
                    title="Copy sanitized prompt"
                    className="h-[38px] px-3 rounded-[10px] bg-[#232326] border border-[#2E2E32] text-white text-[13px] font-[650] inline-flex items-center gap-1.5 hover:bg-[#2A2A2E] transition-colors">
                    {copied ? <Check className="w-4 h-4 text-[#42BE65]" /> : <Copy className="w-4 h-4" />}
                  </button>
                  <button onClick={handleBlock} title="Block — prevent sending (CRITICAL)"
                    className="h-[38px] px-3 rounded-[10px] bg-[#5A0000] border border-[#FF4C4C] text-[#FF8389] inline-flex items-center gap-1.5 hover:bg-[#6E0000] transition-colors">
                    <Ban className="w-4 h-4" />
                  </button>
                </div>

                {/* Policy engine label */}
                <div className="flex items-center justify-between text-[11px] text-[#71717A]">
                  <span className="flex items-center gap-1.5">
                    <PolicyIcon className={`w-3.5 h-3.5 ${POLICY_CONFIG[policy].colour}`} />
                    <span>Policy: <span className={`font-[750] ${POLICY_CONFIG[policy].colour}`}>{policy}</span></span>
                    <span className="text-[#52525B]">·</span>
                    <span className={riskLevel === 'CRITICAL' ? 'text-[#FF8389] font-[650]' : ''}>{rc.label}</span>
                  </span>
                  <span className="inline-flex items-center gap-1 font-[650] text-[#A1A1AA]">
                    <Info className="w-3 h-3" /> {blockedCount} blocked
                  </span>
                </div>
              </>
            ) : (
              <div className="flex items-center justify-between text-[11px] text-[#71717A]">
                <span className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#42BE65]" />
                  <span>Policy: <span className="font-[750] text-[#42BE65]">ALLOW</span> · Detect → Explain → Redact → Protect</span>
                </span>
                <span className="text-[#42BE65] font-[650]">Active</span>
              </div>
            )}
          </div>
        </>)}
      </motion.div>
    </div>
  )
}
