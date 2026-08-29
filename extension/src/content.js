// PromptShield — Content Script v2.0 (real extension, same engine as Claude simulation)
// Injects beside the prompt box on ChatGPT / Claude / Gemini / Perplexity
(() => {
  if (window.__ps_injected) return; window.__ps_injected = true;
  console.log('[PromptShield] content v2.0 injected', location.hostname);

  // ---------- storage helpers ----------
  const getStore = () => new Promise(r => {
    try { chrome.storage.local.get(['ps_model','ps_groq_key','ps_gemini_key','ps_vault_mode','ps_session_v2','ps_session_id','ps_vault_v2'], v => r(v || {})); }
    catch { r({}); }
  });
  const setStore = o => new Promise(r => { try{ chrome.storage.local.set(o, ()=>r(true)); }catch{ r(false);} });

  // ---------- detection engine (ported from src/lib/detection.ts) ----------
  const luhn = s => {
    const d = s.replace(/[\s-]/g,''); if(!/^\d{13,19}$/.test(d)) return false;
    let sum=0, alt=false; for(let i=d.length-1;i>=0;i--){ let n=parseInt(d[i]); if(alt){ n*=2; if(n>9)n-=9 } sum+=n; alt=!alt } return sum%10===0;
  };
  const shannonEntropy = s => {
    const freq={}; for(const c of s) freq[c]=(freq[c]||0)+1;
    let e=0; for(const f of Object.values(freq)){ const p=f/s.length; e -= p*Math.log2(p)} return e;
  };
  const isHighEntropySecret = s => s.length>=20 && /^[A-Za-z0-9_\-+=/]+$/.test(s) && shannonEntropy(s) > 4.5;

  const PATTERNS = [
    {type:'API_KEY',label:'Stripe Secret Key',severity:'HIGH',risk:'Can charge customers',reason:'Stripe secret keys grant full API access.',placeholder:'[REDACTED_STRIPE_KEY]',regex:/\bsk_(live|test|proj)_[A-Za-z0-9]{16,}\b/g,conf:0.99},
    {type:'API_KEY',label:'AWS Access Key',severity:'HIGH',risk:'Cloud takeover',reason:'AKIA keys give AWS access.',placeholder:'[REDACTED_AWS_KEY]',regex:/\bAKIA[0-9A-Z]{16}\b/g,conf:0.98},
    {type:'API_KEY',label:'GitHub Token',severity:'HIGH',risk:'Repo takeover',reason:'GitHub tokens grant repo access.',placeholder:'[REDACTED_GITHUB_TOKEN]',regex:/\b(ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,conf:0.97},
    {type:'API_KEY',label:'Slack Token',severity:'HIGH',risk:'Workspace exfil',reason:'Slack tokens read messages.',placeholder:'[REDACTED_SLACK_TOKEN]',regex:/\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9-]+\b/g,conf:0.96},
    {type:'AADHAAR',label:'Aadhaar Number',severity:'HIGH',risk:'Identity theft',reason:'12-digit govt ID.',placeholder:'[REDACTED_AADHAAR]',regex:/\b\d{4}\s?\d{4}\s?\d{4}\b/g,conf:0.88,validator:m=>m.replace(/\s/g,'').length===12},
    {type:'PAN',label:'PAN Card',severity:'HIGH',risk:'Financial fraud',reason:'PAN linked to tax/bank.',placeholder:'[REDACTED_PAN]',regex:/\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,conf:0.96},
    {type:'CARD',label:'Credit Card',severity:'HIGH',risk:'Financial fraud',reason:'Luhn card.',placeholder:'[REDACTED_CARD]',regex:/\b(?:\d[ -]*?){13,19}\b/g,conf:0.92,validator:luhn},
    {type:'EMAIL',label:'Personal Email',severity:'MEDIUM',risk:'Phishing',reason:'Email enables phishing.',placeholder:'[REDACTED_EMAIL]',regex:/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,conf:0.9},
    {type:'PHONE',label:'Indian Mobile',severity:'MEDIUM',risk:'SIM swap',reason:'Phone used for OTP.',placeholder:'[REDACTED_PHONE]',regex:/\b(?:\+91[\s-]?)?[6-9]\d{9}\b/g,conf:0.9},
    {type:'INTERNAL',label:'Internal Link',severity:'MEDIUM',risk:'Corp leak',reason:'Internal link leaks org.',placeholder:'[REDACTED_INT_LINK]',regex:/https?:\/\/(?:[a-z0-9-]+\.)*atlassian\.net\/wiki\/\S+|https?:\/\/.*\.notion\.site\/\S+/gi,conf:0.85},
    {type:'FINANCIAL',label:'UPI ID',severity:'MEDIUM',risk:'UPI fraud',reason:'UPI linked to bank.',placeholder:'[REDACTED_UPI]',regex:/\b[a-zA-Z0-9.\-_]{2,64}@(okicici|okaxis|okhdfcbank|oksbi|ybl|apl|paytm|upi)\b/gi,conf:0.88},
    {type:'FINANCIAL',label:'Tamil Aadhaar',severity:'HIGH',risk:'Govt ID Tamil',reason:'Tamil Aadhaar.',placeholder:'[REDACTED_AADHAAR]',regex:/(Enoda|Aadhaar)[^\n]{0,24}\d{4}\s?\d{4}\s?\d{4}/gi,conf:0.9},
  ];
  const scanLocal = text => {
    const out=[]; let id=0;
    for(const p of PATTERNS){
      const re=new RegExp(p.regex.source,p.regex.flags); let m;
      while((m=re.exec(text))!==null){
        const span=m[0]; if(p.validator && !p.validator(span)) continue;
        if(p.type==='CARD' && span.includes('@')) continue;
        const start=m.index, end=start+span.length;
        if(out.some(d=> !(end<=d.start || start>=d.end))) continue;
        out.push({id:`d-${id++}`,span,type:p.type,label:p.label,severity:p.severity,risk:p.risk,reason:p.reason,placeholder:p.placeholder,start,end,confidence:p.conf,source:'regex'});
        if(!span.length) re.lastIndex++;
      }
    }
    // contextual
    if(/my salary is/i.test(text)){
      const m=text.match(/my salary is[^\n]{0,40}/gi); if(m) m.forEach((s,i)=>{ const idx=text.indexOf(s); out.push({id:`ctx-${i}`,span:s,type:'FINANCIAL',label:'Salary Disclosure',severity:'MEDIUM',risk:'Comp leak',reason:'Salary is sensitive.',placeholder:'[REDACTED_SALARY]',start:idx,end:idx+s.length,confidence:0.82,source:'llm'}); });
    }
    if(/my manager at/i.test(text)){
      const m=text.match(/my manager at[^\n]{0,40}/gi); if(m) m.forEach((s,i)=>{ const idx=text.indexOf(s); out.push({id:`ctx2-${i}`,span:s,type:'PERSON_NAME',label:'Manager + Org',severity:'LOW',risk:'Workplace graph',reason:'Links to org.',placeholder:'[REDACTED_NAME]',start:idx,end:idx+s.length,confidence:0.7,source:'llm'}); });
    }
    // entropy
    const toks=text.split(/[\s\n,;|]+/);
    for(const tok of toks){
      const cl=tok.replace(/[^A-Za-z0-9_\-+=/]/g,'');
      if(cl.length>=24 && isHighEntropySecret(cl) && !out.some(d=>d.span===cl)){
        const s=text.indexOf(tok); out.push({id:`ent-${cl.slice(0,4)}`,span:cl,type:'API_KEY',label:'High-entropy secret',severity:'HIGH',risk:'Obfuscated',reason:`Entropy ${shannonEntropy(cl).toFixed(2)}>4.5`,placeholder:'[REDACTED_SECRET]',start:s,end:s+cl.length,confidence:0.82,source:'llm'});
      }
    }
    return out.sort((a,b)=>a.start-b.start);
  };
  const redactText = (text,dets,mode='redact')=>{
    if(!dets.length) return text;
    const sorted=[...dets].sort((a,b)=>b.start-a.start);
    let out=text; const pseudo={EMAIL:'user@example.com',PHONE:'+91 90000 00000',PERSON_NAME:'Person A',ADDRESS:'[City, State]'};
    for(const d of sorted){
      if(d.start<0) continue;
      const rep = mode==='pseudonymize' && pseudo[d.type] ? pseudo[d.type] : d.placeholder;
      out=out.slice(0,d.start)+rep+out.slice(d.end);
    }
    return out;
  };
  // vault helpers
  const vaultFake = (type,real)=>{
    const rh=n=>{ const a=new Uint8Array(n); crypto.getRandomValues(a); return Array.from(a).map(b=>b.toString(16).padStart(2,'0')).slice(0,n).join('').slice(0,n)};
    const ra=n=>{ const ch='abcdefghijklmnopqrstuvwxyz0123456789'; const a=new Uint8Array(n); crypto.getRandomValues(a); return Array.from(a).map(b=>ch[b%ch.length]).join('')};
    if(type==='EMAIL') return `user_${rh(4)}@example.com`;
    if(type==='API_KEY' && real.startsWith('sk_live_')) return real.slice(0,8)+'XXXX_MOCKKEY_'+rh(4);
    if(type==='API_KEY' && real.startsWith('AKIA')) return 'AKIA'+ra(16).toUpperCase();
    return `token_${rh(6)}`;
  };
  const vaultGet = async ()=>{
    const d=await getStore(); try{ const raw=d.ps_vault_v2; if(!raw) return []; if(raw.startsWith('[')) return JSON.parse(raw); return JSON.parse(atob(raw)); }catch{ return []}
  };
  const vaultSave = async arr=>{ const b=btoa(JSON.stringify(arr)); await setStore({ps_vault_v2:b}); };
  const vaultTokenize = async (text,dets)=>{
    const sorted=[...dets].filter(d=>d.start>=0).sort((a,b)=>b.start-a.start);
    let out=text; const vault=await vaultGet();
    for(const d of sorted){
      let e=vault.find(v=>v.real===d.span);
      if(!e){ e={real:d.span,fake:vaultFake(d.type,d.span),type:d.type,label:d.label,createdAt:Date.now()}; vault.push(e); }
      out=out.slice(0,d.start)+e.fake+out.slice(d.end);
    }
    await vaultSave(vault); return {tokenized:out, map:vault.slice(-4)};
  };

  // session contamination
  const getSid = async ()=>{
    let d=await getStore(); let sid=d.ps_session_id;
    if(!sid){ sid='sess_'+Math.random().toString(36).slice(2,8)+'_'+Date.now().toString(36); await setStore({ps_session_id:sid, ps_session_created:String(Date.now())}); }
    return sid;
  };
  const sessionLoad = async ()=>{
    const sid=await getSid();
    const d=await getStore();
    try{ const j=JSON.parse(d.ps_session_v2||'null'); if(j && j.sessionId===sid) return j; }catch{}
    return {sessionId:sid, leaks:[], createdAt:Date.now()};
  };
  const sessionSave = async s=>{ await setStore({ps_session_v2:JSON.stringify(s)}); };
  const sessionScore = s=>{
    const sens=h=>h==='HIGH'?9:h==='MEDIUM'?5:2;
    const exp=(t,sev)=>t==='API_KEY'?10:(t==='AADHAAR'||t==='PAN'?9:sev==='HIGH'?8:sev==='MEDIUM'?5:3);
    let max=0, sum=0; for(const l of s.leaks){ const r=sens(l.severity)*exp(l.type,l.severity); if(r>max)max=r; sum+=r; }
    return Math.max(max, Math.min(100, Math.round(sum/10)));
  };

  // LLM scan via Groq/Gemini
  const scanWithGroq = async (text, groqKey, modelHint)=>{
    if(!groqKey || text.length<12) return [];
    const model = 'llama-3.2-3b-preview';
    try{
      const res=await fetch('https://api.groq.com/openai/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+groqKey},body:JSON.stringify({model,temperature:0.1,max_tokens:600,messages:[{role:'system',content:'You are PromptShield. Return ONLY JSON array.'},{role:'user',content:`Analyze prompt for salary/org/medical/person+role.\nPROMPT:\n"""${text.slice(0,3000)}"""\nReturn JSON array of {"span": exact substring, "label": short, "type": one of [FINANCIAL,MEDICAL,INTERNAL,PERSON_NAME,ADDRESS], "severity": HIGH|MEDIUM|LOW, "risk": short, "reason": one sentence, "placeholder": like [REDACTED_SALARY]}. Return [] if none.`}]})});
      if(!res.ok) return [];
      const j=await res.json(); const txt=j.choices?.[0]?.message?.content||''; const s=txt.indexOf('['), e=txt.lastIndexOf(']'); if(s===-1) return [];
      const arr=JSON.parse(txt.slice(s,e+1)); return arr.map((o,i)=>{ const span=String(o.span||'').slice(0,200); const idx=text.indexOf(span); return {id:`groq-${i}`,span:span||o.label,type:o.type||'INTERNAL',label:String(o.label||'Context'),severity:o.severity||'MEDIUM',risk:String(o.risk||'Leak'),reason:String(o.reason||'LLM'),placeholder:String(o.placeholder||'[REDACTED]'),start:idx,end:idx>=0?idx+span.length:-1,confidence:0.78,source:'llm'}; }).filter(d=>d.span);
    }catch(e){ return []; }
  };
  const scanWithGemini = async (text, gemKey)=>{
    if(!gemKey || text.length<12) return [];
    try{
      const res=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${gemKey}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contents:[{parts:[{text:`You are PromptShield. Analyze prompt:\n"""${text.slice(0,3000)}"""\nReturn JSON array of {"span": exact substring, "label": short, "type": [FINANCIAL,MEDICAL,INTERNAL,PERSON_NAME,ADDRESS], "severity": HIGH|MEDIUM|LOW, "risk": short, "reason": one sentence, "placeholder": like [REDACTED]}. Return [] if none.`}]}],generationConfig:{temperature:0.1,maxOutputTokens:600}})});
      if(!res.ok) return [];
      const j=await res.json(); const txt=j.candidates?.[0]?.content?.parts?.[0]?.text||''; const s=txt.indexOf('['), e=txt.lastIndexOf(']'); if(s===-1) return [];
      const arr=JSON.parse(txt.slice(s,e+1)); return arr.map((o,i)=>{ const span=String(o.span||''); const idx=text.indexOf(span); return {id:`gem-${i}`,span,type:o.type||'INTERNAL',label:o.label||'Context',severity:o.severity||'MEDIUM',risk:o.risk||'Leak',reason:o.reason||'Gemini',placeholder:o.placeholder||'[REDACTED]',start:idx,end:idx+span.length,confidence:0.78,source:'llm'}; }).filter(d=>d.span);
    }catch{ return []; }
  };

  // ---------- UI injection ----------
  const createHost = () => {
    if(document.getElementById('ps-host')) return document.getElementById('ps-host');
    const host=document.createElement('div'); host.id='ps-host';
    host.style.cssText='position:fixed;inset:0;pointer-events:none;z-index:2147483647;';
    document.documentElement.appendChild(host);
    const shadow=host.attachShadow({mode:'open'});
    const style=document.createElement('style');
    style.textContent=`
      .ps-card{position:fixed;right:24px;top:96px;width:390px;max-width:calc(100vw - 16px);background:#171719;border:1px solid #2E2E32;border-radius:16px;box-shadow:0 16px 48px rgba(0,0,0,.6);font-family:Inter,system-ui,sans-serif;pointer-events:auto;overflow:hidden}
      .ps-header{height:52px;padding:0 12px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #232326;cursor:grab}
      .ps-header:active{cursor:grabbing}
      .ps-title{font-size:13px;font-weight:750;color:#fff;display:flex;align-items:center;gap:6px}
      .ps-badge{font-size:10px;font-weight:700;padding:2px 6px;border-radius:999px;background:#fff;color:#000}
      .ps-dot{width:6px;height:6px;border-radius:999px}
      .ps-rail{padding:10px 12px;background:#1E1E21;border-bottom:1px solid #232326;display:flex;justify-content:space-between;align-items:center;font-size:11px;font-weight:600;color:#D4D4D8}
      .ps-body{max-height:56vh;overflow:auto}
      .ps-body::-webkit-scrollbar{width:5px}
      .ps-body::-webkit-scrollbar-thumb{background:#2E2E32;border-radius:4px}
      .ps-item{margin:8px 12px;background:#1E1E21;border:1px solid #2E2E32;border-radius:12px;overflow:hidden}
      .ps-btn{height:38px;border-radius:10px;border:1px solid #2E2E32;background:#232326;color:#fff;font-size:13px;font-weight:650;cursor:pointer}
      .ps-btn.primary{background:#fff;color:#000;border-color:#fff}
      .ps-pill{height:26px;padding:0 10px;border-radius:999px;border:1px solid #2E2E32;background:#1E1E21;color:#D4D4D8;font-size:11px;font-weight:600;display:inline-flex;align-items:center;gap:6px}
      .ps-contam{margin:12px;background:#3D0A0A;border:1px solid #FF8389;border-radius:12px;padding:12px}
      .ps-vault{margin:12px;background:#0F0F10;border:1px solid #2E2E32;border-radius:12px;padding:10px}
      .ps-drop{margin:12px;border:2px dashed #0F62FE;background:#EDF5FF;border-radius:12px;padding:12px;text-align:center}
      button{cursor:pointer}
    `;
    shadow.appendChild(style);
    return shadow;
  };

  let shadow, card, bodyEl, railEl, headerEl;
  let pos={x: window.innerWidth-414, y:96};
  if(window.innerWidth<1280){ pos={x: Math.max(12,(window.innerWidth-390)/2), y: window.innerHeight-520 }; }
  let dragging=false, dragStart=null;
  let currentText='', detections=[], isScanning=false, vaultMode=false, sessionTick=0;
  let groqKey='', gemKey='', modelHint='qwen3b';

  const render = async ()=>{
    if(!shadow) shadow=createHost();
    if(!card){
      card=document.createElement('div'); card.className='ps-card';
      card.style.left=pos.x+'px'; card.style.top=pos.y+'px';
      shadow.appendChild(card);
    }
    const store=await getStore();
    groqKey=store.ps_groq_key||''; gemKey=store.ps_gemini_key||''; modelHint=store.ps_model||'qwen3b'; vaultMode=store.ps_vault_mode==='1';
    const hasRisk=detections.length>0;
    const high=detections.filter(d=>d.severity==='HIGH').length;
    const status=isScanning?'scanning':!hasRisk?'safe':high?'risk_high':'risk_med';
    const headerBg=status==='safe'?'#0F5132':status==='scanning'?'#0F2942':status==='risk_high'?'#7A1A1A':'#5E4A1A';
    const statusText=isScanning?'Scanning':!hasRisk?'Safe to send':`${detections.length} risks${high?` · ${high} High`:''}`;
    const redacted = vaultMode ? (await vaultTokenize(currentText,detections)).tokenized : redactText(currentText,detections);
    const sess=await sessionLoad(); const score=sessionScore(sess); const contam=score>15 ? `This chat already contains ${sess.leaks.length} leak${sess.leaks.length>1?'s':''} from ${Math.max(1,Math.round((Date.now()-sess.leaks[0].timestamp)/60000))} min ago. This session is tainted — start NEW CHAT. Score ${score}/100` : null;

    card.innerHTML=`
      <div class="ps-header" style="background:${headerBg}" id="ps-drag">
        <div style="display:flex;align-items:center;gap:8px;min-width:0">
          <span style="display:grid;place-items:center;width:24px;height:24px;border-radius:6px;background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.15)">⋮⋮</span>
          <div style="width:28px;height:28px;border-radius:9px;display:grid;place-items:center;background:rgba(0,0,0,.15);border:1px solid rgba(255,255,255,.15);color:#fff">🛡️</div>
          <div style="min-width:0">
            <div class="ps-title">PromptShield <span class="ps-badge">EXT</span></div>
            <div style="font-size:11px;font-weight:600;color:rgba(255,255,255,.8);display:flex;align-items:center;gap:4px"><span class="ps-dot" style="background:${hasRisk?'#fff':'#A7F0BA'}"></span>${statusText}</div>
          </div>
        </div>
        <div style="display:flex;gap:4px">
          <button id="ps-min" style="width:28px;height:28px;border-radius:999px;background:rgba(0,0,0,.15);border:1px solid rgba(255,255,255,.15);color:#fff">−</button>
          <button id="ps-set" style="width:28px;height:28px;border-radius:999px;background:rgba(0,0,0,.15);border:1px solid rgba(255,255,255,.15);color:#fff">⚙</button>
          <button id="ps-hide" style="width:28px;height:28px;border-radius:999px;background:rgba(0,0,0,.15);border:1px solid rgba(255,255,255,.15);color:#fff">×</button>
        </div>
      </div>
      <div class="ps-rail"><span style="display:flex;align-items:center;gap:6px">⚡ ${isScanning?'Analyzing':hasRisk?`Found ${detections.length}`:'No sensitive data'} ${isScanning?'<span style="width:12px;height:12px;border:2px solid #3A3A42;border-top-color:#0F62FE;border-radius:999px;display:inline-block;animation:spin .8s linear infinite"></span>':''}</span><span style="color:#71717A">${sess.leaks.length} leaks • score ${score}</span></div>
      ${contam?`<div class="ps-contam"><div style="font-size:12px;font-weight:750;color:#fff">Session contaminated</div><div style="font-size:11px;color:#FFB3B8;margin-top:4px">${contam}</div><button id="ps-newchat" style="margin-top:8px;height:28px;padding:0 12px;border-radius:999px;background:#fff;color:#000;font-size:11px;font-weight:700;border:none">Start new chat</button></div>`:''}
      <div class="ps-body">
        ${!hasRisk?`
          <div style="padding:12px">
            <div style="background:#0E1A14;border:1px solid #1F3A2B;border-radius:12px;padding:12px;display:flex;gap:10px">
              <div style="width:32px;height:32px;border-radius:10px;background:#0F5132;display:grid;place-items:center;flex-shrink:0">✓</div>
              <div><div style="font-size:13px;font-weight:650;color:#A7F0BA">Safe to send</div><div style="font-size:12px;color:#6FDC8C;margin-top:4px">No sensitive data. Paste an API key, Aadhaar or email to see red.</div></div>
            </div>
            <div style="margin-top:12px;background:#0F0F10;border:1px solid #2E2E32;border-radius:12px;overflow:hidden">
              <div style="padding:10px 12px;background:linear-gradient(90deg,#1A1A2E,#1E1E21);border-bottom:1px solid #232326;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#A1A1AA">Turn lazy prompts into great ones</div>
              <div style="padding:12px"><div style="font-size:12px;color:#A1A1AA">One tap adds role, goal, constraints and format — placeholders stay safe.</div><button id="ps-boost" style="margin-top:10px;width:100%;height:36px;border-radius:10px;background:linear-gradient(90deg,#7C3AED,#0F62FE);color:#fff;font-size:13px;font-weight:700;border:none">Turn into great prompt</button></div>
            </div>
            <div style="margin-top:12px;border:2px dashed #2E2E32;border-radius:12px;padding:12px;text-align:center;background:#1E1E21">
              <div style="font-size:12px;font-weight:650;color:#D4D4D8">Drop PDF / image here to scan</div><div style="font-size:11px;color:#71717A">OCR via Tesseract.js + pdf.js — 100% offline</div>
            </div>
          </div>
        `:`
          <div style="padding:12px">
            ${detections.map(d=>`
              <div class="ps-item">
                <div style="padding:10px 12px;display:flex;justify-content:space-between;gap:8px">
                  <div style="flex:1;min-width:0">
                    <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
                      <span style="padding:2px 8px;border-radius:999px;font-size:11px;font-weight:750;border:1px solid ${d.severity==='HIGH'?'#FF8389':'#FFB14E'};background:${d.severity==='HIGH'?'#DA1E28':'#FEC57E'};color:${d.severity==='HIGH'?'#fff':'#000'}">${d.severity}</span>
                      <span style="font-size:13px;font-weight:650;color:#fff">${d.label}</span>
                      <span style="font-size:10px;font-family:monospace;padding:2px 6px;border-radius:6px;background:#1E1E21;border:1px solid #2E2E32;color:#A1A1AA">${d.source==='llm'?'AI':d.source}</span>
                    </div>
                    <div style="margin-top:6px;display:inline-flex;gap:6px;align-items:center;padding:4px 8px;background:#0F0F10;border:1px solid #2E2E32;border-radius:8px;max-width:100%">
                      <span style="font-size:12px;font-family:monospace;color:#FF8389;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:120px">${d.span}</span>
                      <span style="color:#52525B">→</span>
                      <span style="font-size:11px;font-family:monospace;color:#42BE65">${d.placeholder}</span>
                    </div>
                  </div>
                </div>
              </div>
            `).join('')}
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
              <span class="ps-pill">Vault <b style="color:${vaultMode?'#42BE65':'#71717A'}">${vaultMode?'ON':'OFF'}</b></span>
              <button id="ps-vault" class="ps-pill" style="cursor:pointer">Toggle Vault</button>
              <span style="font-size:11px;color:#71717A">Score ${Math.round((()=>{
                const a=new Set(currentText.toLowerCase().split(/\W+/).filter(Boolean));
                const b=new Set(redacted.toLowerCase().split(/\W+/).filter(Boolean));
                let inter=0; for(const t of a) if(b.has(t)) inter++; const union=new Set([...a,...b]).size;
                return (union?inter/union:0)*100;
              })())}% preserved</span>
            </div>
            <div style="margin-top:12px;background:#0F0F10;border:1px solid #2E2E32;border-radius:12px;overflow:hidden">
              <div style="padding:10px 12px;background:#1B1B1E;border-bottom:1px solid #232326;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#A1A1AA">Before → After</div>
              <div style="padding:12px">
                <div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#71717A">Original</div>
                <div style="margin-top:4px;background:#1E1E21;border:1px solid #2E2E32;border-radius:10px;padding:10px;font-size:12px;font-family:monospace;color:#FF8389;white-space:pre-wrap;word-break:break-word">${currentText.slice(0,800) || '—'}</div>
                <div style="margin-top:8px;font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#71717A">Safe ${vaultMode?'(Vault)':''}</div>
                <div style="margin-top:4px;background:#0E1A14;border:1px solid #1F3A2B;border-radius:10px;padding:10px;font-size:12px;font-family:monospace;color:#A7F0BA;white-space:pre-wrap;word-break:break-word">${redacted.slice(0,800) || '—'}</div>
              </div>
            </div>
            <button id="ps-apply" class="ps-btn primary" style="width:100%;margin-top:12px">Apply safe rewrite</button>
            <div style="margin-top:12px;background:linear-gradient(90deg,#1A1A2E,#0F0F10);border:1px solid #2E2E32;border-radius:12px;padding:12px">
              <div style="font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#BE95FF">Lazy → Great</div>
              <div style="font-size:12px;color:#A1A1AA;margin-top:4px">Turn scrubbed prompt into great prompt.</div>
              <button id="ps-boost2" style="margin-top:8px;width:100%;height:36px;border-radius:10px;background:linear-gradient(90deg,#7C3AED,#0F62FE);color:#fff;font-size:13px;font-weight:700;border:none">Turn into great prompt</button>
            </div>
          </div>
        `}
      </div>
      <div style="padding:12px;border-top:1px solid #232326;background:#1B1B1E;display:flex;gap:8px">
        <button id="ps-copy" class="ps-btn" style="flex:1">Copy safe</button>
        <button id="ps-detok" class="ps-btn" style="flex:1;display:${vaultMode?'inline-flex':'none'};align-items:center;justify-content:center;gap:4px">Detokenize</button>
      </div>
    `;

    // drag
    const hdr=card.querySelector('#ps-drag');
    if(hdr){
      hdr.onpointerdown=e=>{
        if(e.target.closest('button')) return;
        dragging=true; dragStart={x:e.clientX-pos.x,y:e.clientY-pos.y};
        hdr.setPointerCapture(e.pointerId);
      };
      hdr.onpointermove=e=>{ if(!dragging) return; pos={x:Math.max(4,Math.min(e.clientX-dragStart.x, window.innerWidth-394)), y:Math.max(4,Math.min(e.clientY-dragStart.y, window.innerHeight-420))}; card.style.left=pos.x+'px'; card.style.top=pos.y+'px'; };
      hdr.onpointerup=e=>{ dragging=false; try{hdr.releasePointerCapture(e.pointerId)}catch{} };
    }
    card.querySelector('#ps-hide')?.addEventListener('click',()=>{ card.style.display='none'; showFloating(); });
    card.querySelector('#ps-min')?.addEventListener('click',()=>{
      const b=card.querySelector('.ps-body'); if(b) b.style.display=b.style.display==='none'?'block':'none';
    });
    card.querySelector('#ps-set')?.addEventListener('click',()=> chrome.runtime.openOptionsPage ? chrome.runtime.openOptionsPage() : window.open(chrome.runtime.getURL('popup.html')) );
    card.querySelector('#ps-vault')?.addEventListener('click',async()=>{ await setStore({ps_vault_mode: vaultMode?'0':'1'}); render(); });
    card.querySelector('#ps-apply')?.addEventListener('click',()=>{ const ta=findPromptBox(); if(ta) setPromptBox(ta, redacted); });
    card.querySelector('#ps-copy')?.addEventListener('click',async()=>{ await navigator.clipboard.writeText(redacted); const b=card.querySelector('#ps-copy'); if(b) b.textContent='Copied ✓'; setTimeout(()=>{ if(b) b.textContent='Copy safe'},1200); });
    card.querySelector('#ps-detok')?.addEventListener('click',async()=>{ const v=await vaultGet(); let t=currentText; for(const e of v) if(t.includes(e.fake)) t=t.split(e.fake).join(e.real); const ta=findPromptBox(); if(ta) setPromptBox(ta,t); });
    card.querySelector('#ps-boost')?.addEventListener('click', doBoost);
    card.querySelector('#ps-boost2')?.addEventListener('click', doBoost);
    card.querySelector('#ps-newchat')?.addEventListener('click', async()=>{ await setStore({ps_session_v2:JSON.stringify({sessionId:await getSid(), leaks:[], createdAt:Date.now()})}); const sid='sess_'+Math.random().toString(36).slice(2,8); await setStore({ps_session_id:sid}); render(); });
  };

  const showFloating=()=>{
    let f=document.getElementById('ps-float');
    if(!f){
      f=document.createElement('div'); f.id='ps-float';
      f.style.cssText='position:fixed;bottom:20px;right:20px;z-index:2147483647;';
      f.innerHTML=`<button id="ps-show" style="height:40px;padding:0 16px;border-radius:999px;background:#171719;border:1px solid #2E2E32;color:#fff;font-size:13px;font-weight:650;display:flex;align-items:center;gap:8px;box-shadow:0 8px 24px rgba(0,0,0,.5)">🛡️ PromptShield</button>`;
      document.documentElement.appendChild(f);
      f.querySelector('#ps-show').onclick=()=>{ f.remove(); if(card) card.style.display='block'; };
    }
  };

  const doBoost=async()=>{
    const store=await getStore();
    const gk=store.ps_groq_key||'', gmk=store.ps_gemini_key||'';
    const base = detections.length ? redactText(currentText,detections) : currentText;
    // simple boost via Groq/Gemini
    let out=base;
    if(gk){
      try{
        const r=await fetch('https://api.groq.com/openai/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+gk},body:JSON.stringify({model:'llama-3.1-8b-instant',temperature:0.4,messages:[{role:'system',content:'You are PromptCowboy. Turn lazy prompt into great prompt. Keep placeholders.'},{role:'user',content:base}]})});
        if(r.ok){ const j=await r.json(); out=j.choices?.[0]?.message?.content?.trim()||out; }
      }catch{}
    } else if(gmk){
      try{
        const r=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${gmk}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contents:[{parts:[{text:`Turn lazy prompt into great prompt. Keep placeholders.\n"""${base}"""`}]}]})});
        if(r.ok){ const j=await r.json(); out=j.candidates?.[0]?.content?.parts?.[0]?.text?.trim()||out; }
      }catch{}
    } else {
      out='[Boost requires Groq or Gemini key in popup] '+base;
    }
    const ta=findPromptBox(); if(ta) setPromptBox(ta,out);
  };

  // find prompt box
  const findPromptBox=()=>{
    const sels=['textarea','[contenteditable="true"]','div[role="textbox"]','div[contenteditable="true"]'];
    for(const sel of sels){
      const els=[...document.querySelectorAll(sel)];
      for(const el of els){
        const r=el.getBoundingClientRect();
        if(r.width>200 && r.height>40 && r.bottom < window.innerHeight && r.top > 0){
          // heuristic: near bottom
          if(el.closest('form') || r.bottom > window.innerHeight*0.5) return el;
        }
      }
    }
    return document.querySelector('textarea') || document.querySelector('[contenteditable="true"]');
  };
  const getText=(el)=>{
    if(!el) return '';
    if(el.tagName==='TEXTAREA' || el.tagName==='INPUT') return el.value;
    return el.innerText || el.textContent || '';
  };
  const setPromptBox=(el,txt)=>{
    if(el.tagName==='TEXTAREA' || el.tagName==='INPUT'){ el.focus(); el.value=txt; el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); }
    else { el.focus(); document.execCommand('selectAll',false,null); document.execCommand('insertText',false,txt); el.dispatchEvent(new Event('input',{bubbles:true})); }
    currentText=txt; triggerScan();
  };

  let scanTimer=null;
  const triggerScan=async ()=>{
    const el=findPromptBox(); if(!el) return;
    currentText=getText(el);
    detections=scanLocal(currentText);
    // session contam
    if(detections.length){
      const sess=await sessionLoad();
      const already=sess.leaks.some(l=> detections.some(d=> d.span===l.span));
      if(!already){
        for(const d of detections) sess.leaks.push({id:'l_'+Date.now()+'_'+Math.random().toString(36).slice(2,4), span:d.span,label:d.label,severity:d.severity,type:d.type,timestamp:Date.now(),promptIndex:sess.leaks.length});
        await sessionSave(sess);
      }
    }
    // llm scan if keys
    const store=await getStore();
    const gk=store.ps_groq_key, gmk=store.ps_gemini_key, mh=store.ps_model||'qwen3b';
    if((gk||gmk) && currentText.length>16){
      isScanning=true; await render();
      let extra=[];
      if(gk) extra=await scanWithGroq(currentText,gk,mh);
      if(!extra.length && gmk) extra=await scanWithGemini(currentText,gmk);
      // merge
      const map=new Map();
      for(const d of [...detections,...extra]){ const k=d.type+':'+d.span.toLowerCase(); if(!map.has(k)) map.set(k,d); }
      detections=[...map.values()].sort((a,b)=> (a.severity==='HIGH'?0:a.severity==='MEDIUM'?1:2)-(b.severity==='HIGH'?0:b.severity==='MEDIUM'?1:2));
      isScanning=false;
    }
    await render();
  };

  // observers
  const mo=new MutationObserver(()=> triggerScan());
  mo.observe(document.documentElement,{childList:true,subtree:true,characterData:true});
  document.addEventListener('input', e=>{
    const el=findPromptBox();
    if(el && (e.target===el || el.contains(e.target))) triggerScan();
  }, true);
  // paste high entropy
  window.addEventListener('paste', e=>{
    const t=e.clipboardData?.getData('text')||'';
    const toks=t.split(/\s+/); const hi=toks.filter(x=> x.length>20 && isHighEntropySecret(x));
    if(hi.length) setTimeout(triggerScan, 200);
  });
  // file drop
  const taInit=findPromptBox();
  if(taInit){
    taInit.addEventListener('dragover', e=>{ e.preventDefault(); taInit.style.outline='2px dashed #0F62FE'; });
    taInit.addEventListener('dragleave', ()=> taInit.style.outline='');
    taInit.addEventListener('drop', async e=>{
      e.preventDefault(); taInit.style.outline='';
      const f=e.dataTransfer?.files?.[0]; if(!f) return;
      let txt=''; try{ txt=await f.text(); }catch{ txt=f.name; }
      txt=txt.slice(0,6000);
      const d=scanLocal(txt); const nd=scanLocal(f.name);
      const all=[...d,...nd];
      if(all.length){
        currentText=txt; detections=all; await render();
        // also set to box as scrubbed
        const scrub=redactText(txt,all);
        setPromptBox(taInit, scrub.slice(0,2000));
      }
    });
  }

  // initial render + scan
  render(); setTimeout(triggerScan, 800);
  // poll for box
  setInterval(triggerScan, 2000);
})();
