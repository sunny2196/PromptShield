const $ = id => document.getElementById(id);
const els = { model: $('model'), groq: $('groq'), gemini: $('gemini'), vault: $('vault'), status: $('status') };

async function load() {
  const data = await chrome.storage.local.get(['ps_model','ps_groq_key','ps_gemini_key','ps_vault_mode']);
  if (data.ps_model) els.model.value = data.ps_model;
  if (data.ps_groq_key) els.groq.value = data.ps_groq_key;
  if (data.ps_gemini_key) els.gemini.value = data.ps_gemini_key;
  els.vault.checked = data.ps_vault_mode === '1';
  // also try localStorage from simulation (if user set there)
  try {
    const lsGroq = localStorage.getItem('ps_groq_key');
    const lsGem = localStorage.getItem('ps_gemini_key');
    if (!els.groq.value && lsGroq) els.groq.value = lsGroq;
    if (!els.gemini.value && lsGem) els.gemini.value = lsGem;
  } catch {}
}

$('save').onclick = async () => {
  await chrome.storage.local.set({
    ps_model: els.model.value,
    ps_groq_key: els.groq.value.trim(),
    ps_gemini_key: els.gemini.value.trim(),
    ps_vault_mode: els.vault.checked ? '1' : '0'
  });
  // also mirror to localStorage for simulation sync
  try {
    localStorage.setItem('ps_model', els.model.value);
    localStorage.setItem('ps_groq_key', els.groq.value.trim());
    localStorage.setItem('ps_gemini_key', els.gemini.value.trim());
  } catch {}
  els.status.textContent = 'Saved ✓ — refresh the AI tab to apply';
  els.status.style.color = '#42BE65';
  setTimeout(()=> els.status.textContent='', 2000);
};

$('clear').onclick = async () => {
  await chrome.storage.local.remove(['ps_session_v2','ps_session_id','ps_vault_v2']);
  try { localStorage.removeItem('ps_session_v2'); localStorage.removeItem('ps_session_id'); localStorage.removeItem('ps_vault_v2'); } catch{}
  els.status.textContent = 'Session & vault cleared';
  els.status.style.color = '#A1A1AA';
  setTimeout(()=> els.status.textContent='', 1500);
};

load();
