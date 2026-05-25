/* ── State ──────────────────────────────────────────────────────────────────── */
let selectedDump        = null;
let selectedBinaryModel = null;
let selectedFamilyModel = null;
let currentScanId       = null;

/* Dead-feature keys (reserved / always 0) */
const DEAD_KEYS = new Set([
  'deleted_exe_count',
  'hooked_syscall_count',
  'foreign_conn_count',
  'high_port_count',
  'netfilter_hook_count',
]);

/* ── Helpers ────────────────────────────────────────────────────────────────── */
function formatBytes(b) {
  if (b < 1024)       return b + ' B';
  if (b < 1024 ** 2)  return (b / 1024).toFixed(1) + ' KB';
  if (b < 1024 ** 3)  return (b / 1024 ** 2).toFixed(1) + ' MB';
  return (b / 1024 ** 3).toFixed(2) + ' GB';
}

function formatDate(iso) {
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

function featureLabel(key) {
  const MAP = {
    hidden_proc_count:      'Hidden Processes',
    masqueraded_proc_count: 'Masqueraded Processes',
    deleted_exe_count:      'Deleted Executables',
    hooked_syscall_count:   'Hooked Syscalls',
    hidden_module_count:    'Hidden Modules',
    netfilter_hook_count:   'Netfilter Hooks',
    rwx_region_count:       'RWX Regions',
    total_sockets:          'Total Sockets',
    raw_socket_count:       'Raw Sockets',
    foreign_conn_count:     'Foreign Connections',
    high_port_count:        'High Port Count',
    unknown_lib_count:      'Unknown Libraries',
  };
  return MAP[key] || key;
}

function showError(msg) {
  const el = document.getElementById('error-block');
  el.textContent = '[ ERR ] ' + msg;
  el.classList.add('visible');
}
function hideError() {
  document.getElementById('error-block').classList.remove('visible');
}
function clearResults() {
  document.getElementById('results').classList.remove('visible');
  hideError();
}

/* ── Navigation ─────────────────────────────────────────────────────────────── */
function showPage(name) {
  document.querySelectorAll('.page').forEach(p =>
    p.classList.toggle('active', p.dataset.page === name)
  );
  document.querySelectorAll('.nav-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.page === name)
  );
  if (name === 'history') loadHistory();
}

/* ── Drag-and-drop helpers ───────────────────────────────────────────────────── */
function cardDragOver(e, cardId) {
  e.preventDefault();
  document.getElementById(cardId).classList.add('dragover');
}
function cardDragLeave(cardId) {
  document.getElementById(cardId).classList.remove('dragover');
}
function cardDrop(e, type) {
  e.preventDefault();
  const ids = { dump: 'dump-card', binary: 'binary-card', family: 'family-card' };
  document.getElementById(ids[type]).classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (!file) return;
  if (type === 'dump')   setDump(file);
  if (type === 'binary') setBinaryModel(file);
  if (type === 'family') setFamilyModel(file);
}

/* ── Dump card ──────────────────────────────────────────────────────────────── */
function setDump(file) {
  selectedDump = file;
  document.getElementById('dump-card').classList.add('has-file');
  document.getElementById('dump-strip-name').textContent = file.name;
  document.getElementById('dump-strip-size').textContent = formatBytes(file.size);
  document.getElementById('dump-strip').classList.add('visible');
  document.getElementById('analyze-btn').disabled = false;
  clearResults();
}
function removeDump(e) {
  e.stopPropagation();
  selectedDump = null;
  document.getElementById('file-input').value = '';
  document.getElementById('dump-card').classList.remove('has-file');
  document.getElementById('dump-strip').classList.remove('visible');
  document.getElementById('analyze-btn').disabled = true;
  clearResults();
}

/* ── Binary model card ─────────────────────────────────────────────────────── */
function setBinaryModel(file) {
  selectedBinaryModel = file;
  document.getElementById('binary-card').classList.add('has-file');
  document.getElementById('binary-strip-name').textContent = file.name;
  document.getElementById('binary-strip-size').textContent = formatBytes(file.size);
  document.getElementById('binary-strip').classList.add('visible');
}
function removeBinaryModel(e) {
  e.stopPropagation();
  selectedBinaryModel = null;
  document.getElementById('binary-input').value = '';
  document.getElementById('binary-card').classList.remove('has-file');
  document.getElementById('binary-strip').classList.remove('visible');
}

/* ── Family model card ─────────────────────────────────────────────────────── */
function setFamilyModel(file) {
  selectedFamilyModel = file;
  document.getElementById('family-card').classList.add('has-file');
  document.getElementById('family-strip-name').textContent = file.name;
  document.getElementById('family-strip-size').textContent = formatBytes(file.size);
  document.getElementById('family-strip').classList.add('visible');
}
function removeFamilyModel(e) {
  e.stopPropagation();
  selectedFamilyModel = null;
  document.getElementById('family-input').value = '';
  document.getElementById('family-card').classList.remove('has-file');
  document.getElementById('family-strip').classList.remove('visible');
}

/* ── Analysis ───────────────────────────────────────────────────────────────── */
async function runAnalysis() {
  if (!selectedDump) return;

  currentScanId = null;
  const btn = document.getElementById('analyze-btn');
  btn.disabled = true;
  btn.classList.add('scanning');
  document.getElementById('btn-label').textContent = 'SCANNING…';
  clearResults();

  const wrap  = document.getElementById('progress-wrap');
  const bar   = document.getElementById('progress-bar');
  const pct   = document.getElementById('progress-pct');
  const stage = document.getElementById('progress-stage');
  const steps = document.getElementById('progress-steps');
  bar.style.width   = '0%';
  pct.textContent   = '0%';
  stage.textContent = 'INITIALIZING';
  steps.innerHTML   = '';
  wrap.classList.add('visible');

  const formData = new FormData();
  formData.append('dump', selectedDump);
  if (selectedBinaryModel) formData.append('binary_model_file', selectedBinaryModel);
  if (selectedFamilyModel) formData.append('family_model_file', selectedFamilyModel);

  const stepEls = {};

  try {
    const resp = await fetch('/analyze', { method: 'POST', body: formData });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: 'Unknown error' }));
      showError(err.detail || 'Analysis failed.');
      return;
    }

    const reader  = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const messages = buf.split('\n\n');
      buf = messages.pop();

      for (const msg of messages) {
        const line = msg.trim();
        if (!line.startsWith('data:')) continue;
        let payload;
        try { payload = JSON.parse(line.slice(5).trim()); }
        catch { continue; }

        if (payload.type === 'error') { showError(payload.detail); break; }

        if (payload.type === 'progress') {
          const { step, total, label, cached } = payload;
          const pctVal = Math.round((step / total) * 100);
          bar.style.width   = pctVal + '%';
          pct.textContent   = pctVal + '%';
          stage.textContent = label.toUpperCase();

          Object.values(stepEls).forEach(el => {
            if (el.classList.contains('active')) {
              el.classList.replace('active', 'done');
              const icon = el.querySelector('.step-icon');
              icon.classList.remove('spin');
              icon.textContent = '✓';
            }
          });

          const el = document.createElement('div');
          el.className = 'progress-step active';
          el.innerHTML =
            `<div class="step-icon spin"></div>` +
            `<span>${label}</span>` +
            (cached ? `<span class="cached-mini">CACHED</span>` : '');
          steps.appendChild(el);
          requestAnimationFrame(() => el.classList.add('visible'));
          stepEls[label] = el;
        }

        if (payload.type === 'result') {
          bar.style.width   = '100%';
          pct.textContent   = '100%';
          stage.textContent = 'COMPLETE';
          Object.values(stepEls).forEach(el => {
            el.classList.replace('active', 'done');
            const icon = el.querySelector('.step-icon');
            icon.classList.remove('spin');
            icon.textContent = '✓';
          });
          setTimeout(() => {
            wrap.classList.remove('visible');
            renderResults(payload);
          }, 600);
        }
      }
    }
  } catch (err) {
    showError('Network error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.classList.remove('scanning');
    document.getElementById('btn-label').textContent = 'SCAN MEMORY DUMP';
  }
}

/* ── Render results ─────────────────────────────────────────────────────────── */
function renderResults(data) {
  currentScanId = data.scan_id ?? null;

  /* Verdict header */
  const verdictEl = document.getElementById('results-verdict');
  if (data.any_detected) {
    verdictEl.textContent = '!  THREATS DETECTED';
    verdictEl.className   = 'results-verdict threat';
  } else {
    verdictEl.textContent = 'v  NO THREATS FOUND';
    verdictEl.className   = 'results-verdict clean';
  }
  document.getElementById('results-filename').textContent = data.filename || '';

  /* SHA row */
  const shaEl = document.getElementById('results-sha');
  shaEl.innerHTML =
    `<span class="sha-hash">${data.sha256 || ''}</span>` +
    (data.cached ? `<span class="cached-badge visible">CACHED</span>` : '');

  /* Stage 1 block */
  const s1 = data.stage1 || {};
  const s1Infected = s1.infected ? 'INFECTED' : 'CLEAN';
  const s1Class    = s1.infected ? 'infected' : 'clean';
  const s1Pct      = typeof s1.confidence === 'number'
    ? Math.round(s1.confidence) : 0;
  document.getElementById('stage1-block').innerHTML = `
    <div class="stage1-label">STAGE 1 — BINARY TRIAGE</div>
    <div class="stage1-status ${s1Class}">${s1Infected}</div>
    <div class="stage1-bar-wrap">
      <div class="stage1-bar ${s1Class}" style="width:${s1Pct}%"></div>
    </div>
    <div class="stage1-pct">${s1Pct}%</div>`;

  /* Threat table — sort: detected first, then confidence desc */
  const threats = [...(data.threats || [])].sort((a, b) => {
    if (b.detected !== a.detected) return b.detected - a.detected;
    return (b.confidence || 0) - (a.confidence || 0);
  });
  const tbody = document.getElementById('threat-tbody');
  tbody.innerHTML = '';
  for (const t of threats) {
    const confPct = Math.round((t.confidence || 0) * 100);
    const row = document.createElement('tr');
    row.className = t.detected ? 'row-detected' : '';
    row.innerHTML =
      `<td class="col-family">${t.family}</td>` +
      `<td class="col-status">` +
        `<span class="status-badge ${t.detected ? 'detected' : 'clear'}">` +
          `${t.detected ? 'DETECTED' : 'CLEAR'}` +
        `</span>` +
      `</td>` +
      `<td class="col-conf">` +
        `<div class="conf-bar-wrap">` +
          `<div class="conf-bar ${t.detected ? 'detected' : ''}" style="width:${confPct}%"></div>` +
        `</div>` +
        `<span class="conf-pct">${confPct}%</span>` +
      `</td>`;
    tbody.appendChild(row);
  }

  /* Save strip */
  const scanIdEl = document.getElementById('save-scan-id');
  if (scanIdEl) scanIdEl.textContent = currentScanId != null ? `#${currentScanId}` : '—';
  const labelInput = document.getElementById('label-input');
  if (labelInput) labelInput.value = '';

  /* Features table */
  const ftable = document.getElementById('features-table');
  ftable.innerHTML = '';
  for (const [key, val] of Object.entries(data.features || {})) {
    const dead = DEAD_KEYS.has(key);
    const displayVal = val === -1 ? 'N/A' : val;
    ftable.innerHTML +=
      `<tr>` +
      `<td>${featureLabel(key)}${dead ? ' <span class="reserved">(reserved)</span>' : ''}</td>` +
      `<td>${displayVal}</td>` +
      `</tr>`;
  }

  document.getElementById('results').classList.add('visible');
}

/* ── Save label ─────────────────────────────────────────────────────────────── */
async function saveLabel() {
  if (currentScanId == null) return;
  const label = document.getElementById('label-input').value.trim();
  const btn   = document.getElementById('save-btn');
  try {
    const fd = new FormData();
    fd.append('label', label);
    await fetch(`/scans/${currentScanId}/label`, { method: 'PATCH', body: fd });
    const orig = btn.textContent;
    btn.textContent = 'SAVED';
    setTimeout(() => { btn.textContent = orig; }, 1500);
  } catch { btn.textContent = 'ERR'; }
}

/* ── Download result ────────────────────────────────────────────────────────── */
async function downloadResult() {
  if (currentScanId == null) return;
  try {
    const resp = await fetch(`/scans/${currentScanId}/export`);
    const data = await resp.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `memsnap-scan-${currentScanId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) { showError('Export failed: ' + e.message); }
}

/* ── History ────────────────────────────────────────────────────────────────── */
async function loadHistory() {
  const list = document.getElementById('history-list');
  list.innerHTML = '<div class="history-loading">loading…</div>';
  try {
    const resp  = await fetch('/scans?limit=50');
    const scans = await resp.json();
    if (!scans.length) {
      list.innerHTML = '<div class="history-empty">No scans yet.</div>';
      return;
    }
    list.innerHTML = '';
    for (const s of scans) {
      const anyDetected = s.verdicts?.some(v => v.detected);
      const topConf     = s.verdicts?.reduce((m, v) => Math.max(m, v.confidence || 0), 0) || 0;
      const confPct     = Math.round(topConf * 100);
      const card        = document.createElement('div');
      card.className    = 'history-card';
      card.innerHTML =
        `<div class="history-header">` +
          `<span class="history-id">#${s.id}</span>` +
          `<span class="history-name">${s.dump_name || 'unknown'}</span>` +
          `${s.cached ? '<span class="cached-pill">CACHED</span>' : ''}` +
          `<span class="history-badge ${anyDetected ? 'infected' : 'clean'}">` +
            `${anyDetected ? 'INFECTED' : 'CLEAN'}` +
          `</span>` +
        `</div>` +
        `<div class="history-meta">` +
          `<span>${formatDate(s.created_at)}</span>` +
          `<span>${s.size_bytes ? formatBytes(s.size_bytes) : '—'}</span>` +
          `<span>conf ${confPct}%</span>` +
          `${s.label ? `<span class="history-label">${s.label}</span>` : ''}` +
        `</div>` +
        `<button class="history-view" onclick="loadScan(${s.id})">VIEW</button>`;
      list.appendChild(card);
    }
  } catch (e) {
    list.innerHTML = `<div class="history-empty">Failed to load history: ${e.message}</div>`;
  }
}

async function loadScan(id) {
  try {
    const resp = await fetch(`/scans/${id}/export`);
    const data = await resp.json();
    showPage('scan');
    renderResults({ ...data, type: 'result' });
  } catch (e) { showError('Could not load scan: ' + e.message); }
}

/* ── Boot ───────────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  /* File inputs */
  const fileInput = document.getElementById('file-input');
  if (fileInput) fileInput.addEventListener('change', () => {
    if (fileInput.files?.[0]) setDump(fileInput.files[0]);
  });
  const binaryInput = document.getElementById('binary-input');
  if (binaryInput) binaryInput.addEventListener('change', () => {
    if (binaryInput.files?.[0]) setBinaryModel(binaryInput.files[0]);
  });
  const familyInput = document.getElementById('family-input');
  if (familyInput) familyInput.addEventListener('change', () => {
    if (familyInput.files?.[0]) setFamilyModel(familyInput.files[0]);
  });
});
