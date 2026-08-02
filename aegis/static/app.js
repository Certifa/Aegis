// Aegis Console UI Interactive Controller

state = {
  logEntries: [],
  verifyResult: { ok: true, count: 0, broken_at: null, why: null },
  activeOutcomeFilter: 'ALL',
  searchQuery: '',
  contractVersion: '1.0.0',
};

document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

async function initApp() {
  setupEventListeners();
  await loadContractVersion();
  await refreshAll();
}

function setupEventListeners() {
  // Action Buttons
  document.getElementById('btnVerify').addEventListener('click', async () => {
    await verifyChain();
  });

  document.getElementById('btnRefresh').addEventListener('click', async () => {
    await refreshAll();
  });

  document.getElementById('btnBenign').addEventListener('click', async () => {
    await runDemo('/demo/benign');
  });

  document.getElementById('btnInjected').addEventListener('click', async () => {
    await runDemo('/demo/injected');
  });

  document.getElementById('btnInjectTamper').addEventListener('click', async () => {
    await executeTamper();
  });

  // Filter Pills
  document.querySelectorAll('.filter-pills .pill').forEach(pill => {
    pill.addEventListener('click', (e) => {
      document.querySelectorAll('.filter-pills .pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      state.activeOutcomeFilter = pill.getAttribute('data-filter-outcome');
      renderLogStream();
    });
  });

  // Search input
  document.getElementById('searchInput').addEventListener('input', (e) => {
    state.searchQuery = e.target.value.toLowerCase().trim();
    renderLogStream();
  });

  // Custom Act Modal
  const modal = document.getElementById('actModal');
  document.getElementById('btnCustomAct').addEventListener('click', () => {
    modal.classList.remove('hidden');
  });
  document.getElementById('btnCloseModal').addEventListener('click', () => {
    modal.classList.add('hidden');
  });
  document.getElementById('btnCancelAct').addEventListener('click', () => {
    modal.classList.add('hidden');
  });

  document.getElementById('actForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await submitCustomAction();
    modal.classList.add('hidden');
  });

  // Update act tool args template on change
  document.getElementById('actTool').addEventListener('change', (e) => {
    const tool = e.target.value;
    const argsInput = document.getElementById('actArgsJson');
    if (tool === 'send_email') {
      argsInput.value = JSON.stringify({ to: "bob@corp", subject: "Q3 Report", body: "Attached." }, null, 2);
    } else if (tool === 'read_file') {
      argsInput.value = JSON.stringify({ path: "/data/reports/q3.pdf" }, null, 2);
    } else if (tool === 'http_request') {
      argsInput.value = JSON.stringify({ url: "https://internal.corp/api", method: "GET" }, null, 2);
    } else if (tool === 'make_payment') {
      argsInput.value = JSON.stringify({ amount_eur: 45, iban: "DE89370400440532013000", memo: "Invoice #102" }, null, 2);
    }
  });
}

async function loadContractVersion() {
  try {
    const res = await fetch('/contract');
    if (res.ok) {
      const data = await res.json();
      state.contractVersion = data.version || '1.0.0';
      document.getElementById('contractVersion').textContent = `v${state.contractVersion}`;
    }
  } catch (err) {
    console.warn('Failed to load contract version:', err);
  }
}

async function refreshAll() {
  await fetchLogEntries();
  await verifyChain();
}

async function fetchLogEntries() {
  try {
    const res = await fetch('/log');
    if (res.ok) {
      state.logEntries = await res.json();
      updateMetrics();
      populateTamperSelect();
      renderLogStream();
    }
  } catch (err) {
    console.error('Error fetching logs:', err);
  }
}

async function verifyChain() {
  const btn = document.getElementById('btnVerify');
  btn.disabled = true;
  btn.style.opacity = '0.7';

  try {
    const res = await fetch('/log/verify');
    if (res.ok) {
      state.verifyResult = await res.json();
      renderIntegrityBanner();
      renderLogStream();
    }
  } catch (err) {
    console.error('Error verifying chain:', err);
  } finally {
    btn.disabled = false;
    btn.style.opacity = '1';
  }
}

async function runDemo(endpoint) {
  try {
    const res = await fetch(endpoint, { method: 'POST' });
    if (res.ok) {
      await refreshAll();
    } else {
      alert(`Demo execution failed with status ${res.status}`);
    }
  } catch (err) {
    alert(`Failed to run demo: ${err.message}`);
  }
}

async function submitCustomAction() {
  const principal = document.getElementById('actPrincipal').value;
  const agent = document.getElementById('actAgent').value;
  const tool = document.getElementById('actTool').value;
  let args = {};

  try {
    args = JSON.parse(document.getElementById('actArgsJson').value);
  } catch (e) {
    alert('Invalid JSON in arguments field!');
    return;
  }

  try {
    const res = await fetch('/act', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        request_id: crypto.randomUUID(),
        principal,
        agent,
        tool,
        args,
        ts: new Date().toISOString(),
      }),
    });

    if (res.ok) {
      await refreshAll();
    } else {
      const errData = await res.json();
      alert(`Action error: ${JSON.stringify(errData.detail || errData)}`);
    }
  } catch (err) {
    alert(`Failed to submit action: ${err.message}`);
  }
}

async function executeTamper() {
  const seqVal = document.getElementById('tamperSeqSelect').value;
  const modeVal = document.getElementById('tamperModeSelect').value;

  if (seqVal === '') {
    alert('Please select a target log sequence entry first!');
    return;
  }

  try {
    const res = await fetch('/debug/tamper', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        seq: parseInt(seqVal, 10),
        mode: modeVal,
      }),
    });

    if (res.ok) {
      await refreshAll();
    } else if (res.status === 404) {
      alert('Tampering disabled: AEGIS_DEMO_MODE=1 environment variable is not enabled.');
    } else {
      alert(`Tamper call failed with status ${res.status}`);
    }
  } catch (err) {
    alert(`Failed to tamper log: ${err.message}`);
  }
}

function updateMetrics() {
  const total = state.logEntries.length;
  let allowCount = 0;
  let stepUpCount = 0;
  let denyCount = 0;

  state.logEntries.forEach(entry => {
    const outcome = entry.decision.outcome;
    if (outcome === 'ALLOW') allowCount++;
    else if (outcome === 'STEP_UP') stepUpCount++;
    else if (outcome === 'DENY') denyCount++;
  });

  document.getElementById('metricTotal').textContent = total;
  document.getElementById('metricAllow').textContent = allowCount;
  document.getElementById('metricStepUp').textContent = stepUpCount;
  document.getElementById('metricDeny').textContent = denyCount;

  document.getElementById('countAll').textContent = total;
  document.getElementById('countAllow').textContent = allowCount;
  document.getElementById('countStepUp').textContent = stepUpCount;
  document.getElementById('countDeny').textContent = denyCount;
}

function populateTamperSelect() {
  const select = document.getElementById('tamperSeqSelect');
  select.innerHTML = '';

  if (state.logEntries.length === 0) {
    select.innerHTML = '<option value="">No entries available</option>';
    return;
  }

  // Sort entries by seq ascending for select dropdown
  const sorted = [...state.logEntries].sort((a, b) => a.seq - b.seq);
  sorted.forEach(entry => {
    const opt = document.createElement('option');
    opt.value = entry.seq;
    opt.textContent = `Seq #${entry.seq} — [${entry.decision.outcome}] ${entry.request.tool} (${entry.decision.reason_code})`;
    select.appendChild(opt);
  });
}

function renderIntegrityBanner() {
  const banner = document.getElementById('integrityBanner');
  const checkIcon = document.getElementById('shieldCheckIcon');
  const alertIcon = document.getElementById('shieldAlertIcon');
  const title = document.getElementById('integrityTitle');
  const desc = document.getElementById('integrityDesc');
  const cryptoChip = document.getElementById('cryptoChip');

  const { ok, count, broken_at, why } = state.verifyResult;

  if (ok) {
    banner.className = 'banner-card integrity-banner intact';
    checkIcon.classList.remove('hidden');
    alertIcon.classList.add('hidden');
    title.textContent = 'Provenance Chain Intact';
    cryptoChip.textContent = `SHA-256 Chain · Ed25519 Signed (${count} Verified)`;
    desc.textContent = `All ${count} log entries strictly verified against tamper-proof cryptographic signatures. No unauthorized modifications detected.`;
  } else {
    banner.className = 'banner-card integrity-banner broken';
    checkIcon.classList.add('hidden');
    alertIcon.classList.remove('hidden');
    title.textContent = `CRITICAL: Log Tampering Detected at Sequence #${broken_at}`;
    cryptoChip.textContent = `CORRUPTED: ${why}`;
    desc.textContent = `Verification failed on entry seq #${broken_at}. Reason code: '${why}'. Chain link or signature validation failed!`;
  }
}

function renderLogStream() {
  const stream = document.getElementById('logStream');
  const emptyState = document.getElementById('emptyState');
  stream.innerHTML = '';

  let filtered = state.logEntries;

  // Filter by outcome
  if (state.activeOutcomeFilter !== 'ALL') {
    filtered = filtered.filter(e => e.decision.outcome === state.activeOutcomeFilter);
  }

  // Filter by search query
  if (state.searchQuery) {
    const q = state.searchQuery;
    filtered = filtered.filter(e => {
      return (
        e.request.tool.toLowerCase().includes(q) ||
        e.request.principal.toLowerCase().includes(q) ||
        e.request.agent.toLowerCase().includes(q) ||
        e.decision.reason_code.toLowerCase().includes(q) ||
        (e.decision.matched_rule && e.decision.matched_rule.toLowerCase().includes(q)) ||
        JSON.stringify(e.request.args).toLowerCase().includes(q)
      );
    });
  }

  if (filtered.length === 0) {
    stream.appendChild(emptyState);
    emptyState.classList.remove('hidden');
    return;
  }

  emptyState.classList.add('hidden');

  filtered.forEach(entry => {
    const card = document.createElement('div');
    const isTamperedTarget = (!state.verifyResult.ok && state.verifyResult.broken_at === entry.seq);

    card.className = `log-card outcome-${entry.decision.outcome} ${isTamperedTarget ? 'tampered-highlight' : ''}`;
    
    // Format timestamp
    const tsDate = new Date(entry.ts);
    const formattedTs = tsDate.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

    // Format args nicely
    let argsHtml = '';
    if (entry.request.args && Object.keys(entry.request.args).length > 0) {
      const formattedArgs = Object.entries(entry.request.args)
        .map(([k, v]) => `<span class="args-key">${k}</span>: <span class="args-val">"${v}"</span>`)
        .join(', ');
      argsHtml = `<div class="args-box">{ ${formattedArgs} }</div>`;
    }

    card.innerHTML = `
      <div class="log-header">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="log-seq-tag">#${entry.seq}</span>
          <span class="log-outcome-badge">${entry.decision.outcome}</span>
          ${isTamperedTarget ? '<span class="demo-pill">TAMPERED ROW</span>' : ''}
        </div>
        <div class="log-meta-right">
          <span class="log-ts">${formattedTs}</span>
        </div>
      </div>

      <div class="log-body">
        <div class="log-request-info">
          <span class="principal-agent">${entry.request.principal} · ${entry.request.agent}</span>
          <span class="tool-chip">${entry.request.tool}</span>
          <span class="reason-chip">code: ${entry.decision.reason_code}</span>
          ${entry.decision.matched_rule ? `<span class="matched-rule">rule: ${entry.decision.matched_rule}</span>` : ''}
        </div>

        ${argsHtml}

        <div class="crypto-drawer">
          <button class="crypto-toggle" onclick="toggleCryptoDetails(${entry.seq})">
            <span>▶ Cryptographic Provenance Details</span>
          </button>
          <div class="crypto-details hidden" id="cryptoDetails-${entry.seq}">
            <div class="hash-row">
              <span class="hash-label">Entry Hash:</span>
              <span class="hash-val">${entry.entry_hash || '0000000000000000000000000000000000000000000000000000000000000000'}</span>
            </div>
            <div class="hash-row">
              <span class="hash-label">Prev Hash:</span>
              <span class="hash-val">${entry.prev_hash === "" ? '(root genesis)' : entry.prev_hash}</span>
            </div>
            <div class="hash-row">
              <span class="hash-label">Ed25519 Sig:</span>
              <span class="hash-val">${entry.signature || '0000000000000000000000000000000000000000000000000000000000000000'}</span>
            </div>
          </div>
        </div>
      </div>
    `;

    stream.appendChild(card);
  });
}

function toggleCryptoDetails(seq) {
  const el = document.getElementById(`cryptoDetails-${seq}`);
  if (el) {
    el.classList.toggle('hidden');
  }
}
