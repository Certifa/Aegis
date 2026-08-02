// Aegis Modern SaaS Security Console Controller (Vercel / Linear Aesthetic)

state = {
  logEntries: [],
  receiptCache: {},
  verifyResult: { ok: true, count: 0, broken_at: null, why: null },
  activeOutcomeFilter: 'ALL',
  searchQuery: '',
  contractVersion: '1.0.0',
  autoSyncEnabled: true,
  syncTimer: null,
  selectedSeq: null,
};

document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

async function initApp() {
  setupEventListeners();
  await loadContractVersion();
  await refreshAll();
  startAutoSync();
}

function setupEventListeners() {
  document.getElementById('btnVerify').addEventListener('click', async () => {
    await verifyChain();
  });

  document.getElementById('btnBenign').addEventListener('click', async () => {
    await runDemo('/demo/benign');
  });

  document.getElementById('btnOverreach').addEventListener('click', async () => {
    // No injection anywhere in this path: the agent is asked to pay an invoice
    // and does exactly that. It is refused because it holds more payment
    // authority than it should.
    await runDemo('/demo/overreach');
  });

  document.getElementById('btnInjected').addEventListener('click', async () => {
    await runDemo('/demo/injected');
  });

  document.getElementById('btnInjectTamper').addEventListener('click', async () => {
    await executeTamper();
  });

  document.getElementById('btnToggleSync').addEventListener('click', () => {
    state.autoSyncEnabled = !state.autoSyncEnabled;
    const btn = document.getElementById('btnToggleSync');
    const text = document.getElementById('syncStateText');

    if (state.autoSyncEnabled) {
      btn.classList.remove('off');
      text.textContent = 'ON';
      startAutoSync();
    } else {
      btn.classList.add('off');
      text.textContent = 'OFF';
      stopAutoSync();
    }
  });

  // Policy Modal
  const policyModal = document.getElementById('policyModal');
  document.getElementById('btnViewPolicyHeader').addEventListener('click', async () => {
    await openPolicyModal();
  });
  document.getElementById('btnClosePolicyModal').addEventListener('click', () => {
    policyModal.classList.add('hidden');
  });
  document.getElementById('btnDismissPolicy').addEventListener('click', () => {
    policyModal.classList.add('hidden');
  });
  policyModal.addEventListener('click', (e) => {
    if (e.target === policyModal) {
      policyModal.classList.add('hidden');
    }
  });

  // Inspect Drawer Close
  document.getElementById('btnCloseInspect').addEventListener('click', () => {
    closeInspectPanel();
  });

  // Filter Pills
  document.querySelectorAll('.pill-group .pill').forEach(pill => {
    pill.addEventListener('click', (e) => {
      document.querySelectorAll('.pill-group .pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      state.activeOutcomeFilter = pill.getAttribute('data-filter-outcome');
      renderLogStream();
    });
  });

  // Search Input
  document.getElementById('searchInput').addEventListener('input', (e) => {
    state.searchQuery = e.target.value.toLowerCase().trim();
    renderLogStream();
  });

  // Custom Action Modal
  const actModal = document.getElementById('actModal');
  document.getElementById('btnCustomAct').addEventListener('click', () => {
    actModal.classList.remove('hidden');
  });
  document.getElementById('btnCloseModal').addEventListener('click', () => {
    actModal.classList.add('hidden');
  });
  document.getElementById('btnCancelAct').addEventListener('click', () => {
    actModal.classList.add('hidden');
  });
  actModal.addEventListener('click', (e) => {
    if (e.target === actModal) {
      actModal.classList.add('hidden');
    }
  });

  // Global Escape key listener for closing modals & inspector drawer
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      policyModal.classList.add('hidden');
      actModal.classList.add('hidden');
      closeInspectPanel();
    }
  });

  document.getElementById('actForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await submitCustomAction();
    actModal.classList.add('hidden');
  });

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

function startAutoSync() {
  stopAutoSync();
  state.syncTimer = setInterval(async () => {
    if (state.autoSyncEnabled) {
      await refreshAll();
    }
  }, 2500);
}

function stopAutoSync() {
  if (state.syncTimer) {
    clearInterval(state.syncTimer);
    state.syncTimer = null;
  }
}

async function openPolicyModal() {
  const policyModal = document.getElementById('policyModal');
  const yamlElem = document.getElementById('policyYamlContent');
  policyModal.classList.remove('hidden');

  try {
    const res = await fetch('/policy');
    if (res.ok) {
      const data = await res.json();
      yamlElem.textContent = data.policy_yaml;
    } else {
      yamlElem.textContent = 'Failed to load policy specification.';
    }
  } catch (err) {
    yamlElem.textContent = `Error loading policy: ${err.message}`;
  }
}

async function fetchReceiptText(seq) {
  if (state.receiptCache[seq]) return state.receiptCache[seq];
  try {
    const res = await fetch(`/receipt/${seq}`);
    if (res.ok) {
      const data = await res.json();
      state.receiptCache[seq] = data.text;
      return data.text;
    }
  } catch (e) {
    console.warn(`Failed to fetch receipt for seq ${seq}`, e);
  }
  return null;
}

function inspectRow(seq) {
  state.selectedSeq = seq;
  const entry = state.logEntries.find(e => e.seq === seq);
  if (!entry) return;

  const panel = document.getElementById('inspectPanel');
  const seqNum = document.getElementById('inspectSeqNum');
  const body = document.getElementById('inspectPanelBody');

  seqNum.textContent = String(entry.seq).padStart(4, '0');

  const plainText = state.receiptCache[seq] || entry.decision.reason_code;
  const isTampered = (!state.verifyResult.ok && state.verifyResult.broken_at === entry.seq);

  body.innerHTML = `
    ${isTampered ? `
      <div class="drawer-section" style="border-color:var(--signal-deny-border); background-color:var(--signal-deny-bg);">
        <span class="drawer-label" style="color:var(--signal-deny);">Critical Tamper Anomaly Detected</span>
        <span class="drawer-val mono" style="color:var(--signal-deny); font-weight:600;">
          Reason: ${state.verifyResult.why}
        </span>
        <p style="font-size:11px; color:var(--text-primary); margin-top:4px;">
          ${getTamperExplanation(state.verifyResult.why)}
        </p>
      </div>
    ` : ''}

    <div class="drawer-section">
      <span class="drawer-label">Plain-English Receipt</span>
      <span class="drawer-val" style="font-weight:600; color: ${entry.decision.outcome === 'ALLOW' ? 'var(--signal-allow)' : entry.decision.outcome === 'STEP_UP' ? 'var(--signal-stepup)' : 'var(--signal-deny)'};">
        ${plainText}
      </span>
    </div>

    <div class="drawer-section">
      <span class="drawer-label">Principal &amp; Guarded Agent</span>
      <span class="drawer-val"><strong>${entry.request.principal}</strong> / <span class="mono">${entry.request.agent}</span></span>
    </div>

    <div class="drawer-section">
      <span class="drawer-label">Tool &amp; Policy Reason</span>
      <span class="drawer-val"><strong>${entry.request.tool}</strong> (<span class="mono">code: ${entry.decision.reason_code}</span>)</span>
      ${entry.decision.matched_rule ? `<span class="drawer-val mono" style="color:var(--text-muted); font-size:11px;">rule: ${entry.decision.matched_rule}</span>` : ''}
    </div>

    <div class="drawer-section">
      <span class="drawer-label">Action Arguments Payload (JSON)</span>
      <pre class="code-box-json mono">${JSON.stringify(entry.request.args, null, 2)}</pre>
    </div>

    <div class="drawer-section">
      <span class="drawer-label">SHA-256 Entry Hash</span>
      <span class="drawer-val mono" style="font-size:11px; word-break:break-all;">${entry.entry_hash}</span>
    </div>

    <div class="drawer-section">
      <span class="drawer-label">Previous Entry Hash (Link)</span>
      <span class="drawer-val mono" style="font-size:11px; word-break:break-all;">${entry.prev_hash === "" ? "(Root Genesis)" : entry.prev_hash}</span>
    </div>

    <div class="drawer-section">
      <span class="drawer-label">Ed25519 Signature</span>
      <span class="drawer-val mono" style="font-size:11px; word-break:break-all;">${entry.signature}</span>
    </div>
  `;

  panel.classList.remove('hidden');
  renderChainStrip();
}

function closeInspectPanel() {
  state.selectedSeq = null;
  document.getElementById('inspectPanel').classList.add('hidden');
}

function getTamperExplanation(why) {
  if (why === 'chain_link') {
    return "Previous entry hash link broken. An entry was inserted, reordered, or deleted from the provenance chain.";
  } else if (why === 'content_altered') {
    return "Entry payload modified. Recomputed SHA-256 hash does not match recorded entry_hash.";
  } else if (why === 'bad_signature') {
    return "Ed25519 signature verification failed. Cryptographic signature does not match expected key.";
  }
  return "Cryptographic validation failed on this entry.";
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
      await prefetchReceipts();
      renderLogStream();
      renderChainStrip();
    }
  } catch (err) {
    console.error('Error fetching logs:', err);
  }
}

async function prefetchReceipts() {
  for (const entry of state.logEntries) {
    if (!state.receiptCache[entry.seq]) {
      await fetchReceiptText(entry.seq);
    }
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
      renderChainStrip();
      if (state.selectedSeq !== null) {
        inspectRow(state.selectedSeq);
      }
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
    alert('Invalid JSON in arguments payload!');
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

  document.getElementById('countAll').textContent = total;
  document.getElementById('countAllow').textContent = allowCount;
  document.getElementById('countStepUp').textContent = stepUpCount;
  document.getElementById('countDeny').textContent = denyCount;
}

function populateTamperSelect() {
  const select = document.getElementById('tamperSeqSelect');
  select.innerHTML = '';

  if (state.logEntries.length === 0) {
    select.innerHTML = '<option value="">Target Entry...</option>';
    return;
  }

  const sorted = [...state.logEntries].sort((a, b) => a.seq - b.seq);
  sorted.forEach(entry => {
    const opt = document.createElement('option');
    opt.value = entry.seq;
    opt.textContent = `#${entry.seq} [${entry.decision.outcome}] ${entry.request.tool}`;
    select.appendChild(opt);
  });
}

function renderChainStrip() {
  const strip = document.getElementById('chainStrip');
  const meta = document.getElementById('chainMeta');
  if (!strip) return;

  // /log is newest-first for the table. The chain is only meaningful in the
  // order it was written, so reverse it back to oldest-first here.
  const nodes = [...state.logEntries].sort((a, b) => a.seq - b.seq);
  const { ok, broken_at } = state.verifyResult;

  if (meta) {
    meta.textContent = ok
      ? `${nodes.length} nodes linked`
      : `${nodes.length} nodes, link broken at ${broken_at}`;
  }

  if (nodes.length === 0) {
    strip.innerHTML = '<span class="chain-empty">No entries yet. Run a scenario to build the chain.</span>';
    return;
  }

  let html = '';
  nodes.forEach((entry, i) => {
    // Verification walks the chain and stops at the first failure, so anything
    // past the break has not been verified at all. Rendering it as healthy
    // would be a lie about what we actually know.
    const isBroken = !ok && entry.seq === broken_at;
    const isDead = !ok && entry.seq > broken_at;

    if (i > 0) {
      const linkBroken = !ok && entry.seq === broken_at;
      const linkDead = !ok && entry.seq > broken_at;
      const cls = linkBroken ? 'is-broken' : linkDead ? 'is-dead' : 'is-live';
      html += `<span class="chain-link ${cls}" style="--i:${i}" aria-hidden="true">`;
      if (linkBroken) {
        html += '<span class="link-break-mark">&times;</span>'
             +  '<span class="link-break-label">Link broken</span>';
      }
      html += '</span>';
    }

    const state_cls = isBroken ? 'is-broken' : isDead ? 'is-dead' : 'is-verified';
    const selected = state.selectedSeq === entry.seq ? ' is-selected' : '';
    const label = isBroken
      ? `Entry ${entry.seq}, ${entry.decision.outcome}, chain verification failed here`
      : isDead
        ? `Entry ${entry.seq}, ${entry.decision.outcome}, not verified`
        : `Entry ${entry.seq}, ${entry.decision.outcome}, verified`;

    html += `<button type="button" class="chain-node node-${entry.decision.outcome.toLowerCase()} ${state_cls}${selected}"
                     style="--i:${i}" title="${label}" aria-label="${label}"
                     onclick="inspectRow(${entry.seq})">
               <span class="node-dot"></span>
               <span class="node-seq">${String(entry.seq).padStart(4, '0')}</span>
             </button>`;
  });

  strip.innerHTML = html;

  // One motion beat, and only on a real state change. Auto-sync re-renders
  // every 2.5s; sweeping on every render turns a beat into a throb.
  const sig = ok ? 'ok:' + nodes.length : 'broken:' + broken_at;
  if (state.lastChainSig !== undefined && state.lastChainSig !== sig) {
    strip.classList.remove('is-sweeping');
    void strip.offsetWidth;
    strip.classList.add('is-sweeping');
  }
  state.lastChainSig = sig;
}

function renderIntegrityBanner() {
  const banner = document.getElementById('integrityBanner');
  const title = document.getElementById('integrityTitle');
  const desc = document.getElementById('integrityDesc');
  const cryptoChip = document.getElementById('cryptoChip');

  const { ok, count, broken_at, why } = state.verifyResult;
  const live = document.getElementById('integrityLive');

  if (ok) {
    banner.className = 'banner-card intact';
    // The stamp is decoration; this is the message assistive tech receives.
    if (live) live.textContent = `Chain verified. ${count} entries intact.`;
    title.textContent = 'Provenance Chain Verified';
    cryptoChip.textContent = `SHA-256 Chain · Ed25519 Signed (${count} Verified)`;
    desc.textContent = `All ${count} log entries cryptographically verified against tamper-evident signatures. Zero anomalies detected.`;
  } else {
    banner.className = 'banner-card broken';
    if (live) live.textContent = `Chain broken at exhibit ${String(broken_at).padStart(4, '0')}. Reason: ${why}.`;
    title.textContent = `Chain Broken at Entry ${String(broken_at).padStart(4, '0')}`;
    cryptoChip.textContent = `Corrupted: ${why}`;
    desc.textContent = `Verification failed at entry ${String(broken_at).padStart(4, '0')}: ${getTamperExplanation(why)}`;
  }

}

function renderLogStream() {
  const tbody = document.getElementById('logTableBody');
  const emptyState = document.getElementById('emptyState');
  tbody.innerHTML = '';

  let filtered = state.logEntries;

  if (state.activeOutcomeFilter !== 'ALL') {
    filtered = filtered.filter(e => e.decision.outcome === state.activeOutcomeFilter);
  }

  if (state.searchQuery) {
    const q = state.searchQuery;
    filtered = filtered.filter(e => {
      return (
        e.request.tool.toLowerCase().includes(q) ||
        e.request.principal.toLowerCase().includes(q) ||
        e.request.agent.toLowerCase().includes(q) ||
        e.decision.reason_code.toLowerCase().includes(q) ||
        (e.decision.matched_rule && e.decision.matched_rule.toLowerCase().includes(q)) ||
        (state.receiptCache[e.seq] && state.receiptCache[e.seq].toLowerCase().includes(q)) ||
        JSON.stringify(e.request.args).toLowerCase().includes(q)
      );
    });
  }

  if (filtered.length === 0) {
    emptyState.classList.remove('hidden');
    return;
  }

  emptyState.classList.add('hidden');

  filtered.forEach(entry => {
    const row = document.createElement('tr');
    const isTamperedTarget = (!state.verifyResult.ok && state.verifyResult.broken_at === entry.seq);

    const rowClasses = ['row-' + entry.decision.outcome.toLowerCase()];
    if (isTamperedTarget) rowClasses.push('row-tampered');
    row.className = rowClasses.join(' ');

    const tsFormatted = new Date(entry.ts).toISOString().replace('T', ' ').substring(0, 19);
    const prose = state.receiptCache[entry.seq] || entry.decision.reason_code;
    const hashFragment = entry.entry_hash ? `${entry.entry_hash.substring(0, 8)}...${entry.entry_hash.substring(56)}` : '0000...0000';

    row.onclick = () => inspectRow(entry.seq);

    row.innerHTML = `
      <td class="seq-cell">${String(entry.seq).padStart(4, '0')}</td>
      <td class="ts-cell mono">${tsFormatted}</td>
      <td><span class="badge-outcome badge-${entry.decision.outcome}">${entry.decision.outcome}</span></td>
      <td class="tool-cell mono">${entry.request.tool}</td>
      <td class="principal-cell">${entry.request.principal}</td>
      <td class="prose-cell">
        <span class="prose-main">${prose}</span>
        <span class="prose-reason mono">${entry.decision.reason_code}</span>
        ${entry.decision.outcome !== 'ALLOW' ? `<span class="void-mark">Did not execute</span>` : ''}
        ${isTamperedTarget ? `
          <span class="tamper-note">Anomaly: ${getTamperExplanation(state.verifyResult.why)}</span>
        ` : ''}
      </td>
      <td class="ts-cell mono" style="font-size:11px;">${hashFragment}</td>
      <td style="text-align: right;">
        <button class="btn-pill" style="padding: 2px 8px; font-size: 11px;" onclick="event.stopPropagation(); inspectRow(${entry.seq})">Inspect</button>
      </td>
    `;

    tbody.appendChild(row);
  });
}
