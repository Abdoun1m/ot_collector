/* ── Palette matching styles.css CSS vars ────────────────── */
const P = {
  amber:   '#cf0f1d', amberHi: '#ff3344', amberLo: 'rgba(207,15,29,0.15)',
  green:   '#ff6b35', greenLo: 'rgba(255,107,53,0.15)',
  danger:  '#ff0a1a', dangerHi:'#ff2233', dangerLo:'rgba(255,10,26,0.15)',
  cyan:    '#e8304a', cyanLo:  'rgba(232,48,74,0.15)',
  warn:    '#ff8c42', warnLo:  'rgba(255,140,66,0.15)',
  muted:   '#7a4040',
  line:    '#2e1414',
  ink:     '#f0d8d8',
  panel:   '#0e0404',
};

Chart.defaults.color          = P.muted;
Chart.defaults.borderColor    = P.line;
Chart.defaults.backgroundColor = P.amberLo;
Chart.defaults.font.family    = "'Share Tech Mono', monospace";
Chart.defaults.font.size      = 11;

const CHART_OPTS_BASE = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { labels: { color: P.muted, boxWidth: 10, padding: 12 } } },
  scales: {
    x: { ticks: { color: P.muted }, grid: { color: 'rgba(26,46,46,0.6)' } },
    y: { ticks: { color: P.muted }, grid: { color: 'rgba(26,46,46,0.6)' } },
  },
};

/* ── State ───────────────────────────────────────────────── */
const state = {
  events: [],
  streamPaused: false,
  es: null,
  eps: 0,
  sources: [],
  rules: [],
  forwarding: null,
  filters: { limit: 200, source_type: '', asset_ip: '', severity: '', category: '', search: '' },
};

/* ── DOM refs ────────────────────────────────────────────── */
const el = {
  healthPill:   document.getElementById('health-pill'),
  ratePill:     document.getElementById('rate-pill'),
  clock:        document.getElementById('sys-clock'),
  ticker:       document.getElementById('event-ticker'),
  sbDot:        document.getElementById('sb-health-dot'),
  sbTxt:        document.getElementById('sb-health-txt'),
  sbCount:      document.getElementById('sb-event-count'),
  tabs:         [...document.querySelectorAll('.tabs button')],
  tabDashboard: document.getElementById('tab-dashboard'),
  tabMessages:  document.getElementById('tab-messages'),
  tabSources:   document.getElementById('tab-sources'),
  tabRules:     document.getElementById('tab-rules'),
  tabForwarding:document.getElementById('tab-forwarding'),
  tabSettings:  document.getElementById('tab-settings'),
  modal:        document.getElementById('json-modal'),
  modalBody:    document.getElementById('json-modal-body'),
  modalClose:   document.getElementById('json-modal-close'),
};

let sourceChart, categoryChart, decisionChart, timelineChart;

/* ── Clock ───────────────────────────────────────────────── */
function tickClock() {
  el.clock.textContent = new Date().toISOString().slice(11, 19) + ' UTC';
}
setInterval(tickClock, 1000);
tickClock();

/* ── Shell HTML ──────────────────────────────────────────── */
function renderShell() {
  el.tabDashboard.innerHTML = `
    <div id="kpis" class="grid"></div>
    <div class="grid">
      <div class="card chart"><div class="chart-title">// source distribution</div><canvas id="c-source"></canvas></div>
      <div class="card chart"><div class="chart-title">// events by category</div><canvas id="c-category"></canvas></div>
      <div class="card chart"><div class="chart-title">// decision breakdown</div><canvas id="c-decision"></canvas></div>
      <div class="card full" style="min-height:180px"><div class="chart-title">// event timeline</div><canvas id="c-timeline"></canvas></div>
    </div>`;

  el.tabMessages.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <select id="m-source"><option value="">source: all</option></select>
        <input id="m-asset" placeholder="asset ip" class="mono" style="width:120px" />
        <select id="m-sev">
          <option value="">sev: all</option>
          <option>info</option><option>warning</option><option>error</option><option>critical</option>
        </select>
        <select id="m-cat">
          <option value="">cat: all</option>
          <option>operator_action</option><option>operator_read</option><option>operator_write</option>
          <option>security</option><option>network</option><option>system</option><option>runtime</option>
        </select>
        <input id="m-search" placeholder="search..." style="width:140px" />
        <button id="m-apply" class="primary">Apply</button>
        <button id="m-pause">Pause</button>
        <button id="m-clear" class="ghost">Clear</button>
        <button id="m-export" class="ghost">Export JSON</button>
      </div>
      <div class="msg-scroll">
        <table><thead><tr>
          <th>Timestamp</th><th>Source</th><th>Asset</th><th>Sev</th><th>Category</th><th>Message</th>
        </tr></thead><tbody id="m-tbody"></tbody></table>
      </div>
    </div>`;

  el.tabSources.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <input id="s-search" placeholder="filter sources..." />
        <button id="s-add" class="primary">+ Add Source</button>
        <button id="s-save">Save</button>
        <button id="s-reset" class="ghost">Reset Defaults</button>
      </div>
      <div class="table-wrap">
        <table><thead><tr>
          <th>Name</th><th>Type</th><th>IP Address</th><th>Protocol</th><th>Impact</th><th>Zone</th><th>State</th><th></th>
        </tr></thead><tbody id="s-tbody"></tbody></table>
      </div>
    </div>`;

  el.tabRules.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <button id="r-add" class="primary">+ Add Rule</button>
        <button id="r-save">Save Rules</button>
      </div>
      <div class="table-wrap">
        <table><thead><tr>
          <th>On</th><th>Source</th><th>Asset</th><th>Category</th><th>Sev</th><th>Op</th>
          <th>Action</th><th>Sample</th><th>Fwd</th><th>Store</th><th>Notes</th><th></th>
        </tr></thead><tbody id="r-tbody"></tbody></table>
      </div>
      <div style="margin-top:14px;border-top:1px solid var(--line);padding-top:14px;">
        <div class="chart-title">// rule tester</div>
        <textarea id="r-test-json" rows="5" style="width:100%;margin-bottom:8px"
          placeholder='{"event":{"source_type":"opcua","event_category":"operator_action","tags":{"opcua_operation":"READ"}}}'></textarea>
        <div class="toolbar">
          <button id="r-test" class="primary">Run Test</button>
        </div>
        <pre id="r-test-out" style="margin-top:8px;display:none"></pre>
      </div>
    </div>`;

  el.tabForwarding.innerHTML = `
    <div class="card">
      <div class="chart-title" style="margin-bottom:12px">// dmz forwarding config</div>
      <div class="toolbar" style="flex-direction:column;align-items:flex-start;gap:10px">
        <div style="display:flex;gap:8px;align-items:center;width:100%">
          <input id="f-url" class="mono" placeholder="https://dmz-collector:port/ingest" style="flex:1" />
        </div>
        <div style="display:flex;gap:18px">
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
            <input type="checkbox" id="f-enabled" /> <span>forwarding enabled</span>
          </label>
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
            <input type="checkbox" id="f-only-filtered" /> <span>forward only filtered events</span>
          </label>
        </div>
      </div>
      <div class="toolbar">
        <button id="f-save" class="primary">Save Config</button>
        <button id="f-test">Test Connection</button>
      </div>
      <pre id="f-state" style="margin-top:10px"></pre>
    </div>`;

  el.tabSettings.innerHTML = `
    <div class="card">
      <div class="chart-title" style="margin-bottom:12px">// collector settings</div>
      <p style="color:var(--muted);font-family:var(--font-mono);font-size:12px;line-height:1.8">
        Runtime configuration is managed via environment variables and docker-compose.<br/>
        Use the API endpoints directly for advanced configuration.
      </p>
      <div style="margin-top:16px">
        <button id="st-repair" class="ghost">Repair Storage</button>
      </div>
      <pre id="st-out" style="margin-top:10px;display:none"></pre>
    </div>`;
}

/* ── Tabs ────────────────────────────────────────────────── */
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(n => n.classList.remove('active'));
  el.tabs.forEach(n => n.classList.remove('active'));
  document.getElementById(`tab-${name}`).classList.add('active');
  document.querySelector(`.tabs button[data-tab="${name}"]`).classList.add('active');
}

function bindTabs() { el.tabs.forEach(b => b.onclick = () => switchTab(b.dataset.tab)); }

/* ── Fetch helper ────────────────────────────────────────── */
async function j(url, opt) {
  const r = await fetch(url, opt);
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

/* ── Messages ────────────────────────────────────────────── */
let lastRenderedCount = 0;

function renderMessages() {
  const tbody = document.getElementById('m-tbody');
  if (!tbody) return;
  const slice = state.events.slice(-400).reverse();
  const isNew = slice.length > lastRenderedCount;
  lastRenderedCount = slice.length;

  tbody.innerHTML = slice.map((e, i) => `
    <tr data-i="${i}"${i === 0 && isNew ? ' class="flash-new"' : ''}>
      <td class="mono" style="white-space:nowrap;color:var(--muted);font-size:11px">${esc(fmtTs(e.timestamp))}</td>
      <td><span class="badge">${esc(e.source_type || '?')}</span></td>
      <td style="font-size:11px">${esc(e.asset_name || '')}<br/><span class="mono" style="color:var(--muted)">${esc(e.asset_ip || '')}</span></td>
      <td class="sev-${esc((e.severity || 'info').toLowerCase())}" style="white-space:nowrap">${esc(e.severity || 'info')}</td>
      <td style="color:var(--muted);font-size:11px">${esc(e.event_category || '')}</td>
      <td style="max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.message || '')}</td>
    </tr>`).join('');

  tbody.onclick = ev => {
    const tr = ev.target.closest('tr[data-i]'); if (!tr) return;
    const item = state.events.slice(-400).reverse()[Number(tr.dataset.i)];
    el.modalBody.textContent = JSON.stringify(item, null, 2);
    el.modal.showModal();
  };

  /* Update status bar ticker with latest event */
  if (slice[0]) {
    const e = slice[0];
    el.ticker.textContent = `${fmtTs(e.timestamp)} | ${e.source_type || '?'} | ${e.severity || ''} | ${e.message || ''}`;
  }
}

function fmtTs(ts) {
  if (!ts) return '';
  return ts.replace('T', ' ').replace(/\.\d+Z?$/, '').replace('Z', '');
}

/* ── Sources ─────────────────────────────────────────────── */
function renderSources() {
  const q = (document.getElementById('s-search')?.value || '').toLowerCase();
  const tbody = document.getElementById('s-tbody');
  if (!tbody) return;
  const rows = state.sources.filter(s => JSON.stringify(s).toLowerCase().includes(q));
  tbody.innerHTML = rows.map((s, idx) => `
    <tr>
      <td><input data-f="name" data-i="${idx}" value="${escAttr(s.name || '')}" /></td>
      <td><input data-f="type" data-i="${idx}" value="${escAttr(s.type || '')}" style="width:90px"/></td>
      <td><input data-f="ip" data-i="${idx}" class="mono" value="${escAttr(s.ip || '')}" style="width:120px"/></td>
      <td><input data-f="protocol" data-i="${idx}" value="${escAttr(s.protocol || 'syslog')}" style="width:70px"/></td>
      <td><input data-f="impact" data-i="${idx}" value="${escAttr(s.impact || '')}" style="width:70px"/></td>
      <td><input data-f="zone" data-i="${idx}" value="${escAttr(s.zone || '')}" style="width:50px"/></td>
      <td style="color:${s.enabled ? 'var(--green)' : 'var(--muted)'}">
        <label style="cursor:pointer;display:flex;align-items:center;gap:5px">
          <input type="checkbox" data-f="enabled" data-i="${idx}" ${s.enabled ? 'checked' : ''}/>${s.enabled ? 'active' : 'off'}
        </label>
      </td>
      <td><button data-del="${idx}" class="ghost" style="font-size:10px;padding:3px 8px">Del</button></td>
    </tr>`).join('');

  tbody.querySelectorAll('input').forEach(inp => {
    inp.onchange = () => {
      const i = Number(inp.dataset.i), f = inp.dataset.f;
      state.sources[i][f] = inp.type === 'checkbox' ? inp.checked : inp.value;
      if (f === 'enabled') renderSources();
    };
  });
  tbody.querySelectorAll('button[data-del]').forEach(b => b.onclick = () => {
    state.sources.splice(Number(b.dataset.del), 1); renderSources();
  });
}

/* ── Rules ───────────────────────────────────────────────── */
function renderRules() {
  const tbody = document.getElementById('r-tbody');
  if (!tbody) return;
  const actionColors = { keep:'var(--green)', drop:'var(--danger-hi)', sample:'var(--warn)', forward_only:'var(--cyan)', store_only:'var(--amber)' };
  tbody.innerHTML = state.rules.map((r, idx) => `
    <tr>
      <td><input type="checkbox" data-f="enabled" data-i="${idx}" ${r.enabled ? 'checked' : ''}></td>
      <td><input data-f="source_type" data-i="${idx}" value="${escAttr(r.source_type||'*')}" style="width:80px"></td>
      <td><input data-f="asset" data-i="${idx}" value="${escAttr(r.asset||'*')}" style="width:80px"></td>
      <td><input data-f="category" data-i="${idx}" value="${escAttr(r.category||'*')}" style="width:100px"></td>
      <td><input data-f="severity" data-i="${idx}" value="${escAttr(r.severity||'*')}" style="width:70px"></td>
      <td><input data-f="operation" data-i="${idx}" value="${escAttr(r.operation||'*')}" style="width:70px"></td>
      <td>
        <select data-f="action" data-i="${idx}" style="color:${actionColors[r.action]||'inherit'}">
          ${['keep','drop','sample','forward_only','store_only'].map(a => `<option ${r.action===a?'selected':''} style="color:${actionColors[a]}">${a}</option>`).join('')}
        </select>
      </td>
      <td><input type="number" min="0" max="1" step="0.05" data-f="sample_rate" data-i="${idx}" value="${Number(r.sample_rate||1)}" style="width:60px"></td>
      <td style="text-align:center"><input type="checkbox" data-f="forward_to_dmz" data-i="${idx}" ${r.forward_to_dmz?'checked':''}></td>
      <td style="text-align:center"><input type="checkbox" data-f="store_locally" data-i="${idx}" ${r.store_locally?'checked':''}></td>
      <td><input data-f="notes" data-i="${idx}" value="${escAttr(r.notes||'')}" style="width:100px"></td>
      <td style="white-space:nowrap">
        <button data-up="${idx}" class="ghost" style="padding:2px 6px">↑</button>
        <button data-down="${idx}" class="ghost" style="padding:2px 6px">↓</button>
        <button data-del="${idx}" class="btn-danger" style="padding:2px 8px;font-size:10px">Del</button>
      </td>
    </tr>`).join('');

  tbody.querySelectorAll('input,select').forEach(inp => {
    inp.onchange = () => {
      const i = Number(inp.dataset.i), f = inp.dataset.f;
      state.rules[i][f] = inp.type === 'checkbox' ? inp.checked : (inp.type === 'number' ? Number(inp.value) : inp.value);
    };
  });
  tbody.querySelectorAll('button[data-up]').forEach(b => b.onclick = () => moveRule(Number(b.dataset.up), -1));
  tbody.querySelectorAll('button[data-down]').forEach(b => b.onclick = () => moveRule(Number(b.dataset.down), +1));
  tbody.querySelectorAll('button[data-del]').forEach(b => b.onclick = () => { state.rules.splice(Number(b.dataset.del), 1); renderRules(); });
}

function moveRule(i, d) {
  const k = i + d; if (k < 0 || k >= state.rules.length) return;
  [state.rules[i], state.rules[k]] = [state.rules[k], state.rules[i]]; renderRules();
}

/* ── Forwarding ──────────────────────────────────────────── */
function renderForwarding() {
  if (!state.forwarding) return;
  document.getElementById('f-url').value  = state.forwarding.dmz_collector_url || '';
  document.getElementById('f-enabled').checked = !!state.forwarding.enabled;
  document.getElementById('f-only-filtered').checked = !!state.forwarding.forward_only_filtered_events;
  document.getElementById('f-state').textContent = JSON.stringify(state.forwarding, null, 2);
}

/* ── Dashboard ───────────────────────────────────────────── */
function renderDashboard(summary, timeline) {
  const kpis = document.getElementById('kpis');
  if (!kpis) return;

  const total     = summary.total_events || 0;
  const rate      = summary.event_rate_per_second || 0;
  const forwarded = summary.forwarded_count || 0;
  const dropped   = summary.dropped_count || 0;
  const sampled   = summary.sampled_count || 0;
  const threats   = (summary.by_category?.security || 0) + (summary.by_severity?.critical || 0);

  const kpiDefs = [
    { label: 'total events',    val: fmtNum(total),     cls: '',         pct: Math.min(100, total / 10) },
    { label: 'events / sec',    val: rate.toFixed(1),   cls: 'kpi-cyan', pct: Math.min(100, rate * 10) },
    { label: 'forwarded',       val: fmtNum(forwarded), cls: 'kpi-green',pct: total ? forwarded/total*100 : 0 },
    { label: 'dropped',         val: fmtNum(dropped),   cls: dropped > 0 ? 'kpi-red' : '', pct: total ? dropped/total*100 : 0 },
    { label: 'sampled',         val: fmtNum(sampled),   cls: 'kpi-warn', pct: total ? sampled/total*100 : 0 },
    { label: 'critical/sec threat', val: fmtNum(threats), cls: threats > 0 ? 'kpi-red' : '', pct: Math.min(100, threats) },
  ];

  kpis.innerHTML = kpiDefs.map(k => `
    <div class="card kpi ${k.cls}">
      <div class="kpi-label">${k.label}</div>
      <div class="v">${k.val}</div>
      <div class="kpi-bar"><div class="kpi-bar-fill" style="width:${k.pct.toFixed(1)}%"></div></div>
    </div>`).join('');

  /* chart data */
  const srcLabels = Object.keys(summary.by_source_type || {});
  const srcVals   = Object.values(summary.by_source_type || {});
  const catLabels = Object.keys(summary.by_category || {});
  const catVals   = Object.values(summary.by_category || {});
  const decLabels = Object.keys(summary.by_decision || {});
  const decVals   = Object.values(summary.by_decision || {});
  const tLabels   = (timeline || []).map(x => fmtTs(x.timestamp).slice(11,16));
  const tVals     = (timeline || []).map(x => x.count || 0);

  if (sourceChart)   sourceChart.destroy();
  if (categoryChart) categoryChart.destroy();
  if (decisionChart) decisionChart.destroy();
  if (timelineChart) timelineChart.destroy();

  const PIE_COLORS = ['#ff3344', '#e8304a', '#ff6b35', '#ff8c42', '#c4142a', '#ff1a2e', '#ff5566'];
  const decColors  = decLabels.map(l => ({ keep: P.green, drop: P.dangerHi, sample: P.warn, forward: P.cyan, store: P.amber }[l] || P.muted));

  sourceChart = new Chart(document.getElementById('c-source'), {
    type: 'doughnut',
    data: { labels: srcLabels, datasets: [{ data: srcVals, backgroundColor: PIE_COLORS, borderColor: '#060d0d', borderWidth: 2 }] },
    options: { ...CHART_OPTS_BASE, cutout: '55%', scales: {} },
  });

  categoryChart = new Chart(document.getElementById('c-category'), {
    type: 'bar',
    data: { labels: catLabels, datasets: [{ data: catVals, backgroundColor: P.amberLo, borderColor: P.amber, borderWidth: 1 }] },
    options: { ...CHART_OPTS_BASE, plugins: { legend: { display: false } } },
  });

  decisionChart = new Chart(document.getElementById('c-decision'), {
    type: 'bar',
    data: { labels: decLabels, datasets: [{ data: decVals, backgroundColor: decColors.map(c => c + '33'), borderColor: decColors, borderWidth: 1 }] },
    options: { ...CHART_OPTS_BASE, plugins: { legend: { display: false } } },
  });

  timelineChart = new Chart(document.getElementById('c-timeline'), {
    type: 'line',
    data: {
      labels: tLabels,
      datasets: [{
        data: tVals,
        borderColor: P.green,
        backgroundColor: 'rgba(0,232,122,0.06)',
        borderWidth: 1.5,
        pointRadius: 2,
        pointBackgroundColor: P.green,
        fill: true,
        tension: 0.3,
      }],
    },
    options: { ...CHART_OPTS_BASE, plugins: { legend: { display: false } } },
  });
}

function fmtNum(n) { return n >= 1000 ? (n/1000).toFixed(1)+'k' : String(n); }

/* ── Load ────────────────────────────────────────────────── */
async function loadAll() {
  const [health, events, sources, rules, forwarding, summary, timeline] = await Promise.all([
    j('/health'),
    j(`/events?${new URLSearchParams(state.filters)}`),
    j('/config/sources'),
    j('/config/rules'),
    j('/config/forwarding'),
    j('/stats/summary'),
    j('/stats/timeline'),
  ]);
  setHealth(health.status === 'ok');
  state.events   = events;
  state.sources  = sources;
  state.rules    = rules;
  state.forwarding = forwarding;
  renderMessages(); renderSources(); renderRules(); renderForwarding();
  renderDashboard(summary, timeline);
  hydrateMessageSourceFilter();
  el.sbCount.textContent = `events: ${fmtNum(summary.total_events || 0)}`;
}

function hydrateMessageSourceFilter() {
  const s = document.getElementById('m-source'); if (!s) return;
  s.innerHTML = '<option value="">source: all</option>' +
    [...new Set(state.sources.map(x => x.type).filter(Boolean))].map(t => `<option>${t}</option>`).join('');
}

/* ── Bind ────────────────────────────────────────────────── */
function bind() {
  bindTabs();
  el.modalClose.onclick = () => el.modal.close();

  document.getElementById('m-apply').onclick = async () => {
    state.filters.source_type = document.getElementById('m-source').value.trim();
    state.filters.asset_ip    = document.getElementById('m-asset').value.trim();
    state.filters.severity    = document.getElementById('m-sev').value.trim();
    state.filters.category    = document.getElementById('m-cat').value.trim();
    state.filters.search      = document.getElementById('m-search').value.trim();
    state.events = await j(`/events?${new URLSearchParams(state.filters)}`);
    renderMessages();
  };

  document.getElementById('m-clear').onclick  = () => { state.events = []; renderMessages(); };
  document.getElementById('m-pause').onclick  = ev => {
    state.streamPaused = !state.streamPaused;
    ev.target.textContent = state.streamPaused ? 'Resume' : 'Pause';
    document.getElementById('live-badge').style.opacity = state.streamPaused ? '0.3' : '1';
  };
  document.getElementById('m-export').onclick = () => {
    const blob = new Blob([JSON.stringify(state.events, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = `ot-events-${Date.now()}.json`; a.click();
  };

  document.getElementById('s-search').oninput = renderSources;
  document.getElementById('s-add').onclick = () => {
    state.sources.push({ id: `src-${Date.now()}`, name: 'New Source', type: 'unknown', ip: '', protocol: 'syslog', impact: 'medium', zone: 'L2', enabled: true, forward_enabled: true, notes: '' });
    renderSources();
  };
  document.getElementById('s-save').onclick = async () => {
    await j('/config/sources', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(state.sources) });
    await loadAll();
  };
  document.getElementById('s-reset').onclick = async () => {
    await j('/config/sources', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify([]) });
    await loadAll();
  };

  document.getElementById('r-add').onclick = () => {
    state.rules.push({ id: `rule-${Date.now()}`, enabled: true, source_type: '*', asset: '*', category: '*', severity: '*', operation: '*', action: 'keep', sample_rate: 1, forward_to_dmz: false, store_locally: true, notes: '' });
    renderRules();
  };
  document.getElementById('r-save').onclick = async () => {
    await j('/config/rules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(state.rules) });
    await loadAll();
  };
  document.getElementById('r-test').onclick = async () => {
    const out = document.getElementById('r-test-out');
    try {
      const payload = JSON.parse(document.getElementById('r-test-json').value || '{}');
      const res = await j('/config/rules/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      out.textContent = JSON.stringify(res, null, 2); out.style.display = 'block';
    } catch (e) { out.textContent = String(e); out.style.display = 'block'; }
  };

  document.getElementById('f-save').onclick = async () => {
    state.forwarding.dmz_collector_url = document.getElementById('f-url').value.trim();
    state.forwarding.enabled = document.getElementById('f-enabled').checked;
    state.forwarding.forward_only_filtered_events = document.getElementById('f-only-filtered').checked;
    await j('/config/forwarding', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(state.forwarding) });
    await loadAll();
  };
  document.getElementById('f-test').onclick = async () => {
    const out = await j('/forwarding/test', { method: 'POST' }).catch(e => ({ error: String(e) }));
    document.getElementById('f-state').textContent = JSON.stringify(out, null, 2);
  };

  document.getElementById('st-repair').onclick = async () => {
    const out = document.getElementById('st-out');
    const res = await j('/storage/repair', { method: 'POST' }).catch(e => ({ error: String(e) }));
    out.textContent = JSON.stringify(res, null, 2); out.style.display = 'block';
  };
}

/* ── SSE stream ──────────────────────────────────────────── */
function connectStream() {
  if (state.es) state.es.close();
  state.es = new EventSource('/events/stream');
  state.es.onopen  = () => setHealth(true);
  state.es.onerror = () => setHealth(false);
  state.es.addEventListener('event', ev => {
    if (state.streamPaused) return;
    state.eps++;
    const item = JSON.parse(ev.data);
    state.events.push(item);
    if (state.events.length > 3000) state.events.shift();
    renderMessages();
  });
}

/* ── Health ──────────────────────────────────────────────── */
function setHealth(ok) {
  el.healthPill.className = `pill ${ok ? 'online' : 'offline'}`;
  el.healthPill.textContent = ok ? 'online' : 'offline';
  el.sbDot.className  = `sb-dot ${ok ? 'ok' : 'bad'}`;
  el.sbTxt.textContent = ok ? 'collector online' : 'collector offline';
}

/* ── Rate counter ────────────────────────────────────────── */
setInterval(() => {
  el.ratePill.textContent = `${state.eps} ev/s`;
  state.eps = 0;
}, 1000);

/* ── Dashboard refresh ───────────────────────────────────── */
setInterval(async () => {
  try {
    const [summary, timeline] = await Promise.all([j('/stats/summary'), j('/stats/timeline')]);
    renderDashboard(summary, timeline);
    el.sbCount.textContent = `events: ${fmtNum(summary.total_events || 0)}`;
  } catch {}
}, 5000);

/* ── Escape helpers ──────────────────────────────────────── */
function esc(s) {
  return String(s || '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}
function escAttr(s) { return esc(s).replaceAll('\n', ' '); }

/* ── Boot ────────────────────────────────────────────────── */
async function boot() {
  renderShell();
  bind();
  await loadAll();
  connectStream();
}

boot().catch(e => { console.error(e); setHealth(false); });
