/* ──────────────────────────────────────────────────────────────
   DataProtect OT Collector — SPA
   Vanilla JS, no framework, no build step.
   Chart.js loaded via CDN.
────────────────────────────────────────────────────────────── */

/* ── Chart.js defaults ─────────────────────────────────────── */
Chart.defaults.font.family = "'JetBrains Mono', 'Consolas', monospace";
Chart.defaults.font.size   = 11;

/* ── Palette (mirrors CSS custom props for JS use) ─────────── */
const P = {
  red:      '#E30613', redHi:  '#EF233C', redLo:  'rgba(227,6,19,0.15)',
  critical: '#DC2626',
  warning:  '#F59E0B',
  success:  '#22C55E',
  info:     '#3B82F6',
  cyan:     '#06B6D4',
  purple:   '#8B5CF6',
  text2:    '#A3A3A3',
  grid:     'rgba(255,255,255,0.05)',
};

function themeGrid() {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  return isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.05)';
}

function themeText2() {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  return isLight ? '#525252' : '#A3A3A3';
}

/* ── State ─────────────────────────────────────────────────── */
const state = {
  currentPage: 'dashboard',
  events: [],
  streamPaused: false,
  es: null,
  eps: 0,
  sources: [],
  rules: [],
  forwarding: null,
  health: null,
  filters: { limit: 200, source_type: '', asset_ip: '', severity: '', category: '', search: '' },
  sidebarCollapsed: false,
};

/* ── Chart instances ───────────────────────────────────────── */
const charts = {};

/* ── Page meta ─────────────────────────────────────────────── */
const PAGE_META = {
  dashboard:  { title: 'Dashboard',    subtitle: 'OT event pipeline overview' },
  messages:   { title: 'Messages',     subtitle: 'Live event stream with filtering' },
  sources:    { title: 'Sources',      subtitle: 'Managed OT/ICS source configuration' },
  rules:      { title: 'Rule Matrix',  subtitle: 'Filtering, sampling and forwarding rules' },
  forwarding: { title: 'Forwarding',   subtitle: 'DMZ SIEM forwarding configuration and status' },
  settings:   { title: 'Settings',     subtitle: 'System information and maintenance' },
};

/* ── Fetch helper ──────────────────────────────────────────── */
async function api(url, opt) {
  const r = await fetch(url, opt);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

/* ── Escape helpers ────────────────────────────────────────── */
function esc(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
function escAttr(s) { return esc(s).replaceAll('\n', ' '); }

/* ── Format helpers ────────────────────────────────────────── */
function fmtNum(n) {
  n = Number(n) || 0;
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'k';
  return String(n);
}

function fmtTs(ts) {
  if (!ts) return '—';
  return ts.replace('T', ' ').replace(/\.\d+Z?$/, '').replace('Z', '') + ' UTC';
}

function fmtTsShort(ts) {
  if (!ts) return '—';
  const s = ts.replace('T', ' ').replace(/\.\d+Z?$/, '');
  return s.slice(0, 19);
}

function fmtTimeline(ts) {
  if (!ts) return '';
  const s = ts.replace('T', ' ').replace(/\.\d+Z?$/, '');
  return s.slice(11, 16);
}

/* ── Severity badge HTML ───────────────────────────────────── */
function sevBadge(sev) {
  const s = (sev || 'info').toLowerCase();
  return `<span class="sev-badge ${esc(s)}">${esc(s)}</span>`;
}

/* ── Source type badge HTML ────────────────────────────────── */
function srcBadge(type) {
  if (!type) return '<span class="badge">—</span>';
  const colorMap = {
    opcua: 'cyan', dnp3: 'cyan', modbus: 'cyan', bacnet: 'cyan',
    iec104: 'cyan', 's7comm': 'cyan', profinet: 'cyan',
    pki: 'purple', certificate: 'purple',
    syslog: 'badge', firewall: 'warning', ids: 'warning',
  };
  const cls = colorMap[type.toLowerCase()] || '';
  return `<span class="badge ${esc(cls)}">${esc(type)}</span>`;
}

/* ── Action pill HTML ──────────────────────────────────────── */
function actionPill(action) {
  return `<span class="action-pill action-${esc((action || 'keep').toLowerCase())}">${esc(action || 'keep')}</span>`;
}

/* ── Navigation ────────────────────────────────────────────── */
function switchPage(name) {
  if (!PAGE_META[name]) return;
  state.currentPage = name;

  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));

  const page = document.getElementById(`page-${name}`);
  if (page) page.classList.add('active');

  const navBtn = document.querySelector(`.nav-item[data-page="${name}"]`);
  if (navBtn) navBtn.classList.add('active');

  const meta = PAGE_META[name];
  document.getElementById('page-title').textContent    = meta.title;
  document.getElementById('page-subtitle').textContent = meta.subtitle;
}

function bindNav() {
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => switchPage(btn.dataset.page));
  });
}

/* ── Sidebar collapse ──────────────────────────────────────── */
function bindSidebar() {
  const sidebar = document.getElementById('sidebar');
  const topbar  = document.getElementById('topbar');
  const main    = document.getElementById('main-content');
  const colBtn  = document.getElementById('sidebar-collapse');

  colBtn.addEventListener('click', () => {
    state.sidebarCollapsed = !state.sidebarCollapsed;
    sidebar.classList.toggle('collapsed', state.sidebarCollapsed);
    topbar.classList.toggle('sidebar-collapsed', state.sidebarCollapsed);
    main.classList.toggle('sidebar-collapsed', state.sidebarCollapsed);
  });
}

/* ── Theme toggle ──────────────────────────────────────────── */
function bindTheme() {
  const btn       = document.getElementById('btn-theme');
  const iconDark  = document.getElementById('theme-icon-dark');
  const iconLight = document.getElementById('theme-icon-light');

  function applyTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('dp-theme', t); } catch(e) {}
    const isLight = t === 'light';
    iconDark.style.display  = isLight ? 'none'  : 'block';
    iconLight.style.display = isLight ? 'block' : 'none';
    // Update chart defaults for new theme
    Chart.defaults.color = themeText2();
    Chart.defaults.borderColor = themeGrid();
    // Redraw all charts to pick up new colors
    Object.values(charts).forEach(c => { try { c.update(); } catch(e) {} });
  }

  const saved = (() => { try { return localStorage.getItem('dp-theme'); } catch(e) { return null; } })();
  applyTheme(saved || 'dark');

  btn.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    applyTheme(current === 'light' ? 'dark' : 'light');
  });
}

/* ── Health status ─────────────────────────────────────────── */
function setHealth(ok) {
  const chip = document.getElementById('health-chip');
  const txt  = document.getElementById('health-txt');
  const dot  = document.getElementById('sb-health-dot');
  const sTxt = document.getElementById('sb-health-txt');

  chip.className = `status-chip ${ok ? 'online' : 'offline'}`;
  txt.textContent = ok ? 'Online' : 'Offline';
  dot.className   = `sb-dot ${ok ? 'ok' : 'bad'}`;
  sTxt.textContent = ok ? 'collector online' : 'collector offline';
}

/* ── Last updated ──────────────────────────────────────────── */
function setLastUpdated() {
  document.getElementById('last-updated').textContent =
    'Updated ' + new Date().toLocaleTimeString();
}

/* ── Dashboard ─────────────────────────────────────────────── */
function renderDashboard(summary, timeline) {
  const total     = summary.total_events          || 0;
  const rate      = summary.event_rate_per_second || 0;
  const forwarded = summary.forwarded_count       || 0;
  const dropped   = summary.dropped_count         || 0;
  const sampled   = summary.sampled_count         || 0;
  const security  = summary.by_category?.security || 0;
  const critSev   = summary.by_severity?.critical || 0;
  const threats   = security + critSev;

  // KPI values
  document.getElementById('kv-total').textContent   = fmtNum(total);
  document.getElementById('kv-rate').textContent    = rate.toFixed(2);
  document.getElementById('kv-fwd').textContent     = fmtNum(forwarded);
  document.getElementById('kv-drop').textContent    = fmtNum(dropped);
  document.getElementById('kv-sample').textContent  = fmtNum(sampled);
  document.getElementById('kv-threats').textContent = fmtNum(threats);

  // Threat card pulsing accent
  const kpiThreats = document.getElementById('kpi-threats');
  if (threats > 0) kpiThreats.style.boxShadow = '0 0 0 1px rgba(220,38,38,0.4)';
  else kpiThreats.style.boxShadow = '';

  // Pipeline pipe counts
  document.getElementById('pipe-sources-count').textContent =
    `${state.sources.length} source${state.sources.length !== 1 ? 's' : ''}`;

  const fwdStatus = state.forwarding;
  if (fwdStatus) {
    const fwdEnabled = fwdStatus.enabled;
    document.getElementById('pipe-dmz-status').textContent =
      fwdEnabled ? `${fmtNum(fwdStatus.successful_forward_count || 0)} forwarded` : 'Disabled';
    const dmzIcon = document.getElementById('pipe-dmz-icon');
    dmzIcon.className = `pipeline-icon ${fwdEnabled ? 'success' : 'warning'}`;
  }

  // Charts
  const srcLabels = Object.keys(summary.by_source_type || {});
  const srcVals   = Object.values(summary.by_source_type || {});
  const catLabels = Object.keys(summary.by_category || {});
  const catVals   = Object.values(summary.by_category || {});
  const decLabels = Object.keys(summary.by_decision || {});
  const decVals   = Object.values(summary.by_decision || {});
  const tLabels   = (timeline || []).map(x => fmtTimeline(x.timestamp));
  const tVals     = (timeline || []).map(x => x.count || 0);

  const COLORS = [P.cyan, P.purple, P.warning, P.success, P.info, P.red, P.redHi];
  const decColorMap = {
    keep: P.success, drop: P.critical, sample: P.warning,
    forward_only: P.cyan, store_only: P.text2,
  };

  // Destroy & recreate charts
  if (charts.source)   { charts.source.destroy(); }
  if (charts.category) { charts.category.destroy(); }
  if (charts.decision) { charts.decision.destroy(); }
  if (charts.timeline) { charts.timeline.destroy(); }

  const gridColor = themeGrid();
  const textColor = themeText2();

  const noLegendBase = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: textColor, maxRotation: 30 }, grid: { color: gridColor } },
      y: { ticks: { color: textColor }, grid: { color: gridColor } },
    },
  };

  const cSrc = document.getElementById('c-source');
  if (cSrc) {
    charts.source = new Chart(cSrc, {
      type: 'doughnut',
      data: {
        labels: srcLabels,
        datasets: [{
          data: srcVals,
          backgroundColor: COLORS.slice(0, srcLabels.length),
          borderColor: 'transparent',
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '55%',
        plugins: {
          legend: {
            position: 'right',
            labels: { color: textColor, boxWidth: 10, padding: 8, font: { size: 11 } },
          },
        },
      },
    });
  }

  const cCat = document.getElementById('c-category');
  if (cCat) {
    charts.category = new Chart(cCat, {
      type: 'bar',
      data: {
        labels: catLabels,
        datasets: [{
          data: catVals,
          backgroundColor: catLabels.map((_, i) => COLORS[i % COLORS.length] + '30'),
          borderColor: catLabels.map((_, i) => COLORS[i % COLORS.length]),
          borderWidth: 1.5,
        }],
      },
      options: {
        ...noLegendBase,
        indexAxis: 'y',
        scales: {
          x: { ticks: { color: textColor }, grid: { color: gridColor } },
          y: { ticks: { color: textColor, font: { size: 10 } }, grid: { display: false } },
        },
      },
    });
  }

  const cDec = document.getElementById('c-decision');
  if (cDec) {
    const decColors = decLabels.map(l => decColorMap[l] || P.text2);
    charts.decision = new Chart(cDec, {
      type: 'bar',
      data: {
        labels: decLabels,
        datasets: [{
          data: decVals,
          backgroundColor: decColors.map(c => c + '25'),
          borderColor: decColors,
          borderWidth: 1.5,
          borderRadius: 4,
        }],
      },
      options: noLegendBase,
    });
  }

  const cTimeline = document.getElementById('c-timeline');
  if (cTimeline) {
    charts.timeline = new Chart(cTimeline, {
      type: 'line',
      data: {
        labels: tLabels,
        datasets: [{
          data: tVals,
          borderColor: P.red,
          backgroundColor: P.redLo,
          borderWidth: 1.5,
          pointRadius: tLabels.length > 60 ? 0 : 2,
          pointBackgroundColor: P.red,
          fill: true,
          tension: 0.4,
        }],
      },
      options: {
        ...noLegendBase,
        scales: {
          x: { ticks: { color: textColor, maxTicksLimit: 12 }, grid: { color: gridColor } },
          y: { ticks: { color: textColor }, grid: { color: gridColor } },
        },
      },
    });
  }

  // Dashboard recent events (last 10)
  const dashTbody = document.getElementById('dash-events-tbody');
  if (dashTbody) {
    const recent = state.events.slice(-10).reverse();
    dashTbody.innerHTML = recent.map(e => `
      <tr class="sev-row-${esc((e.severity || 'info').toLowerCase())}">
        <td class="mono" style="white-space:nowrap;font-size:11px;color:var(--text-2)">${esc(fmtTsShort(e.timestamp))}</td>
        <td>${srcBadge(e.source_type)}</td>
        <td>
          <span style="font-size:12px">${esc(e.asset_name || '—')}</span>
          ${e.asset_ip ? `<br/><span class="mono" style="color:var(--text-2);font-size:11px">${esc(e.asset_ip)}</span>` : ''}
        </td>
        <td>${sevBadge(e.severity)}</td>
        <td><span style="font-size:12px;color:var(--text-2)">${esc(e.event_category || '—')}</span></td>
        <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">${esc(e.message || '—')}</td>
      </tr>`).join('');
  }

  document.getElementById('timeline-rate').textContent =
    `${rate.toFixed(2)} ev/s`;
}

/* ── Messages ──────────────────────────────────────────────── */
let lastMsgCount = 0;

function renderMessages() {
  const tbody = document.getElementById('m-tbody');
  if (!tbody) return;

  const slice = state.events.slice(-400).reverse();
  const isNew = slice.length > lastMsgCount;
  lastMsgCount = slice.length;

  const critical = slice.filter(e => (e.severity || '').toLowerCase() === 'critical').length;

  document.getElementById('msg-count-visible').textContent = fmtNum(slice.length);
  document.getElementById('msg-count-total').textContent   = fmtNum(state.events.length);
  document.getElementById('msg-count-critical').textContent = fmtNum(critical);

  // Badge count in nav
  const navBadge = document.getElementById('nav-msg-count');
  if (navBadge) {
    if (slice.length > 0) {
      navBadge.textContent = fmtNum(slice.length);
      navBadge.style.display = 'inline-block';
    } else {
      navBadge.style.display = 'none';
    }
  }

  tbody.innerHTML = slice.map((e, i) => `
    <tr data-ev-idx="${i}"
        class="${i === 0 && isNew ? 'flash-new ' : ''}sev-row-${esc((e.severity || 'info').toLowerCase())}"
        style="cursor:pointer">
      <td class="mono" style="white-space:nowrap;font-size:11px;color:var(--text-2)">${esc(fmtTsShort(e.timestamp))}</td>
      <td>${srcBadge(e.source_type)}</td>
      <td>
        <span style="font-size:12px">${esc(e.asset_name || '—')}</span>
        ${e.asset_ip ? `<br/><span class="mono" style="color:var(--text-2);font-size:11px">${esc(e.asset_ip)}</span>` : ''}
      </td>
      <td>${sevBadge(e.severity)}</td>
      <td style="font-size:12px;color:var(--text-2)">${esc(e.event_category || '—')}</td>
      <td style="max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">${esc(e.message || '—')}</td>
    </tr>`).join('');

  // Row click → modal
  tbody.onclick = ev => {
    const tr = ev.target.closest('tr[data-ev-idx]');
    if (!tr) return;
    const item = state.events.slice(-400).reverse()[Number(tr.dataset.evIdx)];
    if (item) openEventModal(item);
  };

  // Ticker
  if (slice[0]) {
    const e = slice[0];
    document.getElementById('event-ticker').textContent =
      `${fmtTsShort(e.timestamp)} | ${e.source_type || '?'} | ${(e.severity || '').toUpperCase()} | ${e.message || ''}`;
  }
}

/* ── Event modal ───────────────────────────────────────────── */
function openEventModal(ev) {
  const summary = document.getElementById('modal-event-summary');
  const fields = [
    ['ID',         ev.id],
    ['Timestamp',  fmtTs(ev.timestamp)],
    ['Received',   fmtTs(ev.received_at)],
    ['Zone',       ev.zone],
    ['Source Type',ev.source_type],
    ['Asset Name', ev.asset_name],
    ['Asset IP',   ev.asset_ip],
    ['Severity',   ev.severity],
    ['Protocol',   ev.protocol],
    ['Category',   ev.event_category],
  ];

  summary.innerHTML = fields.map(([k, v]) => `
    <div class="event-summary-row">
      <span class="event-summary-label">${esc(k)}</span>
      <span class="event-summary-value">${esc(v || '—')}</span>
    </div>`).join('');

  document.getElementById('modal-json-body').textContent = JSON.stringify(ev, null, 2);

  const modal = document.getElementById('event-modal');
  modal.showModal();
}

/* ── Sources ───────────────────────────────────────────────── */
function renderSources() {
  const q = (document.getElementById('s-search')?.value || '').toLowerCase();
  const tbody = document.getElementById('s-tbody');
  if (!tbody) return;

  const rows = state.sources.filter(s =>
    JSON.stringify(s).toLowerCase().includes(q)
  );

  // Stat cards
  const total    = state.sources.length;
  const enabled  = state.sources.filter(s => s.enabled).length;
  const active   = state.sources.filter(s => s.enabled && s.ip).length;
  const disabled = state.sources.filter(s => !s.enabled).length;

  document.getElementById('src-stat-total').textContent   = total;
  document.getElementById('src-stat-enabled').textContent = enabled;
  document.getElementById('src-stat-active').textContent  = active;
  document.getElementById('src-stat-disabled').textContent = disabled;

  tbody.innerHTML = rows.map((s, idx) => `
    <tr>
      <td><input data-f="name" data-i="${idx}" value="${escAttr(s.name || '')}" style="width:130px" /></td>
      <td><input data-f="type" data-i="${idx}" value="${escAttr(s.type || '')}" style="width:90px" /></td>
      <td><input data-f="ip" data-i="${idx}" class="mono" value="${escAttr(s.ip || '')}" style="width:120px" /></td>
      <td><input data-f="protocol" data-i="${idx}" value="${escAttr(s.protocol || 'syslog')}" style="width:70px" /></td>
      <td><input data-f="zone" data-i="${idx}" value="${escAttr(s.zone || '')}" style="width:50px" /></td>
      <td><input data-f="impact" data-i="${idx}" value="${escAttr(s.impact || '')}" style="width:70px" /></td>
      <td style="text-align:center">
        <div class="toggle-switch">
          <input type="checkbox" data-f="enabled" data-i="${idx}" ${s.enabled ? 'checked' : ''} />
          <span class="toggle-slider"></span>
        </div>
      </td>
      <td style="text-align:center">
        <div class="toggle-switch">
          <input type="checkbox" data-f="forward_enabled" data-i="${idx}" ${s.forward_enabled ? 'checked' : ''} />
          <span class="toggle-slider"></span>
        </div>
      </td>
      <td><input data-f="notes" data-i="${idx}" value="${escAttr(s.notes || '')}" style="width:120px" /></td>
      <td>
        <button data-del="${idx}" class="btn-danger btn-sm">Del</button>
      </td>
    </tr>`).join('');

  tbody.querySelectorAll('input[data-f]').forEach(inp => {
    inp.addEventListener('change', () => {
      const i = Number(inp.dataset.i);
      const f = inp.dataset.f;
      state.sources[i][f] = inp.type === 'checkbox' ? inp.checked : inp.value;
    });
  });

  tbody.querySelectorAll('button[data-del]').forEach(b => {
    b.addEventListener('click', () => {
      state.sources.splice(Number(b.dataset.del), 1);
      renderSources();
    });
  });
}

/* ── Rules ─────────────────────────────────────────────────── */
let rulesModified = false;

function renderRules() {
  const tbody = document.getElementById('r-tbody');
  if (!tbody) return;

  // Stats
  const total   = state.rules.length;
  const enabled = state.rules.filter(r => r.enabled).length;
  const drop    = state.rules.filter(r => r.action === 'drop').length;
  const sample  = state.rules.filter(r => r.action === 'sample').length;
  const fwd     = state.rules.filter(r => r.forward_to_dmz).length;

  document.getElementById('rule-stat-total').textContent   = total;
  document.getElementById('rule-stat-enabled').textContent = enabled;
  document.getElementById('rule-stat-drop').textContent    = drop;
  document.getElementById('rule-stat-sample').textContent  = sample;
  document.getElementById('rule-stat-fwd').textContent     = fwd;

  tbody.innerHTML = state.rules.map((r, idx) => `
    <tr>
      <td style="color:var(--text-2);font-family:var(--font-mono);font-size:12px">${idx + 1}</td>
      <td style="text-align:center">
        <input type="checkbox" data-f="enabled" data-i="${idx}" ${r.enabled ? 'checked' : ''} />
      </td>
      <td><input data-f="source_type" data-i="${idx}" value="${escAttr(r.source_type || '*')}" style="width:80px" /></td>
      <td><input data-f="asset"       data-i="${idx}" value="${escAttr(r.asset || '*')}"       style="width:80px" /></td>
      <td><input data-f="category"    data-i="${idx}" value="${escAttr(r.category || '*')}"    style="width:100px" /></td>
      <td><input data-f="severity"    data-i="${idx}" value="${escAttr(r.severity || '*')}"    style="width:70px" /></td>
      <td><input data-f="operation"   data-i="${idx}" value="${escAttr(r.operation || '*')}"   style="width:70px" /></td>
      <td><input data-f="event_type"  data-i="${idx}" value="${escAttr(r.event_type || '*')}"  style="width:90px" /></td>
      <td><input data-f="message_contains" data-i="${idx}" value="${escAttr(r.message_contains || '')}" style="width:120px" /></td>
      <td>
        <input data-f="tag_key" data-i="${idx}" value="${escAttr(r.tag_key || '')}" style="width:80px" placeholder="key" />
        <input data-f="tag_value" data-i="${idx}" value="${escAttr(r.tag_value || '')}" style="width:70px;margin-top:4px" placeholder="value" />
      </td>
      <td>
        <select data-f="action" data-i="${idx}">
          ${['keep','drop','sample','forward_only','store_only','store_and_forward'].map(a =>
            `<option value="${a}" ${r.action === a ? 'selected' : ''}>${a}</option>`
          ).join('')}
        </select>
      </td>
      <td>
        <input type="number" min="0" max="1" step="0.05" data-f="sample_rate" data-i="${idx}"
          value="${Number(r.sample_rate ?? 1).toFixed(2)}" style="width:60px" />
      </td>
      <td>
        <input type="number" min="0" step="1" data-f="dedup_window_seconds" data-i="${idx}"
          value="${Number(r.dedup_window_seconds ?? 0)}" style="width:60px" />
      </td>
      <td>
        <input type="number" min="0" step="1" data-f="rate_limit_per_second" data-i="${idx}"
          value="${Number(r.rate_limit_per_second ?? 0)}" style="width:60px" />
      </td>
      <td style="text-align:center">
        <input type="checkbox" data-f="forward_to_dmz" data-i="${idx}" ${r.forward_to_dmz ? 'checked' : ''} />
      </td>
      <td style="text-align:center">
        <input type="checkbox" data-f="store_locally" data-i="${idx}" ${r.store_locally ? 'checked' : ''} />
      </td>
      <td style="text-align:center">
        <input type="checkbox" data-f="show_in_ui" data-i="${idx}" ${(r.show_in_ui ?? true) ? 'checked' : ''} />
      </td>
      <td><input data-f="notes" data-i="${idx}" value="${escAttr(r.notes || '')}" style="width:100px" /></td>
      <td style="white-space:nowrap">
        <button data-up="${idx}"  class="btn-ghost btn-sm" style="padding:4px 6px" title="Move up">↑</button>
        <button data-down="${idx}" class="btn-ghost btn-sm" style="padding:4px 6px" title="Move down">↓</button>
        <button data-del="${idx}" class="btn-danger btn-sm">Del</button>
      </td>
    </tr>`).join('');

  tbody.querySelectorAll('input[data-f], select[data-f]').forEach(inp => {
    inp.addEventListener('change', () => {
      const i = Number(inp.dataset.i);
      const f = inp.dataset.f;
      state.rules[i][f] = inp.type === 'checkbox' ? inp.checked :
                          inp.type === 'number'   ? Number(inp.value) : inp.value;
      markRulesModified();
    });
  });

  tbody.querySelectorAll('button[data-up]').forEach(b =>
    b.addEventListener('click', () => moveRule(Number(b.dataset.up), -1)));
  tbody.querySelectorAll('button[data-down]').forEach(b =>
    b.addEventListener('click', () => moveRule(Number(b.dataset.down), +1)));
  tbody.querySelectorAll('button[data-del]').forEach(b =>
    b.addEventListener('click', () => {
      state.rules.splice(Number(b.dataset.del), 1);
      renderRules();
      markRulesModified();
    }));
}

function moveRule(i, d) {
  const k = i + d;
  if (k < 0 || k >= state.rules.length) return;
  [state.rules[i], state.rules[k]] = [state.rules[k], state.rules[i]];
  renderRules();
  markRulesModified();
}

function markRulesModified() {
  rulesModified = true;
  const dot = document.getElementById('r-unsaved');
  if (dot) dot.style.display = 'inline-block';
}

/* ── Forwarding ────────────────────────────────────────────── */
function renderForwarding() {
  const f = state.forwarding;
  if (!f) return;

  // URL input
  const urlEl = document.getElementById('f-url');
  if (urlEl) urlEl.value = f.dmz_collector_url || '';

  // Toggles
  const enEl = document.getElementById('f-enabled');
  if (enEl) enEl.checked = !!f.enabled;

  // Status card
  const statusVal = document.getElementById('fwd-status-value');
  if (statusVal) {
    if (!f.enabled) {
      statusVal.textContent = 'Disabled';
      statusVal.style.color = 'var(--text-2)';
    } else if (f.forward_queue_status === 'connected' || f.successful_forward_count > 0) {
      statusVal.textContent = 'Connected';
      statusVal.style.color = 'var(--success)';
    } else if (f.last_error) {
      statusVal.textContent = 'Failed';
      statusVal.style.color = 'var(--critical)';
    } else {
      statusVal.textContent = 'Enabled';
      statusVal.style.color = 'var(--warning)';
    }
  }

  const urlDisplay = document.getElementById('fwd-url-display');
  if (urlDisplay) urlDisplay.textContent = f.dmz_collector_url || '—';

  const lastSuccess = document.getElementById('fwd-last-success');
  if (lastSuccess) lastSuccess.textContent = fmtTs(f.last_successful_forward_time) || '—';

  const lastError = document.getElementById('fwd-last-error');
  if (lastError) lastError.textContent = f.last_error || '—';

  // Stats cards
  const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = fmtNum(v); };
  el('fwd-stat-success',  f.successful_forward_count || 0);
  el('fwd-stat-failed',   f.failed_forward_count     || 0);
  el('fwd-stat-queued',   f.queued_count             || 0);
  el('fwd-stat-inflight', f.in_flight_count          || 0);
}

/* ── Settings ──────────────────────────────────────────────── */
function renderSettings(health) {
  if (!health) return;
  const set = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v || '—'; };
  set('set-zone',    health.zone);
  set('set-service', health.service);
  set('set-udp',     health.udp_syslog_port);
  set('set-tcp',     health.tcp_syslog_port);
  set('set-api',     health.api_port);
  set('set-file',    health.events_file);

  document.getElementById('sidebar-zone').textContent = health.zone ? `Zone ${health.zone}` : 'Zone OT';
  document.getElementById('sb-zone').textContent = `zone: ${health.zone || 'OT'}`;
}

/* ── Load all data ─────────────────────────────────────────── */
async function loadAll() {
  try {
    const [health, events, sources, rules, forwarding, summary, timeline] = await Promise.all([
      api('/health').catch(() => null),
      api(`/events?${new URLSearchParams(state.filters)}`).catch(() => []),
      api('/config/sources').catch(() => []),
      api('/config/rules').catch(() => []),
      api('/config/forwarding').catch(() => null),
      api('/stats/summary').catch(() => ({})),
      api('/stats/timeline').catch(() => []),
    ]);

    setHealth(!!(health && health.status === 'ok'));
    state.health     = health;
    state.events     = Array.isArray(events) ? events : [];
    state.sources    = Array.isArray(sources) ? sources : [];
    state.rules      = Array.isArray(rules) ? rules : [];
    state.forwarding = forwarding;

    renderMessages();
    renderSources();
    renderRules();
    renderForwarding();
    renderSettings(health);
    renderDashboard(summary || {}, timeline || []);
    hydrateMessageSourceFilter();

    const total = summary?.total_events || 0;
    document.getElementById('sb-event-count').textContent = `events: ${fmtNum(total)}`;

    setLastUpdated();
  } catch (e) {
    console.error('loadAll error:', e);
    setHealth(false);
  }
}

/* ── Refresh dashboard charts only (periodic) ──────────────── */
async function refreshDashboard() {
  try {
    const [summary, timeline] = await Promise.all([
      api('/stats/summary').catch(() => ({})),
      api('/stats/timeline').catch(() => []),
    ]);
    renderDashboard(summary || {}, timeline || []);
    document.getElementById('sb-event-count').textContent =
      `events: ${fmtNum(summary?.total_events || 0)}`;
    setLastUpdated();
  } catch(e) {}
}

/* ── Hydrate source filter dropdown ────────────────────────── */
function hydrateMessageSourceFilter() {
  const sel = document.getElementById('m-source');
  if (!sel) return;
  const types = [...new Set(state.sources.map(s => s.type).filter(Boolean))];
  sel.innerHTML = '<option value="">All Sources</option>' +
    types.map(t => `<option value="${escAttr(t)}">${esc(t)}</option>`).join('');
}

/* ── SSE stream ────────────────────────────────────────────── */
function connectStream() {
  if (state.es) { try { state.es.close(); } catch(e) {} }
  state.es = new EventSource('/events/stream');

  state.es.onopen = () => setHealth(true);

  state.es.onerror = () => {
    setHealth(false);
    // Reconnect after 5s
    setTimeout(() => {
      if (state.es && state.es.readyState === EventSource.CLOSED) {
        connectStream();
      }
    }, 5000);
  };

  state.es.addEventListener('event', ev => {
    if (state.streamPaused) return;
    try {
      const item = JSON.parse(ev.data);
      state.events.push(item);
      if (state.events.length > 3000) state.events.shift();
      state.eps++;
      renderMessages();
      // If dashboard is active, update recent feed
      if (state.currentPage === 'dashboard') {
        const dashTbody = document.getElementById('dash-events-tbody');
        if (dashTbody) {
          const recent = state.events.slice(-10).reverse();
          // lightweight: just re-render last 10
          dashTbody.innerHTML = recent.map(e => `
            <tr class="sev-row-${esc((e.severity || 'info').toLowerCase())}">
              <td class="mono" style="white-space:nowrap;font-size:11px;color:var(--text-2)">${esc(fmtTsShort(e.timestamp))}</td>
              <td>${srcBadge(e.source_type)}</td>
              <td>${esc(e.asset_name || '—')}${e.asset_ip ? `<br/><span class="mono" style="color:var(--text-2);font-size:11px">${esc(e.asset_ip)}</span>` : ''}</td>
              <td>${sevBadge(e.severity)}</td>
              <td style="font-size:12px;color:var(--text-2)">${esc(e.event_category || '—')}</td>
              <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">${esc(e.message || '—')}</td>
            </tr>`).join('');
        }
      }
    } catch(e) { console.warn('SSE parse error', e); }
  });
}

/* ── Rate counter ──────────────────────────────────────────── */
setInterval(() => {
  const rateEl = document.getElementById('rate-display');
  if (rateEl) rateEl.textContent = state.eps;
  state.eps = 0;
}, 1000);

/* ── Bind all UI interactions ──────────────────────────────── */
function bindAll() {
  bindNav();
  bindSidebar();
  bindTheme();

  // Refresh button
  document.getElementById('btn-refresh')?.addEventListener('click', () => loadAll());

  // Modal close
  document.getElementById('modal-close')?.addEventListener('click', () => {
    document.getElementById('event-modal')?.close();
  });
  document.getElementById('modal-close-btn')?.addEventListener('click', () => {
    document.getElementById('event-modal')?.close();
  });
  document.getElementById('modal-copy-json')?.addEventListener('click', () => {
    const text = document.getElementById('modal-json-body')?.textContent || '';
    navigator.clipboard.writeText(text).catch(() => {});
  });

  // Click outside modal to close
  document.getElementById('event-modal')?.addEventListener('click', ev => {
    if (ev.target === ev.currentTarget) ev.currentTarget.close();
  });

  // Messages filter
  document.getElementById('m-apply')?.addEventListener('click', async () => {
    state.filters.source_type = document.getElementById('m-source')?.value.trim() || '';
    state.filters.asset_ip    = '';
    state.filters.severity    = document.getElementById('m-sev')?.value.trim() || '';
    state.filters.category    = document.getElementById('m-cat')?.value.trim() || '';
    state.filters.search      = document.getElementById('m-search')?.value.trim() || '';
    try {
      state.events = await api(`/events?${new URLSearchParams(state.filters)}`);
    } catch(e) { state.events = []; }
    renderMessages();
  });

  document.getElementById('m-clear')?.addEventListener('click', () => {
    state.events = [];
    lastMsgCount = 0;
    renderMessages();
  });

  document.getElementById('m-pause')?.addEventListener('click', ev => {
    state.streamPaused = !state.streamPaused;
    ev.target.textContent = state.streamPaused ? 'Resume' : 'Pause';
    const indicator = document.getElementById('stream-indicator');
    const stateTxt  = document.getElementById('stream-state-txt');
    if (indicator) indicator.classList.toggle('paused', state.streamPaused);
    if (stateTxt)  stateTxt.textContent = state.streamPaused ? 'Paused' : 'Live';
  });

  document.getElementById('m-export')?.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(state.events, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `ot-events-${Date.now()}.json`;
    a.click();
  });

  // Sources
  document.getElementById('s-search')?.addEventListener('input', renderSources);

  document.getElementById('s-add')?.addEventListener('click', () => {
    state.sources.push({
      id: `src-${Date.now()}`,
      name: 'New Source',
      type: 'unknown',
      ip: '',
      protocol: 'syslog',
      impact: 'medium',
      zone: 'OT',
      enabled: true,
      forward_enabled: true,
      notes: '',
    });
    renderSources();
  });

  document.getElementById('s-save')?.addEventListener('click', async () => {
    try {
      await api('/config/sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(state.sources),
      });
      await loadAll();
    } catch(e) { console.error('Save sources error', e); }
  });

  document.getElementById('s-reset')?.addEventListener('click', async () => {
    if (!confirm('Reset sources to defaults?')) return;
    try {
      await api('/config/sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([]),
      });
      await loadAll();
    } catch(e) { console.error('Reset sources error', e); }
  });

  // Rules
  document.getElementById('r-add')?.addEventListener('click', () => {
    state.rules.push({
      id: `rule-${Date.now()}`,
      enabled: true,
      source_type: '*',
      asset: '*',
      category: '*',
      severity: '*',
      operation: '*',
      event_type: '*',
      message_contains: '',
      tag_key: '',
      tag_value: '',
      action: 'keep',
      sample_rate: 1,
      dedup_window_seconds: 0,
      rate_limit_per_second: 0,
      forward_to_dmz: false,
      store_locally: true,
      show_in_ui: true,
      notes: '',
    });
    renderRules();
    markRulesModified();
  });

  document.getElementById('r-save')?.addEventListener('click', async () => {
    try {
      await api('/config/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(state.rules),
      });
      rulesModified = false;
      const dot = document.getElementById('r-unsaved');
      if (dot) dot.style.display = 'none';
      await loadAll();
    } catch(e) { console.error('Save rules error', e); }
  });

  // Rule tester toggle
  document.getElementById('r-tester-toggle')?.addEventListener('click', ev => {
    const body = document.getElementById('r-tester-body');
    if (!body) return;
    const visible = body.style.display !== 'none';
    body.style.display = visible ? 'none' : 'block';
    ev.target.textContent = visible ? 'Expand' : 'Collapse';
  });

  // Rule test run
  document.getElementById('r-test')?.addEventListener('click', async () => {
    const resultEl = document.getElementById('r-test-result');
    if (!resultEl) return;
    try {
      const payload = JSON.parse(document.getElementById('r-test-json')?.value || '{}');
      const res = await api('/config/rules/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      resultEl.style.display = 'block';
      const matched = !!(res.matched_rule_id);
      resultEl.innerHTML = `
        <div class="rule-result-card ${matched ? 'matched' : 'no-match'}">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
            <span style="font-weight:600;font-size:13px;color:${matched ? 'var(--success)' : 'var(--warning)'}">
              ${matched ? 'Rule Matched' : 'No Match (default action)'}
            </span>
          </div>
          ${[
            ['Matched Rule', res.matched_rule_id || '—'],
            ['Drop',         String(res.drop ?? '—')],
            ['Forward',      String(res.forward ?? '—')],
            ['Store',        String(res.store ?? '—')],
            ['Show',         String(res.show ?? '—')],
            ['Sampled',      String(res.sampled ?? '—')],
            ['Reason',       res.decision_reason || '—'],
          ].map(([k, v]) => `
            <div class="test-result-row">
              <span class="test-result-key">${esc(k)}</span>
              <span class="test-result-val">${esc(v)}</span>
            </div>`).join('')}
        </div>`;
    } catch (e) {
      if (resultEl) {
        resultEl.style.display = 'block';
        resultEl.innerHTML = `<div class="result-box" style="color:var(--critical)">${esc(String(e))}</div>`;
      }
    }
  });

  // Forwarding save
  document.getElementById('f-save')?.addEventListener('click', async () => {
    if (!state.forwarding) return;
    state.forwarding.dmz_collector_url = document.getElementById('f-url')?.value.trim() || '';
    state.forwarding.enabled           = document.getElementById('f-enabled')?.checked || false;
    try {
      await api('/config/forwarding', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(state.forwarding),
      });
      await loadAll();
    } catch(e) { console.error('Save forwarding error', e); }
  });

  // Forwarding test
  document.getElementById('f-test')?.addEventListener('click', async () => {
    const card = document.getElementById('fwd-test-result-card');
    const body = document.getElementById('fwd-test-result-body');
    if (!card || !body) return;
    card.style.display = 'block';
    body.innerHTML = '<span style="color:var(--text-2);font-size:13px">Testing connection...</span>';
    try {
      const res = await api('/forwarding/test', { method: 'POST' });
      const ok = res.success === true;
      body.innerHTML = [
        ['Status',      ok ? 'Success' : 'Failed'],
        ['Status Code', res.status_code || '—'],
        ['Error',       res.error || '—'],
      ].map(([k, v]) => `
        <div class="test-result-row">
          <span class="test-result-key">${esc(k)}</span>
          <span class="test-result-val" style="${k === 'Status' ? `color:${ok ? 'var(--success)' : 'var(--critical)'}` : ''}">${esc(String(v))}</span>
        </div>`).join('');
    } catch (e) {
      body.innerHTML = `<div style="color:var(--critical);font-size:13px">${esc(String(e))}</div>`;
    }
  });

  // Forwarding reset queue
  document.getElementById('f-reset-queue')?.addEventListener('click', async () => {
    if (!confirm('Reset the forwarding queue? This will discard queued events.')) return;
    try {
      await api('/forwarding/reset-queue', { method: 'POST' });
      await loadAll();
    } catch(e) { console.error('Reset queue error', e); }
  });

  // Storage repair
  document.getElementById('st-repair')?.addEventListener('click', async () => {
    const out = document.getElementById('st-out');
    if (!out) return;
    out.style.display = 'block';
    out.textContent = 'Repairing...';
    try {
      const res = await api('/storage/repair', { method: 'POST' });
      out.textContent = JSON.stringify(res, null, 2);
    } catch(e) {
      out.textContent = String(e);
    }
  });
}

/* ── Periodic refresh ──────────────────────────────────────── */
setInterval(refreshDashboard, 5000);

/* ── Boot ──────────────────────────────────────────────────── */
async function boot() {
  bindAll();
  switchPage('dashboard');
  await loadAll();
  connectStream();
}

boot().catch(e => { console.error('Boot error:', e); setHealth(false); });
