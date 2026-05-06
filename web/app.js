const state = {
  events: [],
  streamPaused: false,
  es: null,
  eps: 0,
  sources: [],
  rules: [],
  forwarding: null,
  filters: { limit: 200, source_type: "", asset_ip: "", severity: "", category: "", search: "" },
};

const el = {
  healthPill: document.getElementById("health-pill"),
  ratePill: document.getElementById("rate-pill"),
  tabs: [...document.querySelectorAll(".tabs button")],
  tabDashboard: document.getElementById("tab-dashboard"),
  tabMessages: document.getElementById("tab-messages"),
  tabSources: document.getElementById("tab-sources"),
  tabRules: document.getElementById("tab-rules"),
  tabForwarding: document.getElementById("tab-forwarding"),
  tabSettings: document.getElementById("tab-settings"),
  modal: document.getElementById("json-modal"),
  modalBody: document.getElementById("json-modal-body"),
  modalClose: document.getElementById("json-modal-close"),
};

let sourceChart; let categoryChart; let decisionChart; let timelineChart;

function renderShell() {
  el.tabDashboard.innerHTML = `
    <div id="kpis" class="grid"></div>
    <div class="grid">
      <div class="card chart"><canvas id="c-source"></canvas></div>
      <div class="card chart"><canvas id="c-category"></canvas></div>
      <div class="card chart"><canvas id="c-decision"></canvas></div>
      <div class="card full"><canvas id="c-timeline"></canvas></div>
    </div>`;

  el.tabMessages.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <select id="m-source"><option value="">source: all</option></select>
        <input id="m-asset" placeholder="asset ip" class="mono" />
        <select id="m-sev"><option value="">severity: all</option><option>info</option><option>warning</option><option>error</option><option>critical</option></select>
        <select id="m-cat"><option value="">category: all</option><option>operator_action</option><option>operator_read</option><option>operator_write</option><option>security</option><option>network</option><option>system</option><option>runtime</option></select>
        <input id="m-search" placeholder="search text" />
        <button id="m-apply" class="primary">Apply</button>
        <button id="m-pause">Pause Stream</button>
        <button id="m-clear" class="ghost">Clear View</button>
        <button id="m-export" class="ghost">Export JSON</button>
      </div>
      <table><thead><tr>
        <th>timestamp</th><th>source</th><th>asset</th><th>severity</th><th>category</th><th>message</th>
      </tr></thead><tbody id="m-tbody"></tbody></table>
    </div>`;

  el.tabSources.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <input id="s-search" placeholder="search sources" />
        <button id="s-add" class="primary">+ Add Source</button>
        <button id="s-save">Save Sources</button>
        <button id="s-reset" class="ghost">Reset Defaults</button>
      </div>
      <table><thead><tr>
        <th>Name</th><th>Type</th><th>IP Address</th><th>Protocol</th><th>Impact</th><th>Zone</th><th>State</th><th>Actions</th>
      </tr></thead><tbody id="s-tbody"></tbody></table>
    </div>`;

  el.tabRules.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <button id="r-add" class="primary">+ Add Rule</button>
        <button id="r-save">Save Rules</button>
      </div>
      <table><thead><tr>
        <th>Enabled</th><th>Source Type</th><th>Asset</th><th>Category</th><th>Severity</th><th>Operation</th><th>Action</th><th>Sample Rate</th><th>Forward</th><th>Store</th><th>Notes</th><th>Actions</th>
      </tr></thead><tbody id="r-tbody"></tbody></table>
      <h3 style="margin-top:10px;">Rule Test</h3>
      <textarea id="r-test-json" rows="6" placeholder='{"event":{"source_type":"opcua","event_category":"operator_action","tags":{"opcua_operation":"READ"}}}'></textarea>
      <div class="toolbar">
        <button id="r-test" class="primary">Test Rule</button>
        <pre id="r-test-out"></pre>
      </div>
    </div>`;

  el.tabForwarding.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <input id="f-url" class="mono" placeholder="DMZ Collector URL" />
        <label><input type="checkbox" id="f-enabled" /> forwarding enabled</label>
        <label><input type="checkbox" id="f-only-filtered" /> forward only filtered events</label>
      </div>
      <div class="toolbar">
        <button id="f-save" class="primary">Save Forwarding</button>
        <button id="f-test">Test Connection</button>
      </div>
      <pre id="f-state"></pre>
    </div>`;

  el.tabSettings.innerHTML = `<div class="card"><h3>Settings</h3><p>Collector settings are managed via API and compose env.</p></div>`;
}

function switchTab(name) {
  [...document.querySelectorAll(".tab")].forEach((n) => n.classList.remove("active"));
  [...document.querySelectorAll(".tabs button")].forEach((n) => n.classList.remove("active"));
  document.getElementById(`tab-${name}`).classList.add("active");
  document.querySelector(`.tabs button[data-tab="${name}"]`).classList.add("active");
}

function bindTabs() { el.tabs.forEach((b) => b.onclick = () => switchTab(b.dataset.tab)); }

async function j(url, opt) { const r = await fetch(url, opt); if (!r.ok) throw new Error(`${r.status}`); return r.json(); }

function renderMessages() {
  const tbody = document.getElementById("m-tbody");
  tbody.innerHTML = state.events.slice(-400).reverse().map((e, i) => `
    <tr data-i="${i}">
      <td class="mono">${esc(e.timestamp || "")}</td>
      <td><span class="badge">${esc(e.source_type || "")}</span></td>
      <td>${esc(e.asset_name || "")}<br/><span class="mono">${esc(e.asset_ip || "")}</span></td>
      <td class="sev-${esc((e.severity || "info").toLowerCase())}">${esc(e.severity || "")}</td>
      <td>${esc(e.event_category || "")}</td>
      <td>${esc(e.message || "")}</td>
    </tr>
  `).join("");
  tbody.onclick = (ev) => {
    const tr = ev.target.closest("tr[data-i]"); if (!tr) return;
    const idx = Number(tr.dataset.i); const item = state.events.slice(-400).reverse()[idx];
    el.modalBody.textContent = JSON.stringify(item, null, 2); el.modal.showModal();
  };
}

function renderSources() {
  const q = (document.getElementById("s-search")?.value || "").toLowerCase();
  const tbody = document.getElementById("s-tbody");
  const rows = state.sources.filter((s) => JSON.stringify(s).toLowerCase().includes(q));
  tbody.innerHTML = rows.map((s, idx) => `
    <tr>
      <td><input data-f="name" data-i="${idx}" value="${escAttr(s.name || "")}" /></td>
      <td><input data-f="type" data-i="${idx}" value="${escAttr(s.type || "")}" /></td>
      <td><input data-f="ip" data-i="${idx}" class="mono" value="${escAttr(s.ip || "")}" /></td>
      <td><input data-f="protocol" data-i="${idx}" value="${escAttr(s.protocol || "syslog")}" /></td>
      <td><input data-f="impact" data-i="${idx}" value="${escAttr(s.impact || "")}" /></td>
      <td><input data-f="zone" data-i="${idx}" value="${escAttr(s.zone || "")}" /></td>
      <td><label><input type="checkbox" data-f="enabled" data-i="${idx}" ${s.enabled ? "checked" : ""}/> enabled</label></td>
      <td><button data-del="${idx}">Delete</button></td>
    </tr>`).join("");
  tbody.querySelectorAll("input").forEach((inp) => {
    inp.onchange = () => {
      const i = Number(inp.dataset.i), f = inp.dataset.f;
      state.sources[i][f] = inp.type === "checkbox" ? inp.checked : inp.value;
    };
  });
  tbody.querySelectorAll("button[data-del]").forEach((b) => b.onclick = () => {
    state.sources.splice(Number(b.dataset.del), 1); renderSources();
  });
}

function renderRules() {
  const tbody = document.getElementById("r-tbody");
  tbody.innerHTML = state.rules.map((r, idx) => `
    <tr>
      <td><input type="checkbox" data-f="enabled" data-i="${idx}" ${r.enabled ? "checked" : ""}></td>
      <td><input data-f="source_type" data-i="${idx}" value="${escAttr(r.source_type || "*")}"></td>
      <td><input data-f="asset" data-i="${idx}" value="${escAttr(r.asset || "*")}"></td>
      <td><input data-f="category" data-i="${idx}" value="${escAttr(r.category || "*")}"></td>
      <td><input data-f="severity" data-i="${idx}" value="${escAttr(r.severity || "*")}"></td>
      <td><input data-f="operation" data-i="${idx}" value="${escAttr(r.operation || "*")}"></td>
      <td><select data-f="action" data-i="${idx}">${["keep","drop","sample","forward_only","store_only"].map((a)=>`<option ${r.action===a?"selected":""}>${a}</option>`).join("")}</select></td>
      <td><input type="number" min="0" max="1" step="0.05" data-f="sample_rate" data-i="${idx}" value="${Number(r.sample_rate || 1)}"></td>
      <td><input type="checkbox" data-f="forward_to_dmz" data-i="${idx}" ${r.forward_to_dmz ? "checked" : ""}></td>
      <td><input type="checkbox" data-f="store_locally" data-i="${idx}" ${r.store_locally ? "checked" : ""}></td>
      <td><input data-f="notes" data-i="${idx}" value="${escAttr(r.notes || "")}"></td>
      <td><button data-up="${idx}">↑</button><button data-down="${idx}">↓</button><button data-del="${idx}">Del</button></td>
    </tr>`).join("");
  tbody.querySelectorAll("input,select").forEach((inp) => {
    inp.onchange = () => {
      const i = Number(inp.dataset.i), f = inp.dataset.f;
      state.rules[i][f] = inp.type === "checkbox" ? inp.checked : (inp.type === "number" ? Number(inp.value) : inp.value);
    };
  });
  tbody.querySelectorAll("button[data-up]").forEach((b) => b.onclick = () => moveRule(Number(b.dataset.up), -1));
  tbody.querySelectorAll("button[data-down]").forEach((b) => b.onclick = () => moveRule(Number(b.dataset.down), +1));
  tbody.querySelectorAll("button[data-del]").forEach((b) => b.onclick = () => { state.rules.splice(Number(b.dataset.del), 1); renderRules(); });
}

function moveRule(i, d) {
  const j = i + d; if (j < 0 || j >= state.rules.length) return;
  const t = state.rules[i]; state.rules[i] = state.rules[j]; state.rules[j] = t; renderRules();
}

function renderForwarding() {
  if (!state.forwarding) return;
  document.getElementById("f-url").value = state.forwarding.dmz_collector_url || "";
  document.getElementById("f-enabled").checked = !!state.forwarding.enabled;
  document.getElementById("f-only-filtered").checked = !!state.forwarding.forward_only_filtered_events;
  document.getElementById("f-state").textContent = JSON.stringify(state.forwarding, null, 2);
}

function renderDashboard(summary, timeline) {
  const kpis = document.getElementById("kpis");
  kpis.innerHTML = [
    ["total events", summary.total_events || 0],
    ["event rate/sec", summary.event_rate_per_second || 0],
    ["forwarded", summary.forwarded_count || 0],
    ["dropped", summary.dropped_count || 0],
    ["sampled", summary.sampled_count || 0],
    ["critical+security", (summary.by_category?.security || 0) + (summary.by_severity?.critical || 0)],
  ].map(([k,v]) => `<div class="card kpi"><h2>${k}</h2><div class="v">${v}</div></div>`).join("");

  const srcLabels = Object.keys(summary.by_source_type || {}), srcVals = Object.values(summary.by_source_type || {});
  const catLabels = Object.keys(summary.by_category || {}), catVals = Object.values(summary.by_category || {});
  const decLabels = Object.keys(summary.by_decision || {}), decVals = Object.values(summary.by_decision || {});
  const tLabels = (timeline || []).map((x) => (x.timestamp || "").slice(11,16));
  const tVals = (timeline || []).map((x) => x.count || 0);

  if (sourceChart) sourceChart.destroy();
  if (categoryChart) categoryChart.destroy();
  if (decisionChart) decisionChart.destroy();
  if (timelineChart) timelineChart.destroy();
  sourceChart = new Chart(document.getElementById("c-source"), { type: "pie", data: { labels: srcLabels, datasets: [{ data: srcVals }] } });
  categoryChart = new Chart(document.getElementById("c-category"), { type: "bar", data: { labels: catLabels, datasets: [{ data: catVals }] } });
  decisionChart = new Chart(document.getElementById("c-decision"), { type: "bar", data: { labels: decLabels, datasets: [{ data: decVals }] } });
  timelineChart = new Chart(document.getElementById("c-timeline"), { type: "line", data: { labels: tLabels, datasets: [{ data: tVals }] } });
}

async function loadAll() {
  const [health, events, sources, rules, forwarding, summary, timeline] = await Promise.all([
    j("/health"), j(`/events?${new URLSearchParams(state.filters)}`), j("/config/sources"), j("/config/rules"), j("/config/forwarding"), j("/stats/summary"), j("/stats/timeline")
  ]);
  setHealth(health.status === "ok");
  state.events = events;
  state.sources = sources;
  state.rules = rules;
  state.forwarding = forwarding;
  renderMessages(); renderSources(); renderRules(); renderForwarding(); renderDashboard(summary, timeline);
  hydrateMessageSourceFilter();
}

function hydrateMessageSourceFilter() {
  const s = document.getElementById("m-source");
  if (!s) return;
  s.innerHTML = `<option value="">source: all</option>` + [...new Set(state.sources.map((x) => x.type).filter(Boolean))].map((t) => `<option>${t}</option>`).join("");
}

function bind() {
  bindTabs();
  el.modalClose.onclick = () => el.modal.close();

  document.getElementById("m-apply").onclick = async () => {
    state.filters.source_type = document.getElementById("m-source").value.trim();
    state.filters.asset_ip = document.getElementById("m-asset").value.trim();
    state.filters.severity = document.getElementById("m-sev").value.trim();
    state.filters.category = document.getElementById("m-cat").value.trim();
    state.filters.search = document.getElementById("m-search").value.trim();
    state.events = await j(`/events?${new URLSearchParams(state.filters)}`);
    renderMessages();
  };
  document.getElementById("m-clear").onclick = () => { state.events = []; renderMessages(); };
  document.getElementById("m-pause").onclick = (ev) => {
    state.streamPaused = !state.streamPaused;
    ev.target.textContent = state.streamPaused ? "Resume Stream" : "Pause Stream";
  };
  document.getElementById("m-export").onclick = () => {
    const blob = new Blob([JSON.stringify(state.events, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "filtered-events.json"; a.click();
  };

  document.getElementById("s-search").oninput = renderSources;
  document.getElementById("s-add").onclick = () => {
    state.sources.push({ id: `src-${Date.now()}`, name: "New Source", type: "unknown", ip: "", protocol: "syslog", impact: "medium", zone: "L2", enabled: true, forward_enabled: true, notes: "" });
    renderSources();
  };
  document.getElementById("s-save").onclick = async () => { await j("/config/sources", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(state.sources) }); await loadAll(); };
  document.getElementById("s-reset").onclick = async () => { await j("/config/sources", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify([]) }); await loadAll(); };

  document.getElementById("r-add").onclick = () => {
    state.rules.push({ id: `rule-${Date.now()}`, enabled: true, source_type: "*", asset: "*", category: "*", severity: "*", operation: "*", action: "keep", sample_rate: 1, forward_to_dmz: false, store_locally: true, notes: "" });
    renderRules();
  };
  document.getElementById("r-save").onclick = async () => { await j("/config/rules", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(state.rules) }); await loadAll(); };
  document.getElementById("r-test").onclick = async () => {
    const payload = JSON.parse(document.getElementById("r-test-json").value || "{}");
    const out = await j("/config/rules/test", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(payload) });
    document.getElementById("r-test-out").textContent = JSON.stringify(out, null, 2);
  };

  document.getElementById("f-save").onclick = async () => {
    state.forwarding.dmz_collector_url = document.getElementById("f-url").value.trim();
    state.forwarding.enabled = document.getElementById("f-enabled").checked;
    state.forwarding.forward_only_filtered_events = document.getElementById("f-only-filtered").checked;
    await j("/config/forwarding", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(state.forwarding) });
    await loadAll();
  };
  document.getElementById("f-test").onclick = async () => {
    const out = await j("/forwarding/test", { method: "POST" }).catch((e) => ({ error: String(e) }));
    document.getElementById("f-state").textContent = JSON.stringify(out, null, 2);
  };
}

function connectStream() {
  if (state.es) state.es.close();
  state.es = new EventSource("/events/stream");
  state.es.onopen = () => setHealth(true);
  state.es.onerror = () => setHealth(false);
  state.es.addEventListener("event", (ev) => {
    if (state.streamPaused) return;
    state.eps++;
    const item = JSON.parse(ev.data);
    state.events.push(item);
    if (state.events.length > 3000) state.events.shift();
    renderMessages();
  });
}

function setHealth(ok) {
  el.healthPill.classList.toggle("online", ok);
  el.healthPill.classList.toggle("offline", !ok);
  el.healthPill.textContent = ok ? "online" : "offline";
}

setInterval(() => { el.ratePill.textContent = `${state.eps} ev/s`; state.eps = 0; }, 1000);
setInterval(async () => {
  const [summary, timeline] = await Promise.all([j("/stats/summary"), j("/stats/timeline")]).catch(() => [null, null]);
  if (summary && timeline) renderDashboard(summary, timeline);
}, 5000);

function esc(s) { return String(s || "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;"); }
function escAttr(s) { return esc(s).replaceAll("\n", " "); }

async function boot() {
  renderShell();
  bind();
  await loadAll();
  connectStream();
}

boot().catch((e) => { console.error(e); setHealth(false); });

