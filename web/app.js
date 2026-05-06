const state = {
  events: [],
  paused: false,
  stream: null,
  filters: {
    source_type: "",
    severity: "",
    category: "",
    asset_ip: "",
    search: "",
    limit: 200,
  },
  rateCounter: 0,
};

const MAX_ROWS = 1200;

const el = {
  status: document.getElementById("status"),
  rate: document.getElementById("event-rate"),
  eventsBody: document.getElementById("events-body"),
  eventCount: document.getElementById("event-count"),
  summaryJson: document.getElementById("summary-json"),
  toggleStream: document.getElementById("toggle-stream"),
  exportJson: document.getElementById("export-json"),
  applyFilters: document.getElementById("apply-filters"),
  resetFilters: document.getElementById("reset-filters"),
  filterSource: document.getElementById("filter-source"),
  filterSeverity: document.getElementById("filter-severity"),
  filterCategory: document.getElementById("filter-category"),
  filterAsset: document.getElementById("filter-asset"),
  filterSearch: document.getElementById("filter-search"),
  dialog: document.getElementById("event-dialog"),
  dialogJson: document.getElementById("event-json"),
  closeDialog: document.getElementById("close-dialog"),
  cfgDropReads: document.getElementById("cfg-drop-reads"),
  cfgDedup: document.getElementById("cfg-dedup"),
  cfgSampleRate: document.getElementById("cfg-sample-rate"),
  cfgRateLimit: document.getElementById("cfg-rate-limit"),
  saveFilterConfig: document.getElementById("save-filter-config"),
};

let sourceChart;
let severityChart;
let timelineChart;

function setStatus(up) {
  el.status.textContent = up ? "online" : "offline";
  el.status.classList.toggle("status-up", up);
  el.status.classList.toggle("status-down", !up);
}

function qs(params) {
  const u = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== "" && v != null) u.set(k, String(v));
  });
  return u.toString();
}

async function loadEvents() {
  const res = await fetch(`/events?${qs(state.filters)}`);
  const data = await res.json();
  state.events = data;
  renderEvents();
}

function renderEvents() {
  const rows = state.events.slice(-MAX_ROWS).reverse();
  el.eventsBody.innerHTML = rows
    .map((e) => {
      const sev = (e.severity || "info").toLowerCase();
      const msg = escapeHtml(e.message || "");
      return `<tr data-event='${escapeAttr(JSON.stringify(e))}'>
        <td>${escapeHtml(e.timestamp || "")}</td>
        <td>${escapeHtml(e.source_type || "")}</td>
        <td>${escapeHtml(e.asset_name || "")}</td>
        <td class="sev-${sev}">${escapeHtml(e.severity || "")}</td>
        <td>${escapeHtml(e.event_category || "")}</td>
        <td>${msg}</td>
      </tr>`;
    })
    .join("");
  el.eventCount.textContent = `${rows.length} events`;
}

function connectStream() {
  if (state.stream) state.stream.close();
  state.stream = new EventSource("/events/stream");

  state.stream.onopen = () => setStatus(true);
  state.stream.onerror = () => setStatus(false);

  state.stream.addEventListener("event", (ev) => {
    if (state.paused) return;
    state.rateCounter += 1;
    const data = JSON.parse(ev.data);
    if (!matchesActiveFilters(data)) return;
    state.events.push(data);
    if (state.events.length > MAX_ROWS) state.events.shift();
    renderEvents();
  });
}

function matchesActiveFilters(e) {
  if (state.filters.source_type && e.source_type !== state.filters.source_type) return false;
  if (state.filters.severity && e.severity !== state.filters.severity) return false;
  if (state.filters.category && e.event_category !== state.filters.category) return false;
  if (state.filters.asset_ip && e.asset_ip !== state.filters.asset_ip) return false;
  if (state.filters.search) {
    const s = state.filters.search.toLowerCase();
    const blob = JSON.stringify(e).toLowerCase();
    if (!blob.includes(s)) return false;
  }
  return true;
}

async function refreshStats() {
  const [summaryRes, timelineRes] = await Promise.all([
    fetch("/stats/summary"),
    fetch("/stats/timeline"),
  ]);
  const summary = await summaryRes.json();
  const timeline = await timelineRes.json();

  el.summaryJson.textContent = JSON.stringify(summary, null, 2);
  renderCharts(summary, timeline);
}

function renderCharts(summary, timeline) {
  const sourceLabels = Object.keys(summary.by_source_type || {});
  const sourceValues = Object.values(summary.by_source_type || {});
  const severityLabels = Object.keys(summary.by_severity || {});
  const severityValues = Object.values(summary.by_severity || {});
  const timelineLabels = timeline.map((x) => x.timestamp.slice(11, 16));
  const timelineValues = timeline.map((x) => x.count);

  if (sourceChart) sourceChart.destroy();
  sourceChart = new Chart(document.getElementById("source-chart"), {
    type: "pie",
    data: {
      labels: sourceLabels,
      datasets: [{ data: sourceValues }],
    },
  });

  if (severityChart) severityChart.destroy();
  severityChart = new Chart(document.getElementById("severity-chart"), {
    type: "bar",
    data: {
      labels: severityLabels,
      datasets: [{ data: severityValues }],
    },
  });

  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(document.getElementById("timeline-chart"), {
    type: "line",
    data: {
      labels: timelineLabels,
      datasets: [{ data: timelineValues }],
    },
    options: { responsive: true, maintainAspectRatio: false },
  });
}

async function loadFilterConfig() {
  const res = await fetch("/filter/config");
  const cfg = await res.json();
  el.cfgDropReads.checked = !!cfg.drop_opcua_reads;
  el.cfgDedup.checked = !!cfg.drop_duplicates;
  el.cfgSampleRate.value = Number(cfg.sample_rate ?? 0.2);
  el.cfgRateLimit.value = Number(cfg.max_events_per_second ?? 500);
}

async function saveFilterConfig() {
  const payload = {
    drop_opcua_reads: el.cfgDropReads.checked,
    drop_duplicates: el.cfgDedup.checked,
    sample_rate: Number(el.cfgSampleRate.value || 0),
    dedup_window_seconds: 5,
    max_events_per_second: Number(el.cfgRateLimit.value || 0),
    opcua_read_keep_every: 0,
  };
  await fetch("/filter/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

function bindActions() {
  el.applyFilters.addEventListener("click", () => {
    state.filters.source_type = el.filterSource.value.trim();
    state.filters.severity = el.filterSeverity.value.trim();
    state.filters.category = el.filterCategory.value.trim();
    state.filters.asset_ip = el.filterAsset.value.trim();
    state.filters.search = el.filterSearch.value.trim();
    loadEvents().catch(console.error);
  });

  el.resetFilters.addEventListener("click", () => {
    el.filterSource.value = "";
    el.filterSeverity.value = "";
    el.filterCategory.value = "";
    el.filterAsset.value = "";
    el.filterSearch.value = "";
    state.filters.source_type = "";
    state.filters.severity = "";
    state.filters.category = "";
    state.filters.asset_ip = "";
    state.filters.search = "";
    loadEvents().catch(console.error);
  });

  el.toggleStream.addEventListener("click", () => {
    state.paused = !state.paused;
    el.toggleStream.textContent = state.paused ? "Resume Stream" : "Pause Stream";
  });

  el.exportJson.addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(state.events, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ot-events.json";
    a.click();
    URL.revokeObjectURL(url);
  });

  el.eventsBody.addEventListener("click", (ev) => {
    const row = ev.target.closest("tr[data-event]");
    if (!row) return;
    const raw = row.getAttribute("data-event");
    const item = JSON.parse(raw);
    el.dialogJson.textContent = JSON.stringify(item, null, 2);
    el.dialog.showModal();
  });

  el.closeDialog.addEventListener("click", () => el.dialog.close());
  el.saveFilterConfig.addEventListener("click", () => {
    saveFilterConfig().catch(console.error);
  });
}

setInterval(() => {
  el.rate.textContent = `${state.rateCounter} ev/s`;
  state.rateCounter = 0;
}, 1000);

setInterval(() => {
  refreshStats().catch(console.error);
}, 5000);

function escapeHtml(s) {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttr(s) {
  return s.replaceAll("&", "&amp;").replaceAll("'", "&#39;");
}

async function bootstrap() {
  bindActions();
  await Promise.all([loadEvents(), refreshStats(), loadFilterConfig()]);
  connectStream();
}

bootstrap().catch((err) => {
  console.error(err);
  setStatus(false);
});

