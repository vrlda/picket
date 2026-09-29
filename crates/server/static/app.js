const TOKEN_KEY = "watchtower_token";
const KINDS = ["Reboot", "ServiceFailed", "ServiceCrashLoop", "DiskHigh", "InodeHigh",
               "CpuSpike", "MemHigh", "LoadHigh", "SwapHigh", "NetDevErrors",
               "HostUnreachable", "SshLogin", "SshFailed", "SshBruteForce", "RootLogin",
               "SudoUsed", "FileChanged", "NewListeningPort", "NewOutboundConnection",
               "ConnectionRateSpike", "ServiceRestarted", "AgentHeartbeatMissing",
               "AgentQueueGrowing", "ErrorRateSpike", "ContainerStopped",
               "ContainerCrashLoop", "CertExpiring", "PortScanSpike", "OomKill",
               "KernelPanic", "FsReadOnly", "ClockChange", "RequestRateSpike",
               "NewUser", "PackageInstalled", "PersistenceChanged", "SuspiciousExec",
               "UnexpectedExec", "AppException"];
let token = localStorage.getItem(TOKEN_KEY) || "";

const $ = (id) => document.getElementById(id);

function hashRoute() {
  const h = location.hash || "#/incidents";
  if (h.startsWith("#/incidents/")) {
    return { view: "incident", id: h.split("/")[2] };
  }
  if (h.startsWith("#/events")) return { view: "events" };
  return { view: "incidents" };
}

async function api(path, opts) {
  if (!requireToken()) throw new Error("no token");
  const resp = await fetch(path, Object.assign({
    headers: { authorization: "Bearer " + token },
  }, opts || {}));
  if (resp.status === 401) { localStorage.removeItem(TOKEN_KEY); token = ""; requireToken(); throw new Error("unauthorized"); }
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  return resp.json();
}

function setView(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.view === name));
  $("incidents-view").style.display = name === "incidents" ? "block" : "none";
  $("incident-detail").style.display = name === "incident" ? "block" : "none";
  $("filters").style.display = name === "events" ? "flex" : "none";
  $("events").style.display = name === "events" ? "block" : "none";
  $("empty").style.display = "none";
}

async function loadIncidents() {
  const data = await api("/v1/incidents?limit=200");
  const box = $("incidents");
  box.innerHTML = "";
  const list = data.incidents || [];
  $("inc-empty").style.display = list.length ? "none" : "block";
  for (const inc of list) {
    const el = document.createElement("div");
    el.className = "inc " + (inc.severity || "info").toLowerCase();
    el.innerHTML =
      `<div class="headline">${escapeHtml(inc.headline)}</div>
       <div class="meta">
         <span class="chip ${escapeHtml(inc.status)}">${escapeHtml(inc.status)}</span>
         <span class="badge ${(inc.severity || "info").toLowerCase()}">${escapeHtml(inc.severity)}</span>
         <span>${fmt(inc.created_at)}</span>
         <span>${escapeHtml(inc.host_id || "")}</span>
       </div>`;
    el.addEventListener("click", () => { location.hash = "#/incidents/" + inc.id; });
    box.appendChild(el);
  }
}

async function loadIncidentDetail(id) {
  const inc = await api("/v1/incidents/" + encodeURIComponent(id));
  const box = $("incident-detail");
  const evs = (inc.timeline || []).map(e =>
    `<div class="ev ${(e.severity || "info").toLowerCase()}">
       <div class="top"><span class="badge ${(e.severity || "info").toLowerCase()}">${escapeHtml(e.severity)}</span>
       <span class="time">${fmt(e.ts)}</span><span class="summary">${escapeHtml(e.summary)}</span>
       <span class="host">${escapeHtml(e.kind)}</span></div></div>`).join("");
  const actions = (inc.actions || []).map(a => `<li>${escapeHtml(a)}</li>`).join("");
  box.innerHTML =
    `<a id="back" href="#/incidents">&larr; incidents</a>
     <h2><span class="badge ${(inc.severity || "info").toLowerCase()}">${escapeHtml(inc.severity)}</span>
         <span class="chip ${escapeHtml(inc.status)}">${escapeHtml(inc.status)}</span>
         ${escapeHtml(inc.headline)}</h2>
     <div class="meta">host ${escapeHtml(inc.host_id || "")} · created ${fmt(inc.created_at)}</div>
     <div class="cause">${escapeHtml(inc.cause || "")}</div>
     <div class="actions"><ul>${actions}</ul></div>
     <div id="timeline">${evs}</div>
     <p>
       <button id="btn-ack" ${inc.status === "open" ? "" : "disabled"}>Acknowledge</button>
       <button id="btn-resolve" ${inc.status !== "resolved" ? "" : "disabled"}>Resolve</button>
     </p>`;
  $("btn-ack").addEventListener("click", () => setIncidentStatus(id, "ack"));
  $("btn-resolve").addEventListener("click", () => setIncidentStatus(id, "resolve"));
}

async function setIncidentStatus(id, action) {
  try {
    await api("/v1/incidents/" + encodeURIComponent(id) + "/" + action, { method: "POST" });
    await loadIncidentDetail(id);
  } catch (e) {
    $("err").style.display = "block";
    $("err").textContent = "failed: " + e.message;
  }
}

async function route() {
  const r = hashRoute();
  setView(r.view);
  try {
    if (r.view === "incidents") await loadIncidents();
    else if (r.view === "incident") await loadIncidentDetail(r.id);
    else {
      const events = await loadEvents();
      if (events) render(events);
    }
    clearError();
  } catch (e) {
    $("err").style.display = "block";
    $("err").textContent = "load failed: " + e.message;
  }
}

function requireToken() {
  if (token) return true;
  token = prompt("Watchtower API token:", "") || "";
  if (token) localStorage.setItem(TOKEN_KEY, token);
  return !!token;
}

function fmt(ms) {
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19);
}

async function loadEvents() {
  if (!requireToken()) return;
  const kind = document.getElementById("f-kind").value;
  const sev = document.getElementById("f-sev").value;
  const params = new URLSearchParams({ limit: "200" });
  if (kind) params.set("kind", kind);
  if (sev) params.set("severity", sev);
  const resp = await fetch("/v1/events?" + params, {
    headers: { authorization: "Bearer " + token },
  });
  if (resp.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    token = "";
    requireToken();
    return;
  }
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  return (await resp.json()).events || [];
}

function render(events) {
  const box = document.getElementById("events");
  document.getElementById("empty").style.display = events.length ? "none" : "block";
  box.innerHTML = "";
  for (const ev of events) {
    const el = document.createElement("div");
    el.className = "ev " + (ev.severity || "info").toLowerCase();
    const evs = (ev.evidence || []).map(e =>
      `<div>${fmt(e.ts)} — [${escapeHtml(e.source)}] ${escapeHtml(e.detail)}</div>`).join("");
    el.innerHTML =
      `<div class="top">
         <span class="badge ${(ev.severity || "info").toLowerCase()}">${escapeHtml(ev.severity || "?")}</span>
         <span class="time">${fmt(ev.ts)}</span>
         <span class="summary">${escapeHtml(ev.summary)}</span>
         <span class="kind">${escapeHtml(ev.kind || "")}</span>
         <span class="host">${escapeHtml(ev.host_id)}</span>
       </div>
       <div class="evidence">${evs}</div>`;
    el.addEventListener("click", () => el.classList.toggle("open"));
    box.appendChild(el);
  }
}

function clearError() {
  $("err").style.display = "none";
  $("err").textContent = "";
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function init() {
  const fKind = document.getElementById("f-kind");
  for (const k of KINDS) {
    const o = document.createElement("option");
    o.value = k; o.textContent = k;
    fKind.appendChild(o);
  }
  fKind.addEventListener("change", refresh);
  $("f-sev").addEventListener("change", refresh);
  setInterval(refresh, 5000);
  setInterval(() => {
    if (hashRoute().view === "incidents") loadIncidents().then(clearError, () => {});
  }, 5000);
  window.addEventListener("hashchange", route);
  route();
}

async function refresh() {
  if (hashRoute().view !== "events") return;
  const status = document.getElementById("status");
  try {
    const events = await loadEvents();
    if (!events) return; // 401 re-prompt path; next poll retries
    render(events);
    clearError();
    status.textContent = "updated " + fmt(Date.now());
  } catch (e) {
    const err = document.getElementById("err");
    err.style.display = "block";
    err.textContent = "load failed: " + e.message;
  }
}

init();
