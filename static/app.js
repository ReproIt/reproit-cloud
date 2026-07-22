"use strict";

// ---- config -----------------------------------------------------------------
// Served same-origin from the cloud (see reproit-cloud), so the API base
// defaults to this origin (empty string = relative fetches, no CORS). The
// config overlay / `?api=&app=&key=` still let you point it at another cloud.
const DEFAULTS = { api: "", app: "", key: "" };

function loadConfig() {
  const qs = new URLSearchParams(location.search);
  const stored = (() => { try { return JSON.parse(localStorage.getItem("reproit.cfg") || "{}"); } catch { return {}; } })();
  const api = qs.get("api") || stored.api || DEFAULTS.api;
  const app = qs.get("app") || stored.app || DEFAULTS.app;
  // Project secrets never belong in URLs: query strings leak through browser
  // history, copied links, referrers, screenshots, analytics, and support logs.
  // Legacy ?key= links are intentionally ignored; enter the key in Account so
  // it remains in this browser's local credential store.
  const key = stored.key || keyForApp(app) || DEFAULTS.key;
  return { api: api.replace(/\/+$/, ""), app, key };
}
let CFG = loadConfig();

function explicitConfig() {
  const qs = new URLSearchParams(location.search);
  const stored = (() => { try { return JSON.parse(localStorage.getItem("reproit.cfg") || "{}"); } catch { return {}; } })();
  return {
    app: qs.has("app") || Boolean(stored.app),
    key: Boolean(stored.key),
  };
}
const EXPLICIT = explicitConfig();

function keyStore() {
  try { return JSON.parse(localStorage.getItem("reproit.keys") || "{}"); } catch { return {}; }
}
function keyForApp(appId) {
  return keyStore()[appId] || "";
}
// Publishable (pk_live_) keys are stored separately from the secret ones: the
// secret key (keyForApp) drives dashboard Bearer reads + the CLI command, while
// the publishable key is the ONLY one that goes into the SDK snippet + the wired
// demo, since it can be shipped in client JS without exposing reads/export.
function pubKeyStore() {
  try { return JSON.parse(localStorage.getItem("reproit.pubkeys") || "{}"); } catch { return {}; }
}
function pubKeyForApp(appId) {
  return pubKeyStore()[appId] || "";
}
function rememberKey(appId, key, pubKey) {
  if (!appId) return;
  if (key) {
    const keys = keyStore();
    keys[appId] = key;
    localStorage.setItem("reproit.keys", JSON.stringify(keys));
  }
  if (pubKey) {
    const pubs = pubKeyStore();
    pubs[appId] = pubKey;
    localStorage.setItem("reproit.pubkeys", JSON.stringify(pubs));
  }
}
function forgetProjectKeys(appId) {
  if (!appId) return;
  const keys = keyStore();
  const pubs = pubKeyStore();
  delete keys[appId];
  delete pubs[appId];
  localStorage.setItem("reproit.keys", JSON.stringify(keys));
  localStorage.setItem("reproit.pubkeys", JSON.stringify(pubs));
}
function saveConfig(cfg) {
  localStorage.setItem("reproit.cfg", JSON.stringify(cfg));
}

const ACCOUNT_SCROLL_SESSION_KEY = "reproit.dashboard.accountScrollTop";
const VALID_VIEWS = new Set(["triage", "scans", "findings", "seats", "account"]);

function normalizedView(view) {
  if (view === "findings") return "scans";
  return VALID_VIEWS.has(view) ? view : "triage";
}

function initialView() {
  const hashView = normalizedView(location.hash.replace(/^#\/?/, ""));
  if (VALID_VIEWS.has(location.hash.replace(/^#\/?/, ""))) return hashView;
  if (new URLSearchParams(location.search).has("bucket")) return "triage";
  const qs = new URLSearchParams(location.search);
  return normalizedView(qs.get("view"));
}

function replaceOrPushUrl(url, replace) {
  const next = url.pathname + url.search + url.hash;
  if (next === location.pathname + location.search + location.hash) return;
  history[replace ? "replaceState" : "pushState"]({ view: normalizedView(url.hash.replace(/^#\/?/, "")) }, "", url);
}

function syncViewUrl(replace) {
  const url = new URL(location.href);
  url.searchParams.delete("view");
  if (S.view !== "triage") {
    url.searchParams.delete("bucket");
    url.searchParams.delete("sig");
  }
  url.hash = S.view === "triage" ? "" : S.view;
  replaceOrPushUrl(url, replace);
}

function syncProjectUrl(replace) {
  const url = new URL(location.href);
  if (CFG.app) url.searchParams.set("app", CFG.app);
  else url.searchParams.delete("app");
  // Always scrub legacy credentials from navigation state. Authentication is
  // carried by the same-origin session or the browser-local project key store.
  url.searchParams.delete("key");
  url.searchParams.delete("view");
  url.hash = S.view === "triage" ? "" : S.view;
  url.searchParams.delete("bucket");
  replaceOrPushUrl(url, replace);
}

async function api(pathStr) {
  const headers = {};
  if (CFG.key) headers["Authorization"] = "Bearer " + CFG.key;
  const res = await fetch(CFG.api + pathStr, { headers });
  if (!res.ok) throw new Error("HTTP " + res.status + " on " + pathStr);
  return res.json();
}
// Bearer-authed write against the /v1 (project-key) plane, mirroring accountReq's
// {ok,status,data} shape. Used by the dispatch settings form, which PUTs to
// /v1/apps/:app/integrations (an API-key route, so it needs the project key, not
// the session cookie).
async function apiSend(pathStr, method, body) {
  const opts = { method: method || "POST", headers: {} };
  if (CFG.key) opts.headers["Authorization"] = "Bearer " + CFG.key;
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(CFG.api + pathStr, opts);
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}
async function accountReq(pathStr, method, body) {
  const opts = {
    method: method || "GET",
    headers: {},
    credentials: "same-origin",
  };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(CFG.api + pathStr, opts);
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}
async function dashboardGet(pathStr) {
  const headers = {};
  if (S.accountStatus !== "ready" && CFG.key) headers["Authorization"] = "Bearer " + CFG.key;
  const res = await fetch(CFG.api + pathStr, {
    headers,
    credentials: "same-origin",
  });
  if (!res.ok) throw new Error("HTTP " + res.status + " on " + pathStr);
  return res.json();
}
async function loadAccount() {
  S.accountStatus = "loading"; S.accountErr = null;
  const r = await accountReq("/account/me");
  if (r.status === 401) { S.accountStatus = "unauth"; S.account = null; return; }
  if (!r.ok) {
    S.accountStatus = "error";
    S.accountErr = r.data && r.data.error ? r.data.error : "could not load account";
    S.account = null;
    return;
  }
  S.account = r.data;
  S.accountStatus = "ready";
  const activeOrgId = S.account.org && Number(S.account.org.id);
  if (activeOrgId) { try { localStorage.setItem("reproit.activeOrg", String(activeOrgId)); } catch {} }
  const projects = S.account.projects || [];
  const ownsConfiguredApp = projects.some((p) => p.appId === CFG.app);
  if (projects.length) {
    const appId = (!EXPLICIT.app || !ownsConfiguredApp) ? projects[0].appId : CFG.app;
    CFG = { ...CFG, app: appId, key: keyForApp(appId) };
    saveConfig(CFG);
  } else {
    // A new workspace has no active project. Clear any stale project kept in
    // this browser so the dashboard renders onboarding instead of requesting a
    // project that does not exist and misreporting its 404 as a load failure.
    CFG = { ...CFG, app: "", key: "" };
    saveConfig(CFG);
  }
  const email = S.account.email || "";
  const avatar = document.querySelector(".avatar");
  if (avatar && email) avatar.textContent = email.slice(0, 1).toUpperCase();
  paintProjectSwitch();
  paintOrgSwitch();
}
function currentProject() {
  const projects = (S.account && S.account.projects) || [];
  return projects.find((p) => p.appId === CFG.app) || null;
}
function canManageOrg() {
  const role = S.account && S.account.org && S.account.org.role;
  return role === "owner" || role === "admin";
}
function projectOptions() {
  return ((S.account && S.account.projects) || []).map((p) =>
    `<option value="${esc(p.appId)}"${p.appId === CFG.app ? " selected" : ""}>${esc(p.name)} · ${esc(p.appId)}</option>`
  ).join("");
}
function closeHeaderPickers(except) {
  document.querySelectorAll(".header-picker.open").forEach((picker) => {
    if (picker.id === `${except}-picker`) return;
    picker.classList.remove("open");
    picker.querySelector(".header-picker-button")?.setAttribute("aria-expanded", "false");
  });
}
function paintHeaderPicker(kind, items, activeValue, fallback, disabled) {
  const picker = document.getElementById(`${kind}-picker`), button = document.getElementById(`${kind}-picker-button`), value = document.getElementById(`${kind}-picker-value`), menu = document.getElementById(`${kind}-picker-menu`);
  if (!picker || !button || !value || !menu) return;
  const active = items.find((item) => String(item.value) === String(activeValue));
  value.textContent = active ? active.label : fallback;
  button.disabled = disabled || !items.length;
  picker.classList.toggle("disabled", button.disabled);
  menu.innerHTML = items.map((item) => { const selected = String(item.value) === String(activeValue); return `<button type="button" role="option" aria-selected="${selected}" data-picker-option="${kind}" data-picker-value="${esc(item.value)}"><span>${esc(item.label)}</span>${item.meta ? `<small>${esc(item.meta)}</small>` : ""}<i aria-hidden="true">${selected ? "✓" : ""}</i></button>`; }).join("");
  if (button.disabled) closeHeaderPickers();
}
function toggleHeaderPicker(kind, forceOpen) {
  const picker = document.getElementById(`${kind}-picker`), button = document.getElementById(`${kind}-picker-button`);
  if (!picker || !button || button.disabled) return;
  const willOpen = forceOpen == null ? !picker.classList.contains("open") : forceOpen;
  closeHeaderPickers(willOpen ? kind : null);
  picker.classList.toggle("open", willOpen);
  button.setAttribute("aria-expanded", String(willOpen));
  if (willOpen) (picker.querySelector('[role="option"][aria-selected="true"]') || picker.querySelector('[role="option"]'))?.focus();
}
function paintProjectSwitch() {
  const projects = (S.account && S.account.projects) || [];
  paintHeaderPicker("project", projects.map((p) => ({ value: p.appId, label: p.name, meta: p.appId })), CFG.app, "No projects", false);
}
function paintOrgSwitch() {
  const orgs = (S.account && S.account.organizations) || [];
  const activeId = S.account && S.account.org && Number(S.account.org.id);
  paintHeaderPicker("org", orgs.map((org) => ({ value: Number(org.id), label: org.name, meta: org.role })), activeId, "Workspace", S.orgBusy);
}
function redirectToLogin() {
  const next = location.pathname + location.search + location.hash;
  location.replace(`/login?next=${encodeURIComponent(next)}`);
}
function resetAppData() {
  S.selSig = null;
  S.cohorts = null;
  S.errors = null;
  S.bucketBySig = {};
  S.repro = null;
  S.status = "idle";
  S.kbdIdx = -1;
  S.scans = null;
  S.scanDetail = null;
  S.selScanId = null;
  S.scanStatus = "idle";
  S.scanErr = null;
}
function setActiveProject(appId) {
  if (!appId || appId === CFG.app) return;
  CFG = { ...CFG, app: appId, key: keyForApp(appId) };
  saveConfig(CFG);
  syncProjectUrl(true);
  resetAppData();
  if (window.ReproitTriage && window.ReproitTriage.resetForApp) window.ReproitTriage.resetForApp();
  paintProjectSwitch();
  if (S.view === "findings") loadFindings();
  else if (S.view === "scans") loadScans();
  else if (S.view === "account") render();
  else if (window.ReproitTriage) window.ReproitTriage.render(S.view);
}
// absolute url for a possibly-relative blob/evidence path
function abs(u) {
  if (!u) return u;
  return /^https?:\/\//.test(u) ? u : CFG.api + (u.startsWith("/") ? "" : "/") + u;
}

// ---- helpers ----------------------------------------------------------------
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const firstLine = (s) => String(s || "").split("\n")[0];

function fileLineFromMessage(msg) {
  const m = String(msg || "").match(/([\w./-]+\.\w+:\d+(?::\d+)?)/);
  return m ? m[1] : null;
}
function titleFromMessage(msg) {
  return String(firstLine(msg)).replace(/\s*\([\w./-]+\.\w+:\d+(?::\d+)?\)\s*$/, "").trim() || firstLine(msg);
}
function liftStr(lift) {
  return lift === "inf" ? "inf" : (Number(lift).toFixed(1) + "x");
}
function topDiscriminator(cluster) {
  const d = (cluster.discriminators || [])[0];
  if (!d) return null;
  return { label: `${d.key}=${d.value}`, key: d.key, value: d.value, pct: Math.round((d.cohortShare || 0) * 100), lift: liftStr(d.lift) };
}
function platformOf(cluster) {
  const d = (cluster.discriminators || []).find((x) => x.key === "platform");
  return d ? d.value : null;
}
const fmtBytes = (n) => n == null ? "" : (n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB");
// Context values can be nested objects (e.g. build = {version, commit}); render
// them readably instead of "[object Object]".
function fmtCtxVal(v) {
  if (v !== null && typeof v === "object") {
    if (v.version != null) return String(v.version);
    try { return JSON.stringify(v); } catch { return String(v); }
  }
  return String(v == null ? "" : v);
}

// ---- state ------------------------------------------------------------------
const S = {
  cohorts: null,
  errors: null,
  bucketBySig: {},
  account: null,
  accountStatus: "idle", // idle | loading | ready | unauth | error
  accountErr: null,
  projectBusy: false,
  publishableKeyBusy: false,
  roleSaving: false,
  roleDraft: {},
  teamSearch: "",
  inviteEmail: "", inviteRole: "member", inviteBusy: "",
  orgBusy: false, orgNameDraft: null,
  newProject: "",
  projectDeleteConfirm: "", projectDeleteBusy: false,
  orgDeleteConfirm: "", orgDeleteBusy: false,
  justCreatedKey: null,      // {appId, apiKey}: surfaced once, right after creation
  integration: null,         // GET /v1/apps/:app/integrations result
  integrationApp: null,      // which app `integration` belongs to
  integrationStatus: "idle", // idle | loading | ready | error | nokey
  dispatchRepoDraft: null,   // null = show the loaded value; string = user-edited
  dispatchTokenDraft: "",    // blank = keep the stored token unchanged
  dispatchBusy: false,
  selSig: null,
  repro: null,
  view: initialView(),
  error: null, status: "idle", // idle | loading | ready | error
  reproStatus: "idle", // idle | loading | ready | error
  filter: { q: "", disc: "all", sort: "count" },
  scans: null,
  scanDetail: null,
  selScanId: null,
  scanStatus: "idle", // idle | loading | ready | error
  scanErr: null,
  scanFilter: { q: "", status: "all" },
  evKind: null, // selected evidence kind index
  sdkPlatform: (() => {
    try { return localStorage.getItem("reproit.sdkPlatform") || "web"; } catch { return "web"; }
  })(),
  kbdIdx: -1, // keyboard-focused row in filtered list
};
const root = () => document.getElementById("app-root");

function accountScrollEl() {
  return root().querySelector(".single");
}

function saveAccountScroll() {
  if (S.view !== "account") return;
  const el = accountScrollEl();
  if (!el) return;
  try { sessionStorage.setItem(ACCOUNT_SCROLL_SESSION_KEY, String(el.scrollTop)); } catch {}
}

function restoreAccountScroll() {
  if (S.view !== "account") return;
  requestAnimationFrame(() => {
    const el = accountScrollEl();
    if (!el) return;
    const saved = (() => {
      try { return Number(sessionStorage.getItem(ACCOUNT_SCROLL_SESSION_KEY) || 0); } catch { return 0; }
    })();
    if (Number.isFinite(saved) && saved > 0) el.scrollTop = saved;
  });
}

function wireAccountScroll() {
  const el = accountScrollEl();
  if (!el) return;
  el.addEventListener("scroll", () => {
    try { sessionStorage.setItem(ACCOUNT_SCROLL_SESSION_KEY, String(el.scrollTop)); } catch {}
  }, { passive: true });
  restoreAccountScroll();
}

function setView(view, opts) {
  const next = normalizedView(view);
  const options = opts || {};
  if (next === S.view && !options.force) {
    syncViewUrl(options.replace === true);
    return;
  }
  saveAccountScroll();
  S.view = next;
  syncViewUrl(options.replace === true);
  syncNav();
  render();
}

function setBanner(msg, kind) {
  const slot = document.getElementById("banner-slot");
  if (!msg) { slot.innerHTML = ""; return; }
  const cls = kind === "warn" ? "banner warn" : "banner";
  slot.innerHTML = `<p class="${cls}">${kind === "warn" ? "i" : "!"} ${esc(msg)}</p>`;
}
function setConn(_text, _color) {
  // Kept as a no-op shim because triage.js shares this app shell.
}

function errorsForSig(sig) {
  return (S.errors || []).filter((e) => e.sig === sig);
}
function bucketForSig(sig) {
  return S.bucketBySig && S.bucketBySig[sig] ? S.bucketBySig[sig] : null;
}

// list after search + filter + sort
function filteredCohorts() {
  let list = (S.cohorts || []).slice();
  const q = S.filter.q.trim().toLowerCase();
  if (q) list = list.filter((c) =>
    (c.message || "").toLowerCase().includes(q) ||
    (c.sig || "").toLowerCase().includes(q) ||
    (c.discriminators || []).some((d) => (d.key + "=" + d.value).toLowerCase().includes(q)));
  if (S.filter.disc !== "all")
    list = list.filter((c) => (c.discriminators || []).some((d) => (d.key + "=" + d.value) === S.filter.disc));
  if (S.filter.sort === "count") list.sort((a, b) => (b.count || 0) - (a.count || 0));
  else if (S.filter.sort === "recency") list.reverse(); // API returns newest-influenced order; keep stable-ish
  else if (S.filter.sort === "az") list.sort((a, b) => titleFromMessage(a.message).localeCompare(titleFromMessage(b.message)));
  return list;
}
function discOptions() {
  const set = new Map();
  (S.cohorts || []).forEach((c) => (c.discriminators || []).forEach((d) => set.set(d.key + "=" + d.value, true)));
  return Array.from(set.keys()).sort();
}

// ---- data load --------------------------------------------------------------
async function loadFindings() {
  S.error = null; S.status = "loading";
  setBanner("");
  render();
  try {
    let buckets = null;
    if (S.accountStatus === "ready") {
      buckets = await dashboardGet(`/v1/apps/${encodeURIComponent(CFG.app)}/dashboard/buckets`);
      S.cohorts = ((buckets && buckets.items) || []).map((b) => ({
        sig: b.crashSig || b.bucketId,
        message: b.message || b.bucketId,
        count: b.count || 0,
        discriminators: b.discriminators || [],
        bucketId: b.bucketId,
      }));
      S.errors = [];
    } else if (CFG.key) {
      const [cohorts, errors, bucketResp] = await Promise.all([
        dashboardGet(`/v1/errors/${encodeURIComponent(CFG.app)}/cohorts`),
        dashboardGet(`/v1/errors/${encodeURIComponent(CFG.app)}`),
        dashboardGet(`/v1/apps/${encodeURIComponent(CFG.app)}/buckets`).catch(() => null),
      ]);
      buckets = bucketResp;
      S.cohorts = (cohorts.errors || cohorts.clusters_data || []);
      S.errors = errors.errors || [];
    }
    // sig -> bucket id, so detail reads use the stable bucket package.
    S.bucketBySig = {};
    if (buckets && buckets.items) buckets.items.forEach((b) => { if (b.crashSig) S.bucketBySig[b.crashSig] = b.bucketId; });
    S.status = "ready";
    paintProjectSwitch();
    setConn(`${S.cohorts.length} clusters, ${S.errors.length} errors`, "var(--green)");
    if (!S.selSig && S.cohorts.length) {
      const wanted = new URLSearchParams(location.search).get("sig");
      const initial = (wanted && S.cohorts.some((c) => c.sig === wanted)) ? wanted : filteredCohorts()[0].sig;
      await selectSig(initial, false);
    }
    render();
  } catch (e) {
    S.status = "error";
    S.error = e.message;
    setConn("unreachable", "var(--red)");
    setBanner(`Could not reach cloud at ${CFG.api} (${e.message}). If this is CORS, the cloud needs cross-origin headers.`);
    render();
  }
}

function scanStatus(job) {
  if (!job) return "unknown";
  if (Number(job.findings || 0) > 0) return "finding";
  if (Number(job.errors || 0) > 0) return "error";
  if (job.complete) return "clean";
  if (Number(job.running || 0) > 0) return "running";
  return "queued";
}

function scanStatusLabel(job) {
  const status = scanStatus(job);
  if (status === "finding") return "found bug";
  if (status === "clean") return "clean";
  return status;
}

function fmtTime(s) {
  if (!s) return "";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return String(s);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function appDirName(path) {
  const parts = String(path || "").split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] || path || "scan";
}

function filteredScans() {
  let list = (S.scans || []).slice();
  const q = S.scanFilter.q.trim().toLowerCase();
  if (q) list = list.filter((job) =>
    (job.id || "").toLowerCase().includes(q) ||
    (job.appDir || "").toLowerCase().includes(q) ||
    scanStatusLabel(job).toLowerCase().includes(q));
  if (S.scanFilter.status !== "all") {
    list = list.filter((job) => scanStatus(job) === S.scanFilter.status);
  }
  return list;
}

async function loadScans() {
  S.scanStatus = "loading";
  S.scanErr = null;
  setBanner("");
  render();
  const r = await accountReq("/account/scans");
  if (!r.ok) {
    S.scanStatus = "error";
    S.scanErr = (r.data && r.data.error) || "could not load scans";
    render();
    return;
  }
  S.scans = r.data.items || [];
  S.scanStatus = "ready";
  if (!S.selScanId && S.scans.length) {
    await selectScan(S.scans[0].id, false);
  }
  render();
}

async function selectScan(id, doRender = true) {
  S.selScanId = id;
  S.scanDetail = null;
  if (doRender) highlightSelectedScan();
  const r = await accountReq(`/account/scans/${encodeURIComponent(id)}`);
  if (!r.ok) {
    S.scanDetail = { _error: (r.data && r.data.error) || "could not load scan" };
  } else {
    S.scanDetail = r.data;
  }
  if (doRender) paintScanDetail();
}

function highlightSelectedScan() {
  document.querySelectorAll(".item[data-scan]").forEach((el) => {
    const on = el.dataset.scan === S.selScanId;
    el.classList.toggle("sel", on);
    el.setAttribute("aria-selected", on);
  });
}

function paintScanDetail() {
  const cur = document.querySelector(".detail");
  if (!cur) { render(); return; }
  cur.outerHTML = renderScanDetail();
}

async function selectSig(sig, doRender = true) {
  S.selSig = sig;
  S.repro = null; S.evKind = null;
  // Move the highlight in the list NOW, without a re-render, so the click feels
  // instant.
  if (doRender) highlightSelected();
  const bucket = bucketForSig(sig);
  if (bucket) {
    S.reproStatus = "loading";
    try {
      const detailPath = S.accountStatus !== "ready" && CFG.key
        ? `/v1/apps/${encodeURIComponent(CFG.app)}/buckets/${encodeURIComponent(bucket)}`
        : `/v1/apps/${encodeURIComponent(CFG.app)}/buckets/${encodeURIComponent(bucket)}/detail`;
      S.repro = await dashboardGet(detailPath);
      S.reproStatus = "ready";
    } catch (e) { S.repro = { _error: e.message }; S.reproStatus = "error"; }
  } else {
    S.reproStatus = "idle";
  }
  // Swap ONLY the detail panel (once), not the whole page.
  if (doRender) paintDetail();
}

// Toggle the selected list item in place (no DOM rebuild) for instant feedback.
function highlightSelected() {
  document.querySelectorAll(".item[data-sig]").forEach((el) => {
    const on = el.dataset.sig === S.selSig;
    el.classList.toggle("sel", on);
    el.setAttribute("aria-selected", on);
  });
}

// Re-render ONLY the detail panel, not the whole page. Selecting a finding used
// to replace root().innerHTML twice (loading + ready), tearing down the sidebar
// list and reloading the evidence media each time, which flickered. Now the
// sidebar is untouched and only <section.detail> is swapped. Falls back to a
// full render if the page is not built yet.
function paintDetail() {
  const cur = document.querySelector(".detail");
  if (!cur) { render(); return; }
  cur.outerHTML = renderDetail();
}

// ---- findings list ----------------------------------------------------------
function searchIcon() {
  return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>`;
}

function renderListHead(total, shown) {
  const opts = discOptions();
  const discSel = `<div class="selwrap"><select id="f-disc" aria-label="Filter by discriminator">
    <option value="all"${S.filter.disc === "all" ? " selected" : ""}>All cohorts</option>
    ${opts.map((o) => `<option value="${esc(o)}"${S.filter.disc === o ? " selected" : ""}>${esc(o)}</option>`).join("")}
  </select></div>`;
  const sortSel = `<div class="selwrap"><select id="f-sort" aria-label="Sort findings">
    <option value="count"${S.filter.sort === "count" ? " selected" : ""}>Most occurrences</option>
    <option value="recency"${S.filter.sort === "recency" ? " selected" : ""}>Most recent</option>
    <option value="az"${S.filter.sort === "az" ? " selected" : ""}>A to Z</option>
  </select></div>`;
  return `<div class="list-head">
    <div class="titlerow">
      <h2 id="findings-label">Open findings</h2>
      <span class="countbadge" aria-label="${total} findings">${total}</span>
    </div>
    <div class="search" role="search">
      ${searchIcon()}
      <input id="f-search" type="search" placeholder="Search message, sig, cohort" value="${esc(S.filter.q)}"
        aria-label="Search findings" autocomplete="off" spellcheck="false"/>
      ${S.filter.q ? `<button class="clear" id="f-clear" aria-label="Clear search">x</button>` : ""}
    </div>
    <div class="filters">${discSel}${sortSel}</div>
  </div>`;
}

function renderInbox() {
  if (S.status === "loading" && !S.cohorts) {
    return `<aside class="list" aria-busy="true">
      ${renderListHead(0, 0)}
      <div class="list-scroll">${[0, 1, 2, 3].map(() => `<div class="sk-item">
        <div class="sk sk-line" style="width:40%"></div>
        <div class="sk sk-line" style="width:85%"></div>
        <div class="sk sk-line" style="width:55%"></div></div>`).join("")}</div>
    </aside>`;
  }
  if (!S.cohorts || !S.cohorts.length) {
    const projects = (S.account && S.account.projects) || [];
    if (S.accountStatus === "ready" && !projects.length) {
      return `<aside class="list">${renderListHead(0, 0)}
        <div class="empty"><div>
          <div class="ico" aria-hidden="true">[ ]</div>
          <div class="big">Create a project</div>
          <div class="sub">Projects hold app ids, SDK keys, production buckets, and replay evidence.</div>
          <button class="ghostbtn" id="go-account">Open account</button>
        </div></div></aside>`;
    }
    return renderGetStarted(currentProject() || projects[0] || null);
  }
  const list = filteredCohorts();
  const total = S.cohorts.length;
  let rows;
  if (!list.length) {
    rows = `<div class="empty"><div>
      <div class="ico" aria-hidden="true">?</div>
      <div class="big">No matches</div>
      <div class="sub">No findings match your search or filter.</div>
      <button class="ghostbtn" id="f-reset">Clear filters</button>
    </div></div>`;
  } else {
    rows = list.map((c, i) => {
      const d = topDiscriminator(c);
      const fl = fileLineFromMessage(c.message);
      const who = d ? `<span class="who-tag">who: ${esc(d.label)} (${esc(d.lift)})</span>` : `<span>representative slice</span>`;
      const dotColor = (c.discriminators || []).length ? "var(--red)" : "var(--amber)";
      const sel = c.sig === S.selSig;
      const kbd = i === S.kbdIdx;
      return `<div class="item ${sel ? "sel" : ""} ${kbd ? "kbd" : ""}" data-sig="${esc(c.sig)}" data-idx="${i}"
        role="option" aria-selected="${sel}" id="item-${esc(c.sig)}" tabindex="-1">
        <div class="top"><span class="dot" style="background:${dotColor}" aria-hidden="true"></span>
          <span class="sig">${esc(c.sig)}</span><span class="chip" style="margin-left:auto">x${c.count}</span></div>
        <div class="ttl">${esc(titleFromMessage(c.message))}</div>
        <div class="meta">${fl ? `<span>${esc(fl)}</span>` : ""}${who}</div>
      </div>`;
    }).join("");
  }
  return `<aside class="list">
    ${renderListHead(total, list.length)}
    <div class="list-scroll" id="list-scroll" role="listbox" aria-labelledby="findings-label" tabindex="0" aria-activedescendant="${S.kbdIdx >= 0 && list[S.kbdIdx] ? "item-" + esc(list[S.kbdIdx].sig) : ""}">${rows}</div>
    <div class="list-foot">${list.length === total ? `${total} findings` : `${list.length} of ${total}`}
      &nbsp;&middot;&nbsp; <span class="kbd-hint"><kbd>up</kbd><kbd>down</kbd> move <kbd>enter</kbd> open</span></div>
  </aside>`;
}

// ---- detail panels ----------------------------------------------------------
function renderWho(cluster) {
  const ds = cluster.discriminators || [];
  if (!ds.length) return `<div class="muted">No over-represented dimension. This signature hits a representative slice of users.</div>`;
  const rows = ds.map((d) => {
    const pct = Math.round((d.cohortShare || 0) * 100);
    return `<div class="barrow"><span class="lab" title="${esc(d.key)}=${esc(d.value)}">${esc(d.key)}=${esc(d.value)}</span>
      <div class="bar"><i style="width:${pct}%"></i></div><span class="pct">${pct}% &middot; ${esc(liftStr(d.lift))}</span></div>`;
  }).join("");
  return rows + `<div class="muted" style="margin-top:10px">Over-represented vs the app baseline. The discriminator, not the signature.</div>`;
}

// evidence list from repro (array of {url,kind,bytes,ts})
function evidenceList() {
  const r = S.repro || {};
  const ev = r.evidence;
  if (Array.isArray(ev)) return ev.filter((e) => e && e.url);
  // tolerate legacy string forms
  const single = r.evidenceUrl || (typeof ev === "string" ? ev : null);
  return single ? [{ url: single, kind: "video" }] : [];
}

function renderPhone() {
  const evs = evidenceList();
  if (S.reproStatus === "loading") {
    return `<div class="phone"><div class="phone-screen"><div class="sk" style="width:100%;height:100%"></div></div></div>
      <div class="phone-caption">loading evidence...</div>`;
  }
  if (!evs.length) {
    return `<div class="phone"><div class="phone-screen">
      <div class="scan" aria-hidden="true"></div>
      <div class="phone-noev">
        <span class="ico" aria-hidden="true">[ ]</span>
        No evidence artifact captured for this production finding yet.
        Replay the bucket with recording enabled to save a video to R2:
        <code>reproit &lt;bucket-id&gt; --record-video</code>
      </div></div></div>
      <div class="phone-caption">no recording attached</div>`;
  }
  const ki = S.evKind != null && evs[S.evKind] ? S.evKind : 0;
  const cur = evs[ki];
  const url = esc(abs(cur.url));
  const media = (cur.kind === "gif")
    ? `<img src="${url}" alt="Animated reproduction of the bug" loading="lazy"/>`
    : `<video src="${url}" controls autoplay muted loop playsinline aria-label="Reproduction recording"></video>`;
  const tabs = evs.length > 1
    ? `<div class="kindtabs" role="tablist" aria-label="Evidence format">${evs.map((e, i) =>
        `<button class="kindtab ${i === ki ? "on" : ""}" data-evkind="${i}" role="tab" aria-selected="${i === ki}">${esc((e.kind || "media").toUpperCase())}</button>`).join("")}</div>`
    : `<span class="chip">${esc((cur.kind || "media").toUpperCase())}</span>`;
  return `<div class="phone"><div class="phone-screen">
    <div class="scan" aria-hidden="true"></div>${media}</div></div>
    <div class="phone-caption">${tabs}${cur.bytes ? `<span>${esc(fmtBytes(cur.bytes))}</span>` : ""}</div>`;
}

// The hero: the recorded repro video is the focal element (its own stage),
// with the determinism strip below it and a Share button that copies the
// directly-viewable video URL (falling back to the page deep-link).
function renderReproHero(cluster) {
  const evs = evidenceList();
  // A clip is a recording of the deterministic reproduction on synthetic,
  // PII-safe data (never a user session), so it exists only if someone ran a
  // reproduce-with-record. With no clip, lead with the data + commands instead
  // of a big empty video frame.
  const showVideo = S.reproStatus === "loading" || evs.length > 0;
  if (showVideo) {
    return `<div class="card repro-hero" style="margin-top:22px">
      <div class="hd">Deterministic repro <span class="tag">synthetic reproduction, no user data</span></div>
      <div class="hero-stage">${renderPhone()}</div>
      ${renderReproCommands(cluster)}
    </div>`;
  }
  return `<div class="card repro-hero" style="margin-top:22px">
    <div class="hd">Deterministic repro <span class="tag">no recording</span></div>
    ${renderReproCommands(cluster)}
    ${renderClipHint(cluster)}
  </div>`;
}

// How to get a visual clip when none exists: reproduce WITH a recording. The
// clip is always a synthetic, PII-safe reproduction, never a captured session,
// which is why the cloud never records the device.
function renderClipHint(cluster) {
  const app = CFG.app;
  const bkt = bucketForSig(cluster.sig);
  const cmd = bkt
    ? `reproit ${bkt} --record-video`
    : `reproit bugs`;
  return `<div class="clip-hint">
    <span class="ch-ico" aria-hidden="true">&#9654;</span>
    <span>No reproduction clip. A clip records the deterministic reproduction on synthetic, PII-safe data, never a user session. Reproduce and record it: <code>${esc(cmd)}</code>.</span>
  </div>`;
}

// The direct cloud-to-local command for this finding. A production bucket id is
// itself executable: reproit downloads it, saves it locally, and replays it.
function renderReproCommands(cluster) {
  const app = CFG.app;
  const bkt = bucketForSig(cluster.sig);
  const bktArg = bkt || "<bucket-id>";
  const reproduce = `reproit ${bktArg}`;
  return `<div class="cmd-term" role="group" aria-label="Commands to reproduce this finding locally">
    <div class="cmd-bar">
      <span class="cmd-dots" aria-hidden="true"><i></i><i></i><i></i></span>
      <span class="cmd-title">reproduce locally</span>
      <button class="term-copy" id="term-copy" data-cmd="${esc(reproduce)}" aria-label="Copy the reproduce command">copy</button>
    </div>
    <div class="cmd-body">
      <div class="ln cmt"># download, save, and reproduce this production bug locally</div>
      <div class="ln"><span class="prompt">$</span> <span class="cmd">reproit</span> <span class="arg">${esc(bktArg)}</span></div>
    </div>
  </div>`;
}

// The path to the bug as a vertical, scrollable step list (stack-trace style):
// each state on its own row, the action that left it on the row below, the crash
// last. No layout math, so an arbitrarily long repro just scrolls instead of
// breaking like a graph would.
function renderMiniGraph(sig) {
  const errs = errorsForSig(sig);
  const path = (errs[0] && errs[0].path) || [];
  if (!path.length && S.repro && Array.isArray(S.repro.replay) && S.repro.replay.length) {
    return `<ol class="bugpath" role="img" aria-label="Replay actions for this bucket">${S.repro.replay.map((a) =>
      `<li class="bp-act"><span class="bp-arrow">&darr;</span> ${esc(a)}</li>`).join("")}</ol>`;
  }
  if (!path.length) return `<div class="muted">No recorded path for this finding.</div>`;
  let rows = "";
  path.forEach((step) => {
    rows += `<li class="bp-state">${esc(step.sig)}</li>`;
    if (step.action) rows += `<li class="bp-act"><span class="bp-arrow">&darr;</span> ${esc(step.label || step.display || step.action)}</li>`;
  });
  rows += `<li class="bp-state bp-bug">&#10007; ${esc(sig)}</li>`;
  const aria = path.map((p) => p.sig).join(" then ") + " then crash";
  return `<ol class="bugpath" role="img" aria-label="Path to the bug: ${esc(aria)}">${rows}</ol>`;
}

// Incidents-over-time histogram for the selected finding: REAL per-day
// occurrence counts (last 14 days, oldest->newest) carried on each cohort as
// `daily14` by the open cohorts endpoint. No synthesis: the bars are exactly the
// stored occurrence timestamps bucketed by day. Heights are proportional to the
// busiest day; the peak label names that day. Accessible as a single role="img"
// summarizing total + peak (mirrors renderMiniGraph's aria approach).
function dayLabel(daysAgo) {
  if (daysAgo === 0) return "today";
  if (daysAgo === 1) return "yesterday";
  const d = new Date(Date.now() - daysAgo * 86400000);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
function renderIncidents(cluster) {
  const daily = Array.isArray(cluster.daily14) ? cluster.daily14 : null;
  const head = `<div class="hd">Incidents over time <span class="tag">This finding &middot; last 14 days</span>`;
  if (!daily) {
    return `<div class="card incidents" style="margin-top:18px">${head}</div>
      <div class="bd"><div class="muted">incidents are loading...</div></div></div>`;
  }
  const total = daily.reduce((a, b) => a + b, 0);
  if (!total) {
    return `<div class="card incidents" style="margin-top:18px">${head}</div>
      <div class="bd"><div class="muted">no occurrences recorded yet</div></div></div>`;
  }
  const max = Math.max(...daily, 1);
  // i=0 is the oldest (13 days ago), i=13 is today; daysAgo = 13 - i.
  let peakIdx = 0;
  daily.forEach((v, i) => { if (v > daily[peakIdx]) peakIdx = i; });
  const peakDay = dayLabel(13 - peakIdx);
  const bars = daily.map((v, i) => {
    const daysAgo = 13 - i;
    const label = dayLabel(daysAgo);
    const h = v > 0 ? Math.max(6, Math.round((v / max) * 100)) : 0;
    const tip = `${label} &middot; ${v} incident${v === 1 ? "" : "s"}`;
    return `<div class="inc-col" title="${esc(tip)}">
      <div class="inc-bar" style="height:${h}%"${v === 0 ? ' data-empty="1"' : ""}></div>
    </div>`;
  }).join("");
  const aria = `Incidents over time, last 14 days: ${total} total, peak ${daily[peakIdx]} on ${peakDay}.`;
  return `<div class="card incidents" style="margin-top:18px">
    <div class="hd">Incidents over time <span class="tag">This finding &middot; last 14 days</span>
      <span class="inc-tot"><b>${total}</b> total &middot; peak ${esc(peakDay)}</span>
    </div>
    <div class="bd">
      <div class="inc-chart" role="img" aria-label="${esc(aria)}">${bars}</div>
    </div>
  </div>`;
}

function renderDetailLoading() {
  return `<section class="detail" aria-busy="true">
    <div class="sk sk-line" style="width:120px"></div>
    <div class="sk sk-line" style="width:55%;height:24px;margin:14px 0"></div>
    <div class="sk sk-line" style="width:30%"></div>
    <div class="grid"><div class="sk sk-card"></div><div class="sk sk-card"></div></div>
  </section>`;
}

function renderDetail() {
  if (S.status === "loading" && !S.cohorts) return renderDetailLoading();
  const list = filteredCohorts();
  const cluster = (S.cohorts || []).find((c) => c.sig === S.selSig);
  if (!cluster) {
    return `<section class="detail"><div class="empty"><div>
      <div class="ico" aria-hidden="true">&larr;</div>
      <div class="big">Select a finding</div>
      <div class="sub">${list.length ? "Pick a finding from the list to see its evidence and deterministic repro." : "No finding selected."}</div>
    </div></div></section>`;
  }
  const fl = fileLineFromMessage(cluster.message);
  const replayN = (S.repro && S.repro.replay) ? S.repro.replay.length : 0;
  const ctx = (S.repro && S.repro.context) || {};
  const plat = platformOf(cluster);
  const platLabel = plat ? `flutter (${plat})` : (ctx.platform ? `flutter (${ctx.platform})` : "flutter");
  return `<section class="detail">
    <div class="crumb"><b>${esc(cluster.sig)}</b></div>
    <h1 class="h1">${esc(titleFromMessage(cluster.message))}</h1>
    <div class="src">${fl ? esc(fl) : esc(firstLine(cluster.message))}</div>

    <div class="row">
      ${replayN ? `<span class="badge b-rep">&#10003; Reproduced deterministically &middot; ${replayN} action${replayN === 1 ? "" : "s"}</span>`
        : (S.reproStatus === "loading" ? `<span class="badge b-det">checking repro...</span>` : "")}
      <span class="chip">${esc(platLabel)}</span>
      <span class="chip">${cluster.count} occurrence${cluster.count === 1 ? "" : "s"}</span>
      <span class="chip">${esc(cluster.sig)}</span>
    </div>

    ${renderReproHero(cluster)}

    ${renderIncidents(cluster)}

    <div class="grid">
      <div>
        <div class="card who">
          <div class="hd">Who it hits</div>
          <div class="bd">${renderWho(cluster)}</div>
        </div>
        <div class="card">
          <div class="hd">Stack / message</div>
          <div class="bd stk"><b>${esc(firstLine(cluster.message))}</b></div>
        </div>
      </div>
      <div>
        <div class="card">
          <div class="hd">Path to the bug</div>
          <div class="bd" style="overflow:auto">${renderMiniGraph(cluster.sig)}</div>
        </div>
        <div class="card">
          <div class="hd">Context at error time</div>
          <div class="bd ctx-grid">
            ${Object.keys(ctx).length ? Object.entries(ctx).map(([k, v]) => `<span class="chip">${esc(k)}=${esc(fmtCtxVal(v))}</span>`).join("")
              : (S.reproStatus === "loading" ? `<span class="muted">loading context...</span>` : `<span class="muted">no context</span>`)}
          </div>
        </div>
      </div>
    </div>
  </section>`;
}

function renderScansHead(total, shown) {
  return `<div class="list-head">
    <div class="titlerow">
      <h2 id="scans-label">Scans</h2>
    </div>
    <div class="search" role="search">
      ${searchIcon()}
      <input id="scan-search" type="search" placeholder="Search scans" value="${esc(S.scanFilter.q)}"
        aria-label="Search scans" autocomplete="off" spellcheck="false"/>
      ${S.scanFilter.q ? `<button class="clear" id="scan-clear" aria-label="Clear search">x</button>` : ""}
    </div>
    <div class="filters">
      <div class="selwrap"><select id="scan-status" aria-label="Filter scans by result">
        ${[
          ["all", "All scans"],
          ["finding", "Found bugs"],
          ["clean", "Clean"],
          ["running", "Running"],
          ["queued", "Queued"],
          ["error", "Errors"],
        ].map(([v, label]) => `<option value="${v}"${S.scanFilter.status === v ? " selected" : ""}>${esc(label)}</option>`).join("")}
      </select></div>
    </div>
  </div>`;
}

function scanFooter(total, shown) {
  const count = Number(total || 0);
  const visible = shown == null ? count : Number(shown || 0);
  const label = `${count} scan${count === 1 ? "" : "s"}`;
  return `<div class="list-foot">${visible === count ? label : `${visible} of ${label}`}</div>`;
}

function renderScansInbox() {
  if (S.scanStatus === "loading" && !S.scans) {
    return `<aside class="list" aria-busy="true">
      ${renderScansHead(0, 0)}
      <div class="list-scroll">${[0, 1, 2].map(() => `<div class="sk-item">
        <div class="sk sk-line" style="width:38%"></div>
        <div class="sk sk-line" style="width:80%"></div>
        <div class="sk sk-line" style="width:58%"></div></div>`).join("")}</div>
      ${scanFooter(0)}
    </aside>`;
  }
  if (S.scanStatus === "error" && !S.scans) {
    return `<aside class="list">${renderScansHead(0, 0)}
      <div class="empty"><div>
        <div class="ico" aria-hidden="true">!</div>
        <div class="big">Could not load scans</div>
        <div class="sub">${esc(S.scanErr || "Scan state is unavailable.")}</div>
        <button class="ghostbtn" id="scans-retry">Retry</button>
      </div></div>
      ${scanFooter(0)}
    </aside>`;
  }
  if (!S.scans || !S.scans.length) {
    return `<aside class="list">${renderScansHead(0, 0)}
      <div class="empty"><div>
        <div class="ico" aria-hidden="true">[ ]</div>
        <div class="big">No scans yet</div>
        <div class="sub">Run Reproit from CI or your machine and scan results will show here separately from production bugs.</div>
      </div></div>
      ${scanFooter(0)}
    </aside>`;
  }
  const list = filteredScans();
  let rows;
  if (!list.length) {
    rows = `<div class="empty"><div>
      <div class="ico" aria-hidden="true">?</div>
      <div class="big">No matches</div>
      <div class="sub">No scans match your search or filter.</div>
      <button class="ghostbtn" id="scan-reset">Clear filters</button>
    </div></div>`;
  } else {
    rows = list.map((job) => {
      const status = scanStatus(job);
      const sel = job.id === S.selScanId;
      const findings = Number(job.findings || 0);
      return `<div class="item bug-item scan-item ${sel ? "sel" : ""}" data-scan="${esc(job.id)}"
        role="option" aria-selected="${sel}" tabindex="-1">
        <div class="top">
          <span class="sev sev-${status === "finding" ? "crash" : status === "error" ? "leak" : status === "clean" ? "operability" : "unknown"}">${esc(scanStatusLabel(job))}</span>
          <span class="chip" style="margin-left:auto">${findings} finding${findings === 1 ? "" : "s"}</span>
        </div>
        <div class="bug-id">${esc(job.id)}</div>
        <div class="ttl">${esc(appDirName(job.appDir))}</div>
        <div class="meta"><span>${esc(job.backend || "web")}</span><span>${esc(fmtTime(job.started_at))}</span><span>${Number(job.done || 0)}/${Number(job.shards || 0)} runs</span></div>
      </div>`;
    }).join("");
  }
  return `<aside class="list">
    ${renderScansHead(S.scans.length, list.length)}
    <div class="list-scroll" role="listbox" aria-labelledby="scans-label" tabindex="0">${rows}</div>
    ${scanFooter(S.scans.length, list.length)}
  </aside>`;
}

function reportTitle(report, idx) {
  const first = normalizeReport(report).split("\n").map((l) => l.trim()).find(Boolean);
  return first ? first.replace(/^#+\s*/, "").slice(0, 96) : `Finding ${idx + 1}`;
}

function normalizeReport(report) {
  return String(report || "").replace(/\\n/g, "\n").trim();
}

function parseFindingReport(report) {
  const text = normalizeReport(report);
  const labels = ["Path to reproduce", "Repro command", "Observed", "Expected"];
  const out = { title: "", path: "", command: "", observed: "", expected: "", raw: text };
  const hits = labels
    .map((label) => {
      const re = new RegExp(`(^|\\n)${label}:`, "i");
      const m = re.exec(text);
      return m ? { label, index: m.index + (m[1] ? 1 : 0), end: m.index + (m[1] ? 1 : 0) + label.length + 1 } : null;
    })
    .filter(Boolean)
    .sort((a, b) => a.index - b.index);
  out.title = hits.length ? text.slice(0, hits[0].index).trim() : text.split("\n").map((l) => l.trim()).find(Boolean) || "";
  for (let i = 0; i < hits.length; i += 1) {
    const cur = hits[i];
    const next = hits[i + 1];
    const body = text.slice(cur.end, next ? next.index : text.length).trim();
    if (cur.label === "Path to reproduce") out.path = body;
    if (cur.label === "Repro command") out.command = body.split("\n").map((l) => l.trim()).find(Boolean) || "";
    if (cur.label === "Observed") out.observed = body;
    if (cur.label === "Expected") out.expected = body;
  }
  return out;
}

function renderFindingPath(path) {
  const lines = String(path || "").split("\n").map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return "";
  return `<ol class="finding-path">${lines.map((line) => {
    const cleaned = line.replace(/^\d+\.\s*/, "");
    const m = cleaned.match(/^(.*?)(\s+\[[^\]]+\])$/);
    return `<li><span>${esc(m ? m[1].trim() : cleaned)}</span>${m ? `<code>${esc(m[2].trim().slice(1, -1))}</code>` : ""}</li>`;
  }).join("")}</ol>`;
}

function renderScanFinding(job, shard, idx) {
  const parsed = parseFindingReport(shard.report || "");
  const title = parsed.title || `Finding ${idx + 1}`;
  const cmd = parsed.command;
  return `<div class="scan-report">
    <div class="hd">
      <span>Seed ${esc(shard.seed)}</span>
      <span class="tag">${esc(title)}</span>
    </div>
    <div class="scan-finding">
      <div class="finding-summary">${esc(title)}</div>
      ${renderFindingPath(parsed.path)}
      ${cmd ? `<div class="cmd-term finding-cmd" role="group" aria-label="Command to reproduce this scan finding locally">
        <div class="cmd-bar">
          <span class="cmd-title">reproduce locally</span>
          <button class="term-copy" data-copy="${esc(cmd)}" type="button">copy</button>
        </div>
        <div class="cmd-body"><div class="ln"><span class="prompt">$</span> ${esc(cmd)}</div></div>
      </div>` : ""}
      ${parsed.observed || parsed.expected ? `<div class="finding-compare">
        ${parsed.observed ? `<div><div class="mini-label">Observed</div><p>${esc(parsed.observed)}</p></div>` : ""}
        ${parsed.expected ? `<div><div class="mini-label">Expected</div><p>${esc(parsed.expected)}</p></div>` : ""}
      </div>` : ""}
      ${parsed.raw && !parsed.path && !parsed.observed && !parsed.expected ? `<pre class="stack-msg">${esc(parsed.raw)}</pre>` : ""}
    </div>
  </div>`;
}

function renderScanReports(detail) {
  const findings = ((detail && detail.shardDetail) || []).filter((s) => s.state === "finding");
  if (!findings.length) {
    return `<div class="muted">No bug findings were recorded for this scan.</div>`;
  }
  const job = detail || {};
  return `<div class="scan-report-list">${findings.map((s, i) => renderScanFinding(job, s, i)).join("")}</div>`;
}

function renderScanDetail() {
  if (S.scanStatus === "loading" && !S.scans) return renderDetailLoading();
  const list = filteredScans();
  const job = (S.scans || []).find((j) => j.id === S.selScanId);
  if (!job) {
    return `<section class="detail"><div class="empty"><div>
      <div class="ico" aria-hidden="true">&larr;</div>
      <div class="big">Select a scan</div>
      <div class="sub">${list.length ? "Pick a scan from the list to inspect its findings." : "No scan selected."}</div>
    </div></div></section>`;
  }
  const detail = S.scanDetail || job;
  return `<section class="detail">
    <h1 class="h1">${esc(appDirName(job.appDir))}</h1>
    <div class="src">${esc(job.id)}</div>

    <div class="row">
      <span class="chip">${esc(job.backend || "web")}</span>
      <span class="chip">${Number(job.done || 0)}/${Number(job.shards || 0)} runs</span>
      <span class="chip">${esc(fmtTime(job.started_at))}</span>
    </div>

    <div class="card">
      <div class="hd">Findings</div>
      <div class="bd">${detail._error ? `<div class="muted">Could not load scan detail: ${esc(detail._error)}</div>` : renderScanReports(detail)}</div>
    </div>
  </section>`;
}

function renderScansView() {
  if (S.scanStatus === "idle") {
    loadScans();
  }
  return `<div class="wrap">${renderScansInbox()}${renderScanDetail()}</div>`;
}

// ---- account / onboarding ---------------------------------------------------
function maskKey(k) {
  if (!k || k.length < 16) return k || "";
  return k.slice(0, 12) + "…" + k.slice(-4);
}

// The bundled sample shop, served same-origin by this cloud with the ReproIt web
// SDK already inside it. Opening it with ?appId=&key= wires that SDK to THIS
// project's ingest, so clicking Checkout in the demo reports a real crash here.
// It's the fastest way for a new self-host user to see the monitoring loop close
// before pointing the SDK at their own app; needs the project key in the browser
// (present right after you create the project, or remembered from a past visit).
function demoUrl(appId, key) {
  if (!appId || !key) return null;
  // Keep the credential in the URL fragment: fragments are never sent in HTTP
  // requests or Referer headers. The demo consumes it once and immediately
  // replaces the fragment with its normal hash route.
  const cfg = btoa(JSON.stringify({ appId, key }));
  return location.origin + "/demo#reproit=" + encodeURIComponent(cfg);
}

// The "try it now" launcher: one button that opens the demo wired to this
// project. `context` tunes the caption for where it renders (the Connect card vs
// the empty Bugs list).
function renderDemoLauncher(appId, key, context) {
  const url = demoUrl(appId, key);
  if (!url) return "";
  const caption = context === "bugs"
    ? "Open ReproIt’s sample shop, add an item, then check out. The sample crash will appear here."
    : "Open ReproIt’s sample shop and check out to send a sample crash to <b>Bugs</b>.";
  return `<div class="muted" style="margin-top:14px">${caption}</div>
    <button class="primary-sm" type="button" data-demo="${esc(url)}" style="margin-top:8px">Open sample shop &#8599;</button>`;
}

// First-run panel for the Bugs list before any bucket exists. It turns the dead
// "no findings" state into a guided path: create a project (done once there's
// one), launch the wired demo, then watch the first crash arrive live (the list
// polls while this is on screen). Once a bucket lands the normal list replaces
// this. Distinct from the "smoke-test ingest" note for a key-less browser.
function renderGetStarted(project) {
  const appId = project ? project.appId : null;
  const key = appId ? pubKeyForApp(appId) : null;
  const launcher = renderDemoLauncher(appId, key, "bugs");
  const body = launcher
    ? `${launcher}
       <div class="muted demo-waiting" style="margin-top:16px">Waiting for your first bug<span class="demo-dots">…</span></div>`
    : `<div class="sub">Create a project on the Account page to receive its one-time SDK key and connect the sample.</div>
       <button class="ghostbtn" id="go-account" style="margin-top:12px">Open account</button>`;
  return `<aside class="list">${renderListHead(0, 0)}
    <div class="empty"><div style="max-width:560px">
      <div class="ico" aria-hidden="true">[ ]</div>
      <div class="big">Test your new project</div>
      ${body}
    </div></div></aside>`;
}

// The "connect" card: surfaces the project key (once at creation, else the
// browser-remembered one), the SDK start snippet with the app id filled in, and
// the one-line CLI setup command. This is the post-signup onboarding step that
// used to be missing (the key was silently written to localStorage only).
function sdkSetup(platform, appId, publishableKey, ingestBase) {
  const key = publishableKey || "<your pk_live_ key>";
  const repo = "https://github.com/ReproIt/reproit";
  const setups = {
    web: {
      label: "Web",
      install: `mkdir -p src/vendor\ncurl -fsSLo src/vendor/reproit-web.js https://raw.githubusercontent.com/ReproIt/reproit/main/sdk/reproit-web.js`,
      code: `import './vendor/reproit-web.js';\n\nReproIt.start({\n  appId: '${appId}',\n  key: '${key}',\n  endpoint: '${ingestBase}/v1/events',\n  build: { version: '1.4.2', commit: 'abc123' },\n});`,
      guide: `${repo}/blob/main/sdk/reproit-web.README.md`,
    },
    reactNative: {
      label: "React Native",
      install: `git submodule add ${repo} vendor/reproit\nnpm install ./vendor/reproit/sdk/reproit-react-native`,
      code: `import { ReproIt } from 'reproit-react-native';\n\nReproIt.init({\n  appId: '${appId}',\n  endpoint: '${ingestBase}',\n  apiKey: '${key}',\n  build: { version: '1.4.2', commit: 'abc123' },\n});`,
      guide: `${repo}/blob/main/sdk/reproit-react-native/README.md`,
    },
    flutter: {
      label: "Flutter",
      install: `dependencies:\n  reproit_flutter:\n    git:\n      url: ${repo}.git\n      path: sdk/reproit_flutter\n      ref: main`,
      code: `ReproIt.init(const ReproItConfig(\n  appId: '${appId}',\n  endpoint: '${ingestBase}',\n  apiKey: '${key}',\n  buildVersion: '1.4.2',\n  buildCommit: 'abc123',\n));`,
      guide: `${repo}/blob/main/sdk/reproit_flutter/README.md`,
    },
    apple: {
      label: "iOS + macOS",
      install: `git submodule add ${repo} Vendor/reproit\n# Add Vendor/reproit/sdk/reproit-ios as a local Swift package`,
      code: `ReproIt.start(ReproItConfig(\n  appId: "${appId}",\n  endpoint: "${ingestBase}",\n  apiKey: "${key}",\n  buildVersion: "1.4.2",\n  buildCommit: "abc123"\n))`,
      guide: `${repo}/blob/main/sdk/reproit-ios/README.md`,
    },
    android: {
      label: "Android",
      install: `git submodule add ${repo} vendor/reproit\n# Include vendor/reproit/sdk/reproit-android in settings.gradle.kts`,
      code: `ReproIt.init(this, ReproItConfig(\n  appId = "${appId}",\n  endpoint = "${ingestBase}",\n  apiKey = "${key}",\n  buildVersion = "1.4.2",\n  buildCommit = "abc123",\n))`,
      guide: `${repo}/blob/main/sdk/reproit-android/README.md`,
    },
    windows: {
      label: "Windows",
      install: `git submodule add ${repo} vendor/reproit\ndotnet add reference vendor/reproit/sdk/reproit-windows/src/ReproIt.Windows/ReproIt.Windows.csproj`,
      code: `ReproItClient.Init(new ReproItConfig("${appId}")\n{\n    Endpoint = "${ingestBase}",\n    ApiKey = "${key}",\n    BuildVersion = "1.4.2",\n    BuildCommit = "abc123",\n});`,
      guide: `${repo}/blob/main/sdk/reproit-windows/README.md`,
    },
    linux: {
      label: "Linux",
      install: `pip install 'reproit-linux @ git+${repo}.git#subdirectory=sdk/reproit-linux'`,
      code: `ReproIt.init(\n    app_id="${appId}",\n    endpoint="${ingestBase}",\n    api_key="${key}",\n    build_version="1.4.2",\n    build_commit="abc123",\n    root_widget=window,\n)`,
      guide: `${repo}/blob/main/sdk/reproit-linux/README.md`,
    },
  };
  return setups[platform] || setups.web;
}

function renderSdkSetup(appId, publishableKey, ingestBase) {
  const keys = ["web", "reactNative", "flutter", "apple", "android", "windows", "linux"];
  const setup = sdkSetup(S.sdkPlatform, appId, publishableKey, ingestBase);
  const tabs = keys.map((key) => {
    const item = sdkSetup(key, appId, publishableKey, ingestBase);
    return `<button type="button" class="sdk-tab${key === S.sdkPlatform ? " active" : ""}" data-sdk-platform="${key}" aria-pressed="${key === S.sdkPlatform}">${esc(item.label)}</button>`;
  }).join("");
  const codeBox = (label, value) => `<div class="sdk-step"><div class="sdk-step-head"><b>${label}</b><button class="term-copy" data-copy="${esc(value)}" type="button">copy</button></div><pre>${esc(value)}</pre></div>`;
  return `<div class="sdk-setup">
    <div class="sdk-tabs" role="group" aria-label="SDK platform">${tabs}</div>
    ${codeBox("1. Install", setup.install)}
    ${codeBox("2. Initialize at app launch", setup.code)}
    <a class="sdk-guide" href="${esc(setup.guide)}" target="_blank" rel="noopener">Read the ${esc(setup.label)} guide &#8599;</a>
  </div>`;
}

function renderConnectCard(project) {
  if (!project) return "";
  const appId = project.appId;
  const justCreated = S.justCreatedKey && S.justCreatedKey.appId === appId;
  const storedKey = keyForApp(appId);
  const key = justCreated ? S.justCreatedKey.apiKey : storedKey;
  // The SDK snippet + demo ship the PUBLISHABLE key (browser-safe, write-only);
  // the secret key stays for the CLI command and is never placed in page JS.
  const pubKey = justCreated ? S.justCreatedKey.publishableKey : pubKeyForApp(appId);
  const endpoint = location.origin.replace("://cloud.", "://ingest.");
  let keyBlock;
  if (justCreated) {
    keyBlock = `<div style="border:1px solid var(--ok,#2e7d32);border-radius:8px;padding:10px 12px;margin-bottom:12px">
        <div><b>Copy your project key now.</b> It is shown once; only a hash is kept after you leave this page.</div>
        <div class="keybox" style="margin-top:8px"><span>${esc(key)}</span><button class="term-copy" data-copy="${esc(key)}" type="button">copy</button></div>
      </div>`;
  } else if (storedKey) {
    keyBlock = `<div class="muted">Project key (remembered in this browser):</div>
      <div class="keybox"><span>${esc(maskKey(storedKey))}</span><button class="term-copy" data-copy="${esc(storedKey)}" type="button">copy</button></div>`;
  } else {
    keyBlock = `<div class="muted">CLI access now comes from <code>reproit login</code>. It opens the browser, signs in to your account, and discovers your projects.</div>`;
  }
  const publishableBlock = pubKey
    ? `<div class="muted" style="margin-top:14px">Publishable SDK key:</div>
       <div class="keybox"><span>${esc(pubKey)}</span><button class="term-copy" data-copy="${esc(pubKey)}" type="button">copy</button></div>`
    : `<div class="muted" style="margin-top:14px">The publishable key is not stored in this browser. Generate a replacement to connect the SDK. Any previous publishable key for this project will stop working.</div>
       <button class="ghostbtn-sm" id="rotate-publishable-key" type="button" style="margin-top:8px" ${S.publishableKeyBusy ? "disabled" : ""}>${S.publishableKeyBusy ? "Generating…" : "Generate publishable key"}</button>`;
  return `<div class="card">
    <div class="hd">Connect</div>
    <div class="bd">
      ${keyBlock}
      ${publishableBlock}
      ${renderDemoLauncher(appId, pubKey, "connect")}
      <div class="muted" style="margin-top:14px">Connect your app with the write-only publishable key. It can send events but cannot read project data.</div>
      ${renderSdkSetup(appId, pubKey, endpoint)}
    </div>
  </div>`;
}

// The dispatch settings form: binds the GitHub repo + PAT that let the cloud
// trigger hosted reproduction in the customer's CI. Writes to the same
// PUT /v1/apps/:app/integrations the CLI uses. Replaces the old curl-only path.
function renderDispatchSettings(project) {
  if (!project) return "";
  const appId = project.appId;
  const st = S.integrationApp === appId ? S.integrationStatus : "idle";
  let inner;
  if (st === "nokey") {
    inner = `<div class="muted">Configure hosted reproduction when you create the project and its one-time key is available here.</div>`;
  } else if (st === "loading" || st === "idle") {
    inner = `<div class="muted">Loading…</div>`;
  } else if (st === "error") {
    inner = `<div class="muted">Could not load the dispatch binding. Retry from the project switcher.</div>`;
  } else {
    const intg = S.integrationApp === appId && S.integration ? S.integration : {};
    const repoVal = S.dispatchRepoDraft !== null ? S.dispatchRepoDraft : intg.dispatchRepo || "";
    const tokenSet = !!intg.dispatchTokenSet;
    inner = `<div class="muted">Bind the GitHub repo whose CI reproduces this app's bugs. Reproit fires a repository_dispatch there; your workflow runs the reproduction and posts the verdict back. The token is a fine-grained PAT with Contents read/write on that repo.</div>
      <form id="dispatch-form" class="inline-form" style="margin-top:14px">
        <label class="fld-lbl" for="dispatch-repo">Dispatch repo (owner/name)</label>
        <input class="field-input" id="dispatch-repo" value="${esc(repoVal)}" placeholder="acme/web" autocomplete="off" />
        <label class="fld-lbl" for="dispatch-token" style="margin-top:12px">Dispatch token</label>
        <input class="field-input" id="dispatch-token" type="password" value="" placeholder="${tokenSet ? "•••••••• set. Leave blank to keep" : "ghp_… required to enable dispatch"}" autocomplete="off" />
        <div class="inline-row" style="margin-top:14px">
          <button class="primary-sm" type="submit"${S.dispatchBusy ? " disabled" : ""}>${S.dispatchBusy ? "Saving…" : "Save dispatch settings"}</button>
        </div>
      </form>`;
  }
  return `<div class="card">
    <div class="hd">Hosted reproduction</div>
    <div class="bd">${inner}</div>
  </div>`;
}

function renderTrackerSettings(project) {
  const suffix = project ? String(project.appId || "").toUpperCase().replace(/[^A-Z0-9]/g, "_") : "APP_ID";
  const appId = project ? project.appId : "your-app";
  const loginCommand = location.hostname === "cloud.reproit.com"
    ? `reproit login`
    : `reproit login --cloud ${location.origin}`;
  return `<div class="card">
    <div class="hd">Issue tracker</div>
    <div class="bd">
      <div class="muted">Set one provider for this project. ReproIt files a ticket when a new bucket appears and links it back to the bug.</div>
      <div class="setup-list" style="margin-top:14px">
        <div class="setup-row">
          <b>GitHub</b>
          <code>REPROIT_TRACKER_PROVIDER__${esc(suffix)}=github</code>
          <code>REPROIT_GH_REPO__${esc(suffix)}=owner/repo</code>
          <code>REPROIT_GH_TOKEN__${esc(suffix)}=...</code>
        </div>
        <div class="setup-row">
          <b>Jira</b>
          <code>REPROIT_TRACKER_PROVIDER__${esc(suffix)}=jira</code>
          <code>REPROIT_JIRA_BASE_URL__${esc(suffix)}=https://your-site.atlassian.net</code>
          <code>REPROIT_JIRA_PROJECT_KEY__${esc(suffix)}=ENG</code>
        </div>
        <div class="setup-row">
          <b>Linear</b>
          <code>REPROIT_TRACKER_PROVIDER__${esc(suffix)}=linear</code>
          <code>REPROIT_LINEAR_TEAM_ID__${esc(suffix)}=...</code>
          <code>REPROIT_LINEAR_TOKEN__${esc(suffix)}=...</code>
        </div>
        <div class="setup-row">
          <b>Shortcut</b>
          <code>REPROIT_TRACKER_PROVIDER__${esc(suffix)}=shortcut</code>
          <code>REPROIT_SHORTCUT_PROJECT_ID__${esc(suffix)}=...</code>
          <code>REPROIT_SHORTCUT_TOKEN__${esc(suffix)}=...</code>
        </div>
      </div>
      <div class="keybox" style="margin-top:14px"><span>${esc(loginCommand)}</span></div>
    </div>
  </div>`;
}

function renderInviteSettings(account) {
  const invitations = account.invitations || [];
  const pendingRows = invitations.map((invite) => {
    const expires = new Date(invite.expiresAt);
    const expiry = Number.isNaN(expires.getTime()) ? "" : `Expires ${expires.toLocaleDateString()}`;
    return `<div class="pending-invite"><div class="pending-identity"><b>${esc(invite.email)}</b><span>${esc(invite.role)}${expiry ? ` · ${esc(expiry)}` : ""}</span></div><div class="invite-actions"><button class="linkbtn" type="button" data-invite-resend="${Number(invite.id)}" ${S.inviteBusy ? "disabled" : ""}>Resend</button><button class="linkbtn danger-link" type="button" data-invite-revoke="${Number(invite.id)}" ${S.inviteBusy ? "disabled" : ""}>Revoke</button></div></div>`;
  }).join("");
  return `<div class="card invite-card">
    <div class="hd">Invite member <span class="tag">${invitations.length} pending</span></div>
    <div class="bd">
      <form id="invite-form" class="invite-form">
        <label class="fld-lbl" for="invite-email">Email address</label>
        <input class="invite-email" id="invite-email" type="email" value="${esc(S.inviteEmail)}" placeholder="teammate@company.com" autocomplete="email" required />
        <div class="invite-controls"><div class="invite-role-field"><label class="fld-lbl" for="invite-role">Access level</label><div class="selwrap invite-role-wrap"><select id="invite-role"><option value="member"${S.inviteRole === "member" ? " selected" : ""}>Member</option><option value="admin"${S.inviteRole === "admin" ? " selected" : ""}>Admin</option></select></div></div><button class="primary-sm invite-submit" type="submit" ${S.inviteBusy ? "disabled" : ""}>${S.inviteBusy === "send" ? "Sending..." : "Send invite"}</button></div>
        <div class="muted">The invitation expires in 7 days.</div>
      </form>
      ${pendingRows ? `<div class="pending-invites"><div class="pending-title">Pending invitations</div>${pendingRows}</div>` : ""}
    </div>
  </div>`;
}

function renderTeamSettings(account, org) {
  const members = account.members || [];
  const q = S.teamSearch.trim().toLowerCase();
  const roleValue = (m) => S.roleDraft[m.userId] || m.role || "none";
  const changed = members.some((m) => roleValue(m) !== (m.role || "none"));
  const filtered = q ? members.filter((m) => m.email.toLowerCase().includes(q)) : members;
  const roleSelect = (member) => {
    const value = roleValue(member);
    const options = [
      ["none", "no access"],
      ["member", "member"],
      ["admin", "admin"],
      ["owner", "owner"],
    ];
    return `<div class="selwrap role-select-wrap"><select data-account-role-select="${member.userId}" ${S.roleSaving ? "disabled" : ""}>
      ${options.map(([v, label]) => `<option value="${v}"${value === v ? " selected" : ""}>${label}</option>`).join("")}
    </select></div>`;
  };
  const rows = filtered.map((m) => {
    return `<tr>
      <td class="m-email">${esc(m.email)}</td>
      <td class="m-role">${roleSelect(m)}</td>
    </tr>`;
  }).join("");
  return `<div class="card team-card">
    <div class="hd">Team access <span class="tag">${members.filter((m) => m.seat === true).length} active</span></div>
    <div class="bd">
      <div class="team-tools">
        <input id="team-search" value="${esc(S.teamSearch)}" placeholder="Search users" autocomplete="off" />
        <button class="primary-sm" id="team-save" type="button" ${!changed || S.roleSaving ? "disabled" : ""}>${S.roleSaving ? "Saving..." : "Save changes"}</button>
      </div>
      <table class="seattable">
        <colgroup>
          <col>
          <col class="role-col">
        </colgroup>
        <thead><tr><th>User</th><th>Role</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="2" class="muted">${members.length ? "No users match your search." : "No users loaded."}</td></tr>`}</tbody>
      </table>
    </div>
  </div>`;
}

function renderOrganizationSettings(account, org) {
  const name = S.orgNameDraft == null ? (org.name || "") : S.orgNameDraft;
  return `<div class="card org-card"><div class="hd">Workspace</div><div class="bd">${canManageOrg() ? `<form id="org-name-form" class="inline-form"><label class="fld-lbl" for="org-name">Workspace name</label><div class="inline-row"><input id="org-name" value="${esc(name)}" maxlength="80" required /><button class="primary-sm" type="submit" ${S.orgBusy ? "disabled" : ""}>Rename</button></div></form>` : `<div class="muted">${esc(org.name || "Workspace")}</div>`}</div></div>`;
}

function renderProjectDanger(project) {
  if (!project || !canManageOrg()) return "";
  const ready = S.projectDeleteConfirm === project.name && !S.projectDeleteBusy;
  return `<div class="card danger-zone">
    <div class="hd">Delete project</div>
    <div class="bd">
      <p>Permanently deletes this project's bugs, runs, evidence, integrations, and API keys.</p>
      <form id="project-delete-form" class="danger-form">
        <label class="fld-lbl" for="project-delete-confirm">Type ${esc(project.name)} to confirm</label>
        <div class="inline-row">
          <input id="project-delete-confirm" value="${esc(S.projectDeleteConfirm)}" autocomplete="off" />
          <button class="danger-btn" type="submit"${ready ? "" : " disabled"}>${S.projectDeleteBusy ? "Deleting..." : "Delete project"}</button>
        </div>
      </form>
    </div>
  </div>`;
}

function renderOrganizationDanger(account, org) {
  const active = (account.organizations || []).find((item) => item.id === org.id);
  if (org.role !== "owner" || org.selfHosted || !active || active.personal) return "";
  const paid = org.plan && org.plan !== "free";
  const ready = S.orgDeleteConfirm === org.name && !S.orgDeleteBusy && !paid;
  return `<div class="card danger-zone">
    <div class="hd">Delete organization</div>
    <div class="bd">
      <p>Permanently deletes this organization, every project, member, key, bug, run, and evidence object.</p>
      ${paid ? `<div class="muted danger-note">Cancel the ${esc(org.plan)} subscription in billing and wait for the plan to become free before deleting.</div>` : `<form id="org-delete-form" class="danger-form">
        <label class="fld-lbl" for="org-delete-confirm">Type ${esc(org.name)} to confirm</label>
        <div class="inline-row">
          <input id="org-delete-confirm" value="${esc(S.orgDeleteConfirm)}" autocomplete="off" />
          <button class="danger-btn" type="submit"${ready ? "" : " disabled"}>${S.orgDeleteBusy ? "Deleting..." : "Delete organization"}</button>
        </div>
      </form>`}
    </div>
  </div>`;
}

function renderAccountView() {
  if (S.accountStatus === "loading" || S.accountStatus === "idle") {
    return `<div class="single"><section class="seatcard"><div class="sk sk-card"></div></section></div>`;
  }
  if (S.accountStatus === "unauth") {
    return `<div class="empty" style="height:calc(100vh - 100px)"><div>
      <div class="ico" aria-hidden="true">[ ]</div>
      <div class="big">Sign in</div>
      <div class="sub">Projects and production bug buckets are attached to your Reproit account.</div>
      <a class="ghostbtn" href="/login">Sign in</a>
      <a class="retry" href="/signup">Create account</a>
    </div></div>`;
  }
  if (S.accountStatus === "error") {
    return `<div class="empty" style="height:calc(100vh - 100px)"><div>
      <div class="ico" aria-hidden="true">!</div>
      <div class="big">Could not load account</div>
      <div class="sub">${esc(S.accountErr || "Account state is unavailable.")}</div>
      <button class="retry" id="account-retry">Retry</button>
    </div></div>`;
  }
  const a = S.account || {};
  const org = a.org || {};
  const projects = a.projects || [];
  const project = currentProject() || projects[0] || null;
  const canManage = canManageOrg();
  return `<div class="single"><section class="seatcard">
    <div class="account-hero">
      <div class="account-ident">
        <div class="crumb">${esc(org.name || "Organization")} · Account</div>
        <h1 class="h1">${esc(a.email || "Account")}</h1>
        <div class="src">${esc(org.role || "member")} · self-hosted · ${projects.length} project${projects.length === 1 ? "" : "s"}</div>
      </div>
      <div class="account-actions">
        <button class="danger-btn" id="sign-out" type="button">Sign out</button>
      </div>
    </div>

    <div class="grid">
      <div>
        ${renderOrganizationSettings(a, org)}
        <div class="card">
          <div class="hd">Project</div>
          <div class="bd">
            ${projects.length ? `<label class="fld-lbl" for="account-project">Active project</label>
              <div class="selwrap"><select id="account-project">${projectOptions()}</select></div>
              <div class="muted" style="margin-top:10px">Changing the project updates bugs and bucket deep links.</div>`
              : `<div class="muted">No project yet. Create one to receive SDK events and production buckets.</div>`}
            ${canManage ? `<form id="project-form" class="inline-form" style="margin-top:16px">
                <label class="fld-lbl" for="project-name">New project</label>
                <div class="inline-row">
                  <input id="project-name" value="${esc(S.newProject)}" placeholder="Web app, iOS app, Android app" autocomplete="off" />
                  <button class="primary-sm" type="submit"${S.projectBusy ? " disabled" : ""}>${S.projectBusy ? "Creating..." : "Create"}</button>
                </div>
              </form>`
              : `<div class="muted" style="margin-top:16px">Only owners and admins can create projects.</div>`}
          </div>
        </div>
        ${renderConnectCard(project)}
        ${renderDispatchSettings(project)}
        ${renderTrackerSettings(project)}
        ${renderProjectDanger(project)}
      </div>
      <div>
        ${canManage ? `${renderInviteSettings(a)}${renderTeamSettings(a, org)}` : `<div class="card"><div class="hd">Team access</div><div class="bd"><div class="muted">Owners and admins manage team access.</div></div></div>`}
        ${renderOrganizationDanger(a, org)}
      </div>
    </div>
  </section></div>`;
}

async function signOut() {
  const res = await fetch(CFG.api + "/auth/logout", {
    method: "POST",
    credentials: "same-origin",
  });
  const data = await res.json().catch(() => ({}));
  try {
    localStorage.removeItem("reproit.cfg");
    localStorage.removeItem("reproit.keys");
    // Publishable keys are write-only but still credentials: clear them on
    // sign-out too so a shared machine keeps no ingest capability behind.
    localStorage.removeItem("reproit.pubkeys");
    sessionStorage.removeItem(ACCOUNT_SCROLL_SESSION_KEY);
  } catch {}
  S.account = null;
  S.accountStatus = "unauth";
  if (!res.ok) {
    setBanner((data && data.error) || "Could not sign out cleanly", "warn");
  }
  location.href = "/login";
}

async function saveTeamAccess() {
  const members = (S.account && S.account.members) || [];
  const changes = members
    .map((m) => ({ userId: m.userId, role: S.roleDraft[m.userId], current: m.role || "none" }))
    .filter((m) => m.role && m.role !== m.current);
  if (!changes.length) return;
  S.roleSaving = true;
  render();
  for (const change of changes) {
    const r = await accountReq("/account/members/role", "POST", {
      userId: change.userId,
      role: change.role,
    });
    if (!r.ok) {
      S.roleSaving = false;
      setBanner((r.data && r.data.error) || "Could not update team access", "warn");
      render();
      return;
    }
  }
  S.roleSaving = false;
  S.roleDraft = {};
  setBanner("");
  await loadAccount();
  render();
}

async function switchOrganization(orgId){if(!orgId||S.orgBusy)return;S.orgBusy=true;paintOrgSwitch();const r=await accountReq("/account/orgs/active","POST",{orgId:Number(orgId)});if(!r.ok){S.orgBusy=false;setBanner((r.data&&r.data.error)||"Could not switch organization","warn");paintOrgSwitch();return}try{localStorage.setItem("reproit.activeOrg",String(orgId))}catch{}CFG={...CFG,app:"",key:""};saveConfig(CFG);S.orgBusy=false;S.orgNameDraft=null;S.roleDraft={};S.teamSearch="";resetAppData();if(window.ReproitTriage&&window.ReproitTriage.resetForApp)window.ReproitTriage.resetForApp();await loadAccount();syncProjectUrl(true);setBanner("");if(S.view==="scans")loadScans();else render()}
async function sendInvitation(){const email=S.inviteEmail.trim();if(!email||S.inviteBusy)return;S.inviteBusy="send";render();const r=await accountReq("/account/invitations","POST",{email,role:S.inviteRole});S.inviteBusy="";if(!r.ok){setBanner((r.data&&r.data.error)||"Could not send invitation","warn");render();return}S.inviteEmail="";setBanner(`Invitation sent to ${email}.`);await loadAccount();render()}
async function invitationAction(action,id){if(S.inviteBusy)return;S.inviteBusy=action;render();const r=await accountReq(`/account/invitations/${action}`,"POST",{invitationId:Number(id)});S.inviteBusy="";if(!r.ok){setBanner((r.data&&r.data.error)||`Could not ${action} invitation`,"warn");render();return}setBanner(action==="resend"?"Invitation sent again.":"Invitation revoked.");await loadAccount();render()}
async function saveOrganizationName(){const name=(S.orgNameDraft==null?(S.account&&S.account.org&&S.account.org.name):S.orgNameDraft||"").trim();if(!name||S.orgBusy)return;S.orgBusy=true;render();const r=await accountReq("/account/orgs/name","POST",{name});S.orgBusy=false;if(!r.ok){setBanner((r.data&&r.data.error)||"Could not rename workspace","warn");render();return}S.orgNameDraft=null;setBanner("");await loadAccount();render()}

async function createProject(name) {
  const clean = String(name || "").trim();
  if (!clean) return;
  S.projectBusy = true;
  render();
  const r = await accountReq("/account/projects", "POST", { name: clean });
  S.projectBusy = false;
  if (!r.ok) {
    setBanner((r.data && r.data.error) || "Could not create project", "warn");
    render();
    return;
  }
  rememberKey(r.data.appId, r.data.apiKey, r.data.publishableKey);
  CFG = { ...CFG, app: r.data.appId, key: r.data.apiKey };
  saveConfig(CFG);
  // Both keys are returned exactly once; surface them now so the user can copy the
  // secret (CLI / CI) and the publishable key (SDK snippet) before only hashes
  // remain on the server.
  S.justCreatedKey = { appId: r.data.appId, apiKey: r.data.apiKey, publishableKey: r.data.publishableKey };
  S.integration = null;
  S.integrationApp = null;
  S.integrationStatus = "idle";
  syncProjectUrl(true);
  S.newProject = "";
  await loadAccount();
  // loadAccount re-selects the active project and, unless the app was pinned in
  // the URL at page load (EXPLICIT.app), falls back to projects[0] (oldest by id).
  // A freshly created project is newest, so without this it would bounce the view
  // to the oldest project and hide the just-shown key + demo launcher. Re-assert
  // the new project as active so the user lands on what they just made.
  CFG = { ...CFG, app: r.data.appId, key: r.data.apiKey };
  saveConfig(CFG);
  syncProjectUrl(true);
  paintProjectSwitch();
  // Clear any prior project's cached findings/buckets so the Bugs list reloads
  // fresh (empty) for the new project and shows the onboarding panel, instead of
  // rendering the previous project's stale buckets (triage only reloads when its
  // listStatus is idle).
  resetAppData();
  if (window.ReproitTriage && window.ReproitTriage.resetForApp) window.ReproitTriage.resetForApp();
  setView("account", { replace: true, force: true });
  render();
}

async function deleteCurrentProject() {
  const project = currentProject();
  if (!project || S.projectDeleteBusy || S.projectDeleteConfirm !== project.name) return;
  S.projectDeleteBusy = true;
  render();
  const r = await accountReq(`/account/projects/${encodeURIComponent(project.appId)}`, "DELETE", { confirm: S.projectDeleteConfirm });
  S.projectDeleteBusy = false;
  if (!r.ok) {
    setBanner((r.data && r.data.error) || "Could not delete project", "warn");
    render();
    return;
  }
  forgetProjectKeys(project.appId);
  S.projectDeleteConfirm = "";
  S.justCreatedKey = null;
  CFG = { ...CFG, app: "", key: "" };
  saveConfig(CFG);
  resetAppData();
  if (window.ReproitTriage && window.ReproitTriage.resetForApp) window.ReproitTriage.resetForApp();
  await loadAccount();
  syncProjectUrl(true);
  setBanner(`Deleted ${project.name}.`);
  render();
}

async function deleteCurrentOrganization() {
  const org = S.account && S.account.org;
  if (!org || S.orgDeleteBusy || S.orgDeleteConfirm !== org.name) return;
  S.orgDeleteBusy = true;
  render();
  const r = await accountReq("/account/orgs/current", "DELETE", { confirm: S.orgDeleteConfirm });
  S.orgDeleteBusy = false;
  if (!r.ok) {
    setBanner((r.data && r.data.error) || "Could not delete organization", "warn");
    render();
    return;
  }
  S.orgDeleteConfirm = "";
  CFG = { ...CFG, app: "", key: "" };
  saveConfig(CFG);
  resetAppData();
  if (r.data && r.data.orgId) {
    try { localStorage.setItem("reproit.activeOrg", String(r.data.orgId)); } catch {}
  }
  await loadAccount();
  syncProjectUrl(true);
  setBanner(`Deleted ${org.name}.`);
  render();
}

async function rotatePublishableKey() {
  const project = currentProject();
  if (!project || S.publishableKeyBusy) return;
  S.publishableKeyBusy = true;
  render();
  const r = await accountReq(`/account/projects/${encodeURIComponent(project.appId)}/publishable-key`, "POST", {});
  S.publishableKeyBusy = false;
  if (!r.ok || !r.data.publishableKey) {
    setBanner((r.data && r.data.error) || "Could not generate publishable key", "warn");
    render();
    return;
  }
  rememberKey(project.appId, null, r.data.publishableKey);
  setBanner("Publishable key generated. Update the SDK anywhere the previous key was used.");
  render();
}

// Load the dispatch/tracker binding for the active project. Uses the project
// key (Bearer); with no key in this browser we cannot read it, so the form shows
// a "connect the key" note instead of erroring.
async function loadIntegration(appId) {
  if (!appId) return;
  S.dispatchRepoDraft = null; // reload the repo field from the server for this app
  if (!CFG.key) { S.integrationStatus = "nokey"; S.integrationApp = appId; if (S.view === "account") render(); return; }
  S.integrationStatus = "loading";
  S.integrationApp = appId;
  try {
    S.integration = await api("/v1/apps/" + encodeURIComponent(appId) + "/integrations");
    S.integrationStatus = "ready";
  } catch (e) {
    S.integration = null;
    S.integrationStatus = "error";
  }
  if (S.view === "account") render();
}

// Save the dispatch repo/token via PUT /v1/apps/:app/integrations. A blank token
// field keeps the stored one (the endpoint's keep/replace semantics), so a user
// can change the repo without re-entering the PAT.
async function saveDispatch() {
  const project = currentProject();
  if (!project) return;
  const repo = (document.getElementById("dispatch-repo")?.value || "").trim();
  const token = document.getElementById("dispatch-token")?.value || "";
  S.dispatchBusy = true;
  render();
  const body = { dispatchRepo: repo };
  if (token) body.dispatchToken = token;
  const r = await apiSend("/v1/apps/" + encodeURIComponent(project.appId) + "/integrations", "PUT", body);
  S.dispatchBusy = false;
  if (!r.ok) {
    setBanner((r.data && r.data.error) || ("Could not save dispatch settings (HTTP " + r.status + ")"), "warn");
    render();
    return;
  }
  S.dispatchRepoDraft = null;
  S.dispatchTokenDraft = "";
  setBanner("Dispatch settings saved.", "ok");
  await loadIntegration(project.appId);
  render();
}

function syncNav() {
  document.querySelectorAll("nav a[data-view]").forEach((a) => {
    const on = a.dataset.view === S.view;
    a.classList.toggle("on", on);
    if (on) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
}

// ---- top-level render -------------------------------------------------------
function render() {
  if (S.view === "account") {
    root().innerHTML = renderAccountView();
    wireAccountScroll();
    if (S.accountStatus === "idle") loadAccount().then(() => {
      if (S.view === "account") render();
    });
    else {
      // Lazy-load the dispatch binding for the active project, once per app.
      // loadIntegration sets integrationApp, so this guard stops it re-firing.
      const p = currentProject();
      if (p && S.integrationApp !== p.appId) loadIntegration(p.appId);
    }
    return;
  }
  if (S.view === "scans") {
    root().innerHTML = renderScansView();
    return;
  }
  // Non-scan views (the per-seat triage product) are owned by triage.js,
  // which mounts itself into #app-root. app.js owns scans/account; this
  // hands off so the two modules never fight over the same DOM.
  if (S.view !== "findings" && window.ReproitTriage) {
    window.ReproitTriage.render(S.view);
    return;
  }
  if (S.status === "error" && !S.cohorts) {
    root().innerHTML = `<div class="empty" style="height:calc(100vh - 100px)"><div>
      <div class="ico" aria-hidden="true">!</div>
      <div class="big">Cloud unreachable</div>
      <div class="sub">The dashboard could not load findings from the configured cloud API.</div>
      <div class="err-detail">${esc(S.error || "")}</div>
      <div style="display:flex;gap:10px;justify-content:center">
        <button class="retry" id="retry-btn">Retry</button>
      </div>
    </div></div>`;
    return;
  }
  root().innerHTML = `<div class="wrap">${renderInbox()}${renderDetail()}</div>`;
}

// ---- interaction: clicks ----------------------------------------------------
document.addEventListener("click", (ev) => {
  const t = ev.target;

  const pickerToggle = t.closest("[data-picker-toggle]");
  if (pickerToggle) { toggleHeaderPicker(pickerToggle.dataset.pickerToggle); return; }
  const pickerOption = t.closest("[data-picker-option]");
  if (pickerOption) {
    const kind = pickerOption.dataset.pickerOption, value = pickerOption.dataset.pickerValue;
    closeHeaderPickers();
    if (kind === "org") switchOrganization(Number(value)); else setActiveProject(value);
    return;
  }
  closeHeaderPickers();

  const item = t.closest(".item[data-sig]");
  if (item) { S.kbdIdx = Number(item.dataset.idx); selectSig(item.dataset.sig); return; }

  const scanItem = t.closest(".item[data-scan]");
  if (scanItem) { selectScan(scanItem.dataset.scan); return; }

  const navlink = t.closest("nav a[data-view]");
  if (navlink) {
    ev.preventDefault();
    if (S.view === navlink.dataset.view) return;
    setView(navlink.dataset.view);
    return;
  }

  if (t.id === "go-account" || t.id === "account-retry") {
    setView("account");
    if (t.id === "account-retry") loadAccount().then(() => {
      if (S.view === "account") render();
    });
    return;
  }

  if (t.id === "account-open") {
    setView("account");
    return;
  }

  if (t.id === "team-save") {
    saveTeamAccess();
    return;
  }
  const resendInvite=t.closest("[data-invite-resend]");if(resendInvite){invitationAction("resend",resendInvite.dataset.inviteResend);return}
  const revokeInvite=t.closest("[data-invite-revoke]");if(revokeInvite){invitationAction("revoke",revokeInvite.dataset.inviteRevoke);return}

  if (t.id === "sign-out") {
    signOut();
    return;
  }
  if (t.id === "rotate-publishable-key") { rotatePublishableKey(); return; }

  const sdkPlatform = t.closest("[data-sdk-platform]");
  if (sdkPlatform) {
    S.sdkPlatform = sdkPlatform.dataset.sdkPlatform;
    try { localStorage.setItem("reproit.sdkPlatform", S.sdkPlatform); } catch {}
    render();
    return;
  }

  const demoBtn = t.closest("[data-demo]");
  if (demoBtn) {
    window.open(demoBtn.dataset.demo, "_blank", "noopener");
    // Switch to the Bugs list (the "triage" view, owned by triage.js) so its
    // "waiting for your first bug" poller is on screen when the crash arrives
    // from the demo tab.
    if (S.view !== "triage") setView("triage");
    window.ReproitTriage?.watchForFirstBug?.();
    return;
  }

  const copyBtn = t.closest("[data-copy]");
  if (copyBtn) {
    const txt = copyBtn.dataset.copy || "";
    navigator.clipboard?.writeText(txt).then(() => {
      const old = copyBtn.textContent; copyBtn.textContent = "copied"; setTimeout(() => { copyBtn.textContent = old; }, 1100);
    }).catch(() => { copyBtn.textContent = "copy failed"; });
    return;
  }

  const evkind = t.closest("[data-evkind]");
  if (evkind) { S.evKind = Number(evkind.dataset.evkind); render(); return; }

  if (t.id === "f-clear") { S.filter.q = ""; S.kbdIdx = -1; render(); document.getElementById("f-search")?.focus(); return; }
  if (t.id === "f-reset") { S.filter = { q: "", disc: "all", sort: "count" }; S.kbdIdx = -1; render(); return; }
  if (t.id === "retry-btn" || t.id === "map-retry") { loadFindings(); return; }
  if (t.id === "scans-retry") { loadScans(); return; }
  if (t.id === "scan-clear") { S.scanFilter.q = ""; render(); document.getElementById("scan-search")?.focus(); return; }
  if (t.id === "scan-reset") { S.scanFilter = { q: "", status: "all" }; render(); return; }
  if (t.id === "term-copy") {
    const cmd = t.dataset.cmd || "";
    navigator.clipboard?.writeText(cmd).then(() => {
      const old = t.textContent; t.textContent = "copied"; setTimeout(() => { t.textContent = old; }, 1100);
    }).catch(() => { t.textContent = "copy failed"; });
    return;
  }
  if (t.id === "replay-btn") {
    t.textContent = "↻ Replaying...";
    setTimeout(() => { const b = document.getElementById("replay-btn"); if (b) b.textContent = "↻ Replay"; }, 1200);
    return;
  }
});

// ---- interaction: search + filter inputs ------------------------------------
document.addEventListener("input", (ev) => {
  if (ev.target.id === "f-search") {
    S.filter.q = ev.target.value; S.kbdIdx = -1;
    const pos = ev.target.selectionStart;
    render();
    const el = document.getElementById("f-search");
    if (el) { el.focus(); try { el.setSelectionRange(pos, pos); } catch {} }
  }
  if (ev.target.id === "scan-search") {
    S.scanFilter.q = ev.target.value;
    const pos = ev.target.selectionStart;
    render();
    const el = document.getElementById("scan-search");
    if (el) { el.focus(); try { el.setSelectionRange(pos, pos); } catch {} }
  }
  if (ev.target.id === "project-name") {
    S.newProject = ev.target.value;
  }
  if(ev.target.id==="invite-email")S.inviteEmail=ev.target.value;
  if(ev.target.id==="org-name")S.orgNameDraft=ev.target.value;
  if(ev.target.id==="project-delete-confirm" || ev.target.id==="org-delete-confirm"){
    const id=ev.target.id,pos=ev.target.selectionStart;
    if(id==="project-delete-confirm")S.projectDeleteConfirm=ev.target.value;else S.orgDeleteConfirm=ev.target.value;
    render();
    const el=document.getElementById(id);if(el){el.focus();try{el.setSelectionRange(pos,pos)}catch{}}
  }
  if (ev.target.id === "dispatch-repo") {
    S.dispatchRepoDraft = ev.target.value;
  }
  if (ev.target.id === "team-search") {
    S.teamSearch = ev.target.value;
    render();
    document.getElementById("team-search")?.focus();
  }
});
document.addEventListener("change", (ev) => {
  if (ev.target.id === "f-disc") { S.filter.disc = ev.target.value; S.kbdIdx = -1; render(); }
  if (ev.target.id === "f-sort") { S.filter.sort = ev.target.value; S.kbdIdx = -1; render(); }
  if (ev.target.id === "scan-status") { S.scanFilter.status = ev.target.value; render(); }
  if (ev.target.matches("[data-account-role-select]")) {
    S.roleDraft[Number(ev.target.dataset.accountRoleSelect)] = ev.target.value;
    render();
    return;
  }
  if (ev.target.id === "account-project") {
    setActiveProject(ev.target.value);
    render();
  }
  if(ev.target.id==="invite-role")S.inviteRole=ev.target.value;
});
document.addEventListener("submit", (ev) => {
  if (ev.target.id === "project-form") {
    ev.preventDefault();
    createProject(document.getElementById("project-name")?.value || "");
  }
  if (ev.target.id === "dispatch-form") {
    ev.preventDefault();
    saveDispatch();
  }
  if(ev.target.id==="invite-form"){ev.preventDefault();sendInvitation()}
  if(ev.target.id==="org-name-form"){ev.preventDefault();saveOrganizationName()}
  if(ev.target.id==="project-delete-form"){ev.preventDefault();deleteCurrentProject()}
  if(ev.target.id==="org-delete-form"){ev.preventDefault();deleteCurrentOrganization()}
});

// ---- interaction: keyboard navigation ---------------------------------------
document.addEventListener("keydown", (ev) => {
  const toggle = ev.target.closest?.("[data-picker-toggle]");
  if (toggle && ["Enter", " ", "ArrowDown", "ArrowUp"].includes(ev.key)) { ev.preventDefault(); toggleHeaderPicker(toggle.dataset.pickerToggle, true); return; }
  const option = ev.target.closest?.("[data-picker-option]");
  if (!option) return;
  const options = Array.from(option.closest("[role=listbox]").querySelectorAll("[data-picker-option]")), index = options.indexOf(option);
  if (["ArrowDown", "ArrowUp", "Home", "End"].includes(ev.key)) {
    ev.preventDefault();
    const next = ev.key === "Home" ? 0 : ev.key === "End" ? options.length - 1 : ev.key === "ArrowDown" ? Math.min(options.length - 1, index + 1) : Math.max(0, index - 1);
    options[next]?.focus();
  } else if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); option.click(); }
  else if (ev.key === "Escape") { ev.preventDefault(); const kind = option.dataset.pickerOption; closeHeaderPickers(); document.getElementById(`${kind}-picker-button`)?.focus(); }
});
document.addEventListener("keydown", (ev) => {
  if (S.view !== "findings") return;
  // don't hijack typing in the search box except for arrows/enter
  const inSearch = document.activeElement && document.activeElement.id === "f-search";
  const list = filteredCohorts();
  if (!list.length) return;

  if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
    ev.preventDefault();
    if (ev.key === "ArrowDown") S.kbdIdx = Math.min(list.length - 1, S.kbdIdx + 1);
    else S.kbdIdx = Math.max(0, (S.kbdIdx < 0 ? 0 : S.kbdIdx) - 1);
    selectSig(list[S.kbdIdx].sig);
    requestAnimationFrame(() => {
      document.getElementById("item-" + list[S.kbdIdx].sig)?.scrollIntoView({ block: "nearest" });
    });
    return;
  }
  if (ev.key === "Enter" && (inSearch || (document.activeElement && document.activeElement.id === "list-scroll"))) {
    const idx = S.kbdIdx >= 0 ? S.kbdIdx : 0;
    if (list[idx]) { S.kbdIdx = idx; selectSig(list[idx].sig); }
    return;
  }
});

// ---- shared surface for triage.js ------------------------------------------
// The triage product (triage.js) is a separate view that reuses this module's
// config (cloud base + app + Bearer key) and a couple of pure helpers, so the
// two views agree on which cloud/app they're pointed at. Exposed read-only.
window.ReproitApp = {
  cfg: () => CFG,
  esc,
  abs,
  fileLineFromMessage,
  titleFromMessage,
  firstLine,
  setBanner,
  setConn,
  redirectToLogin,
  root,
  // The Bearer-authenticated fetch the findings list uses, reused by the bug
  // list (which is on the same api-key-protected /v1 surface).
  api,
  // Onboarding: the bug list (triage.js) uses these to offer the wired demo from
  // its own empty state, the primary place a first-run user lands. The demo is
  // wired with the publishable key (pubKeyForApp), never the secret one.
  keyForApp,
  pubKeyForApp,
  demoUrl,
  renderDemoLauncher,
};

// ---- boot -------------------------------------------------------------------
async function boot() {
  await loadAccount().catch(() => {
    S.accountStatus = "error";
    S.accountErr = "could not load account";
  });
  if (S.accountStatus === "unauth" && !CFG.key) {
    redirectToLogin();
    return;
  }
  syncViewUrl(true);
  paintProjectSwitch();
  syncNav();
  if (S.view === "account") render();
  else if (S.view === "scans") loadScans();
  else if (S.view !== "findings" && window.ReproitTriage) window.ReproitTriage.render(S.view);
  else loadFindings();
}
boot();

window.addEventListener("beforeunload", saveAccountScroll);
function routeFromUrl() {
  saveAccountScroll();
  S.view = initialView();
  syncNav();
  render();
}
window.addEventListener("popstate", routeFromUrl);
window.addEventListener("hashchange", routeFromUrl);
