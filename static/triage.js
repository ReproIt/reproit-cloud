"use strict";

// =============================================================================
// reproit cloud, per-seat Bugs product.
//
// The front-end a developer uses to see production bugs, GRAB one, and manage
// it. This module owns the Bugs view and account-adjacent helpers; app.js owns
// Account and hands off to window.ReproitTriage.render(view) when the view
// isn't findings (see app.js render()).
//
// Auth model (matches the cloud's route table in src/main.rs):
//   - The bug LIST prefers the signed-in dashboard route. If there is no session,
//     an API key can still use the public replay-package route.
//   - The seat-gated dashboard reads `/detail`, `/triage`, and `/account/*` are
//     COOKIE-authenticated (the /app page is served same-origin, so the session
//     cookie flows automatically with credentials:"include"). A signed-in member
//     without a seat gets 402 there; not signed in gets 401.
// =============================================================================

(function () {
  const A = window.ReproitApp; // shared config + helpers from app.js
  const esc = A.esc;

  // ---- config / fetch -------------------------------------------------------
  const cfg = () => A.cfg();

  // Bearer-authenticated fetch for the api-key-protected bug list. Returns
  // {ok, status, data} so callers can branch on 401/402 without throwing.
  async function apiKeyGet(path) {
    const c = cfg();
    const headers = {};
    if (c.key) headers["Authorization"] = "Bearer " + c.key;
    const res = await fetch(c.api + path, { headers, credentials: "include" });
    let data = null;
    try { data = await res.json(); } catch { /* non-json */ }
    return { ok: res.ok, status: res.status, data };
  }

  // Cookie-authenticated fetch for the seat-gated dashboard surface
  // (detail / triage / account). The session cookie is same-origin, so we just
  // include credentials; no Bearer.
  async function cookieReq(path, method, body) {
    const c = cfg();
    const opts = { method: method || "GET", credentials: "include", headers: {} };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(c.api + path, opts);
    let data = null;
    try { data = await res.json(); } catch { /* non-json */ }
    return { ok: res.ok, status: res.status, data };
  }

  const appPath = (suffix) =>
    `/v1/apps/${encodeURIComponent(cfg().app)}/buckets` + (suffix || "");
  const appRoot = (suffix) =>
    `/v1/apps/${encodeURIComponent(cfg().app)}` + (suffix || "");

  // ---- state ----------------------------------------------------------------
  const T = {
    // bug list (impact-sorted by the API; carries impact + resolution per item)
    buckets: null,        // [{bucketId, count, message, crashSig, repro, lineage, impact, resolution, ...}]
    triageByBucket: {},   // bucketId -> {status, updatedAt}
    listStatus: "idle",   // idle | loading | ready | error | needkey | unauth | noseat
    listErr: null,
    statusFilter: "all",  // all | active | resolving | resolved | regressed (prod-truth resolution)
    selBucket: null,

    // detail
    detail: null,
    detailStatus: "idle", // idle | loading | ready | error
    detailErr: null,
    savingTriage: false,

    // timeline (spike-drops graph on the detail)
    timeline: null,       // {series, total, windowSecs, resolution}
    timelineFor: null,    // bucketId the loaded timeline belongs to
    timelineStatus: "idle", // idle | loading | ready | error

    // regressions / activity strip (recent resolution-event transitions)
    events: null,         // [{bucketId, fromStatus, toStatus, build, at}]
    eventsStatus: "idle", // idle | loading | ready | error

    // seats
    me: null,
    seatsStatus: "idle",  // idle | loading | ready | error | unauth
    seatsErr: null,
  };

  const STATUSES = ["untriaged", "investigating", "fixed", "wontfix"];
  // Prod-truth resolution states, in fix-it-first order (regressed is the loudest).
  const RESOLUTIONS = ["regressed", "active", "resolving", "resolved"];

  // ---- small helpers --------------------------------------------------------
  function reproSummary(repro) {
    // The trust signal: "reproduces 5/5" vs "fixed". Zero attempts are omitted:
    // any developer can run the bucket locally, so absence of a posted replay
    // result is not a workflow state.
    if (!repro || repro.status === "ready" || !repro.attempts) {
      return null;
    }
    const r = `${repro.reproduced}/${repro.attempts}`;
    if (repro.status === "reproduced") return { label: `reproduces ${r}`, cls: "rp-real", detail: "still failing" };
    if (repro.status === "clean") return { label: `fixed ${r}`, cls: "rp-fixed", detail: "no longer reproduces" };
    if (repro.status === "data_dependent") return { label: `data-dependent ${r}`, cls: "rp-data", detail: "input-specific" };
    if (repro.status === "stale") return { label: `stale ${r}`, cls: "rp-none", detail: "graph drifted" };
    if (repro.status === "flaky") return { label: `flaky ${r}`, cls: "rp-data", detail: "intermittent" };
    return { label: `${repro.status} ${r}`, cls: "rp-none", detail: repro.status };
  }

  function statusPill(status) {
    const s = status || "untriaged";
    return `<span class="tstatus ts-${esc(s)}">${esc(s)}</span>`;
  }

  function bucketTriageStatus(b) {
    const t = T.triageByBucket[b.bucketId] || b.triage || {};
    return t.status || "untriaged";
  }

  function untriagedCount() {
    return (T.buckets || []).filter((b) => bucketTriageStatus(b) === "untriaged").length;
  }

  function setBugCountConn() {
    const n = untriagedCount();
    A.setConn(`${n} untriaged bug${n === 1 ? "" : "s"}`, "var(--green)");
  }

  function buildStr(b) {
    if (!b || typeof b !== "object") return "";
    const v = b.version, c = b.commit;
    if (v && c) return `${esc(v)} (${esc(String(c).slice(0, 7))})`;
    if (v) return esc(v);
    if (c) return esc(String(c).slice(0, 7));
    return "";
  }

  function memberEmail(userId) {
    const m = (T.me && T.me.members || []).find((x) => x.userId === userId);
    return m ? m.email : ("user #" + userId);
  }

  // ---- impact / severity / resolution presentation --------------------------
  // The oracle-class severity chip (crash > leak > operability > jank). Mirrors
  // src/ingest/impact.rs `Severity::as_str`, so the chip names the same class the
  // ranking used.
  function severityChip(sev) {
    const s = sev || "unknown";
    return `<span class="sev sev-${esc(s)}" title="oracle class: ${esc(s)}">${esc(s)}</span>`;
  }

  // Only surface non-default prod-truth resolution. REGRESSED is the loudest
  // signal, so it's a red badge, not a quiet pill.
  function resolutionChip(status) {
    const s = status || "active";
    if (s === "active") return "";
    if (s === "regressed") return `<span class="rstatus rs-regressed" title="prod contradicts the claimed fix">&#9888; regressed</span>`;
    return `<span class="rstatus rs-${esc(s)}" title="prod-truth: ${esc(s)}">${esc(s)}</span>`;
  }

  // A compact, human "why it's ranked here" from impact.why. We don't re-derive
  // the score (the API owns it); we read the same factor breakdown the score was
  // built from and surface the loudest reasons: regression first, then spiking,
  // blast (~hits), and the severity class. e.g. "regressed | spiking | ~240 hits | crash".
  function impactWhy(b) {
    const why = (b.impact && b.impact.why) || {};
    const parts = [];
    if (why.boost && why.boost.regressed) parts.push("regressed");
    else if (why.boost && why.boost.new) parts.push("untriaged");
    if (why.trend && why.trend.spiking) parts.push("spiking");
    const count = (why.blast && why.blast.count) != null ? why.blast.count : b.count;
    if (count != null) parts.push("~" + count + " hit" + (count === 1 ? "" : "s"));
    const sev = b.impact && b.impact.severity;
    if (sev && sev !== "unknown") parts.push(sev);
    return parts.join(" · ");
  }

  // The resolution VERDICT in plain words, shown next to the timeline graph.
  // Reads the computed Outcome (status + evidence) the timeline/detail returns.
  function resolutionVerdict(res) {
    if (!res || res.status === "active") return null;
    const fix = res.fixedInBuild;
    switch (res.status) {
      case "regressed":
        return { cls: "rs-regressed", text: `Regressed: the bug came back on ${fix ? esc(fix) : "a fixed build"}${res.lastSeenOnFixedBuild ? " (last seen " + timeAgo(res.lastSeenOnFixedBuild) + ")" : ""}. The fix did not hold.` };
      case "resolved":
        return { cls: "rs-resolved", text: `Resolved: no hits on ${fix ? esc(fix) : "the fix build"} or newer across enough post-fix traffic. Prod confirms the fix.` };
      case "resolving":
        return { cls: "rs-resolving", text: `Resolving: a fix is claimed on ${fix ? esc(fix) : "a build"}, but prod is still validating it (not enough quiet time or traffic yet).` };
      default:
        return null;
    }
  }

  // Coarse "2h ago" / "3d ago" relative time for the activity strip + verdicts.
  function timeAgo(iso) {
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return "";
    const s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }

  // ---- spike-drops timeline: hand-rolled inline SVG (no charting lib) --------
  // Renders the per-window TOTAL series as a bar chart and marks the fix-build
  // point so the spike-drop after a fix is legible. The fix marker is placed at
  // the FIRST window whose timestamp is >= the fix build's first appearance; we
  // approximate that from the per-build `series` (the first window carrying the
  // fix build). If we can't locate it, no marker is drawn (honest: we only mark
  // what we can place).
  function timelineSVG(tl) {
    const total = densifyRecentTimeline(tl);
    if (!total.length) {
      return `<div class="muted" style="padding:8px 2px">No occurrences recorded yet, so there's no timeline to draw.</div>`;
    }
    const W = 300, H = 170, padL = 6, padR = 6, padT = 12, padB = 24;
    const innerW = W - padL - padR, innerH = H - padT - padB;
    const n = total.length;
    const max = Math.max(1, ...total.map((c) => c.count));
    const gap = n > 1 ? Math.min(6, innerW / n * 0.3) : 0;
    const rawBw = (innerW - gap * (n - 1)) / n;
    const bw = Math.min(42, rawBw);
    const offset = (rawBw - bw) / 2;
    const x = (i) => padL + offset + i * (rawBw + gap);
    const yTop = (v) => padT + innerH * (1 - v / max);

    // Locate the fix-build window: the earliest window carrying the fix build in
    // the per-build series. The resolution gives us the fix build name.
    const fixBuild = tl.resolution && tl.resolution.fixedInBuild;
    let fixWin = null;
    if (fixBuild) {
      const fixCells = (tl.series || []).filter((c) => c.build === fixBuild);
      if (fixCells.length) fixWin = fixCells[0].window;
    }
    const fixIdx = fixWin != null ? total.findIndex((c) => c.window === fixWin) : -1;

    const bars = total.map((c, i) => {
      const h = c.count > 0 ? Math.max(2, innerH - innerH * (1 - c.count / max)) : 0;
      const post = fixIdx >= 0 && i >= fixIdx; // bars at/after the fix are "after"
      const cls = post ? "tl-bar tl-post" : "tl-bar";
      return `<rect class="${cls}" x="${x(i).toFixed(1)}" y="${yTop(c.count).toFixed(1)}" width="${bw.toFixed(1)}" height="${h.toFixed(1)}" rx="1.5"><title>${esc(shortWin(c.window))}: ${c.count} hit${c.count === 1 ? "" : "s"}</title></rect>`;
    }).join("");

    // The fix marker: a vertical rule at the fix window + a flag label.
    let marker = "";
    if (fixIdx >= 0) {
      const mx = (x(fixIdx) - gap / 2).toFixed(1);
      marker = `<line class="tl-fixline" x1="${mx}" y1="${padT - 6}" x2="${mx}" y2="${padT + innerH}" />
        <text class="tl-fixlabel" x="${Math.min(W - 70, +mx + 4)}" y="${padT - 1}">fix ${esc(fixBuild)}</text>`;
    }
    const baseY = (padT + innerH).toFixed(1);
    const axis = `<line class="tl-axis" x1="${padL}" y1="${baseY}" x2="${(W - padR).toFixed(1)}" y2="${baseY}" />`;
    const firstLbl = `<text class="tl-tick" x="${padL}" y="${H - 6}">${esc(shortWin(total[0].window))}</text>`;
    const lastLbl = `<text class="tl-tick" x="${W - padR}" y="${H - 6}" text-anchor="end">${esc(shortWin(total[n - 1].window))}</text>`;
    const aria = `Occurrence timeline: ${n} windows, peak ${max} hits${fixIdx >= 0 ? `, fix ${esc(fixBuild)} marked at window ${fixIdx + 1}` : ""}.`;
    return `<svg class="tl-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="${aria}">
      ${axis}${bars}${marker}${firstLbl}${lastLbl}</svg>`;
  }

  function densifyRecentTimeline(tl) {
    const total = (tl && tl.total) || [];
    if (!total.length) return [];
    const windowSecs = Math.max(60, Number(tl.windowSecs || 300));
    const stepMs = windowSecs * 1000;
    const parsed = total
      .map((c) => ({ window: c.window, count: c.count || 0, t: Date.parse(c.window) }))
      .filter((c) => !Number.isNaN(c.t))
      .sort((a, b) => a.t - b.t);
    const nonzero = parsed.filter((c) => c.count > 0).length;
    const recentSecs = nonzero <= 1 ? 25 * 60 : nonzero <= 3 ? 50 * 60 : 90 * 60;
    const slots = Math.max(2, Math.floor(recentSecs / windowSecs) + 1);
    if (!parsed.length || parsed.length > slots) return total;
    const end = Math.floor(parsed[parsed.length - 1].t / stepMs) * stepMs;
    const start = end - (slots - 1) * stepMs;
    const byT = new Map(parsed.map((c) => [Math.floor(c.t / stepMs) * stepMs, c.count]));
    return Array.from({ length: slots }, (_, i) => {
      const t = start + i * stepMs;
      return { window: new Date(t).toISOString(), count: byT.get(t) || 0 };
    });
  }

  // RFC3339 window start -> a short "Jun 21 14:00" label for axis ticks/titles.
  function shortWin(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const mon = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getUTCMonth()];
    const hh = String(d.getUTCHours()).padStart(2, "0");
    const mm = String(d.getUTCMinutes()).padStart(2, "0");
    return `${mon} ${d.getUTCDate()} ${hh}:${mm}`;
  }

  // ---- bug list: data -------------------------------------------------------
  function bucketListFingerprint(list) {
    return JSON.stringify((list || []).map((b) => [
      b.bucketId,
      b.count,
      b.message,
      bucketResolution(b),
      b.triage && b.triage.status,
      b.repro && b.repro.status,
    ]));
  }

  async function loadBuckets(opts) {
    const quiet = opts && opts.quiet;
    const before = bucketListFingerprint(T.buckets || []);
    T.listErr = null;
    if (!quiet) {
      T.listStatus = "loading";
      A.setConn("loading buckets", "var(--amber)");
      renderTriage();
    } else {
      A.setConn("refreshing bugs", "var(--amber)");
    }
    const c = cfg();
    let r = await cookieReq(`/v1/apps/${encodeURIComponent(c.app)}/dashboard/buckets`);
    if (r.status === 401 && c.key) r = await apiKeyGet(appPath(""));
    if (r.status === 401) {
      T.listStatus = c.key ? "needkey" : "unauth";
      quiet ? paintListBodyOnly() : renderTriage();
      return;
    }
    if (r.status === 402) {
      T.listStatus = "noseat";
      quiet ? paintListBodyOnly() : renderTriage();
      return;
    }
    if (!r.ok) {
      T.listStatus = "error";
      T.listErr = (r.data && r.data.error) || ("HTTP " + r.status);
      quiet ? paintListBodyOnly() : renderTriage();
      return;
    }
    const nextBuckets = (r.data && r.data.items) || [];
    T.buckets = nextBuckets;
    T.triageByBucket = {};
    T.buckets.forEach((b) => { if (b.triage) T.triageByBucket[b.bucketId] = b.triage; });
    T.listStatus = "ready";
    setBugCountConn();
    const after = bucketListFingerprint(T.buckets || []);
    const wanted = new URLSearchParams(location.search).get("bucket");
    const hasBucket = (id) => !!id && T.buckets.some((b) => b.bucketId === id);
    if (wanted && hasBucket(wanted)) {
      T.selBucket = wanted;
    } else if (!hasBucket(T.selBucket)) {
      T.selBucket = T.buckets.length ? T.buckets[0].bucketId : null;
    }
    if (!quiet) renderTriage();
    else if (before !== after) paintListBodyOnly();
    // Fetch triage state per bucket (cookie-auth) so the list shows the dev's
    // INTENT status alongside the prod-truth resolution. Done after the list
    // paints so the list isn't blocked on it.
    loadTriageStates({ quiet });
    // The regressions / activity strip (recent prod-truth transitions).
    loadEvents({ quiet });
    if (T.selBucket) loadDetail(T.selBucket, false);
  }

  // ---- regressions / activity strip: recent resolution transitions ----------
  function eventsFingerprint() {
    return JSON.stringify(T.events || []);
  }

  async function loadEvents(opts) {
    const quiet = opts && opts.quiet;
    const before = eventsFingerprint();
    T.eventsStatus = "loading";
    const r = await cookieReq(appRoot("/resolution-events"));
    // The strip is best-effort: a gate (401/402) or error just hides it rather
    // than blocking the list (the list already surfaces the gate state).
    if (!r.ok) {
      T.eventsStatus = "error";
      T.events = [];
      quiet ? paintListBodyOnly() : renderListColumn();
      return;
    }
    T.events = (r.data && r.data.events) || [];
    T.eventsStatus = "ready";
    if (!quiet) renderListColumn();
    else if (before !== eventsFingerprint()) paintListBodyOnly();
  }

  // ---- timeline: the spike-drops graph for the selected bucket --------------
  async function loadTimeline(bucket) {
    T.timelineFor = bucket;
    T.timeline = null; T.timelineStatus = "loading";
    paintDetailOnly();
    const r = await cookieReq(appPath("/" + encodeURIComponent(bucket) + "/timeline?window=300"));
    // Ignore a stale response if the user moved to another bucket meanwhile.
    if (T.timelineFor !== bucket) return;
    if (!r.ok) { T.timelineStatus = "error"; paintDetailOnly(); return; }
    T.timeline = r.data; T.timelineStatus = "ready";
    paintDetailOnly();
  }

  // The bug list endpoint carries no triage status, so fetch each bucket's
  // triage (cookie-auth, seat-gated). A 402/401 here means the member can see
  // the list (org key) but has no seat for the dashboard surface, surface that.
  function triageFingerprint() {
    return JSON.stringify(Object.entries(T.triageByBucket || {}).sort());
  }

  async function loadTriageStates(opts) {
    const quiet = opts && opts.quiet;
    const before = triageFingerprint();
    const buckets = T.buckets || [];
    let gateHit = null;
    await Promise.all(buckets.map(async (b) => {
      const r = await cookieReq(appPath("/" + encodeURIComponent(b.bucketId) + "/triage"));
      if (r.status === 401) { gateHit = "unauth"; return; }
      if (r.status === 402) { gateHit = "noseat"; return; }
      if (r.ok && r.data && r.data.triage) T.triageByBucket[b.bucketId] = r.data.triage;
    }));
    if (gateHit) { T.listStatus = gateHit; }
    setBugCountConn();
    if (gateHit) renderTriage();
    else if (!quiet) renderTriage();
    else if (before !== triageFingerprint()) paintListBodyOnly();
  }

  // ---- detail: data ---------------------------------------------------------
  async function loadDetail(bucket, doRenderList) {
    T.selBucket = bucket;
    T.detail = null; T.detailStatus = "loading"; T.detailErr = null;
    if (doRenderList !== false) renderTriage();
    else paintDetailOnly();
    const r = await cookieReq(appPath("/" + encodeURIComponent(bucket) + "/detail"));
    if (r.status === 401) { T.detailStatus = "error"; T.detailErr = "Sign in to view this bucket."; paintDetailOnly(); return; }
    if (r.status === 402) { T.detailStatus = "error"; T.detailErr = "A dashboard seat is required to open a bug."; paintDetailOnly(); return; }
    if (!r.ok) { T.detailStatus = "error"; T.detailErr = (r.data && r.data.error) || ("HTTP " + r.status); paintDetailOnly(); return; }
    T.detail = r.data; T.detailStatus = "ready";
    // Reflect the freshest triage into the list (e.g. a verified-fix auto-advance).
    if (r.data && r.data.triage) T.triageByBucket[bucket] = r.data.triage;
    paintDetailOnly();
    highlightSelected();
    // Load the spike-drops timeline for this bucket (separate endpoint; carries
    // the per-window series + the computed resolution verdict).
    loadTimeline(bucket);
  }

  // ---- triage control: write ------------------------------------------------
  async function postTriage(bucket, status) {
    T.savingTriage = true; paintDetailOnly();
    const body = { status };
    const r = await cookieReq(appPath("/" + encodeURIComponent(bucket) + "/triage"), "POST", body);
    T.savingTriage = false;
    if (!r.ok) {
      A.setBanner((r.data && r.data.error) || ("Could not update triage (HTTP " + r.status + ")"), "warn");
      paintDetailOnly();
      return;
    }
    A.setBanner("");
    // Refresh detail (carries the canonical triage + any auto-advance) and the
    // timeline/resolution (marking a bucket fixed changes the prod-truth verdict).
    await loadDetail(bucket, false);
    if (T.triageByBucket[bucket]) T.triageByBucket[bucket].status = status;
    loadEvents();        // a fix may surface a fresh transition in the strip
    renderListColumn();  // reflect new status chip in the list
    setBugCountConn();
  }

  // ---- seats: data ----------------------------------------------------------
  async function loadMe() {
    T.seatsStatus = "loading"; T.seatsErr = null;
    renderSeats();
    const r = await cookieReq("/account/me");
    if (r.status === 401) { T.seatsStatus = "unauth"; renderSeats(); return; }
    if (!r.ok) { T.seatsStatus = "error"; T.seatsErr = (r.data && r.data.error) || ("HTTP " + r.status); renderSeats(); return; }
    T.me = r.data; T.seatsStatus = "ready";
    renderSeats();
  }

  // ===========================================================================
  // RENDER
  // ===========================================================================
  const root = () => document.getElementById("app-root");

  function render(view) {
    if (view === "seats") { renderSeats(); if (T.seatsStatus === "idle") loadMe(); return; }
    // default: triage bug list
    if (T.listStatus === "idle") { loadBuckets(); }
    renderTriage();
  }

  // ---- first-bug poll: while the empty onboarding state is on screen (the demo
  // is running in another tab), poll quietly for the first bucket so it appears
  // live. loadBuckets({quiet}) + paintListBodyOnly means no skeleton flicker
  // between polls. Self-heals: the tick stops itself once a bucket lands or the
  // Bugs view is no longer mounted (the user navigated to Account/Scans).
  let _firstBugPollTimer = null;
  function firstBugWaiting() {
    const c = cfg();
    return T.listStatus === "ready" && !(T.buckets && T.buckets.length)
      && !!c.app && !!(A.keyForApp && A.keyForApp(c.app));
  }
  function stopFirstBugPoll() {
    if (_firstBugPollTimer) { clearInterval(_firstBugPollTimer); _firstBugPollTimer = null; }
  }
  async function firstBugTick() {
    if (!root().querySelector("#t-list-body") || !firstBugWaiting()) { stopFirstBugPoll(); return; }
    await loadBuckets({ quiet: true });
  }
  function syncFirstBugPoll() {
    if (firstBugWaiting() && root().querySelector("#t-list-body")) {
      if (!_firstBugPollTimer) _firstBugPollTimer = setInterval(firstBugTick, 4000);
    } else {
      stopFirstBugPoll();
    }
  }

  // ---- triage view (list + detail) ------------------------------------------
  function renderTriage() {
    root().innerHTML = `<div class="wrap">${renderListColumnHTML()}${renderDetailHTML()}</div>`;
    syncFirstBugPoll();
  }
  // Swap only the detail section (no list teardown), so opening a bug doesn't
  // flicker the list (same anti-flicker discipline as app.js paintDetail).
  function paintDetailOnly() {
    const cur = root().querySelector(".detail");
    if (!cur) { renderTriage(); return; }
    cur.outerHTML = renderDetailHTML();
  }
  function renderListColumn() {
    const cur = root().querySelector(".list");
    if (!cur) { renderTriage(); return; }
    cur.outerHTML = renderListColumnHTML();
  }
  function paintListBodyOnly() {
    const cur = root().querySelector("#t-list-body");
    if (!cur) { renderListColumn(); return; }
    cur.innerHTML = renderListBodyHTML();
    syncFirstBugPoll();
  }
  function highlightSelected() {
    root().querySelectorAll(".item[data-bucket]").forEach((el) => {
      const on = el.dataset.bucket === T.selBucket;
      el.classList.toggle("sel", on);
      el.setAttribute("aria-selected", on);
    });
  }

  // The list arrives ALREADY impact-sorted from the API (regressed first), so we
  // preserve that order and only apply the prod-truth resolution filter.
  function bucketResolution(b) {
    return (b.resolution && b.resolution.status) || "active";
  }
  function filteredBuckets() {
    let list = (T.buckets || []).slice();
    if (T.statusFilter !== "all") {
      list = list.filter((b) => bucketResolution(b) === T.statusFilter);
    }
    return list;
  }

  function renderListHead() {
    const total = (T.buckets || []).length;
    const shown = filteredBuckets().length;
    const regressed = (T.buckets || []).filter((b) => bucketResolution(b) === "regressed").length;
    const opts = ["all"].concat(RESOLUTIONS).map((s) =>
      `<option value="${esc(s)}"${T.statusFilter === s ? " selected" : ""}>${s === "all" ? "All statuses" : esc(s)}</option>`).join("");
    return `<div class="list-head">
      ${regressed ? `<div class="titlerow"><button class="regbadge" id="t-filter-regressed" type="button" aria-label="${regressed} regressed, show only these">&#9888; ${regressed} regressed</button></div>` : ""}
      <div class="filters">
        <div class="selwrap"><select id="t-status" aria-label="Filter by prod-truth resolution status">${opts}</select></div>
        <button class="cfgbtn" id="t-refresh" type="button" aria-label="Reload bugs">reload</button>
      </div>
      ${shown !== total ? `<div class="list-foot" style="border:0;padding:8px 0 0">${shown} of ${total} match</div>` : ""}
    </div>`;
  }

  // The REGRESSIONS / activity strip: recent prod-truth transitions so a
  // regression is visible at a glance, not buried in the list. Sits at the top
  // of the list column. Built from GET /v1/apps/:app/resolution-events.
  function renderActivityStrip() {
    const evs = T.events || [];
    if (!evs.length) return ""; // nothing transitioned yet, or strip not loaded
    // Lead with regressions (the urgent ones), then the rest, newest-first within.
    const ordered = evs.slice().sort((a, b) => {
      const ar = a.toStatus === "regressed" ? 0 : 1;
      const br = b.toStatus === "regressed" ? 0 : 1;
      return ar - br;
    }).slice(0, 6);
    const rows = ordered.map((e) => {
      const reg = e.toStatus === "regressed";
      const verb = reg ? "regressed" : (e.toStatus === "resolved" ? "resolved" : e.toStatus);
      const on = e.build ? ` on ${esc(e.build)}` : "";
      return `<button class="actev ${reg ? "actev-reg" : ""}" type="button" data-bucket="${esc(e.bucketId)}"
        aria-label="${esc(e.bucketId)} ${esc(verb)}${on} ${esc(timeAgo(e.at))}">
        <span class="ae-dot" aria-hidden="true"></span>
        <span class="ae-bkt">${esc(e.bucketId)}</span>
        <span class="ae-verb">${esc(verb)}</span><span class="ae-on">${on}</span>
        <span class="ae-ago">${esc(timeAgo(e.at))}</span>
      </button>`;
    }).join("");
    const regCount = evs.filter((e) => e.toStatus === "regressed").length;
    return `<div class="activity" role="region" aria-label="Recent resolution activity">
      <div class="act-hd">${regCount ? `<span class="act-reg">&#9888; ${regCount} regressed</span>` : "recent activity"}</div>
      <div class="act-scroll">${rows}</div>
    </div>`;
  }

  function renderListColumnHTML() {
    const busy = T.listStatus === "loading" && !T.buckets ? ` aria-busy="true"` : "";
    return `<aside class="list"${busy}>
      ${renderListHead()}
      <div id="t-list-body">${renderListBodyHTML()}</div>
    </aside>`;
  }

  function renderListBodyHTML() {
    if (T.listStatus === "needkey") {
      return `<div class="empty"><div>
          <div class="ico" aria-hidden="true">[ ]</div>
          <div class="big">Sign in required</div>
          <div class="sub"><a href="/login" style="color:var(--green)">Sign in</a> to use the dashboard for this cloud.</div>
        </div></div>`;
    }
    if (T.listStatus === "unauth") {
      return `<div class="empty"><div>
          <div class="ico" aria-hidden="true">!</div>
          <div class="big">Sign in required</div>
          <div class="sub"><a href="/login" style="color:var(--green)">Sign in</a> to grab and manage production bugs.</div>
        </div></div>`;
    }
    if (T.listStatus === "noseat") {
      return `<div class="empty"><div>
          <div class="ico" aria-hidden="true">[ ]</div>
          <div class="big">No dashboard seat</div>
          <div class="sub">The Bugs dashboard needs a seat. The CLI/SDK stays free. Ask an owner or admin to assign you one.</div>
        </div></div>`;
    }
    if (T.listStatus === "error") {
      return `<div class="empty"><div>
          <div class="ico" aria-hidden="true">!</div>
          <div class="big">Could not load bugs</div>
          <div class="err-detail">${esc(T.listErr || "")}</div>
          <button class="ghostbtn" id="t-refresh2" type="button">Retry</button>
        </div></div>`;
    }
    if (T.listStatus === "loading" && !T.buckets) {
      return `<div class="list-scroll">${[0, 1, 2, 3].map(() => `<div class="sk-item">
          <div class="sk sk-line" style="width:42%"></div>
          <div class="sk sk-line" style="width:88%"></div>
          <div class="sk sk-line" style="width:60%"></div></div>`).join("")}</div>`;
    }
    return renderReadyListBodyHTML();
  }

  function renderReadyListBodyHTML() {
    const list = filteredBuckets();
    let rows;
    if (!list.length) {
      const hasBuckets = (T.buckets || []).length;
      if (hasBuckets) {
        rows = `<div class="empty"><div>
          <div class="ico" aria-hidden="true">[ ]</div>
          <div class="big">No matches</div>
          <div class="sub">No buckets match this status filter.</div>
        </div></div>`;
      } else {
        // First-run: this is the primary place a new user lands. If the project
        // key is in this browser, offer the wired demo so they can watch a real
        // crash arrive here (the list polls quietly while this is on screen); the
        // moment a bucket lands the normal list replaces this.
        const app = cfg().app;
        const key = app && A.pubKeyForApp ? A.pubKeyForApp(app) : null;
        const launcher = key && A.renderDemoLauncher ? A.renderDemoLauncher(app, key, "bugs") : "";
        rows = launcher
          ? `<div class="empty"><div style="max-width:560px">
              <div class="ico" aria-hidden="true">[ ]</div>
              <div class="big">Watch reproit catch a bug</div>
              <div class="sub">Your project is ready. See reproit catch a live crash before you wire the SDK into your own app.</div>
              ${launcher}
              <div class="muted demo-waiting" style="margin-top:16px">Waiting for your first bug<span class="demo-dots">…</span></div>
            </div></div>`
          : `<div class="empty"><div>
              <div class="ico" aria-hidden="true">[ ]</div>
              <div class="big">No production bugs</div>
              <div class="sub">No error buckets for <b>${esc(cfg().app)}</b> yet. When the SDK ships production errors, they bucket here.</div>
            </div></div>`;
      }
    } else {
      rows = list.map((b, i) => {
        const sel = b.bucketId === T.selBucket;
        const fl = A.fileLineFromMessage(b.message);
        const last = buildStr(b.lineage && b.lineage.lastSeen);
        const res = bucketResolution(b);
        const sev = b.impact && b.impact.severity;
        const reg = res === "regressed";
        const meta = [
          fl ? `<span>${esc(fl)}</span>` : "",
          last ? `<span>last ${last}</span>` : "",
        ].filter(Boolean).join("");
        return `<div class="item bug-item ${sel ? "sel" : ""} ${reg ? "bug-reg" : ""}" data-bucket="${esc(b.bucketId)}"
          role="option" aria-selected="${sel}" tabindex="0">
          <div class="top">
            ${severityChip(sev)}
            ${resolutionChip(res)}
            ${statusPill(bucketTriageStatus(b))}
          </div>
          <div class="bug-id">${esc(b.bucketId)}</div>
          <div class="ttl">${esc(A.titleFromMessage(b.message))}</div>
          ${meta ? `<div class="meta">${meta}</div>` : ""}
        </div>`;
      }).join("");
    }
    return `
      ${renderActivityStrip()}
      <div class="list-scroll" id="t-list" role="listbox" aria-label="Bugs">${rows}</div>
      <div class="list-foot">${list.length} bug${list.length === 1 ? "" : "s"}</div>`;
  }

  function selectedBucketItem() {
    return (T.buckets || []).find((b) => b.bucketId === T.selBucket) || null;
  }

  function timelineTotal() {
    if (T.timeline && T.timelineFor === T.selBucket && Array.isArray(T.timeline.total)) {
      return densifyRecentTimeline(T.timeline);
    }
    return [];
  }

  function signalMetrics(d) {
    const total = timelineTotal();
    const sum = total.reduce((n, c) => n + (c.count || 0), 0);
    const peak = total.reduce((best, c) => (c.count || 0) > (best.count || 0) ? c : best, { count: 0, window: "" });
    return [
      { label: "occurrences", value: String(d.count || sum || 0), sub: "" },
      { label: "actions", value: String((d.replay || []).length), sub: "to reproduce" },
      { label: "peak", value: peak.count ? String(peak.count) : "0", sub: peak.window ? shortWin(peak.window) : "none" },
    ];
  }

  function renderMetricStrip(d) {
    return `<div class="metric-strip">${signalMetrics(d).map((m) => `<div class="metric">
      <div class="m-label">${esc(m.label)}</div>
      <div class="m-value">${esc(m.value)}</div>
      ${m.sub ? `<div class="m-sub">${esc(m.sub)}</div>` : ""}
    </div>`).join("")}</div>`;
  }

  function renderCohortSignals(d) {
    const item = selectedBucketItem() || {};
    const cohorts = d.cohorts || [];
    const discs = (d.discriminators && d.discriminators.length ? d.discriminators : item.discriminators) || [];
    if (cohorts.length) {
      return `<section class="cohort-section">
        <div class="section-kicker">Prevalence across cohorts <span>share of bucket occurrences · xN = vs app baseline</span></div>
        <div class="cohort-grid">${cohorts.slice(0, 6).map(renderCohortCard).join("")}</div>
      </section>`;
    }
    if (!discs.length) {
      return `<section class="cohort-section">
        <div class="cohort-grid">
          <div class="card cohort-card">
            <div class="hd">Prevalence across cohorts</div>
            <div class="bd"><div class="muted">No cohort dimensions recorded yet.</div></div>
          </div>
        </div>
      </section>`;
    }
    return `<section class="cohort-section">
      <div class="section-kicker">Prevalence across cohorts <span>share of occurrences · xN = over-represented vs app baseline</span></div>
      <div class="cohort-grid">${discs.slice(0, 6).map((x) => renderCohortCard({
        key: x.key,
        values: [{ value: x.value, cohortShare: x.cohortShare, baselineShare: x.baselineShare, lift: x.lift }],
      })).join("")}</div>
    </section>`;
  }

  function renderCohortCard(card) {
    const values = card.values || [];
    const best = values[0] || {};
    const lift = best.lift === "inf" ? "inf" : best.lift != null ? `${best.lift}x` : "no baseline";
    return `<div class="card cohort-card">
      <div class="hd">${esc(card.key || "cohort")} <span class="tag">${esc(lift)}</span></div>
      <div class="bd">
        ${values.length ? values.map((x) => {
          const pct = Math.round((Number(x.cohortShare || 0)) * 100);
          const base = Math.round((Number(x.baselineShare || 0)) * 100);
          return `<div class="cohort-row" title="app baseline ${base}%">
            <span>${esc(x.value)}</span><b>${pct}%</b>
            <div class="cohort-bar"><i style="width:${Math.max(2, Math.min(100, pct))}%"></i></div>
          </div>`;
        }).join("") : `<div class="muted">No values recorded.</div>`}
      </div>
    </div>`;
  }

  function renderPathAndStack(d, res) {
    const replay = d.replay || [];
    const displayPath = d.displayPath || [];
    return `<div class="signal-grid">
      ${renderTimelineCard(res)}
      <div class="card path-card">
        <div class="hd">Path to the bug <span class="tag">${replay.length} action${replay.length === 1 ? "" : "s"}</span></div>
        <div class="bd">
          ${displayPath.length
            ? `<ol class="replaysteps">${displayPath.map((step) => {
                const text = step.display || step.label || step.action || "";
                const machine = step.action && text !== step.action ? ` <span class="muted">${esc(step.action)}</span>` : "";
                return `<li><span class="verb">${esc(text)}</span>${machine}</li>`;
              }).join("")}</ol>`
            : replay.length
              ? `<ol class="replaysteps">${replay.map((a) => {
                  const [verb, ...rest] = String(a).split(":");
                  return `<li><span class="verb">${esc(verb)}</span> <span class="tgt">${esc(rest.join(":"))}</span></li>`;
                }).join("")}</ol>`
            : `<div class="muted">No executable replay actions recorded.</div>`}
        </div>
      </div>
      <div class="card">
        <div class="hd">Stack / message</div>
        <div class="bd">
          <pre class="stack-msg">${esc(d.message || d.crashSummary || "No stack message recorded.")}</pre>
        </div>
      </div>
    </div>`;
  }

  // ---- spike-drops timeline card (graph + the verdict in words) -------------
  // `res` is the detail's resolution (immediately available); the timeline load
  // brings the per-window series for the graph. The verdict words come from
  // whichever resolution we have (they're the same Outcome shape).
  function renderTimelineCard(res) {
    let body;
    if (T.timelineStatus === "loading" || (T.timelineStatus !== "ready" && T.timelineFor !== T.selBucket)) {
      body = `<div class="sk sk-line" style="width:90%;height:90px;margin:6px 0"></div>`;
    } else if (T.timelineStatus === "error") {
      body = `<div class="muted">Could not load the occurrence timeline for this bucket.</div>`;
    } else {
      body = timelineSVG(T.timeline || {});
    }
    // The verdict prefers the timeline's resolution (freshest), falling back to
    // the detail's. They're computed by the same engine, so either is correct.
    const verdictRes = (T.timeline && T.timelineFor === T.selBucket && T.timeline.resolution) || res;
    const v = resolutionVerdict(verdictRes);
    return `<div class="card tl-card">
      <div class="hd">Occurrences over time</div>
      <div class="bd">
        <div class="tl-wrap">${body}</div>
        ${v ? `<div class="verdict ${v.cls}" role="status">
          <span class="v-dot" aria-hidden="true"></span><span>${v.text}</span>
        </div>` : ""}
      </div>
    </div>`;
  }

  // ---- detail / grab a bug --------------------------------------------------
  function renderDetailHTML() {
    if (T.detailStatus === "loading" && !T.detail) {
      return `<section class="detail" aria-busy="true">
        <div class="sk sk-line" style="width:130px"></div>
        <div class="sk sk-line" style="width:58%;height:24px;margin:14px 0"></div>
        <div class="sk sk-line" style="width:34%"></div>
        <div class="grid"><div class="sk sk-card"></div><div class="sk sk-card"></div></div>
      </section>`;
    }
    if (T.detailStatus === "error") {
      return `<section class="detail"><div class="empty"><div>
        <div class="ico" aria-hidden="true">!</div>
        <div class="big">Could not open bug</div>
        <div class="err-detail">${esc(T.detailErr || "")}</div>
      </div></div></section>`;
    }
    const d = T.detail;
    if (!d) {
      return `<section class="detail"><div class="empty"><div>
        <div class="ico" aria-hidden="true">&larr;</div>
        <div class="big">Grab a bug</div>
        <div class="sub">Pick a production bug from the list to see its repro command, suspect/replay, and triage controls.</div>
      </div></div></section>`;
    }

    const rp = reproSummary(d.repro);
    const tr = d.triage || { status: "untriaged" };
    const appId = d.appId || cfg().app;
    const cmd = d.reproduceCommand || `reproit cloud reproduce --app ${appId} --bucket ${d.bucketId} --as ${d.bucketId} --run`;
    // The prod-truth resolution (detail carries it directly; the timeline carries
    // it too with the same shape, so the graph + verdict agree).
    const item = selectedBucketItem() || {};
    const res = d.resolution || (T.timeline && T.timeline.resolution) || null;
    const resStatus = (res && res.status) || "active";
    const sev = (item.impact && item.impact.severity) || "crash";

    const autoFixed = tr.status === "fixed" && d.repro && d.repro.status === "clean" && d.repro.attempts;

    return `<section class="detail">
      <div class="crumb"><b>${esc(d.bucketId)}</b></div>
      <h1 class="h1">${esc(A.titleFromMessage(d.message || d.crashSummary || d.bucketId))}</h1>

      <div class="row">
        ${severityChip(sev)}
        ${resolutionChip(resStatus)}
        ${statusPill(tr.status)}
        ${rp ? `<span class="repro ${rp.cls}" title="${esc(rp.detail)}">${esc(rp.label)}</span>` : ""}
        ${autoFixed ? `<span class="badge b-rep">&#10003; fix verified by replay</span>` : ""}
      </div>

      ${renderMetricStrip(d)}
      ${renderCohortSignals(d)}
      ${renderPathAndStack(d, res)}

      <div class="card" style="margin-top:22px">
        <div class="hd">Reproduce locally</div>
        <div class="bd">
          <div class="cmdrow">
            <code class="cmdbox" id="t-cmd">${esc(cmd)}</code>
            <button class="term-copy" id="t-copy" data-cmd="${esc(cmd)}" type="button">copy</button>
          </div>
        </div>
      </div>

      <div class="grid">
        <div>
          <div class="card">
            <div class="hd">Workflow</div>
            <div class="bd">
              <div class="workflow-row">
                <div class="selwrap"><select id="t-set-status" ${T.savingTriage ? "disabled" : ""}>
                  ${STATUSES.map((s) => `<option value="${esc(s)}"${(tr.status || "untriaged") === s ? " selected" : ""}>${esc(s)}</option>`).join("")}
                </select></div>
                <button class="term-replay" id="t-save-triage" type="button" ${T.savingTriage ? "disabled" : ""}>${T.savingTriage ? "Saving…" : "Update status"}</button>
              </div>
            </div>
          </div>
        </div>

        <div>
          <div class="card">
            <div class="hd">Linked ticket</div>
            <div class="bd">${renderTicket(d.ticket)}</div>
          </div>
        </div>
      </div>
    </section>`;
  }

  function renderTicket(ticket) {
    if (!ticket || ticket === null) {
      return `<div class="muted">No linked issue.</div>`;
    }
    const externalId = ticket.externalId != null ? String(ticket.externalId) : "";
    const url = ticket.url ? A.abs(ticket.url) : null;
    const label = `${esc(ticket.provider || "issue")} ${esc(ticket.repo || "")} ${esc(externalId)}`.trim();
    return `<div class="ticketrow">
      <span class="dot" style="background:var(--green)" aria-hidden="true"></span>
      ${url ? `<a href="${esc(url)}" target="_blank" rel="noopener" class="ticketlink">${label}</a>` : esc(label)}
    </div>`;
  }

  // ===========================================================================
  // TEAM view
  // ===========================================================================
  function renderSeats() {
    if (T.seatsStatus === "unauth") {
      root().innerHTML = `<div class="single"><div class="empty"><div>
        <div class="ico" aria-hidden="true">!</div>
        <div class="big">Sign in required</div>
        <div class="sub">Seat management is owner/admin only. <a href="/login" style="color:var(--green)">Sign in</a>.</div>
      </div></div></div>`;
      return;
    }
    if (T.seatsStatus === "error") {
      root().innerHTML = `<div class="single"><div class="empty"><div>
        <div class="ico" aria-hidden="true">!</div>
        <div class="big">Could not load account</div>
        <div class="err-detail">${esc(T.seatsErr || "")}</div>
        <button class="ghostbtn" id="t-seats-retry" type="button">Retry</button>
      </div></div></div>`;
      return;
    }
    if (T.seatsStatus !== "ready" || !T.me) {
      root().innerHTML = `<div class="single" aria-busy="true"><div class="seatcard">
        <div class="sk sk-line" style="width:40%"></div>
        <div class="sk sk-line" style="width:70%;margin:16px 0"></div>
        <div class="sk sk-card" style="height:160px"></div>
      </div></div>`;
      return;
    }
    const me = T.me;
    const org = me.org || {};
    const members = me.members || [];
    const canManage = org.role === "owner" || org.role === "admin";
    if (!canManage) {
      root().innerHTML = `<div class="single"><div class="empty"><div>
        <div class="ico" aria-hidden="true">[ ]</div>
        <div class="big">Team is owner/admin only</div>
        <div class="sub">Ask an owner or admin to manage team access for this org.</div>
      </div></div></div>`;
      return;
    }
    // /me returns the EFFECTIVE seat per member (the org_members.seat flag OR an
    // always-seated owner), so seat status and usage are exact, not approximated.
    const rows = members.map((m) => {
      return `<tr>
        <td class="m-email">${esc(m.email)}</td>
        <td><div class="role-cell"><span class="rolechip rc-${esc(m.role)}">${esc(m.role)}</span></div></td>
      </tr>`;
    }).join("");

    root().innerHTML = `<div class="single"><div class="seatcard">
      <div class="seat-hd">
        <div>
          <h1 class="h1" style="font-size:20px;margin:0">Team access</h1>
        </div>
      </div>
      <table class="seattable">
        <colgroup><col style="width:58%"><col style="width:42%"></colgroup>
        <thead><tr><th>User</th><th>Role</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div></div>`;
  }

  // ===========================================================================
  // EVENTS (delegated; only act when a triage/seats view is mounted)
  // ===========================================================================
  document.addEventListener("click", (ev) => {
    const t = ev.target;

    // activity-strip event -> jump to that bucket (and grab it)
    const actev = t.closest(".actev[data-bucket]");
    if (actev) { loadDetail(actev.dataset.bucket, false); highlightSelected(); return; }

    // bug list row -> grab a bug
    const item = t.closest(".item[data-bucket]");
    if (item) { loadDetail(item.dataset.bucket, false); highlightSelected(); return; }

    // the regressed count badge -> filter the list to just regressions
    if (t.closest("#t-filter-regressed")) { T.statusFilter = "regressed"; renderListColumn(); return; }

    if (t.id === "t-refresh") { loadBuckets({ quiet: true }); return; }
    if (t.id === "t-refresh2") { loadBuckets({ quiet: true }); return; }
    if (t.id === "t-seats-retry") { loadMe(); return; }

    const goto = t.closest("[data-goto]");
    if (goto) { ev.preventDefault(); switchView(goto.dataset.goto); return; }

    // copy reproduce command
    if (t.id === "t-copy") {
      const cmd = t.dataset.cmd || "";
      navigator.clipboard?.writeText(cmd).then(() => {
        const old = t.textContent; t.textContent = "copied"; setTimeout(() => { t.textContent = old; }, 1100);
      }).catch(() => { t.textContent = "copy failed"; });
      return;
    }
    // triage save
    if (t.id === "t-save-triage") {
      const status = document.getElementById("t-set-status")?.value;
      if (!status) return;
      postTriage(T.selBucket, status);
      return;
    }

  });

  document.addEventListener("change", (ev) => {
    if (ev.target.id === "t-status") { T.statusFilter = ev.target.value; renderListColumn(); }
    if (ev.target.id === "t-set-status") return;
  });

  document.addEventListener("keydown", (ev) => {
    // Enter on a focused bug row grabs it.
    if (ev.key === "Enter") {
      const item = document.activeElement && document.activeElement.closest && document.activeElement.closest(".item[data-bucket]");
      if (item) { ev.preventDefault(); loadDetail(item.dataset.bucket, false); highlightSelected(); }
    }
  });

  // Switch the active nav view (drives app.js's S.view via the nav link click).
  function switchView(view) {
    const link = document.querySelector(`nav a[data-view="${view}"]`);
    if (link) link.click();
  }

  function resetForApp() {
    T.buckets = null;
    T.triageByBucket = {};
    T.selBucket = null;
    T.detail = null;
    T.detailStatus = "idle";
    T.timeline = null;
    T.timelineFor = null;
    T.timelineStatus = "idle";
    T.events = null;
    T.eventsStatus = "idle";
    T.listStatus = "idle";
    T.listErr = null;
    T.statusFilter = "all";
    stopFirstBugPoll();
  }

  // expose to app.js
  window.ReproitTriage = { render, resetForApp };
})();
