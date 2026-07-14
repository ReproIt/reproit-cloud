/*!
 * reproit-web, production telemetry SDK (v0)
 *
 * Drop this into a production web app and it emits the SAME marker protocol the
 * Repro It runner uses, but driven by REAL users instead of the fuzzer. Each
 * screen a user lands on is hashed to a state signature; each navigation is an
 * edge. The result is a live usage graph that aligns 1:1 with your test app
 * map, because the signature function here is byte-identical to the runner's.
 *
 * Why it matters:
 *   • shows which states/paths real users actually hit -> tells you what to test
 *   • a production error ships with the exact graph PATH that led to it, so it
 *     becomes a deterministic repro test instead of a "cannot reproduce" ticket
 *   • new/changed screens (a deploy) show up as graph drift -> what to re-test
 *
 * Privacy by design: signatures are STRUCTURAL (a hash of which controls exist),
 * not user data. With redactLabels:true, only the hashes leave the browser.
 * On an error we also attach PII-safe input FINGERPRINTS under context.fingerprint:
 * derived FEATURES of on-screen text fields ({field,len,charset,hasEmoji,isEmpty,
 * isRtl}), never the raw values, so the cloud can build a property-matched replay
 * fixture without storing PII. Password/hidden fields are never read.
 *
 * Usage (script tag):
 *   <script src="reproit-web.js"></script>
 *   <script>ReproIt.init({ appId: "myapp", endpoint: "https://ingest.reproit.com/v1/events", key: "pk_live_..." })</script>
 *
 * Or as a module:  import "./reproit-web.js"; ReproIt.init({...})
 *
 * Electron / Tauri:
 *   This IS the production SDK for Electron and Tauri apps too. Both render
 *   their UI in a webview (Electron = Chromium, Tauri = the system WebView),
 *   so the same DOM walk applies and the signature is byte-identical to what
 *   the reproit electron/tauri runners compute (parity-gated in
 *   runners/signature_test.mjs). Load it in the renderer/frontend exactly as
 *   above; no Electron/Tauri-specific build is needed.
 *     - Electron: include it in your renderer HTML, or import it from the
 *       renderer entry. Do NOT load it in the main process (no DOM there).
 *     - Tauri: import it from your frontend bundle like any web dependency.
 *   See sdk/reproit-web.README.md for the full embedding guide.
 */
(function (global) {
  "use strict";

  var DEFAULTS = {
    appId: "app",
    endpoint: null, // POST target; if null, events go to opts.onEvent / console
    key: null, // write-only publishable key (pk_live_...); sent as Bearer
    reportAutomation: false, // report webdriver-driven sessions (test rigs opt in)
    onEvent: null, // callback(event), dev hook / custom transport
    sampleRate: 1.0, // fraction of sessions that report (0..1)
    maxLabels: 24, // labels per state signature (matches the runner)
    maxLabelLen: 40,
    pathCap: 60, // how much of the graph trail to keep for repros
    flushMs: 5000, // batch flush interval
    redactLabels: false, // true => send only signatures, never control text
    debounceMs: 350, // settle window after an interaction before snapshotting
    valueNodes: [], // Layer-3 opt-in selectors marking EXTRA value-bearing nodes
    build: null, // developer-provided { version, commit }; stamped as context.build
  };

  // Keep only the provided string fields of a developer-supplied build identity
  // ({version, commit}). Returns null when neither is a non-empty string, so no
  // build object is stamped into the batch context.
  function normalizeBuild(build) {
    if (!build || typeof build !== "object") return null;
    var out = {};
    if (typeof build.version === "string" && build.version.length) out.version = build.version;
    if (typeof build.commit === "string" && build.commit.length) out.commit = build.commit;
    return out.version || out.commit ? out : null;
  }

  // Layer-3 opt-in (docs/signature.md "Value-state"): a list of selectors that
  // mark EXTRA DOM nodes as value-bearing even when their role is not a value-
  // role. Selectors use the same grammar as `value_nodes:` in reproit.yaml:
  //   key:<id>          -> data-testid / id / name == <id>
  //   role:<role>#<idx> -> the idx-th node of that canonical role (document order)
  //   <css>             -> any other string is treated as a raw CSS selector
  // The matcher is module-level so domToNode (called from snapshot) can consult
  // it without threading config through every recursion. setValueNodeSelectors
  // installs the active list; matchesValueNode tests a single element against it.
  var VALUE_NODE_SELECTORS = [];
  function setValueNodeSelectors(list) {
    VALUE_NODE_SELECTORS = Array.isArray(list) ? list.slice() : [];
  }
  function matchesValueNode(el) {
    if (!VALUE_NODE_SELECTORS.length) return false;
    for (var i = 0; i < VALUE_NODE_SELECTORS.length; i++) {
      if (elMatchesSelector(el, VALUE_NODE_SELECTORS[i])) return true;
    }
    return false;
  }
  // Test one element against one value-node selector (key:/role:/raw CSS).
  function elMatchesSelector(el, sel) {
    if (!sel || typeof sel !== "string") return false;
    if (sel.indexOf("key:") === 0) {
      var id = sel.slice(4);
      if (!id) return false;
      var got = (el.getAttribute("data-testid") || el.getAttribute("data-test-id") ||
        el.getAttribute("id") || el.getAttribute("name") || "");
      return got.trim() === id;
    }
    if (sel.indexOf("role:") === 0) {
      var hash = sel.indexOf("#");
      if (hash < 0) return false;
      var role = sel.slice(5, hash);
      var idx = parseInt(sel.slice(hash + 1), 10);
      if (!(idx >= 0)) return false;
      // Resolve the idx-th element of this canonical role in document order.
      var root = document.body || document.documentElement;
      if (!root) return false;
      var seen = -1, target = null;
      (function walk(node) {
        if (target) return;
        if (roleOf(node) === role) { seen++; if (seen === idx) { target = node; return; } }
        var kids = node.children || [];
        for (var k = 0; k < kids.length; k++) walk(kids[k]);
      })(root);
      return target === el;
    }
    // raw CSS selector
    try { return el.matches && el.matches(sel); } catch (e) { return false; }
  }

  // ====================================================================
  //  CANONICAL STRUCTURAL SIGNATURE
  //  Byte-identical to the Rust oracle (crates/reproit/src/model/signature.rs)
  //  and to runners/web/runner.mjs. Spec: docs/signature.md. Proven against
  //  signature_vectors.json by sdk/test/signature_test.js.
  //
  //  A signature hashes STRUCTURE (roles + ids + types + icons + tree shape),
  //  never localized text, so an EN and a DE render of the same screen hash
  //  identically. The descriptor is:
  //      "A:" + anchor + "\n" + tokens.join(";")
  //  where each retained node emits one pre-order token:
  //      <depth>:<role>[:<type>][#<icon>][@<id>]   (plus "*" if collapsed)
  //  hashed with FNV-1a 32-bit -> 8 hex chars.
  // ====================================================================

  // Fixed, language-independent role vocabulary. Anything else -> "node".
  var ROLES = {
    screen: 1, header: 1, text: 1, button: 1, link: 1, textfield: 1, image: 1,
    icon: 1, list: 1, listitem: 1, tab: 1, switch: 1, checkbox: 1, radio: 1,
    slider: 1, menu: 1, menuitem: 1, dialog: 1, group: 1, node: 1,
  };
  // Roles that flicker in/out and are dropped before hashing (rule 2).
  // "progress" is the role name for spinner/progress.
  var TRANSIENT_ROLES = { toast: 1, snackbar: 1, spinner: 1, progress: 1, tooltip: 1, badge: 1 };

  // Value-role set (docs/signature.md "Value-state", Layer 2). A node is
  // value-bearing iff it has a `value` AND either its RAW role is one of these OR
  // it carries the opt-in `value_node` flag (Layer 3). Several of these roles
  // (status, log, progressbar, meter, timer, output) are NOT in the structural
  // ROLES vocabulary, so they normalize to "node" in the token body; the
  // value-role test deliberately uses the RAW role, not the normalized one.
  // Chrome roles (button/label/header/text/link) are NEVER value-bearing, so the
  // chrome-text exclusion (rule 1) is preserved exactly.
  var VALUE_ROLES = { textfield: 1, status: 1, log: 1, progressbar: 1, meter: 1, timer: 1, output: 1 };

  function normalizeRole(role) {
    return ROLES[role] ? role : "node";
  }
  function isTransientNode(node) {
    return !!node.transient || !!TRANSIENT_ROLES[node.role];
  }
  // True if this node carries a canonical value-class in the V: section: it has a
  // `value` AND it is value-bearing (raw role is a value-role, or value_node-
  // flagged). Mirrors the oracle's is_value_bearing exactly.
  function isValueBearing(node) {
    return node.value != null && (!!VALUE_ROLES[node.role] || !!node.value_node);
  }

  // The shared UTF-8 encoder for the canonical hash + V: byte-order sort. The
  // descriptor and V: keys can carry non-ASCII (a localized route in the anchor,
  // a non-ASCII developer id, an emoji icon), so we MUST fold the UTF-8 BYTES of
  // the string, exactly like the Rust oracle's `desc.as_bytes()`. Hashing the
  // UTF-16 code units instead silently diverged on any non-ASCII descriptor.
  var REPROIT_UTF8 = new TextEncoder();

  // FNV-1a 32-bit over the UTF-8 BYTES of the descriptor -> 8 hex. Byte-for-byte
  // identical to the Rust oracle's fnv1a32_hex (offset basis 0x811c9dc5, prime
  // 0x01000193) over `descriptor.as_bytes()`.
  function fnv1a32hex(s) {
    var bytes = REPROIT_UTF8.encode(s);
    var h = 0x811c9dc5;
    for (var i = 0; i < bytes.length; i++) {
      h ^= bytes[i];
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return ("0000000" + (h >>> 0).toString(16)).slice(-8);
  }

  // Lexicographic comparison of two strings by their UTF-8 byte sequence, to
  // match Rust's `String::cmp` (which compares bytes). JS `<` compares UTF-16
  // code units, which diverges from byte order for astral vs high-BMP keys, so
  // the V: section MUST sort with this instead.
  function reproitCmpUtf8(a, b) {
    var ab = REPROIT_UTF8.encode(a);
    var bb = REPROIT_UTF8.encode(b);
    var n = ab.length < bb.length ? ab.length : bb.length;
    for (var i = 0; i < n; i++) {
      if (ab[i] !== bb[i]) return ab[i] < bb[i] ? -1 : 1;
    }
    return ab.length === bb.length ? 0 : ab.length < bb.length ? -1 : 1;
  }

  // Rules 1, 2, 4: exclude text (no text field exists), drop transient
  // subtrees, keep document order. Returns null if the node itself is transient.
  function normalizeNode(node) {
    if (isTransientNode(node)) return null;
    var kids = [];
    var children = node.children || [];
    for (var i = 0; i < children.length; i++) {
      var n = normalizeNode(children[i]);
      if (n) kids.push(n);
    }
    return {
      role: normalizeRole(node.role),
      type: node.type != null ? node.type : null,
      icon: node.icon != null ? node.icon : null,
      id: node.id != null ? node.id : null,
      children: kids,
    };
  }

  // Token body after "<depth>:", without the repeat marker:
  //   <role>[:<type>][#<icon>][@<id>]
  function tokenBody(n) {
    var s = n.role;
    if (n.type != null) s += ":" + n.type;
    if (n.icon != null) s += "#" + n.icon;
    if (n.id != null) s += "@" + n.id;
    return s;
  }

  // Subtree key for collapse comparison (rule 3): pre-order token list with
  // depth re-based to 0 so sibling subtrees compare regardless of absolute depth.
  function subtreeKey(n) {
    var tokens = [];
    (function walk(node, depth) {
      tokens.push(depth + ":" + tokenBody(node));
      for (var i = 0; i < node.children.length; i++) walk(node.children[i], depth + 1);
    })(n, 0);
    return tokens.join(";");
  }

  function serializeNode(n, depth, repeated, tokens) {
    var tok = depth + ":" + tokenBody(n);
    if (repeated) tok += "*";
    tokens.push(tok);
    serializeChildren(n.children, depth + 1, tokens);
  }
  // Collapse maximal runs of >= 2 consecutive identical sibling subtrees into a
  // single "*"-marked emission (count dropped).
  function serializeChildren(children, depth, tokens) {
    var i = 0;
    while (i < children.length) {
      var key = subtreeKey(children[i]);
      var j = i + 1;
      while (j < children.length && subtreeKey(children[j]) === key) j++;
      serializeNode(children[i], depth, (j - i) >= 2, tokens);
      i = j;
    }
  }

  // ---- Layer 2: value-class identity (canonical) --------------------------
  // Strict ^[+-]?[0-9]+(\.[0-9]+)?$: optional sign, one or more ASCII digits,
  // optionally a period and one or more ASCII digits. No grouping separators, no
  // exponent, no leading/trailing dot. Locale-safe by construction. Mirrors the
  // oracle's is_strict_decimal byte-for-byte.
  function isStrictDecimal(s) {
    var i = 0;
    var n = s.length;
    if (i < n && (s.charCodeAt(i) === 43 || s.charCodeAt(i) === 45)) i++; // + or -
    var intStart = i;
    while (i < n && s.charCodeAt(i) >= 48 && s.charCodeAt(i) <= 57) i++;
    if (i === intStart) return false; // need at least one integer digit
    if (i < n && s.charCodeAt(i) === 46) { // '.'
      i++;
      var fracStart = i;
      while (i < n && s.charCodeAt(i) >= 48 && s.charCodeAt(i) <= 57) i++;
      if (i === fracStart) return false; // trailing dot with no fraction
    }
    return i === n;
  }

  // Map a value string to a bounded, deterministic, locale-safe value-class
  // token (docs/signature.md "Value-state"). Identical rule to the Rust oracle's
  // value_class: EMPTY / strict-decimal -> ZERO|NEG|POS1|POS2|POS3|POSL / else
  // NONEMPTY. Anything ambiguously formatted (grouped/locale numbers, currency,
  // exponent, non-ASCII digits) falls to NONEMPTY because we do not guess locale.
  function valueClass(s) {
    var t = (s == null ? "" : String(s)).replace(/^\s+|\s+$/g, "");
    if (t.length === 0) return "EMPTY";
    if (isStrictDecimal(t)) {
      var num = parseFloat(t);
      var a = Math.abs(num);
      if (num === 0) return "ZERO";
      if (num < 0) return "NEG";
      if (a < 10) return "POS1";
      if (a < 100) return "POS2";
      if (a < 1000) return "POS3";
      return "POSL";
    }
    return "NONEMPTY";
  }

  // The V:-section key for a value-bearing node: its stable `id` rendered as
  // key:<id> if present, else the structural fallback role:<role>#<idx> using the
  // NORMALIZED role and the per-parent structural index among same-role
  // non-transient siblings (matching the selector grammar). Mirrors value_key.
  function valueKeyOf(node, structuralIndex) {
    if (node.id != null) return "key:" + node.id;
    return "role:" + normalizeRole(node.role) + "#" + structuralIndex;
  }

  // Collect (value_key, value_class) pairs for every value-bearing node in the
  // tree, pre-order, skipping transient subtrees (rule 2) so the V: section is
  // consistent with the structural body. The root gets index 0 (no peers); each
  // keyless child gets its position among same-normalized-role non-transient
  // siblings under the same parent. Mirrors collect_values + collect_values_children.
  function collectValues(node, out) {
    if (isTransientNode(node)) return;
    if (isValueBearing(node)) out.push([valueKeyOf(node, 0), valueClass(node.value)]);
    collectValuesChildren(node, out);
  }
  function collectValuesChildren(node, out) {
    var roleCounts = {};
    var children = node.children || [];
    for (var i = 0; i < children.length; i++) {
      var child = children[i];
      if (isTransientNode(child)) continue;
      var role = normalizeRole(child.role);
      var idx = roleCounts[role] || 0;
      roleCounts[role] = idx + 1;
      if (isValueBearing(child)) out.push([valueKeyOf(child, idx), valueClass(child.value)]);
      collectValuesChildren(child, out);
    }
  }

  // Build the V: section suffix. Returns "" when there are NO value-bearing
  // nodes, which keeps the descriptor (and hash) byte-identical to a pre-value-
  // state tree. Otherwise returns "\nV:" + sorted key=class entries joined by ";".
  function valueSection(root) {
    var pairs = [];
    collectValues(root, pairs);
    if (pairs.length === 0) return "";
    pairs.sort(function (a, b) { return reproitCmpUtf8(a[0], b[0]); });
    var body = pairs.map(function (p) { return p[0] + "=" + p[1]; }).join(";");
    return "\nV:" + body;
  }

  // The exact UTF-8 descriptor string that gets hashed. The V: section (Layer 2)
  // is appended only when at least one value-bearing node exists; otherwise it is
  // "" and the descriptor is byte-identical to a pre-value-state tree.
  function descriptorOf(anchor, root) {
    var tokens = [];
    var norm = normalizeNode(root);
    if (norm) serializeNode(norm, 0, false, tokens);
    return "A:" + (anchor == null ? "" : anchor) + "\n" + tokens.join(";") + valueSection(root);
  }

  // Canonical structural signature: FNV-1a over the descriptor.
  function signatureOf(anchor, root) {
    return fnv1a32hex(descriptorOf(anchor, root));
  }

  // ---- DOM -> canonical Node tree -----------------------------------------
  // Map a live DOM element to a canonical role. Derived from tag + aria role +
  // input type, NEVER from visible text. Most-specific first.
  function roleOf(el) {
    var tag = el.tagName.toLowerCase();
    var ariaRole = (el.getAttribute("role") || "").toLowerCase();
    // explicit aria role wins when it is in (or maps into) the vocabulary
    if (ariaRole) {
      if (ariaRole === "textbox" || ariaRole === "searchbox" || ariaRole === "combobox") return "textfield";
      if (ariaRole === "heading") return "header";
      if (ariaRole === "img") return "image";
      if (ariaRole === "switch") return "switch";
      if (ariaRole === "link") return "link";
      if (ariaRole === "button") return "button";
      if (ROLES[ariaRole]) return ariaRole;
    }
    if (tag === "input") {
      var t = (el.getAttribute("type") || "text").toLowerCase();
      if (t === "checkbox") return "checkbox";
      if (t === "radio") return "radio";
      if (t === "range") return "slider";
      if (["button", "submit", "reset", "image"].indexOf(t) >= 0) return "button";
      return "textfield";
    }
    if (tag === "textarea" || tag === "select") return "textfield";
    if (tag === "a") return "link";
    if (tag === "button") return "button";
    if (tag === "img" || tag === "svg") return "image";
    if (/^h[1-6]$/.test(tag) || tag === "header") return "header";
    if (tag === "ul" || tag === "ol") return "list";
    if (tag === "li") return "listitem";
    if (tag === "dialog") return "dialog";
    if (tag === "nav" || tag === "menu") return "menu";
    if (ariaRole) return "node"; // an aria role outside vocabulary
    return "node";
  }

  // Optional input type refinement, only for textfield-ish controls.
  function typeOf(el, role) {
    if (role !== "textfield") return null;
    var tag = el.tagName.toLowerCase();
    if (tag !== "input") return null;
    var t = (el.getAttribute("type") || "text").toLowerCase();
    var allowed = { text: 1, password: 1, email: 1, number: 1, search: 1 };
    return allowed[t] ? t : "text";
  }

  // Language-independent icon identity: an icon-font codepoint or an svg <use>
  // href / data-icon asset name. Never localized text.
  function iconOf(el) {
    var di = el.getAttribute && (el.getAttribute("data-icon") || el.getAttribute("data-icon-name"));
    if (di && di.trim()) return di.trim();
    // svg <use xlink:href="#icon-x"> / <use href="#icon-x">
    var use = el.querySelector ? el.querySelector("use[href], use[xlink\\:href]") : null;
    if (use) {
      var href = use.getAttribute("href") || use.getAttributeNS("http://www.w3.org/1999/xlink", "href") || use.getAttribute("xlink:href");
      if (href && href.trim()) return href.trim().replace(/^#/, "");
    }
    // icon-font convention: <i class="material-icons">codepoint/name</i> with a
    // data attribute, or a ligature. We only read a stable data-attr, not text.
    return null;
  }

  // Stable developer identifier: data-testid > id > name. Omitted if none.
  function idOf(el) {
    var testid = el.getAttribute("data-testid") || el.getAttribute("data-test-id");
    if (testid && testid.trim()) return testid.trim();
    var id = el.getAttribute("id");
    if (id && id.trim()) return id.trim();
    var name = el.getAttribute("name");
    if (name && name.trim()) return name.trim();
    return null;
  }

  // Runner-native replay selector for an element. This is deliberately more
  // specific than `idOf`: web replay resolves key:testid:/key:id:/key:name:
  // selectors differently, so preserve the source kind.
  function actionKeyOf(el) {
    var testid = el.getAttribute("data-testid") || el.getAttribute("data-test-id");
    if (testid && testid.trim()) return "key:testid:" + testid.trim();
    var id = el.getAttribute("id");
    if (id && id.trim()) return "key:id:" + id.trim();
    var name = el.getAttribute("name");
    if (name && name.trim()) return "key:name:" + name.trim();
    return null;
  }

  // Heuristic: is this element a transient node (toast/snackbar/spinner/
  // progress/tooltip/badge) by role, aria-live, or class name? Dropped from hash.
  function isTransientEl(el) {
    var ariaRole = (el.getAttribute("role") || "").toLowerCase();
    if (TRANSIENT_ROLES[ariaRole]) return true;
    if (ariaRole === "alert" || ariaRole === "status") return true;
    var live = (el.getAttribute("aria-live") || "").toLowerCase();
    if (live === "assertive" || live === "polite") return true;
    var cls = (el.getAttribute("class") || "").toLowerCase();
    if (/\b(toast|snackbar|spinner|progress|loader|loading|tooltip|badge)\b/.test(cls)) return true;
    if (el.hasAttribute && el.hasAttribute("data-transient")) return true;
    return false;
  }

  // The RAW value-role of a DOM element for the Layer-2 value-class, derived from
  // tag + aria role, NEVER from text. This is intentionally distinct from roleOf:
  // it returns one of the value-role names (status/log/progressbar/meter/timer/
  // output) for the matching ARIA roles, and "textfield" for form fields, so the
  // canonical is_value_bearing test sees the RAW role the oracle expects. An
  // aria-live region (polite/assertive) maps to "status" (a value-role) so a live
  // region becomes value-bearing WITHOUT any opt-in. Returns null for chrome.
  function valueRoleOf(el) {
    var tag = el.tagName.toLowerCase();
    var ariaRole = (el.getAttribute("role") || "").toLowerCase();
    if (ariaRole === "status" || ariaRole === "log" || ariaRole === "progressbar" ||
        ariaRole === "meter" || ariaRole === "timer") {
      return ariaRole;
    }
    if (tag === "output" || ariaRole === "output") return "output";
    // aria-live region (polite/assertive) -> a value-role status node.
    var live = (el.getAttribute("aria-live") || "").toLowerCase();
    if (live === "polite" || live === "assertive") return "status";
    // form fields hold a .value: they are textfield value-roles.
    if (tag === "input") {
      var t = (el.getAttribute("type") || "text").toLowerCase();
      // Non-text inputs (checkbox/radio/range/buttons) are not text value fields.
      if (["checkbox", "radio", "range", "button", "submit", "reset", "image", "hidden", "file", "password"].indexOf(t) >= 0) return null;
      return "textfield";
    }
    if (tag === "textarea" || tag === "select") return "textfield";
    if (ariaRole === "textbox" || ariaRole === "searchbox" || ariaRole === "combobox") return "textfield";
    return null;
  }

  // The displayed data value of a value-role element: the field's `.value` for
  // form controls, else the trimmed textContent for output/status/live nodes.
  // Password fields are never read (valueRoleOf already excludes them).
  function valueOf(el) {
    var tag = el.tagName.toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") {
      return el.value != null ? String(el.value) : "";
    }
    return (el.textContent != null ? el.textContent : "").trim();
  }

  // Build the canonical Node tree from a DOM root. Invisible elements are
  // skipped but their children are hoisted (matches structure regardless of
  // wrapper visibility). Transient subtrees carry transient:true so the shared
  // normalizer drops them. The root node's role is forced to "screen".
  //
  // Value-state (Layer 2): a value-bearing element (a value-role by tag/aria, OR
  // an opt-in value_node) gets `value` + `value_node` set on its Node so the
  // canonical descriptor folds its value-class into the V: section. Value-bearing
  // WINS over the transient heuristic: a role=status / aria-live node that the
  // transient heuristic would otherwise drop is kept as a value node instead, so
  // a counter/stopwatch live region produces distinct value-states.
  function domToNode(root, isRoot) {
    var role = isRoot ? "screen" : roleOf(root);
    var vrole = isRoot ? null : valueRoleOf(root);
    var optIn = !isRoot && typeof matchesValueNode === "function" && matchesValueNode(root);
    var valueBearing = !isRoot && (!!vrole || optIn);
    var transient = !isRoot && !valueBearing && isTransientEl(root);
    var node = {
      role: role,
      id: idOf(root) || undefined,
      type: typeOf(root, role) || undefined,
      icon: iconOf(root) || undefined,
      transient: transient,
      children: [],
    };
    if (valueBearing) {
      node.value = valueOf(root);
      // An opt-in node whose role is NOT a value-role needs the flag so the
      // canonical is_value_bearing accepts it; a value-role node is accepted by
      // role alone but the flag is harmless and keeps the two paths uniform.
      node.value_node = true;
    }
    if (transient) return node; // subtree dropped anyway; do not recurse
    var kids = root.children || [];
    for (var i = 0; i < kids.length; i++) {
      var el = kids[i];
      if (!visible(el)) {
        // hoist visible descendants of an invisible wrapper
        collectVisibleInto(el, node.children);
        continue;
      }
      node.children.push(domToNode(el, false));
    }
    return node;
  }
  function collectVisibleInto(el, out) {
    var kids = el.children || [];
    for (var i = 0; i < kids.length; i++) {
      var c = kids[i];
      if (!visible(c)) { collectVisibleInto(c, out); continue; }
      out.push(domToNode(c, false));
    }
  }

  // The screen anchor: path + SPA hash route, query EXCLUDED -- byte-identical to
  // the runner (runners/web/runner.mjs). Hash routers put the real route in
  // location.hash (#/a vs #/b on one pathname), so it MUST be in the anchor or the
  // SDK collapses distinct screens that the runner keeps separate, breaking the
  // "byte-identical to the runner's signature" contract on every hash-router SPA.
  function anchorOf() {
    try {
      if (typeof location !== "undefined" && location.pathname) {
        var hash = location.hash || "";
        var q = hash.indexOf("?");
        if (q >= 0) hash = hash.slice(0, q);
        return location.pathname + hash;
      }
    } catch (e) {}
    return null;
  }

  function interactive(el) {
    var tag = el.tagName.toLowerCase();
    var role = el.getAttribute("role") || "";
    if (["a", "button", "input", "select", "textarea"].indexOf(tag) >= 0) return true;
    if (["button", "link", "menuitem", "tab", "checkbox", "switch"].indexOf(role) >= 0) return true;
    return el.hasAttribute("onclick") || el.tabIndex >= 0;
  }

  function actionSelectorOf(el) {
    var key = actionKeyOf(el);
    if (key) return key;
    var role = roleOf(el);
    var root = document.body || document.documentElement;
    if (!root) return null;
    var idx = -1;
    var found = false;
    (function walk(node) {
      if (found) return;
      if (node !== root && visible(node) && interactive(node) && roleOf(node) === role) {
        idx++;
        if (node === el) {
          found = true;
          return;
        }
      }
      var kids = node.children || [];
      for (var k = 0; k < kids.length; k++) walk(kids[k]);
    })(root);
    return found ? "role:" + role + "#" + idx : null;
  }

  function nameOf(el) {
    var a = el.getAttribute && (el.getAttribute("aria-label") || el.getAttribute("title") || el.getAttribute("alt"));
    if (a && a.trim()) return a.trim();
    var t = (el.innerText || el.textContent || "").trim().split("\n")[0].trim();
    return t;
  }

  function visible(el) {
    var r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return false;
    var st = getComputedStyle(el);
    return st.visibility !== "hidden" && st.display !== "none";
  }

  // ---- PII-safe input fingerprinting (tier-3 context) ---------------------
  // On an error we capture DERIVED FEATURES of on-screen text-field values, never
  // the values themselves, so the cloud can property-match a replay fixture (a
  // 312-char name, an emoji, a Turkish "i", an empty/RTL field) WITHOUT storing
  // PII. fingerprintValue is the load-bearing pure function: identical shape and
  // rules across all five SDKs and host-unit-tested in each.

  // RTL detection: any char in the Hebrew/Arabic/Syriac/Thaana/N'Ko + Arabic
  // presentation-form ranges marks the string as right-to-left.
  function reproitIsRtl(str) {
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (
        (c >= 0x0590 && c <= 0x05ff) || // Hebrew
        (c >= 0x0600 && c <= 0x06ff) || // Arabic
        (c >= 0x0700 && c <= 0x074f) || // Syriac
        (c >= 0x0780 && c <= 0x07bf) || // Thaana
        (c >= 0x07c0 && c <= 0x07ff) || // N'Ko
        (c >= 0x08a0 && c <= 0x08ff) || // Arabic Extended-A
        (c >= 0xfb1d && c <= 0xfb4f) || // Hebrew presentation forms
        (c >= 0xfb50 && c <= 0xfdff) || // Arabic presentation forms-A
        (c >= 0xfe70 && c <= 0xfeff)    // Arabic presentation forms-B
      ) {
        return true;
      }
    }
    return false;
  }

  // Emoji detection: scan code points for the common emoji/pictographic blocks
  // and regional indicators (flags). Code-point aware so surrogate pairs count.
  function reproitHasEmoji(str) {
    for (var i = 0; i < str.length; i++) {
      var c = str.codePointAt(i);
      if (c > 0xffff) i++; // skip the low surrogate of an astral code point
      if (
        (c >= 0x1f000 && c <= 0x1faff) || // pictographs, emoji, symbols, etc.
        (c >= 0x1f1e6 && c <= 0x1f1ff) || // regional indicators (flags)
        (c >= 0x2600 && c <= 0x27bf) ||   // misc symbols + dingbats
        c === 0x2764 ||                    // heavy black heart
        c === 0xfe0f ||                    // variation selector-16 (emoji style)
        c === 0x200d ||                    // zero-width joiner (emoji sequences)
        (c >= 0x2190 && c <= 0x21ff && false) // (arrows: not emoji) placeholder
      ) {
        return true;
      }
    }
    return false;
  }

  // Fingerprint schema version for the byte/script/combining/zero-width/
  // newline/edge-whitespace features below.
  var FP_VERSION = 2;

  // UTF-8 byte length, computed per code point so it's identical across SDKs
  // regardless of the host's native string encoding. Catches the byte-limit
  // (DB varchar) overflow class that code-point `len` alone misses.
  function reproitByteLen(str) {
    var bytes = 0;
    for (var i = 0; i < str.length; i++) {
      var c = str.codePointAt(i);
      if (c > 0xffff) i++; // astral: skip the low surrogate
      if (c < 0x80) bytes += 1;
      else if (c < 0x800) bytes += 2;
      else if (c < 0x10000) bytes += 3;
      else bytes += 4;
    }
    return bytes;
  }

  // Zero-width / invisible code points (injection + normalization breakers).
  function reproitHasZeroWidth(str) {
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c === 0x200b || c === 0x200c || c === 0x200d || c === 0x2060 || c === 0xfeff) {
        return true;
      }
    }
    return false;
  }

  // Combining marks (a base char + combining accent renders differently than a
  // precomposed one; a classic normalization/layout breaker).
  function reproitHasCombining(str) {
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (
        (c >= 0x0300 && c <= 0x036f) ||
        (c >= 0x1ab0 && c <= 0x1aff) ||
        (c >= 0x1dc0 && c <= 0x1dff) ||
        (c >= 0x20d0 && c <= 0x20ff) ||
        (c >= 0xfe20 && c <= 0xfe2f)
      ) {
        return true;
      }
    }
    return false;
  }

  function reproitIsCombiningCp(c) {
    return (c >= 0x0300 && c <= 0x036f) ||
      (c >= 0x1ab0 && c <= 0x1aff) ||
      (c >= 0x1dc0 && c <= 0x1dff) ||
      (c >= 0x20d0 && c <= 0x20ff) ||
      (c >= 0xfe20 && c <= 0xfe2f);
  }

  function reproitGraphemeCount(str) {
    var n = 0;
    var joined = false;
    for (var _i = 0, chars = Array.from(str); _i < chars.length; _i++) {
      var c = chars[_i].codePointAt(0);
      if (c === 0x200d) {
        joined = true;
        continue;
      }
      if (reproitIsCombiningCp(c) || (c >= 0xfe00 && c <= 0xfe0f)) continue;
      if (joined) {
        joined = false;
        continue;
      }
      n += 1;
    }
    return n;
  }

  // The Unicode SCRIPTS present, as a sorted unique list of coarse bucket names.
  // Mixed-script (e.g. ["Arabic","Latin"]) is what bidi bugs need, which `isRtl`
  // alone can't express. Ranges are fixed and shared verbatim across all SDKs.
  function reproitScripts(str) {
    var found = {};
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) ||
          (c >= 0xc0 && c <= 0x24f) || (c >= 0x1e00 && c <= 0x1eff)) found["Latin"] = 1;
      else if (c >= 0x370 && c <= 0x3ff) found["Greek"] = 1;
      else if (c >= 0x400 && c <= 0x4ff) found["Cyrillic"] = 1;
      else if (c >= 0x590 && c <= 0x5ff) found["Hebrew"] = 1;
      else if ((c >= 0x600 && c <= 0x6ff) || (c >= 0x750 && c <= 0x77f) ||
               (c >= 0x8a0 && c <= 0x8ff)) found["Arabic"] = 1;
      else if (c >= 0x900 && c <= 0x97f) found["Devanagari"] = 1;
      else if (c >= 0xe00 && c <= 0xe7f) found["Thai"] = 1;
      else if ((c >= 0x3040 && c <= 0x30ff) || (c >= 0x3400 && c <= 0x9fff) ||
               (c >= 0xac00 && c <= 0xd7a3) || (c >= 0xf900 && c <= 0xfaff)) found["CJK"] = 1;
    }
    return Object.keys(found).sort();
  }

  // Pure fingerprint of a single value. Captures FEATURES, never the value.
  //   len          : Unicode code-point count (so "José🎉" -> 5)
  //   bytes        : UTF-8 byte length
  //   graphemes    : approximate user-visible cluster count
  //   charset      : "numeric" (all ASCII digits) | "ascii" | "unicode"
  //   scripts      : sorted Unicode script buckets present (mixed-script bidi)
  //   hasEmoji     : contains an emoji/pictographic code point
  //   isEmpty      : empty or whitespace-only
  //   isRtl        : contains a right-to-left script char
  //   hasCombiningMarks / hasZeroWidth / hasNewline / leadingTrailingWhitespace
  function fingerprintValue(str) {
    var s = str == null ? "" : String(str);
    // Code-point length (Array.from splits on code points, not UTF-16 units).
    var len = Array.from(s).length;
    var trimmed = s.replace(/^\s+|\s+$/g, "");
    var isEmpty = trimmed.length === 0;
    var hasUnicode = false;
    var allDigits = !isEmpty;
    var hasNewline = false;
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c > 0x7f) hasUnicode = true;
      if (c < 0x30 || c > 0x39) allDigits = false;
      if (c === 0x0a || c === 0x0d) hasNewline = true;
    }
    var charset = hasUnicode ? "unicode" : allDigits ? "numeric" : "ascii";
    // Edge whitespace: a fixed whitespace set (parity-safe, not locale trim).
    function isWs(cc) {
      return cc === 0x09 || cc === 0x0a || cc === 0x0b || cc === 0x0c ||
             cc === 0x0d || cc === 0x20 || cc === 0xa0;
    }
    var edgeWs = s.length > 0 && (isWs(s.charCodeAt(0)) || isWs(s.charCodeAt(s.length - 1)));
    return {
      len: len,
      bytes: reproitByteLen(s),
      graphemes: reproitGraphemeCount(s),
      charset: charset,
      scripts: reproitScripts(s),
      hasEmoji: reproitHasEmoji(s),
      isEmpty: isEmpty,
      isRtl: reproitIsRtl(s),
      hasCombiningMarks: reproitHasCombining(s),
      hasZeroWidth: reproitHasZeroWidth(s),
      hasNewline: hasNewline,
      leadingTrailingWhitespace: edgeWs,
    };
  }

  // A stable label for a field: prefer an explicit name/aria-label/id, else the
  // associated <label> text, else fall back to a positional index. Never derived
  // from the field's VALUE.
  function fieldLabel(el, index) {
    var lbl =
      (el.getAttribute && (el.getAttribute("aria-label") ||
        el.getAttribute("name") ||
        el.getAttribute("id") ||
        el.getAttribute("placeholder"))) ||
      "";
    lbl = lbl && lbl.trim();
    if (!lbl && el.labels && el.labels.length) {
      lbl = (el.labels[0].innerText || el.labels[0].textContent || "").trim();
    }
    return lbl || "#" + index;
  }

  // Walk visible text inputs/fields, fingerprinting each VALUE then discarding
  // it. Returns an array of {field, len, charset, hasEmoji, isEmpty, isRtl}.
  function collectFieldFingerprints() {
    var out = [];
    if (typeof document === "undefined") return out;
    var nodes = document.querySelectorAll(
      "input, textarea, [contenteditable='true'], [contenteditable='']"
    );
    var skipTypes = { password: 1, hidden: 1, file: 1, submit: 1, button: 1, image: 1, reset: 1 };
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      var tag = el.tagName.toLowerCase();
      if (tag === "input") {
        var type = (el.getAttribute("type") || "text").toLowerCase();
        // Never even READ password fields; skip non-text controls.
        if (skipTypes[type]) continue;
      }
      if (!visible(el)) continue;
      var value =
        tag === "input" || tag === "textarea"
          ? el.value
          : el.innerText || el.textContent || "";
      var fp = fingerprintValue(value);
      // Explicitly drop the raw value before it can leave this function.
      value = null;
      out.push({
        field: fieldLabel(el, i),
        len: fp.len,
        charset: fp.charset,
        hasEmoji: fp.hasEmoji,
        isEmpty: fp.isEmpty,
        isRtl: fp.isRtl,
      });
    }
    return out;
  }

  // Snapshot the live DOM into the CANONICAL structural signature. The sig is a
  // hash of the canonical Node tree (role + id + type + icon + shape), anchored
  // on the route, byte-identical to the runner and the Rust oracle. Localized
  // text never enters the hash; it is kept only as display-only `labels`.
  function snapshot(cfg) {
    var root = document.body || document.documentElement;
    var tree = root ? domToNode(root, true) : { role: "screen", children: [] };
    var anchor = anchorOf();
    var sig = signatureOf(anchor, tree);

    // display-only labels for `map --show` (never folded into the hash)
    var labels = [];
    var seen = {};
    var nodes = document.querySelectorAll("*");
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      if (!visible(el)) continue;
      var name = nameOf(el);
      if (name && name.length <= cfg.maxLabelLen && !seen[name]) {
        seen[name] = 1;
        labels.push(name);
      }
    }
    return { sig: sig, anchor: anchor, labels: labels.slice(0, cfg.maxLabels) };
  }

  // The production SDK is an ORACLE runner, not an error firehose: it reports
  // only findings we are confident about (zero/low false positive), so buckets in
  // the cloud stay high-signal. A genuine uncaught error IS the `crash` oracle and
  // is reported as such; but the environment/third-party noise every browser emits
  // through window.onerror is NOT the app crashing, carries no actionable info,
  // and is dropped AT THE SOURCE. Substring match on the lowercased message:
  var CRASH_NOISE = [
    "script error",                  // cross-origin, opaque: no stack, not ours
    "resizeobserver loop",           // benign layout notification, not a crash
    "failed to fetch",               // network flake, not a code defect
    "networkerror when attempting",  // network flake
    "load failed",                   // network flake (Safari fetch)
    "aborterror",                    // a request the app itself aborted
    "the operation was aborted",
    "the user aborted a request",
  ];
  // Script URLs that are never the app's own code: browser extensions and
  // internal browser pages. An error sourced here is not a finding about the app.
  var NOISE_SOURCE = /^(chrome|moz|safari-web|webkit-masked)-extension:|^chrome:\/\//i;
  // True when an uncaught error is environment/third-party noise rather than the
  // app crashing, so the SDK drops it instead of shipping a low-signal bucket.
  function isCrashNoise(message, source) {
    var m = String(message == null ? "" : message).toLowerCase().trim();
    if (!m || m === "script error." || m === "script error") return true;
    for (var i = 0; i < CRASH_NOISE.length; i++) {
      if (m.indexOf(CRASH_NOISE[i]) !== -1) return true;
    }
    if (source && NOISE_SOURCE.test(String(source))) return true;
    return false;
  }

  // ---- the SDK ------------------------------------------------------------
  var ReproIt = {
    _cfg: null,
    _buf: [],
    _cur: null, // current state signature
    _path: [], // [{sig, action, label?}] graph trail for repros
    _pending: null, // last interaction's {action,label?}, awaiting a snapshot
    _timer: null,
    _on: false,
    _build: null, // developer-provided { version, commit } or null

    init: function (opts) {
      if (this._on) return this;
      var cfg = Object.assign({}, DEFAULTS, opts || {});
      // Automation-driven sessions (Playwright/Selenium, including reproit's own
      // replays) never feed production telemetry: a replayed crash would re-count
      // the very bucket it reproduces. Test rigs opt in via reportAutomation.
      if (navigator.webdriver && !cfg.reportAutomation) return this;
      // session sampling: report only a fraction of sessions
      if (Math.random() >= cfg.sampleRate) return this;
      this._cfg = cfg;
      this._on = true;
      // Developer-provided build identity, stamped under context.build so the
      // cloud can segment bugs by build (regressed in / resolved since). Only the
      // provided fields ride; null (omitted) when no build was supplied.
      this._build = normalizeBuild(cfg.build);
      // Layer-3 opt-in value-node selectors (docs/signature.md "Value-state").
      setValueNodeSelectors(cfg.valueNodes);

      var self = this;
      // 1. observe an initial state once the DOM settles
      this._settle(function () { self._observe("load"); });

      // 2. navigations (SPA + classic)
      this._wrapHistory();
      addEventListener("popstate", function () { self._settle(function () { self._observe("nav"); }); });

      // 3. interactions -> remember structural action + display label, then re-snapshot
      addEventListener(
        "click",
        function (e) {
          var t = e.target;
          while (t && t !== document && !interactive(t)) t = t.parentElement;
          var label = t && t !== document ? nameOf(t) || "" : "";
          var sel = t && t !== document ? actionSelectorOf(t) : null;
          self._pending = { action: sel ? "tap:" + sel : "tap:?", label: label || undefined };
          self._settle(function () { self._observe(self._pending); });
        },
        true
      );

      // 4. crash oracle: a genuine uncaught error is the `crash` oracle firing,
      //    tagged so, carrying the graph PATH to it (the seed of a deterministic
      //    repro). Environment/third-party noise is dropped so only oracle-grade
      //    findings ship. General (non-oracle) error capture is a future opt-in.
      addEventListener("error", function (e) {
        var message = e.message || String(e);
        if (isCrashNoise(message, e.filename)) return;
        self._emit({
          kind: "error",
          oracle: "crash",
          sig: self._cur,
          path: self._errorPath(),
          message: message,
          stack: e.error && e.error.stack ? String(e.error.stack).split("\n").slice(0, 8) : undefined,
          source: e.filename,
          line: e.lineno,
          context: self._errorContext(),
        });
      });
      addEventListener("unhandledrejection", function (e) {
        var r = e.reason || {};
        var reason = r.message || String(r);
        if (isCrashNoise(reason, undefined)) return;
        self._emit({
          kind: "error",
          oracle: "crash",
          sig: self._cur,
          path: self._errorPath(),
          message: "unhandledrejection: " + reason,
          stack: r.stack ? String(r.stack).split("\n").slice(0, 8) : undefined,
          context: self._errorContext(),
        });
      });

      // 5. flush on a timer and when the page goes away
      this._timer = setInterval(function () { self._flush(); }, cfg.flushMs);
      addEventListener("pagehide", function () { self._flush(true); });
      addEventListener("visibilitychange", function () {
        if (document.visibilityState === "hidden") self._flush(true);
      });
      return this;
    },

    // Zero-config start: the one-line quickstart. Begins telemetry with sensible
    // defaults and no required options, deriving appId from the page host when
    // one is not supplied, then delegating to init (which stays the full,
    // explicit entry point). Additive and backward-compatible: ReproIt.start()
    // is the copy-paste one-liner, ReproIt.init(opts) is unchanged. A web page
    // has no build-mode distinction, so start() is active wherever it is loaded;
    // the existing webdriver/reportAutomation guard still keeps test-rig sessions
    // out of production telemetry. Pass any init option to override a default
    // (e.g. ReproIt.start({ endpoint, key })).
    start: function (opts) {
      var o = opts || {};
      if (o.appId == null) {
        var host = "";
        try {
          if (typeof location !== "undefined" && location.hostname) host = location.hostname;
        } catch (e) {}
        o = Object.assign({}, o, { appId: host || "app" });
      }
      return this.init(o);
    },

    // Register an app invariant: a predicate the app declares that must hold in
    // EVERY visited state (a running total never negative, the selected tab
    // always highlighted). `test` returns truthy when it holds, or falsy /
    // throws / an { ok:false, message } object when it is violated. reproit's
    // fuzzer evaluates every registered invariant on each state-settle and
    // reports the failures as `invariant` findings; in production the registry
    // is inert (a plain array push, no evaluation), so this is zero-overhead
    // until a run reproduces it. Registration is idempotent by id, so a hot
    // reload re-registering the same id replaces rather than duplicates it.
    // Stored on a stable global (window.__reproit_invariants) so reproit reads
    // it without coupling to this SDK's internals.
    invariant: function (id, test) {
      if (typeof id !== "string" || typeof test !== "function") return this;
      if (typeof window === "undefined") return this;
      var reg = window.__reproit_invariants || (window.__reproit_invariants = []);
      for (var i = 0; i < reg.length; i++) {
        if (reg[i].id === id) { reg[i].test = test; return this; }
      }
      reg.push({ id: id, test: test });
      return this;
    },

    _settle: function (fn) {
      clearTimeout(this._settleT);
      this._settleT = setTimeout(fn, this._cfg.debounceMs);
    },

    _wrapHistory: function () {
      var self = this;
      ["pushState", "replaceState"].forEach(function (m) {
        var orig = history[m];
        history[m] = function () {
          var r = orig.apply(this, arguments);
          self._settle(function () { self._observe("nav"); });
          return r;
        };
      });
    },

    // Observe the current screen; if its signature changed, record the edge.
    _observe: function (step) {
      if (!this._on) return;
      var snap = snapshot(this._cfg);
      if (snap.sig === this._cur) {
        // No structural change, but a same-sig INTERACTION still belongs in the
        // path: dropping it breaks replay fidelity when the tap mutates state
        // the signature ignores (e.g. "add to cart" only bumps a counter, yet
        // the later crash needs that item in the cart). Recorded as a self-loop
        // path step only; no edge event (the map has nothing new to learn).
        if (step && typeof step === "object" && step.action) {
          var selfStep = { sig: snap.sig, action: step.action };
          if (!this._cfg.redactLabels && step.label) selfStep.label = step.label;
          this._path.push(selfStep);
          if (this._path.length > this._cfg.pathCap) this._path.shift();
          this._pending = null;
        }
        return;
      }
      var action = (step && typeof step === "object") ? step.action : step;
      var label = (step && typeof step === "object") ? step.label : undefined;
      var from = this._cur;
      this._cur = snap.sig;
      var pathStep = { sig: snap.sig, action: action };
      if (!this._cfg.redactLabels && label) pathStep.label = label;
      this._path.push(pathStep);
      if (this._path.length > this._cfg.pathCap) this._path.shift();
      var ev = {
        kind: "edge",
        from: from,
        action: action || "auto",
        to: snap.sig,
        labels: this._cfg.redactLabels ? undefined : snap.labels,
      };
      if (!this._cfg.redactLabels && label) ev.label = label;
      this._emit(ev);
      this._pending = null;
    },

    // The action path to an error, INCLUDING the in-flight action. A click that
    // throws synchronously (the crashing tap) sets `_pending` but crashes before
    // its debounced `_observe` records it, so the bare path stops one step short
    // of the bug. Append the pending action so the captured repro contains the
    // step that actually triggers the crash -- otherwise a replay reaches the
    // screen but never fires it.
    _errorPath: function () {
      var path = this._path.slice();
      if (this._pending) {
        var step = { sig: this._cur, action: this._pending.action };
        if (!this._cfg.redactLabels && this._pending.label) step.label = this._pending.label;
        path.push(step);
      }
      return path;
    },

    // On-error context. Tier-3 input fingerprints ride here under
    // `context.fingerprint` (PII-safe FEATURES of on-screen fields, never the
    // raw values). Best-effort: failure to read the DOM never breaks reporting.
    _errorContext: function () {
      try {
        var fp = collectFieldFingerprints();
        if (fp.length) return { fingerprint: fp, fpVersion: FP_VERSION };
      } catch (e) {}
      return undefined;
    },

    _emit: function (ev) {
      ev.t = Date.now();
      if (this._cfg.onEvent) {
        try { this._cfg.onEvent(ev); } catch (e) {}
      }
      this._buf.push(ev);
      if (this._buf.length >= 50) this._flush();
    },

    _flush: function (useBeacon) {
      if (!this._buf.length) return;
      var batch = { appId: this._cfg.appId, sentAt: Date.now(), events: this._buf };
      // Stamp the developer-provided build identity as context.build (only the
      // provided fields); omitted entirely when no build was supplied.
      if (this._build) batch.ctx = { build: this._build };
      this._buf = [];
      var cfg = this._cfg;
      if (!cfg.endpoint) {
        if (!cfg.onEvent && typeof console !== "undefined") console.debug("[reproit]", batch);
        return;
      }
      var body = JSON.stringify(batch);
      // sendBeacon cannot carry an Authorization header, so a keyed config always
      // posts via fetch; `keepalive: true` gives it beacon-like unload survival.
      if (useBeacon && navigator.sendBeacon && !cfg.key) {
        navigator.sendBeacon(cfg.endpoint, body);
      } else {
        var headers = { "Content-Type": "application/json" };
        if (cfg.key) headers["Authorization"] = "Bearer " + cfg.key;
        fetch(cfg.endpoint, {
          method: "POST",
          headers: headers,
          body: body,
          keepalive: true,
        }).catch(function () {});
      }
    },
  };

  // Expose the pure fingerprint helpers (load-bearing, host-testable).
  ReproIt.fingerprintValue = fingerprintValue;
  ReproIt.collectFieldFingerprints = collectFieldFingerprints;
  ReproIt.FP_VERSION = FP_VERSION;
  // The production error gate (host-testable): true for environment/third-party
  // noise the SDK must NOT report, so the crash oracle stays zero/low-FP.
  ReproIt.isCrashNoise = isCrashNoise;

  // Expose the CANONICAL signature core (load-bearing, parity-tested against
  // signature_vectors.json + the Rust oracle). signatureOf/descriptorOf take a
  // canonical Node tree; domToNode builds one from a live DOM root.
  ReproIt.signatureOf = signatureOf;
  ReproIt.descriptorOf = descriptorOf;
  ReproIt.domToNode = domToNode;
  ReproIt.anchorOf = anchorOf;
  // Layer-2 value-class bucketer + Layer-3 opt-in selector installer (load-
  // bearing, parity-tested against the oracle's value_class / V: section).
  ReproIt.valueClass = valueClass;
  ReproIt.setValueNodeSelectors = setValueNodeSelectors;
  // Developer-provided build identity normalizer (load-bearing, host-testable):
  // keeps only the provided {version, commit} string fields, else null.
  ReproIt.normalizeBuild = normalizeBuild;
  ReproIt._actionKeyOf = actionKeyOf;

  global.ReproIt = ReproIt;
  if (typeof module !== "undefined" && module.exports) module.exports = ReproIt;
})(typeof window !== "undefined" ? window : this);
