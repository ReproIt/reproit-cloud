// NimbusShop is a tiny hash-routed storefront with FIVE planted UI bugs, each
// caught by a different reproit oracle, plus a null-deref CRASH reached by
// Cart -> Checkout. It ships with the reproit web SDK wired to the cloud that
// served this page, so clicking around is exactly what a real user in production
// does: a crash here is reported to your dashboard and grouped into a bucket.
//
//   1. overflow      a product SKU spills out of its card (home)
//   2. a11y          the cart icon button has no accessible name (top bar)
//   3. content-bug   the profile greets "[object Object]" (profile)
//   4. dead-end      the Help screen has no way out (help)
//   5. broken-route  the footer "Docs" link 404s (every screen)
//   + crash          Cart -> Checkout dereferences a null order -> TypeError
//
// CSP note: this page is served under `script-src 'self'` (no inline handlers),
// so every control is wired here by event delegation, never an inline onclick.

const view = document.getElementById("view");

// The cart model. Add/remove are safe; "Checkout" routes to the confirmation
// screen, which is where the crash lives (see the "/confirm" screen below).
const cart = {
  items: [{ name: "Nimbus Tee", price: 24 }],
  addItem() {
    this.items.push({ name: "Cloud Mug", price: 14 });
    render();
  },
  removeLast() {
    this.items.pop();
    render();
  },
  checkout() {
    location.hash = "#/confirm";
  },
};

// The pending order is only populated by a real checkout flow that was never
// built, so it stays null. The confirmation screen reads `order.total` on render
// -> uncaught TypeError, captured by the SDK's error listener with the graph
// PATH that led to it (Home -> Cart -> Checkout).
let order = null;

// The signed-in user. BUG (content-bug): the profile screen interpolates the
// whole object into a template instead of `user.name`.
const user = { name: "Avery", plan: "pro" };

const screens = {
  "/": () => `
    <h1>Featured</h1>
    <div class="grid">
      ${product("Nimbus Tee", "$24", "TEE-001")}
      <!-- BUG (overflow): long, non-breaking SKU in a fixed-width card. -->
      ${product("Aurora Hoodie", "$68", "HOODIE-4815162342-LIMITED-EDITION-XL")}
      ${product("Cloud Mug", "$14", "MUG-007")}
    </div>`,

  "/cart": () => {
    const items = cart.items;
    const body = items.length
      ? `<ul class="cart-list" data-testid="cart-list">${items
          .map((it) => `<li>${it.name}: $${it.price}</li>`)
          .join("")}</ul>`
      : `<p class="empty" data-testid="cart-empty">Your cart is empty.</p>`;
    return `
    <h1>Your cart</h1>
    ${body}
    <div class="row">
      <button data-testid="cart-add" data-action="cart-add">Add item</button>
      <button data-testid="cart-remove" data-action="cart-remove">Remove last</button>
      <button data-testid="cart-checkout" data-action="cart-checkout">Checkout</button>
    </div>`;
  },

  // BUG (crash): `order.total` throws because order is null. Reached via Cart ->
  // Checkout, so a real user who checks out trips it every time.
  "/confirm": () => `
    <h1>Order confirmed</h1>
    <p class="total">Total charged: $${order.total.toFixed(2)}</p>
    <p>Thanks for shopping with NimbusShop.</p>`,

  "/profile": () => `
    <h1>Profile</h1>
    <!-- BUG (content-bug): should be user.name, interpolates the whole object. -->
    <p class="greeting" data-testid="greeting">Welcome back, ${user}!</p>
    <dl>
      <dt>Plan</dt><dd>${user.plan}</dd>
    </dl>`,

  // BUG (dead-end): a full-screen Help article with no navigation, no back, no
  // links. Once a user lands here they are trapped.
  "/help": () => `
    <section class="help-takeover">
      <h1>Help Center</h1>
      <p>Frequently asked questions will appear here soon.</p>
      <p>For now, there is nothing on this page and no way forward.</p>
    </section>`,
};

function product(name, price, sku) {
  return `
    <article class="card">
      <div class="thumb"></div>
      <h3>${name}</h3>
      <div class="price">${price}</div>
      <div class="sku" data-testid="sku-${sku}">${sku}</div>
    </article>`;
}

function render() {
  const route = location.hash.replace(/^#/, "") || "/";
  const screen = screens[route] || screens["/"];
  // The Help takeover hides the chrome to make the dead-end real.
  document.body.classList.toggle("takeover", route === "/help");
  // Clear first so a screen whose render throws (the /confirm crash) leaves an
  // empty view, not the previous screen's stale DOM.
  view.innerHTML = "";
  view.innerHTML = screen();
}

window.addEventListener("hashchange", render);

// One delegated click listener for every control on the page (CSP-safe: no
// inline handlers). `data-action` runs a cart method; `data-nav` navigates.
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-action],[data-nav]");
  if (!el) return;
  const nav = el.getAttribute("data-nav");
  if (nav) {
    location.hash = nav;
    return;
  }
  switch (el.getAttribute("data-action")) {
    case "cart-add":
      cart.addItem();
      break;
    case "cart-remove":
      cart.removeLast();
      break;
    case "cart-checkout":
      cart.checkout();
      break;
  }
});

// Production telemetry SDK. This page was served by your reproit cloud; the
// project id + write-only key arrive in a one-time URL fragment, which browsers
// never send to the server or in Referer headers. Consume it before hash routing,
// then replace it with the normal landing route so it is not retained in history.
let wired = null;
if (location.hash.startsWith("#reproit=")) {
  try {
    wired = JSON.parse(atob(decodeURIComponent(location.hash.slice(9))));
  } catch {}
  history.replaceState(null, "", location.pathname + location.search + "#/");
}
const appId = wired && wired.appId;
const key = wired && wired.key;

// Normalize the landing route so "/" and "/#/" don't read as two screens.
if (!location.hash) location.hash = "#/";
render();
const banner = document.getElementById("demo-banner");
const bannerText = document.getElementById("demo-banner-text");

if (window.ReproIt && appId && key) {
  ReproIt.init({
    appId: appId,
    key: key,
    endpoint: location.origin + "/v1/events",
    // Flush promptly so the crash shows up in the dashboard within a beat, not
    // after the default batch interval.
    flushMs: 1500,
  });
  bannerText.textContent =
    "This shop is monitored by reproit. Add to cart, then hit Checkout. The crash lands in your dashboard.";
  banner.hidden = false;
} else if (window.ReproIt) {
  ReproIt.init({
    appId: appId || "nimbusshop",
    onEvent: (ev) => console.log("[reproit sdk]", ev.kind, ev.message || ev.to || ""),
  });
  bannerText.textContent =
    "Console-only demo (no project connected). Open this from your dashboard to wire it to your cloud.";
  banner.hidden = false;
}
