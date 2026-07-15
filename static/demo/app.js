// NimbusShop is the polished first-run sample for ReproIt Cloud. The store is
// intentionally ordinary except for one planted checkout crash. That single
// failure demonstrates the complete production capture and reproduction loop
// without making onboarding look like a broken application.

const view = document.getElementById("view");
const cartCount = document.getElementById("cart-count");
const cartButton = document.querySelector(".cart-button");
const toast = document.getElementById("cart-status");

const products = [
  { id: "tee", name: "Nimbus Tee", price: 24, sku: "TEE-001", art: "tee" },
  { id: "hoodie", name: "Aurora Hoodie", price: 68, sku: "HOODIE-042", art: "hoodie" },
  { id: "mug", name: "Cloud Mug", price: 14, sku: "MUG-007", art: "mug" },
];

const cart = {
  items: [],
  add(productId) {
    const product = products.find((item) => item.id === productId);
    if (!product) return;
    this.items.push(product);
    render();
    showToast(`${product.name} added to cart`);
  },
  remove(index) {
    this.items.splice(index, 1);
    render();
  },
  checkout() {
    if (!this.items.length) return;
    location.hash = "#/confirm";
  },
};

// The confirmation payload is deliberately absent. Checkout reaches this screen
// and reads order.total, producing the one real crash this sample exists to show.
let order = null;
const user = { name: "Avery", plan: "Pro" };
let toastTimer = null;

function money(value) {
  return "$" + value.toFixed(2);
}

function productArt(kind) {
  if (kind === "tee") {
    return `<svg class="product-art" viewBox="0 0 120 120" aria-hidden="true">
      <path d="M39 30 23 40l10 20 10-5v39h34V55l10 5 10-20-16-10-10 8H49l-10-8Z" fill="currentColor" opacity=".94"/>
      <path d="M49 38c2 8 20 8 22 0" fill="none" stroke="#cdd7ff" stroke-width="4" stroke-linecap="round"/>
    </svg>`;
  }
  if (kind === "hoodie") {
    return `<svg class="product-art" viewBox="0 0 120 120" aria-hidden="true">
      <path d="M43 35c1-17 33-17 34 0l14 12-8 47H37l-8-47 14-12Z" fill="currentColor" opacity=".94"/>
      <path d="M43 36c4 14 30 14 34 0M48 73h24M60 50v18" fill="none" stroke="#ffe1e8" stroke-width="4" stroke-linecap="round"/>
    </svg>`;
  }
  return `<svg class="product-art" viewBox="0 0 120 120" aria-hidden="true">
    <path d="M30 36h54v49c0 8-7 15-15 15H45c-8 0-15-7-15-15V36Z" fill="currentColor" opacity=".94"/>
    <path d="M84 49h8c17 0 17 27 0 27h-8M45 24c-7 7 7 10 0 17M62 20c-7 7 7 10 0 17" fill="none" stroke="#d9fff6" stroke-width="5" stroke-linecap="round"/>
  </svg>`;
}

function productCard(product) {
  return `<article class="card">
    <div class="thumb thumb-${product.art}">${productArt(product.art)}</div>
    <div class="card-body">
      <h3>${product.name}</h3>
      <div class="product-meta">
        <span class="price">${money(product.price)}</span>
        <span class="sku" title="${product.sku}">${product.sku}</span>
      </div>
      <button class="add-button" type="button" data-product="${product.id}">Add to cart</button>
    </div>
  </article>`;
}

function homeScreen() {
  return `<section class="hero">
      <div>
        <p class="eyebrow">Built for lighter days</p>
        <h1>Essentials for work above the clouds.</h1>
        <p class="hero-copy">Soft layers, useful objects, and a little more room to think.</p>
      </div>
      <div class="hero-note"><strong>Free shipping</strong>On every sample order today.</div>
    </section>
    <section aria-labelledby="featured-heading">
      <div class="section-head">
        <h2 id="featured-heading">Featured products</h2>
        <span>Three everyday favorites</span>
      </div>
      <div class="grid">${products.map(productCard).join("")}</div>
    </section>`;
}

function cartScreen() {
  if (!cart.items.length) {
    return `<div class="page-head"><p class="eyebrow">Your bag</p><h1>Your cart</h1></div>
      <section class="empty-cart">
        <h2>Your cart is empty</h2>
        <p>Pick something from the shop to continue.</p>
        <button class="primary-button" type="button" data-nav="#/">Browse products</button>
      </section>`;
  }
  const rows = cart.items.map((item, index) => `<li class="cart-item">
      <div><strong>${item.name}</strong><small>${item.sku}</small></div>
      <span>${money(item.price)}</span>
      <button class="remove-button" type="button" data-remove="${index}">Remove</button>
    </li>`).join("");
  const total = cart.items.reduce((sum, item) => sum + item.price, 0);
  return `<div class="page-head"><p class="eyebrow">Your bag</p><h1>Your cart</h1><p>Review your items before checkout.</p></div>
    <section class="surface">
      <ul class="cart-list" data-testid="cart-list">${rows}</ul>
      <div class="cart-summary">
        <strong>Total ${money(total)}</strong>
        <div class="actions">
          <button class="secondary-button" type="button" data-nav="#/">Keep shopping</button>
          <button class="primary-button" data-testid="cart-checkout" type="button" data-action="cart-checkout">Checkout</button>
        </div>
      </div>
    </section>`;
}

const screens = {
  "/": homeScreen,
  "/cart": cartScreen,
  "/confirm": () => `<div class="page-head"><h1>Order confirmed</h1></div>
    <section class="surface"><p>Total charged: ${money(order.total)}</p></section>`,
  "/profile": () => `<div class="page-head"><p class="eyebrow">Account</p><h1>Profile</h1></div>
    <section class="surface profile-grid">
      <div class="avatar" aria-hidden="true">A</div>
      <div><h2>Welcome back, ${user.name}</h2><p>${user.plan} member · Sample account</p></div>
    </section>`,
  "/help": () => `<div class="page-head"><p class="eyebrow">Support</p><h1>How can we help?</h1><p>Everything you need to move through this sample store.</p></div>
    <section class="help-list">
      <div class="help-item"><strong>Shipping</strong><p>Sample orders ship free and are never actually charged.</p></div>
      <div class="help-item"><strong>Returns</strong><p>This is a ReproIt demonstration, so there is nothing to return.</p></div>
    </section>
    <button class="primary-button" type="button" data-nav="#/">Return to shop</button>`,
};

function currentRoute() {
  return location.hash.replace(/^#/, "") || "/";
}

function syncChrome(route) {
  const count = cart.items.length;
  cartCount.textContent = String(count);
  cartButton.setAttribute("aria-label", `Cart, ${count} item${count === 1 ? "" : "s"}`);
  cartButton.setAttribute("aria-current", route === "/cart" ? "page" : "false");
  document.querySelectorAll("[data-route]").forEach((link) => {
    if (link.dataset.route === route) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
}

function render() {
  const route = currentRoute();
  const screen = screens[route] || screens["/"];
  syncChrome(route);
  view.innerHTML = "";
  view.innerHTML = screen();
}

function showToast(message) {
  toast.textContent = message;
  toast.hidden = false;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 1800);
}

window.addEventListener("hashchange", render);
document.addEventListener("click", (event) => {
  const control = event.target.closest("[data-product],[data-remove],[data-action],[data-nav]");
  if (!control) return;
  const nav = control.getAttribute("data-nav");
  if (nav) {
    location.hash = nav;
    return;
  }
  if (control.hasAttribute("data-product")) {
    cart.add(control.dataset.product);
    return;
  }
  if (control.hasAttribute("data-remove")) {
    cart.remove(Number(control.dataset.remove));
    return;
  }
  if (control.dataset.action === "cart-checkout") cart.checkout();
});

// The project id and write-only key arrive in a URL fragment. Fragments are not
// sent to the server or in Referer headers. Consume it, then replace the fragment
// with the normal shop route so the credential is not retained in history.
let wired = null;
if (location.hash.startsWith("#reproit=")) {
  try {
    wired = JSON.parse(atob(decodeURIComponent(location.hash.slice(9))));
  } catch {}
  history.replaceState(null, "", location.pathname + location.search + "#/");
}
const appId = wired && wired.appId;
const key = wired && wired.key;
if (!location.hash) location.hash = "#/";

const banner = document.getElementById("demo-banner");
const bannerText = document.getElementById("demo-banner-text");
if (window.ReproIt && appId && key) {
  ReproIt.init({
    appId,
    key,
    endpoint: location.origin + "/v1/events",
    flushMs: 1500,
  });
  bannerText.textContent = "Add any item, open your cart, then check out. The captured crash will appear in your dashboard.";
  banner.hidden = false;
} else if (window.ReproIt) {
  ReproIt.init({
    appId: appId || "nimbusshop",
    onEvent: (event) => console.log("[ReproIt SDK]", event.kind, event.message || event.to || ""),
  });
  bannerText.textContent = "This sample is not connected. Open it from your Cloud dashboard to capture the checkout crash.";
  banner.hidden = false;
}
render();
