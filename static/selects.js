(() => {
  let nextId = 0;

  function selectLabel(select) {
    if (select.getAttribute("aria-label")) return select.getAttribute("aria-label");
    if (select.id) {
      const label = Array.from(document.querySelectorAll("label[for]"))
        .find((item) => item.getAttribute("for") === select.id);
      if (label) return label.textContent.trim();
    }
    return "Choose an option";
  }

  function closeAll(except) {
    document.querySelectorAll(".custom-select-wrap.open").forEach((wrap) => {
      if (wrap === except) return;
      wrap.classList.remove("open", "open-up");
      wrap.querySelector(".custom-select-button")?.setAttribute("aria-expanded", "false");
    });
  }

  function sync(select) {
    const wrap = select.closest(".custom-select-wrap");
    if (!wrap) return;
    const button = wrap.querySelector(".custom-select-button");
    const menu = wrap.querySelector(".custom-select-menu");
    const selected = select.options[select.selectedIndex];
    button.disabled = select.disabled;
    button.querySelector("span").textContent = selected ? selected.textContent : "Choose";
    menu.replaceChildren(...Array.from(select.options).map((option, index) => {
      const item = document.createElement("button");
      const active = index === select.selectedIndex;
      item.type = "button";
      item.className = "custom-select-option";
      item.dataset.customSelectIndex = String(index);
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", active ? "true" : "false");
      item.disabled = option.disabled;
      const text = document.createElement("span");
      text.textContent = option.textContent;
      const check = document.createElement("i");
      check.setAttribute("aria-hidden", "true");
      check.textContent = active ? "✓" : "";
      item.append(text, check);
      return item;
    }));
  }

  function enhance(select) {
    if (!(select instanceof HTMLSelectElement) || select.dataset.customSelect === "true") return;
    let wrap = select.closest(".selwrap");
    if (!wrap) {
      wrap = document.createElement("div");
      wrap.className = "selwrap";
      select.before(wrap);
      wrap.append(select);
    }
    wrap.classList.add("custom-select-wrap");
    select.dataset.customSelect = "true";
    select.classList.add("native-select-source");
    select.tabIndex = -1;
    select.setAttribute("aria-hidden", "true");

    const id = `custom-select-${++nextId}`;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "custom-select-button";
    button.dataset.customSelectToggle = id;
    button.setAttribute("aria-haspopup", "listbox");
    button.setAttribute("aria-expanded", "false");
    button.setAttribute("aria-controls", `${id}-menu`);
    button.setAttribute("aria-label", selectLabel(select));
    button.innerHTML = '<span></span><i aria-hidden="true"></i>';

    const menu = document.createElement("div");
    menu.id = `${id}-menu`;
    menu.className = "custom-select-menu";
    menu.dataset.customSelectMenu = id;
    menu.setAttribute("role", "listbox");
    menu.setAttribute("aria-label", selectLabel(select));

    select.after(button, menu);
    if (select.id) {
      Array.from(document.querySelectorAll("label[for]"))
        .filter((label) => label.getAttribute("for") === select.id)
        .forEach((label) => label.setAttribute("for", `${id}-button`));
      button.id = `${id}-button`;
    }
    select.addEventListener("change", () => sync(select));
    sync(select);
  }

  function enhanceAll(scope = document) {
    if (scope instanceof HTMLSelectElement) enhance(scope);
    scope.querySelectorAll?.("select").forEach(enhance);
  }

  function open(wrap) {
    closeAll(wrap);
    const menu = wrap.querySelector(".custom-select-menu");
    const optionCount = menu.querySelectorAll(".custom-select-option").length;
    const rect = wrap.getBoundingClientRect();
    const expectedHeight = Math.min(optionCount * 36 + 12, 260);
    wrap.classList.toggle("open-up", rect.bottom + expectedHeight + 8 > window.innerHeight && rect.top > expectedHeight);
    wrap.classList.add("open");
    wrap.querySelector(".custom-select-button").setAttribute("aria-expanded", "true");
    const selected = menu.querySelector('[aria-selected="true"]');
    (selected || menu.querySelector(".custom-select-option"))?.focus();
  }

  document.addEventListener("click", (event) => {
    const toggle = event.target.closest?.("[data-custom-select-toggle]");
    if (toggle) {
      event.preventDefault();
      const wrap = toggle.closest(".custom-select-wrap");
      if (wrap.classList.contains("open")) closeAll();
      else open(wrap);
      return;
    }
    const option = event.target.closest?.("[data-custom-select-index]");
    if (option) {
      event.preventDefault();
      const wrap = option.closest(".custom-select-wrap");
      const select = wrap.querySelector("select");
      select.selectedIndex = Number(option.dataset.customSelectIndex);
      sync(select);
      closeAll();
      select.dispatchEvent(new Event("change", { bubbles: true }));
      return;
    }
    closeAll();
  });

  document.addEventListener("keydown", (event) => {
    const button = event.target.closest?.("[data-custom-select-toggle]");
    if (button && ["Enter", " ", "ArrowDown", "ArrowUp"].includes(event.key)) {
      event.preventDefault();
      open(button.closest(".custom-select-wrap"));
      return;
    }
    const option = event.target.closest?.("[data-custom-select-index]");
    if (!option) {
      if (event.key === "Escape") closeAll();
      return;
    }
    const wrap = option.closest(".custom-select-wrap");
    const options = Array.from(wrap.querySelectorAll(".custom-select-option:not(:disabled)"));
    const index = options.indexOf(option);
    if (event.key === "Escape") {
      event.preventDefault();
      closeAll();
      wrap.querySelector(".custom-select-button")?.focus();
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      option.click();
    } else if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      let target = index;
      if (event.key === "ArrowDown") target = Math.min(options.length - 1, index + 1);
      if (event.key === "ArrowUp") target = Math.max(0, index - 1);
      if (event.key === "Home") target = 0;
      if (event.key === "End") target = options.length - 1;
      options[target]?.focus();
    }
  });

  function start() {
    enhanceAll();
    new MutationObserver((mutations) => {
      mutations.forEach((mutation) => mutation.addedNodes.forEach((node) => {
        if (node.nodeType === 1) enhanceAll(node);
      }));
    }).observe(document.body, { childList: true, subtree: true });
  }

  window.ReproitSelects = { enhanceAll, closeAll };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();

