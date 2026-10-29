"use strict";

(() => {
  const key = "vpn-ui-theme";
  let storageMessage = "";

  function apply(theme) {
    document.documentElement.dataset.theme = theme;
    const toggle = document.getElementById("theme-toggle");
    if (toggle) toggle.setAttribute("aria-checked", String(theme === "dark"));
    document.dispatchEvent(new Event("themechange"));
  }

  function storageError(error) {
    storageMessage = "Theme preference could not be saved or loaded. This change may last only for this page.";
    console.warn("vpn-ui: theme storage unavailable", error.name);
    const status = document.getElementById("theme-status");
    if (status) status.textContent = storageMessage;
  }

  try {
    apply(localStorage.getItem(key) === "dark" ? "dark" : "light");
  } catch (error) {
    storageError(error);
    apply("light");
  }

  document.addEventListener("DOMContentLoaded", () => {
    const toggle = document.getElementById("theme-toggle");
    toggle.setAttribute("aria-checked", String(document.documentElement.dataset.theme === "dark"));
    document.getElementById("theme-status").textContent = storageMessage;
    toggle.addEventListener("click", () => {
      const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      apply(theme);
      try {
        localStorage.setItem(key, theme);
        storageMessage = "";
        document.getElementById("theme-status").textContent = "";
      } catch (error) {
        storageError(error);
      }
    });
  });

  window.addEventListener("storage", event => {
    if (event.key === key || event.key === null) apply(event.newValue === "dark" ? "dark" : "light");
  });
})();
