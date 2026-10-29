"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.resolve(__dirname,
  "../../../../../project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/var/www/theme.js"), "utf8");

function visit(storage, blocked = false) {
  const events = {}, windowEvents = {}, clicks = {};
  const attributes = {};
  const status = {textContent: ""};
  const toggle = {
    setAttribute: (name, value) => { attributes[name] = value; },
    addEventListener: (name, callback) => { clicks[name] = callback; }
  };
  const document = {
    documentElement: {dataset: {}},
    getElementById: id => id === "theme-toggle" ? toggle : status,
    addEventListener: (name, callback) => { events[name] = callback; },
    dispatchEvent: () => {}
  };
  vm.runInNewContext(source, {
    document, Event: class { constructor(type) { this.type = type; } },
    window: {addEventListener: (name, callback) => { windowEvents[name] = callback; }},
    console: {warn: () => {}},
    localStorage: {
      getItem: key => { if (blocked) throw new Error("blocked"); return storage.get(key); },
      setItem: (key, value) => { if (blocked) throw new Error("blocked"); storage.set(key, value); }
    }
  });
  const earlyTheme = document.documentElement.dataset.theme;
  events.DOMContentLoaded();
  return {document, attributes, status, click: clicks.click, sync: windowEvents.storage, earlyTheme};
}

const storage = new Map();
const login = visit(storage);
assert.equal(login.earlyTheme, "light");
login.click();
assert.equal(storage.get("vpn-ui-theme"), "dark");
assert.equal(login.attributes["aria-checked"], "true");
const management = visit(storage);
assert.equal(management.earlyTheme, "dark");
assert.equal(visit(storage).earlyTheme, "dark"); // Reload / next session / logout destination.
management.click();
assert.equal(visit(storage).earlyTheme, "light");
login.sync({key: "vpn-ui-theme", newValue: "light"});
assert.equal(login.attributes["aria-checked"], "false");
login.sync({key: null, newValue: null});
assert.equal(login.document.documentElement.dataset.theme, "light");
storage.set("vpn-ui-theme", "invalid");
assert.equal(visit(storage).earlyTheme, "light");
const unavailable = visit(storage, true);
assert.match(unavailable.status.textContent, /could not be saved or loaded/);
unavailable.click();
assert.equal(unavailable.document.documentElement.dataset.theme, "dark");
assert.match(unavailable.status.textContent, /only for this page/);
console.log("Theme persistence, early application, cross-tab sync, invalid values and storage failure: passed");
