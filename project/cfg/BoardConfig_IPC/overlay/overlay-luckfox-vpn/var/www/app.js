"use strict";

const api = "/cgi-bin/vpn.cgi/";
const byId = id => document.getElementById(id);
let page = "dashboard";
let busy = false;
let pendingPage = false;
let generation = 0;
let controller = new AbortController();
let previous = null;
let cpuHistory = [];
let rxHistory = [];
let txHistory = [];
let qrURL = null;
let enabled = true;
let clientSnapshot = null;
let ledState = "unavailable";

function text(id, value) { byId(id).textContent = value; }
function bytes(value) {
  if (value === null || value === undefined) return "Unavailable";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return value.toFixed(unit ? 1 : 0) + " " + units[unit];
}
function when(epoch) { return epoch ? new Date(epoch * 1000).toLocaleString() : "Unavailable"; }
function closeQR() {
  byId("qr-dialog").close();
  byId("qr-image").removeAttribute("src");
  if (qrURL) URL.revokeObjectURL(qrURL);
  qrURL = null;
}
function wipe() {
  generation++;
  controller.abort();
  controller = new AbortController();
  enabled = false;
  pendingPage = false;
  previous = null;
  clientSnapshot = null;
  cpuHistory = []; rxHistory = []; txHistory = [];
  closeQR();
  byId("add-dialog").close();
  byId("add-client").reset();
  byId("protected").hidden = true;
  for (const id of ["client-rows", "backup-rows", "settings", "storage"]) byId(id).replaceChildren();
  for (const id of ["vpn-state", "vpn-detail", "recent", "uptime", "glance", "cpu", "load",
    "memory", "swap", "temperature", "network", "led-state"]) text(id, "");
  for (const id of ["cpu-chart", "net-chart"]) {
    const canvas = byId(id);
    canvas.getContext("2d").clearRect(0, 0, canvas.width, canvas.height);
  }
}

async function request(action, fields, blob = false, raw = false) {
  const options = {cache: "no-store", credentials: "same-origin", signal: controller.signal};
  if (fields !== undefined) {
    options.method = "POST";
    options.headers = {"X-VPN-UI": "1", "Content-Type": raw ? "application/gzip" : "application/x-www-form-urlencoded"};
    if (raw) options.headers["X-VPN-Backup-Name"] = fields.name;
    options.body = raw ? fields : new URLSearchParams(fields);
  }
  const current = generation;
  const response = await fetch(api + action, options);
  if (response.status === 401) {
    wipe();
    location.replace("/");
    throw new Error("Session expired. Sign in again.");
  }
  let result;
  if (blob && response.ok) {
    result = await response.blob();
  } else {
    result = await response.json();
    if (!response.ok || !result.ok) {
      if (current === generation && action === "leds" && result.leds) renderLEDs(result.leds);
      throw new Error(result.error?.message || "Device request failed.");
    }
  }
  if (current !== generation) throw new DOMException("Discarded stale response", "AbortError");
  return result;
}

function chart(id, series) {
  const canvas = byId(id), ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const maximum = id === "cpu-chart" ? 100 : Math.max(1, ...series.flatMap(s => s.values));
  for (const {values, color} of series) {
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
    values.forEach((value, index) => {
      const x = index * canvas.width / 29;
      const y = canvas.height - 4 - value / maximum * (canvas.height - 8);
      if (index) ctx.lineTo(x, y); else ctx.moveTo(x, y);
    });
    ctx.stroke();
  }
}
function appendHistory(history, value) {
  if (value !== null) history.push(value);
  if (history.length > 30) history.shift();
}

function drawCharts() {
  const colors = getComputedStyle(document.documentElement);
  const rx = colors.getPropertyValue("--chart-rx").trim();
  const tx = colors.getPropertyValue("--chart-tx").trim();
  chart("cpu-chart", [{values: cpuHistory, color: rx}]);
  chart("net-chart", [{values: rxHistory, color: rx}, {values: txHistory, color: tx}]);
}
function renderLEDs(state) {
  ledState = state;
  text("led-state", state);
  const toggle = byId("led-toggle");
  toggle.dataset.state = state;
  toggle.dataset.unavailable = String(state === "unavailable");
  toggle.setAttribute("aria-checked", String(state === "enabled"));
  toggle.disabled = busy || state === "unavailable";
  text("led-help", state === "mixed" ? "Mixed trigger configuration. Toggle to enable all LEDs." :
    state === "unavailable" ? "LED controls are unavailable on this device." :
    state === "enabled" ? "All LED triggers enabled." : "All LEDs disabled.");
}

function renderStatus(data) {
  const m = data.metrics, s = data.settings;
  const delta = previous ? m.cpu.total - previous.cpu.total : 0;
  const cpu = delta > 0 ? Math.max(0, Math.min(100, 100 * (1 - (m.cpu.idle - previous.cpu.idle) / delta))) : null;
  const elapsed = previous ? m.uptime - previous.uptime : 0;
  const rates = {};
  for (const name of ["eth0", "wg0"]) {
    const current = m.networks[name], before = previous?.networks[name];
    rates[name] = elapsed > 0 && current && before && current.rx >= before.rx && current.tx >= before.tx
      ? {rx: (current.rx - before.rx) / elapsed, tx: (current.tx - before.tx) / elapsed} : null;
  }
  text("vpn-state", data.running ? "Running" : "Stopped");
  text("vpn-detail", `${data.interface} / ${data.address ?? "no live IPv4 address"} / UDP ${data.listen_port} / ${s.pivpnHOST}:${s.pivpnPORT}`);
  const seconds = Math.floor(m.uptime);
  text("uptime", `${Math.floor(seconds / 86400)}d ${Math.floor(seconds / 3600) % 24}h ${Math.floor(seconds / 60) % 60}m`);
  const used = m.memory.available === null ? null : m.memory.total - m.memory.available;
  text("cpu", cpu === null ? "Sampling..." : cpu.toFixed(1) + "%");
  text("load", "Load (1 / 5 / 15 min): " + m.load.map(x => x.toFixed(2)).join(" / "));
  text("memory", `${bytes(used)} / ${bytes(m.memory.total)}`);
  text("swap", `Swap: ${bytes(m.memory.swap_total - m.memory.swap_free)} / ${bytes(m.memory.swap_total)}`);
  text("temperature", m.temperatures.length ? m.temperatures.map(t =>
    t.name + ": " + (t.celsius === null ? "Unavailable" : t.celsius.toFixed(1) + " C")).join(" / ") : "Unavailable");
  text("network", ["eth0", "wg0"].map(name => name + ": " + (rates[name] ?
    `RX ${bytes(rates[name].rx)}/s / TX ${bytes(rates[name].tx)}/s` : "Unavailable / sampling")).join(" | "));
  text("glance", `CPU ${cpu === null ? "sampling" : cpu.toFixed(1) + "%"} / RAM ${bytes(used)} of ${bytes(m.memory.total)} / LEDs ${data.leds}`);
  renderLEDs(data.leds);
  byId("storage").replaceChildren(...m.storage.map(disk => {
    const p = document.createElement("p");
    p.textContent = `${disk.path}: ${bytes(disk.used)} / ${bytes(disk.total)} (${bytes(disk.free)} free)`;
    return p;
  }));
  const labels = {pivpnHOST: "Endpoint host", pivpnPORT: "Listen port", pivpnNET: "Tunnel network",
    subnetClass: "Prefix length", pivpnDNS1: "Primary DNS", pivpnDNS2: "Secondary DNS",
    pivpnMTU: "MTU", ALLOWED_IPS: "Client AllowedIPs"};
  byId("settings").replaceChildren(...Object.entries(labels).flatMap(([key, label]) => {
    const term = document.createElement("dt"), detail = document.createElement("dd");
    term.textContent = label; detail.textContent = s[key] ?? "Unavailable";
    return [term, detail];
  }));
  appendHistory(cpuHistory, cpu);
  appendHistory(rxHistory, rates.eth0?.rx ?? null);
  appendHistory(txHistory, rates.eth0?.tx ?? null);
  drawCharts();
  previous = m;
}

function cell(row, value, detail) {
  const td = row.insertCell();
  td.textContent = value;
  if (detail) { const small = document.createElement("small"); small.textContent = detail; td.append(small); }
  return td;
}
function button(container, label, handler, danger = false) {
  const element = document.createElement("button");
  element.textContent = label;
  element.className = danger ? "danger" : "secondary";
  element.addEventListener("click", handler);
  container.append(element);
  return element;
}
function icon(name) {
  const shapes = {
    user: ["M20 21a8 8 0 0 0-16 0", "M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0"],
    download: ["M12 3v12m-5-5 5 5 5-5", "M4 16v5h16v-5"],
    remove: ["M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"],
    qr: ["M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3z",
      "M15 15h2v2h-2zM19 13h2v4M13 21h4v-2m4 0v2h-2M13 11v2h-2M3 12h4"]
  };
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  for (const [key, value] of Object.entries({viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
    "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true"})) {
    svg.setAttribute(key, value);
  }
  for (const shape of shapes[name]) {
    const path = document.createElementNS(svg.namespaceURI, "path");
    path.setAttribute("d", shape);
    svg.append(path);
  }
  return svg;
}
function iconButton(container, label, symbol, handler, danger = false) {
  const element = button(container, label, handler, danger);
  element.classList.add("icon-button");
  element.setAttribute("aria-label", label);
  element.title = label;
  element.replaceChildren(icon(symbol));
}
function since(epoch) {
  if (!epoch) return "No handshake";
  const seconds = Math.floor(Date.now() / 1000 - epoch);
  if (seconds < 0) return "Handshake time approximate";
  if (seconds < 60) return "Handshake just now";
  if (seconds < 3600) return `Handshake ${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `Handshake ${Math.floor(seconds / 3600)}h ago`;
  return `Handshake ${Math.floor(seconds / 86400)}d ago`;
}
function renderClients(data) {
  text("recent", String(data.clients.filter(client => client.recent).length));
  const now = performance.now();
  const elapsed = clientSnapshot ? (now - clientSnapshot.time) / 1000 : 0;
  const expanded = new Set([...byId("client-rows").querySelectorAll("details[open]")].map(item => item.dataset.name));
  const rows = data.clients.map(client => {
    const row = document.createElement("li");
    row.className = "client-row";
    const avatar = document.createElement("span");
    avatar.className = "client-avatar";
    avatar.setAttribute("aria-hidden", "true");
    avatar.append(icon("user"));
    const dot = document.createElement("span");
    dot.className = client.enabled && client.recent ? "peer-dot recent" : "peer-dot";
    avatar.append(dot);
    const info = document.createElement("div");
    info.className = "client-info";
    const name = document.createElement("h4");
    name.className = "client-name";
    name.textContent = client.name;
    const meta = document.createElement("div");
    meta.className = "client-meta";
    const before = clientSnapshot?.clients.get(client.name);
    const ratesAvailable = data.running && client.enabled && elapsed > 0 && before &&
      client.rx !== null && client.tx !== null && before.rx !== null && before.tx !== null &&
      client.rx >= before.rx && client.tx >= before.tx;
    const traffic = ratesAvailable ? `RX ${bytes((client.rx - before.rx) / elapsed)}/s / TX ${bytes((client.tx - before.tx) / elapsed)}/s` :
      data.running && client.enabled ? "Traffic sampling / unavailable" : "Live traffic unavailable";
    for (const value of [client.ip, traffic, client.enabled ? since(client.handshake) : "Disabled",
      !data.running ? "wg0 stopped" : client.recent ? "Recent handshake" : "No recent handshake"]) {
      const span = document.createElement("span");
      span.textContent = value;
      meta.append(span);
    }
    const details = document.createElement("details");
    details.className = "client-details";
    details.dataset.name = client.name;
    details.open = expanded.has(client.name);
    const summary = document.createElement("summary");
    summary.textContent = "Details";
    const description = document.createElement("p");
    description.textContent = `Created: ${when(client.created)} / Handshake: ${when(client.handshake)} / Endpoint: ${client.endpoint || "Unavailable"} / Total RX ${bytes(client.rx)} / TX ${bytes(client.tx)}`;
    details.append(summary, description);
    info.append(name, meta, details);
    const actions = document.createElement("div");
    actions.className = "client-actions";
    const toggle = button(actions, "", () => {
      if (client.enabled && !confirm(`Disable ${client.name}? This revokes VPN traffic but keeps its profile.`)) return;
      act(() => request(client.enabled ? "client-disable" : "client-enable", {name: client.name}));
    });
    toggle.className = "toggle";
    toggle.setAttribute("role", "switch");
    toggle.setAttribute("aria-checked", String(client.enabled));
    toggle.setAttribute("aria-label", "Enable client " + client.name);
    toggle.title = client.enabled ? "Disable " + client.name : "Enable " + client.name;
    const thumb = document.createElement("span");
    thumb.className = "toggle-thumb";
    toggle.append(thumb);
    iconButton(actions, "Show QR for " + client.name, "qr", () => act(async () => {
      closeQR();
      const blob = await request("client-qr?name=" + encodeURIComponent(client.name), undefined, true);
      qrURL = URL.createObjectURL(blob);
      byId("qr-image").src = qrURL;
      byId("qr-dialog").showModal();
    }));
    iconButton(actions, "Download profile for " + client.name, "download", () => {
      if (confirm("This profile is a credential. Anyone holding it can use this VPN identity. Download?")) {
        act(() => download("client-config?name=" + encodeURIComponent(client.name), client.name + ".conf"));
      }
    });
    iconButton(actions, "Remove client " + client.name, "remove", () => {
      if (!confirm(`Permanently remove ${client.name}? Stored profile and keys will be deleted. A new identity is needed to reconnect.`)) return;
      act(() => request("client-remove", {name: client.name}));
    }, true);
    for (const element of actions.querySelectorAll("button")) element.disabled = busy;
    row.append(avatar, info, actions);
    return row;
  });
  clientSnapshot = {time: now, clients: new Map(data.clients.map(client => [client.name, client]))};
  byId("client-rows").replaceChildren(...rows);
  if (!rows.length) {
    const row = document.createElement("li");
    row.className = "empty-clients";
    row.textContent = "No configured clients.";
    byId("client-rows").append(row);
  }
}
function renderBackups(data) {
  const rows = data.backups.map(backup => {
    const row = document.createElement("tr");
    cell(row, backup.file); cell(row, bytes(backup.size)); cell(row, when(backup.modified));
    const actions = row.insertCell();
    button(actions, "Download", () => {
      if (confirm("This unencrypted archive contains VPN private keys. Download to a trusted device?")) {
        act(() => download("backup-download?file=" + encodeURIComponent(backup.file), backup.file));
      }
    });
    button(actions, "Restore", () => {
      if (!confirm(`Restore ${backup.file}? This replaces VPN keys, clients and settings and restarts wg0. Keep an off-device backup first. Continue?`)) return;
      act(() => request("restore", {file: backup.file}));
    }, true);
    button(actions, "Delete", () => {
      if (!confirm(`Permanently delete ${backup.file}? This cannot be undone. Download a copy first if you may need it.`)) return;
      act(() => request("backup-delete", {file: backup.file}));
    }, true);
    return row;
  });
  byId("backup-rows").replaceChildren(...rows);
  if (!rows.length) {
    const row = document.createElement("tr");
    cell(row, "No backups yet.").colSpan = 4;
    byId("backup-rows").append(row);
  }
}
async function download(route, name) {
  const blob = await request(route, undefined, true), url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = name;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function refresh() {
  renderStatus(await request("status"));
  if (page === "clients" || page === "dashboard") renderClients(await request("clients"));
  if (page === "backups") renderBackups(await request("backups"));
  if (enabled) byId("protected").hidden = false;
}
function setBusy(value) {
  busy = value;
  document.querySelectorAll("#protected button:not(#theme-toggle), #add-dialog button").forEach(element => {
    element.disabled = value || element.dataset.unavailable === "true";
  });
  if (!value && pendingPage && enabled) {
    pendingPage = false;
    poll();
  }
}
async function act(action) {
  if (busy || !enabled) return;
  setBusy(true);
  text("message", "Working...");
  try {
    const result = await action();
    text("message", result?.live === false ? "Saved. Changes are not live until WireGuard starts." : "Done.");
    await refresh();
  } catch (error) {
    if (error.name !== "AbortError") text("message", error.message);
  } finally {
    setBusy(false);
  }
}
async function poll() {
  if (busy || !enabled || document.hidden) return;
  setBusy(true);
  try { await refresh(); text("message", ""); }
  catch (error) { if (error.name !== "AbortError") text("message", error.message); }
  finally { setBusy(false); }
}

document.querySelectorAll("[data-page]").forEach(element => element.addEventListener("click", () => {
  if (!enabled) return;
  page = element.dataset.page;
  for (const section of document.querySelectorAll(".page")) section.hidden = section.id !== page;
  for (const item of document.querySelectorAll("[data-page]")) item.removeAttribute("aria-current");
  element.setAttribute("aria-current", "page");
  text("page-title", element.textContent);
  if (busy) pendingPage = true; else poll();
}));
byId("add-client").addEventListener("submit", event => {
  event.preventDefault();
  act(async () => {
    const result = await request("client-add", {name: byId("client-name").value});
    byId("add-client").reset();
    byId("add-dialog").close();
    return result;
  });
});
byId("led-toggle").addEventListener("click", () => act(() => request("leds", {enabled: ledState === "enabled" ? "0" : "1"})));
document.addEventListener("themechange", drawCharts);
byId("new-client").addEventListener("click", () => {
  byId("add-dialog").showModal();
  byId("client-name").focus();
});
byId("cancel-add").addEventListener("click", () => byId("add-dialog").close());
byId("create-backup").addEventListener("click", () => act(() => request("backup-create", {})));
byId("upload-backup").addEventListener("submit", event => {
  event.preventDefault();
  const file = byId("backup-file").files[0];
  if (!file || file.size === 0 || file.size > 16 * 1024 * 1024) {
    text("message", "Choose a non-empty .tgz file no larger than 16 MiB."); return;
  }
  if (!/^pivpnbackup-[0-9]{8}-[0-9]{6}(?:-[1-9][0-9]*)?\.tgz$/.test(file.name)) {
    text("message", "Use the original pivpnbackup-YYYYMMDD-HHMMSS.tgz filename, with an optional numeric suffix."); return;
  }
  act(async () => {
    const result = await request("backup-upload", file, false, true);
    byId("upload-backup").reset();
    return result;
  });
});
byId("close-qr").addEventListener("click", closeQR);
byId("qr-dialog").addEventListener("cancel", event => { event.preventDefault(); closeQR(); });
byId("logout").addEventListener("click", async () => {
  wipe();
  text("message", "Signing out...");
  try {
    await request("logout", {});
    location.replace("/");
  } catch (error) {
    if (error.name !== "AbortError") text("message", "Server-side logout is unconfirmed: " + error.message + " Use Log out to retry.");
  }
});
window.addEventListener("pagehide", wipe);
window.addEventListener("pageshow", event => {
  if (event.persisted) { wipe(); location.reload(); }
});
document.addEventListener("visibilitychange", () => {
  previous = null;
  clientSnapshot = null;
  if (!document.hidden) poll();
});
setInterval(poll, 10000);
poll();
