"use strict";

const api = "/cgi-bin/vpn.cgi/";
const message = document.getElementById("message");
const form = document.getElementById("auth");
let setup = false;
const passwordInput = document.getElementById("password");
const confirmInput = document.getElementById("confirm");

function updatePasswordCriteria() {
  const password = passwordInput.value;
  const criteria = [
    ["password-length", password.length >= 8 && password.length <= 32],
    ["password-lowercase", /[a-z]/.test(password)],
    ["password-uppercase", /[A-Z]/.test(password)],
    ["password-number", /[0-9]/.test(password)]
  ];
  for (const [id, met] of criteria) {
    const item = document.getElementById(id);
    item.dataset.valid = String(met);
    item.textContent = item.textContent.split(":")[0] + ": " + (met ? "met" : "not met");
  }
}

function updatePasswordMatch() {
  const match = document.getElementById("password-match");
  match.dataset.match = !confirmInput.value
    ? ""
    : String(passwordInput.value === confirmInput.value);
  match.textContent = !confirmInput.value
    ? "Enter the password again to check whether it matches."
    : passwordInput.value === confirmInput.value
      ? "Passwords match."
      : "Passwords do not match.";
}

async function request(action, fields) {
  const response = await fetch(api + action, fields ? {
    method: "POST",
    credentials: "same-origin",
    headers: {"X-VPN-UI": "1", "Content-Type": "application/x-www-form-urlencoded"},
    body: new URLSearchParams(fields),
    cache: "no-store"
  } : {cache: "no-store", credentials: "same-origin"});
  const data = await response.json();
  if (!response.ok || !data.ok) throw new Error(data.error?.message || "Device request failed.");
  return data;
}

async function initialize() {
  try {
    setup = (await request("state")).setup;
    document.getElementById("title").textContent = setup ? "Set up web access" : "Sign in";
    document.getElementById("submit").textContent = setup ? "Set password" : "Sign in";
    for (const id of ["token-label", "setup-help", "confirm-label"]) {
      document.getElementById(id).hidden = !setup;
    }
    document.getElementById("password-criteria").hidden = !setup;
    passwordInput.autocomplete = setup ? "new-password" : "current-password";
    passwordInput.minLength = setup ? 8 : 0;
    passwordInput.maxLength = setup ? 32 : 128;
    confirmInput.maxLength = setup ? 32 : 128;
    confirmInput.required = setup;
    if (setup) {
      updatePasswordCriteria();
      updatePasswordMatch();
    }
    message.textContent = "";
    form.hidden = false;
  } catch (error) {
    message.textContent = error.message + " Reload to retry.";
  }
}

form.addEventListener("submit", async event => {
  event.preventDefault();
  const button = document.getElementById("submit");
  button.disabled = true;
  message.textContent = "Please wait...";
  try {
    const fields = {password: document.getElementById("password").value};
    if (setup) {
      fields.token = document.getElementById("token").value;
      fields.password_confirm = document.getElementById("confirm").value;
    }
    await request(setup ? "setup" : "login", fields);
    form.reset();
    if (setup) {
      await initialize();
      message.textContent = "Password saved. Sign in to continue.";
    } else {
      location.replace(api + "app");
    }
  } catch (error) {
    message.textContent = error.message;
    passwordInput.value = "";
    confirmInput.value = "";
    if (setup) {
      updatePasswordCriteria();
      updatePasswordMatch();
    }
  } finally {
    button.disabled = false;
  }
});

passwordInput.addEventListener("input", () => {
  if (setup) {
    updatePasswordCriteria();
    updatePasswordMatch();
  }
});
confirmInput.addEventListener("input", () => {
  if (setup) updatePasswordMatch();
});

window.addEventListener("pagehide", () => form.reset());
initialize();
