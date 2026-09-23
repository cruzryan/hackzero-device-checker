import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { enable as enableAutostart } from "@tauri-apps/plugin-autostart";
import {
  REQUIREMENTS,
  summarize,
  describeDelivery,
  formatCheckedAt,
  diagnosticsSections,
  diagnosticsText,
  platformName,
  clean
} from "./copy.js";

// Fixed first-party documentation only. A checker report never provides a URL.
const remediation = {
  windows: {
    disk_encryption: "https://support.microsoft.com/en-au/windows/device-encryption-in-windows-cf7e2b6f-3e70-4882-9532-18633605b7df",
    screen_lock: "https://support.microsoft.com/en-us/windows/configure-a-screen-saver-in-windows-a9dc2a0c-dc8e-9161-d270-aaccc252082a",
    automatic_updates: "https://support.microsoft.com/en-us/windows/install-windows-updates-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a",
    endpoint_protection: "https://support.microsoft.com/windows/stay-protected-with-the-windows-security-app-2ae0363d-0ada-c064-8b56-6a39afb6a963"
  },
  darwin: {
    disk_encryption: "https://support.apple.com/en-ie/guide/mac-help/-mh11785/mac",
    screen_lock: "https://support.apple.com/en-ie/guide/mac-help/mchlp2270/mac",
    automatic_updates: "https://support.apple.com/en-lamr/guide/mac-help/mchla7037245/mac",
    endpoint_protection: "https://support.apple.com/en-ie/guide/security/sec469d47bd8/web"
  },
  linux: {
    disk_encryption: "https://documentation.ubuntu.com/desktop/en/latest/explanation/hardware-backed-disk-encryption/",
    screen_lock: "https://help.ubuntu.com/stable/ubuntu-help/session-screenlocks.html.en",
    automatic_updates: "https://documentation.ubuntu.com/security/security-updates/",
    endpoint_protection: "https://documentation.ubuntu.com/security/security-features/security-features-overview/"
  }
};

const UPDATE_CHECK_EVERY = 6 * 60 * 60 * 1000;
const $ = (selector) => document.querySelector(selector);
const shell = $(".app-shell");

let currentResult = null;
let currentPlatform = "";
let connection = null;
let checkInFlight = false;
// When a manual check fails, the page shows the failure until a NEWER result
// exists. An older saved report must not quietly bring back a green state.
let lastFailureAt = 0;
let availableUpdate = null;
let installingUpdate = false;
let lastUpdateCheck = 0;

// ------------------------------------------------------------------ DOM helpers

// Every string from the collector or server is inserted as text, never HTML.
function el(tag, { className, text, attrs } = {}, children = []) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  if (attrs) for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  for (const child of children) if (child) node.append(child);
  return node;
}

function errorText(error) {
  let text = "";
  if (typeof error === "string") text = clean(error);
  else if (error && typeof error.message === "string") text = clean(error.message);
  if (!text) return "Something went wrong.";
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

const timeOnly = (date) => new Intl.DateTimeFormat(undefined, { timeStyle: "short" }).format(date);
function friendlyTime(date) {
  const today = new Date();
  const sameDay = date.toDateString() === today.toDateString();
  return sameDay ? timeOnly(date) : new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(date);
}

// ------------------------------------------------------------------ rendering

const INDICATOR = { pass: "✓", fail: "!", unknown: "?", missing: "?" };

function requirementPanel(key) {
  const rules = REQUIREMENTS[key];
  if (!rules) return null;
  const panelId = `requirements-${key}`;
  const toggle = el("button", { className: "details-toggle", text: "What we check ", attrs: { type: "button", "data-details": panelId, "aria-expanded": "false", "aria-controls": panelId } }, [
    el("span", { text: "?", attrs: { "aria-hidden": "true" } })
  ]);
  const panel = el("div", { className: "requirements-panel", attrs: { id: panelId } }, [
    el("strong", { text: "To pass, this device must have:" }),
    el("ul", {}, rules.map((rule) => el("li", { text: rule })))
  ]);
  panel.hidden = true;
  return [toggle, panel];
}

function renderRow(row, platform) {
  const guide = row.state === "fail" ? remediation[platform]?.[row.key] : null;
  const lines = el("ul", { className: "detail-lines" }, row.lines.map((line) => el("li", { className: `line ${line.tone}`, text: line.text })));
  const result = el("div", { className: "result" }, [lines]);
  if (guide) {
    result.append(el("button", { className: "fix-link", text: `How to fix this on ${platformName(platform)} →`, attrs: { type: "button", "data-remediation": row.key } }));
  }
  const panel = requirementPanel(row.key);
  if (panel) result.append(...panel);
  return el("article", { className: `finding ${row.state}`, attrs: { "data-key": row.key } }, [
    el("div", { className: "finding-title" }, [
      el("span", { className: "indicator", text: INDICATOR[row.state] || "?", attrs: { "aria-hidden": "true" } }),
      el("strong", { text: row.label }),
      el("span", { className: "status-pill", text: row.pill })
    ]),
    result
  ]);
}

function renderDashboard(server) {
  const target = $("#dashboardVerdict");
  target.replaceChildren();
  if (!server || (!server.status && !server.problems.length && !server.warnings.length)) {
    target.hidden = true;
    return;
  }
  target.hidden = false;
  target.className = `dashboard-verdict ${server.status === "fail" || server.problems.length ? "fail" : server.warnings.length ? "warn" : "pass"}`;
  target.append(el("h2", { text: "What your dashboard shows" }));
  if (!server.problems.length && !server.warnings.length) {
    target.append(el("p", { text: server.status === "fail" ? "Your dashboard shows this device as failing." : "Your dashboard shows this device as passing." }));
    return;
  }
  const list = el("ul", { className: "detail-lines" });
  server.problems.forEach((text) => list.append(el("li", { className: "line fail", text })));
  server.warnings.forEach((text) => list.append(el("li", { className: "line warn", text })));
  target.append(list);
}

function setTone(tone) {
  shell.classList.toggle("needs-attention", tone === "attention" || tone === "failed");
  shell.classList.toggle("needs-verification", tone === "verify");
  shell.classList.toggle("protected", tone === "protected");
}

function renderResult(result) {
  currentResult = result;
  const summary = summarize(result);
  currentPlatform = summary.platform;
  setTone(summary.tone);
  $("#headline").textContent = summary.headline;
  $("#description").textContent = summary.description;
  $("#summaryStatus").textContent = summary.summaryStatus;
  $("#summaryDetail").textContent = summary.summaryDetail;
  $("#checkedAt").textContent = formatCheckedAt(result);
  const delivery = describeDelivery(result, { formatTime: friendlyTime });
  const note = $("#deliveryNote");
  note.hidden = !delivery;
  note.className = `delivery-note ${delivery?.tone || ""}`;
  note.textContent = delivery?.text || "";
  $("#posture").replaceChildren(...summary.rows.map((row) => renderRow(row, summary.platform)));
  renderDashboard(summary.server);
}

// A failed check clears every trace of the previous result: headline, rows,
// classes, time and delivery. Nothing green survives a failure.
function renderCheckFailure(message) {
  currentResult = null;
  lastFailureAt = Date.now();
  setTone("failed");
  $("#headline").textContent = "Could not check this device";
  $("#description").textContent = message;
  $("#summaryStatus").textContent = "Check failed";
  $("#summaryDetail").textContent = "No result to show";
  $("#checkedAt").textContent = `Check failed at ${timeOnly(new Date())}`;
  const note = $("#deliveryNote");
  note.hidden = false;
  note.className = "delivery-note fail";
  note.textContent = "Nothing was sent to HackZero from this check. Try again in a moment.";
  $("#posture").replaceChildren();
  renderDashboard(null);
}

function renderConnection(value) {
  connection = value;
  shell.classList.toggle("unpaired", !value?.paired);
  const action = $("#connectHackZero");
  const title = $("#connectionTitle");
  const description = $("#connectionDescription");
  const disconnect = $("#disconnectHackZero");
  const uninstall = $("#uninstallDeviceChecker");
  if (value?.paired) {
    const identity = clean(value.person_name, 80) || "Connected device";
    const workspace = clean(value.workspace_name, 80);
    action.replaceChildren(workspace ? `${identity} · ${workspace}` : identity);
    action.disabled = true;
    title.textContent = "This device is connected";
    description.textContent = `${identity} is sending read-only posture checks to ${workspace || "your workspace"}.`;
    disconnect.hidden = false;
    uninstall.hidden = false;
  } else {
    action.replaceChildren("Connect device ", el("b", { text: "→" }));
    action.disabled = false;
    title.textContent = "Connect this device to HackZero";
    description.textContent = "Sign in to send this device's read-only posture record to your workspace.";
    disconnect.hidden = true;
    uninstall.hidden = true;
  }
}

function setLaunchState({ title, description, failed = false, visible = true }) {
  const screen = $("#launchScreen");
  screen.hidden = !visible;
  $("#launchTitle").textContent = title;
  $("#launchDescription").textContent = description;
  $("#launchRetry").hidden = !failed;
  screen.classList.toggle("failed", failed);
}

// ------------------------------------------------------------------ checks

async function loadConnection() {
  try {
    renderConnection(await invoke("connection_status"));
    return true;
  } catch (error) {
    console.error("Device Checker connection status failed", error);
    if (!connection) {
      renderConnection({ paired: false });
      $("#connectionDescription").textContent = "We couldn't read whether this device is connected. Close and reopen Device Checker, or connect again.";
    }
    return false;
  }
}

async function refresh({ initial = false } = {}) {
  if (checkInFlight) return;
  checkInFlight = true;
  const button = $("#checkAgain");
  if (initial) setLaunchState({ title: "Loading HackZero Device Checker", description: "This might take a moment." });
  button.disabled = true;
  button.textContent = "Checking…";
  try {
    const result = await invoke("check_now");
    if (!result || typeof result !== "object" || typeof result.report !== "object" || result.report === null) {
      throw new Error("Device Checker returned an unreadable result.");
    }
    lastFailureAt = 0;
    renderResult(result);
    if (initial) setLaunchState({ visible: false, title: "", description: "" });
  } catch (error) {
    console.error("Device Checker check failed", error);
    renderCheckFailure(`We couldn't run the check: ${errorText(error)} Try again, or open Diagnostics.`);
    if (initial && !connection?.paired) {
      setLaunchState({
        title: "Something went wrong",
        description: "We could not start the local device check. Try again, or close and reopen Device Checker.",
        failed: true
      });
    } else if (initial) {
      // Connected: show the failure in the main window, where Check again and
      // Diagnostics are available.
      setLaunchState({ visible: false, title: "", description: "" });
    }
  } finally {
    checkInFlight = false;
    button.disabled = false;
    button.textContent = "Check again";
  }
}

// Reloads the last saved result (written by a manual or background check).
async function reloadFromLast() {
  if (checkInFlight) return;
  await loadConnection();
  if (!connection?.paired) return;
  try {
    const last = await invoke("last_report");
    if (checkInFlight || !last || last.available === false || typeof last.report !== "object" || last.report === null) return;
    const savedAt = Date.parse(last.checked_at);
    if (lastFailureAt && !(savedAt > lastFailureAt)) return;
    if (currentResult && Date.parse(currentResult.checked_at) > savedAt) return;
    lastFailureAt = 0;
    renderResult(last);
  } catch (error) {
    console.error("Device Checker could not load the last report", error);
  }
}

let reloadTimer = null;
function scheduleReload() {
  window.clearTimeout(reloadTimer);
  reloadTimer = window.setTimeout(reloadFromLast, 250);
}

// ------------------------------------------------------------------ updates

async function checkForUpdate({ quiet = false } = {}) {
  if (installingUpdate) return;
  const target = $("#updateState");
  const install = $("#installUpdate");
  lastUpdateCheck = Date.now();
  if (!quiet) {
    install.disabled = true;
    install.textContent = "Checking for updates…";
    target.textContent = "Checking for updates…";
  }
  try {
    const found = await check();
    if (installingUpdate) return;
    availableUpdate = found;
    if (!found) {
      target.textContent = "Up to date";
      install.textContent = "Check for updates";
      return;
    }
    target.textContent = `Version ${clean(found.version, 40)} is ready to install.`;
    install.textContent = `Install v${clean(found.version, 40)}`;
  } catch (error) {
    // An update-server outage is never a failed security setting.
    console.error("Device Checker update check failed", error);
    if (!quiet || !availableUpdate) {
      availableUpdate = null;
      target.textContent = "Update status unavailable";
      install.textContent = "Check for updates";
    }
  } finally {
    if (!installingUpdate) install.disabled = false;
  }
}

async function updateAction() {
  const install = $("#installUpdate");
  // Installing is only possible after this process itself found a signed release.
  if (!availableUpdate) {
    await checkForUpdate();
    return;
  }
  installingUpdate = true;
  install.disabled = true;
  install.textContent = "Downloading…";
  try {
    await availableUpdate.downloadAndInstall();
    install.textContent = "Restarting…";
    await relaunch();
  } catch (error) {
    console.error("Device Checker update install failed", error);
    installingUpdate = false;
    install.disabled = false;
    install.textContent = `Install v${clean(availableUpdate.version, 40)}`;
    $("#updateState").textContent = "The signed update could not be installed.";
  }
}

// ------------------------------------------------------------------ modals

let modalOpener = null;

function focusables(dialog) {
  return [...dialog.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])")]
    .filter((node) => !node.disabled && !node.hidden && node.offsetParent !== null);
}

function openModal(dialog) {
  modalOpener = document.activeElement;
  if (!dialog.open) dialog.showModal();
  const first = focusables(dialog)[0];
  first?.focus();
}

function closeModal(dialog) {
  if (dialog.dataset.locked === "true") return;
  if (dialog.open) dialog.close();
  if (modalOpener && typeof modalOpener.focus === "function") modalOpener.focus();
  modalOpener = null;
}

function wireModal(dialog) {
  // Esc: the native cancel event. Honour a locked (busy) dialog.
  dialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    closeModal(dialog);
  });
  // Click outside the card (on the backdrop) closes.
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) closeModal(dialog);
    if (event.target.closest("[data-close]")) closeModal(dialog);
  });
  // Keep Tab focus inside the dialog.
  dialog.addEventListener("keydown", (event) => {
    if (event.key !== "Tab") return;
    const items = focusables(dialog);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
}

// ------------------------------------------------------------------ diagnostics

let diagnosticsPlain = "";

function renderDiagnostics(sections) {
  const body = $("#diagnosticsBody");
  body.replaceChildren(...sections.map((section) => el("section", { className: "diag-section" }, [
    el("h3", { text: section.title }),
    el("table", {}, [
      el("tbody", {}, section.rows.map(([key, value]) => el("tr", {}, [el("th", { text: key, attrs: { scope: "row" } }), el("td", { text: value })])))
    ])
  ])));
}

async function openDiagnostics() {
  const dialog = $("#diagnosticsDialog");
  $("#diagnosticsStatus").textContent = "";
  $("#diagnosticsBody").replaceChildren(el("p", { className: "modal-loading", text: "Reading diagnostics…" }));
  openModal(dialog);
  const [version, diag] = await Promise.allSettled([getVersion(), invoke("diagnose")]);
  const sections = diagnosticsSections(diag.status === "fulfilled" ? diag.value : null, {
    appVersion: version.status === "fulfilled" ? version.value : "unknown",
    error: diag.status === "rejected" ? errorText(diag.reason) : undefined,
    fallbackLast: currentResult,
    connection
  });
  diagnosticsPlain = diagnosticsText(sections);
  renderDiagnostics(sections);
}

async function copyDiagnostics() {
  const status = $("#diagnosticsStatus");
  try {
    await navigator.clipboard.writeText(diagnosticsPlain);
    status.textContent = "Copied";
  } catch {
    const area = el("textarea", { attrs: { "aria-hidden": "true" } });
    area.value = diagnosticsPlain;
    area.style.position = "fixed";
    area.style.opacity = "0";
    $("#diagnosticsDialog").append(area);
    area.select();
    const copied = document.execCommand("copy");
    area.remove();
    status.textContent = copied ? "Copied" : "Couldn't copy. Select the text and copy it.";
  }
}

// ------------------------------------------------------------------ uninstall

function uninstallState({ title, paragraphs = [], actions = [], locked = false, closable = true }) {
  const dialog = $("#uninstallDialog");
  dialog.dataset.locked = locked || !closable ? "true" : "false";
  $("#uninstallTitle").textContent = title;
  $("#uninstallClose").hidden = locked || !closable;
  $("#uninstallBody").replaceChildren(...paragraphs.map((text) => (typeof text === "string" ? el("p", { text }) : text)));
  $("#uninstallActions").replaceChildren(...actions);
  const first = focusables(dialog).find((node) => node.closest("#uninstallActions"));
  first?.focus();
}

function actionButton(text, onClick, className = "secondary-action") {
  const button = el("button", { className, text, attrs: { type: "button" } });
  button.addEventListener("click", onClick);
  return button;
}

function showUninstallConfirm(errorMessage) {
  const paragraphs = [
    "This disconnects this computer from HackZero, stops Device Checker from starting when you sign in, and deletes its saved data on this computer.",
    "Then we'll show you how to remove the app itself."
  ];
  if (errorMessage) paragraphs.push(el("p", { className: "modal-error", text: errorMessage }));
  uninstallState({
    title: "Disconnect and uninstall?",
    paragraphs,
    actions: [
      actionButton("Cancel", () => closeModal($("#uninstallDialog"))),
      actionButton("Disconnect and uninstall", runUninstall, "check-action plain danger")
    ]
  });
}

async function quitApp() {
  try {
    await invoke("quit_app");
  } catch (error) {
    console.error("Device Checker could not quit", error);
  }
}

function showUninstallDone(outcome) {
  const platform = outcome?.platform;
  const paragraphs = ["This computer is disconnected and Device Checker will no longer start when you sign in."];
  if (outcome?.local_data_removed === false && outcome?.local_data_path) {
    paragraphs.push(el("p", { className: "modal-error", text: `Some saved files couldn't be removed. You can delete this folder: ${clean(outcome.local_data_path)}` }));
  }
  const actions = [];
  if (platform === "macos") {
    paragraphs.push("To finish, drag HackZero Device Checker from Applications to the Trash.");
    actions.push(actionButton("Quit", quitApp));
    actions.push(actionButton("Show in Finder and quit", async () => {
      try { await invoke("open_uninstall_location"); } catch (error) { console.error(error); }
      await quitApp();
    }, "check-action plain"));
  } else if (platform === "windows") {
    paragraphs.push("To finish, open Settings > Apps > Installed apps, find HackZero Device Checker, and choose Uninstall.");
    actions.push(actionButton("Quit", quitApp));
    actions.push(actionButton("Open Installed apps and quit", async () => {
      try { await invoke("open_uninstall_location"); } catch (error) { console.error(error); }
      await quitApp();
    }, "check-action plain"));
  } else {
    paragraphs.push("To finish, remove HackZero Device Checker with your package manager (for example, Ubuntu Software or apt), or delete the AppImage file.");
    actions.push(actionButton("Quit", quitApp, "check-action plain"));
  }
  uninstallState({ title: "Almost done", paragraphs, actions, closable: false });
}

async function runUninstall() {
  uninstallState({ title: "Disconnecting…", paragraphs: ["Removing this computer from HackZero. This takes a few seconds."], locked: true });
  try {
    const outcome = await invoke("uninstall_device_checker");
    renderConnection({ paired: false });
    showUninstallDone(outcome);
  } catch (error) {
    console.error("Device Checker uninstall failed", error);
    $("#uninstallDialog").dataset.locked = "false";
    showUninstallConfirm(`We couldn't disconnect this computer: ${errorText(error)} Check your connection and try again. Nothing was removed.`);
  }
}

// ------------------------------------------------------------------ wiring

$("#checkAgain").addEventListener("click", () => refresh());
$("#posture").addEventListener("click", (event) => {
  const details = event.target.closest("[data-details]");
  if (details) {
    const panel = document.getElementById(details.dataset.details);
    if (panel) {
      const expanded = details.getAttribute("aria-expanded") === "true";
      details.setAttribute("aria-expanded", String(!expanded));
      panel.hidden = expanded;
    }
    return;
  }
  const key = event.target.closest("[data-remediation]")?.dataset.remediation;
  const guide = key && remediation[currentPlatform]?.[key];
  if (guide) openUrl(guide);
});
$("#launchRetry").addEventListener("click", () => refresh({ initial: true }));
$("#installUpdate").addEventListener("click", updateAction);
$("#openDiagnostics").addEventListener("click", openDiagnostics);
$("#copyDiagnostics").addEventListener("click", copyDiagnostics);
$("#uninstallDeviceChecker").addEventListener("click", () => {
  showUninstallConfirm();
  openModal($("#uninstallDialog"));
});
$("#uninstallClose").addEventListener("click", () => closeModal($("#uninstallDialog")));
wireModal($("#diagnosticsDialog"));
wireModal($("#uninstallDialog"));

$("#connectHackZero").addEventListener("click", async () => {
  const button = $("#connectHackZero");
  const title = $("#connectionTitle");
  const description = $("#connectionDescription");
  button.disabled = true;
  button.replaceChildren("Waiting for approval ", el("b", { text: "•" }));
  title.textContent = "Continue in your browser";
  description.textContent = "A secure approval page is opening in your default browser. Approve this device there, then return here.";
  try {
    renderConnection(await invoke("connect_hackzero"));
  } catch (error) {
    console.error("Device Checker pairing failed", error);
    button.disabled = false;
    button.replaceChildren("Try again ", el("b", { text: "→" }));
    title.textContent = "Could not start sign in";
    // Never display a server response or internal error here. Those responses
    // can include proxy HTML and security details.
    description.textContent = "We couldn't open the secure approval page. Check your connection and try again.";
    return;
  }
  try {
    // Start at sign-in with the person's consent, only after this device is paired.
    await enableAutostart();
  } catch (error) {
    console.error("Device Checker could not enable start at sign-in", error);
  }
  // Send the first signed report right away.
  await refresh();
});

$("#disconnectHackZero").addEventListener("click", async () => {
  const button = $("#disconnectHackZero");
  if (!window.confirm("Disconnect this device from HackZero? It will stop sending posture checks.")) return;
  button.disabled = true;
  try {
    renderConnection(await invoke("disconnect_hackzero"));
  } catch (error) {
    // Never leave a click with no feedback.
    console.error("Device Checker disconnect failed", error);
    $("#connectionDescription").textContent = "We couldn't disconnect this device. Check your connection and try again.";
    $("#description").textContent = `We couldn't disconnect this device: ${errorText(error)} Check your connection and try again.`;
  } finally {
    button.disabled = false;
  }
});

// Background ticks run in the native process; reload what they saved.
listen("report-updated", scheduleReload);
listen("system-resumed", scheduleReload);
listen("window-shown", () => {
  scheduleReload();
  if (Date.now() - lastUpdateCheck > UPDATE_CHECK_EVERY) checkForUpdate({ quiet: true });
});
window.addEventListener("focus", scheduleReload);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") scheduleReload();
});
window.setInterval(() => checkForUpdate({ quiet: true }), UPDATE_CHECK_EVERY);

(async () => {
  checkForUpdate();
  await loadConnection();
  await refresh({ initial: true });
})();
