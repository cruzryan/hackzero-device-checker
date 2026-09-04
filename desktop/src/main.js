import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { enable as enableAutostart } from "@tauri-apps/plugin-autostart";

const labels = {
  disk_encryption: "Disk encryption",
  screen_lock: "Screen lock",
  automatic_updates: "Automatic updates",
  pending_updates: "Pending updates",
  endpoint_protection: "Endpoint protection"
};

function statusLabel(status) {
  return { pass: "Protected", fail: "Needs attention", needs_attention: "Needs attention", unknown: "Not available" }[status] || "Not available";
}

function render(report) {
  const findings = report.findings || [];
  const hasFailure = findings.some((finding) => finding.status === "fail");
  document.querySelector("#headline").textContent = hasFailure ? "This device needs attention" : "This device is protected";
  document.querySelector("#description").textContent = hasFailure
    ? "Fix the items below, then check again. We only read these settings; we never change them."
    : "These security settings are on. We only read them; we never change anything on your device.";
  const checkTime = new Date(report.checked_at);
  document.querySelector("#checkedAt").textContent = Number.isNaN(checkTime.valueOf())
    ? "Checked locally"
    : `Checked locally: ${new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(checkTime)}`;
  document.querySelector("#posture").innerHTML = findings.map((finding) => `
    <article class="finding ${finding.status}">
      <div><span class="indicator">${finding.status === "pass" ? "✓" : finding.status === "fail" ? "!" : "–"}</span><strong>${labels[finding.check] || finding.check}</strong></div>
      <div class="result"><span>${statusLabel(finding.status)}</span>${finding.reason ? `<small>${finding.reason.replaceAll("_", " ")}</small>` : ""}</div>
    </article>`).join("");
}

function renderConnection(connection) {
  const action = document.querySelector("#connectHackZero");
  const title = document.querySelector("#connectionTitle");
  const description = document.querySelector("#connectionDescription");
  if (connection?.paired) {
    const identity = connection.person_name || "Connected device";
    const workspace = connection.workspace_name ? ` · ${connection.workspace_name}` : "";
    action.textContent = `${identity}${workspace}`;
    action.disabled = true;
    title.textContent = "This device is connected";
    description.textContent = `${identity} is sending read-only posture checks to ${connection.workspace_name || "your workspace"}.`;
  } else {
    action.textContent = "Connect to HackZero";
    action.disabled = false;
    title.textContent = "Connect this device to HackZero";
    description.textContent = "Sign in to send this device's read-only posture record to your workspace.";
  }
}

let availableUpdate = null;

async function checkForUpdate() {
  const target = document.querySelector("#updateState");
  const install = document.querySelector("#installUpdate");
  target.textContent = "Checking for signed updates…";
  try {
    availableUpdate = await check();
    if (!availableUpdate) {
      target.textContent = "You’re on the latest signed release.";
      return;
    }
    target.textContent = `Version ${availableUpdate.version} is ready to install.`;
    install.hidden = false;
  } catch {
    // An update-server outage is never a failed security setting.
    target.textContent = "Couldn’t check for updates. Try again later.";
  }
}

async function installAvailableUpdate() {
  const install = document.querySelector("#installUpdate");
  if (!availableUpdate) return;
  install.disabled = true;
  install.textContent = "Downloading…";
  try {
    await availableUpdate.downloadAndInstall();
    install.textContent = "Restarting…";
    await relaunch();
  } catch {
    install.disabled = false;
    install.textContent = "Try update again";
    document.querySelector("#updateState").textContent = "The signed update could not be installed.";
  }
}

async function refresh() {
  const button = document.querySelector("#checkAgain");
  button.disabled = true;
  button.textContent = "Checking…";
  try { render(await invoke("check_now")); }
  catch { document.querySelector("#headline").textContent = "Could not check this device"; }
  finally { button.disabled = false; button.textContent = "Check again"; }
}

document.querySelector("#checkAgain").addEventListener("click", refresh);
document.querySelector("#openHackZero").addEventListener("click", () => openUrl("https://hackzero.ai"));
document.querySelector("#viewReleases").addEventListener("click", () => openUrl("https://github.com/cruzryan/hackzero-device-checker/releases"));
document.querySelector("#installUpdate").addEventListener("click", installAvailableUpdate);
document.querySelector("#connectHackZero").addEventListener("click", async () => {
  const button = document.querySelector("#connectHackZero");
  button.disabled = true;
  button.textContent = "Waiting for sign in…";
  try {
    renderConnection(await invoke("connect_hackzero"));
    // Start with the signed-in user's consent, only after this device is paired.
    await enableAutostart();
  }
  catch (error) { button.disabled = false; button.textContent = "Try connecting again"; }
});
Promise.all([
  refresh(),
  invoke("connection_status").then(renderConnection),
  checkForUpdate(),
]);
