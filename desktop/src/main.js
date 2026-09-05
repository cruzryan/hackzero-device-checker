import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { enable as enableAutostart } from "@tauri-apps/plugin-autostart";

const labels = {
  disk_encryption: "Disk encryption",
  screen_lock: "Screen lock",
  automatic_updates: "Automatic updates",
  endpoint_protection: "Endpoint protection"
};

// Fixed first-party documentation only. A checker report never provides a URL.
const remediation = {
  windows: {
    disk_encryption: ["Turn on device encryption", "https://support.microsoft.com/en-au/windows/device-encryption-in-windows-cf7e2b6f-3e70-4882-9532-18633605b7df"],
    screen_lock: ["Set a screen lock", "https://support.microsoft.com/en-us/windows/configure-a-screen-saver-in-windows-a9dc2a0c-dc8e-9161-d270-aaccc252082a"],
    automatic_updates: ["Manage Windows Update", "https://support.microsoft.com/en-us/windows/install-windows-updates-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a"],
    endpoint_protection: ["Open Windows Security", "https://support.microsoft.com/windows/stay-protected-with-the-windows-security-app-2ae0363d-0ada-c064-8b56-6a39afb6a963"]
  },
  darwin: {
    disk_encryption: ["Turn on FileVault", "https://support.apple.com/en-ie/guide/mac-help/-mh11785/mac"],
    screen_lock: ["Set a screen lock", "https://support.apple.com/en-ie/guide/mac-help/mchlp2270/mac"],
    automatic_updates: ["Set automatic updates", "https://support.apple.com/en-lamr/guide/mac-help/mchla7037245/mac"],
    endpoint_protection: ["Learn about macOS protections", "https://support.apple.com/en-ie/guide/security/sec469d47bd8/web"]
  },
  linux: {
    disk_encryption: ["Learn about disk encryption", "https://documentation.ubuntu.com/desktop/en/latest/explanation/hardware-backed-disk-encryption/"],
    screen_lock: ["Set a screen lock", "https://help.ubuntu.com/stable/ubuntu-help/session-screenlocks.html.en"],
    automatic_updates: ["Set automatic updates", "https://documentation.ubuntu.com/security/security-updates/"],
    endpoint_protection: ["Review Ubuntu security", "https://documentation.ubuntu.com/security/security-features/security-features-overview/"]
  }
};

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function statusLabel(status) {
  return { pass: "Protected", fail: "Needs attention", needs_attention: "Needs attention", unknown: "Not available" }[status] || "Not available";
}

function render(report) {
  window.latestReportPlatform = report.platform;
  // Pending updates are maintenance timing, not an AC-12 requirement. Keep
  // them out of the person-facing posture score so the evaluated controls are
  // exactly encryption, lock, automatic updates, and endpoint protection.
  const findings = (report.findings || []).filter((finding) => finding.check !== "pending_updates");
  const hasFailure = findings.some((finding) => finding.status === "fail");
  const failedCount = findings.filter((finding) => finding.status === "fail").length;
  const protectedCount = findings.filter((finding) => finding.status === "pass").length;
  document.querySelector("#headline").textContent = hasFailure ? "This device needs attention" : "This device is protected";
  document.querySelector("#description").textContent = hasFailure
    ? "Fix the items below, then check again. We only read these settings; we never change them."
    : "These security settings are on. We only read them; we never change anything on your device.";
  document.querySelector("#summaryStatus").textContent = hasFailure ? "Action needed" : "Device protected";
  document.querySelector("#summaryDetail").textContent = hasFailure
    ? `${failedCount} setting${failedCount === 1 ? "" : "s"} needs attention`
    : `${protectedCount} protections are on`;
  const checkTime = new Date(report.checked_at);
  document.querySelector("#checkedAt").textContent = Number.isNaN(checkTime.valueOf())
    ? "Last checked just now"
    : `Last checked ${new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(checkTime)}`;
  const platformRemediation = remediation[report.platform] || {};
  document.querySelector("#posture").innerHTML = findings.map((finding) => {
    // An unreadable local signal is not an instruction to change a setting.
    // Only an affirmative failed check receives a remediation link.
    const guide = finding.status === "fail" ? platformRemediation[finding.check] : null;
    return `
    <article class="finding ${finding.status}">
      <div class="finding-title"><span class="indicator">${finding.status === "pass" ? "✓" : finding.status === "fail" ? "!" : "–"}</span><strong>${escapeHtml(labels[finding.check] || finding.check)}</strong><span class="status-pill">${statusLabel(finding.status)}</span></div>
      <div class="result">${finding.reason ? `<small>${escapeHtml(finding.reason.replaceAll("_", " "))}</small>` : ""}${guide ? `<button class="fix-link" data-remediation="${escapeHtml(finding.check)}">${escapeHtml(guide[0])} →</button>` : ""}</div>
    </article>`;
  }).join("");
}

function renderConnection(connection) {
  document.querySelector(".app-shell").classList.toggle("unpaired", !connection?.paired);
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
    action.innerHTML = "Connect device <b>→</b>";
    action.disabled = false;
    title.textContent = "Connect this device to HackZero";
    description.textContent = "Sign in to send this device's read-only posture record to your workspace.";
  }
}

let availableUpdate = null;
let backgroundTimer = null;
// Keep the splash visible only in the local Vite preview so its design can be
// reviewed. Packaged builds dismiss it as soon as the first check completes.
// Local review uses the same flow as a packaged app.  This is intentionally
// kept uncommitted; production already dismisses the splash after first check.
const keepLaunchVisible = false;

function setLaunchState({ title, description, failed = false, visible = true }) {
  const screen = document.querySelector("#launchScreen");
  screen.hidden = !visible;
  document.querySelector("#launchTitle").textContent = title;
  document.querySelector("#launchDescription").textContent = description;
  document.querySelector("#launchRetry").hidden = !failed;
  screen.classList.toggle("failed", failed);
}

function startBackgroundChecks() {
  if (backgroundTimer) return;
  const tick = () => invoke("background_tick").catch(() => {
    // Delivery is durable and retried at the next scheduled tick. A network
    // outage must not turn the local UI or device posture into a failure.
  });
  tick();
  backgroundTimer = window.setInterval(tick, 60 * 60 * 1000);
}

async function checkForUpdate() {
  const target = document.querySelector("#updateState");
  const install = document.querySelector("#installUpdate");
  target.textContent = "Checking for updates…";
  try {
    availableUpdate = await check();
    if (!availableUpdate) {
      target.textContent = "Up to date";
      return;
    }
    target.textContent = `Version ${availableUpdate.version} is ready to install.`;
    install.hidden = false;
  } catch {
    // An update-server outage is never a failed security setting.
    target.textContent = "Update status unavailable";
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

async function refresh({ initial = false } = {}) {
  const button = document.querySelector("#checkAgain");
  if (initial) {
    setLaunchState({
      title: "Loading HackZero Device Checker",
      description: "This might take a moment."
    });
  }
  button.disabled = true;
  button.textContent = "Checking…";
  try {
    render(await invoke("check_now"));
    if (initial && !keepLaunchVisible) setLaunchState({ visible: false, title: "", description: "" });
  }
  catch {
    document.querySelector("#headline").textContent = "Could not check this device";
    if (initial) {
      setLaunchState({
        title: "Something went wrong",
        description: "We could not start the local device check. Try again, or close and reopen Device Checker.",
        failed: true
      });
    }
  }
  finally { button.disabled = false; button.textContent = "Check again"; }
}

document.querySelector("#checkAgain").addEventListener("click", refresh);
document.querySelector("#posture").addEventListener("click", (event) => {
  const check = event.target.closest("[data-remediation]")?.dataset.remediation;
  const platform = window.latestReportPlatform;
  const guide = check && remediation[platform]?.[check];
  if (guide) openUrl(guide[1]);
});
document.querySelector("#launchRetry").addEventListener("click", () => refresh({ initial: true }));
document.querySelector("#openHackZero")?.addEventListener("click", () => openUrl("https://hackzero.ai"));
document.querySelector("#viewReleases")?.addEventListener("click", () => openUrl("https://github.com/cruzryan/hackzero-device-checker/releases"));
document.querySelector("#installUpdate").addEventListener("click", installAvailableUpdate);
document.querySelector("#connectHackZero").addEventListener("click", async () => {
  const button = document.querySelector("#connectHackZero");
  const title = document.querySelector("#connectionTitle");
  const description = document.querySelector("#connectionDescription");
  button.disabled = true;
  button.innerHTML = "Waiting for approval <b>•</b>";
  title.textContent = "Continue in your browser";
  description.textContent = "A secure approval page is opening in your default browser. Approve this device there, then return here.";
  try {
    renderConnection(await invoke("connect_hackzero"));
    // Start with the signed-in user's consent, only after this device is paired.
    await enableAutostart();
    startBackgroundChecks();
  }
  catch (error) {
    console.error("Device Checker pairing failed", error);
    button.disabled = false;
    button.innerHTML = "Try again <b>→</b>";
    title.textContent = "Could not start sign in";
    // Never display a server response or internal error to the person using
    // the app. Those responses can include proxy HTML and security details.
    description.textContent = "We couldn't open the secure approval page. Check your connection and try again.";
  }
});
Promise.all([
  refresh({ initial: true }),
  invoke("connection_status").then((connection) => {
    renderConnection(connection);
    if (connection?.paired) startBackgroundChecks();
  }),
  checkForUpdate(),
]);
