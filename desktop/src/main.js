import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

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
  document.querySelector("#checkedAt").textContent = `Checked locally: ${new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(report.checked_at))}`;
  document.querySelector("#posture").innerHTML = findings.map((finding) => `
    <article class="finding ${finding.status}">
      <div><span class="indicator">${finding.status === "pass" ? "✓" : finding.status === "fail" ? "!" : "–"}</span><strong>${labels[finding.check] || finding.check}</strong></div>
      <div class="result"><span>${statusLabel(finding.status)}</span>${finding.reason ? `<small>${finding.reason.replaceAll("_", " ")}</small>` : ""}</div>
    </article>`).join("");
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
refresh();
