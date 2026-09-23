import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  describeSignal,
  summarize,
  describeDelivery,
  formatCheckedAt,
  diagnosticsSections,
  diagnosticsText,
  profileSummary,
  pendingSentence,
  REQUIRED_SIGNALS
} from "../src/copy.js";

const texts = (row) => row.lines.map((line) => line.text);
const tones = (row) => row.lines.map((line) => line.tone);
const allStrings = [];
function track(row) {
  allStrings.push(row.label, row.pill, ...texts(row));
  return row;
}
const sl = (detail, status = "fail", code, platform = "darwin") =>
  track(describeSignal("screen_lock", { status, code, detail }, platform));

// ------------------------------------------------------------ screen lock

test("real case: battery 2 min, plugged in 30 min, password delay 300 s", () => {
  const row = sl({
    limit_minutes: 15,
    password: "delay",
    password_delay_seconds: 300,
    active_power: "battery",
    profiles: [
      { power: "battery", display_off_minutes: 2, lock_minutes: 7, ok: true },
      { power: "ac", display_off_minutes: 30, lock_minutes: 35, ok: false }
    ]
  }, "fail", "screen_lock_timeout_too_long");
  assert.equal(row.state, "fail");
  assert.deepEqual(texts(row), [
    "Plugged in: the screen turns off after 30 min and asks for a password 5 min later, so it locks after 35 min. Set it so the total is 15 min or less.",
    "On battery: locks after 7 min."
  ]);
  assert.deepEqual(tones(row), ["fail", "ok"]);
});

test("plugged in never turns off", () => {
  const row = sl({
    password: "immediate",
    password_delay_seconds: 0,
    profiles: [
      { power: "battery", display_off_minutes: 5, lock_minutes: 5, ok: true },
      { power: "ac", display_off_minutes: 0, lock_minutes: 0, ok: false }
    ]
  }, "fail", "screen_lock_never");
  assert.deepEqual(texts(row), [
    "Plugged in: the screen never turns off, so it never locks. Set Turn display off to 15 min or less.",
    "On battery: locks after 5 min."
  ]);
});

test("password off on wake", () => {
  const row = sl({
    password: "off",
    profiles: [
      { power: "ac", display_off_minutes: 10, lock_minutes: 0, ok: false },
      { power: "battery", display_off_minutes: 2, lock_minutes: 0, ok: false }
    ]
  }, "fail", "screen_lock_password_off");
  assert.equal(texts(row)[0], "No password is required when the screen wakes. Turn on Require password in Lock Screen settings.");
  assert.equal(tones(row)[0], "fail");
  // Without a password, the timer lines never claim the screen locks.
  assert.ok(texts(row).slice(1).every((text) => !/locks/.test(text)));
  assert.equal(texts(row)[1], "Plugged in: the screen turns off after 10 min.");
});

test("Mac mini has only a plugged in profile", () => {
  const row = sl({ password: "immediate", password_delay_seconds: 0, profiles: [{ power: "ac", display_off_minutes: 10, lock_minutes: 10, ok: true }] }, "pass");
  assert.equal(row.state, "pass");
  assert.deepEqual(texts(row), ["Plugged in: locks after 10 min."]);
});

test("a single 'any' profile has no power prefix", () => {
  const row = sl({ password: "immediate", profiles: [{ power: "any", display_off_minutes: 10, lock_minutes: 10, ok: true }] }, "pass", undefined, "linux");
  assert.deepEqual(texts(row), ["Locks after 10 min."]);
});

test("Windows uses Plugged in / On battery and Windows fix wording", () => {
  const row = sl({
    password: "immediate",
    profiles: [
      { power: "battery", display_off_minutes: 5, lock_minutes: 5, ok: true },
      { power: "ac", display_off_minutes: 20, lock_minutes: 20, ok: false }
    ]
  }, "fail", "screen_lock_timeout_too_long", "windows");
  assert.deepEqual(texts(row), [
    "Plugged in: the screen turns off after 20 min, so it locks after 20 min. Set the screen to turn off after 15 min or less in Settings > System > Power & battery.",
    "On battery: locks after 5 min."
  ]);
});

test("a password delay of 5 seconds counts as immediate", () => {
  const row = sl({ password: "delay", password_delay_seconds: 5, profiles: [{ power: "ac", display_off_minutes: 20, lock_minutes: 20, ok: false }] });
  assert.deepEqual(texts(row), ["Plugged in: the screen turns off after 20 min, so it locks after 20 min. Set Turn display off to 15 min or less."]);
});

test("screen saver that starts sooner is named", () => {
  const row = sl({ password: "delay", password_delay_seconds: 60, screensaver_minutes: 20, profiles: [{ power: "ac", display_off_minutes: 30, lock_minutes: 21, ok: false }] });
  assert.deepEqual(texts(row), ["Plugged in: the screen saver starts after 20 min and asks for a password 1 min later, so it locks after 21 min. Set it so the total is 15 min or less."]);
});

test("exactly 15 minutes passes", () => {
  const row = sl({ password: "delay", password_delay_seconds: 300, profiles: [{ power: "ac", display_off_minutes: 10, lock_minutes: 15, ok: true }] }, "pass");
  assert.deepEqual(texts(row), ["Plugged in: locks after 15 min."]);
});

test("unreadable password setting says exactly what", () => {
  const row = sl({ password: "unknown", profiles: [{ power: "ac", display_off_minutes: 5, lock_minutes: 5, ok: true }] }, "unknown", "signal_unavailable");
  assert.equal(row.state, "unknown");
  assert.ok(texts(row).includes("We couldn't read the password setting on this Mac."));
});

test("unknown with no detail is platform correct", () => {
  assert.deepEqual(texts(sl(undefined, "unknown", "signal_unavailable", "darwin")), ["We couldn't read the screen lock settings on this Mac."]);
  assert.deepEqual(texts(sl(undefined, "unknown", "signal_unavailable", "windows")), ["We couldn't read the screen lock settings on this PC."]);
});

test("legacy screen lock codes", () => {
  assert.deepEqual(texts(sl(undefined, "fail", "screen_lock_timeout_too_long")), ["The screen takes longer than 15 minutes to lock."]);
  assert.deepEqual(texts(sl(undefined, "fail", "screen_lock_password_not_required")), ["No password is required when the screen wakes. Turn on Require password in Lock Screen settings."]);
  assert.match(texts(sl(undefined, "fail", "screen_lock_disabled"))[0], /^Automatic screen lock is off\./);
  assert.match(texts(sl(undefined, "fail", "screen_lock_never"))[0], /never locks/);
  assert.match(texts(sl(undefined, "fail", "screen_lock_password_off"))[0], /^No password is required/);
});

// ------------------------------------------------------------ disk encryption

const disk = (detail, status, code, platform = "darwin") => track(describeSignal("disk_encryption", { status, code, detail }, platform));

test("disk encryption states", () => {
  assert.deepEqual(texts(disk({ state: "on" }, "pass")), ["FileVault is on."]);
  assert.deepEqual(texts(disk({ state: "off" }, "fail", "disk_encryption_disabled")), ["FileVault is off. Turn it on in Privacy & Security."]);
  const encrypting = disk({ state: "encrypting", percent: 42 }, "pass");
  assert.equal(encrypting.state, "pass");
  assert.deepEqual(texts(encrypting), ["FileVault is turning on (42% done)."]);
  assert.deepEqual(texts(disk({ state: "decrypting", percent: 60 }, "fail", "disk_encryption_decrypting")), ["FileVault is being turned off (60% decrypted). Turn it back on in Privacy & Security."]);
  assert.match(texts(disk({ state: "pending_restart" }, "fail", "disk_encryption_disabled"))[0], /waiting for a restart/);
  assert.match(texts(disk({ state: "off" }, "fail", "disk_encryption_disabled", "windows"))[0], /^BitLocker is off/);
  assert.match(texts(disk({ state: "suspended" }, "fail", "disk_encryption_suspended", "windows"))[0], /^BitLocker is suspended/);
  assert.match(texts(disk({ state: "decrypting", percent: 10 }, "fail", "disk_encryption_decrypting", "windows"))[0], /^BitLocker is being turned off \(10% decrypted\)/);
  assert.deepEqual(texts(disk(undefined, "fail", "disk_encryption_disabled")), ["FileVault is off. Turn it on in Privacy & Security."]);
  assert.deepEqual(texts(disk(undefined, "unknown", "signal_unavailable")), ["We couldn't read whether FileVault is on for this Mac."]);
  assert.deepEqual(texts(disk(undefined, "unknown", "signal_unavailable", "windows")), ["We couldn't read the BitLocker status on this PC."]);
});

// ------------------------------------------------------------ automatic updates

const updates = (detail, status, code, platform = "darwin") => track(describeSignal("automatic_updates", { status, code, detail }, platform));

test("macOS lists exactly which update toggles are off", () => {
  const row = updates({ check: true, download: false, security_responses: false, system_data: true, os_install: false }, "fail", "automatic_updates_disabled");
  assert.deepEqual(texts(row), [
    '"Download new updates when available" is off.',
    '"Install Security Responses and system files" is off.',
    "Turn them on in System Settings > General > Software Update > Automatic updates."
  ]);
  const check = updates({ check: false, download: true, security_responses: true }, "fail", "automatic_updates_disabled");
  assert.deepEqual(texts(check), ['"Check for updates" is off.', "Turn it on in System Settings > General > Software Update > Automatic updates."]);
  // os_install is not required.
  assert.equal(updates({ check: true, download: true, security_responses: true, os_install: false }, "pass").state, "pass");
});

test("Windows update states", () => {
  assert.match(texts(updates({ check: true, download: true, paused: true, policy_disabled: false }, "fail", "automatic_updates_paused", "windows"))[0], /^Windows Update is paused\./);
  assert.match(texts(updates({ check: false, download: false, paused: false, policy_disabled: true }, "fail", "automatic_updates_disabled", "windows")).join(" "), /turned off by a policy/);
  assert.ok(texts(updates({ check: false, download: true, paused: false, policy_disabled: false }, "fail", "automatic_updates_disabled", "windows")).includes("Windows Update is not set to check for updates automatically."));
  assert.match(texts(updates(undefined, "fail", "automatic_updates_paused", "windows"))[0], /paused/);
  assert.match(texts(updates(undefined, "fail", "automatic_updates_disabled", "windows"))[0], /^Automatic updates are off/);
  assert.match(texts(updates(undefined, "unknown", "signal_unavailable", "windows"))[0], /Windows Update settings on this PC/);
});

// ------------------------------------------------------------ pending

test("pending updates are a warning, not a fail", () => {
  const row = track(describeSignal("pending_maintenance", { status: "needs_attention", code: "updates_pending", detail: { count: 3, waiting_days: 38 } }, "darwin"));
  assert.equal(row.state, "warn");
  assert.deepEqual(texts(row), ["3 updates are waiting to install (the oldest for 38 days). Restart to finish them."]);
  assert.equal(pendingSentence({ count: 1, waiting_days: 1 }), "1 update is waiting to install (for 1 day). Restart to finish it.");
  assert.equal(pendingSentence({ count: 2, waiting_days: 0 }), "2 updates are waiting to install. Restart to finish them.");
  // A pending warning never changes the headline.
  const result = passingResult();
  result.report.pending_maintenance = { status: "needs_attention", code: "updates_pending", detail: { count: 3, waiting_days: 38 } };
  assert.equal(summarize(result).tone, "protected");
});

// ------------------------------------------------------------ endpoint

const endpoint = (detail, status, code, warnings, platform = "darwin") => track(describeSignal("endpoint_protection", { status, code, detail, warnings }, platform));

test("macOS endpoint protection", () => {
  assert.match(texts(endpoint({ gatekeeper: false, system_data_updates: true }, "fail", "gatekeeper_disabled"))[0], /^Gatekeeper is off/);
  assert.ok(texts(endpoint({ gatekeeper: true, system_data_updates: false }, "fail", "definitions_updates_off")).some((text) => text.startsWith("XProtect data updates are off")));
  const stale = endpoint({ gatekeeper: true, system_data_updates: true, definitions_version: 5300, definitions_age_days: 45 }, "pass", undefined, ["definitions_stale"]);
  assert.equal(stale.state, "warn");
  assert.ok(texts(stale).some((text) => text.startsWith("Apple's malware definitions last updated 45 days ago.")));
  assert.match(texts(endpoint(undefined, "fail", "gatekeeper_disabled"))[0], /^Gatekeeper is off/);
  assert.match(texts(endpoint(undefined, "fail", "definitions_updates_off"))[0], /^XProtect data updates are off/);
  assert.match(texts(endpoint(undefined, "fail", "endpoint_protection_unavailable"))[0], /Gatekeeper or XProtect/);
});

test("Windows endpoint protection", () => {
  assert.deepEqual(texts(endpoint({ defender_realtime: true, defender_mode: "normal", other_antivirus: 0, definitions_age_days: 1 }, "pass", undefined, undefined, "windows")), ["Microsoft Defender real-time protection is on."]);
  assert.deepEqual(texts(endpoint({ defender_realtime: false, defender_mode: "passive", other_antivirus: 1, definitions_age_days: 1 }, "pass", undefined, undefined, "windows")), ["Another antivirus is on and up to date."]);
  assert.match(texts(endpoint({ defender_realtime: false, defender_mode: "passive", other_antivirus: 0 }, "fail", "endpoint_protection_unavailable", undefined, "windows")).join(" "), /passive mode and no other antivirus is on/);
  const stale = endpoint({ defender_realtime: true, defender_mode: "normal", other_antivirus: 0, definitions_age_days: 9 }, "pass", undefined, ["definitions_stale"], "windows");
  assert.ok(texts(stale).includes("Microsoft Defender definitions last updated 9 days ago. Run Windows Update to refresh them."));
  assert.match(texts(endpoint(undefined, "fail", "endpoint_protection_unavailable", undefined, "windows"))[0], /^Real-time antivirus protection is not on/);
});

// ------------------------------------------------------------ generic rules

test("an unmapped failure code gets a specific generic failure, never 'verified'", () => {
  for (const key of [...REQUIRED_SIGNALS, "pending_maintenance"]) {
    for (const platform of ["darwin", "windows", "linux"]) {
      const row = track(describeSignal(key, { status: "fail", code: "brand_new_code_2027" }, platform));
      assert.equal(row.state, "fail");
      assert.ok(texts(row).some((text) => text === "This setting is not on." || row.lines.some((line) => line.tone === "fail")), `${key} ${platform}`);
      assert.ok(!texts(row).join(" ").toLowerCase().includes("verified"));
    }
  }
  assert.deepEqual(texts(track(describeSignal("screen_lock", { status: "fail", code: "brand_new_code_2027" }, "darwin"))), ["This setting is not on."]);
});

test("needs_attention on a required signal never reads verified and blocks green", () => {
  const result = passingResult();
  result.report.disk_encryption = { status: "needs_attention", code: "something_new" };
  const summary = summarize(result);
  assert.notEqual(summary.tone, "protected");
  const row = summary.rows.find((r) => r.key === "disk_encryption");
  assert.equal(row.state, "warn");
  assert.ok(!texts(row).join(" ").toLowerCase().includes("verified"));
  assert.ok(row.lines.length > 0);
});

// ------------------------------------------------------------ headline

function passingResult() {
  return {
    source: "manual",
    checked_at: "2026-09-23T15:47:00Z",
    delivery: "uploaded",
    http_status: 200,
    report: {
      schema_version: 1,
      platform: "darwin",
      disk_encryption: { status: "pass", detail: { state: "on" } },
      screen_lock: { status: "pass", detail: { password: "immediate", profiles: [{ power: "ac", display_off_minutes: 10, lock_minutes: 10, ok: true }] } },
      automatic_updates: { status: "pass", detail: { check: true, download: true, security_responses: true } },
      endpoint_protection: { status: "pass", detail: { gatekeeper: true, system_data_updates: true } },
      pending_maintenance: { status: "pass" }
    },
    server: { status: "pass", problems: [], warnings: [] }
  };
}

test("green only when all four required signals pass", () => {
  assert.equal(summarize(passingResult()).tone, "protected");
  assert.equal(summarize(passingResult()).headline, "This device is protected");
});

test("a missing required signal is 'Not reported' and not green", () => {
  const result = passingResult();
  delete result.report.endpoint_protection;
  const summary = summarize(result);
  assert.equal(summary.tone, "verify");
  const row = summary.rows.find((r) => r.key === "endpoint_protection");
  assert.equal(row.state, "missing");
  assert.equal(row.pill, "Not reported");
});

test("empty findings are not green", () => {
  assert.notEqual(summarize({ report: {} }).tone, "protected");
  assert.notEqual(summarize({}).tone, "protected");
  assert.notEqual(summarize(null).tone, "protected");
});

test("unknown copy is platform correct", () => {
  const result = passingResult();
  result.report.screen_lock = { status: "unknown", code: "signal_unavailable" };
  const summary = summarize(result);
  assert.equal(summary.tone, "verify");
  assert.match(summary.description, /this Mac/);
  assert.doesNotMatch(summary.description, /Windows/);
});

test("the headline agrees with a failing server verdict", () => {
  const result = passingResult();
  result.server = { status: "fail", problems: ["Screen lock is longer than 15 minutes on AC power."], warnings: [] };
  const summary = summarize(result);
  assert.equal(summary.tone, "attention");
  assert.deepEqual(summary.server.problems, ["Screen lock is longer than 15 minutes on AC power."]);
});

// ------------------------------------------------------------ delivery and time

test("delivery copy", () => {
  const formatTime = () => "3:47 PM";
  assert.deepEqual(describeDelivery({ delivery: "uploaded", checked_at: "2026-09-23T15:47:00Z" }, { formatTime }), { tone: "ok", text: "Sent to HackZero at 3:47 PM" });
  assert.equal(describeDelivery({ delivery: "queued" }).text, "Couldn't reach HackZero. It will retry automatically.");
  assert.equal(describeDelivery({ delivery: "rejected", http_status: 401 }).text, "HackZero didn't accept this report (401). This computer may no longer be connected.");
  assert.match(describeDelivery({ delivery: "rejected", http_status: 400 }).text, /^HackZero didn't accept this report \(400\)\./);
  assert.equal(describeDelivery({ delivery: "not_sent" }).tone, "info");
});

test("an unparseable timestamp never says 'just now'", () => {
  const text = formatCheckedAt({ checked_at: "not a time" });
  assert.doesNotMatch(text, /just now/i);
  assert.match(text, /unknown/);
  assert.match(formatCheckedAt({ checked_at: "2026-09-23T15:47:00Z", source: "background" }, { formatDateTime: () => "Sep 23, 3:47 PM" }), /^Sep 23, 3:47 PM \(automatic\)$/);
});

// ------------------------------------------------------------ diagnostics

test("diagnostics show every signal with detail and never private material", () => {
  assert.equal(profileSummary({ power: "ac", display_off_minutes: 30, lock_minutes: 35, ok: false }), "Plugged in: display off 30 min, lock 35 min, FAIL");
  const last = passingResult();
  last.report.screen_lock = {
    status: "fail",
    code: "screen_lock_timeout_too_long",
    detail: { limit_minutes: 15, password: "delay", password_delay_seconds: 300, profiles: [{ power: "battery", display_off_minutes: 2, lock_minutes: 7, ok: true }, { power: "ac", display_off_minutes: 30, lock_minutes: 35, ok: false }] }
  };
  const sections = diagnosticsSections({
    checker_version: "1.4.0",
    os_version: "26.5.2",
    platform: "darwin",
    paired: true,
    workspace_name: "HackZero",
    person_name: "Ryan",
    device_id: "dev_123",
    private_key: "SECRET-SHOULD-NOT-APPEAR",
    agent_state: { last_full_report: "2026-09-23T15:47:00Z" },
    queue_count: 0,
    last
  }, { appVersion: "2.0.0", formatDateTime: () => "Sep 23, 3:47 PM" });
  const text = diagnosticsText(sections);
  assert.match(text, /App version: 2\.0\.0/);
  assert.match(text, /Checker version: 1\.4\.0/);
  assert.match(text, /Screen lock profile: Plugged in: display off 30 min, lock 35 min, FAIL/);
  assert.match(text, /Screen lock profile: On battery: display off 2 min, lock 7 min, OK/);
  assert.match(text, /Screen lock: status fail; code screen_lock_timeout_too_long/);
  assert.match(text, /Screen lock password delay seconds: 300/);
  for (const label of ["Disk encryption", "Automatic updates", "Malware protection", "Pending updates"]) assert.match(text, new RegExp(`${label}: status`));
  assert.match(text, /Delivery: uploaded/);
  assert.match(text, /HTTP status: 200/);
  assert.doesNotMatch(text, /SECRET-SHOULD-NOT-APPEAR/);
});

test("diagnostics fall back when the collector has no diagnose command", () => {
  const text = diagnosticsText(diagnosticsSections(null, { appVersion: "2.0.0", error: "unknown command", fallbackLast: passingResult(), connection: { paired: true, workspace_name: "W" } }));
  assert.match(text, /Diagnostics error: unknown command/);
  assert.match(text, /Workspace: W/);
  assert.match(text, /Disk encryption: status pass/);
});

// ------------------------------------------------------------ copy rules

test("no em dashes in any copy", () => {
  for (const text of allStrings) assert.ok(!text.includes("2014"), text);
  const source = readFileSync(new URL("../src/copy.js", import.meta.url), "utf8");
  assert.ok(!source.includes("2014"));
});
