// Person-facing copy for Device Checker results.
//
// This module is pure: no DOM, no Tauri. It turns the collector's structured
// RunResult (see the device contract) into sentences that say which setting,
// which power mode, the numbers, and how to fix it. Every sentence is built
// from structured `detail` fields and fixed codes, never from free text.
//
// UI copy rule: no em dashes anywhere in the strings below.

export const REQUIRED_SIGNALS = ["disk_encryption", "screen_lock", "automatic_updates", "endpoint_protection"];
export const ROW_ORDER = [...REQUIRED_SIGNALS, "pending_maintenance"];

export const LABELS = {
  disk_encryption: "Disk encryption",
  screen_lock: "Screen lock",
  automatic_updates: "Automatic updates",
  endpoint_protection: "Malware protection",
  pending_maintenance: "Pending updates"
};

export const REQUIREMENTS = {
  disk_encryption: ["The system drive is fully encrypted (FileVault on a Mac, BitLocker or Device encryption on Windows)."],
  screen_lock: [
    "In every power mode (plugged in and on battery), a password is required 15 minutes or less after you stop using the computer.",
    "That time is when the screen turns off (or the screen saver starts) plus any password delay.",
    "A password is required when the screen wakes."
  ],
  automatic_updates: ["The computer checks for updates, downloads them, and installs security fixes automatically."],
  endpoint_protection: ["Built-in malware protection is on: Gatekeeper and XProtect updates on a Mac, Microsoft Defender or another up-to-date antivirus on Windows."],
  pending_maintenance: ["Waiting updates are a reminder only. They never make this device fail."]
};

const STATUS_PILL = {
  pass: "Passing",
  fail: "Failing",
  warn: "Warning",
  unknown: "Couldn't check",
  missing: "Not reported"
};

const MAX_TEXT = 300;
const MAX_LIST = 20;

// ---------------------------------------------------------------- helpers

export function clean(value, max = MAX_TEXT) {
  if (value === null || value === undefined) return "";
  // eslint-disable-next-line no-control-regex
  const text = String(value).replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function asInt(value) {
  return typeof value === "number" && Number.isFinite(value) ? Math.round(value) : null;
}

function asBool(value) {
  return typeof value === "boolean" ? value : null;
}

function plural(count, one, many) {
  return count === 1 ? one : many;
}

function capitalize(text) {
  return text ? text[0].toUpperCase() + text.slice(1) : text;
}

const ok = (text) => ({ tone: "ok", text });
const bad = (text) => ({ tone: "fail", text });
const warn = (text) => ({ tone: "warn", text });
const unread = (text) => ({ tone: "unknown", text });
const info = (text) => ({ tone: "info", text });

export function platformName(platform) {
  return { darwin: "macOS", windows: "Windows", linux: "Linux" }[platform] || "this computer";
}

export function deviceNoun(platform) {
  return { darwin: "this Mac", windows: "this PC", linux: "this computer" }[platform] || "this computer";
}

// Power profile names. "any" (a single setting for every power source) has no prefix.
export const POWER_NAMES = { ac: "Plugged in", battery: "On battery", ups: "On UPS power", any: "" };
const POWER_ORDER = { ac: 0, battery: 1, ups: 2, any: 3 };

export function powerName(power) {
  return Object.prototype.hasOwnProperty.call(POWER_NAMES, power) ? POWER_NAMES[power] : "";
}

function withPower(power, sentence) {
  const prefix = powerName(power);
  return prefix ? `${prefix}: ${sentence}` : capitalize(sentence);
}

// A password delay of 5 seconds or less counts as immediate (macOS default is 5 s).
function effectiveDelaySeconds(seconds) {
  const value = asInt(seconds);
  if (value === null || value <= 5) return 0;
  return value;
}

function formatDelay(seconds) {
  if (seconds < 60) return `${seconds} sec`;
  return `${Math.ceil(seconds / 60)} min`;
}

// ---------------------------------------------------------------- screen lock

function displayFix(platform, limit) {
  switch (platform) {
    case "darwin": return `Set Turn display off to ${limit} min or less.`;
    case "windows": return `Set the screen to turn off after ${limit} min or less in Settings > System > Power & battery.`;
    case "linux": return `Set Screen Blank to ${limit} min or less in Power settings.`;
    default: return `Set the screen to turn off after ${limit} min or less.`;
  }
}

function screensaverFix(platform, limit) {
  switch (platform) {
    case "darwin": return `Set Start Screen Saver when inactive to ${limit} min or less.`;
    case "windows": return `Set the screen saver wait time to ${limit} min or less.`;
    default: return `Set the screen saver to start after ${limit} min or less.`;
  }
}

export function passwordOffCopy(platform) {
  switch (platform) {
    case "darwin": return "No password is required when the screen wakes. Turn on Require password in Lock Screen settings.";
    case "windows": return "No password is required when the screen wakes. In Settings > Accounts > Sign-in options, require sign-in every time you have been away.";
    case "linux": return "No password is required when the screen wakes. Turn on Automatic Screen Lock in Privacy settings.";
    default: return "No password is required when the screen wakes. Turn on the password requirement in your lock screen settings.";
  }
}

function profileLine(profile, detail, limit, delaySeconds, platform, passwordOff) {
  const power = typeof profile.power === "string" ? profile.power : "";
  const lock = asInt(profile.lock_minutes);
  const display = asInt(profile.display_off_minutes);
  const screensaver = asInt(detail.screensaver_minutes);

  if (passwordOff) {
    // Without a password the screen turning off is not a lock. Say what the
    // timer is, without calling it locked.
    if (display === 0) return info(withPower(power, "the screen never turns off."));
    if (display !== null) return info(withPower(power, `the screen turns off after ${display} min.`));
    return null;
  }

  if (profile.ok === true) {
    if (lock !== null && lock > 0) return ok(withPower(power, `locks after ${lock} min.`));
    return ok(withPower(power, `locks within ${limit} min.`));
  }

  // The sooner of display-off and screen saver (whichever is set and non-zero)
  // starts the clock; the password delay is added on top.
  const triggers = [];
  if (display !== null && display > 0) triggers.push({ kind: "display", minutes: display });
  if (screensaver !== null && screensaver > 0) triggers.push({ kind: "screensaver", minutes: screensaver });
  triggers.sort((a, b) => a.minutes - b.minutes);
  const trigger = triggers[0];

  if (lock === 0 || (!trigger && display === 0)) {
    if (display === 0 && !trigger) {
      return bad(withPower(power, `the screen never turns off, so it never locks. ${displayFix(platform, limit)}`));
    }
    return bad(withPower(power, `it never locks. Set it to lock within ${limit} min.`));
  }

  if (lock !== null && lock > limit) {
    if (trigger) {
      const what = trigger.kind === "display"
        ? `the screen turns off after ${trigger.minutes} min`
        : `the screen saver starts after ${trigger.minutes} min`;
      if (delaySeconds > 0) {
        return bad(withPower(power, `${what} and asks for a password ${formatDelay(delaySeconds)} later, so it locks after ${lock} min. Set it so the total is ${limit} min or less.`));
      }
      const fix = trigger.kind === "display" ? displayFix(platform, limit) : screensaverFix(platform, limit);
      return bad(withPower(power, `${what}, so it locks after ${lock} min. ${fix}`));
    }
    return bad(withPower(power, `it locks after ${lock} min. Set it so the total is ${limit} min or less.`));
  }

  return unread(withPower(power, `we couldn't read when the screen locks on ${deviceNoun(platform)}.`));
}

function screenLockLines(signal, platform) {
  const detail = isObject(signal.detail) ? signal.detail : {};
  const limit = asInt(detail.limit_minutes) || 15;
  const password = typeof detail.password === "string" ? detail.password : null;
  const delaySeconds = effectiveDelaySeconds(detail.password_delay_seconds);
  const lines = [];

  if (password === "off") lines.push(bad(passwordOffCopy(platform)));

  const profiles = (Array.isArray(detail.profiles) ? detail.profiles : [])
    .filter(isObject)
    .slice(0, 8)
    .sort((a, b) => (POWER_ORDER[a.power] ?? 9) - (POWER_ORDER[b.power] ?? 9));
  for (const profile of profiles) {
    const line = profileLine(profile, detail, limit, delaySeconds, platform, password === "off");
    if (line) lines.push(line);
  }

  if (password === "unknown") lines.push(unread(`We couldn't read the password setting on ${deviceNoun(platform)}.`));

  if (!lines.length) {
    // Legacy reports (no detail) and code-only fallbacks.
    switch (signal.code) {
      case "screen_lock_password_off":
      case "screen_lock_password_not_required":
        lines.push(bad(passwordOffCopy(platform)));
        break;
      case "screen_lock_disabled":
        lines.push(bad(`Automatic screen lock is off. Set the screen to lock within ${limit} minutes.`));
        break;
      case "screen_lock_never":
        lines.push(bad(`The screen never locks on its own. Set it to lock within ${limit} minutes.`));
        break;
      case "screen_lock_timeout_too_long":
        lines.push(bad(`The screen takes longer than ${limit} minutes to lock.`));
        break;
      default:
        if (signal.status === "pass") lines.push(ok(`The screen locks within ${limit} minutes and asks for a password.`));
        else if (signal.status === "unknown") lines.push(unread(`We couldn't read the screen lock settings on ${deviceNoun(platform)}.`));
    }
  } else if (signal.status === "unknown" && !profiles.length && password !== "unknown") {
    lines.push(unread(`We couldn't read when the screen turns off on ${deviceNoun(platform)}.`));
  }
  return lines;
}

// ---------------------------------------------------------------- disk encryption

function diskLines(signal, platform) {
  const detail = isObject(signal.detail) ? signal.detail : {};
  const percent = asInt(detail.percent);
  const mac = platform === "darwin";
  const win = platform === "windows";
  const name = mac ? "FileVault" : win ? "BitLocker" : "Disk encryption";
  const turnOnPlace = mac ? "Privacy & Security" : win ? "Settings > Privacy & security > Device encryption" : "your disk settings";

  switch (detail.state) {
    case "on":
      return [ok(mac ? "FileVault is on." : win ? "BitLocker is on for the system drive." : "The system disk is encrypted.")];
    case "encrypting":
      return [ok(`${name} is turning on${percent !== null ? ` (${percent}% done)` : ""}.`)];
    case "decrypting":
      return [bad(`${name} is being turned off${percent !== null ? ` (${percent}% decrypted)` : ""}. Turn it back on in ${mac ? "Privacy & Security" : win ? "BitLocker settings" : "your disk settings"}.`)];
    case "pending_restart":
      return [bad(`${name} is set to turn on but is waiting for a restart. Restart ${deviceNoun(platform)} to start encrypting.`)];
    case "suspended":
      return [bad("BitLocker is suspended, so the drive is not protected. Resume protection in Control Panel > BitLocker Drive Encryption.")];
    case "off":
      return [bad(offCopy())];
    default:
      break;
  }
  function offCopy() {
    if (mac) return "FileVault is off. Turn it on in Privacy & Security.";
    if (win) return `BitLocker is off for the system drive. Turn on encryption in ${turnOnPlace}.`;
    return "The system disk is not encrypted. On Linux, encryption is set up when the system is installed; ask your IT admin for help.";
  }
  switch (signal.code) {
    case "disk_encryption_disabled": return [bad(offCopy())];
    case "disk_encryption_decrypting": return [bad(`${name} is being turned off. Turn it back on in ${mac ? "Privacy & Security" : win ? "BitLocker settings" : "your disk settings"}.`)];
    case "disk_encryption_suspended": return [bad("BitLocker is suspended, so the drive is not protected. Resume protection in Control Panel > BitLocker Drive Encryption.")];
    default: break;
  }
  if (signal.status === "pass") return [ok(mac ? "FileVault is on." : win ? "BitLocker is on for the system drive." : "The system disk is encrypted.")];
  if (signal.status === "unknown") {
    if (mac) return [unread("We couldn't read whether FileVault is on for this Mac.")];
    if (win) return [unread("We couldn't read the BitLocker status on this PC.")];
    return [unread(`We couldn't read whether the disk is encrypted on ${deviceNoun(platform)}.`)];
  }
  return [];
}

// ---------------------------------------------------------------- automatic updates

export const MAC_UPDATE_TOGGLES = [
  ["check", "Check for updates"],
  ["download", "Download new updates when available"],
  ["security_responses", "Install Security Responses and system files"]
];

function updatesLines(signal, platform) {
  const detail = isObject(signal.detail) ? signal.detail : {};
  const lines = [];
  if (platform === "darwin") {
    const off = MAC_UPDATE_TOGGLES.filter(([key]) => asBool(detail[key]) === false);
    const unreadable = MAC_UPDATE_TOGGLES.filter(([key]) => asBool(detail[key]) === null);
    for (const [, label] of off) lines.push(bad(`"${label}" is off.`));
    if (off.length) {
      lines.push(bad(`Turn ${plural(off.length, "it", "them")} on in System Settings > General > Software Update > Automatic updates.`));
    }
    if (signal.status === "unknown" && unreadable.length) {
      lines.push(unread(`We couldn't read ${unreadable.map(([, label]) => `"${label}"`).join(", ")} on this Mac.`));
    }
    if (!lines.length && signal.status === "pass") {
      lines.push(ok("Checking, downloading, and Security Responses are all set to happen automatically."));
    }
  } else if (platform === "windows") {
    if (asBool(detail.paused) === true) lines.push(bad("Windows Update is paused. Resume updates in Settings > Windows Update."));
    if (asBool(detail.policy_disabled) === true) lines.push(bad("Automatic updates are turned off by a policy on this PC. Ask your IT admin to turn them back on."));
    const checkOff = asBool(detail.check) === false;
    const downloadOff = asBool(detail.download) === false;
    if (checkOff) lines.push(bad("Windows Update is not set to check for updates automatically."));
    if (downloadOff) lines.push(bad("Windows Update is not set to download updates automatically."));
    if ((checkOff || downloadOff) && asBool(detail.policy_disabled) !== true) {
      lines.push(bad("Turn on automatic updates in Settings > Windows Update > Advanced options."));
    }
    if (!lines.length && signal.status === "pass") lines.push(ok("Windows Update checks for and installs updates automatically."));
  } else if (!lines.length && signal.status === "pass") {
    lines.push(ok("Automatic security updates are on."));
  }

  if (!lines.some((line) => line.tone === "fail")) {
    switch (signal.code) {
      case "automatic_updates_paused":
        lines.push(bad("Windows Update is paused. Resume updates in Settings > Windows Update."));
        break;
      case "automatic_updates_disabled":
        if (platform === "darwin") lines.push(bad('Automatic updates are off. In Software Update > Automatic updates, turn on "Check for updates", "Download new updates when available" and "Install Security Responses and system files".'));
        else if (platform === "windows") lines.push(bad("Automatic updates are off. Turn them on in Settings > Windows Update."));
        else lines.push(bad("Automatic security updates are off. Turn on unattended upgrades in Software & Updates."));
        break;
      default:
        break;
    }
  }
  if (!lines.length && signal.status === "unknown") {
    const where = platform === "darwin" ? "the Software Update settings" : platform === "windows" ? "the Windows Update settings" : "the automatic update settings";
    lines.push(unread(`We couldn't read ${where} on ${deviceNoun(platform)}.`));
  }
  return lines;
}

// ---------------------------------------------------------------- pending updates

export function pendingSentence(detail) {
  const count = asInt(detail?.count);
  const days = asInt(detail?.waiting_days);
  let sentence;
  if (count === 1) sentence = "1 update is waiting to install";
  else if (count !== null && count > 1) sentence = `${count} updates are waiting to install`;
  else sentence = "Updates are waiting to install";
  if (days !== null && days > 0) {
    const span = `${days} ${plural(days, "day", "days")}`;
    sentence += count === 1 ? ` (for ${span})` : ` (the oldest for ${span})`;
  }
  return `${sentence}. Restart to finish ${count === 1 ? "it" : "them"}.`;
}

function pendingLines(signal, platform) {
  const detail = isObject(signal.detail) ? signal.detail : {};
  if (signal.status === "needs_attention" || signal.code === "updates_pending") return [warn(pendingSentence(detail))];
  if (signal.status === "pass") return [ok("No updates are waiting to install.")];
  if (signal.status === "unknown") return [unread(`We couldn't read whether updates are waiting on ${deviceNoun(platform)}.`)];
  return [];
}

// ---------------------------------------------------------------- endpoint protection

const GATEKEEPER_OFF = "Gatekeeper is off, so apps from unknown developers can open without a check. In Privacy & Security, set Allow applications from to App Store & Known Developers.";
const XPROTECT_OFF = 'XProtect data updates are off, so malware definitions stop updating. Turn on "Install Security Responses and system files" in Software Update > Automatic updates.';

function endpointLines(signal, platform) {
  const detail = isObject(signal.detail) ? signal.detail : {};
  const warnings = Array.isArray(signal.warnings) ? signal.warnings : [];
  const age = asInt(detail.definitions_age_days);
  const lines = [];
  let handledStale = false;

  if (platform === "darwin") {
    const gatekeeper = asBool(detail.gatekeeper);
    const updates = asBool(detail.system_data_updates);
    if (gatekeeper === false || (gatekeeper === null && signal.code === "gatekeeper_disabled")) lines.push(bad(GATEKEEPER_OFF));
    else if (gatekeeper === true) lines.push(ok("Gatekeeper is on."));
    if (updates === false || (updates === null && signal.code === "definitions_updates_off")) lines.push(bad(XPROTECT_OFF));
    else if (updates === true) lines.push(ok("XProtect updates are on."));
    if (warnings.includes("definitions_stale")) {
      handledStale = true;
      lines.push(warn(`Apple's malware definitions last updated ${age !== null ? `${age} ${plural(age, "day", "days")} ago` : "more than 30 days ago"}. Open Software Update and check for updates to refresh them.`));
    } else if (age !== null && (gatekeeper !== null || updates !== null)) {
      lines.push(ok(`Malware definitions updated ${age === 0 ? "today" : `${age} ${plural(age, "day", "days")} ago`}.`));
    }
    if (signal.status === "unknown") {
      if (gatekeeper === null) lines.push(unread("We couldn't read the Gatekeeper setting on this Mac."));
      if (updates === null) lines.push(unread("We couldn't read the XProtect update setting on this Mac."));
    }
    if (!lines.some((line) => line.tone === "fail") && signal.code === "endpoint_protection_unavailable") {
      lines.push(bad("Gatekeeper or XProtect updates are not on. Check Privacy & Security and Software Update > Automatic updates."));
    }
  } else if (platform === "windows") {
    const realtime = asBool(detail.defender_realtime);
    const mode = typeof detail.defender_mode === "string" ? detail.defender_mode : null;
    const others = asInt(detail.other_antivirus);
    const defenderActive = realtime === true && (mode === "normal" || mode === null);
    if (defenderActive) lines.push(ok("Microsoft Defender real-time protection is on."));
    if (others !== null && others > 0) {
      lines.push(ok(others === 1 ? "Another antivirus is on and up to date." : `${others} other antivirus products are on and up to date.`));
    }
    if (signal.status === "fail" && realtime === null && mode === null && others === null) {
      // Legacy report without detail: say only what we know.
      lines.push(bad("Real-time antivirus protection is not on. Turn on Real-time protection in Windows Security > Virus & threat protection."));
    } else if (signal.status === "fail") {
      let defenderState = "Microsoft Defender real-time protection is off";
      if (mode === "passive") defenderState = "Microsoft Defender is in passive mode";
      else if (mode === "edr_block") defenderState = "Microsoft Defender is in EDR block mode only";
      else if (mode === "off") defenderState = "Microsoft Defender is off";
      lines.push(bad(`${defenderState} and no other antivirus is on. Turn on Real-time protection in Windows Security > Virus & threat protection.`));
    }
    if (warnings.includes("definitions_stale")) {
      handledStale = true;
      const who = defenderActive ? "Microsoft Defender" : "Antivirus";
      lines.push(warn(`${who} definitions last updated ${age !== null ? `${age} ${plural(age, "day", "days")} ago` : "more than 7 days ago"}. Run Windows Update to refresh them.`));
    }
    if (!lines.length && signal.status === "unknown") lines.push(unread("We couldn't read the Microsoft Defender status on this PC."));
  } else {
    if (signal.status === "pass") lines.push(ok("Malware protection is running."));
    if (signal.status === "fail") lines.push(bad(`No malware protection was found running on ${deviceNoun(platform)}.`));
    if (signal.status === "unknown") lines.push(unread(`We couldn't read the malware protection status on ${deviceNoun(platform)}.`));
  }
  if (!handledStale && warnings.includes("definitions_stale")) {
    lines.push(warn(`Malware definitions last updated ${age !== null ? `${age} ${plural(age, "day", "days")} ago` : "a while ago"}. Check for updates to refresh them.`));
  }
  return lines;
}

// ---------------------------------------------------------------- signals

const BUILDERS = {
  disk_encryption: diskLines,
  screen_lock: screenLockLines,
  automatic_updates: updatesLines,
  endpoint_protection: endpointLines,
  pending_maintenance: pendingLines
};

const KNOWN_WARNINGS = new Set(["definitions_stale"]);

export function rowState(signal) {
  if (!isObject(signal) || typeof signal.status !== "string") return "missing";
  const warnings = Array.isArray(signal.warnings) ? signal.warnings : [];
  switch (signal.status) {
    case "pass": return warnings.length ? "warn" : "pass";
    case "fail": return "fail";
    case "unknown": return "unknown";
    // needs_attention and anything unexpected: never presented as verified.
    default: return "warn";
  }
}

export function describeSignal(key, signal, platform) {
  const state = rowState(signal);
  const label = LABELS[key] || clean(key, 60);
  if (state === "missing") {
    return { key, label, state, pill: STATUS_PILL.missing, lines: [unread("Not reported. The checker did not send this setting. Update Device Checker, then check again.")] };
  }
  const builder = BUILDERS[key];
  let lines = builder ? builder(signal, platform) : [];
  lines = lines.filter(Boolean).map((line) => ({ tone: line.tone, text: clean(line.text) }));

  // Never leave a non-passing row without a specific explanation, and never
  // let a non-passing row read as verified.
  if (state === "fail" && !lines.some((line) => line.tone === "fail")) {
    lines.push(bad("This setting is not on."));
  }
  if (state === "unknown" && !lines.some((line) => line.tone === "unknown" || line.tone === "fail")) {
    lines.push(unread(`We couldn't read this setting on ${deviceNoun(platform)}.`));
  }
  const warnings = Array.isArray(signal.warnings) ? signal.warnings : [];
  if (warnings.some((code) => !KNOWN_WARNINGS.has(code)) && !lines.some((line) => line.tone === "warn")) {
    lines.push(warn("This setting has a warning. Open Diagnostics for details."));
  }
  if (state === "warn" && !lines.some((line) => line.tone === "warn" || line.tone === "fail")) {
    lines.push(warn("This setting needs a look. Open Diagnostics for details."));
  }
  if (state !== "pass") {
    // A passing sentence alone must never stand for a non-passing row.
    lines = lines.filter((line, index, all) => line.tone !== "ok" || all.some((other) => other.tone !== "ok" && other.tone !== "info"));
  }
  return { key, label, state, pill: STATUS_PILL[state], lines };
}

// ---------------------------------------------------------------- summary

function serverVerdict(result) {
  const server = isObject(result?.server) ? result.server : null;
  if (!server) return null;
  const list = (value) => (Array.isArray(value) ? value : []).slice(0, MAX_LIST).map((item) => clean(item)).filter(Boolean);
  return {
    status: server.status === "pass" || server.status === "fail" ? server.status : null,
    problems: list(server.problems),
    warnings: list(server.warnings)
  };
}

export function summarize(result) {
  const report = isObject(result?.report) ? result.report : {};
  const platform = typeof report.platform === "string" ? report.platform : "";
  const rows = ROW_ORDER.map((key) => describeSignal(key, report[key], platform));
  const required = rows.filter((row) => REQUIRED_SIGNALS.includes(row.key));
  const statusOf = (key) => (isObject(report[key]) ? report[key].status : undefined);

  const failed = REQUIRED_SIGNALS.filter((key) => statusOf(key) === "fail");
  const attention = REQUIRED_SIGNALS.filter((key) => {
    const status = statusOf(key);
    return typeof status === "string" && !["pass", "fail", "unknown"].includes(status);
  });
  const unverified = REQUIRED_SIGNALS.filter((key) => statusOf(key) === "unknown" || typeof statusOf(key) !== "string");
  const passed = REQUIRED_SIGNALS.filter((key) => statusOf(key) === "pass");
  const server = serverVerdict(result);
  const serverFails = server?.status === "fail" || (server?.problems.length ?? 0) > 0;
  const warningRows = rows.filter((row) => row.state === "warn").length;

  let tone;
  let headline;
  let description;
  let summaryStatus;
  let summaryDetail;
  if (failed.length || attention.length || serverFails) {
    tone = "attention";
    headline = "This device needs attention";
    const count = failed.length + attention.length;
    if (count) {
      description = "Fix the items below, then check again. We only read these settings; we never change them.";
      summaryDetail = `${count} ${plural(count, "setting needs", "settings need")} attention`;
    } else {
      description = "Your HackZero dashboard reports a problem with this device. See what your dashboard shows below.";
      summaryDetail = "Your dashboard reports a problem";
    }
    summaryStatus = "Action needed";
  } else if (unverified.length) {
    tone = "verify";
    headline = "Couldn't verify this device yet";
    description = `We couldn't read every required setting on ${deviceNoun(platform)}. See the details below, then check again.`;
    summaryStatus = "Verification needed";
    summaryDetail = `${passed.length} verified, ${unverified.length} couldn't be checked`;
  } else if (passed.length === REQUIRED_SIGNALS.length) {
    tone = "protected";
    headline = "This device is protected";
    description = "These security settings are on. We only read them; we never change anything on your device.";
    summaryStatus = "Device protected";
    summaryDetail = `All ${passed.length} protections are on${warningRows ? `, ${warningRows} ${plural(warningRows, "thing", "things")} to look at` : ""}`;
  } else {
    // Defensive: anything that is not explicitly all-pass is never green.
    tone = "verify";
    headline = "Couldn't verify this device yet";
    description = `We couldn't read every required setting on ${deviceNoun(platform)}. See the details below, then check again.`;
    summaryStatus = "Verification needed";
    summaryDetail = `${passed.length} verified`;
  }
  return { tone, headline, description, summaryStatus, summaryDetail, rows, required, server, platform };
}

// ---------------------------------------------------------------- delivery and time

function parseTime(value) {
  if (typeof value !== "string" || !value) return null;
  const time = new Date(value);
  return Number.isNaN(time.valueOf()) ? null : time;
}

const defaultTime = (date) => new Intl.DateTimeFormat(undefined, { timeStyle: "short" }).format(date);
const defaultDateTime = (date) => new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);

export function describeDelivery(result, { formatTime = defaultTime } = {}) {
  if (!isObject(result)) return null;
  const status = asInt(result.http_status);
  switch (result.delivery) {
    case "uploaded": {
      const at = parseTime(result.checked_at);
      return { tone: "ok", text: at ? `Sent to HackZero at ${formatTime(at)}` : "Sent to HackZero" };
    }
    case "queued":
      return { tone: "warn", text: "Couldn't reach HackZero. It will retry automatically." };
    case "rejected": {
      const code = status !== null ? ` (${status})` : "";
      const gone = [401, 403, 404, 410].includes(status) ? " This computer may no longer be connected." : " Try updating Device Checker, then check again.";
      return { tone: "fail", text: `HackZero didn't accept this report${code}.${gone}` };
    }
    case "not_sent":
      return { tone: "info", text: "This check was not sent to HackZero." };
    default:
      return null;
  }
}

export function formatCheckedAt(result, { formatDateTime = defaultDateTime } = {}) {
  const at = parseTime(result?.checked_at) || parseTime(result?.report?.collected_at);
  if (!at) return "Time of last check unknown";
  const automatic = result?.source === "background" ? " (automatic)" : "";
  return `${formatDateTime(at)}${automatic}`;
}

// ---------------------------------------------------------------- diagnostics

function diagValue(value) {
  if (value === null || value === undefined || value === "") return "none";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return clean(value);
  try {
    return clean(JSON.stringify(value));
  } catch {
    return "unreadable";
  }
}

export function profileSummary(profile) {
  if (!isObject(profile)) return "unreadable";
  const name = powerName(profile.power) || (profile.power === "any" ? "All power sources" : clean(profile.power, 20) || "Unknown power");
  const parts = [];
  const display = asInt(profile.display_off_minutes);
  if (display !== null) parts.push(`display off ${display === 0 ? "never" : `${display} min`}`);
  const lock = asInt(profile.lock_minutes);
  if (lock !== null) parts.push(`lock ${lock === 0 ? "never" : `${lock} min`}`);
  parts.push(profile.ok === true ? "OK" : "FAIL");
  return `${name}: ${parts.join(", ")}`;
}

function signalRows(key, signal) {
  const label = LABELS[key] || clean(key, 60);
  if (!isObject(signal)) return [[label, "not reported"]];
  const head = [`status ${diagValue(signal.status)}`];
  if (signal.code) head.push(`code ${diagValue(signal.code)}`);
  const warnings = Array.isArray(signal.warnings) ? signal.warnings : [];
  if (warnings.length) head.push(`warnings ${warnings.slice(0, MAX_LIST).map((code) => clean(code, 60)).join(", ")}`);
  const rows = [[label, head.join("; ")]];
  const detail = isObject(signal.detail) ? signal.detail : {};
  for (const [field, value] of Object.entries(detail).slice(0, 40)) {
    if (field === "profiles" && Array.isArray(value)) {
      value.slice(0, 8).forEach((profile) => rows.push([`${label} profile`, profileSummary(profile)]));
    } else {
      rows.push([`${label} ${clean(field, 60).replace(/_/g, " ")}`, diagValue(value)]);
    }
  }
  return rows;
}

export function diagnosticsSections(diag, { appVersion, error, fallbackLast, connection, formatDateTime = defaultDateTime } = {}) {
  const data = isObject(diag) ? diag : {};
  const last = isObject(data.last) ? data.last : isObject(fallbackLast) ? fallbackLast : null;
  const report = isObject(last?.report) ? last.report : {};
  const conn = isObject(connection) ? connection : {};
  const sections = [];

  const app = [
    ["App version", diagValue(appVersion)],
    ["Checker version", diagValue(data.checker_version ?? report.checker_version)],
    ["OS version", diagValue(data.os_version ?? report.os_version)],
    ["Platform", diagValue(data.platform ?? report.platform)]
  ];
  if (error) app.push(["Diagnostics error", clean(error)]);
  sections.push({ title: "This app", rows: app });

  const paired = typeof data.paired === "boolean" ? data.paired : conn.paired;
  sections.push({
    title: "Connection",
    rows: [
      ["Connected", diagValue(paired)],
      ["Workspace", diagValue(data.workspace_name ?? conn.workspace_name)],
      ["Person", diagValue(data.person_name ?? conn.person_name)],
      ["Device ID", diagValue(data.device_id)],
      ["Reports waiting to send", diagValue(data.queue_count)]
    ]
  });

  if (isObject(data.agent_state)) {
    const rows = Object.entries(data.agent_state).slice(0, 30).map(([field, value]) => [clean(field, 60).replace(/_/g, " "), diagValue(value)]);
    if (rows.length) sections.push({ title: "Background schedule", rows });
  }

  if (last) {
    const at = parseTime(last.checked_at);
    const server = serverVerdict(last);
    const rows = [
      ["Checked at", at ? formatDateTime(at) : diagValue(last.checked_at)],
      ["Source", last.source === "background" ? "background (automatic)" : last.source === "manual" ? "manual" : diagValue(last.source)],
      ["Delivery", diagValue(last.delivery)],
      ["HTTP status", diagValue(last.http_status)],
      ["Error", diagValue(last.error)],
      ["Dashboard verdict", server ? diagValue(server.status) : "none"]
    ];
    if (server?.problems.length) rows.push(["Dashboard problems", server.problems.join(" | ")]);
    if (server?.warnings.length) rows.push(["Dashboard warnings", server.warnings.join(" | ")]);
    rows.push(["Report collected at", diagValue(report.collected_at)]);
    rows.push(["Report schema", diagValue(report.schema_version)]);
    sections.push({ title: "Last check", rows });

    const signals = [];
    const keys = [...ROW_ORDER, ...Object.keys(report).filter((key) => !ROW_ORDER.includes(key) && isObject(report[key]) && "status" in report[key])];
    for (const key of keys.slice(0, 12)) signals.push(...signalRows(key, report[key]));
    sections.push({ title: "Signals", rows: signals });
  } else {
    sections.push({ title: "Last check", rows: [["Last check", "No check has been saved yet"]] });
  }
  return sections;
}

export function diagnosticsText(sections) {
  const out = ["HackZero Device Checker diagnostics"];
  for (const section of sections) {
    out.push("", `== ${section.title} ==`);
    for (const [key, value] of section.rows) out.push(`${key}: ${value}`);
  }
  return `${out.join("\n")}\n`;
}
