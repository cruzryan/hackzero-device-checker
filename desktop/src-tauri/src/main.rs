#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Output};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager,
};

// The Go collector communicates through captured stdout/stderr. Its short
// checks must never create a visible console window on Windows.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How often the resident app asks the collector for one scheduler tick. The
/// collector itself decides whether a full report or a heartbeat is due.
const BACKGROUND_EVERY: Duration = Duration::from_secs(60 * 60);
/// Granularity of the background loop. Also used to notice the computer waking.
const BACKGROUND_POLL: Duration = Duration::from_secs(30);
/// A loop iteration that took this much wall-clock time means the computer slept.
const WAKE_GAP: Duration = Duration::from_secs(120);
/// After a wake, give the network a moment before the catch-up tick.
const AFTER_WAKE_DELAY: Duration = Duration::from_secs(45);
const MAX_ERROR_CHARS: usize = 300;

/// The ONLY collector invocations this app can make. Every argument is fixed
/// here; no UI value ever becomes an argument or a shell command.
#[derive(Clone, Copy)]
enum Collector {
    Status,
    Report,
    RunOnce,
    Last,
    Diagnose,
    Connection,
    Pair,
    Disconnect,
}

impl Collector {
    fn args(self) -> &'static [&'static str] {
        match self {
            Collector::Status => &["status"],
            Collector::Report => &["report"],
            Collector::RunOnce => &["run", "--once"],
            Collector::Last => &["last"],
            Collector::Diagnose => &["diagnose"],
            Collector::Connection => &["connection"],
            Collector::Pair => &["pair"],
            Collector::Disconnect => &["disconnect"],
        }
    }
}

/// Serialises collector runs that collect or change state (manual check,
/// background tick, pair, disconnect). The collector also holds its own lock
/// file; this keeps the app from racing itself and surfacing a lock error.
struct CollectorGate(Mutex<()>);

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn is_elevated() -> bool {
    true
}

#[derive(Deserialize, Serialize)]
struct Connection {
    paired: bool,
    workspace_name: Option<String>,
    person_name: Option<String>,
}

fn checker_path(app: &AppHandle) -> Result<PathBuf, String> {
    // An installed build resolves this from its bundled resources. During
    // development this fixed path points at the locally built Windows collector.
    // An environment override is for packaging/CI only; it never comes from UI.
    if let Some(path) = std::env::var_os("HACKZERO_CHECKER_BIN") {
        return Ok(PathBuf::from(path));
    }
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bin/device-checker-windows-amd64.exe");
    if cfg!(debug_assertions) && cfg!(target_os = "windows") && development.exists() {
        return Ok(development);
    }
    let bundled_name = if cfg!(target_os = "windows") {
        "device-checker-windows-amd64.exe"
    } else if cfg!(target_os = "macos") {
        // A universal (arm64 + x86_64) binary, so Intel and Apple silicon Macs
        // both run the same bundled collector.
        "device-checker-macos-universal"
    } else {
        "device-checker-linux-amd64"
    };
    app.path()
        .resource_dir()
        .map(|dir| dir.join(bundled_name))
        .map_err(|_| "Device Checker's files are missing. Reinstall Device Checker.".to_string())
}

fn run_collector(app: &AppHandle, which: Collector, extra: &[String]) -> Result<Output, String> {
    let mut command = Command::new(checker_path(app)?);
    command.args(which.args());
    command.args(extra);
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .output()
        .map_err(|error| short_error(format!("Could not start Device Checker: {error}").as_bytes()))
}

/// A short, printable-ASCII message for the UI. Collector errors are our own
/// short messages, but they are still capped and stripped of control bytes.
fn short_error(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    let text = text.strip_prefix("device-checker:").unwrap_or(text).trim();
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { ' ' })
        .take(MAX_ERROR_CHARS)
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        "Device Checker stopped without a message.".into()
    } else {
        cleaned
    }
}

fn failure_message(output: &Output) -> String {
    if output.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
        short_error(&output.stderr)
    } else {
        short_error(&output.stdout)
    }
}

/// The collector prints one JSON document; tolerate stray lines before it by
/// taking the last complete JSON value on stdout.
fn parse_json(stdout: &[u8]) -> Option<Value> {
    serde_json::Deserializer::from_slice(stdout)
        .into_iter::<Value>()
        .filter_map(Result::ok)
        .last()
}

/// Defence in depth: never pass anything that looks like private key material
/// to the webview, even though the collector's `diagnose` never includes it.
fn scrub(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|key, _| {
                let key = key.to_ascii_lowercase();
                !(key.contains("private") || key.contains("secret") || key == "identity")
            });
            for child in map.values_mut() {
                scrub(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

fn read_connection(app: &AppHandle) -> Result<Connection, String> {
    let output = run_collector(app, Collector::Connection, &[])?;
    if !output.status.success() {
        return Err(failure_message(&output));
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "Device Checker returned an unreadable connection status.".to_string())
}

fn gate(app: &AppHandle) -> std::sync::MutexGuard<'_, ()> {
    app.state::<CollectorGate>().inner().0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn blocking<T: Send + 'static>(task: impl FnOnce() -> Result<T, String> + Send + 'static) -> impl std::future::Future<Output = Result<T, String>> {
    async move {
        tauri::async_runtime::spawn_blocking(task)
            .await
            .map_err(|error| short_error(error.to_string().as_bytes()))?
    }
}

/// One visible check. When connected this is exactly ONE signed `report`
/// (collect, sign, send, persist) and the UI shows exactly that RunResult.
/// When not connected it is a local-only `status`, wrapped in the same shape
/// with `delivery: "not_sent"`.
#[tauri::command]
async fn check_now(app: AppHandle) -> Result<Value, String> {
    blocking(move || {
        let _guard = gate(&app);
        let paired = read_connection(&app).map(|c| c.paired).unwrap_or(false);
        if paired {
            let output = run_collector(&app, Collector::Report, &[])?;
            if let Some(result) = parse_json(&output.stdout) {
                if result.get("report").map(Value::is_object).unwrap_or(false) {
                    return Ok(result);
                }
            }
            return Err(failure_message(&output));
        }
        let output = run_collector(&app, Collector::Status, &[])?;
        if !output.status.success() {
            return Err(failure_message(&output));
        }
        let report = parse_json(&output.stdout)
            .filter(Value::is_object)
            .ok_or_else(|| "Device Checker returned an unreadable result.".to_string())?;
        let checked_at = report
            .get("collected_at")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        Ok(json!({ "source": "manual", "checked_at": checked_at, "report": report, "delivery": "not_sent" }))
    })
    .await
}

/// The last persisted RunResult (manual or background), or `{"available": false}`.
#[tauri::command]
async fn last_report(app: AppHandle) -> Result<Value, String> {
    blocking(move || {
        let output = run_collector(&app, Collector::Last, &[])?;
        if !output.status.success() {
            return Err(failure_message(&output));
        }
        parse_json(&output.stdout).ok_or_else(|| "Device Checker returned an unreadable last report.".to_string())
    })
    .await
}

#[tauri::command]
async fn diagnose(app: AppHandle) -> Result<Value, String> {
    blocking(move || {
        let output = run_collector(&app, Collector::Diagnose, &[])?;
        if !output.status.success() {
            return Err(failure_message(&output));
        }
        let mut value = parse_json(&output.stdout).ok_or_else(|| "Device Checker returned unreadable diagnostics.".to_string())?;
        scrub(&mut value);
        Ok(value)
    })
    .await
}

#[tauri::command]
async fn connection_status(app: AppHandle) -> Result<Connection, String> {
    blocking(move || read_connection(&app)).await
}

#[tauri::command]
async fn connect_hackzero(app: AppHandle) -> Result<Connection, String> {
    // Browser login stays in the default browser. The app waits only for the
    // loopback callback, then receives a one-use code and no browser session.
    blocking(move || {
        let _guard = gate(&app);
        let server = std::env::var("HACKZERO_SERVER").unwrap_or_else(|_| "https://dashboard.hackzero.ai".into());
        let output = run_collector(&app, Collector::Pair, &["--server".to_string(), server])?;
        if !output.status.success() {
            return Err(failure_message(&output));
        }
        serde_json::from_slice(&output.stdout).map_err(|_| "Invalid pairing response.".to_string())
    })
    .await
}

fn disconnect(app: &AppHandle) -> Result<(), String> {
    let output = run_collector(app, Collector::Disconnect, &[])?;
    if !output.status.success() {
        return Err(failure_message(&output));
    }
    Ok(())
}

#[tauri::command]
async fn disconnect_hackzero(app: AppHandle) -> Result<Connection, String> {
    blocking(move || {
        let _guard = gate(&app);
        disconnect(&app)?;
        Ok(Connection { paired: false, workspace_name: None, person_name: None })
    })
    .await
}

#[derive(Serialize)]
struct Uninstall {
    platform: &'static str,
    local_data_removed: bool,
    local_data_path: Option<String>,
}

/// The collector's state directory: `os.UserConfigDir()/HackZero/DeviceChecker`.
/// Tauri's config_dir is the same base on every platform.
fn state_dir(app: &AppHandle) -> Option<PathBuf> {
    let base = app.path().config_dir().ok()?;
    if !base.is_absolute() {
        return None;
    }
    Some(base.join("HackZero").join("DeviceChecker"))
}

fn remove_state_dir(dir: &PathBuf) -> bool {
    match std::fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
        // Never follow a link: remove exactly this app's own directory.
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => false,
        Ok(_) => std::fs::remove_dir_all(dir).is_ok(),
    }
}

/// Disconnect (revokes this device with HackZero and deletes its identity),
/// stop starting at login, and delete the app's local state directory. The
/// app bundle itself is removed by the person (see the platform steps in UI).
#[tauri::command]
async fn uninstall_device_checker(app: AppHandle) -> Result<Uninstall, String> {
    blocking(move || {
        let _guard = gate(&app);
        disconnect(&app)?;
        {
            use tauri_plugin_autostart::ManagerExt;
            let _ = app.autolaunch().disable();
        }
        let dir = state_dir(&app);
        let removed = dir.as_ref().map(remove_state_dir).unwrap_or(false);
        Ok(Uninstall {
            platform: std::env::consts::OS,
            local_data_removed: removed,
            local_data_path: if removed { None } else { dir.map(|d| d.display().to_string()) },
        })
    })
    .await
}

#[cfg(target_os = "macos")]
fn app_bundle_path() -> PathBuf {
    let installed = PathBuf::from("/Applications/HackZero Device Checker.app");
    if installed.exists() {
        return installed;
    }
    // .../HackZero Device Checker.app/Contents/MacOS/<binary>
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.ancestors().nth(3).map(PathBuf::from))
        .filter(|bundle| bundle.extension().map(|ext| ext == "app").unwrap_or(false))
        .unwrap_or(installed)
}

/// Opens the place where the person finishes uninstalling. Fixed per platform.
#[tauri::command]
fn open_uninstall_location(app: AppHandle) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let _ = &app;
        Command::new("/usr/bin/open")
            .arg("-R")
            .arg(app_bundle_path())
            .spawn()
            .map(|_| ())
            .map_err(|_| "Could not open Finder.".to_string())
    }
    #[cfg(target_os = "windows")]
    {
        use tauri_plugin_opener::OpenerExt;
        app.opener()
            .open_url("ms-settings:appsfeatures", None::<&str>)
            .map_err(|_| "Could not open Installed apps.".to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = &app;
        Ok(())
    }
}

#[tauri::command]
fn quit_app(app: AppHandle) {
    app.exit(0);
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    // The page reloads the last saved result (a background tick may have run
    // while it was hidden) and re-checks for app updates if due.
    let _ = app.emit("window-shown", ());
}

/// One scheduler tick in a short-lived child, then tell the page to reload.
fn background_tick(app: &AppHandle) {
    let _guard = gate(app);
    let paired = read_connection(app).map(|c| c.paired).unwrap_or(false);
    if !paired {
        return;
    }
    // Failures are retried by the collector's durable queue on the next tick;
    // a network outage must never become a posture failure.
    let _ = run_collector(app, Collector::RunOnce, &[]);
    let _ = app.emit("report-updated", ());
}

/// The Tauri process is the resident tray host. It runs the collector's
/// scheduler tick once an hour. The first tick waits a full interval: the
/// launch check already sent a report. A long gap between loop iterations
/// means the computer slept; then the page reloads and a catch-up tick runs.
fn background_loop(app: AppHandle) {
    let mut last_wall = SystemTime::now();
    let mut next_tick = last_wall + BACKGROUND_EVERY;
    loop {
        std::thread::sleep(BACKGROUND_POLL);
        let now = SystemTime::now();
        let gap = now.duration_since(last_wall).unwrap_or_default();
        last_wall = now;
        if gap > WAKE_GAP {
            let _ = app.emit("system-resumed", ());
            next_tick = now + AFTER_WAKE_DELAY;
        }
        // The clock moved backwards (manual change): do not wait longer than one interval.
        if next_tick.duration_since(now).map(|wait| wait > BACKGROUND_EVERY).unwrap_or(false) {
            next_tick = now + BACKGROUND_EVERY;
        }
        if now >= next_tick {
            next_tick = now + BACKGROUND_EVERY;
            background_tick(&app);
        }
    }
}

fn main() {
    let launch_in_background = std::env::args().any(|arg| arg == "--background");
    tauri::Builder::default()
        // A second launch focuses the resident checker instead of making
        // another scheduler/reporting process. This also prevents duplicate
        // tray icons at login.
        .plugin(tauri_plugin_single_instance::init(|app, _, _| show_main_window(app)))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--background"]),
        ))
        .manage(CollectorGate(Mutex::new(())))
        .setup(move |app| {
            // The manifest prompts before this in a normal Windows build. This
            // prevents a malformed launcher from ever presenting partial
            // posture as a legitimate assessment.
            if cfg!(target_os = "windows") && !is_elevated() {
                app.handle().exit(1);
                return Ok(());
            }
            let show = MenuItem::with_id(app, "show", "Open Device Checker", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::new()
                // An explicit icon is required: without it Windows can create
                // an empty/invisible tray entry during development.
                .icon(app.default_window_icon().expect("application icon is bundled").clone())
                .tooltip("HackZero Device Checker")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            if launch_in_background {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            let handle = app.handle().clone();
            std::thread::spawn(move || background_loop(handle));
            Ok(())
        })
        .on_window_event(move |window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            check_now,
            last_report,
            diagnose,
            connection_status,
            connect_hackzero,
            disconnect_hackzero,
            uninstall_device_checker,
            open_uninstall_location,
            quit_app
        ])
        .run(tauri::generate_context!())
        .expect("Tauri application error");
}
