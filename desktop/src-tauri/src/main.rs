#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

// The Go collector communicates through captured stdout/stderr. Its short
// checks must never create a visible console window on Windows.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Serialize)]
struct Finding {
    check: String,
    status: String,
    reason: Option<String>,
}
#[derive(Serialize)]
struct Report {
    checked_at: String,
    platform: String,
    findings: Vec<Finding>,
}

#[derive(Deserialize, Serialize)]
struct Connection {
    paired: bool,
    workspace_name: Option<String>,
    person_name: Option<String>,
}

fn unavailable_findings() -> Vec<Finding> {
    vec![
        Finding {
            check: "disk_encryption".into(),
            status: "unknown".into(),
            reason: Some("checker_not_installed".into()),
        },
        Finding {
            check: "screen_lock".into(),
            status: "unknown".into(),
            reason: None,
        },
        Finding {
            check: "automatic_updates".into(),
            status: "unknown".into(),
            reason: None,
        },
        Finding {
            check: "pending_updates".into(),
            status: "unknown".into(),
            reason: None,
        },
        Finding {
            check: "endpoint_protection".into(),
            status: "unknown".into(),
            reason: None,
        },
    ]
}

fn checker_report(app: &tauri::AppHandle) -> Report {
    // The only child process this UI is permitted to start is its sibling checker
    // with the fixed `status` argument. No UI text ever becomes a shell command.
    let output = checker_command(app).arg("status").output();
    if let Ok(result) = output {
        if result.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&result.stdout) {
                // The Go collector exposes a deliberately named report schema,
                // rather than an untyped array. Keep this adapter fixed and
                // explicit so a UI value can never select a command or field.
                let findings = [
                    ("disk_encryption", "disk_encryption"),
                    ("screen_lock", "screen_lock"),
                    ("automatic_updates", "automatic_updates"),
                    ("pending_updates", "pending_maintenance"),
                    ("endpoint_protection", "endpoint_protection"),
                ]
                .into_iter()
                .filter_map(|(check, field)| {
                    let signal = json.get(field)?;
                    Some(Finding {
                        check: check.to_string(),
                        status: signal.get("status")?.as_str()?.to_string(),
                        reason: signal
                            .get("code")
                            .and_then(|x| x.as_str())
                            .map(str::to_string),
                    })
                })
                .collect::<Vec<_>>();
                let findings = if findings.is_empty() { unavailable_findings() } else { findings };
                return Report {
                    checked_at: json
                        .get("collected_at")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    platform: json
                        .get("platform")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    findings,
                };
            }
        }
    }
    Report {
        checked_at: chrono_like_now(),
        platform: String::new(),
        findings: unavailable_findings(),
    }
}

fn checker_connection(app: &tauri::AppHandle) -> Connection {
    let output = checker_command(app).arg("connection").output();
    output.ok().and_then(|result| serde_json::from_slice(&result.stdout).ok()).unwrap_or(Connection {
        paired: false, workspace_name: None, person_name: None,
    })
}

fn checker_path(app: &tauri::AppHandle) -> PathBuf {
    // An installed build will resolve this from its bundled resources. During
    // development this fixed path points at the checked-in Windows collector.
    // An environment override is for packaging/CI only; it never comes from UI.
    if let Some(path) = std::env::var_os("HACKZERO_CHECKER_BIN") {
        return PathBuf::from(path);
    }
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../bin/device-checker-windows-amd64.exe");
    if cfg!(debug_assertions) && development.exists() { return development; }
    let bundled_name = if cfg!(target_os = "windows") {
        "device-checker-windows-amd64.exe"
    } else if cfg!(target_os = "macos") {
        "device-checker-macos-arm64"
    } else {
        "device-checker-linux-amd64"
    };
    app.path().resource_dir().expect("application resources are available").join(bundled_name)
}

fn checker_command(app: &tauri::AppHandle) -> Command {
    let mut command = Command::new(checker_path(app));
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);
    command
}
fn chrono_like_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[tauri::command]
fn check_now(app: tauri::AppHandle) -> Report {
    checker_report(&app)
}

#[tauri::command]
fn connection_status(app: tauri::AppHandle) -> Connection { checker_connection(&app) }

#[tauri::command]
async fn connect_hackzero(app: tauri::AppHandle) -> Result<Connection, String> {
    // Browser login stays in the default browser. The app waits only for the
    // loopback callback, then receives a one-use code and no browser session.
    tauri::async_runtime::spawn_blocking(move || {
        let output = checker_command(&app)
            .arg("pair")
            .arg("--server")
            .arg(std::env::var("HACKZERO_SERVER").unwrap_or_else(|_| "https://dashboard.hackzero.ai".into()))
            .output()
            .map_err(|error| format!("Could not start Device Checker: {error}"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }
        serde_json::from_slice(&output.stdout).map_err(|error| format!("Invalid pairing response: {error}"))
    }).await.map_err(|error| error.to_string())?
}

#[tauri::command]
async fn background_tick(app: tauri::AppHandle) -> Result<(), String> {
    // The Tauri process is the resident, signed tray host. A short-lived child
    // performs one durable scheduler tick, so there is no second daemon to
    // manage and no terminal window on any supported desktop platform.
    tauri::async_runtime::spawn_blocking(move || {
        let output = checker_command(&app)
            .arg("run")
            .arg("--once")
            .output()
            .map_err(|error| format!("Could not run background check: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }).await.map_err(|error| error.to_string())?
}

fn main() {
    let launch_in_background = std::env::args().any(|arg| arg == "--background");
    tauri::Builder::default()
        // A second launch should focus the resident checker instead of making
        // another scheduler/reporting process. This also prevents duplicate
        // tray icons at login.
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--background"]),
        ))
        .setup(move |app| {
            let show = MenuItem::with_id(app, "show", "Open Device Checker", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::new()
                // An explicit icon is required: without it Windows can create
                // an empty/invisible tray entry during development.
                .icon(
                    app.default_window_icon()
                        .expect("application icon is bundled")
                        .clone(),
                )
                .tooltip("HackZero Device Checker — local checks active")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            if launch_in_background {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
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
            connection_status,
            connect_hackzero,
            background_tick
        ])
        .run(tauri::generate_context!())
        .expect("Tauri application error");
}
