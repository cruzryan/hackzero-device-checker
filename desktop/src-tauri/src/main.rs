#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[derive(Serialize)]
struct Finding {
    check: String,
    status: String,
    reason: Option<String>,
}
#[derive(Serialize)]
struct Report {
    checked_at: String,
    findings: Vec<Finding>,
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

fn checker_report() -> Report {
    // The only child process this UI is permitted to start is its sibling checker
    // with the fixed `status` argument. No UI text ever becomes a shell command.
    let output = Command::new(checker_path()).arg("status").output();
    if let Ok(result) = output {
        if result.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&result.stdout) {
                let findings = json
                    .get("findings")
                    .and_then(|x| x.as_array())
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|f| {
                                Some(Finding {
                                    check: f.get("check")?.as_str()?.to_string(),
                                    status: f.get("status")?.as_str()?.to_string(),
                                    reason: f
                                        .get("reason")
                                        .and_then(|x| x.as_str())
                                        .map(str::to_string),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_else(unavailable_findings);
                return Report {
                    checked_at: json
                        .get("checked_at")
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
        findings: unavailable_findings(),
    }
}

fn checker_path() -> PathBuf {
    // An installed build will resolve this from its bundled resources. During
    // development this fixed path points at the checked-in Windows collector.
    // An environment override is for packaging/CI only; it never comes from UI.
    if let Some(path) = std::env::var_os("HACKZERO_CHECKER_BIN") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../bin/device-checker-windows-amd64.exe")
}
fn chrono_like_now() -> String {
    chrono::Utc::now().to_rfc3339()
}
#[tauri::command]
fn check_now() -> Report {
    checker_report()
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let show = MenuItem::with_id(app, "show", "Open Device Checker", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::new()
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
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![check_now])
        .run(tauri::generate_context!())
        .expect("Tauri application error");
}
