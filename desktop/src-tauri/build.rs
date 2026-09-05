#[cfg(target_os = "windows")]
fn main() {
    // Device posture is a privileged local-security check. Windows owns the
    // consent prompt: if the person declines it, process creation is aborted
    // and there is no partially-functional checker window.
    let windows = tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest"));
    let attributes = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attributes).expect("failed to build Tauri application");
}

#[cfg(not(target_os = "windows"))]
fn main() {
    tauri_build::build()
}
