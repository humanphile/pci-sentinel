pub mod build_meta {
    include!(concat!(env!("OUT_DIR"), "/build_meta.rs"));
}
pub mod licensing;

mod audit;
mod bootstrap;
mod db;
mod regulatory_store;
mod server;

use server::{start_inference_server, stop_inference_server};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tauri::{command, Emitter, Manager, RunEvent};

// 1. Define a thread-safe session state
#[derive(Default, Clone)]
struct ActiveSession {
    username: Arc<Mutex<String>>,
}

/// Purge any stray llama-server processes (e.g., orphans from a crashed run).
fn kill_stray_llama() {
    #[cfg(target_os = "macos")]
    let _ = Command::new("sh")
        .arg("-c")
        .arg("pkill -9 llama-server || true")
        .status();
    #[cfg(target_os = "windows")]
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", "llama-server.exe"])
        .status();
    #[cfg(target_os = "linux")]
    let _ = Command::new("sh")
        .arg("-c")
        .arg("pkill -9 llama-server || true")
        .status();
}

#[command]
fn get_pci_requirement_controls(
    requirement_number: Option<u32>,
) -> Result<Option<regulatory_store::PciRequirementGroup>, String> {
    let id = requirement_number.unwrap_or(1);
    Ok(regulatory_store::get_pci_requirement(id))
}

// 2. Update authenticate_user to set this session upon successful login
#[command]
fn authenticate_user(
    username: String,
    password: String,
    state: tauri::State<ActiveSession>,
) -> Result<LoginResponse, String> {
    let conn = db::get_connection().map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare("SELECT password, is_first_login, role, created_at FROM users WHERE username = ?")
        .map_err(|e| e.to_string())?;

    let mut rows = stmt.query([&username]).map_err(|e| e.to_string())?;

    if let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let db_pass: String = row.get(0).map_err(|e| e.to_string())?;
        let is_first: bool = row.get(1).map_err(|e| e.to_string())?;
        let role: String = row.get(2).map_err(|e| e.to_string())?;
        let created_at: String = row.get(3).map_err(|e| e.to_string())?;

        if !db::verify_password(&password, &db_pass) {
            return Ok(LoginResponse {
                success: false,
                is_first_login: false,
                role: "".into(),
                message: "Incorrect password.".into(),
            });
        }

        // Transparently upgrade legacy plaintext passwords to the hashed
        // format on the next successful login from an older database.
        if !db::is_hashed_password(&db_pass) {
            let _ = conn.execute(
                "UPDATE users SET password = ?1 WHERE username = ?2",
                rusqlite::params![db::hash_password(&password), &username],
            );
        }

        if role == "demo" {
            if let Ok(parsed_time) =
                chrono::NaiveDateTime::parse_from_str(&created_at, "%Y-%m-%d %H:%M:%S")
            {
                let now = chrono::Utc::now().naive_utc();
                let duration = now.signed_duration_since(parsed_time);

                if duration.num_seconds() > 604_800 {
                    return Ok(LoginResponse {
                        success: false,
                        is_first_login: false,
                        role: "".into(),
                        message: "Trial Expired: Your 7-day demo period has elapsed. Please activate a subscription key.".into(),
                    });
                }
            }
        }

        // Securely bind active session username
        let mut session_user = state.username.lock().unwrap();
        *session_user = username;

        Ok(LoginResponse {
            success: true,
            is_first_login: is_first,
            role,
            message: "Authentication successful.".into(),
        })
    } else {
        Ok(LoginResponse {
            success: false,
            is_first_login: false,
            role: "".into(),
            message: "User not found.".into(),
        })
    }
}

#[command]
async fn run_pci_control_audit(
    evidence: String,
    requirement_number: Option<u32>,
    control_id: Option<String>,
    state: tauri::State<'_, ActiveSession>,
) -> Result<audit::SingleAuditResult, String> {
    let req_id = requirement_number.unwrap_or(1);
    let ctrl_id = control_id.ok_or("control_id missing")?;

    let username = {
        let guard = state.username.lock().unwrap();
        if guard.is_empty() {
            "demo".to_string()
        } else {
            guard.clone()
        }
    };

    // Strict Database Role & Trial Enforcement
    {
        let conn = db::get_connection().map_err(|e| e.to_string())?;

        let mut role_stmt = conn
            .prepare("SELECT role FROM users WHERE username = ?")
            .map_err(|e| e.to_string())?;
        let user_role: String = role_stmt
            .query_row([&username], |row| row.get(0))
            .unwrap_or_else(|_| "demo".to_string());

        if user_role == "demo" {
            // Check distinct controls already evaluated by THIS user for THIS
            // specific requirement number. Legacy records without an owner
            // (pre-attribution databases) are conservatively attributed so the
            // demo limitation cannot be bypassed by data written earlier.
            let mut hist_stmt = conn
                .prepare(
                    "SELECT DISTINCT control_id FROM audit_records \
                 WHERE requirement_number = ?1 AND (username = ?2 OR username = '')",
                )
                .map_err(|e| e.to_string())?;

            let tested_controls: Result<Vec<String>, _> = hist_stmt
                .query_map(rusqlite::params![req_id, &username], |row| row.get(0))
                .map(|iter| iter.flatten().collect());

            if let Ok(controls) = tested_controls {
                // If a control was already evaluated for this requirement, and the user is trying a DIFFERENT control ID
                if !controls.is_empty() && !controls.contains(&ctrl_id) {
                    return Err(format!(
                        "Demo Limitation: Trial accounts are restricted to evaluating only 1 control per requirement. You have already evaluated control '{}' for Requirement {}. Please activate your subscription license to test additional controls.",
                        controls[0], req_id
                    ));
                }
            }
        }
    }

    audit::query_pci_single_control(&username, &evidence, req_id, &ctrl_id)
        .await
        .map_err(|e| e.to_string())
}

#[command]
fn secure_shutdown() -> Result<(), String> {
    kill_stray_llama();
    std::process::exit(0);
}

#[command]
fn export_single_control_dossier(
    payload: audit::SingleExportPayload,
) -> Result<audit::ExportResponse, String> {
    audit::generate_single_signed_pdf(&payload)
}

#[command]
fn export_pci_dossier(payload: audit::BatchExportPayload) -> Result<audit::ExportResponse, String> {
    audit::generate_pci_signed_pdf(&payload)
}

#[command]
fn verify_pci_dossier(payload: audit::BatchVerificationPayload) -> Result<bool, String> {
    audit::verify_pci_signature(&payload)
}

#[command]
fn get_pci_audit_history() -> Result<Vec<db::AuditRecord>, String> {
    db::fetch_audit_history()
}

#[command]
fn open_pdf_file(file_path: Option<String>) -> Result<(), String> {
    let target = file_path.ok_or("No file path provided")?;

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(&target)
            .spawn()
            .map_err(|e| format!("Failed to open file: {}", e))?;
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", &target])
            .spawn()
            .map_err(|e| format!("Failed to open file: {}", e))?;
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(&target)
            .spawn()
            .map_err(|e| format!("Failed to open file: {}", e))?;
    }

    Ok(())
}

#[command]
fn reset_llama_knowledge_base(password: String) -> Result<String, String> {
    let conn = db::get_connection().map_err(|e| e.to_string())?;

    let hwid = licensing::get_machine_hardware_id();

    let mut stmt = conn
        .prepare("SELECT value FROM enclave_meta WHERE key = 'admin_reset_pass'")
        .map_err(|e| e.to_string())?;

    let expected_pass = match stmt.query_row([], |row| row.get::<_, String>(0)) {
        Ok(p) => p,
        Err(_) => {
            // Derived from the same formula as the sentinel-licenser CLI. The
            // derived value is persisted so both sides stay in lock-step.
            let short_pass = licensing::admin_reset_password(&hwid);

            conn.execute(
                "INSERT OR REPLACE INTO enclave_meta (key, value) VALUES ('admin_reset_pass', ?)",
                [short_pass.clone()],
            )
            .map_err(|e| e.to_string())?;

            short_pass
        }
    };

    if password != expected_pass {
        return Err("Unauthorized: Incorrect hardware-bound admin password.".into());
    }

    Ok("Llama knowledge base successfully reset via hardware-bound authorization.".into())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LoginResponse {
    success: bool,
    is_first_login: bool,
    role: String,
    message: String,
}

#[command]
fn get_machine_hardware_id() -> Result<String, String> {
    Ok(licensing::get_machine_hardware_id())
}

#[command]
fn update_password(
    username: String,
    old_password: Option<String>,
    new_password: String,
) -> Result<String, String> {
    if new_password.len() < 8 {
        return Err("Password complexity failed: Must be at least 8 characters long.".into());
    }

    let has_letter = new_password.chars().any(|c| c.is_alphabetic());
    let has_digit = new_password.chars().any(|c| c.is_numeric());
    let has_special = new_password.chars().any(|c| !c.is_alphanumeric());

    if !has_letter || !has_digit || !has_special {
        return Err("Password complexity failed: Must contain letters, numbers, and at least one special character.".into());
    }

    let conn = db::get_connection().map_err(|e| e.to_string())?;

    if let Some(old_pass) = old_password {
        let mut stmt = conn
            .prepare("SELECT password FROM users WHERE username = ?")
            .map_err(|e| e.to_string())?;
        let db_pass: String = stmt
            .query_row([&username], |row| row.get(0))
            .map_err(|_| "User not found.".to_string())?;

        if !db::verify_password(&old_pass, &db_pass) {
            return Err("Incorrect current password provided.".into());
        }
    }

    conn.execute(
        "UPDATE users SET password = ?, is_first_login = 0 WHERE username = ?",
        rusqlite::params![db::hash_password(&new_password), &username],
    )
    .map_err(|e| e.to_string())?;

    Ok("Password updated successfully.".into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(server::ServerProcess(Mutex::new(None)))
        .manage(ActiveSession::default())
        .setup(move |app| {
            // Clean up any orphaned llama-server from a previous crash/run.
            kill_stray_llama();

            if let Err(e) = db::init_database() {
                eprintln!("[DB Error] Failed to initialize SQLite audit store: {}", e);
            } else {
                println!("✓ Sentinel GRC SQLite audit store initialized");
            }

            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = bootstrap::ensure_inference_runtime(app_handle.clone()).await {
                    eprintln!("[Bootstrap Error] Failed to ensure runtime assets: {}", e);
                    let _ =
                        app_handle.emit("bootstrap-error", format!("Runtime setup failed: {}", e));
                    return;
                }

                let state = app_handle.state::<server::ServerProcess>();
                if let Err(e) = server::start_inference_server(app_handle.clone(), state).await {
                    eprintln!(
                        "[Server Error] Failed to auto-start inference server: {}",
                        e
                    );
                    let _ = app_handle.emit(
                        "bootstrap-error",
                        format!("Inference server failed to start: {}", e),
                    );
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            bootstrap::ensure_inference_runtime,
            start_inference_server,
            stop_inference_server,
            secure_shutdown,
            get_pci_requirement_controls,
            run_pci_control_audit,
            export_single_control_dossier,
            export_pci_dossier,
            verify_pci_dossier,
            get_pci_audit_history,
            open_pdf_file,
            reset_llama_knowledge_base,
            authenticate_user,
            update_password,
            get_machine_hardware_id,
            licensing::activate_subscription_key
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(move |app_handle, event| {
        if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
            // Gracefully terminate our tracked llama-server child first, then
            // purge any strays from earlier crashed runs.
            if let Some(state) = app_handle.try_state::<server::ServerProcess>() {
                if let Ok(mut guard) = state.0.lock() {
                    if let Some(mut child) = guard.take() {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                }
            }
            kill_stray_llama();
            println!("✓ Guardian: llama-server successfully purged on exit.");
        }
    });
}
