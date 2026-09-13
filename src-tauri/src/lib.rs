mod audit;
mod regulatory_store;
mod db;

use std::sync::{Arc, Mutex};
use std::process::Command;
use tauri::{command, WindowEvent};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::CommandChild;

#[derive(Clone)]
struct ServerState {
    child: Arc<Mutex<Option<CommandChild>>>,
}

#[command]
fn get_pci_requirement_controls(requirement_number: Option<u32>, requirementNumber: Option<u32>) -> Result<Option<regulatory_store::PciRequirementGroup>, String> {
    let id = requirement_number.or(requirementNumber).unwrap_or(1);
    Ok(regulatory_store::get_pci_requirement(id))
}

#[command]
async fn run_pci_control_audit(
    evidence: String, 
    requirement_number: Option<u32>, 
    requirementNumber: Option<u32>, 
    control_id: Option<String>,
    controlId: Option<String>
) -> Result<audit::SingleAuditResult, String> {
    let req_id = requirement_number.or(requirementNumber).unwrap_or(1);
    let ctrl_id = control_id.or(controlId).ok_or("control_id missing")?;
    audit::query_pci_single_control(&evidence, req_id, &ctrl_id)
        .await
        .map_err(|e| e.to_string())
}

#[command]
fn export_single_control_dossier(payload: audit::SingleExportPayload) -> Result<audit::ExportResponse, String> {
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
fn open_pdf_file(file_path: Option<String>, filePath: Option<String>) -> Result<(), String> {
    let target = file_path.or(filePath).ok_or("No file path provided")?;
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(&target)
            .spawn()
            .map_err(|e| format!("Failed to open file: {}", e))?;
    }
    Ok(())
}

#[command]
fn reset_llama_knowledge_base(password: String) -> Result<String, String> {
    const ADMIN_PASSWORD: &str = "AdminSecret123!";
    if password != ADMIN_PASSWORD {
        return Err("Unauthorized: Incorrect admin password.".into());
    }
    Ok("Llama knowledge base successfully reset.".into())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LoginResponse {
    success: bool,
    is_first_login: bool,
    role: String,
    message: String,
}

#[command]
fn authenticate_user(username: String, password: String) -> Result<LoginResponse, String> {
    let conn = db::get_connection().map_err(|e| e.to_string())?;
    
    // Fetch password, first login flag, role, and creation timestamp
    let mut stmt = conn.prepare("SELECT password, is_first_login, role, created_at FROM users WHERE username = ?")
        .map_err(|e| e.to_string())?;
    
    let mut rows = stmt.query([&username]).map_err(|e| e.to_string())?;
    
    if let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let db_pass: String = row.get(0).map_err(|e| e.to_string())?;
        let is_first: bool = row.get(1).map_err(|e| e.to_string())?;
        let role: String = row.get(2).map_err(|e| e.to_string())?;
        let created_at: String = row.get(3).map_err(|e| e.to_string())?;
        
        // Verify Password first
        if db_pass != password {
            return Ok(LoginResponse {
                success: false,
                is_first_login: false,
                role: "".into(),
                message: "Incorrect password.".into(),
            });
        }

        // Check 7-day expiration specifically for 'demo' accounts
        if role == "demo" {
            // Parse created_at string (SQLite format: "YYYY-MM-DD HH:MM:SS")
            if let Ok(parsed_time) = chrono::NaiveDateTime::parse_from_str(&created_at, "%Y-%m-%d %H:%M:%S") {
                let now = chrono::Utc::now().naive_utc();
                let duration = now.signed_duration_since(parsed_time);
                
                // 7 days in seconds = 7 * 24 * 60 * 60 = 604,800 seconds
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
fn get_machine_hardware_id() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ioreg")
            .args(["-c", "IOPlatformExpertDevice", "-d", "2"])
            .output()
            .map_err(|e| format!("Failed to query macOS hardware: {}", e))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("IOPlatformUUID") {
                let parts: Vec<&str> = line.split('"').collect();
                if parts.len() >= 4 {
                    return Ok(parts[3].to_string());
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("powershell")
            .args(["-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"])
            .output()
            .map_err(|e| format!("Failed to query Windows hardware UUID: {}", e))?;
        
        let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !uuid.is_empty() && uuid != "00000000-0000-0000-0000-000000000000" {
            return Ok(uuid);
        }
    }
    
    Ok("PCISENTINEL-FALLBACK-HWID".to_string())
}

fn detect_hypervisor() -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ioreg").args(["-l"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("VMware") || stdout.contains("VirtualBox") || stdout.contains("Parallels") || stdout.contains("QEMU") {
                return true;
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("powershell")
            .args(["-Command", "(Get-CimInstance Win32_ComputerSystem).Manufacturer"])
            .output() 
        {
            let mfr = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if mfr.contains("vmware") || mfr.contains("virtualbox") || mfr.contains("qemu") || mfr.contains("xen") {
                return true;
            }
        }

        // Also check model string for Hyper-V or general virtualization
        if let Ok(output) = std::process::Command::new("powershell")
            .args(["-Command", "(Get-CimInstance Win32_ComputerSystem).Model"])
            .output() 
        {
            let model = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if model.contains("virtual") || model.contains("kvm") {
                return true;
            }
        }
    }

    false
}




#[command]
fn activate_subscription_key(username: String, license_key: String) -> Result<String, String> {
    if !license_key.starts_with("PCI-SUB-") {
        return Err("Invalid subscription key format.".into());
    }

    // Block standard keys on virtual machines to prevent clone exploitation
    if detect_hypervisor() {
        return Err("Activation Denied: Standard consumer subscriptions cannot be activated inside virtual machines. Contact support for Enterprise Node licenses.".into());
    }

    let hwid = get_machine_hardware_id()?;
    let expected_signature_stub = &hwid[..8.min(hwid.len())];
    
    if !license_key.contains(expected_signature_stub) {
        return Err("License Activation Failed: This key is bound to a different hardware device.".into());
    }

    let conn = db::get_connection().map_err(|e| e.to_string())?;
    conn.execute(
        "UPDATE users SET role = 'subscriber' WHERE username = ?",
        [&username],
    ).map_err(|e| e.to_string())?;

    Ok("Subscription activated successfully! Full multi-control access unlocked.".into())
}

#[command]
fn update_password(username: String, new_password: String) -> Result<String, String> {
    let conn = db::get_connection().map_err(|e| e.to_string())?;
    conn.execute(
        "UPDATE users SET password = ?, is_first_login = 0 WHERE username = ?",
        [&new_password, &username],
    ).map_err(|e| e.to_string())?;
    
    Ok("Password updated successfully. First login completed.".into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let child_handle = Arc::new(Mutex::new(None));
    let server_state = ServerState {
        child: Arc::clone(&child_handle),
    };

    let exit_child_handle = Arc::clone(&child_handle);

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(server_state)
        .setup(move |app| {
            if let Err(e) = db::init_database() {
                eprintln!("[DB Error] Failed to initialize SQLite audit store: {}", e);
            } else {
                println!("✓ PCI-Sentinel SQLite audit store initialized");
            }

            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let candidate_paths = [
                format!("{}/pci-sentinel/src-tauri/bin/models/qwen2.5-7b-instruct-q4_k_m.gguf", home),
                format!("{}/grc-sentinel/src-tauri/bin/models/qwen2.5-7b-instruct-q4_k_m.gguf", home),
                format!("{}/models/qwen2.5-7b-instruct-q4_k_m.gguf", home),
            ];

            let model_path = candidate_paths
                .iter()
                .find(|p| std::path::Path::new(p).exists())
                .cloned()
                .unwrap_or_else(|| candidate_paths[1].clone());

            let sidecar_command = app
                .shell()
                .sidecar("llama-server")
                .map_err(|e| format!("Failed to configure sidecar: {}", e))?
                .args([
                    "-m",
                    &model_path,
                    "-c",
                    "4096",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "8090",
                    "-ngl",
                    "99",
                    "--no-ui",
                    "--api-key",
                    audit::INTERNAL_ENCLAVE_TOKEN,
                ]);

            let (_rx, child) = sidecar_command
                .spawn()
                .map_err(|e| format!("Failed to spawn llama-server: {}", e))?;

            if let Ok(mut guard) = child_handle.lock() {
                *guard = Some(child);
            }

            println!("✓ PCI-Sentinel inference engine active on 127.0.0.1:8090");
            Ok(())
        })
        .on_window_event(move |_window, event| {
            if let WindowEvent::Destroyed = event {
                if let Ok(mut guard) = exit_child_handle.lock() {
                    if let Some(child) = guard.take() {
                        let _ = child.kill();
                        println!("✓ llama-server terminated cleanly.");
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
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
            activate_subscription_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}