use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};

use crate::bootstrap::{LEGACY_MODEL_FILENAME, MODEL_FILENAME};

pub struct ServerProcess(pub Mutex<Option<Child>>);

impl Drop for ServerProcess {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.0.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// Purge any stray llama-server processes (e.g., orphans from a crashed run).
/// Kept coarse and blunt on purpose: the guarantee that only one inference
/// engine ever survives is more important than surgical precision.
pub(crate) fn kill_stray_llama() {
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

/// Detect whether the local hardware can run the model comfortably.
#[derive(Clone, Debug)]
pub struct HardwareProfile {
    pub total_ram_bytes: u64,
    pub physical_cores: u32,
}

/// Safety margin reserved on top of the model file size to cover the OS,
/// the 4K-token KV cache, and Metal/GPU buffers.
const RAM_OVERHEAD_BYTES: u64 = 3 * 1024 * 1024 * 1024;
/// Minimum physical cores required (llama.cpp is usable below this but
/// evaluations become impractically slow).
const MIN_PHYSICAL_CORES: u32 = 4;
/// The 3B Q4_K_M file is ~2.1 GB; used to decide whether to even download it
/// before the file exists on disk (weak machines skip straight to 0.5B).
pub const QWEN_3B_NOMINAL_BYTES: u64 = 2_200_000_000;

pub fn collect_hardware_profile() -> HardwareProfile {
    use sysinfo::{MemoryRefreshKind, RefreshKind, System};

    let sys = System::new_with_specifics(
        RefreshKind::nothing().with_memory(MemoryRefreshKind::everything()),
    );
    HardwareProfile {
        total_ram_bytes: sys.total_memory(),
        physical_cores: sys
            .physical_core_count()
            .map(|n| n as u32)
            .unwrap_or(0),
    }
}

/// A model can run when the machine has its file size plus the safety margin
/// in RAM and at least the minimum number of physical cores.
pub fn model_capable(profile: &HardwareProfile, model_bytes: u64) -> bool {
    profile.total_ram_bytes >= model_bytes.saturating_add(RAM_OVERHEAD_BYTES)
        && profile.physical_cores >= MIN_PHYSICAL_CORES
}

/// The chosen inference model for this machine.
pub struct RuntimeModelChoice {
    pub model_path: PathBuf,
    /// Filename of the selected GGUF (e.g. `qwen2.5-3b-instruct-q4_k_m.gguf`).
    pub model_name: String,
    /// `"ok"` = full-size model, `"hardware"` = downgraded due to weak
    /// hardware, `"missing"` = downgraded because full-size weights absent.
    pub reason: &'static str,
    /// Human-readable explanation surfaced to the user in dialogs/logs.
    pub message: String,
}

/// Pick the model to serve: the 3B weights when they exist AND the machine is
/// capable; otherwise the lightweight 0.5B fallback.
pub fn choose_runtime_model(app: &AppHandle) -> Result<RuntimeModelChoice, String> {
    let profile = collect_hardware_profile();
    let app_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let preferred = app_dir.join(MODEL_FILENAME);
    let legacy = app_dir.join(LEGACY_MODEL_FILENAME);

    let preferred_bytes = fs::metadata(&preferred).map(|m| m.len()).unwrap_or(0);
    let legacy_bytes = fs::metadata(&legacy).map(|m| m.len()).unwrap_or(0);
    let ram_gb = profile.total_ram_bytes / (1024 * 1024 * 1024);

    if preferred_bytes > 0 && model_capable(&profile, preferred_bytes) {
        Ok(RuntimeModelChoice {
            model_path: preferred,
            model_name: MODEL_FILENAME.to_string(),
            reason: "ok",
            message: format!(
                "Hardware sufficient: {} GB RAM, {} physical cores — running {}.",
                ram_gb, profile.physical_cores, MODEL_FILENAME
            ),
        })
    } else if legacy_bytes > 0 {
        if preferred_bytes > 0 {
            let required_gb = (preferred_bytes + RAM_OVERHEAD_BYTES) / (1024 * 1024 * 1024);
            Ok(RuntimeModelChoice {
                model_path: legacy,
                model_name: LEGACY_MODEL_FILENAME.to_string(),
                reason: "hardware",
                message: format!(
                    "This machine has {ram_gb} GB RAM and {} physical CPU cores, but running {} needs at least ~{required_gb} GB RAM and {MIN_PHYSICAL_CORES} cores. The enclave has switched to the lighter Qwen 2.5 0.5B model — the software may not be able to generate the desired results.",
                    profile.physical_cores, MODEL_FILENAME
                ),
            })
        } else {
            Ok(RuntimeModelChoice {
                model_path: legacy,
                model_name: LEGACY_MODEL_FILENAME.to_string(),
                reason: "missing",
                message: format!(
                    "{} is not downloaded; using the legacy {} model.",
                    MODEL_FILENAME, LEGACY_MODEL_FILENAME
                ),
            })
        }
    } else {
        Err(format!(
            "Runtime model missing: neither {} nor {} found. Run ensure_inference_runtime first.",
            MODEL_FILENAME, LEGACY_MODEL_FILENAME
        ))
    }
}

fn spawn_inference_child(app: &AppHandle) -> Result<Child, String> {
    let app_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let is_windows = std::env::consts::OS == "windows";
    let binary_name = if is_windows {
        "llama-server.exe"
    } else {
        "llama-server"
    };
    let binary_path = app_dir.join("bin").join(binary_name);

    if !binary_path.exists() {
        return Err("Runtime assets missing. Run ensure_inference_runtime first.".into());
    }

    let choice = choose_runtime_model(app)?;
    if choice.reason != "ok" {
        println!("⚠️  {}", choice.message);
    }
    println!("Using model: {}", choice.model_path.display());
    println!("Spawning llama-server from: {}", binary_path.display());

    Command::new(&binary_path)
        .arg("-m")
        .arg(&choice.model_path)
        .arg("--port")
        .arg("8090")
        .arg("--host")
        .arg("127.0.0.1")
        .arg("-c")
        .arg("4096") // Explicit context size to prevent default allocation spikes
        .stdout(Stdio::inherit()) // Pipe server logs directly to your terminal
        .stderr(Stdio::inherit()) // Pipe server errors directly to your terminal
        .spawn()
        .map_err(|e| format!("Failed to spawn llama-server: {}", e))
}

#[tauri::command]
pub async fn start_inference_server(
    app: AppHandle,
    state: State<'_, ServerProcess>,
) -> Result<u16, String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    if guard.is_some() {
        return Ok(8090);
    }

    let child = spawn_inference_child(&app)?;
    *guard = Some(child);
    Ok(8090)
}

/// Wait until llama-server answers /health, up to `timeout_secs`.
async fn wait_until_healthy(timeout_secs: u64) -> Result<(), String> {
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        match client.get("http://127.0.0.1:8090/health").send().await {
            Ok(res) if res.status().is_success() => return Ok(()),
            _ => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
        }
    }
    Err("Timed out waiting for the inference engine to become healthy after restart.".into())
}

/// Kill the current inference engine process and spawn a fresh one, then wait
/// until it answers /health. This truly "flushes" the LLM's retained context /
/// KV cache so the next audit starts from a clean knowledge base.
#[tauri::command]
pub async fn restart_inference_server(
    app: AppHandle,
    state: State<'_, ServerProcess>,
) -> Result<u16, String> {
    {
        let mut guard = state.0.lock().map_err(|e| e.to_string())?;
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    // Purge any strays so the port is guaranteed free before the respawn.
    kill_stray_llama();

    let child = spawn_inference_child(&app)?;
    {
        let mut guard = state.0.lock().map_err(|e| e.to_string())?;
        *guard = Some(child);
    }

    wait_until_healthy(20).await?;
    Ok(8090)
}

#[tauri::command]
pub async fn stop_inference_server(state: State<'_, ServerProcess>) -> Result<(), String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    if let Some(mut child) = guard.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 3B Q4_K_M is ~2.1 GB.
    const THREE_B_BYTES: u64 = 2_200_000_000;
    // 0.5B Q4_K_M is ~470 MB.
    const HALF_B_BYTES: u64 = 470_000_000;

    fn profile(ram_gb: u64, cores: u32) -> HardwareProfile {
        HardwareProfile {
            total_ram_bytes: ram_gb * 1024 * 1024 * 1024,
            physical_cores: cores,
        }
    }

    #[test]
    fn capable_machine_runs_three_b() {
        // 16 GB RAM, 10 cores (e.g., Apple M4): 2.2 GB + 3 GB margin = 5.2 GB.
        assert!(model_capable(&profile(16, 10), THREE_B_BYTES));
        assert!(model_capable(&profile(8, 8), THREE_B_BYTES));
    }

    #[test]
    fn weak_ram_blocks_three_b_but_allows_half_b() {
        // 4 GB RAM is well below the 5.2 GB required for 3B...
        assert!(!model_capable(&profile(4, 8), THREE_B_BYTES));
        // ... but comfortably above the ~3.4 GB needed for 0.5B.
        assert!(model_capable(&profile(4, 8), HALF_B_BYTES));
    }

    #[test]
    fn too_few_cores_blocks_even_with_ram() {
        assert!(!model_capable(&profile(16, 2), THREE_B_BYTES));
        assert!(!model_capable(&profile(16, 2), HALF_B_BYTES));
    }
}
