use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};

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

fn spawn_inference_child(app: &AppHandle) -> Result<Child, String> {
    let app_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let is_windows = std::env::consts::OS == "windows";
    let binary_name = if is_windows {
        "llama-server.exe"
    } else {
        "llama-server"
    };
    let binary_path = app_dir.join("bin").join(binary_name);
    let model_path = app_dir.join("qwen2.5-0.5b-instruct-q4_k_m.gguf");

    if !binary_path.exists() || !model_path.exists() {
        return Err("Runtime assets missing. Run ensure_inference_runtime first.".into());
    }

    println!("Spawning llama-server from: {}", binary_path.display());

    Command::new(&binary_path)
        .arg("-m")
        .arg(&model_path)
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
