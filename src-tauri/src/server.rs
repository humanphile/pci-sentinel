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

#[tauri::command]
pub async fn start_inference_server(
    app: AppHandle,
    state: State<'_, ServerProcess>,
) -> Result<u16, String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    if guard.is_some() {
        return Ok(8090);
    }

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

    let child = Command::new(&binary_path)
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
        .map_err(|e| format!("Failed to spawn llama-server: {}", e))?;

    *guard = Some(child);
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
