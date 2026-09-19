use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tauri::{AppHandle, Emitter, Manager};

const HUGGINGFACE_USER: &str = "ahmadnan";
const HUGGINGFACE_REPO: &str = "pci-sentinel-runtime";

/// Preferred inference model (Qwen 2.5-3B-Instruct Q4_K_M, ~2.1 GB). The 0.5B
/// model was too small to reliably judge PCI DSS mandates vs. evidence.
pub const MODEL_FILENAME: &str = "qwen2.5-3b-instruct-q4_k_m.gguf";

/// Legacy model kept for graceful fallback until the new weights are uploaded
/// to the runtime repo — the app still boots and audits on the old model.
pub const LEGACY_MODEL_FILENAME: &str = "qwen2.5-0.5b-instruct-q4_k_m.gguf";

#[tauri::command]
pub async fn ensure_inference_runtime(app: AppHandle) -> Result<String, String> {
    let app_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&app_dir).map_err(|e| e.to_string())?;

    let os = env::consts::OS; // e.g., "windows", "macos", "linux"
    let arch = env::consts::ARCH; // e.g., "aarch64", "x86_64"

    let is_windows = os == "windows";
    let binary_name = if is_windows {
        "llama-server.exe"
    } else {
        "llama-server"
    };

    // Binaries are stored in a 'bin' subdirectory to keep dylibs / helper files organized
    let bin_dir = app_dir.join("bin");
    fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;
    let binary_path = bin_dir.join(binary_name);
    let model_path = app_dir.join(MODEL_FILENAME);

    let client = reqwest::Client::new();

    // 1. Dynamic Architecture & OS Archive Mapping
    let archive_name = match (os, arch) {
        ("macos", "aarch64") => "llama-macos-arm64.tar.gz",
        ("macos", "x86_64") => "llama-macos-x64.tar.gz",
        ("windows", "x86_64") => "llama-win-x64.zip",
        _ => {
            return Err(format!(
                "Unsupported platform combination: OS={}, Arch={}",
                os, arch
            ))
        }
    };

    // 2. Check/Download binary runtime if missing
    let binary_valid = binary_path.exists()
        && fs::metadata(&binary_path)
            .map(|m| m.len() > 10_000)
            .unwrap_or(false);

    if binary_valid {
        let _ = app.emit("bootstrap-progress", "✓ Valid local secure runtime found.");
    } else {
        let _ = app.emit(
            "bootstrap-progress",
            &format!("Downloading runtime for {} ({}) ...", os, arch),
        );
        let download_url = format!(
            "https://huggingface.co/{}/{}/resolve/main/{}",
            HUGGINGFACE_USER, HUGGINGFACE_REPO, archive_name
        );
        download_and_extract_binary(&client, &download_url, &app_dir, is_windows, &app).await?;
    }

    // Set executable permissions on Unix systems
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("chmod")
            .args(["+x", binary_path.to_str().unwrap()])
            .status();
    }

    // 3. Check/Download Qwen model weights if missing
    if !model_path.exists()
        || fs::metadata(&model_path)
            .map(|m| m.len() == 0)
            .unwrap_or(true)
    {
        let _ = app.emit(
            "bootstrap-progress",
            "Downloading Qwen AI model weights (~2.1 GB)... Please wait.",
        );
        let model_url = format!(
            "https://huggingface.co/{}/{}/resolve/main/{}",
            HUGGINGFACE_USER, HUGGINGFACE_REPO, MODEL_FILENAME
        );
        download_file(&client, &model_url, &model_path, &app).await?;
    }

    let _ = app.emit(
        "bootstrap-progress",
        "Starting local inference server enclave...",
    );
    Ok(binary_path.to_string_lossy().to_string())
}

async fn download_file(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    app: &AppHandle,
) -> Result<(), String> {
    let mut response = client
        .get(url)
        .header(reqwest::header::USER_AGENT, "pci-sentinel")
        .send()
        .await
        .map_err(|e| format!("Request send error: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to download {}: status {}",
            url,
            response.status()
        ));
    }

    let total_size = response.content_length().unwrap_or(2_100_000_000);
    let mut downloaded: u64 = 0;
    let mut file = File::create(dest).map_err(|e| format!("File create error: {}", e))?;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("Chunk error: {}", e))?
    {
        file.write_all(&chunk)
            .map_err(|e| format!("Write error: {}", e))?;
        downloaded += chunk.len() as u64;
        let pct = ((downloaded as f64 / total_size as f64) * 100.0).min(100.0);
        let _ = app.emit(
            "bootstrap-progress",
            format!("Downloading AI model weights: {:.1}% (~2.1GB)", pct),
        );
    }

    Ok(())
}

async fn download_and_extract_binary(
    client: &reqwest::Client,
    url: &str,
    dest_dir: &Path,
    is_windows: bool,
    app: &AppHandle,
) -> Result<(), String> {
    let archive_path = dest_dir.join(if is_windows {
        "llama_tmp.zip"
    } else {
        "llama_tmp.tar.gz"
    });

    let mut response = client
        .get(url)
        .header(reqwest::header::USER_AGENT, "pci-sentinel")
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to download binary archive: status {}",
            response.status()
        ));
    }

    let mut file = File::create(&archive_path).map_err(|e| format!("File error: {}", e))?;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("Chunk error: {}", e))?
    {
        file.write_all(&chunk)
            .map_err(|e| format!("Write error: {}", e))?;
    }
    drop(file);

    let _ = app.emit(
        "bootstrap-progress",
        "Extracting secure runtime binaries...",
    );

    if is_windows {
        // Extract Windows .zip archive
        let file = File::open(&archive_path).map_err(|e| format!("Failed to open zip: {}", e))?;
        let mut archive =
            zip::ZipArchive::new(file).map_err(|e| format!("Zip parse error: {}", e))?;

        let bin_dir = dest_dir.join("bin");
        fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;

        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .map_err(|e| format!("Zip index error: {}", e))?;
            let outpath = bin_dir.join(entry.name());

            if entry.name().ends_with('/') {
                fs::create_dir_all(&outpath).map_err(|e| e.to_string())?;
            } else {
                if let Some(p) = outpath.parent() {
                    fs::create_dir_all(p).map_err(|e| e.to_string())?;
                }
                let mut outfile =
                    File::create(&outpath).map_err(|e| format!("Create file error: {}", e))?;
                std::io::copy(&mut entry, &mut outfile)
                    .map_err(|e| format!("Copy file error: {}", e))?;
            }
        }
    } else {
        // Extract macOS/Linux .tar.gz archive
        let status = std::process::Command::new("tar")
            .args([
                "-xzf",
                archive_path.to_str().unwrap(),
                "-C",
                dest_dir.to_str().unwrap(),
            ])
            .status()
            .map_err(|e| format!("Tar error: {}", e))?;

        if !status.success() {
            return Err("Failed to extract tar.gz archive".into());
        }
    }

    let _ = fs::remove_file(archive_path);
    Ok(())
}
