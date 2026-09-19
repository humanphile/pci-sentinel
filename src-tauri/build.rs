use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    tauri_build::build();

    let start = SystemTime::now();
    let since_epoch = start.duration_since(UNIX_EPOCH).unwrap();
    let build_timestamp = since_epoch.as_secs();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("build_meta.rs");

    let code = format!("pub const BUILD_TIMESTAMP: u64 = {};\n", build_timestamp);

    fs::write(&dest_path, code).expect("Failed to write build metadata");
}
