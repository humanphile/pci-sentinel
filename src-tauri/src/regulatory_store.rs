use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PciControl {
    pub control_id: String,
    pub title_en: String,
    pub mandate_text: String,
    pub required_artifacts: Vec<String>,
    #[serde(default)]
    pub sample_evidence: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PciRequirementGroup {
    pub requirement_id: u32,
    pub title: String,
    pub controls: Vec<PciControl>,
}

pub fn get_pci_requirement(req_id: u32) -> Option<PciRequirementGroup> {
    let filename = format!("req_{}.json", req_id);
    let mut candidate_paths = vec![
        PathBuf::from("baselines/pci_dss").join(&filename),
        PathBuf::from("src-tauri/baselines/pci_dss").join(&filename),
        PathBuf::from("/Users/ahmadnan/pci-sentinel/src-tauri/baselines/pci_dss").join(&filename),
    ];

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(dir) = exe_path.parent() {
            candidate_paths.push(dir.join("baselines/pci_dss").join(&filename));
            candidate_paths.push(dir.join("../Resources/baselines/pci_dss").join(&filename));
            candidate_paths.push(dir.join("../../baselines/pci_dss").join(&filename));
        }
    }

    let file_path = candidate_paths.into_iter().find(|p| p.exists())?;
    let raw = fs::read_to_string(file_path).ok()?;
    let parsed: PciRequirementGroup = serde_json::from_str(&raw).ok()?;

    Some(parsed)
}
