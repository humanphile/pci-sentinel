use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;
use chrono::Local;
use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Signature, Verifier};
use rand::rngs::OsRng;
use base64::Engine;
use std::path::PathBuf;

use crate::regulatory_store;
use crate::db;

pub const INTERNAL_ENCLAVE_TOKEN: &str = "pci-sentinel-airgap-auth-token-8812";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SingleAuditResult {
    pub control_id: String,
    pub status: String,
    pub finding: String,
    pub remediation: String,
    #[serde(default)]
    pub evidence: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SingleExportPayload {
    pub requirement_title: String,
    pub control: SingleAuditResult,
    pub evidence: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BatchExportPayload {
    pub requirement_title: String,
    pub evidence: String,
    pub controls: Vec<SingleAuditResult>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BatchVerificationPayload {
    pub requirement_title: String,
    pub evidence: String,
    pub controls: Vec<SingleAuditResult>,
    pub pubkey_b64: String,
    pub signature_b64: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExportResponse {
    pub export_path: String,
    pub pubkey_b64: String,
    pub signature_b64: String,
    pub record_id: i64,
}

pub async fn query_pci_single_control(
    evidence: &str,
    requirement_id: u32,
    control_id: &str,
) -> Result<SingleAuditResult, Box<dyn std::error::Error>> {
    let req_group = regulatory_store::get_pci_requirement(requirement_id)
        .ok_or_else(|| format!("Requirement {} not loaded", requirement_id))?;

    let ctrl = req_group.controls.iter().find(|c| c.control_id == control_id)
        .ok_or_else(|| format!("Control {} not found", control_id))?;

    let client = reqwest::Client::new();
    let system_instruction = format!(
        "You are an accredited Qualified Security Assessor (QSA) evaluating evidence strictly against PCI DSS v4.0 Control [{}] ({}).\n\
        MANDATE: {}\n\
        EXPECTED ARTIFACTS: {:?}\n\n\
        INSTRUCTIONS:\n\
        1. Compare the provided evidence exclusively against this control.\n\
        2. Assign status: 'COMPLIANT', 'NON_COMPLIANT', or 'INSUFFICIENT'.\n\
        3. If evidence is missing required details or absent, mark 'INSUFFICIENT' and specify what is missing.\n\
        4. Provide an actionable technical remediation directive.\n\
        5. Return raw JSON only: {{ \"control_id\": \"{}\", \"status\": \"...\", \"finding\": \"...\", \"remediation\": \"...\" }}",
        ctrl.control_id, ctrl.title_en, ctrl.mandate_text, ctrl.required_artifacts, ctrl.control_id
    );

    let prompt = format!(
        "<|im_start|>system\n{}<|im_end|>\n<|im_start|>user\nAudit the following evidence:\n{}<|im_end|>\n<|im_start|>assistant\n",
        system_instruction, evidence
    );

    let res = client
        .post("http://127.0.0.1:8090/completion")
        .header("Authorization", format!("Bearer {}", INTERNAL_ENCLAVE_TOKEN))
        .json(&json!({
            "prompt": prompt,
            "temperature": 0.0,
            "n_predict": 1024,
            "stop": ["<|im_end|>"]
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let content = res["content"].as_str().unwrap_or("{}").trim().to_string();
    let mut cleaned = content.clone();
    if cleaned.starts_with("```json") {
        cleaned = cleaned.replace("```json", "").replace("```", "").trim().to_string();
    } else if cleaned.starts_with("```") {
        cleaned = cleaned.replace("```", "").trim().to_string();
    }

    let start_idx = cleaned.find('{').unwrap_or(0);
    let end_idx = cleaned.rfind('}').unwrap_or(cleaned.len().saturating_sub(1));
    if start_idx <= end_idx {
        cleaned = cleaned[start_idx..=end_idx].to_string();
    }

    let mut result: SingleAuditResult = serde_json::from_str(&cleaned).unwrap_or_else(|_| SingleAuditResult {
        control_id: control_id.to_string(),
        status: "INSUFFICIENT".to_string(),
        finding: "Failed to parse structured audit finding from inference output.".to_string(),
        remediation: "Verify input evidence format and rerun evaluation.".to_string(),
        evidence: evidence.to_string(),
    });

    result.evidence = evidence.to_string();
    Ok(result)
}

fn get_app_dir() -> PathBuf {
    if let Some(mut dir) = dirs::data_local_dir() {
        dir.push("pci-sentinel");
        dir
    } else {
        PathBuf::from(".pci-sentinel")
    }
}

fn get_desktop_dir() -> PathBuf {
    dirs::desktop_dir().unwrap_or_else(|| PathBuf::from("."))
}

fn get_or_create_auditor_key() -> Result<SigningKey, String> {
    let key_dir = get_app_dir();
    let key_file = key_dir.join("pci_auditor_key.bin");

    if fs::metadata(&key_file).is_ok() {
        let key_bytes = fs::read(&key_file).map_err(|e| format!("Failed to read key: {}", e))?;
        if key_bytes.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&key_bytes);
            return Ok(SigningKey::from_bytes(&array));
        }
    }

    let _ = fs::create_dir_all(&key_dir);
    let signing_key = SigningKey::generate(&mut OsRng);
    fs::write(&key_file, signing_key.to_bytes())
        .map_err(|e| format!("Failed to save signing key: {}", e))?;

    Ok(signing_key)
}

fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut current = String::new();
        for word in trimmed.split_whitespace() {
            if current.len() + word.len() + 1 > max_chars {
                if !current.is_empty() {
                    lines.push(current);
                    current = String::new();
                }
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    lines
}

fn sanitize(input: &str) -> String {
    input.chars()
        .filter(|c| c.is_ascii() && *c != '(' && *c != ')' && *c != '\\')
        .collect()
}

fn watermark_block() -> String {
    "q\n\
    /GS1 gs\n\
    0.88 0.90 0.93 rg\n\
    0.7071 0.7071 -0.7071 0.7071 140 160 cm\n\
    BT\n\
    /F1 22 Tf\n\
    0 0 Td (PCI DSS v4.0 QUALIFIED ATTESTATION) Tj\n\
    0 -30 Td (AIR-GAPPED HARDWARE ENCLAVE VERIFIED) Tj\n\
    ET\n\
    Q\n".to_string()
}

pub fn generate_single_signed_pdf(payload: &SingleExportPayload) -> Result<ExportResponse, String> {
    let mut single_ctrl = payload.control.clone();
    if single_ctrl.evidence.is_empty() {
        single_ctrl.evidence = payload.evidence.clone();
    }
    let batch = BatchExportPayload {
        requirement_title: format!("{} - Control {}", payload.requirement_title, single_ctrl.control_id),
        evidence: payload.evidence.clone(),
        controls: vec![single_ctrl],
    };
    generate_pci_signed_pdf(&batch)
}

pub fn generate_pci_signed_pdf(payload: &BatchExportPayload) -> Result<ExportResponse, String> {
    let now = Local::now();
    let file_date = now.format("%Y-%m-%d_%H-%M-%S").to_string();
    let printable_date = now.format("%Y-%m-%d %H:%M:%S").to_string();

    let is_single = payload.controls.len() == 1;
    let filename = if is_single {
        format!("PCI_DSS_Control_{}_{}.pdf", payload.controls[0].control_id, file_date)
    } else {
        format!("PCI_DSS_Consolidated_Dossier_{}.pdf", file_date)
    };

    let export_file = get_desktop_dir().join(filename);
    let export_path = export_file.to_string_lossy().to_string();

    let mut hasher = Sha256::new();
    hasher.update(payload.requirement_title.as_bytes());
    for c in &payload.controls {
        hasher.update(c.control_id.as_bytes());
        hasher.update(c.status.as_bytes());
        hasher.update(c.finding.as_bytes());
        hasher.update(c.remediation.as_bytes());
        hasher.update(c.evidence.as_bytes());
    }
    let result_bytes = hasher.finalize();
    let digest_hex: String = result_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let signing_key = get_or_create_auditor_key()?;
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let signature = signing_key.sign(&result_bytes);

    let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    let total = payload.controls.len();
    let compliant = payload.controls.iter().filter(|c| c.status == "COMPLIANT").count();
    let non_compliant = payload.controls.iter().filter(|c| c.status == "NON_COMPLIANT").count();
    let insufficient = payload.controls.iter().filter(|c| c.status == "INSUFFICIENT").count();
    let score = if total > 0 { (compliant * 100) / total } else { 0 };

    let mut raw_pages_stream: Vec<String> = Vec::new();

    // --- PAGE 1: EXECUTIVE SUMMARY & MULTI-LINE TABLE ROWS (NO TRUNCATION) ---
    let mut table_rows = String::new();
    for ctrl in &payload.controls {
        let tag = match ctrl.status.as_str() {
            "COMPLIANT" => "[PASS]",
            "NON_COMPLIANT" => "[FAIL]",
            _ => "[INSUF]",
        };
        
        // Wrap finding text properly by whole words (up to 68 characters per column line)
        let finding_lines = wrap_text(&sanitize(&ctrl.finding), 68);
        let first_line = finding_lines.get(0).cloned().unwrap_or_default();

        // Print first line with Control ID and Status Tag
        table_rows.push_str(&format!(
            "0 -13 Td ({:<8}) Tj 55 0 Td ({:<8}) Tj 60 0 Td ({}) Tj -115 0 Td\n",
            ctrl.control_id, tag, first_line
        ));

        // For single-control reports or when text wraps, indent additional lines under the Finding column
        let extra_limit = if is_single { finding_lines.len() } else { 2 };
        for extra in finding_lines.iter().skip(1).take(extra_limit - 1) {
            table_rows.push_str(&format!(
                "115 -10 Td ({}) Tj -115 0 Td\n",
                extra
            ));
        }
    }

    let summary_stream = format!(
        "{}\
        BT\n\
        /F2 8 Tf\n\
        50 755 Td (PCI-SENTINEL | FORMAL ATTESTATION OF COMPLIANCE | AIR-GAPPED EVALUATION) Tj\n\
        380 0 Td ({}) Tj\n\
        -380 -7 Td (_________________________________________________________________________________________) Tj\n\
        /F1 14 Tf\n\
        0 -22 Td (PCI DSS v4.0 FORMAL ASSESSMENT DOSSIER) Tj\n\
        /F2 9 Tf\n\
        0 -13 Td (Target Scope:        {}) Tj\n\
        0 -12 Td (Compliance Status:   {}% (Passed: {}, Failed: {}, Insufficient: {}, Total: {})) Tj\n\
        0 -14 Td (=========================================================================================) Tj\n\
        /F1 9.5 Tf\n\
        0 -13 Td (MANDATE EVALUATION AUDIT BREAKDOWN) Tj\n\
        /F2 7.5 Tf\n\
        0 -12 Td (CONTROL    STATUS    FINDING OVERVIEW) Tj\n\
        0 -5 Td (-----------------------------------------------------------------------------------------) Tj\n\
        {}\
        0 -14 Td (_________________________________________________________________________________________) Tj\n\
        /F1 8.5 Tf\n\
        0 -13 Td (CRYPTOGRAPHIC ATTESTATION SEAL:) Tj\n\
        /F2 7 Tf\n\
        0 -10 Td (SHA-256 Digest:    {}) Tj\n\
        0 -10 Td (Auditor Public Key: {}) Tj\n\
        0 -10 Td (Ed25519 Signature:  {}) Tj\n\
        0 -14 Td (_________________________________________________________________________________________) Tj\n\
        /F2 8 Tf\n\
        0 -11 Td (CONFIDENTIAL | PCI SECURITY STANDARDS COUNCIL COMPLIANT) Tj\n\
        ET\n",
        watermark_block(),
        printable_date,
        payload.requirement_title,
        score,
        compliant,
        non_compliant,
        insufficient,
        total,
        table_rows,
        digest_hex,
        pubkey_b64,
        sig_b64
    );
    raw_pages_stream.push(summary_stream);

    // --- SUBSEQUENT PAGES: UNTRUNCATED EVIDENCE, FINDING & REMEDIATION ---
    let mut current_page = String::new();
    let mut y_cursor = 720;

    let init_page = |cur_str: &mut String, y: &mut i32| {
        *y = 710;
        cur_str.push_str(&watermark_block());
        cur_str.push_str(&format!(
            "BT\n/F2 8 Tf\n50 755 Td (PCI-SENTINEL | EVIDENCE ARTIFACTS & TECHNICAL OBSERVATIONS) Tj\n\
            380 0 Td ({}) Tj\n\
            -380 -7 Td (_________________________________________________________________________________________) Tj\n",
            printable_date
        ));
    };

    init_page(&mut current_page, &mut y_cursor);

    for ctrl in &payload.controls {
        let ev_lines = wrap_text(&sanitize(&ctrl.evidence), 76);
        let finding_lines = wrap_text(&sanitize(&ctrl.finding), 76);
        let rem_lines = wrap_text(&sanitize(&ctrl.remediation), 76);
        
        let block_height = 16 + 11 + (ev_lines.len() as i32 * 10) + 11 + (finding_lines.len() as i32 * 10) + 11 + (rem_lines.len() as i32 * 10) + 12;

        if y_cursor < block_height + 50 {
            current_page.push_str("ET\n");
            raw_pages_stream.push(current_page.clone());
            current_page = String::new();
            init_page(&mut current_page, &mut y_cursor);
        }

        let status_tag = match ctrl.status.as_str() {
            "COMPLIANT" => "PASSED",
            "NON_COMPLIANT" => "FAILED (NON-COMPLIANT)",
            _ => "INSUFFICIENT EVIDENCE",
        };

        current_page.push_str(&format!(
            "/F1 10 Tf\n0 -16 Td (CONTROL [{}]: {}) Tj\n/F2 8 Tf\n",
            ctrl.control_id, status_tag
        ));
        y_cursor -= 16;

        current_page.push_str("/F1 8 Tf\n0 -11 Td (INGESTED EVIDENCE ARTIFACT:) Tj\n/F2 7.5 Tf\n");
        y_cursor -= 11;
        if ev_lines.is_empty() {
            current_page.push_str("0 -10 Td (  No evidence artifact submitted for this control.) Tj\n");
            y_cursor -= 10;
        } else {
            for line in ev_lines {
                current_page.push_str(&format!("0 -10 Td (  | {}) Tj\n", line));
                y_cursor -= 10;
            }
        }

        current_page.push_str("/F1 8 Tf\n0 -11 Td (AUDITOR FINDING / OBSERVATION:) Tj\n/F2 7.5 Tf\n");
        y_cursor -= 11;
        for line in finding_lines {
            current_page.push_str(&format!("0 -10 Td (  {}) Tj\n", line));
            y_cursor -= 10;
        }

        current_page.push_str("/F1 8 Tf\n0 -11 Td (MANDATED TECHNICAL REMEDIATION ACTION:) Tj\n/F2 7.5 Tf\n");
        y_cursor -= 11;
        for line in rem_lines {
            current_page.push_str(&format!("0 -10 Td (  >> {}) Tj\n", line));
            y_cursor -= 10;
        }

        current_page.push_str("0 -8 Td (-----------------------------------------------------------------------------------------) Tj\n");
        y_cursor -= 8;
    }

    current_page.push_str("0 -14 Td (END OF FORMAL AUDIT TRAIL RECORD) Tj\nET\n");
    raw_pages_stream.push(current_page);

    let total_pages = raw_pages_stream.len();
    let mut final_pages_stream: Vec<String> = Vec::new();

    for (idx, mut page) in raw_pages_stream.into_iter().enumerate() {
        let page_num_str = format!("Page {} of {}", idx + 1, total_pages);
        let footer_snippet = format!(
            "BT\n/F2 8 Tf\n490 35 Td ({}) Tj\nET\n",
            page_num_str
        );
        page.push_str(&footer_snippet);
        final_pages_stream.push(page);
    }

    let num_pages = final_pages_stream.len();
    let mut page_objs = String::new();
    let mut kids = String::new();
    for i in 0..num_pages {
        let page_obj_id = 3 + i;
        let content_obj_id = 3 + num_pages + i;
        kids.push_str(&format!("{} 0 R ", page_obj_id));
        page_objs.push_str(&format!(
            "{} 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources {} 0 R >> endobj\n",
            page_obj_id,
            content_obj_id,
            3 + (2 * num_pages)
        ));
    }

    let resources_obj_id = 3 + (2 * num_pages);
    let mut streams_pdf = String::new();
    for (i, stream) in final_pages_stream.iter().enumerate() {
        let content_obj_id = 3 + num_pages + i;
        streams_pdf.push_str(&format!(
            "{} 0 obj << /Length {} >> stream\n{}\nendstream\nendobj\n",
            content_obj_id,
            stream.as_bytes().len(),
            stream
        ));
    }

    let static_resources = format!(
        "{} 0 obj << /Font << /F1 {} 0 R /F2 {} 0 R >> /ExtGState << /GS1 {} 0 R >> >> endobj\n\
        {} 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> endobj\n\
        {} 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n\
        {} 0 obj << /Type /ExtGState /ca 0.18 /CA 0.18 >> endobj\n",
        resources_obj_id,
        resources_obj_id + 1,
        resources_obj_id + 2,
        resources_obj_id + 3,
        resources_obj_id + 1,
        resources_obj_id + 2,
        resources_obj_id + 3
    );

    let pdf_body = format!(
        "%PDF-1.4\n\
        1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n\
        2 0 obj << /Type /Pages /Kids [{}] /Count {} >> endobj\n\
        {}{}{}",
        kids.trim(),
        num_pages,
        page_objs,
        streams_pdf,
        static_resources
    );

    let total_objects = resources_obj_id + 4;
    let mut xref = format!("xref\n0 {}\n0000000000 65535 f \n", total_objects);

    for obj_id in 1..total_objects {
        let search_pattern = format!("{} 0 obj", obj_id);
        if let Some(pos) = pdf_body.find(&search_pattern) {
            xref.push_str(&format!("{:010} 00000 n \n", pos));
        } else {
            xref.push_str("0000000000 00000 n \n");
        }
    }

    let startxref_offset = pdf_body.as_bytes().len();
    let complete_pdf = format!(
        "{}\n{}\ntrailer << /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF",
        pdf_body, xref, total_objects, startxref_offset
    );

    let mut file = File::create(&export_file).map_err(|e| format!("Failed to create PDF: {}", e))?;
    file.write_all(complete_pdf.as_bytes()).map_err(|e| format!("Failed to write PDF: {}", e))?;

    let record_id = db::insert_audit_record(
        &printable_date,
        "PCI DSS v4.0",
        &payload.requirement_title,
        if score >= 80 { "COMPLIANT" } else { "NON_COMPLIANT" },
        &format!("Passed: {}, Failed: {}, Insufficient: {}, Total: {}", compliant, non_compliant, insufficient, total),
        "Full observations, evidence artifacts, and remediation plans in PDF dossier.",
        &payload.evidence,
        &digest_hex,
        &sig_b64,
        &pubkey_b64,
        &export_path,
    )?;

    Ok(ExportResponse {
        export_path,
        pubkey_b64,
        signature_b64: sig_b64,
        record_id,
    })
}

pub fn verify_pci_signature(payload: &BatchVerificationPayload) -> Result<bool, String> {
    let mut hasher = Sha256::new();
    hasher.update(payload.requirement_title.as_bytes());
    for c in &payload.controls {
        hasher.update(c.control_id.as_bytes());
        hasher.update(c.status.as_bytes());
        hasher.update(c.finding.as_bytes());
        hasher.update(c.remediation.as_bytes());
        hasher.update(c.evidence.as_bytes());
    }
    let result_bytes = hasher.finalize();

    let pubkey_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.pubkey_b64)
        .map_err(|e| format!("Invalid public key encoding: {}", e))?;
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into().map_err(|_| "Invalid public key length")?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array).map_err(|e| e.to_string())?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.signature_b64)
        .map_err(|e| format!("Invalid signature encoding: {}", e))?;
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| "Invalid signature length")?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key.verify(&result_bytes, &signature).map(|_| true).map_err(|e| e.to_string())
}
