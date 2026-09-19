use base64::Engine;
use chrono::{NaiveDate, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

// Embed your vendor public key generated from the CLI tool here:
// const VENDOR_PUBKEY_B64: &str = "YOUR_EMBEDDED_PUBLIC_KEY_HERE";

const VENDOR_PUBKEY_B64: &str = "q7/n7XMEoTEPLxFRW9ADTMwubkceIyN/K9rp1o03op4=";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LicensePayload {
    username: String,
    hwid: String,
    tier: String,
    issued_at: String,
    expires_at: String,
}

pub fn get_machine_hardware_id() -> String {
    let base_path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    let mut hasher = Sha256::new();
    hasher.update(base_path.to_string_lossy().as_bytes());
    hasher.update(std::env::consts::OS.as_bytes());
    hasher.update(std::env::consts::ARCH.as_bytes());

    let result = hasher.finalize();
    format!(
        "GRC-HWID-{:016x}",
        u64::from_ne_bytes(result[0..8].try_into().unwrap())
    )
}

/// Hardware-bound admin reset password (matches the `sentinel-licenser` CLI).
///
/// `GRC-ADM-` + first 16 hex chars of SHA-256(HWID + "-SENTINEL-GRC-ADMIN-SALT-2026"),
/// uppercased. This is the ONLY password that can authorize a knowledge-base reset.
pub fn admin_reset_password(hwid: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hwid.as_bytes());
    hasher.update(b"-SENTINEL-GRC-ADMIN-SALT-2026");
    let result = hasher.finalize();

    let hex_string: String = result
        .as_slice()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("GRC-ADM-{}", &hex_string[..16]).to_uppercase()
}

/// Verify a signed `PCI-SUB-...` license against the current hardware profile
/// and a vendor public key (base64, 32 bytes). Returns the decoded payload on
/// success. Public so it can be unit-tested with a test keypair.
pub fn verify_license_key(
    license_string: &str,
    current_hwid: &str,
    pubkey_b64: &str,
) -> Result<LicensePayload, String> {
    if !license_string.starts_with("PCI-SUB-") {
        return Err("Invalid license key format.".into());
    }

    let core_data = &license_string[8..];
    let parts: Vec<&str> = core_data.split('.').collect();
    if parts.len() != 2 {
        return Err("Malformed license key structure.".into());
    }

    let payload_b64 = parts[0];
    let sig_b64 = parts[1];

    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .map_err(|_| "Failed to decode license payload.")?;
    let payload_str =
        String::from_utf8(payload_bytes).map_err(|_| "Invalid license text encoding.")?;

    let payload: LicensePayload = serde_json::from_str(&payload_str)
        .map_err(|_| "Failed to parse license JSON structure.")?;

    if payload.hwid != current_hwid {
        return Err(format!(
            "License key locked to another hardware profile. Your HWID: {}",
            current_hwid
        ));
    }

    let pubkey_bytes = base64::engine::general_purpose::STANDARD
        .decode(pubkey_b64)
        .map_err(|_| "Invalid vendor public key configuration.")?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "Invalid public key length.")?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array).map_err(|e| e.to_string())?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|_| "Invalid signature encoding.")?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Invalid signature length.")?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(payload_str.as_bytes(), &signature)
        .map_err(|_| "Cryptographic signature validation failed! Key is untrusted.")?;

    let today = Utc::now().date_naive();
    let expiry_date = NaiveDate::parse_from_str(&payload.expires_at, "%Y-%m-%d")
        .map_err(|_| "Invalid expiration date format in license.")?;

    if today > expiry_date {
        return Err(format!("License expired on {}.", payload.expires_at));
    }

    Ok(payload)
}

#[tauri::command]
pub fn activate_subscription_key(
    username: String,
    license_string: String,
) -> Result<String, String> {
    let payload = verify_license_key(
        &license_string,
        &get_machine_hardware_id(),
        VENDOR_PUBKEY_B64,
    )?;

    // Persist the subscriber role for the authenticated user so the upgrade
    // survives application restarts (stored in the SQLCipher-encrypted store).
    let conn = crate::db::get_connection().map_err(|e| format!("Database unavailable: {}", e))?;
    let updated = conn
        .execute(
            "UPDATE users SET role = 'subscriber' WHERE username = ?1",
            [&username],
        )
        .map_err(|e| format!("Failed to persist subscription role: {}", e))?;
    if updated == 0 {
        return Err(format!(
            "User '{}' not found in the local enclave store.",
            username
        ));
    }

    Ok(format!(
        "✓ Successfully activated Sentinel GRC Enterprise for {}!",
        payload.username
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_license(hwid: &str, expires_at: &str) -> (String, String) {
        // (license_string, pubkey_b64) pair produced from a throwaway keypair.
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());

        let payload = LicensePayload {
            username: "tester".into(),
            hwid: hwid.into(),
            tier: "enterprise".into(),
            issued_at: "2026-09-19".into(),
            expires_at: expires_at.into(),
        };
        let payload_str = serde_json::to_string(&payload).unwrap();
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload_str.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD
            .encode(signing_key.sign(payload_str.as_bytes()).to_bytes());

        (format!("PCI-SUB-{}.{}", payload_b64, sig_b64), pubkey_b64)
    }

    #[test]
    fn hwid_has_expected_format() {
        let hwid = get_machine_hardware_id();
        assert!(hwid.starts_with("GRC-HWID-"));
        let suffix = &hwid["GRC-HWID-".len()..];
        assert_eq!(suffix.len(), 16);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn admin_reset_password_matches_formula() {
        let hwid = "GRC-HWID-0123456789abcdef";
        let pass = admin_reset_password(hwid);
        assert!(pass.starts_with("GRC-ADM-"));
        let suffix = &pass["GRC-ADM-".len()..];
        assert_eq!(suffix.len(), 16);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));

        // Deterministic for the same hardware id.
        assert_eq!(pass, admin_reset_password(hwid));

        // Independent recomputation of the documented formula.
        let mut hasher = Sha256::new();
        hasher.update(hwid.as_bytes());
        hasher.update(b"-SENTINEL-GRC-ADMIN-SALT-2026");
        let hex_string: String = hasher
            .finalize()
            .as_slice()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let expected = format!("GRC-ADM-{}", &hex_string[..16]).to_uppercase();
        assert_eq!(pass, expected);
    }

    #[test]
    fn valid_license_verifies() {
        let (license, pubkey) = test_license("GRC-HWID-aaaa", "2999-01-01");
        let payload = verify_license_key(&license, "GRC-HWID-aaaa", &pubkey).unwrap();
        assert_eq!(payload.username, "tester");
    }

    #[test]
    fn license_bound_to_other_hwid_is_rejected() {
        let (license, pubkey) = test_license("GRC-HWID-aaaa", "2999-01-01");
        let err = verify_license_key(&license, "GRC-HWID-bbbb", &pubkey).unwrap_err();
        assert!(err.contains("another hardware profile"));
    }

    #[test]
    fn expired_license_is_rejected() {
        let (license, pubkey) = test_license("GRC-HWID-aaaa", "2020-01-01");
        let err = verify_license_key(&license, "GRC-HWID-aaaa", &pubkey).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let err = verify_license_key("NOT-A-LICENSE", "hwid", "x").unwrap_err();
        assert!(err.contains("Invalid license key format"));

        let err = verify_license_key("PCI-SUB-short", "hwid", "x").unwrap_err();
        assert!(err.contains("Malformed license key structure"));
    }
}
