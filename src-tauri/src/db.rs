use rand::RngCore;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub fn get_connection() -> Result<Connection, rusqlite::Error> {
    let mut path = directories::ProjectDirs::from("com", "pci", "sentinel")
        .map(|proj| proj.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    std::fs::create_dir_all(&path).unwrap_or_default();
    path.push("sentinel_audit.db");

    let conn = Connection::open(&path)?;

    // Derive a strong database encryption key bound to the machine HWID
    let hwid = crate::licensing::get_machine_hardware_id();
    let mut hasher = Sha256::new();
    hasher.update(hwid.as_bytes());
    hasher.update(b"-SENTINEL-DB-ENCRYPTION-SALT-2026");
    let result = hasher.finalize();

    let result_bytes = result.as_slice();
    let hex_key = result_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Apply SQLCipher transparent encryption key to the connection
    conn.pragma_update(None, "key", &hex_key)?;

    Ok(conn)
}

/// Hash a password with a random per-user salt.
///
/// Stored format: `sha256$<salt_hex>$<hash_hex>` where the hash is
/// SHA-256(salt || plaintext). This is a local-build credential store on
/// top of an already SQLCipher-encrypted database — suitable for this
/// offline enclave, and a strict improvement over storing plaintext.
pub fn hash_password(plain: &str) -> String {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let salt_hex: String = salt.iter().map(|b| format!("{:02x}", b)).collect();
    let hash = hash_with_salt(&salt_hex, plain);
    format!("sha256${}${}", salt_hex, hash)
}

fn hash_with_salt(salt_hex: &str, plain: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt_hex.as_bytes());
    hasher.update(plain.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verify a password against a stored value.
///
/// `stored` may be either the new `sha256$salt$hash` format or a legacy
/// plaintext value from databases created before hashing was introduced.
/// Legacy values are transparently upgraded on the next successful login.
pub fn verify_password(plain: &str, stored: &str) -> bool {
    if let Some(rest) = stored.strip_prefix("sha256$") {
        let mut parts = rest.splitn(2, '$');
        let (Some(salt), Some(expected_hex)) = (parts.next(), parts.next()) else {
            return false;
        };
        let computed = hash_with_salt(salt, plain);
        let computed_bytes = computed.as_bytes();
        let expected_bytes = expected_hex.as_bytes();
        if computed_bytes.len() != expected_bytes.len() {
            return false;
        }
        // Constant-time comparison to avoid timing side-channels.
        let mut diff: u8 = 0;
        for (a, b) in computed_bytes.iter().zip(expected_bytes.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    } else {
        // Legacy plaintext storage from earlier builds.
        plain == stored
    }
}

/// True when the stored value uses the hashed format (vs legacy plaintext).
pub fn is_hashed_password(stored: &str) -> bool {
    stored.starts_with("sha256$")
}

pub fn init_database() -> Result<(), rusqlite::Error> {
    let conn = get_connection()?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            is_first_login INTEGER NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS enclave_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            control_id TEXT NOT NULL,
            requirement_number INTEGER NOT NULL,
            status TEXT NOT NULL,
            summary TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            username TEXT NOT NULL DEFAULT ''
        )",
        [],
    )?;

    // Migration: databases created by earlier builds lack the `username`
    // column. Add it in place so the trail can be attributed per user and
    // demo restrictions are scoped to the active user.
    {
        let mut check = conn.prepare(
            "SELECT COUNT(*) FROM pragma_table_info('audit_records') WHERE name = 'username'",
        )?;
        let exists: i64 = check.query_row([], |row| row.get(0))?;
        if exists == 0 {
            conn.execute(
                "ALTER TABLE audit_records ADD COLUMN username TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
    }

    // Migration: persist the full evidence text alongside its hash so sealed
    // reports/dossiers can reproduce what was actually evaluated, not just a
    // digest.
    {
        let mut check = conn.prepare(
            "SELECT COUNT(*) FROM pragma_table_info('audit_records') WHERE name = 'evidence_text'",
        )?;
        let exists: i64 = check.query_row([], |row| row.get(0))?;
        if exists == 0 {
            conn.execute(
                "ALTER TABLE audit_records ADD COLUMN evidence_text TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
    }

    // Seed default users if table is empty (properly inside the function body)
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM users")?;
    let count: i64 = stmt.query_row([], |row| row.get(0))?;

    if count == 0 {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        // 1. Seed Demo User (Limited role / 7-day demo window)
        conn.execute(
            "INSERT INTO users (username, password, is_first_login, role, created_at) VALUES (?, ?, ?, ?, ?)",
            rusqlite::params!["demo", hash_password("demo"), 0, "demo", now],
        )?;

        // 2. Seed Admin User (Subscriber role, requires password change on first login)
        conn.execute(
            "INSERT INTO users (username, password, is_first_login, role, created_at) VALUES (?, ?, ?, ?, ?)",
            rusqlite::params!["admin", hash_password("admin"), 1, "subscriber", now],
        )?;
    }

    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct AuditRecord {
    pub id: i64,
    pub timestamp: String,
    pub control_id: String,
    pub requirement_number: u32,
    pub status: String,
    pub summary: String,
    pub evidence_hash: String,
    pub evidence_text: String,
    pub username: String,
}

/// Named parameters for persisting a single audit evaluation. Using a struct
/// (instead of positional args) makes call sites immune to argument-order
/// mistakes, which have historically broken this codebase.
#[derive(Debug, Clone)]
pub struct AuditInsert<'a> {
    pub username: &'a str,
    pub timestamp: &'a str,
    pub control_id: &'a str,
    pub status: &'a str,
    pub summary: &'a str,
    pub evidence_hash: &'a str,
    pub evidence_text: &'a str,
    pub requirement_number: u32,
}

pub fn insert_audit_record(record: &AuditInsert) -> Result<i64, String> {
    let conn = get_connection().map_err(|e| e.to_string())?;

    conn.execute(
        "INSERT INTO audit_records (timestamp, control_id, requirement_number, status, summary, evidence_hash, evidence_text, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            record.timestamp,
            record.control_id,
            record.requirement_number,
            record.status,
            record.summary,
            record.evidence_hash,
            record.evidence_text,
            record.username,
        ],
    ).map_err(|e| e.to_string())?;

    Ok(conn.last_insert_rowid())
}

pub fn fetch_audit_history() -> Result<Vec<AuditRecord>, String> {
    let conn = get_connection().map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_records'")
        .map_err(|e| e.to_string())?;
    let table_exists = stmt.exists([]).map_err(|e| e.to_string())?;

    if !table_exists {
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare(
        "SELECT id, timestamp, control_id, requirement_number, status, summary, evidence_hash, evidence_text, username \
         FROM audit_records ORDER BY id DESC"
    ).map_err(|e| e.to_string())?;

    let record_iter = stmt
        .query_map([], |row| {
            Ok(AuditRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                control_id: row.get(2)?,
                requirement_number: row.get(3)?,
                status: row.get(4)?,
                summary: row.get(5)?,
                evidence_hash: row.get(6)?,
                evidence_text: row.get(7)?,
                username: row.get(8)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut records = Vec::new();
    for r in record_iter.flatten() {
        records.push(r);
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trip() {
        let stored = hash_password("Admin@123");
        assert!(stored.starts_with("sha256$"));
        assert!(verify_password("Admin@123", &stored));
        assert!(!verify_password("wrong-pass", &stored));
        assert!(is_hashed_password(&stored));
    }

    #[test]
    fn legacy_plaintext_still_verifies() {
        assert!(verify_password("demo", "demo"));
        assert!(!verify_password("Demo123!", "demo"));
        assert!(!is_hashed_password("demo"));
    }

    #[test]
    fn unique_salts_produce_distinct_hashes() {
        let a = hash_password("Same@Pass1");
        let b = hash_password("Same@Pass1");
        assert_ne!(a, b);
        assert!(verify_password("Same@Pass1", &a));
        assert!(verify_password("Same@Pass1", &b));
    }

    #[test]
    fn malformed_hash_entries_fail_safely() {
        assert!(!verify_password("anything", "sha256$notenough"));
        assert!(!verify_password("anything", "not-a-real-format-either"));
    }
}
