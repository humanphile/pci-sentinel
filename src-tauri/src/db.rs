use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditRecord {
pub id: i64,
pub timestamp: String,
pub framework: String,
pub requirement: String,
pub status: String,
pub finding: String,
pub remediation: String,
pub evidence: String,
pub sha256_digest: String,
pub signature_b64: String,
pub pubkey_b64: String,
pub export_path: String,
}

fn get_db_path() -> PathBuf {
let mut dir = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
dir.push("pci-sentinel");
let _ = fs::create_dir_all(&dir);
dir.join("pci_audit_trail.db")
}

pub fn get_connection() -> Result<Connection, rusqlite::Error> {
let path = get_db_path();
Connection::open(path)
}

pub fn init_database() -> Result<(), String> {
    let conn = get_connection().map_err(|e| format!("Failed to open DB: {}", e))?;

    // Existing Audit Records Table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS pci_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            framework TEXT NOT NULL,
            requirement TEXT NOT NULL,
            status TEXT NOT NULL,
            finding TEXT NOT NULL,
            remediation TEXT NOT NULL,
            evidence TEXT NOT NULL,
            sha256_digest TEXT NOT NULL,
            signature_b64 TEXT NOT NULL,
            pubkey_b64 TEXT NOT NULL,
            export_path TEXT NOT NULL DEFAULT ''
        )",
        [],
    ).map_err(|e| format!("Failed to initialize table: {}", e))?;

    let _ = conn.execute("ALTER TABLE pci_records ADD COLUMN export_path TEXT NOT NULL DEFAULT ''", []);

    // Users Table (Without hardcoded seeding)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_first_login BOOLEAN NOT NULL DEFAULT 1,
            role TEXT NOT NULL DEFAULT 'demo',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    ).map_err(|e| format!("Failed to initialize users table: {}", e))?;

    Ok(())
}

pub fn insert_audit_record(
timestamp: &str,
framework: &str,
requirement: &str,
status: &str,
finding: &str,
remediation: &str,
evidence: &str,
sha256_digest: &str,
signature_b64: &str,
pubkey_b64: &str,
export_path: &str,
) -> Result<i64, String> {
let conn = get_connection().map_err(|e| format!("Failed to open DB: {}", e))?;

conn.execute(
    "INSERT INTO pci_records (
        timestamp, framework, requirement, status, finding, remediation,
        evidence, sha256_digest, signature_b64, pubkey_b64, export_path
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    params![
        timestamp, framework, requirement, status, finding, remediation,
        evidence, sha256_digest, signature_b64, pubkey_b64, export_path
    ],
).map_err(|e| format!("Failed to insert record: {}", e))?;

Ok(conn.last_insert_rowid())
}

pub fn fetch_audit_history() -> Result<Vec<AuditRecord>, String> {
let conn = get_connection().map_err(|e| format!("Failed to open DB: {}", e))?;

let mut stmt = conn
    .prepare("SELECT id, timestamp, framework, requirement, status, finding, remediation, evidence, sha256_digest, signature_b64, pubkey_b64, export_path FROM pci_records ORDER BY id DESC")
    .map_err(|e| format!("Query preparation failed: {}", e))?;

let rows = stmt
    .query_map([], |row| {
        Ok(AuditRecord {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            framework: row.get(2)?,
            requirement: row.get(3)?,
            status: row.get(4)?,
            finding: row.get(5)?,
            remediation: row.get(6)?,
            evidence: row.get(7)?,
            sha256_digest: row.get(8)?,
            signature_b64: row.get(9)?,
            pubkey_b64: row.get(10)?,
            export_path: row.get(11)?,
        })
    })
    .map_err(|e| format!("Query error: {}", e))?;

let mut history = Vec::new();
for r in rows {
    if let Ok(rec) = r {
        history.push(rec);
    }
}
Ok(history)
}