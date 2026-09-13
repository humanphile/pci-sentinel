import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

interface PciControl {
  control_id: string;
  title_en: string;
  mandate_text: string;
  required_artifacts: string[];
  sample_evidence?: string;
}

interface PciRequirementGroup {
  requirement_id: number;
  title: string;
  controls: PciControl[];
}

interface AuditResult {
  control_id: string;
  status: string;
  finding: string;
  remediation: string;
  evidence?: string;
}

interface ExportResponse {
  export_path: string;
  pubkey_b64: string;
  signature_b64: string;
  record_id: number;
}

interface AuditRecord {
  id: number;
  timestamp: string;
  framework: string;
  requirement: string;
  status: string;
  finding: string;
  remediation: string;
  evidence: string;
  sha256_digest: string;
  signature_b64: string;
  pubkey_b64: string;
  export_path: string;
}

const PCI_REQUIREMENTS = [
  { id: 1, name: "Req 1: Install & Maintain Network Security Controls" },
  { id: 2, name: "Req 2: Apply Secure Configurations to All Components" },
  { id: 3, name: "Req 3: Protect Stored Account Data" },
  { id: 4, name: "Req 4: Protect Cardholder Data in Transit" },
  { id: 5, name: "Req 5: Protect Systems from Malicious Software" },
  { id: 6, name: "Req 6: Develop & Maintain Secure Systems and Software" },
  { id: 7, name: "Req 7: Restrict Access by Business Need to Know" },
  { id: 8, name: "Req 8: Identify Users & Authenticate Access" },
  { id: 9, name: "Req 9: Restrict Physical Access to Cardholder Data" },
  { id: 10, name: "Req 10: Log & Monitor All Access to System Components" },
  { id: 11, name: "Req 11: Test Security of Systems & Networks Regularly" },
  { id: 12, name: "Req 12: Support InfoSec with Policies & Programs" },
];

export default function App() {
  // ==================== ALL HOOKS DECLARED AT THE TOP ====================
  const [selectedReqId, setSelectedReqId] = useState<number>(2);
  const [activeGroup, setActiveGroup] = useState<PciRequirementGroup | null>(null);
  const [activeControlIndex, setActiveControlIndex] = useState<number>(0);
  const [evidenceText, setEvidenceText] = useState<string>("");
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  
  const [completedAudits, setCompletedAudits] = useState<Record<string, AuditResult>>({});
  const [currentResult, setCurrentResult] = useState<AuditResult | null>(null);
  
  const [lastExport, setLastExport] = useState<ExportResponse | null>(null);
  const [verificationValid, setVerificationValid] = useState<boolean | null>(null);
  const [history, setHistory] = useState<AuditRecord[]>([]);
  const [showHistory, setShowHistory] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Password-protected knowledge base reset state
  const [showResetModal, setShowResetModal] = useState<boolean>(false);
  const [adminPassword, setAdminPassword] = useState<string>("");
  const [isResetting, setIsResetting] = useState<boolean>(false);

  // Authentication & Demo State
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [mustChangePassword, setMustChangePassword] = useState<boolean>(false);
  const [loginUser, setLoginUser] = useState<string>("demo");
  const [loginPass, setLoginPass] = useState<string>("demo");
  const [newPass, setNewPass] = useState<string>("");
  const [authError, setAuthError] = useState<string | null>(null);
  const [userRole, setUserRole] = useState<string>("demo");

  // Subscription & Activation State
  const [showActivationModal, setShowActivationModal] = useState<boolean>(false);
  const [licenseKeyInput, setLicenseKeyInput] = useState<string>("");
  const [machineHwid, setMachineHwid] = useState<string>("");
  const [isActivating, setIsActivating] = useState<boolean>(false);

  // Audit History Search & Filter State
  const [historySearchQuery, setHistorySearchQuery] = useState<string>("");
  const [historyStatusFilter, setHistoryStatusFilter] = useState<string>("ALL");
  // ======================================================================

  const loadRequirement = async (reqId: number) => {
    try {
      const res = await invoke<PciRequirementGroup | null>("get_pci_requirement_controls", {
        requirementNumber: reqId,
      });

      setCompletedAudits({});
      setCurrentResult(null);
      setLastExport(null);
      setVerificationValid(null);

      setActiveGroup(res);
      setSelectedReqId(reqId);
      setActiveControlIndex(0);

      if (res && res.controls.length > 0) {
        setEvidenceText(res.controls[0].sample_evidence || "");
      } else {
        setEvidenceText("");
      }
    } catch (err) {
      console.error("Failed to load requirement:", err);
    }
  };

  const loadHistory = async () => {
    try {
      const recs = await invoke<AuditRecord[]>("get_pci_audit_history");
      setHistory(recs || []);
    } catch (err) {
      console.error("Failed to load history:", err);
    }
  };

  useEffect(() => {
    loadRequirement(2);
    loadHistory();
  }, []);

  const activeControl: PciControl | undefined = activeGroup?.controls[activeControlIndex];

  const handleSelectControl = (index: number) => {
    if (!activeGroup || index < 0 || index >= activeGroup.controls.length) return;
    setActiveControlIndex(index);
    const ctrl = activeGroup.controls[index];
    setEvidenceText(completedAudits[ctrl.control_id]?.evidence || ctrl.sample_evidence || "");
    setCurrentResult(completedAudits[ctrl.control_id] || null);
    setVerificationValid(null);
  };

  const handleFileBrowse = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const MAX_SIZE = 5 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      setStatusMessage("⚠️ Error: File size exceeds the 5MB limit to prevent performance degradation.");
      return;
    }

    const reader = new FileReader();
    const fileExt = file.name.split('.').pop()?.toLowerCase();

    if (['txt', 'md', 'json', 'csv', 'log'].includes(fileExt || '')) {
      reader.onload = (event) => {
        const content = event.target?.result as string;
        setEvidenceText(`[Uploaded File: ${file.name}]\n\n${content}`);
        setStatusMessage(`✓ Loaded text file: ${file.name}`);
      };
      reader.readAsText(file);
    } else {
      reader.onload = () => {
        setEvidenceText(`[Uploaded Artifact File: ${file.name} (${(file.size / 1024).toFixed(1)} KB)]\nFile Type: ${file.type || fileExt}\n\n[Attached file payload successfully registered for audit evaluation.]`);
        setStatusMessage(`✓ Attached file artifact: ${file.name}`);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleEvaluateStep = async () => {
    if (!activeControl || !evidenceText.trim()) return;

    // --- DEMO RESTRICTION CHECK ---
    if (userRole === "demo" && auditedCount >= 1) {
      setStatusMessage("⚠️ Demo Limitation: Free trial accounts are restricted to 1 control audit per requirement. Flush memory or upgrade to unlock full access.");
      return;
    }
    // ------------------------------

    setIsEvaluating(true);
    setStatusMessage(`QSA Auditing Control ${activeControl.control_id}...`);

    try {
      const res = await invoke<AuditResult>("run_pci_control_audit", {
        evidence: evidenceText,
        requirementNumber: selectedReqId,
        controlId: activeControl.control_id,
      });

      const enriched: AuditResult = { ...res, evidence: evidenceText };
      setCurrentResult(enriched);
      setCompletedAudits((prev) => ({ ...prev, [enriched.control_id]: enriched }));
      setStatusMessage(`✓ Control ${enriched.control_id} evaluated: ${enriched.status}`);
    } catch (err) {
      setStatusMessage("Audit error: " + String(err));
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleExportSingle = async () => {
    if (!activeControl || !currentResult || !activeGroup) return;
    try {
      const payload = {
        requirement_title: activeGroup.title,
        control: { ...currentResult, evidence: evidenceText },
        evidence: evidenceText,
      };
      const res = await invoke<ExportResponse>("export_single_control_dossier", { payload });
      setLastExport(res);
      setVerificationValid(null);
      await loadHistory();
      setStatusMessage(`✓ Sealed Single Control Report for ${currentResult.control_id} (#${res.record_id})`);
    } catch (err) {
      setStatusMessage("Export failure: " + String(err));
    }
  };

  const handleExportConsolidated = async () => {
    if (!activeGroup || Object.keys(completedAudits).length === 0) {
      setStatusMessage("Evaluate at least one control before consolidating.");
      return;
    }

    try {
      const allResults: AuditResult[] = activeGroup.controls.map((c) => {
        return completedAudits[c.control_id] || {
          control_id: c.control_id,
          status: "INSUFFICIENT",
          finding: "No evidence artifact provided during audit wizard evaluation.",
          remediation: `Furnish required operational artifacts: ${c.required_artifacts.join(", ")}`,
          evidence: "No artifact uploaded.",
        };
      });

      const payload = {
        requirement_title: activeGroup.title,
        evidence: `Consolidated wizard audit trail covering ${activeGroup.title}.`,
        controls: allResults,
      };

      const res = await invoke<ExportResponse>("export_pci_dossier", { payload });
      setLastExport(res);
      setVerificationValid(null);
      await loadHistory();
      setStatusMessage(`✓ Consolidated Multi-Page Master Dossier Sealed (#${res.record_id})`);
    } catch (err) {
      setStatusMessage("Consolidated export failure: " + String(err));
    }
  };

  const handleFlushAndNextRequirement = async () => {
    const nextId = selectedReqId < 12 ? selectedReqId + 1 : 1;
    await loadRequirement(nextId);
    setStatusMessage(`Requirement ${selectedReqId} memory flushed. Loaded Requirement ${nextId}.`);
  };

  const handleResetKnowledgeBase = async () => {
    if (!adminPassword.trim()) {
      setStatusMessage("⚠️ Please enter the admin password.");
      return;
    }

    setIsResetting(true);
    try {
      const res = await invoke<string>("reset_llama_knowledge_base", {
        password: adminPassword,
      });
      setStatusMessage(`✓ ${res}`);
      setShowResetModal(false);
      setAdminPassword("");
    } catch (err) {
      setStatusMessage(`✗ Reset failed: ${err}`);
    } finally {
      setIsResetting(false);
    }
  };

  const handleOpenPdf = async (filePath: string) => {
    if (!filePath) return;
    try {
      await invoke("open_pdf_file", { filePath });
    } catch (err) {
      setStatusMessage("Could not open PDF: " + String(err));
    }
  };

  const handleVerify = async () => {
    if (!lastExport || !activeGroup) return;
    try {
      const isConsolidated = lastExport.export_path.includes("Consolidated");
      const controlsToVerify = isConsolidated
        ? activeGroup.controls.map((c) => completedAudits[c.control_id] || {
            control_id: c.control_id,
            status: "INSUFFICIENT",
            finding: "No evidence artifact provided during audit wizard evaluation.",
            remediation: `Furnish required operational artifacts: ${c.required_artifacts.join(", ")}`,
            evidence: "No artifact uploaded.",
          })
        : currentResult ? [{ ...currentResult, evidence: evidenceText }] : [];

      const payload = {
        requirement_title: isConsolidated ? activeGroup.title : `${activeGroup.title} - Control ${currentResult?.control_id}`,
        evidence: isConsolidated ? `Consolidated wizard audit trail covering ${activeGroup.title}.` : evidenceText,
        controls: controlsToVerify,
        pubkey_b64: lastExport.pubkey_b64,
        signature_b64: lastExport.signature_b64,
      };

      const valid = await invoke<boolean>("verify_pci_dossier", { payload });
      setVerificationValid(valid);
    } catch (err) {
      setVerificationValid(false);
      setStatusMessage("Verification error: " + String(err));
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    try {
      const res = await invoke<{ success: boolean; is_first_login: boolean; role: string; message: string }>("authenticate_user", {
        username: loginUser,
        password: loginPass,
      });

      if (res.success) {
        setUserRole(res.role);
        if (res.is_first_login && loginUser === "demo") {
          setMustChangePassword(true);
        } else {
          setIsAuthenticated(true);
        }
      } else {
        setAuthError(res.message);
      }
    } catch (err) {
      setAuthError("Login failed: " + String(err));
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    if (!newPass.trim() || newPass.length < 4) {
      setAuthError("Password must be at least 4 characters long.");
      return;
    }
    try {
      await invoke("update_password", { username: loginUser, newPassword: newPass });
      setMustChangePassword(false);
      setIsAuthenticated(true);
      setStatusMessage("✓ Password successfully updated. Welcome to PCI-Sentinel.");
    } catch (err) {
      setAuthError("Failed to update password: " + String(err));
    }
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setUserRole("demo");
    setMustChangePassword(false);
    setLoginPass("");
    setStatusMessage("✓ Logged out securely.");
  };

  const fetchMachineHwid = async () => {
    try {
      const hwid = await invoke<string>("get_machine_hardware_id");
      setMachineHwid(hwid);
    } catch (err) {
      console.error("Failed to fetch HWID:", err);
      setMachineHwid("UNKNOWN-HWID");
    }
  };

  const handleOpenActivationModal = () => {
    fetchMachineHwid();
    setShowActivationModal(true);
  };

  const handleActivateSubscription = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!licenseKeyInput.trim()) {
      setStatusMessage("⚠️ Please enter a valid subscription key.");
      return;
    }

    setIsActivating(true);
    try {
      const res = await invoke<string>("activate_subscription_key", {
        username: loginUser,
        licenseKey: licenseKeyInput.trim(),
      });
      setUserRole("subscriber");
      setStatusMessage(`✓ ${res}`);
      setShowActivationModal(false);
      setLicenseKeyInput("");
    } catch (err) {
      setStatusMessage("✗ Activation error: " + String(err));
    } finally {
      setIsActivating(false);
    }
  };

  const auditedCount = Object.keys(completedAudits).length;
  const passedCount = Object.values(completedAudits).filter((a) => a.status === "COMPLIANT").length;
  const failedCount = Object.values(completedAudits).filter((a) => a.status === "NON_COMPLIANT").length;
  const totalCount = activeGroup?.controls.length || 0;
  const progressPct = totalCount > 0 ? Math.round((auditedCount / totalCount) * 100) : 0;

  const filteredHistory = history.filter((rec) => {
    const matchesQuery = 
      rec.requirement.toLowerCase().includes(historySearchQuery.toLowerCase()) ||
      rec.finding.toLowerCase().includes(historySearchQuery.toLowerCase()) ||
      rec.sha256_digest.toLowerCase().includes(historySearchQuery.toLowerCase());
    
    const matchesStatus = 
      historyStatusFilter === "ALL" || rec.status === historyStatusFilter;

    return matchesQuery && matchesStatus;
  });

  // ==================== CONDITIONAL RETURN AFTER ALL HOOKS ====================
  if (!isAuthenticated) {
    return (
      <div className="app-shell" style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh", background: "#020617" }}>
        <div className="pane" style={{ width: "400px", padding: "24px", background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px" }}>
          <h2 style={{ marginBottom: "16px", textAlign: "center", color: "#38bdf8", fontSize: "1.1rem", letterSpacing: "1px" }}>
            PCI-SENTINEL ACCESS GATE
          </h2>
          
          {authError && (
            <div style={{ marginBottom: "12px", padding: "8px", background: "#7f1d1d", color: "#fca5a5", fontSize: "0.75rem", borderRadius: "6px", border: "1px solid #991b1b" }}>
              {authError}
            </div>
          )}

          {!mustChangePassword ? (
            <form onSubmit={handleLogin}>
              <label className="label">Username</label>
              <input 
                className="select-box" 
                style={{ marginBottom: "12px", width: "100%", background: "#020617", color: "#e2e8f0" }}
                value={loginUser}
                onChange={(e) => setLoginUser(e.target.value)}
                placeholder="Username"
              />
              <label className="label">Password</label>
              <input 
                type="password"
                className="select-box" 
                style={{ marginBottom: "16px", width: "100%", background: "#020617", color: "#e2e8f0" }}
                value={loginPass}
                onChange={(e) => setLoginPass(e.target.value)}
                placeholder="Password"
              />
              <button type="submit" className="btn-primary" style={{ width: "100%" }}>
                Login to Enclave
              </button>
            </form>
          ) : (
            <form onSubmit={handleChangePassword}>
              <div style={{ fontSize: "0.75rem", color: "#38bdf8", marginBottom: "12px", lineHeight: "1.4" }}>
                First-time login detected for demo account. You must change your password to proceed into the application.
              </div>
              <label className="label">New Secure Password</label>
              <input 
                type="password"
                className="select-box" 
                style={{ marginBottom: "16px", width: "100%", background: "#020617", color: "#e2e8f0" }}
                value={newPass}
                onChange={(e) => setNewPass(e.target.value)}
                placeholder="Enter new password (min 4 chars)..."
              />
              <button type="submit" className="btn-primary" style={{ width: "100%" }}>
                Update Password & Enter
              </button>
            </form>
          )}
        </div>
      </div>
    );
  }
  // ============================================================================

  return (
    <div className="app-shell">
      <header className="analytics-header">
        <div className="analytics-stat">
          <span className="stat-label">WIZARD PROGRESS</span>
          <span className="stat-value">{auditedCount} / {totalCount} ({progressPct}%)</span>
        </div>
        <div className="analytics-stat">
          <span className="stat-label">PASSED</span>
          <span className="stat-value green">{passedCount}</span>
        </div>
        <div className="analytics-stat">
          <span className="stat-label">VIOLATIONS</span>
          <span className="stat-value red">{failedCount}</span>
        </div>
        <div className="analytics-stat">
          <span className="stat-label">ACTIVE STEP</span>
          <span className="stat-value" style={{ color: "#38bdf8" }}>{activeControl?.control_id || "--"}</span>
        </div>
      </header>

      <div className="container">
        {/* Pane 1: Audit Wizard */}
        <section className="pane">
          <div className="pane-header">
            <h2>AUDIT WIZARD</h2>
            <span className="badge-pci">Step {activeControlIndex + 1} of {totalCount}</span>
          </div>

          <label className="label">Target Requirement Domain</label>
          <select
            className="select-box"
            value={selectedReqId}
            onChange={(e) => loadRequirement(Number(e.target.value))}
          >
            {PCI_REQUIREMENTS.map((req) => (
              <option key={req.id} value={req.id}>
                {req.name}
              </option>
            ))}
          </select>

          <label className="label">Select Sub-Control Step</label>
          <select
            className="select-box"
            value={activeControlIndex}
            onChange={(e) => handleSelectControl(Number(e.target.value))}
          >
            {activeGroup?.controls.map((c, idx) => (
              <option key={c.control_id} value={idx}>
                [{c.control_id}] {c.title_en} {completedAudits[c.control_id] ? `(${completedAudits[c.control_id].status})` : ""}
              </option>
            ))}
          </select>

          {activeControl && (
            <div 
              className="baseline-banner custom-scrollbar" 
              style={{ maxHeight: "240px", overflowY: "auto", paddingRight: "6px" }}
            >
              <div style={{ fontWeight: 800, color: "#38bdf8", marginBottom: "4px" }}>
                [{activeControl.control_id}] {activeControl.title_en}
              </div>
              <div style={{ fontSize: "0.72rem", color: "#cbd5e1", marginBottom: "6px" }}>
                {activeControl.mandate_text}
              </div>
              <div style={{ fontSize: "0.68rem", color: "#94a3b8" }}>
                <strong>Expected Artifacts:</strong> {activeControl.required_artifacts.join(", ")}
              </div>
            </div>
          )}

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "8px", marginBottom: "4px" }}>
            <label className="label" style={{ margin: 0 }}>Step Evidence Artifact</label>
            <label style={{ fontSize: "0.7rem", color: "#38bdf8", cursor: "pointer", background: "#082f49", padding: "2px 8px", borderRadius: "4px", border: "1px solid #0284c7" }}>
              📁 Browse...
              <input 
                type="file" 
                style={{ display: "none" }} 
                accept=".txt,.md,.json,.csv,.log,.pdf,.png,.jpg,.jpeg"
                onChange={handleFileBrowse}
              />
            </label>
          </div>
          <textarea
            className="evidence-area"
            value={evidenceText}
            onChange={(e) => setEvidenceText(e.target.value)}
            placeholder="Paste operational evidence, policies, or configs, or click 'Browse...' to upload a file (Max 5MB)..."
          />

          <div style={{ display: "flex", gap: "8px", marginBottom: "8px" }}>
            <button
              className="btn-secondary"
              style={{ flex: 1 }}
              onClick={() => handleSelectControl(Math.max(0, activeControlIndex - 1))}
              disabled={activeControlIndex === 0}
            >
              ← Previous
            </button>
            <button
              className="btn-secondary"
              style={{ flex: 1 }}
              onClick={() => handleSelectControl(Math.min(totalCount - 1, activeControlIndex + 1))}
              disabled={activeControlIndex === totalCount - 1}
            >
              Next →
            </button>
          </div>

          <button
            className="btn-primary"
            onClick={handleEvaluateStep}
            disabled={isEvaluating || !evidenceText.trim()}
          >
            {isEvaluating ? "Evaluating Control via Metal..." : `⚡ Audit Control ${activeControl?.control_id || ""}`}
          </button>
        </section>

        {/* Pane 2: Step Assessment */}
        <section className="pane">
          <div className="pane-header">
            <h2>STEP ASSESSMENT</h2>
            <span className="badge-pci" style={{ color: "#34d399", borderColor: "#065f46" }}>Temperature: 0.0</span>
          </div>

          <label className="label">PROGRESS MATRIX ({activeGroup?.title || "Requirement"})</label>
          <div style={{ 
            maxHeight: "220px", 
            overflowY: "auto", 
            paddingRight: "4px", 
            marginBottom: "12px",
            border: "1px solid #1e293b",
            borderRadius: "6px",
            padding: "8px",
            background: "#020617"
          }} className="custom-scrollbar">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "6px" }}>
              {activeGroup?.controls.map((control, idx) => {
                const audit = completedAudits[control.control_id];
                const isSelected = activeControlIndex === idx;
                return (
                  <button
                    key={control.control_id}
                    onClick={() => handleSelectControl(idx)}
                    style={{
                      background: isSelected ? "#082f49" : "#0f172a",
                      border: isSelected ? "1px solid #0284c7" : "1px solid #1e293b",
                      borderRadius: "6px",
                      padding: "8px 4px",
                      textAlign: "center",
                      cursor: "pointer",
                      color: isSelected ? "#38bdf8" : "#94a3b8",
                      transition: "all 0.2s"
                    }}
                  >
                    <div style={{ fontSize: "0.75rem", fontWeight: 700 }}>{control.control_id}</div>
                    <div style={{ fontSize: "0.55rem", textTransform: "uppercase", marginTop: "2px", opacity: 0.8 }}>
                      {audit?.status || 'PENDING'}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          <label className="label">CURRENT CONTROL VERDICT</label>
          <div className="card" style={{ marginBottom: "12px", padding: "10px" }}>
            <p className="mono-text" style={{ fontWeight: 700, color: currentResult?.status === "COMPLIANT" ? "#34d399" : currentResult?.status === "NON_COMPLIANT" ? "#f87171" : "#e2e8f0" }}>
              {currentResult?.status || 'NOT YET EVALUATED'}
            </p>
          </div>

          <label className="label">AUDIT FINDING / OBSERVATION</label>
          <div className="card custom-scrollbar" style={{ maxHeight: "130px", overflowY: "auto", padding: "10px" }}>
            <p style={{ fontSize: "0.75rem", color: "#cbd5e1", margin: 0, lineHeight: 1.4 }}>
              {currentResult?.finding || 'Evaluate evidence to generate observation.'}
            </p>
          </div>
        </section>

        {/* Pane 3: Attestation & Reports */}
        <section className="pane">
          <div className="pane-header">
            <h2>ATTESTATION & REPORTS</h2>
            <button className="btn-history-toggle" onClick={() => setShowHistory(!showHistory)}>
              {showHistory ? "← Attestation" : `📜 Trail (${history.length})`}
            </button>
          </div>

          {statusMessage && <div className="status-notification">{statusMessage}</div>}

          {!showHistory ? (
            <>
              <div className="card">
                <label className="card-label">Hardware Enclave</label>
                <p className="mono-text green">Apple Silicon Metal (Isolated PCI Enclave)</p>

                <label className="card-label">Last Exported Report</label>
                <p className="mono-text wrap">{lastExport ? lastExport.export_path.split("/").pop() : "None yet"}</p>

                <label className="card-label">Ed25519 Seal Signature</label>
                <p className="mono-text wrap">{lastExport?.signature_b64 || "Unsealed"}</p>
              </div>

              {verificationValid !== null && (
                <div className={`verification-banner ${verificationValid ? "banner-valid" : "banner-invalid"}`}>
                  {verificationValid
                    ? "✓ ED25519 SEAL VALID (FULL DOSSIER & EVIDENCE VERIFIED)"
                    : "✗ SIGNATURE INVALID (INTEGRITY COMPROMISED)"}
                </div>
              )}

              <div className="action-footer">
                <button
                  className="btn-export"
                  style={{ background: "#0284c7", marginBottom: "8px" }}
                  onClick={handleExportSingle}
                  disabled={!currentResult}
                >
                  Seal Single Control Report [{activeControl?.control_id}]
                </button>

                <button
                  className="btn-export"
                  onClick={handleExportConsolidated}
                  disabled={auditedCount === 0}
                >
                  Seal Consolidated Dossier ({auditedCount}/{totalCount})
                </button>

                <button
                  className="btn-secondary"
                  style={{ width: "100%", marginTop: "6px", marginBottom: "6px" }}
                  onClick={handleFlushAndNextRequirement}
                >
                  🧹 Flush Memory & Next Requirement →
                </button>

                <button className="btn-verify" onClick={handleVerify} disabled={!lastExport}>
                  Verify Active Cryptographic Seal
                </button>

                {/* Subscription Upgrade Button */}
                {userRole === "demo" && (
                  <button
                    className="btn-primary"
                    style={{ width: "100%", marginTop: "8px", background: "#0284c7" }}
                    onClick={handleOpenActivationModal}
                  >
                    ⭐ Upgrade to Full Subscription
                  </button>
                )}

                {showActivationModal && (
                  <div style={{
                    marginTop: "10px",
                    padding: "14px",
                    background: "#0f172a",
                    border: "1px solid #0284c7",
                    borderRadius: "8px"
                  }}>
                    <label className="label" style={{ color: "#38bdf8", fontSize: "0.7rem" }}>Hardware ID (HWID)</label>
                    <div style={{ 
                      fontSize: "0.65rem", 
                      background: "#020617", 
                      color: "#94a3b8", 
                      padding: "6px", 
                      borderRadius: "4px", 
                      marginBottom: "8px",
                      wordBreak: "break-all",
                      fontFamily: "monospace"
                    }}>
                      {machineHwid}
                    </div>

                    <form onSubmit={handleActivateSubscription}>
                      <label className="label" style={{ color: "#38bdf8", fontSize: "0.7rem" }}>Enter License Key</label>
                      <input
                        type="text"
                        className="select-box"
                        style={{ marginBottom: "8px", fontSize: "0.75rem", padding: "6px", background: "#020617", color: "#e2e8f0" }}
                        value={licenseKeyInput}
                        onChange={(e) => setLicenseKeyInput(e.target.value)}
                        placeholder="PCI-SUB-xxxxxxxx..."
                      />
                      <div style={{ display: "flex", gap: "6px" }}>
                        <button
                          type="submit"
                          className="btn-primary"
                          style={{ flex: 1, fontSize: "0.7rem", padding: "6px" }}
                          disabled={isActivating}
                        >
                          {isActivating ? "Activating..." : "Activate Key"}
                        </button>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{ flex: 1, fontSize: "0.7rem", padding: "6px" }}
                          onClick={() => { setShowActivationModal(false); setLicenseKeyInput(""); }}
                        >
                          Cancel
                        </button>
                      </div>
                    </form>
                  </div>
                )}

                {/* Logout Button */}
                <button
                  className="btn-secondary"
                  style={{ width: "100%", marginTop: "12px", background: "#334155", borderColor: "#475569", color: "#f8fafc" }}
                  onClick={handleLogout}
                >
                  🚪 Secure Logout
                </button>

                {/* Password Protected Reset Button */}
                <button
                  className="btn-secondary"
                  style={{ width: "100%", marginTop: "8px", background: "#7f1d1d", borderColor: "#991b1b", color: "#fca5a5" }}
                  onClick={() => setShowResetModal(true)}
                >
                  🔒 Reset Llama Knowledge Base
                </button>

                {showResetModal && (
                  <div style={{
                    marginTop: "10px",
                    padding: "12px",
                    background: "#0f172a",
                    border: "1px solid #ef4444",
                    borderRadius: "8px"
                  }}>
                    <label className="label" style={{ color: "#fca5a5", fontSize: "0.7rem" }}>Enter Admin Password</label>
                    <input
                      type="password"
                      className="select-box"
                      style={{ marginBottom: "8px", borderColor: "#ef4444", fontSize: "0.75rem", padding: "6px" }}
                      value={adminPassword}
                      onChange={(e) => setAdminPassword(e.target.value)}
                      placeholder="Admin password..."
                    />
                    <div style={{ display: "flex", gap: "6px" }}>
                      <button
                        className="btn-primary"
                        style={{ flex: 1, background: "#dc2626", fontSize: "0.7rem", padding: "6px" }}
                        onClick={handleResetKnowledgeBase}
                        disabled={isResetting}
                      >
                        {isResetting ? "Resetting..." : "Confirm"}
                      </button>
                      <button
                        className="btn-secondary"
                        style={{ flex: 1, fontSize: "0.7rem", padding: "6px" }}
                        onClick={() => { setShowResetModal(false); setAdminPassword(""); }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="history-list">
              <label className="label">SEALED DOSSIERS ({filteredHistory.length} of {history.length})</label>
              
              {/* Search & Filter Controls */}
              <div style={{ display: "flex", gap: "6px", marginBottom: "8px" }}>
                <input
                  type="text"
                  className="select-box"
                  style={{ flex: 2, fontSize: "0.7rem", padding: "6px", background: "#020617", color: "#e2e8f0" }}
                  value={historySearchQuery}
                  onChange={(e) => setHistorySearchQuery(e.target.value)}
                  placeholder="Search requirement, finding, SHA..."
                />
                <select
                  className="select-box"
                  style={{ flex: 1, fontSize: "0.7rem", padding: "6px", background: "#020617", color: "#e2e8f0" }}
                  value={historyStatusFilter}
                  onChange={(e) => setHistoryStatusFilter(e.target.value)}
                >
                  <option value="ALL">All Status</option>
                  <option value="COMPLIANT">Passed</option>
                  <option value="NON_COMPLIANT">Failed</option>
                </select>
              </div>

              {filteredHistory.length === 0 ? (
                <div style={{ textAlign: "center", padding: "20px", fontSize: "0.75rem", color: "#64748b" }}>
                  No matching dossiers found.
                </div>
              ) : (
                filteredHistory.map((rec) => (
                  <div key={rec.id} className="history-card">
                    <div className="history-header">
                      <span className="history-id">#{rec.id}</span>
                      <span className={`history-tag ${rec.status === "COMPLIANT" ? "tag-pass" : "tag-fail"}`}>
                        {rec.status}
                      </span>
                    </div>
                    <div className="history-title">{rec.requirement}</div>
                    <div className="history-date">{rec.timestamp}</div>
                    <div className="history-digest">SHA: {rec.sha256_digest.substring(0, 16)}...</div>

                    {rec.export_path ? (
                      <button
                        className="btn-open-report"
                        onClick={() => handleOpenPdf(rec.export_path)}
                      >
                        📄 Open Report PDF
                      </button>
                    ) : null}
                  </div>
                ))
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}