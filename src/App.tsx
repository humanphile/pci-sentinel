import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";
import { isTauri } from './utils/env';

export function useServerShutdownGuard() {
  useEffect(() => {
    const handleBeforeUnload = () => {
      invoke('stop_inference_server').catch(() => {});
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, []);
}

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
  control_id: string;
  requirement_number: number;
  status: string;
  summary: string;
  evidence_hash: string;
  username: string;
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
  useServerShutdownGuard();

  // ==================== ALL HOOKS DECLARED AT THE TOP (STRICT RULE) ====================
  const [isServerReady, setIsServerReady] = useState<boolean>(false);
  const [bootStatusMsg, setBootStatusMsg] = useState<string>("Initializing Sentinel GRC Secure Enclave...");
  const [bootError, setBootError] = useState<string | null>(null);
  const [bootAttempt, setBootAttempt] = useState<number>(0);

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
  const [demoUsage, setDemoUsage] = useState<{ tested_controls: string[]; quota: number } | null>(null);
  const [showHistory, setShowHistory] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const [showResetModal, setShowResetModal] = useState<boolean>(false);
  const [adminPassword, setAdminPassword] = useState<string>("");
  const [isResetting, setIsResetting] = useState<boolean>(false);

  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [mustChangePassword, setMustChangePassword] = useState<boolean>(false);
  const [loginUser, setLoginUser] = useState<string>("demo");
  const [loginPass, setLoginPass] = useState<string>("demo");
  const [newPass, setNewPass] = useState<string>("");
  const [authError, setAuthError] = useState<string | null>(null);
  const [userRole, setUserRole] = useState<string>(isTauri() ? "admin" : "demo");

  const [showActivationModal, setShowActivationModal] = useState<boolean>(false);
  const [licenseKeyInput, setLicenseKeyInput] = useState<string>("");
  const [machineHwid, setMachineHwid] = useState<string>("");
  const [isActivating, setIsActivating] = useState<boolean>(false);

  const [historySearchQuery, setHistorySearchQuery] = useState<string>("");
  const [historyStatusFilter, setHistoryStatusFilter] = useState<string>("ALL");

  const [showAboutModal, setShowAboutModal] = useState(false);


  const [showChangePasswordModal, setShowChangePasswordModal] = useState<boolean>(false);
  const [oldPasswordInput, setOldPasswordInput] = useState<string>("");
  const [changeNewPassInput, setChangeNewPassInput] = useState<string>("");
  const [changePassError, setChangePassError] = useState<string | null>(null);

  const [showShutdownConfirmModal, setShowShutdownConfirmModal] = useState<boolean>(false);

  const [imageEvidenceB64, setImageEvidenceB64] = useState<string | null>(null);
  const [isFlushing, setIsFlushing] = useState<boolean>(false);
  
// ====================================================================================

  // Surface fatal runtime bootstrap failures from the Rust side (download
  // errors, missing runtime assets, server spawn failures).
  useEffect(() => {
    if (!isTauri()) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      const un = await listen<string>("bootstrap-error", (event) => {
        if (!cancelled && event.payload) setBootError(event.payload);
      });
      if (cancelled) un();
      else unlisten = un;
    })();
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  // Poll server health on startup until llama-server is ready. A failed or
  // missing runtime would otherwise leave the splash screen forever, so we
  // fail loudly after a generous timeout and offer a Retry path.
  useEffect(() => {
    let interval: ReturnType<typeof setInterval> | undefined;
    const timeout = setTimeout(() => {
      if (interval) clearInterval(interval);
      setBootError(
        "Timed out waiting for the local inference engine to become ready. " +
        "The runtime may have failed to download or start. Verify your network connection and try again."
      );
    }, 120_000);

    interval = setInterval(async () => {
      try {
        const res = await fetch('http://127.0.0.1:8090/health');
        if (res.ok) {
          clearInterval(interval);
          clearTimeout(timeout);
          setIsServerReady(true);
        }
      } catch (e) {
        setBootStatusMsg('Downloading model weights or spinning up secure local inference server...');
      }
    }, 1500);

    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, [bootAttempt]);

  const handleRetryBoot = async () => {
    setBootError(null);
    setBootStatusMsg("Retrying runtime setup...");
    if (isTauri()) {
      try {
        await invoke("ensure_inference_runtime");
        await invoke("start_inference_server");
      } catch (err) {
        setBootError(String(err));
        return;
      }
    }
    // Re-arm the health poll (timeout + interval) via a fresh boot attempt.
    setBootAttempt((n) => n + 1);
  };

  const loadRequirement = async (reqId: number, hydrate: boolean = true) => {
    try {
      setImageEvidenceB64(null);
      const res = await invoke<PciRequirementGroup | null>("get_pci_requirement_controls", {
        requirementNumber: reqId,
      });

      // Pull the persistent trail from the encrypted SQLite store so switching
      // requirements never erases previously saved evaluations — unless a
      // "flush" was requested, in which case the wizard starts from a clean
      // slate (the durable trail below stays intact in the database).
      let saved: Record<string, AuditResult> = {};
      if (hydrate) {
        try {
          const recs = await invoke<AuditRecord[]>("get_pci_audit_history");
          setHistory(recs || []);
          saved = hydrateCompletedFromHistory(recs || [], reqId);
        } catch (err) {
          console.error("Failed to load audit history:", err);
        }
      }

      setCompletedAudits(saved);
      setCurrentResult(null);
      setLastExport(null);
      setVerificationValid(null);

      setActiveGroup(res);
      setSelectedReqId(reqId);
      setActiveControlIndex(0);

      if (res && res.controls.length > 0) {
        const ctrl = res.controls[0];
        setEvidenceText(saved[ctrl.control_id]?.evidence || ctrl.sample_evidence || "");
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

  // Rebuild the in-memory progress matrix from the persisted SQLite trail for
  // a given requirement, so progress survives requirement switches and restarts.
  const hydrateCompletedFromHistory = (recs: AuditRecord[], reqId: number): Record<string, AuditResult> => {
    const map: Record<string, AuditResult> = {};
    for (const rec of recs) {
      if (rec.requirement_number === reqId) {
        map[rec.control_id] = {
          control_id: rec.control_id,
          status: rec.status,
          finding: rec.summary,
          remediation: "",
          evidence: "",
        };
      }
    }
    return map;
  };

  useEffect(() => {
    if (isServerReady) {
      loadRequirement(2);
      loadHistory();
    }
  }, [isServerReady]);

  // Demo-trial bookkeeping for the current requirement: mirrors the backend
  // restriction SQL so the hint under the control picker stays truthful and
  // updates immediately after each evaluation.
  useEffect(() => {
    if (!isServerReady || userRole !== "demo") {
      setDemoUsage(null);
      return;
    }
    invoke<{ tested_controls: string[]; quota: number }>("get_demo_requirement_usage", {
      requirementNumber: selectedReqId,
    })
      .then(setDemoUsage)
      .catch((err) => console.error("Failed to load demo usage:", err));
  }, [isServerReady, userRole, selectedReqId, history]);

  const activeControl: PciControl | undefined = activeGroup?.controls[activeControlIndex];

  // Demo-trial hint state for the control picker.
  const demoTested = demoUsage?.tested_controls ?? [];
  const demoSlotUsed = demoTested.length > 0;
  const demoSlotUsedBySelection =
    demoSlotUsed && activeControl ? demoTested.includes(activeControl.control_id) : false;
  const demoHintText = !demoSlotUsed
    ? `Demo trial: 1 of 1 control slot remaining for Requirement ${selectedReqId} — it can be verified only once.`
    : demoSlotUsedBySelection
    ? `Demo trial: control ${demoTested[0]} already verified — this requirement's 1 slot is used (no re-verification).`
    : `Demo trial: slot used by ${demoTested[0]} — other controls in Requirement ${selectedReqId} require a subscription.`;

  const handleSelectControl = (index: number) => {
    if (!activeGroup || index < 0 || index >= activeGroup.controls.length) return;
    setActiveControlIndex(index);
    setImageEvidenceB64(null);
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

    const IMAGE_EXTS = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'heic'];

    const reader = new FileReader();
    const fileExt = file.name.split('.').pop()?.toLowerCase();

    if (['txt', 'md', 'json', 'csv', 'log'].includes(fileExt || '')) {
      reader.onload = (event) => {
        const content = event.target?.result as string;
        setEvidenceText(`[Uploaded File: ${file.name}]\n\n${content}`);
        setImageEvidenceB64(null);
        setStatusMessage(`✓ Loaded text file: ${file.name}`);
      };
      reader.readAsText(file);
    } else if (IMAGE_EXTS.includes(fileExt || '')) {
      // Images are captured as base64 payloads and OCR-scanned locally
      // (Apple Vision on macOS) so the text-only local LLM can genuinely
      // evaluate the image content instead of hallucinating about it.
      reader.onload = (event) => {
        const dataUrl = event.target?.result as string;
        const b64 = dataUrl.includes(',') ? dataUrl.split(',')[1] : dataUrl;
        setImageEvidenceB64(b64);
        setEvidenceText(`[Uploaded Artifact File: ${file.name} (${(file.size / 1024).toFixed(1)} KB)]\nFile Type: ${file.type || fileExt}\n\n[Image payload captured. The enclave will OCR this image locally before the QSA evaluates its content.]`);
        setStatusMessage(`✓ Image attached: ${file.name} — content will be OCR-scanned locally, then evaluated against the control mandate.`);
      };
      reader.readAsDataURL(file);
    } else {
      reader.onload = () => {
        setEvidenceText(`[Uploaded Artifact File: ${file.name} (${(file.size / 1024).toFixed(1)} KB)]\nFile Type: ${file.type || fileExt}\n\n[Attached file payload successfully registered for audit evaluation.]`);
        setImageEvidenceB64(null);
        setStatusMessage(`✓ Attached file artifact: ${file.name}`);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleEvaluateStep = async () => {
    if (!activeControl || !evidenceText.trim()) return;

    setIsEvaluating(true);
    setStatusMessage(`QSA Auditing Control ${activeControl.control_id}...`);

    try {
      const res = await invoke<AuditResult>("run_pci_control_audit", {
        evidence: evidenceText,
        requirementNumber: selectedReqId,
        controlId: activeControl.control_id,
        evidenceBinaryBase64: imageEvidenceB64 ?? undefined,
      });

      const enriched: AuditResult = { ...res, evidence: evidenceText };
      setCurrentResult(enriched);
      setCompletedAudits((prev) => ({ ...prev, [enriched.control_id]: enriched }));
      setStatusMessage(`✓ Control ${enriched.control_id} evaluated: ${enriched.status}`);

      // Refresh the persistent trail from the encrypted database immediately so
      // the Trail counter and progress matrix stay in sync with what was saved.
      try {
        const recs = await invoke<AuditRecord[]>("get_pci_audit_history");
        setHistory(recs || []);
        const hydrated = hydrateCompletedFromHistory(recs || [], selectedReqId);
        setCompletedAudits((prev) => ({ ...hydrated, ...prev }));
      } catch (err) {
        console.error("Failed to refresh audit trail:", err);
      }
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
	if (userRole === "demo") {
    setStatusMessage("⚠️ Demo Limitation: Consolidated master dossier export requires an enterprise subscription key.");
    setShowActivationModal(true);
    return;
  }   

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
    const currentId = selectedReqId;
    const nextId = currentId < 12 ? currentId + 1 : 1;

    setIsFlushing(true);
    setStatusMessage(`Flushing inference engine memory & loading Requirement ${nextId}...`);

    // Kill and respawn llama-server with a fresh model context (releases any
    // retained KV cache / conversation state), then start the next requirement
    // with a clean wizard slate.
    if (isTauri()) {
      try {
        await invoke("restart_inference_server");
        setStatusMessage(`✓ Inference engine flushed and restarted fresh. Loading Requirement ${nextId}...`);
      } catch (err) {
        setStatusMessage(`⚠️ Flush warning: ${String(err)} (continuing to next requirement)`);
      }
    }

    // Fresh knowledge base: clear the in-memory wizard state and load the next
    // requirement WITHOUT re-hydrating the progress matrix from the trail. The
    // durable trail in the encrypted database is intentionally left intact.
    setCompletedAudits({});
    setCurrentResult(null);
    setLastExport(null);
    setVerificationValid(null);
    setImageEvidenceB64(null);
    await loadRequirement(nextId, false);
    setIsFlushing(false);
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
      // The sealed trail was wiped on the backend; reflect that in the wizard
      // matrix and Trail view, and load the current requirement fresh.
      setCompletedAudits({});
      setCurrentResult(null);
      setHistory([]);
      setImageEvidenceB64(null);
      await loadRequirement(selectedReqId, false);
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

  // (PDF viewing is available at export time via the "Open Report" flow; the
  // persistent trail keeps the finding summary + evidence digest instead of a
  // file path, since reports are sealed to the user's Desktop.)

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
        if (res.is_first_login) {
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
    if (!newPass.trim() || newPass.length < 8) {
      setAuthError("Password must be at least 8 characters long.");
      return;
    }
    try {
      await invoke("update_password", { username: loginUser, newPassword: newPass });
      setMustChangePassword(false);
      setIsAuthenticated(true);
      setStatusMessage("✓ Password successfully updated.");
    } catch (err) {
      setAuthError("Failed to update password: " + String(err));
    }
  };

 // const handleLogout = () => {
 //   setIsAuthenticated(false);
 //   setUserRole("demo");
 //   setMustChangePassword(false);
 //   setLoginPass("");
 //   setStatusMessage("✓ Logged out securely.");
 // };



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
        licenseString: licenseKeyInput.trim(),
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
    const reqLabel = `req ${rec.requirement_number}`;
    const matchesQuery = 
      reqLabel.toLowerCase().includes(historySearchQuery.toLowerCase()) ||
      (rec.control_id ?? "").toLowerCase().includes(historySearchQuery.toLowerCase()) ||
      rec.summary.toLowerCase().includes(historySearchQuery.toLowerCase()) ||
      rec.evidence_hash.toLowerCase().includes(historySearchQuery.toLowerCase());
    
    const matchesStatus = 
      historyStatusFilter === "ALL" || rec.status === historyStatusFilter;

    return matchesQuery && matchesStatus;
  });

  // ==================== CONDITIONAL RENDERS (AFTER ALL HOOKS) ====================

  // 1. Splash screen while server/model boots up
  if (!isServerReady) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh', background: '#020617', color: '#f8fafc', fontFamily: 'sans-serif' }}>
        {!bootError ? (
          <>
            <div style={{ width: '48px', height: '48px', border: '4px solid #1e293b', borderTop: '4px solid #38bdf8', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
            <h2 style={{ marginTop: '24px', fontSize: '1.25rem', letterSpacing: '1px', color: '#38bdf8' }}>SENTINEL GRC SECURE ENCLAVE</h2>
            <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '8px', maxWidth: '400px', textAlign: 'center', lineHeight: '1.4' }}>{bootStatusMsg}</p>
          </>
        ) : (
          <div style={{ maxWidth: '420px', width: '100%', margin: '0 16px', background: '#0f172a', border: '1px solid #991b1b', borderRadius: '12px', padding: '20px' }}>
            <h2 style={{ fontSize: '1.05rem', letterSpacing: '1px', color: '#fca5a5', margin: '0 0 10px 0' }}>
              ⚠️ ENCLAVE STARTUP FAILED
            </h2>
            <p style={{ color: '#94a3b8', fontSize: '0.78rem', lineHeight: '1.5', margin: '0 0 18px 0', wordBreak: 'break-word' }}>
              {bootError}
            </p>
            <button
              className="btn-primary"
              style={{ width: '100%' }}
              onClick={handleRetryBoot}
            >
              🔄 Retry Runtime Setup
            </button>
          </div>
        )}
        <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  // 2. Login gate if not authenticated
  if (!isAuthenticated) {
    return (
      <div className="app-shell" style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh", background: "#020617" }}>
        <div className="pane" style={{ width: "400px", padding: "24px", background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px" }}>
          <h2 style={{ marginBottom: "16px", textAlign: "center", color: "#38bdf8", fontSize: "1.1rem", letterSpacing: "1px" }}>
            SENTINEL GRC ACCESS GATE
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
                First-time login detected. You must set a secure password to proceed into the application.
              </div>
              <label className="label">New Secure Password</label>
              <input 
                type="password"
                className="select-box" 
                style={{ marginBottom: "16px", width: "100%", background: "#020617", color: "#e2e8f0" }}
                value={newPass}
                onChange={(e) => setNewPass(e.target.value)}
                placeholder="Enter new password (min 8 chars, letters + numbers + special)..."
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

  // ==================== MAIN DASHBOARD RENDER ====================
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

          {userRole === "demo" && (
            <div
              style={{
                marginTop: "6px",
                padding: "8px 10px",
                borderRadius: "6px",
                fontSize: "0.7rem",
                background: demoSlotUsed ? "#3b0a0a" : "#082f49",
                border: demoSlotUsed ? "1px solid #dc2626" : "1px solid #0284c7",
                color: demoSlotUsed ? "#fca5a5" : "#7dd3fc",
              }}
            >
              {demoHintText}
            </div>
          )}

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

                {lastExport && (
                  <button
                    className="btn-export"
                    style={{ marginTop: "8px" }}
                    onClick={() => handleOpenPdf(lastExport.export_path)}
                  >
                    📄 Open Last Report
                  </button>
                )}

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
                  disabled={isFlushing}
                >
                  {isFlushing ? "🔄 Flushing Memory..." : "🧹 Flush Memory & Next Requirement →"}
                </button>

                <button className="btn-verify" onClick={handleVerify} disabled={!lastExport}>
                  Verify Active Cryptographic Seal
                </button>

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

<button
  className="btn-secondary"
  style={{ width: "100%", marginTop: "8px", background: "#1e293b", borderColor: "#334155", color: "#f8fafc" }}
  onClick={() => { setShowChangePasswordModal(true); setChangePassError(null); }}
>
  🔑 Change Password
</button>


<button
  className="btn-secondary"
  style={{ 
    width: "100%", 
    marginTop: "8px", 
    background: "#7f1d1d", 
    borderColor: "#991b1b", 
    color: "#fca5a5",
    fontWeight: "bold" 
  }}
  onClick={() => setShowShutdownConfirmModal(true)}
>
  🔒 Secure Shutdown
</button>

                {/* About Sentinel GRC Button */}
                <button 
                  onClick={() => setShowAboutModal(true)}
                  className="btn-secondary"
  style={{ width: "100%", marginTop: "8px", background: "#1e293b", borderColor: "#334155", color: "#f8fafc" }}
>
                  ℹ️ About Sentinel GRC
                </button>

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
                    <div style={{ fontSize: "0.68rem", color: "#94a3b8", marginBottom: "8px", lineHeight: "1.4" }}>
                      ⚠️ This permanently wipes the sealed audit trail and restarts the
                      inference engine with a fresh model context. This cannot be undone.
                    </div>
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
                    <div className="history-title">Req {rec.requirement_number} · Control {rec.control_id}</div>
                    <main className="history-date">{rec.timestamp}</main>
                    <div className="history-digest">Evidence SHA-256: {rec.evidence_hash ? rec.evidence_hash.substring(0, 16) : "—"}...</div>
                    <div style={{ fontSize: "0.65rem", color: "#94a3b8", marginTop: "4px", lineHeight: "1.4" }}>
                      {rec.summary ? rec.summary.substring(0, 140) : "No finding summary recorded."}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </section>
      </div>

      {/* About Modal Overlay */}
      {showAboutModal && (
  <div style={{
    position: "fixed",
    top: 0,
    left: 0,
    width: "100vw",
    height: "100vh",
    backgroundColor: "rgba(2, 6, 23, 0.8)",
    backdropFilter: "blur(4px)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 9999,
    padding: "16px"
  }}>
    <div style={{
      backgroundColor: "#0f172a",
      border: "1px solid #334155",
      borderRadius: "12px",
      maxWidth: "500px",
      width: "100%",
      padding: "24px",
      color: "#f8fafc",
      boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.7)",
      position: "relative"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", borderBottom: "1px solid #1e293b", paddingBottom: "12px", marginBottom: "16px" }}>
        <div>
          <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "#34d399", margin: 0 }}>Sentinel GRC — Secure Enclave Suite</h3>
          <p style={{ fontSize: "0.7rem", color: "#94a3b8", margin: "4px 0 0 0" }}>Enterprise Air-Gapped Compliance Engine v1.0.0</p>
        </div>
        <button 
          onClick={() => setShowAboutModal(false)}
          style={{ background: "transparent", border: "none", color: "#94a3b8", fontSize: "1.1rem", cursor: "pointer", padding: "0 4px" }}
        >
          ✕
        </button>
      </div>

      <div style={{ fontSize: "0.75rem", color: "#cbd5e1", lineHeight: "1.5", display: "flex", flexDirection: "column", gap: "12px" }}>
        <div style={{ background: "#020617", padding: "10px", borderRadius: "8px", border: "1px solid #1e293b" }}>
          <p style={{ margin: "0 0 4px 0" }}><strong>Principal Assessor:</strong> Ahmad Adnan</p>
          <p style={{ margin: 0 }}><strong>Contact:</strong> sentinel-grc@proton.me</p>
        </div>
        <p style={{ margin: 0 }}>
          Sentinel GRC is an elite, air-gapped compliance auditing and cryptographic attestation engine designed for high-security environments. It enables automated, local-first assessment without transmitting sensitive data across public networks.
        </p>
        <div style={{ borderTop: "1px solid #1e293b", paddingTop: "8px", display: "flex", flexDirection: "column", gap: "4px" }}>
          <p style={{ margin: 0 }}>🔒 <strong>Active Enclave:</strong> Apple Silicon Metal / Local GGML Qwen 2.5</p>
          <p style={{ margin: 0 }}>🛡️ <strong>Cryptography:</strong> Ed25519 Asymmetric Seals & SHA-256 Digests</p>
          <p style={{ margin: 0 }}>🗺️ <strong>Framework Roadmap:</strong> PCI DSS v4.0.1, ISO/IEC 27001, NCA, PDPL</p>
        </div>
      </div>

      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "20px", borderTop: "1px solid #1e293b", paddingTop: "12px" }}>
        <button 
          onClick={() => setShowAboutModal(false)}
          className="btn-primary"
          style={{ fontSize: "0.75rem", padding: "8px 16px", background: "#059669" }}
        >
          Close Enclave Info
        </button>
      </div>
    </div>
  </div>
)}

{showChangePasswordModal && (
  <div style={{
    position: "fixed", top: 0, left: 0, width: "100vw", height: "100vh",
    backgroundColor: "rgba(2, 6, 23, 0.8)", backdropFilter: "blur(4px)",
    display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999, padding: "16px"
  }}>
    <div style={{
      backgroundColor: "#0f172a", border: "1px solid #334155", borderRadius: "12px",
      maxWidth: "400px", width: "100%", padding: "24px", color: "#f8fafc", boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.7)"
    }}>
      <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "#38bdf8", marginBottom: "12px" }}>Change Account Password</h3>
      <p style={{ fontSize: "0.7rem", color: "#94a3b8", marginBottom: "16px", lineHeight: "1.4" }}>
        Password must be at least 8 characters and include letters, numbers, and a special character.
      </p>

      {changePassError && (
        <div style={{ marginBottom: "12px", padding: "8px", background: "#7f1d1d", color: "#fca5a5", fontSize: "0.7rem", borderRadius: "6px", border: "1px solid #991b1b" }}>
          {changePassError}
        </div>
      )}

      <form onSubmit={async (e) => {
        e.preventDefault();
        setChangePassError(null);
        try {
          const res = await invoke<string>("update_password", {
            username: loginUser,
            oldPassword: oldPasswordInput,
            newPassword: changeNewPassInput,
          });
          setStatusMessage(`✓ ${res}`);
          setShowChangePasswordModal(false);
          setOldPasswordInput("");
          setChangeNewPassInput("");
        } catch (err) {
          setChangePassError(String(err));
        }
      }}>
        <label className="label" style={{ fontSize: "0.7rem" }}>Current Password</label>
        <input
          type="password"
          className="select-box"
          style={{ marginBottom: "10px", width: "100%", background: "#020617", color: "#e2e8f0", fontSize: "0.75rem", padding: "6px" }}
          value={oldPasswordInput}
          onChange={(e) => setOldPasswordInput(e.target.value)}
          placeholder="Enter current password..."
        />

        <label className="label" style={{ fontSize: "0.7rem" }}>New Secure Password</label>
        <input
          type="password"
          className="select-box"
          style={{ marginBottom: "16px", width: "100%", background: "#020617", color: "#e2e8f0", fontSize: "0.75rem", padding: "6px" }}
          value={changeNewPassInput}
          onChange={(e) => setChangeNewPassInput(e.target.value)}
          placeholder="Min 8 chars, alphanumeric & special..."
        />

        <div style={{ display: "flex", gap: "6px" }}>
          <button type="submit" className="btn-primary" style={{ flex: 1, fontSize: "0.75rem", padding: "8px" }}>
            Update Password
          </button>
          <button
            type="button"
            className="btn-secondary"
            style={{ flex: 1, fontSize: "0.75rem", padding: "8px" }}
            onClick={() => setShowChangePasswordModal(false)}
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  </div>
)}


{showShutdownConfirmModal && (
  <div style={{
    position: "fixed", top: 0, left: 0, width: "100vw", height: "100vh",
    backgroundColor: "rgba(2, 6, 23, 0.85)", backdropFilter: "blur(4px)",
    display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999, padding: "16px"
  }}>
    <div style={{
      backgroundColor: "#0f172a", border: "1px solid #7f1d1d", borderRadius: "12px",
      maxWidth: "420px", width: "100%", padding: "24px", color: "#f8fafc", 
      boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.8)"
    }}>
      <h3 style={{ fontSize: "1.05rem", fontWeight: 700, color: "#fca5a5", marginBottom: "12px", display: "flex", alignItems: "center", gap: "8px" }}>
        ⚠️ Confirm Secure Shutdown
      </h3>
      <p style={{ fontSize: "0.75rem", color: "#94a3b8", marginBottom: "20px", lineHeight: "1.5" }}>
        This will forcefully terminate the local inference engine, release network ports, purge memory enclaves, and exit Sentinel GRC completely. 
      </p>

      <div style={{ display: "flex", gap: "8px" }}>
        <button
          type="button"
          className="btn-primary"
          style={{ flex: 1, fontSize: "0.75rem", padding: "10px", background: "#7f1d1d", borderColor: "#991b1b", color: "#fff" }}
          onClick={async () => {
            try {
              await invoke("secure_shutdown");
            } catch (err) {
              console.error("Secure shutdown failed:", err);
            }
          }}
        >
          Yes, Shut Down
        </button>
        <button
          type="button"
          className="btn-secondary"
          style={{ flex: 1, fontSize: "0.75rem", padding: "10px", background: "#1e293b", borderColor: "#334155", color: "#f8fafc" }}
          onClick={() => setShowShutdownConfirmModal(false)}
        >
          Cancel
        </button>
      </div>
    </div>
  </div>
)}



    </div>
  );
}