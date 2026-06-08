import React, { useState, useEffect, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { DiscoveryProgressModal } from '../components/settings/DiscoveryProgressModal';

// AG-Onboarding-FirstFinding (2026-06-01): Step 6 "Scanning" is the
// magical-moment step. Wizard kicks the first scan, mounts the live
// findings modal inline, and on completion deep-links to the single
// highest-risk identity from the just-completed run. Turns the wizard
// from "settings form → orphan landing" into Wiz-style "connect →
// first finding in <2min".
// AG-PILOT-WIZARD-SUBS (2026-06-08): added explicit Subscriptions step
// between Test and Configure. Customer picks which discovered subs to
// monitor (billed per-sub) instead of platform auto-activating everything.
const STEPS = ['Welcome', 'Cloud Provider', 'Credentials', 'Test', 'Subscriptions', 'Configure', 'Launch', 'Scanning'];

interface TestResult {
  status: string;
  subscriptions?: { id: string; name: string }[];
  error?: string;
  message?: string;
}

interface ChecklistItem {
  key: string;
  label: string;
  done: boolean;
}

const CLOUD_OPTIONS = [
  { key: 'azure', label: 'Microsoft Azure', desc: 'Entra ID, Azure RBAC, Key Vaults, Storage' },
];

/** SessionStorage key for persisting wizard step across refreshes. */
function stepKey(orgId: number | string): string {
  return `ag_wizard_step_${orgId}`;
}
/** SessionStorage key recording explicit wizard completion. */
function completeKey(orgId: number | string): string {
  return `ag_wizard_complete_${orgId}`;
}

export default function OnboardingWizard() {
  const { user } = useAuth();
  const location = useLocation();
  const orgId = user?.organization_id ?? 0;

  // Determine initial step: fromSignup → skip step 0 (org name already entered)
  // Otherwise restore from sessionStorage, defaulting to step 0.
  const fromSignup = !!(location.state as any)?.fromSignup;
  const initialStep = (() => {
    if (fromSignup) return 1; // Cloud Provider
    const saved = sessionStorage.getItem(stepKey(orgId));
    return saved ? Math.min(parseInt(saved, 10) || 0, STEPS.length - 1) : 0;
  })();

  const [step, setStep] = useState(initialStep);
  const [orgName, setOrgName] = useState('');
  const [selectedCloud, setSelectedCloud] = useState('azure');
  const [azureTenantId, setAzureTenantId] = useState('');
  const [azureClientId, setAzureClientId] = useState('');
  const [azureClientSecret, setAzureClientSecret] = useState('');
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [testing, setTesting] = useState(false);
  // AG-PILOT-WIZARD-SUBS (2026-06-08): track which subs the customer
  // explicitly chose to monitor. Wizard's new Subscriptions step.
  const [activatingSubIds, setActivatingSubIds] = useState<string[]>([]);
  const [activatingSubs, setActivatingSubs] = useState(false);
  const [discoveryInterval, setDiscoveryInterval] = useState('12');
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [emailTo, setEmailTo] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [checklist, setChecklist] = useState<ChecklistItem[]>([]);
  const [showChecklist, setShowChecklist] = useState(false);
  const [orgNamePreFilled, setOrgNamePreFilled] = useState(false);
  // First-finding launch state — after settings save, we trigger the
  // initial scan and mount the live-findings modal inline on step 6.
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanConnectionId, setScanConnectionId] = useState<number | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [navigatingToFinding, setNavigatingToFinding] = useState(false);

  // Persist step to sessionStorage whenever it changes
  useEffect(() => {
    if (orgId) sessionStorage.setItem(stepKey(orgId), step.toString());
  }, [step, orgId]);

  // Load checklist + org name on mount
  useEffect(() => {
    fetch('/api/onboarding/status')
      .then(r => r.json())
      .then(data => {
        if (data.checklist) setChecklist(data.checklist);

        // FIX 3+4: Only show checklist when wizard was explicitly completed AND
        // backend confirms cloud provider is actually configured.
        // The backend now returns onboarding_completed=false if cloud_connections=0,
        // but we also check client-side sessionStorage as a secondary gate.
        const wizardExplicitlyDone =
          sessionStorage.getItem(completeKey(orgId)) === 'true';
        const hasCompletedRun = data.snapshot_completed === true;
        if (data.onboarding_completed && (data.azure_configured || wizardExplicitlyDone || hasCompletedRun)) {
          setShowChecklist(true);
        }

        if (data.org_name) { setOrgName(data.org_name); setOrgNamePreFilled(true); }
      })
      .catch(() => {});
  }, [orgId]);

  const canNext = useCallback((): boolean => {
    if (step === 0) return orgName.trim().length > 0;
    if (step === 1) return !!selectedCloud;
    if (step === 2) {
      if (selectedCloud === 'azure') {
        return !!(azureTenantId.trim() && azureClientId.trim() && azureClientSecret.trim());
      }
      return false; // AWS/GCP not yet supported
    }
    if (step === 3) return testResult?.status === 'success';
    // AG-PILOT-WIZARD-SUBS: at least 1 sub must be picked before proceeding
    if (step === 4) return activatingSubIds.length > 0;
    if (step === 5) return !emailEnabled || /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(emailTo.trim());
    return true;
  }, [step, orgName, selectedCloud, azureTenantId, azureClientId, azureClientSecret, testResult, activatingSubIds, emailEnabled, emailTo]);

  // Auto-trigger test when arriving at Step 3 (Test Connection) with credentials filled
  const autoTestTriggered = React.useRef(false);
  useEffect(() => {
    if (step === 3 && azureTenantId.trim() && azureClientId.trim() && azureClientSecret.trim()
        && !testing && !testResult && !autoTestTriggered.current) {
      autoTestTriggered.current = true;
      handleTestConnection();
    }
    if (step !== 3) autoTestTriggered.current = false;
  }, [step]);

  async function handleTestConnection() {
    setTesting(true);
    setTestResult(null);
    setError(null);
    try {
      const res = await fetch('/api/onboarding/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          azure_directory_id: azureTenantId.trim(),
          azure_client_id: azureClientId.trim(),
          azure_client_secret: azureClientSecret.trim(),
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setTestResult({ status: 'error', error: data.error || data.message || 'Connection failed' });
      } else {
        setTestResult(data);
      }
    } catch (e: any) {
      setTestResult({ status: 'error', error: e?.message || 'Connection test failed' });
    } finally {
      setTesting(false);
    }
  }

  async function handleComplete() {
    setSaving(true);
    setError(null);
    setScanError(null);
    try {
      // 1. Save settings (creates / updates the cloud connection)
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org_name: orgName.trim(),
          azure_directory_id: azureTenantId.trim(),
          azure_client_id: azureClientId.trim(),
          azure_client_secret: azureClientSecret.trim(),
          discovery_interval_hours: discoveryInterval,
          email_enabled: String(emailEnabled),
          email_to: emailEnabled ? emailTo.trim() : '',
          onboarding_completed: 'true',
        }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to save settings');
      }
      if (orgId) {
        sessionStorage.setItem(completeKey(orgId), 'true');
        sessionStorage.removeItem(stepKey(orgId));
      }

      // AG-PILOT-WIZARD-SUBS (2026-06-08): activate the customer's
      // chosen subscriptions BEFORE triggering discovery. Without this,
      // first scan would find 0 identities because no subs are 'active'.
      if (activatingSubIds.length > 0) {
        try {
          await fetch('/api/subscriptions/activate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ account_ids: activatingSubIds }),
          });
        } catch (subErr) {
          // Non-fatal — customer can activate manually from Subs page
          console.warn('Failed to activate selected subscriptions', subErr);
        }
      }

      // 2. Trigger the initial scan immediately so the wizard hands off
      //    to a live scan progress experience instead of an empty
      //    /subscriptions page.
      let triggeredConnectionId: number | null = null;
      try {
        const triggerRes = await fetch('/api/runs/trigger', { method: 'POST' });
        if (triggerRes.ok) {
          const triggerData = await triggerRes.json().catch(() => ({}));
          triggeredConnectionId =
            triggerData.cloud_connection_id ?? triggerData.connection_id ?? null;
        } else {
          // Scan-trigger failure is not fatal — fall back to the legacy
          // /subscriptions destination so the user isn't stuck.
          setScanError('Could not start the first scan automatically. You can run it manually from Settings → Connections.');
        }
      } catch (triggerErr) {
        setScanError('Could not start the first scan automatically.');
      }

      // 3. Advance to the Scanning step + mount the live findings modal.
      //    If trigger failed, the modal will still open and poll —
      //    /api/discovery/status will return any in-flight job (or the
      //    most-recent completed job) and the user sees what's there.
      setScanConnectionId(triggeredConnectionId);
      setShowScanModal(true);
      setStep(7);
    } catch (e: any) {
      setError(e?.message || 'Setup failed');
    } finally {
      setSaving(false);
    }
  }

  async function handleScanComplete() {
    // Modal called onComplete — fetch the top critical/high identity
    // from the just-finished run and deep-link there. If nothing
    // critical was found, fall through to the dashboard.
    setNavigatingToFinding(true);
    try {
      const r = await fetch('/api/onboarding/first-finding');
      const d = await r.json().catch(() => ({}));
      if (d && d.identity_id) {
        window.location.href = `/identities/${encodeURIComponent(d.identity_id)}`;
        return;
      }
    } catch (_e) {
      // fall through
    }
    // No critical/high → land on the dashboard
    window.location.href = '/';
  }

  function handleScanModalClose() {
    // User closed the modal without waiting for scan completion.
    // Don't auto-navigate to a finding — they're choosing to exit.
    setShowScanModal(false);
    window.location.href = '/';
  }

  // If onboarding is completed, show the checklist dashboard
  if (showChecklist && checklist.length > 0) {
    const doneCount = checklist.filter(c => c.done).length;
    const pct = Math.round((doneCount / checklist.length) * 100);
    return (
      <div className="min-h-screen bg-ob-surface flex flex-col items-center justify-center px-4 py-12">
        <div className="w-full max-w-lg bg-ob-raised border border-gray-700 rounded-2xl p-8">
          <h2 className="text-xl font-bold text-white mb-1">Setup Progress</h2>
          <p className="text-sm text-gray-400 mb-6">{doneCount} of {checklist.length} steps completed</p>

          {/* Progress bar */}
          <div className="w-full h-2 bg-gray-700 rounded-full mb-6 overflow-hidden">
            <div className="h-full bg-blue-600 rounded-full transition-all" style={{ width: `${pct}%` }} />
          </div>

          <div className="space-y-3">
            {checklist.map(item => (
              <div key={item.key} className={`flex items-center gap-3 p-3 rounded-lg border ${
                item.done ? 'border-green-800 bg-green-900/20' : 'border-gray-700 bg-gray-800/30'
              }`}>
                <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                  item.done ? 'bg-green-600 text-white' : 'bg-gray-700 text-gray-400'
                }`}>
                  {item.done ? '\u2713' : '\u2022'}
                </div>
                <span className={`text-sm ${item.done ? 'text-green-300' : 'text-gray-300'}`}>{item.label}</span>
              </div>
            ))}
          </div>

          <div className="mt-6 flex gap-3">
            <button
              onClick={() => { window.location.href = '/'; }}
              className="flex-1 py-2.5 rounded-lg text-sm font-semibold bg-blue-600 text-white hover:bg-blue-700 transition"
            >
              Go to Dashboard
            </button>
            <button
              onClick={() => { window.location.href = '/settings'; }}
              className="px-4 py-2.5 rounded-lg text-sm font-medium text-gray-300 border border-gray-600 hover:bg-gray-800 transition"
            >
              Settings
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-ob-surface flex flex-col items-center justify-center px-4 py-12">
      {/* Logo + Title */}
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-white">AuditGraph Setup</h1>
        <p className="text-sm text-gray-400 mt-1">Configure your identity security audit in a few steps</p>
      </div>

      {/* Progress Bar */}
      <div className="flex items-center gap-2 mb-8">
        {STEPS.map((label, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition ${
              i < step ? 'bg-green-500 text-white' :
              i === step ? 'bg-blue-600 text-white' :
              'bg-gray-700 text-gray-400'
            }`}>
              {i < step ? '\u2713' : i + 1}
            </div>
            <span className={`text-xs font-medium hidden sm:inline ${
              i === step ? 'text-blue-400' : 'text-gray-500'
            }`}>{label}</span>
            {i < STEPS.length - 1 && (
              <div className={`w-8 h-0.5 ${i < step ? 'bg-green-500' : 'bg-gray-700'}`} />
            )}
          </div>
        ))}
      </div>

      {/* Card */}
      <div className="w-full max-w-xl bg-ob-raised border border-gray-700 rounded-2xl shadow-lg p-8">
        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-900/30 border border-red-700 text-red-300 text-sm">
            {error}
          </div>
        )}

        {/* Step 0: Welcome */}
        {step === 0 && (
          <div className="space-y-4">
            <div>
              <h2 className="text-xl font-bold text-white">Welcome to AuditGraph</h2>
              <p className="text-sm text-gray-400 mt-2">
                Let's get your identity security audit configured. We'll walk you through
                connecting to your cloud environment, testing the connection, and capturing your first snapshot.
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Organization Name</label>
              <input
                type="text"
                value={orgName}
                onChange={e => setOrgName(e.target.value)}
                placeholder="e.g., Contoso Ltd"
                disabled={orgNamePreFilled}
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-600 rounded-lg text-sm text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none disabled:opacity-60 disabled:cursor-not-allowed"
              />
            </div>
          </div>
        )}

        {/* Step 1: Cloud Provider */}
        {step === 1 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-white">Select Cloud Provider</h2>
              <p className="text-sm text-gray-400 mt-2">
                Choose the cloud environment to connect first. You can add more providers later.
              </p>
            </div>
            <div className="space-y-3">
              {CLOUD_OPTIONS.map(cloud => (
                  <button
                    key={cloud.key}
                    onClick={() => setSelectedCloud(cloud.key)}
                    className={`w-full text-left p-4 rounded-xl border-2 transition ${
                      selectedCloud === cloud.key
                        ? 'border-blue-500 bg-blue-900/20'
                        : 'border-gray-700 hover:border-gray-500'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-sm font-semibold text-white">{cloud.label}</div>
                        <div className="text-xs text-gray-400 mt-0.5">{cloud.desc}</div>
                      </div>
                      {selectedCloud === cloud.key && (
                        <div className="w-6 h-6 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs">{'\u2713'}</div>
                      )}
                    </div>
                  </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 2: Credentials */}
        {step === 2 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-white">Azure AD Credentials</h2>
              <p className="text-sm text-gray-400 mt-2">
                Create an App Registration in Azure AD with{' '}
                <code className="text-xs bg-gray-700 px-1 rounded text-blue-300">Directory.Read.All</code> and{' '}
                <code className="text-xs bg-gray-700 px-1 rounded text-blue-300">Reader</code> RBAC permissions.
              </p>
            </div>
            <div className="bg-blue-900/20 border border-blue-700 rounded-lg px-4 py-3 text-xs text-blue-300">
              <strong>Required permissions:</strong> Directory.Read.All (Application), Reader RBAC on target subscriptions,
              RoleManagement.Read.Directory (for PIM), Policy.Read.All (for Conditional Access)
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Entra Directory ID</label>
              <input
                type="text"
                value={azureTenantId}
                onChange={e => setAzureTenantId(e.target.value)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-600 rounded-lg text-sm font-mono text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Client ID (Application ID)</label>
              <input
                type="text"
                value={azureClientId}
                onChange={e => setAzureClientId(e.target.value)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-600 rounded-lg text-sm font-mono text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Client Secret</label>
              <input
                type="password"
                value={azureClientSecret}
                onChange={e => setAzureClientSecret(e.target.value)}
                placeholder="Enter client secret value"
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-600 rounded-lg text-sm text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
              />
            </div>
          </div>
        )}

        {/* Step 3: Test Connection */}
        {step === 3 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-white">Test Connection</h2>
              <p className="text-sm text-gray-400 mt-2">
                Verify that AuditGraph can connect to your Entra directory and discover subscriptions.
              </p>
            </div>

            <button
              onClick={handleTestConnection}
              disabled={testing}
              className="w-full py-3 rounded-lg text-sm font-semibold bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition flex items-center justify-center gap-2"
            >
              {testing ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Testing connection...
                </>
              ) : (
                'Test Connection'
              )}
            </button>

            {testResult && testResult.status === 'success' && (
              <div className="p-4 rounded-lg bg-green-900/30 border border-green-700">
                <div className="flex items-center gap-2 text-green-400 font-semibold text-sm">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  Connection Successful
                </div>
                <p className="text-xs text-green-300 mt-1">{testResult.message}</p>
                {!!testResult.subscriptions && testResult.subscriptions.length > 0 && (
                  <div className="mt-3 space-y-1">
                    <div className="text-xs font-medium text-green-400">Accessible Subscriptions:</div>
                    {testResult.subscriptions.map(sub => (
                      <div key={sub.id} className="text-xs text-green-300 pl-3">
                        {sub.name} <span className="text-green-500 font-mono">({sub.id})</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {testResult && testResult.status === 'error' && (
              <div className="p-4 rounded-lg bg-red-900/30 border border-red-700">
                <div className="flex items-center gap-2 text-red-400 font-semibold text-sm">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                  Connection Failed
                </div>
                <p className="text-xs text-red-300 mt-1">{testResult.error}</p>
                <button
                  onClick={() => { setStep(2); setTestResult(null); }}
                  className="mt-2 text-xs text-red-400 hover:text-red-300 hover:opacity-80 cursor-pointer"
                >
                  Go back and fix credentials
                </button>
              </div>
            )}
          </div>
        )}

        {/* AG-PILOT-WIZARD-SUBS (2026-06-08): Step 4 — Subscriptions
            Customer picks which discovered subs to monitor. Each
            activated sub is a separately billed monitoring unit. */}
        {step === 4 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-white">Activate Subscriptions</h2>
              <p className="text-sm text-gray-400 mt-2">
                Choose which subscriptions to monitor. Each activated subscription is billed separately
                — you can add or remove subs from the Subscriptions page anytime.
              </p>
            </div>

            <div className="bg-gray-800 rounded-lg p-4 max-h-96 overflow-y-auto space-y-1">
              {(testResult?.subscriptions || []).map(s => (
                <label key={s.id} className="flex items-center gap-3 p-2.5 rounded hover:bg-gray-700 cursor-pointer">
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-gray-600 text-blue-600"
                    checked={activatingSubIds.includes(s.id)}
                    onChange={e => {
                      if (e.target.checked) {
                        setActivatingSubIds(prev => [...prev, s.id]);
                      } else {
                        setActivatingSubIds(prev => prev.filter(x => x !== s.id));
                      }
                    }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-white truncate">{s.name}</div>
                    <div className="text-[11px] font-mono text-gray-500 truncate">{s.id}</div>
                  </div>
                  <div className="text-xs text-gray-400">$69/mo</div>
                </label>
              ))}
              {(!testResult?.subscriptions || testResult.subscriptions.length === 0) && (
                <p className="text-sm text-amber-400 p-2">
                  No subscriptions discovered. Go back and verify your credentials grant Reader RBAC on at least one subscription.
                </p>
              )}
            </div>

            <div className="flex items-center justify-between text-sm">
              <button
                onClick={() => setActivatingSubIds((testResult?.subscriptions || []).map(s => s.id))}
                className="text-blue-400 hover:text-blue-300">
                Select all
              </button>
              <span className="text-gray-400">
                {activatingSubIds.length} of {testResult?.subscriptions?.length || 0} selected
                {activatingSubIds.length > 0 && (
                  <> · <span className="text-white font-medium">${activatingSubIds.length * 69}/mo</span></>
                )}
              </span>
            </div>

            {error && (
              <p className="text-sm text-red-400">{error}</p>
            )}
          </div>
        )}

        {/* Step 5: Configure (was step 4 before adding Subscriptions step) */}
        {step === 5 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-white">Configure Snapshots</h2>
              <p className="text-sm text-gray-400 mt-2">
                Set how often AuditGraph captures snapshots and whether to send email alerts.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Snapshot Frequency</label>
              <div className="flex gap-3">
                {['6', '12', '24'].map(val => (
                  <button
                    key={val}
                    onClick={() => setDiscoveryInterval(val)}
                    className={`flex-1 py-2.5 rounded-lg text-sm font-medium border transition ${
                      discoveryInterval === val
                        ? 'bg-blue-600 text-white border-blue-600'
                        : 'bg-gray-800 text-gray-300 border-gray-600 hover:border-gray-500'
                    }`}
                  >
                    Every {val}h
                  </button>
                ))}
              </div>
            </div>

            <div className="pt-2">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-300">Email Notifications</label>
                <button
                  onClick={() => setEmailEnabled(!emailEnabled)}
                  className={`relative w-11 h-6 rounded-full transition ${emailEnabled ? 'bg-blue-600' : 'bg-gray-600'}`}
                >
                  <div className="absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform left-0.5"
                    style={{ transform: emailEnabled ? 'translateX(20px)' : 'translateX(0)' }}
                  />
                </button>
              </div>
              {emailEnabled && (
                <div className="mt-3">
                  <label className="block text-xs text-gray-400 mb-1">Notification Email</label>
                  <input
                    type="email"
                    value={emailTo}
                    onChange={e => setEmailTo(e.target.value)}
                    placeholder="security@yourcompany.com"
                    className="w-full px-4 py-2.5 bg-gray-800 border border-gray-600 rounded-lg text-sm text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  />
                </div>
              )}
            </div>
          </div>
        )}

        {/* Step 6: Launch (was step 5 before adding Subscriptions step) */}
        {step === 6 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-white">Review &amp; Launch</h2>
              <p className="text-sm text-gray-400 mt-2">
                Review your configuration before completing setup.
              </p>
            </div>

            <div className="bg-gray-800 rounded-lg p-4 space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Organization</span>
                <span className="font-medium text-white">{orgName}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Cloud Provider</span>
                <span className="font-medium text-blue-400 capitalize">{selectedCloud}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Entra Directory</span>
                <span className="font-mono text-xs text-gray-300">{azureTenantId.slice(0, 8)}...</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Subscriptions to Monitor</span>
                <span className="font-medium text-green-400">
                  {activatingSubIds.length} of {testResult?.subscriptions?.length || 0}
                  <span className="text-gray-500 ml-2">(${activatingSubIds.length * 69}/mo)</span>
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Snapshot Frequency</span>
                <span className="font-medium text-white">Every {discoveryInterval} hours</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Email Alerts</span>
                <span className={`font-medium ${emailEnabled ? 'text-green-400' : 'text-gray-500'}`}>
                  {emailEnabled ? emailTo : 'Disabled'}
                </span>
              </div>
            </div>

            <button
              onClick={handleComplete}
              disabled={saving}
              className="w-full py-3 rounded-lg text-sm font-semibold bg-green-600 text-white hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition flex items-center justify-center gap-2"
            >
              {saving ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Completing setup...
                </>
              ) : (
                'Complete Setup'
              )}
            </button>
          </div>
        )}

        {/* Step 7: Scanning — first-finding handoff. Renders behind the
            modal; serves as the page content if the user closes the modal
            without navigating. (was step 6 before adding Subscriptions) */}
        {step === 7 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-white">First scan running…</h2>
              <p className="text-sm text-gray-400 mt-2">
                We're discovering your identities and analyzing risk. The
                modal will close automatically when we find your first
                critical finding.
              </p>
            </div>
            {scanError && (
              <div className="bg-amber-900/20 border border-amber-800 text-amber-300 text-sm rounded-lg p-3">
                {scanError}
              </div>
            )}
            {navigatingToFinding && (
              <div className="flex items-center gap-2 text-sm text-blue-300">
                <div className="w-3 h-3 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
                Loading your first finding…
              </div>
            )}
            <button
              onClick={() => setShowScanModal(true)}
              className="text-xs font-medium text-blue-400 hover:text-blue-300 transition underline"
            >
              Re-open scan progress
            </button>
          </div>
        )}

        {/* Navigation */}
        {step < 6 && (
          <div className="flex items-center justify-between mt-8 pt-4 border-t border-gray-700">
            <button
              onClick={() => { setStep(step - 1); setError(null); }}
              disabled={step === 0}
              className="px-4 py-2 rounded-lg text-sm font-medium text-gray-400 hover:bg-gray-800 disabled:opacity-30 disabled:cursor-not-allowed transition"
            >
              Back
            </button>

            {step < 5 && (
              <button
                onClick={() => { setStep(step + 1); setError(null); }}
                disabled={!canNext()}
                className="px-6 py-2 rounded-lg text-sm font-semibold bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition"
              >
                Next
              </button>
            )}
          </div>
        )}
      </div>

      {/* Skip link */}
      <button
        onClick={() => { window.location.href = '/'; }}
        className="mt-4 text-xs text-gray-500 hover:text-gray-300 transition"
      >
        Skip setup for now
      </button>

      {/* AG-Onboarding-FirstFinding: live findings modal mounts inline
          when the wizard kicks the first scan. onComplete handoff
          deep-links to the top critical/high identity. */}
      {showScanModal && (
        <DiscoveryProgressModal
          connectionId={scanConnectionId}
          onClose={handleScanModalClose}
          onComplete={handleScanComplete}
        />
      )}
    </div>
  );
}
