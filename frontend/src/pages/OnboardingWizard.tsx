import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

const STEPS = ['Welcome', 'Cloud Provider', 'Credentials', 'Test', 'Configure', 'Launch'];

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
  { key: 'aws', label: 'Amazon Web Services', desc: 'IAM, Organizations, S3, KMS (coming soon)' },
  { key: 'gcp', label: 'Google Cloud', desc: 'Cloud IAM, Projects, GCS, KMS (coming soon)' },
];

export default function OnboardingWizard() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [orgName, setOrgName] = useState('');
  const [selectedCloud, setSelectedCloud] = useState('azure');
  const [azureTenantId, setAzureTenantId] = useState('');
  const [azureClientId, setAzureClientId] = useState('');
  const [azureClientSecret, setAzureClientSecret] = useState('');
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [testing, setTesting] = useState(false);
  const [discoveryInterval, setDiscoveryInterval] = useState('12');
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [emailTo, setEmailTo] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [checklist, setChecklist] = useState<ChecklistItem[]>([]);
  const [showChecklist, setShowChecklist] = useState(false);

  // Load checklist on mount
  useEffect(() => {
    fetch('/api/onboarding/status')
      .then(r => r.json())
      .then(data => {
        if (data.checklist) setChecklist(data.checklist);
        if (data.onboarding_completed) setShowChecklist(true);
      })
      .catch(() => {});
  }, []);

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
    if (step === 4) return !emailEnabled || (emailTo.includes('@'));
    return true;
  }, [step, orgName, selectedCloud, azureTenantId, azureClientId, azureClientSecret, testResult, emailEnabled, emailTo]);

  async function handleTestConnection() {
    setTesting(true);
    setTestResult(null);
    setError(null);
    try {
      const res = await fetch('/api/onboarding/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          azure_tenant_id: azureTenantId.trim(),
          azure_client_id: azureClientId.trim(),
          azure_client_secret: azureClientSecret.trim(),
        }),
      });
      const data = await res.json();
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
    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org_name: orgName.trim(),
          azure_tenant_id: azureTenantId.trim(),
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
      // Trigger first snapshot
      await fetch('/api/runs/trigger', { method: 'POST' });
      navigate('/');
    } catch (e: any) {
      setError(e?.message || 'Setup failed');
    } finally {
      setSaving(false);
    }
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
              onClick={() => navigate('/')}
              className="flex-1 py-2.5 rounded-lg text-sm font-semibold bg-blue-600 text-white hover:bg-blue-700 transition"
            >
              Go to Dashboard
            </button>
            <button
              onClick={() => navigate('/settings')}
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
                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-600 rounded-lg text-sm text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
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
              {CLOUD_OPTIONS.map(cloud => {
                const disabled = cloud.key !== 'azure';
                return (
                  <button
                    key={cloud.key}
                    onClick={() => !disabled && setSelectedCloud(cloud.key)}
                    disabled={disabled}
                    className={`w-full text-left p-4 rounded-xl border-2 transition ${
                      selectedCloud === cloud.key
                        ? 'border-blue-500 bg-blue-900/20'
                        : disabled
                          ? 'border-gray-700 bg-gray-800/30 opacity-50 cursor-not-allowed'
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
                      {disabled && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-gray-600 text-gray-300">Coming Soon</span>
                      )}
                    </div>
                  </button>
                );
              })}
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
                  className="mt-2 text-xs text-red-400 underline hover:text-red-300"
                >
                  Go back and fix credentials
                </button>
              </div>
            )}
          </div>
        )}

        {/* Step 4: Configure */}
        {step === 4 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-white">Configure Discovery</h2>
              <p className="text-sm text-gray-400 mt-2">
                Set how often AuditGraph scans your environment and whether to send email alerts.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Discovery Frequency</label>
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

        {/* Step 5: Launch */}
        {step === 5 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-white">Review &amp; Launch</h2>
              <p className="text-sm text-gray-400 mt-2">
                Review your configuration and capture your first snapshot.
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
                <span className="text-gray-400">Subscriptions Found</span>
                <span className="font-medium text-green-400">{testResult?.subscriptions?.length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Discovery Frequency</span>
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
                  Saving &amp; Starting Discovery...
                </>
              ) : (
                'Complete Setup & Start Discovery'
              )}
            </button>
          </div>
        )}

        {/* Navigation */}
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
      </div>

      {/* Skip link */}
      <button
        onClick={() => navigate('/')}
        className="mt-4 text-xs text-gray-500 hover:text-gray-300 transition"
      >
        Skip setup for now
      </button>
    </div>
  );
}
