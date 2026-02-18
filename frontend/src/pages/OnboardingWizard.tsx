import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const STEPS = ['Welcome', 'Credentials', 'Test', 'Configure', 'Launch'];

interface TestResult {
  status: string;
  subscriptions?: { id: string; name: string }[];
  error?: string;
  message?: string;
}

export default function OnboardingWizard() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [orgName, setOrgName] = useState('');
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

  const canNext = (): boolean => {
    if (step === 0) return orgName.trim().length > 0;
    if (step === 1) return !!(azureTenantId.trim() && azureClientId.trim() && azureClientSecret.trim());
    if (step === 2) return testResult?.status === 'success';
    if (step === 3) return !emailEnabled || (emailTo.includes('@'));
    return true;
  };

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
      // Trigger first discovery
      await fetch('/api/runs/trigger', { method: 'POST' });
      navigate('/');
    } catch (e: any) {
      setError(e?.message || 'Setup failed');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center px-4 py-12">
      {/* Logo + Title */}
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900">AuditGraph Setup</h1>
        <p className="text-sm text-gray-500 mt-1">Configure your identity security audit in a few steps</p>
      </div>

      {/* Progress Bar */}
      <div className="flex items-center gap-2 mb-8">
        {STEPS.map((label, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition ${
              i < step ? 'bg-green-500 text-white' :
              i === step ? 'bg-blue-600 text-white' :
              'bg-gray-200 text-gray-500'
            }`}>
              {i < step ? '\u2713' : i + 1}
            </div>
            <span className={`text-xs font-medium hidden sm:inline ${
              i === step ? 'text-blue-600' : 'text-gray-400'
            }`}>{label}</span>
            {i < STEPS.length - 1 && (
              <div className={`w-8 h-0.5 ${i < step ? 'bg-green-500' : 'bg-gray-200'}`} />
            )}
          </div>
        ))}
      </div>

      {/* Card */}
      <div className="w-full max-w-xl bg-white rounded-2xl shadow-lg border p-8">
        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
            {error}
          </div>
        )}

        {/* Step 0: Welcome */}
        {step === 0 && (
          <div className="space-y-6">
            <div>
              <h2 className="text-xl font-bold text-gray-900">Welcome to AuditGraph</h2>
              <p className="text-sm text-gray-600 mt-2">
                Let's get your identity security audit configured. We'll walk you through
                connecting to Azure AD, testing the connection, and running your first discovery scan.
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Organization Name</label>
              <input
                type="text"
                value={orgName}
                onChange={e => setOrgName(e.target.value)}
                placeholder="e.g., Contoso Ltd"
                className="w-full px-4 py-2.5 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
              />
            </div>
          </div>
        )}

        {/* Step 1: Credentials */}
        {step === 1 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-gray-900">Azure AD Credentials</h2>
              <p className="text-sm text-gray-600 mt-2">
                Create an App Registration in Azure AD with <code className="text-xs bg-gray-100 px-1 rounded">Directory.Read.All</code> and <code className="text-xs bg-gray-100 px-1 rounded">Reader</code> RBAC
                permissions. Enter the service principal credentials below.
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Entra Directory ID</label>
              <input
                type="text"
                value={azureTenantId}
                onChange={e => setAzureTenantId(e.target.value)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                className="w-full px-4 py-2.5 border rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Client ID (Application ID)</label>
              <input
                type="text"
                value={azureClientId}
                onChange={e => setAzureClientId(e.target.value)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                className="w-full px-4 py-2.5 border rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Client Secret</label>
              <input
                type="password"
                value={azureClientSecret}
                onChange={e => setAzureClientSecret(e.target.value)}
                placeholder="Enter client secret value"
                className="w-full px-4 py-2.5 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
              />
            </div>
          </div>
        )}

        {/* Step 2: Test Connection */}
        {step === 2 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-gray-900">Test Connection</h2>
              <p className="text-sm text-gray-600 mt-2">
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
              <div className="p-4 rounded-lg bg-green-50 border border-green-200">
                <div className="flex items-center gap-2 text-green-700 font-semibold text-sm">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  Connection Successful
                </div>
                <p className="text-xs text-green-600 mt-1">{testResult.message}</p>
                {!!testResult.subscriptions && testResult.subscriptions.length > 0 && (
                  <div className="mt-3 space-y-1">
                    <div className="text-xs font-medium text-green-700">Accessible Subscriptions:</div>
                    {testResult.subscriptions.map(sub => (
                      <div key={sub.id} className="text-xs text-green-600 pl-3">
                        {sub.name} <span className="text-green-400 font-mono">({sub.id})</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {testResult && testResult.status === 'error' && (
              <div className="p-4 rounded-lg bg-red-50 border border-red-200">
                <div className="flex items-center gap-2 text-red-700 font-semibold text-sm">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                  Connection Failed
                </div>
                <p className="text-xs text-red-600 mt-1">{testResult.error}</p>
                <button
                  onClick={() => { setStep(1); setTestResult(null); }}
                  className="mt-2 text-xs text-red-600 underline hover:text-red-800"
                >
                  Go back and fix credentials
                </button>
              </div>
            )}
          </div>
        )}

        {/* Step 3: Configure */}
        {step === 3 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-gray-900">Configure Discovery</h2>
              <p className="text-sm text-gray-600 mt-2">
                Set how often AuditGraph scans your Azure environment and whether to send email alerts.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Discovery Frequency</label>
              <div className="flex gap-3">
                {['6', '12', '24'].map(val => (
                  <button
                    key={val}
                    onClick={() => setDiscoveryInterval(val)}
                    className={`flex-1 py-2.5 rounded-lg text-sm font-medium border transition ${
                      discoveryInterval === val
                        ? 'bg-blue-600 text-white border-blue-600'
                        : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    Every {val}h
                  </button>
                ))}
              </div>
            </div>

            <div className="pt-2">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-700">Email Notifications</label>
                <button
                  onClick={() => setEmailEnabled(!emailEnabled)}
                  className={`relative w-11 h-6 rounded-full transition ${emailEnabled ? 'bg-blue-600' : 'bg-gray-300'}`}
                >
                  <div className={`absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform ${emailEnabled ? 'translate-x-5.5 left-0.5' : 'left-0.5'}`}
                    style={{ transform: emailEnabled ? 'translateX(20px)' : 'translateX(0)' }}
                  />
                </button>
              </div>
              {emailEnabled && (
                <div className="mt-3">
                  <label className="block text-xs text-gray-500 mb-1">Notification Email</label>
                  <input
                    type="email"
                    value={emailTo}
                    onChange={e => setEmailTo(e.target.value)}
                    placeholder="security@yourcompany.com"
                    className="w-full px-4 py-2.5 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  />
                </div>
              )}
            </div>
          </div>
        )}

        {/* Step 4: Launch */}
        {step === 4 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-xl font-bold text-gray-900">Review &amp; Launch</h2>
              <p className="text-sm text-gray-600 mt-2">
                Review your configuration and start the first discovery scan.
              </p>
            </div>

            <div className="bg-gray-50 rounded-lg p-4 space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">Organization</span>
                <span className="font-medium text-gray-900">{orgName}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Entra Directory</span>
                <span className="font-mono text-xs text-gray-700">{azureTenantId.slice(0, 8)}...</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Subscriptions Found</span>
                <span className="font-medium text-green-700">{testResult?.subscriptions?.length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Discovery Frequency</span>
                <span className="font-medium text-gray-900">Every {discoveryInterval} hours</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Email Alerts</span>
                <span className={`font-medium ${emailEnabled ? 'text-green-700' : 'text-gray-400'}`}>
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
        <div className="flex items-center justify-between mt-8 pt-4 border-t">
          <button
            onClick={() => { setStep(step - 1); setError(null); }}
            disabled={step === 0}
            className="px-4 py-2 rounded-lg text-sm font-medium text-gray-600 hover:bg-gray-100 disabled:opacity-30 disabled:cursor-not-allowed transition"
          >
            Back
          </button>

          {step < 4 && (
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
        className="mt-4 text-xs text-gray-400 hover:text-gray-600 transition"
      >
        Skip setup for now
      </button>
    </div>
  );
}
