import React, { useEffect, useState } from 'react';

interface SettingsData {
  org_name: string;
  discovery_interval_hours: string;
  email_enabled: string;
  email_to: string;
  notify_new_identities: string;
  notify_removed_identities: string;
  notify_permission_changes: string;
  notify_risk_changes: string;
  notify_credential_changes: string;
}

interface StatusData {
  azure_configured: boolean;
  email_configured: boolean;
  scheduler_running: boolean;
  next_run: string | null;
}

export default function Settings() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [status, setStatus] = useState<StatusData | null>(null);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const res = await fetch('/api/settings');
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        const data = await res.json();
        setSettings(data.settings as SettingsData);
        setStatus(data.status);
      } catch (e: any) {
        setError(e?.message || 'Failed to load settings');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  async function handleSave() {
    if (!settings) return;
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      setSettings(data.settings as SettingsData);
      setSuccess(`Settings saved (${data.updated?.length || 0} updated)`);
      setTimeout(() => setSuccess(null), 4000);
    } catch (e: any) {
      setError(e?.message || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  }

  function update(key: keyof SettingsData, value: string) {
    if (!settings) return;
    setSettings({ ...settings, [key]: value });
  }

  function toggleBool(key: keyof SettingsData) {
    if (!settings) return;
    setSettings({ ...settings, [key]: settings[key] === 'true' ? 'false' : 'true' });
  }

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-48" />
          <div className="h-48 bg-gray-100 rounded-xl" />
          <div className="h-48 bg-gray-100 rounded-xl" />
          <div className="h-48 bg-gray-100 rounded-xl" />
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Settings</h2>
        <p className="text-sm text-gray-600 mt-1">
          Configure discovery schedule, notifications, and organization details
        </p>
      </div>

      {/* Error / Success */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-700">
          {error}
        </div>
      )}
      {success && (
        <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-sm text-green-700">
          {success}
        </div>
      )}

      {settings && (
        <>
          {/* Section 1: Organization */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="text-lg font-semibold text-gray-900">Organization</div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Organization Name
              </label>
              <input
                type="text"
                value={settings.org_name}
                onChange={e => update('org_name', e.target.value)}
                placeholder="e.g., Acme Corp"
                className="w-full max-w-md px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <p className="text-xs text-gray-400 mt-1">
                Appears on PDF report cover pages and email notifications
              </p>
            </div>
          </div>

          {/* Section 2: Discovery Schedule */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="text-lg font-semibold text-gray-900">Discovery Schedule</div>

            {/* Status indicators */}
            <div className="flex items-center gap-6 text-sm">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${status?.azure_configured ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-gray-600">
                  Azure: {status?.azure_configured ? 'Connected' : 'Not configured'}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${status?.scheduler_running ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
                <span className="text-gray-600">
                  Scheduler: {status?.scheduler_running ? 'Running' : 'Stopped'}
                </span>
              </div>
              {status?.next_run && (
                <span className="text-gray-400 text-xs">
                  Next run: {new Date(status.next_run).toLocaleString()}
                </span>
              )}
            </div>

            {/* Interval selector */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Discovery Interval
              </label>
              <div className="flex gap-3">
                {['6', '12', '24'].map(val => (
                  <button
                    key={val}
                    onClick={() => update('discovery_interval_hours', val)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium border transition ${
                      settings.discovery_interval_hours === val
                        ? 'bg-blue-600 text-white border-blue-600'
                        : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    Every {val} hours
                  </button>
                ))}
              </div>
              <p className="text-xs text-gray-400 mt-2">
                How often the discovery engine scans your Azure environment. Takes effect on next scheduler restart.
              </p>
            </div>
          </div>

          {/* Section 3: Email Notifications */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-lg font-semibold text-gray-900">Email Notifications</div>
              <button
                onClick={() => toggleBool('email_enabled')}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  settings.email_enabled === 'true' ? 'bg-blue-600' : 'bg-gray-300'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    settings.email_enabled === 'true' ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>

            {/* Email service status */}
            <div className="flex items-center gap-2 text-sm">
              <span className={`w-2 h-2 rounded-full ${status?.email_configured ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-gray-600">
                Email service: {status?.email_configured ? 'Configured (Microsoft Graph)' : 'Not configured (needs Azure credentials)'}
              </span>
            </div>

            {settings.email_enabled === 'true' && (
              <>
                {/* Recipient */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Notification Recipient
                  </label>
                  <input
                    type="email"
                    value={settings.email_to}
                    onChange={e => update('email_to', e.target.value)}
                    placeholder="alerts@yourcompany.com"
                    className="w-full max-w-md px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Email address to receive change notifications. Leave empty to use the default.
                  </p>
                </div>

                {/* Change type toggles */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Notify on these change types
                  </label>
                  <div className="space-y-2">
                    {([
                      { key: 'notify_new_identities' as const, label: 'New identities added', color: 'text-green-600' },
                      { key: 'notify_removed_identities' as const, label: 'Identities removed', color: 'text-red-600' },
                      { key: 'notify_permission_changes' as const, label: 'Permission / role changes', color: 'text-orange-600' },
                      { key: 'notify_risk_changes' as const, label: 'Risk level escalations', color: 'text-purple-600' },
                      { key: 'notify_credential_changes' as const, label: 'Credential status changes', color: 'text-yellow-700' },
                    ]).map(item => (
                      <label key={item.key} className="flex items-center gap-3 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={settings[item.key] === 'true'}
                          onChange={() => toggleBool(item.key)}
                          className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                        />
                        <span className="text-sm text-gray-700">{item.label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>

          {/* Save button */}
          <div className="flex items-center gap-4">
            <button
              onClick={handleSave}
              disabled={saving}
              className={`px-6 py-3 rounded-xl text-sm font-semibold text-white transition ${
                saving
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-700 shadow-sm'
              }`}
            >
              {saving ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Saving...
                </span>
              ) : (
                'Save Settings'
              )}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
