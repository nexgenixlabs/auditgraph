import React, { useEffect, useState, useCallback } from 'react';

interface WebhookData {
  id: number;
  name: string;
  url: string;
  secret: string | null;
  event_types: string[];
  headers: Record<string, string> | null;
  enabled: boolean;
  created_at: string | null;
  updated_at: string | null;
  total_deliveries: number;
  successful_deliveries: number;
  last_delivered_at: string | null;
}

interface WebhookDelivery {
  id: number;
  event_type: string;
  status: string;
  http_status: number | null;
  attempts: number;
  created_at: string | null;
  delivered_at: string | null;
}

interface WebhookFormData {
  name: string;
  url: string;
  secret: string;
  event_types: string[];
}

const WEBHOOK_EVENT_LABELS: Record<string, string> = {
  discovery_completed: 'Discovery Completed',
  risk_escalation: 'Risk Escalation',
  new_identities: 'New Identities',
  removed_identities: 'Removed Identities',
  permission_changes: 'Permission Changes',
  credential_changes: 'Credential Changes',
  drift_detected: 'Drift Detected',
};

const ALL_WEBHOOK_EVENTS = Object.keys(WEBHOOK_EVENT_LABELS);

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
  report_schedule_enabled: string;
  report_schedule_frequency: string;
  report_email_to: string;
}

interface StatusData {
  azure_configured: boolean;
  email_configured: boolean;
  scheduler_running: boolean;
  next_run: string | null;
  next_report: string | null;
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

  // Webhook state
  const [webhooks, setWebhooks] = useState<WebhookData[]>([]);
  const [webhookModal, setWebhookModal] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState<WebhookData | null>(null);
  const [webhookForm, setWebhookForm] = useState<WebhookFormData>({ name: '', url: 'https://', secret: '', event_types: [] });
  const [webhookSaving, setWebhookSaving] = useState(false);
  const [webhookError, setWebhookError] = useState<string | null>(null);
  const [testingWebhookId, setTestingWebhookId] = useState<number | null>(null);
  const [expandedDeliveries, setExpandedDeliveries] = useState<number | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null);

  const loadWebhooks = useCallback(async () => {
    try {
      const res = await fetch('/api/webhooks');
      if (res.ok) {
        const data = await res.json();
        setWebhooks(data.webhooks || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { loadWebhooks(); }, [loadWebhooks]);

  async function handleWebhookSave() {
    setWebhookSaving(true);
    setWebhookError(null);
    try {
      const method = editingWebhook ? 'PUT' : 'POST';
      const url = editingWebhook ? `/api/webhooks/${editingWebhook.id}` : '/api/webhooks';
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(webhookForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      setWebhookModal(false);
      setEditingWebhook(null);
      loadWebhooks();
    } catch (e: any) {
      setWebhookError(e?.message || 'Failed to save webhook');
    } finally {
      setWebhookSaving(false);
    }
  }

  async function handleWebhookDelete(id: number) {
    try {
      await fetch(`/api/webhooks/${id}`, { method: 'DELETE' });
      setDeleteConfirm(null);
      loadWebhooks();
    } catch { /* ignore */ }
  }

  async function handleWebhookTest(id: number) {
    setTestingWebhookId(id);
    try {
      await fetch(`/api/webhooks/${id}/test`, { method: 'POST' });
      loadWebhooks();
    } catch { /* ignore */ }
    finally { setTestingWebhookId(null); }
  }

  async function handleToggleWebhook(wh: WebhookData) {
    try {
      await fetch(`/api/webhooks/${wh.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !wh.enabled }),
      });
      loadWebhooks();
    } catch { /* ignore */ }
  }

  async function loadDeliveries(webhookId: number) {
    if (expandedDeliveries === webhookId) {
      setExpandedDeliveries(null);
      return;
    }
    try {
      const res = await fetch(`/api/webhooks/${webhookId}/deliveries?limit=10`);
      if (res.ok) {
        const data = await res.json();
        setDeliveries(data.deliveries || []);
        setExpandedDeliveries(webhookId);
      }
    } catch { /* ignore */ }
  }

  function openWebhookModal(wh?: WebhookData) {
    if (wh) {
      setEditingWebhook(wh);
      setWebhookForm({
        name: wh.name,
        url: wh.url,
        secret: wh.secret || '',
        event_types: wh.event_types || [],
      });
    } else {
      setEditingWebhook(null);
      setWebhookForm({ name: '', url: 'https://', secret: '', event_types: [] });
    }
    setWebhookError(null);
    setWebhookModal(true);
  }

  function toggleWebhookEvent(event: string) {
    setWebhookForm(prev => ({
      ...prev,
      event_types: prev.event_types.includes(event)
        ? prev.event_types.filter(e => e !== event)
        : [...prev.event_types, event],
    }));
  }

  // Test email state
  const [testingEmail, setTestingEmail] = useState(false);
  const [testResult, setTestResult] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  async function handleTestEmail() {
    if (!settings) return;
    setTestingEmail(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/settings/test-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_to: settings.email_to }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Send failed');
      setTestResult({ type: 'success', message: data.message || 'Test email sent successfully' });
      setTimeout(() => setTestResult(null), 6000);
    } catch (e: any) {
      setTestResult({ type: 'error', message: e?.message || 'Failed to send test email' });
    } finally {
      setTestingEmail(false);
    }
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

                {/* Test email button */}
                <div className="flex items-center gap-3">
                  <button
                    onClick={handleTestEmail}
                    disabled={testingEmail || !status?.email_configured}
                    className={`px-4 py-2 rounded-lg text-sm font-medium border transition ${
                      testingEmail || !status?.email_configured
                        ? 'bg-gray-100 text-gray-400 border-gray-200 cursor-not-allowed'
                        : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    {testingEmail ? (
                      <span className="flex items-center gap-2">
                        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        Sending...
                      </span>
                    ) : 'Send Test Email'}
                  </button>
                  {testResult && (
                    <span className={`text-sm ${testResult.type === 'success' ? 'text-green-600' : 'text-red-600'}`}>
                      {testResult.message}
                    </span>
                  )}
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

          {/* Section 4: Scheduled Reports */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-lg font-semibold text-gray-900">Scheduled Reports</div>
              <button
                onClick={() => toggleBool('report_schedule_enabled')}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  settings.report_schedule_enabled === 'true' ? 'bg-blue-600' : 'bg-gray-300'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    settings.report_schedule_enabled === 'true' ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>

            <p className="text-sm text-gray-500">
              Automatically send an executive summary report on a recurring schedule.
            </p>

            {settings.report_schedule_enabled === 'true' && (
              <>
                {/* Frequency selector */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Delivery Frequency
                  </label>
                  <div className="flex gap-3">
                    {([
                      { value: 'weekly', label: 'Weekly (Mon 8:00 UTC)' },
                      { value: 'monthly', label: 'Monthly (1st 8:00 UTC)' },
                    ] as const).map(opt => (
                      <button
                        key={opt.value}
                        onClick={() => update('report_schedule_frequency', opt.value)}
                        className={`px-4 py-2 rounded-lg text-sm font-medium border transition ${
                          settings.report_schedule_frequency === opt.value
                            ? 'bg-blue-600 text-white border-blue-600'
                            : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                        }`}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                  <p className="text-xs text-gray-400 mt-2">
                    Schedule changes take effect on next scheduler restart.
                  </p>
                </div>

                {/* Report recipient */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Report Recipient
                  </label>
                  <input
                    type="email"
                    value={settings.report_email_to}
                    onChange={e => update('report_email_to', e.target.value)}
                    placeholder={settings.email_to || 'Uses notification recipient'}
                    className="w-full max-w-md px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Leave empty to use the notification recipient above.
                  </p>
                </div>

                {/* Next delivery time */}
                {status?.next_report && (
                  <div className="flex items-center gap-2 text-sm">
                    <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                    <span className="text-gray-600">
                      Next delivery: {new Date(status.next_report).toLocaleString()}
                    </span>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Section 5: Webhooks */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-lg font-semibold text-gray-900">Webhooks</div>
                <p className="text-sm text-gray-500 mt-0.5">
                  Send real-time alerts to Slack, Teams, Splunk, or any HTTP endpoint
                </p>
              </div>
              <button
                onClick={() => openWebhookModal()}
                disabled={webhooks.length >= 10}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
                  webhooks.length >= 10
                    ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 text-white hover:bg-blue-700'
                }`}
              >
                + Add Webhook
              </button>
            </div>

            {webhooks.length === 0 ? (
              <div className="text-sm text-gray-400 text-center py-6 border border-dashed rounded-lg">
                No webhooks configured. Add one to receive real-time alerts.
              </div>
            ) : (
              <div className="space-y-3">
                {webhooks.map(wh => (
                  <div key={wh.id} className="border rounded-lg">
                    <div className="flex items-center justify-between px-4 py-3">
                      <div className="flex items-center gap-3 min-w-0 flex-1">
                        {/* Enabled toggle */}
                        <button
                          onClick={() => handleToggleWebhook(wh)}
                          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0 ${
                            wh.enabled ? 'bg-green-500' : 'bg-gray-300'
                          }`}
                        >
                          <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                            wh.enabled ? 'translate-x-4' : 'translate-x-0.5'
                          }`} />
                        </button>

                        <div className="min-w-0 flex-1">
                          <div className="text-sm font-medium text-gray-900 truncate">{wh.name}</div>
                          <div className="text-xs text-gray-400 font-mono truncate">{wh.url}</div>
                        </div>
                      </div>

                      {/* Event type badges */}
                      <div className="hidden sm:flex items-center gap-1 mx-3 flex-shrink-0">
                        {(wh.event_types || []).slice(0, 3).map(et => (
                          <span key={et} className="px-1.5 py-0.5 bg-blue-50 text-blue-700 text-[10px] font-medium rounded">
                            {WEBHOOK_EVENT_LABELS[et]?.split(' ')[0] || et}
                          </span>
                        ))}
                        {(wh.event_types || []).length > 3 && (
                          <span className="text-[10px] text-gray-400">+{wh.event_types.length - 3}</span>
                        )}
                      </div>

                      {/* Stats + actions */}
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <span className="text-xs text-gray-400">
                          {wh.successful_deliveries}/{wh.total_deliveries} delivered
                        </span>
                        <button
                          onClick={() => handleWebhookTest(wh.id)}
                          disabled={testingWebhookId === wh.id}
                          className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded transition"
                        >
                          {testingWebhookId === wh.id ? 'Testing...' : 'Test'}
                        </button>
                        <button
                          onClick={() => loadDeliveries(wh.id)}
                          className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded transition"
                        >
                          {expandedDeliveries === wh.id ? 'Hide' : 'Log'}
                        </button>
                        <button
                          onClick={() => openWebhookModal(wh)}
                          className="px-2 py-1 text-xs font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded transition"
                        >
                          Edit
                        </button>
                        {deleteConfirm === wh.id ? (
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => handleWebhookDelete(wh.id)}
                              className="px-2 py-1 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded transition"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => setDeleteConfirm(null)}
                              className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded transition"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setDeleteConfirm(wh.id)}
                            className="px-2 py-1 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded transition"
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Delivery log (expandable) */}
                    {expandedDeliveries === wh.id && (
                      <div className="border-t px-4 py-3 bg-gray-50">
                        <div className="text-xs font-semibold text-gray-600 mb-2">Recent Deliveries</div>
                        {deliveries.length === 0 ? (
                          <div className="text-xs text-gray-400">No deliveries yet</div>
                        ) : (
                          <div className="space-y-1">
                            {deliveries.map(d => (
                              <div key={d.id} className="flex items-center justify-between text-xs">
                                <div className="flex items-center gap-2">
                                  <span className={`w-1.5 h-1.5 rounded-full ${
                                    d.status === 'delivered' ? 'bg-green-500' : d.status === 'pending' ? 'bg-yellow-500' : 'bg-red-500'
                                  }`} />
                                  <span className="font-medium text-gray-700">{WEBHOOK_EVENT_LABELS[d.event_type] || d.event_type}</span>
                                </div>
                                <div className="flex items-center gap-3 text-gray-400">
                                  {d.http_status && <span>HTTP {d.http_status}</span>}
                                  <span>{d.created_at ? new Date(d.created_at).toLocaleString() : '-'}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            <p className="text-xs text-gray-400">
              Maximum 10 webhooks. Payloads are signed with HMAC-SHA256 if a secret is configured.
            </p>
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

      {/* Webhook Add/Edit Modal */}
      {webhookModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="fixed inset-0 bg-black/40" onClick={() => setWebhookModal(false)} />
          <div className="relative bg-white rounded-xl shadow-2xl border w-full max-w-lg mx-4 p-6 space-y-4">
            <div className="text-lg font-semibold text-gray-900">
              {editingWebhook ? 'Edit Webhook' : 'Add Webhook'}
            </div>

            {webhookError && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
                {webhookError}
              </div>
            )}

            {/* Name */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
              <input
                type="text"
                value={webhookForm.name}
                onChange={e => setWebhookForm(prev => ({ ...prev, name: e.target.value }))}
                placeholder="e.g., Slack SOC Alerts"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            {/* URL */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">URL (HTTPS only)</label>
              <input
                type="url"
                value={webhookForm.url}
                onChange={e => setWebhookForm(prev => ({ ...prev, url: e.target.value }))}
                placeholder="https://hooks.slack.com/services/..."
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            {/* Secret */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Secret Key <span className="text-gray-400 font-normal">(optional)</span>
              </label>
              <input
                type="text"
                value={webhookForm.secret}
                onChange={e => setWebhookForm(prev => ({ ...prev, secret: e.target.value }))}
                placeholder="Used for HMAC-SHA256 signature verification"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            {/* Event types */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Event Types</label>
              <div className="grid grid-cols-2 gap-2">
                {ALL_WEBHOOK_EVENTS.map(event => (
                  <label key={event} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={webhookForm.event_types.includes(event)}
                      onChange={() => toggleWebhookEvent(event)}
                      className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-700">{WEBHOOK_EVENT_LABELS[event]}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setWebhookModal(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleWebhookSave}
                disabled={webhookSaving || !webhookForm.name || !webhookForm.url.startsWith('https://') || webhookForm.event_types.length === 0}
                className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition ${
                  webhookSaving || !webhookForm.name || !webhookForm.url.startsWith('https://') || webhookForm.event_types.length === 0
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {webhookSaving ? 'Saving...' : editingWebhook ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
