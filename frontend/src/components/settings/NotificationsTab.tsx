import React from 'react';
import { SettingsData, StatusData, WebhookData, WebhookDelivery } from './types';

const REPORT_FREQUENCY_OPTIONS = [
  { value: 'weekly', label: 'Weekly (Mon 8:00 UTC)' },
  { value: 'monthly', label: 'Monthly (1st 8:00 UTC)' },
] as const;

interface NotificationsTabProps {
  settings: SettingsData;
  status: StatusData | null;
  update: (key: keyof SettingsData, value: string) => void;
  toggleBool: (key: keyof SettingsData) => void;
  testingEmail: boolean;
  testResult: { type: 'success' | 'error'; message: string } | null;
  handleTestEmail: () => void;
  webhooks: WebhookData[];
  openWebhookModal: (wh?: WebhookData) => void;
  handleToggleWebhook: (wh: WebhookData) => void;
  handleWebhookTest: (id: number) => void;
  handleWebhookDelete: (id: number) => void;
  loadDeliveries: (webhookId: number) => void;
  testingWebhookId: number | null;
  expandedDeliveries: number | null;
  deliveries: WebhookDelivery[];
  deleteConfirm: number | null;
  setDeleteConfirm: (id: number | null) => void;
  WEBHOOK_EVENT_LABELS: Record<string, string>;
}

export function NotificationsTab({
  settings,
  status,
  update,
  toggleBool,
  testingEmail,
  testResult,
  handleTestEmail,
  webhooks,
  openWebhookModal,
  handleToggleWebhook,
  handleWebhookTest,
  handleWebhookDelete,
  loadDeliveries,
  testingWebhookId,
  expandedDeliveries,
  deliveries,
  deleteConfirm,
  setDeleteConfirm,
  WEBHOOK_EVENT_LABELS,
}: NotificationsTabProps) {
  return (
    <>
          {/* Section 4: Email Notifications */}
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
                {/* Recipient + Sender */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Alert Recipients</label>
                    <input
                      type="email"
                      value={settings.email_to}
                      onChange={e => update('email_to', e.target.value)}
                      placeholder="alerts@yourcompany.com"
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Sender</label>
                    <div className="px-3 py-2 border border-gray-200 rounded-lg text-sm text-gray-500 bg-gray-50">
                      auditgraphalerts@nexgenixlabs.com
                    </div>
                  </div>
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

                {/* Notification toggles — 6 switches */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-3">Notification Types</label>
                  <div className="space-y-3">
                    {([
                      { key: 'notify_credential_changes' as const, label: 'Secret / credential expiry', description: 'Alert when secrets or certificates are expiring or expired' },
                      { key: 'notify_permission_changes' as const, label: 'Drift detection', description: 'Notify when permission or role changes are detected' },
                      { key: 'notify_risk_changes' as const, label: 'Critical risk alerts', description: 'Immediate alerts for critical and high risk escalations' },
                      { key: 'notify_new_identities' as const, label: 'Snapshot failure alerts', description: 'Alert when a snapshot capture fails or encounters errors' },
                      { key: 'notify_removed_identities' as const, label: 'Snapshot completion', description: 'Summary notification after each successful snapshot' },
                      { key: 'notify_weekly_digest' as const, label: 'Weekly risk digest', description: 'Weekly summary of risk posture and key changes' },
                    ]).map(item => (
                      <div key={item.key} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-b-0">
                        <div>
                          <div className="text-sm font-medium text-gray-800">{item.label}</div>
                          <div className="text-xs text-gray-400">{item.description}</div>
                        </div>
                        <button
                          onClick={() => toggleBool(item.key)}
                          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors shrink-0 ${
                            settings[item.key] === 'true' ? 'bg-blue-500' : 'bg-gray-300'
                          }`}
                        >
                          <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                            settings[item.key] === 'true' ? 'translate-x-4' : 'translate-x-0.5'
                          }`} />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>

          {/* Section 4: Report Schedule */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-lg font-semibold text-gray-900">Report Schedule</div>
              {status?.report_schedule_allowed !== false && (
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
              )}
            </div>

            <p className="text-sm text-gray-500">
              Automatically send an executive summary report on a recurring schedule.
            </p>

            {/* Entitlement lock — visible but disabled for free-tier orgs */}
            {status?.report_schedule_allowed === false ? (
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <p className="text-sm text-gray-600">
                  Scheduled reports are available on Pro and Trial plans.
                  Contact sales to upgrade.
                </p>
              </div>
            ) : settings.report_schedule_enabled === 'true' ? (
              <>
                {/* Frequency selector */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Delivery Frequency
                  </label>
                  <div className="flex gap-3">
                    {REPORT_FREQUENCY_OPTIONS.map(opt => (
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
                </div>

                {/* Report recipient */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Delivery Email
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

                {/* Schedule status: next + last delivery */}
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2 text-sm">
                    <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                    <span className="text-gray-600">
                      Next delivery: {status?.next_report
                        ? new Date(status.next_report).toLocaleString()
                        : 'Pending scheduler start'}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <span className="w-2 h-2 rounded-full bg-gray-400" />
                    <span className="text-gray-500">
                      Last delivery: {status?.last_report
                        ? new Date(status.last_report).toLocaleString()
                        : 'Never'}
                    </span>
                  </div>
                </div>
              </>
            ) : null}
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
    </>
  );
}
