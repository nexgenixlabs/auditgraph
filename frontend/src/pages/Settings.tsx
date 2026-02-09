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

// Risk Rule types
interface RiskRuleCondition {
  field: string;
  op: string;
  value: string | number | boolean;
}

interface RiskRuleData {
  id: number;
  name: string;
  description: string | null;
  conditions: { all: RiskRuleCondition[] };
  action_type: 'adjust_points' | 'force_level';
  points_adjustment: number;
  force_level: string | null;
  reason_text: string | null;
  enabled: boolean;
  priority: number;
  created_at: string | null;
  updated_at: string | null;
}

interface RiskRuleFormData {
  name: string;
  description: string;
  conditions: RiskRuleCondition[];
  action_type: 'adjust_points' | 'force_level';
  points_adjustment: number;
  force_level: string;
  reason_text: string;
  priority: number;
}

const RULE_FIELDS: { value: string; label: string; type: 'select' | 'text' | 'number' | 'boolean'; options?: string[] }[] = [
  { value: 'identity_category', label: 'Identity Category', type: 'select', options: ['service_principal', 'human_user', 'guest', 'managed_identity_system', 'managed_identity_user'] },
  { value: 'activity_status', label: 'Activity Status', type: 'select', options: ['active', 'inactive', 'stale', 'never_used'] },
  { value: 'has_entra_role', label: 'Has Entra Role (contains)', type: 'text' },
  { value: 'has_rbac_role', label: 'Has RBAC Role (contains)', type: 'text' },
  { value: 'has_write_permissions', label: 'Has Write Permissions', type: 'boolean' },
  { value: 'role_count', label: 'Role Count', type: 'number' },
  { value: 'api_permission_count', label: 'API Permission Count', type: 'number' },
  { value: 'risk_score', label: 'Default Risk Score', type: 'number' },
  { value: 'enabled', label: 'Identity Enabled', type: 'boolean' },
  { value: 'display_name', label: 'Display Name (contains)', type: 'text' },
  { value: 'credential_status', label: 'Credential Status', type: 'select', options: ['expired', 'expiring_soon', 'healthy'] },
  { value: 'app_role_count', label: 'App Role Count', type: 'number' },
];

const OPS_FOR_TYPE: Record<string, { value: string; label: string }[]> = {
  select: [{ value: 'eq', label: '=' }, { value: 'neq', label: '!=' }, { value: 'in', label: 'in' }],
  text: [{ value: 'contains', label: 'contains' }, { value: 'eq', label: '=' }, { value: 'neq', label: '!=' }],
  number: [{ value: 'gt', label: '>' }, { value: 'gte', label: '>=' }, { value: 'lt', label: '<' }, { value: 'lte', label: '<=' }, { value: 'eq', label: '=' }],
  boolean: [{ value: 'eq', label: '=' }],
};

const EMPTY_RULE_FORM: RiskRuleFormData = {
  name: '', description: '', conditions: [{ field: 'identity_category', op: 'eq', value: '' }],
  action_type: 'adjust_points', points_adjustment: 0, force_level: 'critical', reason_text: '', priority: 100,
};

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

  // Risk rule state
  const [riskRules, setRiskRules] = useState<RiskRuleData[]>([]);
  const [ruleModal, setRuleModal] = useState(false);
  const [editingRule, setEditingRule] = useState<RiskRuleData | null>(null);
  const [ruleForm, setRuleForm] = useState<RiskRuleFormData>({ ...EMPTY_RULE_FORM });
  const [ruleSaving, setRuleSaving] = useState(false);
  const [ruleError, setRuleError] = useState<string | null>(null);
  const [ruleDeleteConfirm, setRuleDeleteConfirm] = useState<number | null>(null);
  const [previewResult, setPreviewResult] = useState<{ count: number; identities: { display_name: string; risk_level: string }[] } | null>(null);
  const [previewing, setPreviewing] = useState(false);

  const loadRiskRules = useCallback(async () => {
    try {
      const res = await fetch('/api/risk-rules');
      if (res.ok) {
        const data = await res.json();
        setRiskRules(data.rules || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { loadRiskRules(); }, [loadRiskRules]);

  function openRuleModal(rule?: RiskRuleData) {
    if (rule) {
      setEditingRule(rule);
      setRuleForm({
        name: rule.name,
        description: rule.description || '',
        conditions: rule.conditions?.all || [{ field: 'identity_category', op: 'eq', value: '' }],
        action_type: rule.action_type,
        points_adjustment: rule.points_adjustment,
        force_level: rule.force_level || 'critical',
        reason_text: rule.reason_text || '',
        priority: rule.priority,
      });
    } else {
      setEditingRule(null);
      setRuleForm({ ...EMPTY_RULE_FORM, conditions: [{ field: 'identity_category', op: 'eq', value: '' }] });
    }
    setRuleError(null);
    setPreviewResult(null);
    setRuleModal(true);
  }

  async function handleRuleSave() {
    setRuleSaving(true);
    setRuleError(null);
    try {
      const payload = {
        name: ruleForm.name,
        description: ruleForm.description || null,
        conditions: { all: ruleForm.conditions },
        action_type: ruleForm.action_type,
        points_adjustment: ruleForm.action_type === 'adjust_points' ? ruleForm.points_adjustment : 0,
        force_level: ruleForm.action_type === 'force_level' ? ruleForm.force_level : null,
        reason_text: ruleForm.reason_text || null,
        priority: ruleForm.priority,
      };
      const method = editingRule ? 'PUT' : 'POST';
      const url = editingRule ? `/api/risk-rules/${editingRule.id}` : '/api/risk-rules';
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      setRuleModal(false);
      setEditingRule(null);
      loadRiskRules();
    } catch (e: any) {
      setRuleError(e?.message || 'Failed to save rule');
    } finally {
      setRuleSaving(false);
    }
  }

  async function handleRuleDelete(id: number) {
    try {
      await fetch(`/api/risk-rules/${id}`, { method: 'DELETE' });
      setRuleDeleteConfirm(null);
      loadRiskRules();
    } catch { /* ignore */ }
  }

  async function handleToggleRule(rule: RiskRuleData) {
    try {
      await fetch(`/api/risk-rules/${rule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !rule.enabled }),
      });
      loadRiskRules();
    } catch { /* ignore */ }
  }

  async function handlePreview() {
    setPreviewing(true);
    setPreviewResult(null);
    try {
      const res = await fetch('/api/risk-rules/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          conditions: { all: ruleForm.conditions },
          action_type: ruleForm.action_type,
          points_adjustment: ruleForm.points_adjustment,
          force_level: ruleForm.force_level,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setPreviewResult({ count: data.affected_count, identities: data.affected || [] });
      }
    } catch { /* ignore */ }
    finally { setPreviewing(false); }
  }

  function addCondition() {
    setRuleForm(prev => ({
      ...prev,
      conditions: [...prev.conditions, { field: 'identity_category', op: 'eq', value: '' }],
    }));
  }

  function removeCondition(idx: number) {
    setRuleForm(prev => ({
      ...prev,
      conditions: prev.conditions.filter((_, i) => i !== idx),
    }));
  }

  function updateCondition(idx: number, updates: Partial<RiskRuleCondition>) {
    setRuleForm(prev => ({
      ...prev,
      conditions: prev.conditions.map((c, i) => i === idx ? { ...c, ...updates } : c),
    }));
  }

  // User management state
  interface UserData { id: number; username: string; display_name: string; role: string; enabled: boolean; last_login_at: string | null; created_at: string | null; }
  interface UserFormData { username: string; display_name: string; password: string; role: string; }

  const [users, setUsers] = useState<UserData[]>([]);
  const [userModal, setUserModal] = useState(false);
  const [editingUser, setEditingUser] = useState<UserData | null>(null);
  const [userForm, setUserForm] = useState<UserFormData>({ username: '', display_name: '', password: '', role: 'viewer' });
  const [userSaving, setUserSaving] = useState(false);
  const [userError, setUserError] = useState<string | null>(null);
  const [userDeleteConfirm, setUserDeleteConfirm] = useState<number | null>(null);

  const loadUsers = useCallback(async () => {
    try {
      const res = await fetch('/api/users');
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { loadUsers(); }, [loadUsers]);

  function openUserModal(u?: UserData) {
    if (u) {
      setEditingUser(u);
      setUserForm({ username: u.username, display_name: u.display_name, password: '', role: u.role });
    } else {
      setEditingUser(null);
      setUserForm({ username: '', display_name: '', password: '', role: 'viewer' });
    }
    setUserError(null);
    setUserModal(true);
  }

  async function handleUserSave() {
    setUserSaving(true);
    setUserError(null);
    try {
      const method = editingUser ? 'PUT' : 'POST';
      const url = editingUser ? `/api/users/${editingUser.id}` : '/api/users';
      const payload: Record<string, unknown> = {
        display_name: userForm.display_name,
        role: userForm.role,
      };
      if (!editingUser) {
        payload.username = userForm.username;
        payload.password = userForm.password;
      } else if (userForm.password) {
        payload.password = userForm.password;
      }
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      setUserModal(false);
      setEditingUser(null);
      loadUsers();
    } catch (e: unknown) {
      setUserError(e instanceof Error ? e.message : 'Failed to save user');
    } finally {
      setUserSaving(false);
    }
  }

  async function handleUserDelete(id: number) {
    try {
      const res = await fetch(`/api/users/${id}`, { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json();
        setUserError(data.error || 'Delete failed');
        return;
      }
      setUserDeleteConfirm(null);
      loadUsers();
    } catch { /* ignore */ }
  }

  async function handleToggleUser(u: UserData) {
    try {
      const res = await fetch(`/api/users/${u.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !u.enabled }),
      });
      if (!res.ok) {
        const data = await res.json();
        setUserError(data.error || 'Toggle failed');
        return;
      }
      loadUsers();
    } catch { /* ignore */ }
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

          {/* Section 6: Custom Risk Rules */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-lg font-semibold text-gray-900">Custom Risk Rules</div>
                <p className="text-sm text-gray-500 mt-0.5">
                  Adjust risk scoring with custom conditions — runs after default scoring
                </p>
              </div>
              <button
                onClick={() => openRuleModal()}
                disabled={riskRules.length >= 50}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
                  riskRules.length >= 50
                    ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 text-white hover:bg-blue-700'
                }`}
              >
                + Add Rule
              </button>
            </div>

            {riskRules.length === 0 ? (
              <div className="text-sm text-gray-400 text-center py-6 border border-dashed rounded-lg">
                No custom risk rules configured. Add one to customize risk scoring.
              </div>
            ) : (
              <div className="space-y-2">
                {riskRules.map(rule => (
                  <div key={rule.id} className="border rounded-lg px-4 py-3 flex items-center justify-between">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <button
                        onClick={() => handleToggleRule(rule)}
                        className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0 ${
                          rule.enabled ? 'bg-green-500' : 'bg-gray-300'
                        }`}
                      >
                        <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                          rule.enabled ? 'translate-x-4' : 'translate-x-0.5'
                        }`} />
                      </button>

                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-gray-900 truncate">{rule.name}</div>
                        <div className="text-xs text-gray-400">
                          {(rule.conditions?.all || []).length} condition{(rule.conditions?.all || []).length !== 1 ? 's' : ''} · Priority {rule.priority}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 flex-shrink-0">
                      {/* Action badge */}
                      {rule.action_type === 'force_level' ? (
                        <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${
                          rule.force_level === 'critical' ? 'bg-red-100 text-red-700' :
                          rule.force_level === 'high' ? 'bg-orange-100 text-orange-700' :
                          rule.force_level === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                          'bg-green-100 text-green-700'
                        }`}>
                          FORCE {(rule.force_level || '').toUpperCase()}
                        </span>
                      ) : (
                        <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${
                          rule.points_adjustment > 0 ? 'bg-red-50 text-red-600' : 'bg-green-50 text-green-600'
                        }`}>
                          {rule.points_adjustment > 0 ? '+' : ''}{rule.points_adjustment} pts
                        </span>
                      )}

                      <button
                        onClick={() => openRuleModal(rule)}
                        className="px-2 py-1 text-xs font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded transition"
                      >
                        Edit
                      </button>
                      {ruleDeleteConfirm === rule.id ? (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => handleRuleDelete(rule.id)}
                            className="px-2 py-1 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded transition"
                          >
                            Confirm
                          </button>
                          <button
                            onClick={() => setRuleDeleteConfirm(null)}
                            className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded transition"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setRuleDeleteConfirm(rule.id)}
                          className="px-2 py-1 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded transition"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <p className="text-xs text-gray-400">
              Maximum 50 rules. Rules run after default scoring on every discovery run, ordered by priority (lower runs first).
            </p>
          </div>

          {/* Section 7: User Management */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-lg font-semibold text-gray-900">User Management</div>
                <p className="text-sm text-gray-500 mt-0.5">
                  Manage user accounts and role-based access control
                </p>
              </div>
              <button
                onClick={() => openUserModal()}
                className="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 transition"
              >
                + Add User
              </button>
            </div>

            {userError && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
                {userError}
                <button onClick={() => setUserError(null)} className="ml-2 font-medium underline">Dismiss</button>
              </div>
            )}

            {users.length === 0 ? (
              <p className="text-sm text-gray-400 py-4 text-center">No users configured</p>
            ) : (
              <div className="space-y-2">
                {users.map(u => (
                  <div key={u.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center text-xs font-bold text-gray-600 uppercase">
                        {u.display_name.charAt(0)}
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-900 flex items-center gap-2">
                          {u.display_name}
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase ${
                            u.role === 'admin' ? 'bg-red-50 text-red-700' :
                            u.role === 'auditor' ? 'bg-blue-50 text-blue-700' :
                            'bg-gray-100 text-gray-600'
                          }`}>
                            {u.role}
                          </span>
                          {!u.enabled && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-50 text-yellow-700">DISABLED</span>
                          )}
                        </div>
                        <div className="text-xs text-gray-500">
                          @{u.username}
                          {u.last_login_at && <> &middot; Last login: {new Date(u.last_login_at).toLocaleDateString()}</>}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleToggleUser(u)}
                        className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                          u.enabled ? 'bg-green-500' : 'bg-gray-300'
                        }`}
                        title={u.enabled ? 'Disable user' : 'Enable user'}
                      >
                        <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                          u.enabled ? 'translate-x-4' : 'translate-x-0.5'
                        }`} />
                      </button>
                      <button
                        onClick={() => openUserModal(u)}
                        className="px-2 py-1 text-xs text-blue-600 hover:bg-blue-50 rounded transition"
                      >
                        Edit
                      </button>
                      {userDeleteConfirm === u.id ? (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => handleUserDelete(u.id)}
                            className="px-2 py-1 text-xs text-white bg-red-600 hover:bg-red-700 rounded transition"
                          >
                            Confirm
                          </button>
                          <button
                            onClick={() => setUserDeleteConfirm(null)}
                            className="px-2 py-1 text-xs text-gray-600 hover:bg-gray-100 rounded transition"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setUserDeleteConfirm(u.id)}
                          className="px-2 py-1 text-xs text-red-600 hover:bg-red-50 rounded transition"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <p className="text-xs text-gray-400">
              Roles: Admin (full access), Auditor (read + remediation), Viewer (read-only). The last admin cannot be deleted or demoted.
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

      {/* Risk Rule Add/Edit Modal */}
      {ruleModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="fixed inset-0 bg-black/40" onClick={() => setRuleModal(false)} />
          <div className="relative bg-white rounded-xl shadow-2xl border w-full max-w-2xl mx-4 p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="text-lg font-semibold text-gray-900">
              {editingRule ? 'Edit Risk Rule' : 'Add Risk Rule'}
            </div>

            {ruleError && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
                {ruleError}
              </div>
            )}

            {/* Name & Description */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
                <input
                  type="text"
                  value={ruleForm.name}
                  onChange={e => setRuleForm(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="e.g., Guest write access = critical"
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Priority</label>
                <input
                  type="number"
                  value={ruleForm.priority}
                  onChange={e => setRuleForm(prev => ({ ...prev, priority: parseInt(e.target.value) || 100 }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
              <input
                type="text"
                value={ruleForm.description}
                onChange={e => setRuleForm(prev => ({ ...prev, description: e.target.value }))}
                placeholder="Optional description"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            {/* Conditions builder */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Conditions <span className="text-gray-400 font-normal">(ALL must match)</span>
              </label>
              <div className="space-y-2">
                {ruleForm.conditions.map((cond, idx) => {
                  const fieldDef = RULE_FIELDS.find(f => f.value === cond.field);
                  const ops = OPS_FOR_TYPE[fieldDef?.type || 'text'] || OPS_FOR_TYPE.text;
                  return (
                    <div key={idx} className="flex items-center gap-2">
                      {/* Field */}
                      <select
                        value={cond.field}
                        onChange={e => {
                          const newField = RULE_FIELDS.find(f => f.value === e.target.value);
                          const defaultOp = newField?.type === 'boolean' ? 'eq' : newField?.type === 'number' ? 'gt' : newField?.type === 'text' ? 'contains' : 'eq';
                          const defaultVal = newField?.type === 'boolean' ? true : '';
                          updateCondition(idx, { field: e.target.value, op: defaultOp, value: defaultVal });
                        }}
                        className="px-2 py-1.5 border border-gray-300 rounded text-sm bg-white flex-1 min-w-0"
                      >
                        {RULE_FIELDS.map(f => (
                          <option key={f.value} value={f.value}>{f.label}</option>
                        ))}
                      </select>

                      {/* Op */}
                      <select
                        value={cond.op}
                        onChange={e => updateCondition(idx, { op: e.target.value })}
                        className="px-2 py-1.5 border border-gray-300 rounded text-sm bg-white w-20"
                      >
                        {ops.map(o => (
                          <option key={o.value} value={o.value}>{o.label}</option>
                        ))}
                      </select>

                      {/* Value */}
                      {fieldDef?.type === 'boolean' ? (
                        <select
                          value={String(cond.value)}
                          onChange={e => updateCondition(idx, { value: e.target.value === 'true' })}
                          className="px-2 py-1.5 border border-gray-300 rounded text-sm bg-white w-24"
                        >
                          <option value="true">true</option>
                          <option value="false">false</option>
                        </select>
                      ) : fieldDef?.type === 'select' && fieldDef.options ? (
                        <select
                          value={String(cond.value)}
                          onChange={e => updateCondition(idx, { value: e.target.value })}
                          className="px-2 py-1.5 border border-gray-300 rounded text-sm bg-white flex-1 min-w-0"
                        >
                          <option value="">Select...</option>
                          {fieldDef.options.map(o => (
                            <option key={o} value={o}>{o.replace(/_/g, ' ')}</option>
                          ))}
                        </select>
                      ) : fieldDef?.type === 'number' ? (
                        <input
                          type="number"
                          value={String(cond.value)}
                          onChange={e => updateCondition(idx, { value: parseInt(e.target.value) || 0 })}
                          className="px-2 py-1.5 border border-gray-300 rounded text-sm w-24"
                        />
                      ) : (
                        <input
                          type="text"
                          value={String(cond.value)}
                          onChange={e => updateCondition(idx, { value: e.target.value })}
                          placeholder="Value"
                          className="px-2 py-1.5 border border-gray-300 rounded text-sm flex-1 min-w-0"
                        />
                      )}

                      {/* Remove */}
                      {ruleForm.conditions.length > 1 && (
                        <button
                          onClick={() => removeCondition(idx)}
                          className="text-red-400 hover:text-red-600 text-sm px-1"
                        >
                          x
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
              <button
                onClick={addCondition}
                className="mt-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
              >
                + Add Condition
              </button>
            </div>

            {/* Action */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Action</label>
              <div className="flex gap-3 mb-3">
                <button
                  onClick={() => setRuleForm(prev => ({ ...prev, action_type: 'adjust_points' }))}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition ${
                    ruleForm.action_type === 'adjust_points'
                      ? 'bg-blue-600 text-white border-blue-600'
                      : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                  }`}
                >
                  Adjust Points
                </button>
                <button
                  onClick={() => setRuleForm(prev => ({ ...prev, action_type: 'force_level' }))}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition ${
                    ruleForm.action_type === 'force_level'
                      ? 'bg-blue-600 text-white border-blue-600'
                      : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                  }`}
                >
                  Force Risk Level
                </button>
              </div>

              {ruleForm.action_type === 'adjust_points' ? (
                <div className="flex items-center gap-3">
                  <label className="text-sm text-gray-600">Points:</label>
                  <input
                    type="number"
                    value={ruleForm.points_adjustment}
                    onChange={e => setRuleForm(prev => ({ ...prev, points_adjustment: parseInt(e.target.value) || 0 }))}
                    className="w-24 px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500"
                  />
                  <span className="text-xs text-gray-400">Positive = increase risk, negative = decrease</span>
                </div>
              ) : (
                <div className="flex items-center gap-3">
                  <label className="text-sm text-gray-600">Level:</label>
                  <select
                    value={ruleForm.force_level}
                    onChange={e => setRuleForm(prev => ({ ...prev, force_level: e.target.value }))}
                    className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm bg-white"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </div>
              )}
            </div>

            {/* Reason text */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Reason Text <span className="text-gray-400 font-normal">(shown in risk reasons)</span>
              </label>
              <input
                type="text"
                value={ruleForm.reason_text}
                onChange={e => setRuleForm(prev => ({ ...prev, reason_text: e.target.value }))}
                placeholder="e.g., Guest with write access violates policy"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            {/* Preview */}
            <div className="border-t pt-3">
              <button
                onClick={handlePreview}
                disabled={previewing || ruleForm.conditions.length === 0}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition"
              >
                {previewing ? 'Checking...' : 'Preview Affected Identities'}
              </button>
              {previewResult && (
                <div className="mt-2 text-sm">
                  <span className="font-medium text-gray-900">{previewResult.count}</span>
                  <span className="text-gray-500"> {previewResult.count === 1 ? 'identity' : 'identities'} would match</span>
                  {previewResult.identities.length > 0 && (
                    <div className="mt-1 space-y-0.5">
                      {previewResult.identities.slice(0, 5).map((id, i) => (
                        <div key={i} className="text-xs text-gray-500 flex items-center gap-2">
                          <span className={`w-1.5 h-1.5 rounded-full ${
                            id.risk_level === 'critical' ? 'bg-red-500' :
                            id.risk_level === 'high' ? 'bg-orange-500' :
                            id.risk_level === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                          }`} />
                          {id.display_name}
                        </div>
                      ))}
                      {previewResult.count > 5 && (
                        <div className="text-xs text-gray-400">...and {previewResult.count - 5} more</div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setRuleModal(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleRuleSave}
                disabled={ruleSaving || !ruleForm.name || ruleForm.conditions.length === 0}
                className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition ${
                  ruleSaving || !ruleForm.name || ruleForm.conditions.length === 0
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {ruleSaving ? 'Saving...' : editingRule ? 'Update Rule' : 'Create Rule'}
              </button>
            </div>
          </div>
        </div>
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

      {/* User Add/Edit Modal */}
      {userModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="fixed inset-0 bg-black/40" onClick={() => setUserModal(false)} />
          <div className="relative bg-white rounded-xl shadow-2xl border w-full max-w-lg mx-4 p-6 space-y-4">
            <div className="text-lg font-semibold text-gray-900">
              {editingUser ? 'Edit User' : 'Add User'}
            </div>

            {userError && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">{userError}</div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
              <input
                type="text"
                value={userForm.username}
                onChange={e => setUserForm(prev => ({ ...prev, username: e.target.value }))}
                disabled={!!editingUser}
                placeholder="e.g., john.doe"
                className={`w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 ${
                  editingUser ? 'bg-gray-100 text-gray-500' : ''
                }`}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
              <input
                type="text"
                value={userForm.display_name}
                onChange={e => setUserForm(prev => ({ ...prev, display_name: e.target.value }))}
                placeholder="e.g., John Doe"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Password {editingUser && <span className="font-normal text-gray-400">(leave blank to keep current)</span>}
              </label>
              <input
                type="password"
                value={userForm.password}
                onChange={e => setUserForm(prev => ({ ...prev, password: e.target.value }))}
                placeholder={editingUser ? 'Unchanged' : 'Minimum 8 characters'}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
              <div className="flex gap-2">
                {['admin', 'auditor', 'viewer'].map(role => (
                  <button
                    key={role}
                    onClick={() => setUserForm(prev => ({ ...prev, role }))}
                    className={`px-4 py-2 rounded-lg text-sm font-medium border transition ${
                      userForm.role === role
                        ? role === 'admin' ? 'bg-red-600 text-white border-red-600'
                          : role === 'auditor' ? 'bg-blue-600 text-white border-blue-600'
                          : 'bg-gray-600 text-white border-gray-600'
                        : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    {role.charAt(0).toUpperCase() + role.slice(1)}
                  </button>
                ))}
              </div>
              <p className="text-xs text-gray-400 mt-1">
                {userForm.role === 'admin' ? 'Full access: settings, users, discovery, webhooks, rules'
                  : userForm.role === 'auditor' ? 'Read + remediation actions, exports, reports'
                  : 'Read-only: view dashboards, identities, reports'}
              </p>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setUserModal(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleUserSave}
                disabled={userSaving || !userForm.display_name || (!editingUser && (!userForm.username || userForm.password.length < 8))}
                className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition ${
                  userSaving || !userForm.display_name || (!editingUser && (!userForm.username || userForm.password.length < 8))
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {userSaving ? 'Saving...' : editingUser ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
