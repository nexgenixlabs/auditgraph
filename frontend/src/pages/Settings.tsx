import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { getTermLabel, getTermDiscount, ACCOUNT_TIER_LABELS } from '../constants/pricing';

interface CloudProviderConfig {
  enabled: boolean;
  plan: string | null;
}

interface TenantCloudConfig {
  cloud_providers: Record<string, CloudProviderConfig>;
  addons: Record<string, boolean>;
}

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
  notify_weekly_digest: string;
  report_schedule_enabled: string;
  report_schedule_frequency: string;
  report_email_to: string;
  azure_tenant_id: string;
  azure_client_id: string;
  azure_client_secret: string;
  aws_access_key_id: string;
  aws_secret_access_key: string;
  aws_region: string;
  gcp_project_id: string;
  gcp_service_account_json: string;
  timezone: string;
  theme: string;
}

interface StatusData {
  azure_configured: boolean;
  email_configured: boolean;
  scheduler_running: boolean;
  next_run: string | null;
  next_report: string | null;
}

export default function Settings() {
  const { isSuperAdmin, user } = useAuth();
  const location = useLocation();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [status, setStatus] = useState<StatusData | null>(null);

  // Phase 78b: Cloud connections state
  const [cloudConfig, setCloudConfig] = useState<TenantCloudConfig | null>(null);
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionTestResult, setConnectionTestResult] = useState<{ status: 'success' | 'error'; message: string; subscriptions?: { id: string; name: string }[] } | null>(null);
  const cloudSectionRef = useRef<HTMLDivElement>(null);
  const isAdmin = user?.role === 'admin';

  // Scroll to #cloud-connections anchor
  useEffect(() => {
    if (location.hash === '#cloud-connections' && cloudSectionRef.current) {
      setTimeout(() => cloudSectionRef.current?.scrollIntoView({ behavior: 'smooth' }), 300);
    }
  }, [location.hash, loading]);

  // Fetch cloud config
  useEffect(() => {
    fetch('/api/tenant/config')
      .then(r => r.ok ? r.json() : null)
      .then(cfg => {
        if (cfg) setCloudConfig({ cloud_providers: cfg.cloud_providers, addons: cfg.addons });
      })
      .catch(() => {});
  }, []);

  async function handleTestConnection() {
    if (!settings) return;
    setTestingConnection(true);
    setConnectionTestResult(null);
    try {
      const res = await fetch('/api/settings/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          azure_tenant_id: settings.azure_tenant_id,
          azure_client_id: settings.azure_client_id,
          azure_client_secret: settings.azure_client_secret,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setConnectionTestResult({ status: 'error', message: data.error || data.message || 'Connection failed' });
      } else {
        setConnectionTestResult({ status: data.status, message: data.message, subscriptions: data.subscriptions });
      }
    } catch (e: unknown) {
      setConnectionTestResult({ status: 'error', message: e instanceof Error ? e.message : 'Network error' });
    } finally {
      setTestingConnection(false);
    }
  }

  // Phase 45: Tenant info
  const [currentTenant, setCurrentTenant] = useState<any>(null);
  const [tenants, setTenants] = useState<any[]>([]);

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

  // Phase 45: Load tenant data
  useEffect(() => {
    async function loadTenant() {
      try {
        const res = await fetch('/api/tenant');
        if (res.ok) {
          const data = await res.json();
          setCurrentTenant(data.tenant);
        }
      } catch { /* ignore */ }
    }
    loadTenant();
  }, []);

  // Load tenants list for superadmin user modal
  useEffect(() => {
    if (!isSuperAdmin) return;
    fetch('/api/tenants')
      .then(r => r.ok ? r.json() : { tenants: [] })
      .then(d => setTenants(d.tenants || []))
      .catch(() => {});
  }, [isSuperAdmin]);

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

  // Change password state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [pwChanging, setPwChanging] = useState(false);
  const [pwMessage, setPwMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleChangePassword = async () => {
    setPwMessage(null);
    if (!currentPassword) { setPwMessage({ type: 'error', text: 'Enter your current password' }); return; }
    if (newPassword.length < 8) { setPwMessage({ type: 'error', text: 'New password must be at least 8 characters' }); return; }
    if (newPassword !== confirmPassword) { setPwMessage({ type: 'error', text: 'New passwords do not match' }); return; }

    setPwChanging(true);
    try {
      const res = await fetch('/api/auth/password', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to change password');
      setPwMessage({ type: 'success', text: 'Password changed successfully' });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (e: unknown) {
      setPwMessage({ type: 'error', text: e instanceof Error ? e.message : 'Failed to change password' });
    } finally {
      setPwChanging(false);
    }
  };

  // User management state
  interface UserData { id: number; username: string; display_name: string; role: string; enabled: boolean; last_login_at: string | null; created_at: string | null; tenant_id?: number; tenant_name?: string; is_superadmin?: boolean; }
  interface UserFormData { username: string; display_name: string; password: string; role: string; tenant_id?: number; is_superadmin?: boolean; }

  const [users, setUsers] = useState<UserData[]>([]);
  const [userModal, setUserModal] = useState(false);
  const [editingUser, setEditingUser] = useState<UserData | null>(null);
  const [userForm, setUserForm] = useState<UserFormData>({ username: '', display_name: '', password: '', role: 'compliance' });
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
      setUserForm({ username: u.username, display_name: u.display_name, password: '', role: u.role, tenant_id: u.tenant_id, is_superadmin: u.is_superadmin });
    } else {
      setEditingUser(null);
      setUserForm({ username: '', display_name: '', password: '', role: 'compliance', tenant_id: undefined, is_superadmin: false });
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
      // Phase 46: Include tenant fields for superadmins
      if (isSuperAdmin) {
        if (userForm.tenant_id !== undefined) payload.tenant_id = userForm.tenant_id;
        payload.is_superadmin = !!userForm.is_superadmin;
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

  // Compliance framework state
  interface ComplianceFramework {
    id: number;
    key: string;
    name: string;
    description: string | null;
    version: string | null;
    enabled: boolean;
    controls: { id: number; control_id: string; name: string }[];
  }
  const [compFrameworks, setCompFrameworks] = useState<ComplianceFramework[]>([]);
  const [togglingFramework, setTogglingFramework] = useState<number | null>(null);

  const loadComplianceFrameworks = useCallback(async () => {
    try {
      const res = await fetch('/api/compliance/frameworks');
      if (res.ok) {
        const data = await res.json();
        setCompFrameworks(data || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { loadComplianceFrameworks(); }, [loadComplianceFrameworks]);

  async function handleToggleFramework(fw: ComplianceFramework) {
    setTogglingFramework(fw.id);
    try {
      const res = await fetch(`/api/compliance/frameworks/${fw.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !fw.enabled }),
      });
      if (res.ok) {
        loadComplianceFrameworks();
      }
    } catch { /* ignore */ }
    finally { setTogglingFramework(null); }
  }

  // API Key management state
  interface ApiKeyData {
    id: number;
    key_prefix: string;
    name: string;
    description: string | null;
    role: string;
    enabled: boolean;
    created_by: number | null;
    created_by_name: string | null;
    created_at: string | null;
    last_used_at: string | null;
    expires_at: string | null;
    usage_count: number;
  }

  interface ApiKeyFormData {
    name: string;
    description: string;
    role: string;
    expires_at: string;
  }

  const [apiKeys, setApiKeys] = useState<ApiKeyData[]>([]);
  const [apiKeyModal, setApiKeyModal] = useState(false);
  const [editingApiKey, setEditingApiKey] = useState<ApiKeyData | null>(null);
  const [apiKeyForm, setApiKeyForm] = useState<ApiKeyFormData>({
    name: '', description: '', role: 'compliance', expires_at: ''
  });
  const [apiKeySaving, setApiKeySaving] = useState(false);
  const [apiKeyError, setApiKeyError] = useState<string | null>(null);
  const [apiKeyDeleteConfirm, setApiKeyDeleteConfirm] = useState<number | null>(null);
  const [newKeyValue, setNewKeyValue] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  const loadApiKeys = useCallback(async () => {
    try {
      const res = await fetch('/api/api-keys');
      if (res.ok) {
        const data = await res.json();
        setApiKeys(data.api_keys || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { loadApiKeys(); }, [loadApiKeys]);

  function openApiKeyModal(key?: ApiKeyData) {
    if (key) {
      setEditingApiKey(key);
      setApiKeyForm({
        name: key.name,
        description: key.description || '',
        role: key.role,
        expires_at: key.expires_at ? key.expires_at.split('T')[0] : '',
      });
    } else {
      setEditingApiKey(null);
      setApiKeyForm({ name: '', description: '', role: 'compliance', expires_at: '' });
    }
    setApiKeyError(null);
    setNewKeyValue(null);
    setCopiedKey(false);
    setApiKeyModal(true);
  }

  async function handleApiKeySave() {
    setApiKeySaving(true);
    setApiKeyError(null);
    try {
      const method = editingApiKey ? 'PUT' : 'POST';
      const url = editingApiKey ? `/api/api-keys/${editingApiKey.id}` : '/api/api-keys';
      const payload: Record<string, unknown> = {
        name: apiKeyForm.name,
        description: apiKeyForm.description || null,
        role: apiKeyForm.role,
      };
      if (!editingApiKey && apiKeyForm.expires_at) {
        payload.expires_at = apiKeyForm.expires_at;
      }
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');

      if (data.key) {
        setNewKeyValue(data.key);
        loadApiKeys();
      } else {
        setApiKeyModal(false);
        setEditingApiKey(null);
        loadApiKeys();
      }
    } catch (e: unknown) {
      setApiKeyError(e instanceof Error ? e.message : 'Failed to save API key');
    } finally {
      setApiKeySaving(false);
    }
  }

  async function handleApiKeyDelete(id: number) {
    try {
      const res = await fetch(`/api/api-keys/${id}`, { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json();
        setApiKeyError(data.error || 'Delete failed');
        return;
      }
      setApiKeyDeleteConfirm(null);
      loadApiKeys();
    } catch { /* ignore */ }
  }

  async function handleToggleApiKey(key: ApiKeyData) {
    try {
      const res = await fetch(`/api/api-keys/${key.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !key.enabled }),
      });
      if (!res.ok) {
        const data = await res.json();
        setApiKeyError(data.error || 'Toggle failed');
        return;
      }
      loadApiKeys();
    } catch { /* ignore */ }
  }

  function handleCopyKey() {
    if (newKeyValue) {
      navigator.clipboard.writeText(newKeyValue);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  }

  // SOAR Playbook state
  interface SoarPlaybookData {
    id: number;
    name: string;
    description: string | null;
    enabled: boolean;
    trigger_type: string;
    trigger_conditions: Record<string, unknown>;
    action_type: string;
    action_config: Record<string, unknown>;
    integration: string;
    cooldown_minutes: number;
    created_by: string | null;
    created_at: string | null;
    last_triggered_at: string | null;
    trigger_count: number;
  }

  interface SoarFormData {
    name: string;
    description: string;
    trigger_type: string;
    trigger_conditions: string;
    action_type: string;
    action_config: string;
    integration: string;
    cooldown_minutes: number;
  }

  const SOAR_TRIGGER_LABELS: Record<string, string> = {
    anomaly: 'Anomaly Detected',
    risk_escalation: 'Risk Escalation',
    drift: 'Drift Detected',
    new_identity: 'New Identity',
  };

  const SOAR_ACTION_LABELS: Record<string, string> = {
    webhook: 'Webhook',
    create_ticket: 'Create Ticket',
    send_notification: 'In-App Notification',
    tag_for_review: 'Tag for Review',
  };

  const SOAR_INTEGRATION_LABELS: Record<string, string> = {
    slack: 'Slack',
    teams: 'Teams',
    pagerduty: 'PagerDuty',
    servicenow: 'ServiceNow',
    jira: 'Jira',
    custom_webhook: 'Custom Webhook',
    internal: 'Internal',
  };

  const [soarPlaybooks, setSoarPlaybooks] = useState<SoarPlaybookData[]>([]);
  const [soarModal, setSoarModal] = useState(false);
  const [editingSoar, setEditingSoar] = useState<SoarPlaybookData | null>(null);
  const [soarForm, setSoarForm] = useState<SoarFormData>({
    name: '', description: '', trigger_type: 'anomaly', trigger_conditions: '{}',
    action_type: 'send_notification', action_config: '{}', integration: 'internal', cooldown_minutes: 60,
  });
  const [soarSaving, setSoarSaving] = useState(false);
  const [soarError, setSoarError] = useState<string | null>(null);
  const [soarDeleteConfirm, setSoarDeleteConfirm] = useState<number | null>(null);
  const [testingSoarId, setTestingSoarId] = useState<number | null>(null);
  const [soarTestResult, setSoarTestResult] = useState<Record<string, unknown> | null>(null);

  const loadSoarPlaybooks = useCallback(async () => {
    try {
      const res = await fetch('/api/soar/playbooks');
      if (res.ok) {
        const data = await res.json();
        setSoarPlaybooks(data.playbooks || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { loadSoarPlaybooks(); }, [loadSoarPlaybooks]);

  function openSoarModal(pb?: SoarPlaybookData) {
    if (pb) {
      setEditingSoar(pb);
      setSoarForm({
        name: pb.name,
        description: pb.description || '',
        trigger_type: pb.trigger_type,
        trigger_conditions: JSON.stringify(pb.trigger_conditions || {}, null, 2),
        action_type: pb.action_type,
        action_config: JSON.stringify(pb.action_config || {}, null, 2),
        integration: pb.integration,
        cooldown_minutes: pb.cooldown_minutes,
      });
    } else {
      setEditingSoar(null);
      setSoarForm({
        name: '', description: '', trigger_type: 'anomaly', trigger_conditions: '{}',
        action_type: 'send_notification', action_config: '{}', integration: 'internal', cooldown_minutes: 60,
      });
    }
    setSoarError(null);
    setSoarTestResult(null);
    setSoarModal(true);
  }

  async function handleSoarSave() {
    setSoarSaving(true);
    setSoarError(null);
    try {
      let triggerConditions: Record<string, unknown> = {};
      let actionConfig: Record<string, unknown> = {};
      try { triggerConditions = JSON.parse(soarForm.trigger_conditions); } catch { /* ignore */ }
      try { actionConfig = JSON.parse(soarForm.action_config); } catch { /* ignore */ }

      const payload = {
        name: soarForm.name,
        description: soarForm.description || null,
        trigger_type: soarForm.trigger_type,
        trigger_conditions: triggerConditions,
        action_type: soarForm.action_type,
        action_config: actionConfig,
        integration: soarForm.integration,
        cooldown_minutes: soarForm.cooldown_minutes,
      };

      const method = editingSoar ? 'PUT' : 'POST';
      const url = editingSoar ? `/api/soar/playbooks/${editingSoar.id}` : '/api/soar/playbooks';
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      setSoarModal(false);
      setEditingSoar(null);
      loadSoarPlaybooks();
    } catch (e: unknown) {
      setSoarError(e instanceof Error ? e.message : 'Failed to save playbook');
    } finally {
      setSoarSaving(false);
    }
  }

  async function handleSoarDelete(id: number) {
    try {
      await fetch(`/api/soar/playbooks/${id}`, { method: 'DELETE' });
      setSoarDeleteConfirm(null);
      loadSoarPlaybooks();
    } catch { /* ignore */ }
  }

  async function handleToggleSoar(pb: SoarPlaybookData) {
    try {
      await fetch(`/api/soar/playbooks/${pb.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !pb.enabled }),
      });
      loadSoarPlaybooks();
    } catch { /* ignore */ }
  }

  async function handleSoarTest(id: number) {
    setTestingSoarId(id);
    setSoarTestResult(null);
    try {
      const res = await fetch(`/api/soar/playbooks/${id}/test`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setSoarTestResult(data);
      }
    } catch { /* ignore */ }
    finally { setTestingSoarId(null); }
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

  // Phase 54: SSO/SAML state
  const [ssoConfig, setSsoConfig] = useState({
    sso_enabled: 'false',
    sso_idp_entity_id: '',
    sso_idp_sso_url: '',
    sso_idp_slo_url: '',
    sso_idp_x509_cert: '',
    sso_role_mapping: '{}',
    sso_default_role: 'compliance',
    sso_jit_enabled: 'true',
    sso_force_sso: 'false',
  });
  const [ssoSpInfo, setSsoSpInfo] = useState({ sp_entity_id: '', sp_acs_url: '', sp_metadata_url: '' });
  const [ssoRoleMappings, setSsoRoleMappings] = useState<{ group: string; role: string }[]>([]);
  const [ssoSaving, setSsoSaving] = useState(false);
  const [ssoParsing, setSsoParsing] = useState(false);
  const [ssoMetadataUrl, setSsoMetadataUrl] = useState('');
  const [ssoMessage, setSsoMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // SA Governance settings (Phase 63)
  const [saGov, setSaGov] = useState({
    sa_gov_max_credential_age_days: '365',
    sa_gov_attestation_interval_days: '90',
    sa_gov_dormant_threshold_days: '90',
    sa_gov_require_owner: 'true',
  });
  const [saGovSaving, setSaGovSaving] = useState(false);
  const [saGovMsg, setSaGovMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Phase 72: Data Retention
  const [retention, setRetention] = useState({
    retention_enabled: 'false',
    retention_discovery_days: '90',
    retention_drift_days: '90',
    retention_activity_days: '180',
    retention_anomalies_days: '90',
    retention_soar_days: '90',
    retention_notifications_days: '90',
  });
  const [retentionSaving, setRetentionSaving] = useState(false);
  const [retentionMsg, setRetentionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [cleanupRunning, setCleanupRunning] = useState(false);
  const [cleanupResult, setCleanupResult] = useState<{ total: number; deleted: Record<string, number> } | null>(null);
  const [storageStats, setStorageStats] = useState<{
    total_size_mb: number;
    row_counts: Record<string, number>;
    oldest_records: Record<string, string | null>;
  } | null>(null);

  useEffect(() => {
    fetch('/api/settings/sa-governance')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.settings) setSaGov(prev => ({ ...prev, ...data.settings }));
      })
      .catch(() => {});
  }, []);

  // Load retention settings from main settings + storage stats
  useEffect(() => {
    fetch('/api/system/storage')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.retention) {
          setRetention({
            retention_enabled: data.retention.enabled ? 'true' : 'false',
            retention_discovery_days: String(data.retention.discovery_days),
            retention_drift_days: String(data.retention.drift_days),
            retention_activity_days: String(data.retention.activity_days),
            retention_anomalies_days: String(data.retention.anomalies_days),
            retention_soar_days: String(data.retention.soar_days),
            retention_notifications_days: String(data.retention.notifications_days),
          });
        }
        if (data?.storage) {
          setStorageStats({
            total_size_mb: data.storage.total_size_mb,
            row_counts: data.storage.row_counts,
            oldest_records: data.storage.oldest_records,
          });
        }
      })
      .catch(() => {});
  }, []);

  async function handleRetentionSave() {
    setRetentionSaving(true);
    setRetentionMsg(null);
    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(retention),
      });
      if (res.ok) {
        setRetentionMsg({ type: 'success', text: 'Retention policies saved' });
      } else {
        const d = await res.json().catch(() => ({}));
        setRetentionMsg({ type: 'error', text: d.error || 'Save failed' });
      }
    } catch {
      setRetentionMsg({ type: 'error', text: 'Network error' });
    } finally {
      setRetentionSaving(false);
    }
  }

  async function handleManualCleanup() {
    if (!window.confirm('Run data cleanup now? This will permanently delete records older than the configured retention periods.')) return;
    setCleanupRunning(true);
    setCleanupResult(null);
    try {
      const res = await fetch('/api/system/cleanup', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setCleanupResult(data);
        // Refresh storage stats
        fetch('/api/system/storage')
          .then(r => r.ok ? r.json() : null)
          .then(data => {
            if (data?.storage) {
              setStorageStats({
                total_size_mb: data.storage.total_size_mb,
                row_counts: data.storage.row_counts,
                oldest_records: data.storage.oldest_records,
              });
            }
          })
          .catch(() => {});
      }
    } catch {
      // cleanup failed
    } finally {
      setCleanupRunning(false);
    }
  }

  async function handleSaGovSave() {
    setSaGovSaving(true);
    setSaGovMsg(null);
    try {
      const res = await fetch('/api/settings/sa-governance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(saGov),
      });
      if (res.ok) {
        setSaGovMsg({ type: 'success', text: 'SA governance settings saved' });
      } else {
        const d = await res.json().catch(() => ({}));
        setSaGovMsg({ type: 'error', text: d.error || 'Save failed' });
      }
    } catch {
      setSaGovMsg({ type: 'error', text: 'Network error' });
    }
    setSaGovSaving(false);
  }

  useEffect(() => {
    fetch('/api/settings/sso')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!data) return;
        setSsoConfig(prev => ({
          ...prev,
          sso_enabled: data.sso_enabled || 'false',
          sso_idp_entity_id: data.sso_idp_entity_id || '',
          sso_idp_sso_url: data.sso_idp_sso_url || '',
          sso_idp_slo_url: data.sso_idp_slo_url || '',
          sso_idp_x509_cert: data.sso_idp_x509_cert || '',
          sso_role_mapping: data.sso_role_mapping || '{}',
          sso_default_role: data.sso_default_role || 'compliance',
          sso_jit_enabled: data.sso_jit_enabled || 'true',
          sso_force_sso: data.sso_force_sso || 'false',
        }));
        setSsoSpInfo({
          sp_entity_id: data.sp_entity_id || '',
          sp_acs_url: data.sp_acs_url || '',
          sp_metadata_url: data.sp_metadata_url || '',
        });
        try {
          const mapping = JSON.parse(data.sso_role_mapping || '{}');
          setSsoRoleMappings(Object.entries(mapping).map(([group, role]) => ({ group, role: role as string })));
        } catch { /* ignore */ }
      })
      .catch(() => {});
  }, []);

  async function handleSsoParseMetadata() {
    if (!ssoMetadataUrl) return;
    setSsoParsing(true);
    setSsoMessage(null);
    try {
      const res = await fetch('/api/settings/sso/parse-metadata', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ metadata_url: ssoMetadataUrl }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to parse metadata');
      setSsoConfig(prev => ({
        ...prev,
        sso_idp_entity_id: data.idp_entity_id || prev.sso_idp_entity_id,
        sso_idp_sso_url: data.idp_sso_url || prev.sso_idp_sso_url,
        sso_idp_slo_url: data.idp_slo_url || prev.sso_idp_slo_url,
        sso_idp_x509_cert: data.idp_x509_cert || prev.sso_idp_x509_cert,
      }));
      setSsoMessage({ type: 'success', text: 'IdP metadata parsed successfully' });
    } catch (e: any) {
      setSsoMessage({ type: 'error', text: e?.message || 'Failed to parse metadata' });
    } finally {
      setSsoParsing(false);
    }
  }

  async function handleSsoSave() {
    setSsoSaving(true);
    setSsoMessage(null);
    try {
      const mapping: Record<string, string> = {};
      ssoRoleMappings.forEach(m => { if (m.group.trim()) mapping[m.group.trim()] = m.role; });
      const payload = { ...ssoConfig, sso_role_mapping: JSON.stringify(mapping) };
      const res = await fetch('/api/settings/sso', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to save SSO settings');
      setSsoMessage({ type: 'success', text: 'SSO settings saved' });
      setTimeout(() => setSsoMessage(null), 4000);
    } catch (e: any) {
      setSsoMessage({ type: 'error', text: e?.message || 'Failed to save' });
    } finally {
      setSsoSaving(false);
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
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-5">
            <div className="text-lg font-semibold text-gray-900">Organization</div>

            <div className="grid grid-cols-2 gap-6">
              {/* Left: Logo upload */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Organization Logo</label>
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-gray-400 transition">
                  {currentTenant?.settings?.logo_url ? (
                    <img src={String(currentTenant.settings.logo_url)} alt="Logo" className="w-16 h-16 mx-auto mb-2 rounded-lg object-cover" />
                  ) : (
                    <svg className="w-12 h-12 mx-auto text-gray-300 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                    </svg>
                  )}
                  <p className="text-xs text-gray-500">Drag & drop or click to upload</p>
                  <p className="text-[10px] text-gray-400 mt-1">PNG, SVG, or JPG — max 2MB</p>
                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/svg+xml"
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      if (file.size > 2 * 1024 * 1024) { setError('Logo must be under 2MB'); return; }
                      const reader = new FileReader();
                      reader.onload = async () => {
                        try {
                          const tid = currentTenant?.id;
                          if (!tid) { setError('No tenant context'); return; }
                          const res = await fetch(`/api/tenants/${tid}/logo`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ logo: reader.result }),
                          });
                          if (!res.ok) throw new Error('Upload failed');
                          setSuccess('Logo uploaded');
                        } catch { setError('Failed to upload logo'); }
                      };
                      reader.readAsDataURL(file);
                    }}
                    className="hidden"
                    id="logo-upload"
                  />
                  <label htmlFor="logo-upload" className="mt-2 inline-block px-3 py-1.5 bg-gray-100 text-gray-700 text-xs font-medium rounded-lg hover:bg-gray-200 cursor-pointer transition">
                    Choose File
                  </label>
                </div>
              </div>

              {/* Right: Org Name + Timezone + Theme */}
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Organization Name</label>
                  <input
                    type="text"
                    value={settings.org_name}
                    onChange={e => update('org_name', e.target.value)}
                    placeholder="e.g., Acme Corp"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="text-xs text-gray-400 mt-1">Appears on PDF reports and email notifications</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Timezone</label>
                  <select
                    value={settings.timezone || 'UTC'}
                    onChange={e => update('timezone' as keyof SettingsData, e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="UTC">UTC</option>
                    <option value="America/New_York">Eastern (ET)</option>
                    <option value="America/Chicago">Central (CT)</option>
                    <option value="America/Denver">Mountain (MT)</option>
                    <option value="America/Los_Angeles">Pacific (PT)</option>
                    <option value="Europe/London">London (GMT)</option>
                    <option value="Europe/Berlin">Berlin (CET)</option>
                    <option value="Asia/Tokyo">Tokyo (JST)</option>
                    <option value="Asia/Kolkata">India (IST)</option>
                    <option value="Australia/Sydney">Sydney (AEST)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Theme</label>
                  <div className="flex gap-2">
                    {(['light', 'dark', 'system'] as const).map(t => (
                      <button
                        key={t}
                        onClick={() => update('theme' as keyof SettingsData, t)}
                        className={`px-4 py-2 rounded-lg text-sm font-medium border transition capitalize ${
                          settings.theme === t
                            ? 'bg-blue-600 text-white border-blue-600'
                            : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                        }`}
                      >
                        {t}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Subscription Info */}
            {currentTenant && (
              <div className="pt-3 border-t space-y-3">
                <div className="text-sm font-semibold text-gray-800">Subscription</div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="bg-gray-50 rounded-lg p-3">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Plan</div>
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                      (ACCOUNT_TIER_LABELS[currentTenant.plan] || ACCOUNT_TIER_LABELS.free).bg
                    } ${(ACCOUNT_TIER_LABELS[currentTenant.plan] || ACCOUNT_TIER_LABELS.free).color}`}>
                      {(ACCOUNT_TIER_LABELS[currentTenant.plan] || ACCOUNT_TIER_LABELS.free).label}
                    </span>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-3">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Term</div>
                    <div className="text-sm font-semibold text-gray-800">
                      {getTermLabel(currentTenant.subscription_term || 0)}
                      {getTermDiscount(currentTenant.subscription_term || 0) > 0 && (
                        <span className="ml-1 text-[10px] text-green-600 font-semibold">{getTermDiscount(currentTenant.subscription_term || 0) * 100}% off</span>
                      )}
                    </div>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-3">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Activated</div>
                    <div className="text-sm font-semibold text-gray-800">
                      {currentTenant.license_activated_at
                        ? new Date(currentTenant.license_activated_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
                        : '\u2014'}
                    </div>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-3">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Expires</div>
                    <div className={`text-sm font-semibold ${
                      currentTenant.license_expires_at
                        ? (new Date(currentTenant.license_expires_at).getTime() - Date.now()) / 86400000 < 30
                          ? 'text-yellow-600'
                          : (new Date(currentTenant.license_expires_at).getTime() - Date.now()) < 0
                            ? 'text-red-600'
                            : 'text-gray-800'
                        : 'text-gray-400'
                    }`}>
                      {currentTenant.license_expires_at
                        ? new Date(currentTenant.license_expires_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
                        : currentTenant.subscription_term === 0 ? 'Monthly (no expiry)' : '\u2014'}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Section 2: Cloud Connections */}
          <div ref={cloudSectionRef} id="cloud-connections" className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="text-lg font-semibold text-gray-900">Cloud Connections</div>
            <p className="text-xs text-gray-500">Configure cloud provider credentials for identity discovery.</p>

            {!isAdmin ? (
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-sm text-gray-600">
                Contact your tenant administrator to configure cloud credentials.
              </div>
            ) : (
              <div className="space-y-5">
                {/* Azure */}
                {cloudConfig?.cloud_providers?.azure?.enabled ? (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-blue-700">Azure</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-blue-50 text-blue-600 border border-blue-200">
                        {cloudConfig.cloud_providers.azure.plan || 'enabled'}
                      </span>
                      {status?.azure_configured && (
                        <span className="flex items-center gap-1 text-[10px] text-green-600 font-medium">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                          Connected
                        </span>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Azure Tenant ID</label>
                      <input
                        type="text"
                        value={settings?.azure_tenant_id || ''}
                        onChange={e => update('azure_tenant_id' as keyof SettingsData, e.target.value)}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Application (Client) ID</label>
                      <input
                        type="text"
                        value={settings?.azure_client_id || ''}
                        onChange={e => update('azure_client_id' as keyof SettingsData, e.target.value)}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Client Secret</label>
                      <input
                        type="password"
                        value={settings?.azure_client_secret || ''}
                        onChange={e => update('azure_client_secret' as keyof SettingsData, e.target.value)}
                        placeholder="Enter client secret"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                      <p className="text-[10px] text-gray-400 mt-1">Secret is masked after saving. Clear and re-enter to change.</p>
                    </div>

                    <div className="flex items-center gap-3 pt-1">
                      <button
                        onClick={handleTestConnection}
                        disabled={testingConnection || !settings?.azure_tenant_id || !settings?.azure_client_id || !settings?.azure_client_secret}
                        className={`px-4 py-2 text-sm font-medium rounded-lg transition ${
                          testingConnection || !settings?.azure_tenant_id || !settings?.azure_client_id || !settings?.azure_client_secret
                            ? 'bg-gray-200 text-gray-400 cursor-not-allowed'
                            : 'bg-blue-50 text-blue-700 border border-blue-200 hover:bg-blue-100'
                        }`}
                      >
                        {testingConnection ? 'Testing...' : 'Test Connection'}
                      </button>
                      {connectionTestResult && (
                        <span className={`text-sm ${connectionTestResult.status === 'success' ? 'text-green-600' : 'text-red-600'}`}>
                          {connectionTestResult.message}
                        </span>
                      )}
                    </div>

                    {connectionTestResult?.status === 'success' && connectionTestResult.subscriptions && connectionTestResult.subscriptions.length > 0 && (
                      <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                        <div className="text-xs font-semibold text-green-700 mb-1">Discovered Subscriptions</div>
                        <div className="space-y-1">
                          {connectionTestResult.subscriptions.map(sub => (
                            <div key={sub.id} className="text-xs text-green-800 flex items-center gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                              <span className="font-medium">{sub.name}</span>
                              <span className="text-green-600 font-mono text-[10px]">{sub.id}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <p className="text-xs text-gray-400">
                      Credentials are saved with the global &quot;Save Settings&quot; button below.
                    </p>
                  </div>
                ) : (
                  <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 flex items-center gap-3">
                    <div className="text-sm font-medium text-gray-600">Azure</div>
                    <span className="text-xs text-gray-400">Not enabled. Contact your AuditGraph administrator to enable this provider.</span>
                  </div>
                )}

                {/* AWS */}
                {cloudConfig?.cloud_providers?.aws?.enabled ? (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-orange-700">AWS</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-orange-50 text-orange-600 border border-orange-200">
                        {cloudConfig.cloud_providers.aws.plan || 'enabled'}
                      </span>
                      {settings?.aws_access_key_id && (
                        <>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-orange-50 text-orange-600">IAM Access Key</span>
                          <span className="flex items-center gap-1 text-[10px] text-green-600 font-medium">
                            <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                            Configured
                          </span>
                        </>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Access Key ID</label>
                      <input
                        type="text"
                        value={settings?.aws_access_key_id || ''}
                        onChange={e => update('aws_access_key_id' as keyof SettingsData, e.target.value)}
                        placeholder="AKIAIOSFODNN7EXAMPLE"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Secret Access Key</label>
                      <input
                        type="password"
                        value={settings?.aws_secret_access_key || ''}
                        onChange={e => update('aws_secret_access_key' as keyof SettingsData, e.target.value)}
                        placeholder="Enter secret access key"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                      <p className="text-[10px] text-gray-400 mt-1">Secret is masked after saving. Clear and re-enter to change.</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Default Region</label>
                      <select
                        value={settings?.aws_region || 'us-east-1'}
                        onChange={e => update('aws_region' as keyof SettingsData, e.target.value)}
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      >
                        <option value="us-east-1">US East (N. Virginia)</option>
                        <option value="us-east-2">US East (Ohio)</option>
                        <option value="us-west-1">US West (N. California)</option>
                        <option value="us-west-2">US West (Oregon)</option>
                        <option value="eu-west-1">EU (Ireland)</option>
                        <option value="eu-west-2">EU (London)</option>
                        <option value="eu-central-1">EU (Frankfurt)</option>
                        <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                        <option value="ap-southeast-2">Asia Pacific (Sydney)</option>
                        <option value="ap-northeast-1">Asia Pacific (Tokyo)</option>
                      </select>
                    </div>

                    <p className="text-xs text-gray-400">
                      Credentials are saved with the global &quot;Save Settings&quot; button below.
                    </p>
                  </div>
                ) : cloudConfig ? (
                  <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 flex items-center gap-3">
                    <div className="text-sm font-medium text-gray-600">AWS</div>
                    <span className="text-xs text-gray-400">Not enabled. Contact your AuditGraph administrator to enable this provider.</span>
                  </div>
                ) : null}

                {/* GCP */}
                {cloudConfig?.cloud_providers?.gcp?.enabled ? (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-red-600">GCP</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-red-50 text-red-500 border border-red-200">
                        {cloudConfig.cloud_providers.gcp.plan || 'enabled'}
                      </span>
                      {settings?.gcp_project_id && (
                        <>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-50 text-red-600">Service Account</span>
                          <span className="flex items-center gap-1 text-[10px] text-green-600 font-medium">
                            <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                            Configured
                          </span>
                        </>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Project ID</label>
                      <input
                        type="text"
                        value={settings?.gcp_project_id || ''}
                        onChange={e => update('gcp_project_id' as keyof SettingsData, e.target.value)}
                        placeholder="my-project-123456"
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Service Account JSON Key</label>
                      <textarea
                        value={settings?.gcp_service_account_json || ''}
                        onChange={e => update('gcp_service_account_json' as keyof SettingsData, e.target.value)}
                        placeholder='{"type": "service_account", "project_id": "...", ...}'
                        rows={4}
                        className="w-full max-w-lg px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                      <p className="text-[10px] text-gray-400 mt-1">Paste the full JSON key file contents. Stored encrypted.</p>
                    </div>

                    <p className="text-xs text-gray-400">
                      Credentials are saved with the global &quot;Save Settings&quot; button below.
                    </p>
                  </div>
                ) : cloudConfig ? (
                  <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 flex items-center gap-3">
                    <div className="text-sm font-medium text-gray-600">GCP</div>
                    <span className="text-xs text-gray-400">Not enabled. Contact your AuditGraph administrator to enable this provider.</span>
                  </div>
                ) : null}
              </div>
            )}
          </div>

          {/* Section 3: Discovery Schedule */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="text-lg font-semibold text-gray-900">Discovery Schedule</div>

            {/* Status indicators */}
            <div className="flex items-center gap-6 text-sm">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${status?.azure_configured ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-gray-600">
                  Azure: {status?.azure_configured ? 'Connected' : 'Not configured'}
                </span>
                {status?.azure_configured && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-50 text-blue-600">Service Principal</span>
                )}
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
              <button
                onClick={async () => {
                  try {
                    const res = await fetch('/api/runs/trigger', { method: 'POST' });
                    if (res.ok) setSuccess('Scan triggered successfully');
                    else setError('Failed to trigger scan');
                  } catch { setError('Failed to trigger scan'); }
                }}
                className="ml-auto px-3 py-1.5 text-xs font-medium text-blue-600 border border-blue-300 rounded-lg hover:bg-blue-50 transition"
              >
                Scan Now
              </button>
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
                      { key: 'notify_new_identities' as const, label: 'Scan failure alerts', description: 'Alert when a discovery scan fails or encounters errors' },
                      { key: 'notify_removed_identities' as const, label: 'Discovery completion', description: 'Summary notification after each successful scan' },
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

          {/* Change Password */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div>
              <div className="text-lg font-semibold text-gray-900">Change Password</div>
              <p className="text-sm text-gray-500 mt-0.5">Update your account password</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-2xl">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Current Password</label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={e => { setCurrentPassword(e.target.value); setPwMessage(null); }}
                  className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Enter current password"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">New Password</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={e => { setNewPassword(e.target.value); setPwMessage(null); }}
                  className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Min. 8 characters"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Confirm New Password</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={e => { setConfirmPassword(e.target.value); setPwMessage(null); }}
                  className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Repeat new password"
                />
              </div>
            </div>
            {pwMessage && (
              <div className={`text-sm px-3 py-2 rounded-lg ${pwMessage.type === 'success' ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
                {pwMessage.text}
              </div>
            )}
            <button
              onClick={handleChangePassword}
              disabled={pwChanging || !currentPassword || !newPassword || !confirmPassword}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 transition disabled:opacity-50"
            >
              {pwChanging ? 'Changing...' : 'Change Password'}
            </button>
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
                            u.role === 'reader' ? 'bg-blue-50 text-blue-700' :
                            'bg-gray-100 text-gray-600'
                          }`}>
                            {u.role}
                          </span>
                          {!u.enabled && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-50 text-yellow-700">DISABLED</span>
                          )}
                          {isSuperAdmin && u.tenant_name && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-purple-50 text-purple-700">{u.tenant_name}</span>
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
              Roles: Admin (full access), Reader (read-only), Compliance (reports + compliance config). The last admin cannot be deleted or demoted.
            </p>
          </div>

          {/* Section 8: API Keys */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-lg font-semibold text-gray-900">API Keys</div>
                <p className="text-sm text-gray-500 mt-0.5">
                  Manage programmatic access keys for integrations and automations
                </p>
              </div>
              <button
                onClick={() => openApiKeyModal()}
                className="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 transition"
              >
                + Create API Key
              </button>
            </div>

            {apiKeyError && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">
                {apiKeyError}
                <button onClick={() => setApiKeyError(null)} className="ml-2 font-medium underline">Dismiss</button>
              </div>
            )}

            {apiKeys.length === 0 ? (
              <p className="text-sm text-gray-400 py-4 text-center">No API keys configured</p>
            ) : (
              <div className="space-y-2">
                {apiKeys.map(k => (
                  <div key={k.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center text-xs font-bold text-purple-600">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                            d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-900 flex items-center gap-2">
                          {k.name}
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase ${
                            k.role === 'admin' ? 'bg-red-50 text-red-700' :
                            k.role === 'reader' ? 'bg-blue-50 text-blue-700' :
                            'bg-gray-100 text-gray-600'
                          }`}>
                            {k.role}
                          </span>
                          {!k.enabled && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-50 text-yellow-700">DISABLED</span>
                          )}
                        </div>
                        <div className="text-xs text-gray-500">
                          <span className="font-mono">{k.key_prefix}{'****'}</span>
                          {' '}&middot; {k.usage_count} request{k.usage_count !== 1 ? 's' : ''}
                          {k.last_used_at && <> &middot; Last used {new Date(k.last_used_at).toLocaleDateString()}</>}
                          {k.expires_at && <> &middot; Expires {new Date(k.expires_at).toLocaleDateString()}</>}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleToggleApiKey(k)}
                        className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                          k.enabled ? 'bg-green-500' : 'bg-gray-300'
                        }`}
                        title={k.enabled ? 'Disable key' : 'Enable key'}
                      >
                        <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                          k.enabled ? 'translate-x-4' : 'translate-x-0.5'
                        }`} />
                      </button>
                      <button
                        onClick={() => openApiKeyModal(k)}
                        className="px-2 py-1 text-xs text-blue-600 hover:bg-blue-50 rounded transition"
                      >
                        Edit
                      </button>
                      {apiKeyDeleteConfirm === k.id ? (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => handleApiKeyDelete(k.id)}
                            className="px-2 py-1 text-xs text-white bg-red-600 hover:bg-red-700 rounded transition"
                          >
                            Confirm
                          </button>
                          <button
                            onClick={() => setApiKeyDeleteConfirm(null)}
                            className="px-2 py-1 text-xs text-gray-600 hover:bg-gray-100 rounded transition"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setApiKeyDeleteConfirm(k.id)}
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
              API keys authenticate requests via <code className="bg-gray-100 px-1 rounded">X-API-Key</code> header or Bearer token with <code className="bg-gray-100 px-1 rounded">ag_</code> prefix.
              Keys inherit the assigned role's permissions.
            </p>
          </div>

          {/* Section 9: SSO/SAML Configuration (Phase 54) */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-lg font-semibold text-gray-900">SSO / SAML</div>
                <p className="text-sm text-gray-500 mt-0.5">Configure SAML 2.0 Single Sign-On with your identity provider</p>
              </div>
              <button
                onClick={() => setSsoConfig(prev => ({ ...prev, sso_enabled: prev.sso_enabled === 'true' ? 'false' : 'true' }))}
                className={`relative inline-flex h-5 w-9 items-center rounded-full transition ${ssoConfig.sso_enabled === 'true' ? 'bg-blue-600' : 'bg-gray-300'}`}
              >
                <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition ${ssoConfig.sso_enabled === 'true' ? 'translate-x-[18px]' : 'translate-x-[3px]'}`} />
              </button>
            </div>

            {ssoMessage && (
              <div className={`p-3 rounded-lg text-sm ${ssoMessage.type === 'success' ? 'bg-green-50 border border-green-200 text-green-700' : 'bg-red-50 border border-red-200 text-red-700'}`}>
                {ssoMessage.text}
              </div>
            )}

            {/* IdP Metadata URL shortcut */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">IdP Metadata URL</label>
              <div className="flex gap-2">
                <input
                  value={ssoMetadataUrl}
                  onChange={e => setSsoMetadataUrl(e.target.value)}
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm"
                  placeholder="https://login.microsoftonline.com/.../federationmetadata/2007-06/federationmetadata.xml"
                />
                <button
                  onClick={handleSsoParseMetadata}
                  disabled={ssoParsing || !ssoMetadataUrl}
                  className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-40 transition whitespace-nowrap"
                >
                  {ssoParsing ? 'Parsing...' : 'Fetch & Parse'}
                </button>
              </div>
              <p className="text-[10px] text-gray-400 mt-1">Auto-fills the fields below from your IdP's metadata endpoint</p>
            </div>

            {/* Manual IdP config fields */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">IdP Entity ID</label>
                <input
                  value={ssoConfig.sso_idp_entity_id}
                  onChange={e => setSsoConfig(prev => ({ ...prev, sso_idp_entity_id: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                  placeholder="https://sts.windows.net/..."
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">SSO URL</label>
                <input
                  value={ssoConfig.sso_idp_sso_url}
                  onChange={e => setSsoConfig(prev => ({ ...prev, sso_idp_sso_url: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                  placeholder="https://login.microsoftonline.com/.../saml2"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">SLO URL (Optional)</label>
                <input
                  value={ssoConfig.sso_idp_slo_url}
                  onChange={e => setSsoConfig(prev => ({ ...prev, sso_idp_slo_url: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                  placeholder="https://login.microsoftonline.com/.../saml2"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Default Role</label>
                <select
                  value={ssoConfig.sso_default_role}
                  onChange={e => setSsoConfig(prev => ({ ...prev, sso_default_role: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                >
                  <option value="compliance">Compliance</option>
                  <option value="reader">Reader</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">X.509 Certificate (PEM)</label>
              <textarea
                value={ssoConfig.sso_idp_x509_cert}
                onChange={e => setSsoConfig(prev => ({ ...prev, sso_idp_x509_cert: e.target.value }))}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-xs font-mono"
                placeholder="MIIDpDCCA..."
              />
            </div>

            {/* SP Information (read-only) */}
            {ssoSpInfo.sp_entity_id && (
              <div className="bg-gray-50 rounded-lg p-3 space-y-1">
                <div className="text-xs font-semibold text-gray-700 mb-1">Service Provider Information (copy to your IdP)</div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-gray-500 w-24">Entity ID:</span>
                  <code className="text-gray-800 bg-white px-2 py-0.5 rounded border text-[11px] flex-1">{ssoSpInfo.sp_entity_id}</code>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-gray-500 w-24">ACS URL:</span>
                  <code className="text-gray-800 bg-white px-2 py-0.5 rounded border text-[11px] flex-1">{ssoSpInfo.sp_acs_url}</code>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-gray-500 w-24">Metadata:</span>
                  <code className="text-gray-800 bg-white px-2 py-0.5 rounded border text-[11px] flex-1">{ssoSpInfo.sp_metadata_url}</code>
                </div>
              </div>
            )}

            {/* Role Mapping */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-medium text-gray-600">Role Mapping (IdP Group → AuditGraph Role)</label>
                <button
                  onClick={() => setSsoRoleMappings(prev => [...prev, { group: '', role: 'compliance' }])}
                  className="text-xs text-blue-600 hover:underline"
                >
                  + Add Mapping
                </button>
              </div>
              {ssoRoleMappings.length === 0 && (
                <p className="text-xs text-gray-400 py-2">No role mappings configured. All SSO users will get the default role.</p>
              )}
              {ssoRoleMappings.map((m, i) => (
                <div key={i} className="flex items-center gap-2 mb-1.5">
                  <input
                    value={m.group}
                    onChange={e => {
                      const updated = [...ssoRoleMappings];
                      updated[i] = { ...m, group: e.target.value };
                      setSsoRoleMappings(updated);
                    }}
                    className="flex-1 px-3 py-1.5 border border-gray-300 rounded-lg text-sm"
                    placeholder="IdP Group Name"
                  />
                  <span className="text-xs text-gray-400">→</span>
                  <select
                    value={m.role}
                    onChange={e => {
                      const updated = [...ssoRoleMappings];
                      updated[i] = { ...m, role: e.target.value };
                      setSsoRoleMappings(updated);
                    }}
                    className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm"
                  >
                    <option value="compliance">Compliance</option>
                    <option value="reader">Reader</option>
                    <option value="admin">Admin</option>
                  </select>
                  <button
                    onClick={() => setSsoRoleMappings(prev => prev.filter((_, j) => j !== i))}
                    className="text-red-400 hover:text-red-600 text-xs px-1"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>

            {/* Toggle options */}
            <div className="flex items-center gap-6">
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <button
                  onClick={() => setSsoConfig(prev => ({ ...prev, sso_jit_enabled: prev.sso_jit_enabled === 'true' ? 'false' : 'true' }))}
                  className={`relative inline-flex h-4 w-7 items-center rounded-full transition ${ssoConfig.sso_jit_enabled === 'true' ? 'bg-blue-600' : 'bg-gray-300'}`}
                >
                  <span className={`inline-block h-3 w-3 rounded-full bg-white transition ${ssoConfig.sso_jit_enabled === 'true' ? 'translate-x-[14px]' : 'translate-x-[2px]'}`} />
                </button>
                JIT User Provisioning
              </label>
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <button
                  onClick={() => setSsoConfig(prev => ({ ...prev, sso_force_sso: prev.sso_force_sso === 'true' ? 'false' : 'true' }))}
                  className={`relative inline-flex h-4 w-7 items-center rounded-full transition ${ssoConfig.sso_force_sso === 'true' ? 'bg-red-600' : 'bg-gray-300'}`}
                >
                  <span className={`inline-block h-3 w-3 rounded-full bg-white transition ${ssoConfig.sso_force_sso === 'true' ? 'translate-x-[14px]' : 'translate-x-[2px]'}`} />
                </button>
                Force SSO (disable local login)
              </label>
            </div>
            {ssoConfig.sso_force_sso === 'true' && (
              <p className="text-xs text-red-500">Warning: Enabling Force SSO will prevent local credential login for all non-superadmin users in this tenant.</p>
            )}

            <button
              onClick={handleSsoSave}
              disabled={ssoSaving}
              className="px-6 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-40 transition"
            >
              {ssoSaving ? 'Saving...' : 'Save SSO Settings'}
            </button>
          </div>

          {/* Section 10: Compliance Frameworks */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div>
              <div className="text-lg font-semibold text-gray-900">Compliance Frameworks</div>
              <p className="text-sm text-gray-500 mt-0.5">
                Enable or disable compliance frameworks evaluated against your identity posture
              </p>
            </div>

            {compFrameworks.length === 0 ? (
              <div className="text-sm text-gray-400 text-center py-6 border border-dashed rounded-lg">
                No compliance frameworks found. They will be seeded on backend startup.
              </div>
            ) : (
              <div className="space-y-2">
                {compFrameworks.map(fw => (
                  <div key={fw.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <button
                        onClick={() => handleToggleFramework(fw)}
                        disabled={togglingFramework === fw.id}
                        className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0 ${
                          fw.enabled ? 'bg-green-500' : 'bg-gray-300'
                        }`}
                      >
                        <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                          fw.enabled ? 'translate-x-4' : 'translate-x-0.5'
                        }`} />
                      </button>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-gray-900 flex items-center gap-2">
                          {fw.name}
                          {fw.version && (
                            <span className="px-1.5 py-0.5 bg-gray-100 text-gray-500 text-[10px] font-medium rounded">
                              {fw.version}
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-gray-500">
                          {fw.controls?.length || 0} controls
                          {fw.description && <> &middot; {fw.description.slice(0, 80)}{fw.description.length > 80 ? '...' : ''}</>}
                        </div>
                      </div>
                    </div>
                    <span className={`text-xs font-medium px-2 py-0.5 rounded ${
                      fw.enabled ? 'bg-green-50 text-green-700' : 'bg-gray-100 text-gray-500'
                    }`}>
                      {fw.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </div>
                ))}
              </div>
            )}

            <p className="text-xs text-gray-400">
              Disabled frameworks are excluded from the compliance dashboard and gap analysis. Controls are evaluated on each API call using current identity posture data.
            </p>
          </div>

          {/* Section 10: SOAR Playbooks */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-lg font-semibold text-gray-900">SOAR Playbooks</div>
                <p className="text-sm text-gray-500 mt-0.5">
                  Automated response playbooks triggered by security events
                </p>
              </div>
              <button
                onClick={() => openSoarModal()}
                disabled={soarPlaybooks.length >= 20}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
                  soarPlaybooks.length >= 20
                    ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                    : 'bg-blue-600 text-white hover:bg-blue-700'
                }`}
              >
                + Add Playbook
              </button>
            </div>

            {soarPlaybooks.length === 0 ? (
              <div className="text-sm text-gray-400 text-center py-6 border border-dashed rounded-lg">
                No SOAR playbooks configured. Add one to automate security responses.
              </div>
            ) : (
              <div className="space-y-3">
                {soarPlaybooks.map(pb => (
                  <div key={pb.id} className="border rounded-lg px-4 py-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3 min-w-0 flex-1">
                        <button
                          onClick={() => handleToggleSoar(pb)}
                          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0 ${
                            pb.enabled ? 'bg-green-500' : 'bg-gray-300'
                          }`}
                        >
                          <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                            pb.enabled ? 'translate-x-4' : 'translate-x-0.5'
                          }`} />
                        </button>
                        <div className="min-w-0 flex-1">
                          <div className="text-sm font-medium text-gray-900 truncate">{pb.name}</div>
                          {pb.description && (
                            <div className="text-xs text-gray-400 truncate">{pb.description}</div>
                          )}
                        </div>
                      </div>

                      <div className="hidden sm:flex items-center gap-1.5 mx-3 flex-shrink-0">
                        <span className="px-1.5 py-0.5 bg-amber-50 text-amber-700 text-[10px] font-medium rounded">
                          {SOAR_TRIGGER_LABELS[pb.trigger_type] || pb.trigger_type}
                        </span>
                        <span className="text-gray-300 text-[10px]">&rarr;</span>
                        <span className="px-1.5 py-0.5 bg-blue-50 text-blue-700 text-[10px] font-medium rounded">
                          {SOAR_ACTION_LABELS[pb.action_type] || pb.action_type}
                        </span>
                        <span className="px-1.5 py-0.5 bg-gray-100 text-gray-600 text-[10px] font-medium rounded">
                          {SOAR_INTEGRATION_LABELS[pb.integration] || pb.integration}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 flex-shrink-0">
                        <span className="text-xs text-gray-400">
                          {pb.trigger_count}x
                          {pb.last_triggered_at && (
                            <> &middot; {new Date(pb.last_triggered_at).toLocaleDateString()}</>
                          )}
                        </span>
                        <button
                          onClick={() => handleSoarTest(pb.id)}
                          disabled={testingSoarId === pb.id}
                          className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded transition"
                        >
                          {testingSoarId === pb.id ? 'Testing...' : 'Test'}
                        </button>
                        <button
                          onClick={() => openSoarModal(pb)}
                          className="px-2 py-1 text-xs font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded transition"
                        >
                          Edit
                        </button>
                        {soarDeleteConfirm === pb.id ? (
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => handleSoarDelete(pb.id)}
                              className="px-2 py-1 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded transition"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => setSoarDeleteConfirm(null)}
                              className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded transition"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setSoarDeleteConfirm(pb.id)}
                            className="px-2 py-1 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded transition"
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Test result inline */}
                    {soarTestResult && (soarTestResult as Record<string, unknown>).playbook_id === pb.id && (
                      <div className="mt-2 p-2 bg-gray-50 rounded border text-xs">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`w-2 h-2 rounded-full ${(soarTestResult as Record<string, unknown>).would_match ? 'bg-green-500' : 'bg-yellow-500'}`} />
                          <span className="font-medium text-gray-700">
                            {(soarTestResult as Record<string, unknown>).would_match ? 'Would trigger' : 'Would NOT trigger'}
                          </span>
                          {!(soarTestResult as Record<string, unknown>).cooldown_ok && (
                            <span className="text-orange-600">(cooldown active)</span>
                          )}
                        </div>
                        <div className="text-gray-500">{(soarTestResult as Record<string, unknown>).summary as string}</div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            <p className="text-xs text-gray-400">
              Maximum 20 playbooks. Playbooks are evaluated automatically after discovery runs detect anomalies, drift, or risk changes.
              Cooldown prevents duplicate actions.
            </p>
          </div>

          {/* Section 11: Service Account Governance (Phase 63) */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div>
              <div className="text-lg font-semibold text-gray-900">Service Account Governance</div>
              <p className="text-sm text-gray-500 mt-0.5">
                Configure governance policies for non-human identities (service principals, managed identities).
              </p>
            </div>

            {saGovMsg && (
              <div className={`rounded-lg p-3 text-sm ${saGovMsg.type === 'success' ? 'bg-green-50 border border-green-200 text-green-700' : 'bg-red-50 border border-red-200 text-red-700'}`}>
                {saGovMsg.text}
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Max Credential Age (days)</label>
                <input
                  type="number"
                  min={1}
                  max={3650}
                  value={saGov.sa_gov_max_credential_age_days}
                  onChange={e => setSaGov(prev => ({ ...prev, sa_gov_max_credential_age_days: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                <p className="text-xs text-gray-400 mt-1">Credentials older than this are flagged</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Attestation Interval (days)</label>
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={saGov.sa_gov_attestation_interval_days}
                  onChange={e => setSaGov(prev => ({ ...prev, sa_gov_attestation_interval_days: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                <p className="text-xs text-gray-400 mt-1">How often owners must re-attest</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Dormant Threshold (days)</label>
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={saGov.sa_gov_dormant_threshold_days}
                  onChange={e => setSaGov(prev => ({ ...prev, sa_gov_dormant_threshold_days: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                <p className="text-xs text-gray-400 mt-1">No sign-in within this = dormant</p>
              </div>
            </div>

            <div className="flex items-center justify-between max-w-xs">
              <label className="text-sm font-medium text-gray-700">Require Owner</label>
              <button
                type="button"
                onClick={() => setSaGov(prev => ({ ...prev, sa_gov_require_owner: prev.sa_gov_require_owner === 'true' ? 'false' : 'true' }))}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  saGov.sa_gov_require_owner === 'true' ? 'bg-blue-600' : 'bg-gray-300'
                }`}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  saGov.sa_gov_require_owner === 'true' ? 'translate-x-6' : 'translate-x-1'
                }`} />
              </button>
            </div>
            <p className="text-xs text-gray-400 -mt-2">Unowned service accounts flagged as non-compliant</p>

            <button
              onClick={handleSaGovSave}
              disabled={saGovSaving}
              className={`px-4 py-2 rounded-lg text-sm font-medium text-white transition ${
                saGovSaving ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
              }`}
            >
              {saGovSaving ? 'Saving...' : 'Save Governance Policy'}
            </button>
          </div>

          {/* Section 12: Data Retention (Phase 72) */}
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <div>
              <div className="text-lg font-semibold text-gray-900">Data Retention</div>
              <p className="text-sm text-gray-500 mt-0.5">
                Configure how long historical data is kept. A daily cleanup job runs at 03:00 UTC.
              </p>
            </div>

            {retentionMsg && (
              <div className={`rounded-lg p-3 text-sm ${retentionMsg.type === 'success' ? 'bg-green-50 border border-green-200 text-green-700' : 'bg-red-50 border border-red-200 text-red-700'}`}>
                {retentionMsg.text}
              </div>
            )}

            {/* Enable toggle */}
            <div className="flex items-center justify-between">
              <div>
                <span className="text-sm font-medium text-gray-700">Enable Automatic Cleanup</span>
                <p className="text-xs text-gray-400">When enabled, old data is automatically deleted on schedule</p>
              </div>
              <button
                type="button"
                onClick={() => setRetention(prev => ({ ...prev, retention_enabled: prev.retention_enabled === 'true' ? 'false' : 'true' }))}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  retention.retention_enabled === 'true' ? 'bg-blue-600' : 'bg-gray-300'
                }`}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  retention.retention_enabled === 'true' ? 'translate-x-6' : 'translate-x-1'
                }`} />
              </button>
            </div>

            {/* Retention periods */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Discovery Runs (days)</label>
                <input
                  type="number" min={7} max={3650}
                  value={retention.retention_discovery_days}
                  onChange={e => setRetention(prev => ({ ...prev, retention_discovery_days: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                {storageStats && <p className="text-xs text-gray-400 mt-1">{storageStats.row_counts?.discovery_runs ?? 0} runs stored</p>}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Drift Reports (days)</label>
                <input
                  type="number" min={7} max={3650}
                  value={retention.retention_drift_days}
                  onChange={e => setRetention(prev => ({ ...prev, retention_drift_days: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                {storageStats && <p className="text-xs text-gray-400 mt-1">{storageStats.row_counts?.drift_reports ?? 0} reports stored</p>}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Activity Log (days)</label>
                <input
                  type="number" min={7} max={3650}
                  value={retention.retention_activity_days}
                  onChange={e => setRetention(prev => ({ ...prev, retention_activity_days: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                {storageStats && <p className="text-xs text-gray-400 mt-1">{storageStats.row_counts?.activity_log ?? 0} entries stored</p>}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Anomalies (days)</label>
                <input
                  type="number" min={7} max={3650}
                  value={retention.retention_anomalies_days}
                  onChange={e => setRetention(prev => ({ ...prev, retention_anomalies_days: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                <p className="text-xs text-gray-400 mt-1">Only resolved anomalies are cleaned</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">SOAR Actions (days)</label>
                <input
                  type="number" min={7} max={3650}
                  value={retention.retention_soar_days}
                  onChange={e => setRetention(prev => ({ ...prev, retention_soar_days: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                {storageStats && <p className="text-xs text-gray-400 mt-1">{storageStats.row_counts?.soar_actions ?? 0} actions stored</p>}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Notifications (days)</label>
                <input
                  type="number" min={7} max={3650}
                  value={retention.retention_notifications_days}
                  onChange={e => setRetention(prev => ({ ...prev, retention_notifications_days: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                {storageStats && <p className="text-xs text-gray-400 mt-1">{storageStats.row_counts?.notifications ?? 0} notifications stored</p>}
              </div>
            </div>

            {/* Storage summary */}
            {storageStats && (
              <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-700">Database Size</span>
                  <span className="text-sm font-bold text-gray-900">{storageStats.total_size_mb} MB</span>
                </div>
                {Object.entries(storageStats.oldest_records).some(([, v]) => v) && (
                  <div className="mt-2 text-xs text-gray-500 space-y-0.5">
                    {Object.entries(storageStats.oldest_records).map(([table, oldest]) => oldest && (
                      <div key={table} className="flex justify-between">
                        <span>{table.replace(/_/g, ' ')}</span>
                        <span>oldest: {new Date(oldest).toLocaleDateString()}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Cleanup result */}
            {cleanupResult && (
              <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                <p className="text-sm font-medium text-green-700">Cleanup complete: {cleanupResult.total} records deleted</p>
                {cleanupResult.total > 0 && (
                  <div className="mt-1 text-xs text-green-600 space-y-0.5">
                    {Object.entries(cleanupResult.deleted).map(([table, count]) => count > 0 && (
                      <div key={table}>{table.replace(/_/g, ' ')}: {count}</div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="flex items-center gap-3">
              <button
                onClick={handleRetentionSave}
                disabled={retentionSaving}
                className={`px-4 py-2 rounded-lg text-sm font-medium text-white transition ${
                  retentionSaving ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {retentionSaving ? 'Saving...' : 'Save Retention Policy'}
              </button>
              <button
                onClick={handleManualCleanup}
                disabled={cleanupRunning}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition border ${
                  cleanupRunning ? 'bg-gray-100 text-gray-400 border-gray-200 cursor-not-allowed' : 'bg-white text-red-600 border-red-200 hover:bg-red-50'
                }`}
              >
                {cleanupRunning ? 'Cleaning...' : 'Run Cleanup Now'}
              </button>
            </div>
          </div>

          {/* Section 13: Integrations (Phase 83) */}
          <IntegrationsSection />

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
                {['admin', 'reader', 'compliance'].map(role => (
                  <button
                    key={role}
                    onClick={() => setUserForm(prev => ({ ...prev, role }))}
                    className={`px-4 py-2 rounded-lg text-sm font-medium border transition ${
                      userForm.role === role
                        ? role === 'admin' ? 'bg-red-600 text-white border-red-600'
                          : role === 'reader' ? 'bg-blue-600 text-white border-blue-600'
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
                  : userForm.role === 'reader' ? 'Read + remediation actions, exports, reports'
                  : 'Read-only: view dashboards, identities, reports'}
              </p>
            </div>

            {/* Phase 46: Tenant + Superadmin fields (superadmin only) */}
            {isSuperAdmin && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Tenant</label>
                  <select
                    value={userForm.tenant_id || ''}
                    onChange={e => setUserForm(prev => ({ ...prev, tenant_id: e.target.value ? Number(e.target.value) : undefined }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="">-- Select Tenant --</option>
                    {tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </select>
                </div>
                <div className="flex items-end">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={!!userForm.is_superadmin}
                      onChange={e => setUserForm(prev => ({ ...prev, is_superadmin: e.target.checked }))}
                      className="w-4 h-4 text-amber-600 border-gray-300 rounded focus:ring-amber-500"
                    />
                    <span className="text-sm font-medium text-gray-700">Superadmin</span>
                  </label>
                </div>
              </div>
            )}

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

      {/* API Key Create/Edit Modal */}
      {apiKeyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="fixed inset-0 bg-black/40" onClick={() => { setApiKeyModal(false); setNewKeyValue(null); }} />
          <div className="relative bg-white rounded-xl shadow-2xl border w-full max-w-lg mx-4 p-6 space-y-4">
            {newKeyValue ? (
              <>
                <div className="text-lg font-semibold text-gray-900">API Key Created</div>
                <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-sm text-amber-800">
                  Copy this key now. It will not be shown again.
                </div>
                <div className="bg-gray-50 border rounded-lg p-3 font-mono text-sm break-all select-all">
                  {newKeyValue}
                </div>
                <div className="flex items-center justify-end gap-3 pt-2">
                  <button
                    onClick={handleCopyKey}
                    className="px-4 py-2 text-sm font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg transition"
                  >
                    {copiedKey ? 'Copied!' : 'Copy to Clipboard'}
                  </button>
                  <button
                    onClick={() => { setApiKeyModal(false); setNewKeyValue(null); }}
                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition"
                  >
                    Done
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="text-lg font-semibold text-gray-900">
                  {editingApiKey ? 'Edit API Key' : 'Create API Key'}
                </div>
                {apiKeyError && (
                  <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">{apiKeyError}</div>
                )}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
                  <input
                    type="text"
                    value={apiKeyForm.name}
                    onChange={e => setApiKeyForm(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="e.g., CI/CD Pipeline Key"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                  <input
                    type="text"
                    value={apiKeyForm.description}
                    onChange={e => setApiKeyForm(prev => ({ ...prev, description: e.target.value }))}
                    placeholder="Optional description"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
                  <div className="flex gap-2">
                    {['admin', 'reader', 'compliance'].map(role => (
                      <button
                        key={role}
                        onClick={() => setApiKeyForm(prev => ({ ...prev, role }))}
                        className={`px-4 py-2 rounded-lg text-sm font-medium border transition ${
                          apiKeyForm.role === role
                            ? role === 'admin' ? 'bg-red-600 text-white border-red-600'
                              : role === 'reader' ? 'bg-blue-600 text-white border-blue-600'
                              : 'bg-gray-600 text-white border-gray-600'
                            : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                        }`}
                      >
                        {role.charAt(0).toUpperCase() + role.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>
                {!editingApiKey && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Expiration <span className="font-normal text-gray-400">(optional)</span>
                    </label>
                    <input
                      type="date"
                      value={apiKeyForm.expires_at}
                      onChange={e => setApiKeyForm(prev => ({ ...prev, expires_at: e.target.value }))}
                      className="w-full max-w-xs px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    />
                    <p className="text-xs text-gray-400 mt-1">Leave blank for a non-expiring key</p>
                  </div>
                )}
                <div className="flex items-center justify-end gap-3 pt-2">
                  <button
                    onClick={() => setApiKeyModal(false)}
                    className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleApiKeySave}
                    disabled={apiKeySaving || !apiKeyForm.name}
                    className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition ${
                      apiKeySaving || !apiKeyForm.name ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
                    }`}
                  >
                    {apiKeySaving ? 'Saving...' : editingApiKey ? 'Update' : 'Create'}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* SOAR Playbook Create/Edit Modal */}
      {soarModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="fixed inset-0 bg-black/40" onClick={() => setSoarModal(false)} />
          <div className="relative bg-white rounded-xl shadow-2xl border w-full max-w-lg mx-4 p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="text-lg font-semibold text-gray-900">
              {editingSoar ? 'Edit SOAR Playbook' : 'Add SOAR Playbook'}
            </div>
            {soarError && (
              <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg p-2">{soarError}</div>
            )}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
              <input
                type="text"
                value={soarForm.name}
                onChange={e => setSoarForm(prev => ({ ...prev, name: e.target.value }))}
                placeholder="e.g. Critical Anomaly Slack Alert"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
              <input
                type="text"
                value={soarForm.description}
                onChange={e => setSoarForm(prev => ({ ...prev, description: e.target.value }))}
                placeholder="Optional description"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Trigger Type</label>
                <select
                  value={soarForm.trigger_type}
                  onChange={e => setSoarForm(prev => ({ ...prev, trigger_type: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                >
                  {Object.entries(SOAR_TRIGGER_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>{v}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Action Type</label>
                <select
                  value={soarForm.action_type}
                  onChange={e => setSoarForm(prev => ({ ...prev, action_type: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                >
                  {Object.entries(SOAR_ACTION_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>{v}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Integration</label>
                <select
                  value={soarForm.integration}
                  onChange={e => setSoarForm(prev => ({ ...prev, integration: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                >
                  {Object.entries(SOAR_INTEGRATION_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>{v}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Cooldown (minutes)</label>
                <input
                  type="number"
                  min={1}
                  max={1440}
                  value={soarForm.cooldown_minutes}
                  onChange={e => setSoarForm(prev => ({ ...prev, cooldown_minutes: parseInt(e.target.value) || 60 }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Trigger Conditions <span className="font-normal text-gray-400">(JSON)</span>
              </label>
              <textarea
                value={soarForm.trigger_conditions}
                onChange={e => setSoarForm(prev => ({ ...prev, trigger_conditions: e.target.value }))}
                rows={3}
                placeholder='{"severity": "critical"}'
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <p className="text-[10px] text-gray-400 mt-0.5">All conditions must match the event. Empty = match all events of this trigger type.</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Action Config <span className="font-normal text-gray-400">(JSON)</span>
              </label>
              <textarea
                value={soarForm.action_config}
                onChange={e => setSoarForm(prev => ({ ...prev, action_config: e.target.value }))}
                rows={3}
                placeholder='{"url": "https://hooks.slack.com/..."}'
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <p className="text-[10px] text-gray-400 mt-0.5">Webhook: url. Ticket: base_url, project_key, api_token. Notification/Tag: no config needed.</p>
            </div>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setSoarModal(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleSoarSave}
                disabled={soarSaving || !soarForm.name}
                className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition ${
                  soarSaving || !soarForm.name ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {soarSaving ? 'Saving...' : editingSoar ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══ Phase 83: Integrations Section ═══ */

const INTEGRATION_EVENTS = [
  { key: 'critical_risk', label: 'Critical Risk Detected' },
  { key: 'anomaly_detected', label: 'Anomaly Detected' },
  { key: 'drift_detected', label: 'Drift Detected' },
  { key: 'scan_complete', label: 'Scan Complete' },
  { key: 'scan_failed', label: 'Scan Failed' },
  { key: 'credential_expiring', label: 'Credential Expiring' },
];

function IntegrationsSection() {
  const [slackUrl, setSlackUrl] = useState('');
  const [teamsUrl, setTeamsUrl] = useState('');
  const [slackEvents, setSlackEvents] = useState<string[]>([]);
  const [teamsEvents, setTeamsEvents] = useState<string[]>([]);
  const [slackConfigured, setSlackConfigured] = useState(false);
  const [teamsConfigured, setTeamsConfigured] = useState(false);
  const [showSlackUrl, setShowSlackUrl] = useState(false);
  const [showTeamsUrl, setShowTeamsUrl] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState<{ platform: string; success: boolean; message: string } | null>(null);
  const [testing, setTesting] = useState('');

  useEffect(() => {
    fetch('/api/settings/integrations')
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d) {
          setSlackConfigured(d.slack?.configured || false);
          setTeamsConfigured(d.teams?.configured || false);
          setSlackEvents(d.slack?.events || []);
          setTeamsEvents(d.teams?.events || []);
        }
      })
      .catch(() => {});
  }, []);

  async function handleSave(platform: 'slack' | 'teams') {
    setSaving(true);
    try {
      const body: any = {};
      if (platform === 'slack') {
        if (slackUrl) body.slack_webhook_url = slackUrl;
        body.slack_events = slackEvents;
      } else {
        if (teamsUrl) body.teams_webhook_url = teamsUrl;
        body.teams_events = teamsEvents;
      }
      const res = await fetch('/api/settings/integrations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        if (platform === 'slack' && slackUrl) setSlackConfigured(true);
        if (platform === 'teams' && teamsUrl) setTeamsConfigured(true);
      }
    } catch { /* ignore */ }
    setSaving(false);
  }

  async function handleTest(platform: 'slack' | 'teams') {
    const url = platform === 'slack' ? slackUrl : teamsUrl;
    if (!url) {
      setTestResult({ platform, success: false, message: 'Enter a webhook URL first' });
      return;
    }
    setTesting(platform);
    setTestResult(null);
    try {
      const res = await fetch('/api/settings/integrations/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ platform, webhook_url: url }),
      });
      const data = await res.json();
      setTestResult({ platform, success: data.success, message: data.message });
    } catch (e: any) {
      setTestResult({ platform, success: false, message: e?.message || 'Test failed' });
    }
    setTesting('');
  }

  function toggleEvent(platform: 'slack' | 'teams', eventKey: string) {
    if (platform === 'slack') {
      setSlackEvents(prev => prev.includes(eventKey) ? prev.filter(e => e !== eventKey) : [...prev, eventKey]);
    } else {
      setTeamsEvents(prev => prev.includes(eventKey) ? prev.filter(e => e !== eventKey) : [...prev, eventKey]);
    }
  }

  function renderCard(platform: 'slack' | 'teams') {
    const isSlack = platform === 'slack';
    const url = isSlack ? slackUrl : teamsUrl;
    const setUrl = isSlack ? setSlackUrl : setTeamsUrl;
    const configured = isSlack ? slackConfigured : teamsConfigured;
    const showUrl = isSlack ? showSlackUrl : showTeamsUrl;
    const setShowUrl = isSlack ? setShowSlackUrl : setShowTeamsUrl;
    const events = isSlack ? slackEvents : teamsEvents;
    const brandColor = isSlack ? 'purple' : 'blue';

    return (
      <div className="border rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className={`w-8 h-8 rounded-lg bg-${brandColor}-100 flex items-center justify-center`}>
              <span className={`text-${brandColor}-700 text-sm font-bold`}>{isSlack ? 'S' : 'T'}</span>
            </div>
            <div>
              <div className="text-sm font-semibold text-gray-900">{isSlack ? 'Slack' : 'Microsoft Teams'}</div>
              <div className={`text-[10px] ${configured ? 'text-green-600' : 'text-gray-400'}`}>
                {configured ? 'Connected' : 'Not configured'}
              </div>
            </div>
          </div>
          {configured && (
            <span className="w-2 h-2 rounded-full bg-green-500" />
          )}
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Webhook URL</label>
          <div className="relative">
            <input
              type={showUrl ? 'text' : 'password'}
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder={`${isSlack ? 'https://hooks.slack.com/services/...' : 'https://outlook.office.com/webhook/...'}`}
              className="w-full px-3 py-2 pr-16 border border-gray-300 rounded-lg text-xs focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <button
              onClick={() => setShowUrl(!showUrl)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-gray-400 hover:text-gray-600"
            >
              {showUrl ? 'Hide' : 'Show'}
            </button>
          </div>
        </div>

        {/* Event toggles */}
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-2">Event Notifications</label>
          <div className="grid grid-cols-2 gap-1.5">
            {INTEGRATION_EVENTS.map(ev => (
              <label key={ev.key} className="flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer hover:bg-gray-50">
                <input
                  type="checkbox"
                  checked={events.includes(ev.key)}
                  onChange={() => toggleEvent(platform, ev.key)}
                  className="w-3.5 h-3.5 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-[11px] text-gray-700">{ev.label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Test result */}
        {testResult && testResult.platform === platform && (
          <div className={`rounded-lg px-3 py-2 text-xs ${testResult.success ? 'bg-green-50 text-green-700 border border-green-200' : 'bg-red-50 text-red-700 border border-red-200'}`}>
            {testResult.message}
          </div>
        )}

        <div className="flex items-center gap-2">
          <button
            onClick={() => handleTest(platform)}
            disabled={testing === platform}
            className="px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-50 transition disabled:opacity-50"
          >
            {testing === platform ? 'Testing...' : 'Test Connection'}
          </button>
          <button
            onClick={() => handleSave(platform)}
            disabled={saving}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition disabled:opacity-50"
          >
            {saving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
      <div className="flex items-center gap-3">
        <svg className="w-5 h-5 text-gray-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        <div>
          <div className="text-lg font-semibold text-gray-900">Integrations</div>
          <p className="text-xs text-gray-500">Push security notifications to Slack and Microsoft Teams</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {renderCard('slack')}
        {renderCard('teams')}
      </div>
    </div>
  );
}
