import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { GeneralTab } from '../components/settings/GeneralTab';
import { ConnectionsTab } from '../components/settings/ConnectionsTab';
import { NotificationsTab } from '../components/settings/NotificationsTab';
import { ScoringTab } from '../components/settings/ScoringTab';
import { UsersTab } from '../components/settings/UsersTab';
import { SecurityTab } from '../components/settings/SecurityTab';
import { ComplianceSettingsTab } from '../components/settings/ComplianceSettingsTab';
import { GovernanceTab } from '../components/settings/GovernanceTab';
import { AdvancedTab } from '../components/settings/AdvancedTab';
import { IntegrationsTab } from '../components/settings/IntegrationsTab';
import type { CloudConnection } from '../components/settings/types';

interface CloudProviderConfig {
  enabled: boolean;
  plan: string | null;
}

interface OrgCloudConfig {
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
  discovery_completed: 'Snapshot Completed',
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
  azure_directory_id: string;
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

// ─── Ticketing Integration Component ───────────────────────────

const TICKETING_PROVIDERS = [
  { key: 'jira', label: 'Jira', icon: '🟦', desc: 'Atlassian Jira Cloud or Server',
    fields: [
      { name: 'cloud_url', label: 'Cloud URL', placeholder: 'acme.atlassian.net', type: 'text' },
      { name: 'api_token', label: 'API Token', placeholder: 'Your Jira API token', type: 'password' },
      { name: 'project_key', label: 'Project Key', placeholder: 'SECOPS', type: 'text' },
      { name: 'issue_type', label: 'Issue Type', placeholder: 'Task', type: 'select', options: ['Task', 'Bug', 'Story'] },
    ],
  },
  { key: 'servicenow', label: 'ServiceNow', icon: '🟩', desc: 'ServiceNow ITSM',
    fields: [
      { name: 'instance_url', label: 'Instance URL', placeholder: 'acme.service-now.com', type: 'text' },
      { name: 'client_id', label: 'Client ID', placeholder: 'OAuth Client ID', type: 'text' },
      { name: 'client_secret', label: 'Client Secret', placeholder: 'OAuth Client Secret', type: 'password' },
      { name: 'assignment_group', label: 'Assignment Group', placeholder: 'Security Ops', type: 'text' },
    ],
  },
  { key: 'azure_devops', label: 'Azure DevOps', icon: '🔷', desc: 'Azure DevOps Work Items',
    fields: [
      { name: 'org_url', label: 'Organization URL', placeholder: 'dev.azure.com/acme', type: 'text' },
      { name: 'pat', label: 'Personal Access Token', placeholder: 'Your PAT', type: 'password' },
      { name: 'project_name', label: 'Project Name', placeholder: 'SecurityOps', type: 'text' },
      { name: 'work_item_type', label: 'Work Item Type', placeholder: 'Task', type: 'select', options: ['Task', 'Bug', 'Issue'] },
    ],
  },
] as const;

function TicketingSection({ ticketingRef }: { ticketingRef: React.RefObject<HTMLDivElement | null> }) {
  const [configuring, setConfiguring] = useState<string | null>(null);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);

  const provider = TICKETING_PROVIDERS.find(p => p.key === configuring);

  function handleConnect(key: string) {
    setConfiguring(key);
    setFormData({});
    setSaved(null);
  }

  function handleSave() {
    setSaving(true);
    // Simulate save — backend integration can be added later
    setTimeout(() => {
      setSaving(false);
      setSaved(configuring);
      setConfiguring(null);
    }, 800);
  }

  return (
    <div ref={ticketingRef} id="ticketing" className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
      <div className="flex items-center gap-3">
        <span className="text-xl">🎫</span>
        <div>
          <div className="text-lg font-semibold text-gray-900">Ticketing</div>
          <p className="text-xs text-gray-500">Connect your ITSM platform to create remediation tickets directly from the dashboard. <span className="text-amber-600 font-medium">(Preview — integration coming soon)</span></p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {TICKETING_PROVIDERS.map(t => (
          <div key={t.key} className={`border rounded-lg p-4 text-center transition ${
            saved === t.key ? 'border-green-300 bg-green-50' : 'border-gray-200 hover:border-blue-300 hover:shadow-sm'
          }`}>
            <div className="text-2xl mb-2">{t.icon}</div>
            <div className="font-semibold text-sm text-gray-900">{t.label}</div>
            <p className="text-xs text-gray-500 mt-1 mb-3">{t.desc}</p>
            {saved === t.key ? (
              <span className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-green-700 bg-green-100 rounded-lg">
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                Connected
              </span>
            ) : (
              <button
                onClick={() => handleConnect(t.key)}
                className="px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-50 transition"
              >
                Connect
              </button>
            )}
          </div>
        ))}
      </div>

      {/* Configuration Panel */}
      {configuring && provider && (
        <div className="border border-blue-200 rounded-lg bg-blue-50/30 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold text-gray-900">Configure {provider.label}</div>
            <button onClick={() => setConfiguring(null)} className="text-gray-400 hover:text-gray-600 text-xs">Cancel</button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {provider.fields.map(f => (
              <div key={f.name}>
                <label className="block text-xs font-medium text-gray-700 mb-1">{f.label}</label>
                {f.type === 'select' ? (
                  <select
                    value={formData[f.name] || ''}
                    onChange={e => setFormData(prev => ({ ...prev, [f.name]: e.target.value }))}
                    className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="">Select...</option>
                    {f.options?.map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                ) : (
                  <input
                    type={f.type === 'password' ? 'password' : 'text'}
                    value={formData[f.name] || ''}
                    onChange={e => setFormData(prev => ({ ...prev, [f.name]: e.target.value }))}
                    placeholder={f.placeholder}
                    className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                )}
              </div>
            ))}
          </div>
          <div className="flex items-center gap-3 pt-2">
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save & Connect'}
            </button>
            <button
              onClick={() => setConfiguring(null)}
              className="px-4 py-2 text-xs font-medium rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-50 transition"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <p className="text-xs text-gray-400">
        Configured ticketing enables the "Create Ticket" button on remediation cards across the CISO Dashboard.
      </p>
    </div>
  );
}

const SETTINGS_TABS = [
  { key: 'general', label: 'General' },
  { key: 'users', label: 'Users' },
  { key: 'connections', label: 'Connections' },
  { key: 'notifications', label: 'Notifications' },
  { key: 'security', label: 'Security' },
  { key: 'compliance', label: 'Compliance' },
  { key: 'scoring', label: 'Scoring' },
  { key: 'governance', label: 'Governance' },
  { key: 'integrations', label: 'Integrations' },
  { key: 'advanced', label: 'Advanced' },
] as const;

type SettingsTab = typeof SETTINGS_TABS[number]['key'];

export default function Settings() {
  const { isSuperAdmin, user } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  const activeTab: SettingsTab = (SETTINGS_TABS.some(t => t.key === urlTab) ? urlTab : 'general') as SettingsTab;
  const ticketingRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [status, setStatus] = useState<StatusData | null>(null);

  // Phase 78b: Cloud connections state
  const [cloudConfig, setCloudConfig] = useState<OrgCloudConfig | null>(null);
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionTestResult, setConnectionTestResult] = useState<{ status: 'success' | 'error'; message: string; subscriptions?: { id: string; name: string }[] } | null>(null);
  const [maskCredentials, setMaskCredentials] = useState(true);
  const cloudSectionRef = useRef<HTMLDivElement>(null);
  const isAdmin = user?.role === 'admin';

  // Cloud connections (multi-directory)
  const [cloudConnections, setCloudConnections] = useState<CloudConnection[]>([]);
  const [showAddWizard, setShowAddWizard] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [wizardCloud, setWizardCloud] = useState('azure');
  const [wizardLabel, setWizardLabel] = useState('');
  const [wizardAzureDirectoryId, setWizardAzureDirectoryId] = useState('');
  const [wizardClientId, setWizardClientId] = useState('');
  const [wizardClientSecret, setWizardClientSecret] = useState('');
  const [wizardRegion, setWizardRegion] = useState('us-east-1');
  const [wizardTesting, setWizardTesting] = useState(false);
  const [wizardTestResult, setWizardTestResult] = useState<{ status: string; message: string; subscriptions?: { id: string; name: string }[] } | null>(null);
  const [wizardSaving, setWizardSaving] = useState(false);
  const [scanningConnId, setScanningConnId] = useState<number | null>(null);

  // Phase 3: Active snapshot jobs per connection
  const [activeJobs, setActiveJobs] = useState<Record<number, any>>({});

  // Phase 85: Organization onboarding stage
  const [orgStage, setOrgStage] = useState<string>('active');
  const [primaryCloud, setPrimaryCloud] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);
  const [addingCloud, setAddingCloud] = useState(false);

  // Hash scroll: when navigating to /settings/integrations#ticketing, scroll to ticketing section
  useEffect(() => {
    if (location.hash === '#ticketing' && activeTab === 'integrations') {
      setTimeout(() => ticketingRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200);
    }
  }, [activeTab, location.hash]);

  useEffect(() => {
    if (user?.is_superadmin) return;
    fetch('/api/organization/stage')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.stage) setOrgStage(data.stage);
        if (data?.primary_cloud) setPrimaryCloud(data.primary_cloud);
      })
      .catch(() => {});
  }, [user]);

  // Fetch cloud connections
  function fetchConnections() {
    fetch('/api/client/connections')
      .then(r => r.ok ? r.json() : { connections: [] })
      .then(d => setCloudConnections(d.connections || []))
      .catch(() => {});
  }
  useEffect(() => { fetchConnections(); }, []);

  // Phase 3: Poll active snapshot jobs for connections
  useEffect(() => {
    const connIds = Object.keys(activeJobs).map(Number);
    if (connIds.length === 0) return;

    const poll = async () => {
      const next: Record<number, any> = {};
      for (const cid of connIds) {
        try {
          const r = await fetch(`/api/discovery/jobs/${cid}`);
          if (r.ok) {
            const d = await r.json();
            if (d.active_job) {
              next[cid] = d.active_job;
            }
            // If no active_job, job completed — don't add to next, refresh connections
          }
        } catch { /* ignore */ }
      }
      setActiveJobs(next);
      // If any jobs disappeared (completed), refresh connections list
      if (Object.keys(next).length < connIds.length) {
        fetchConnections();
      }
    };

    const interval = setInterval(poll, 3000);
    return () => clearInterval(interval);
  }, [Object.keys(activeJobs).join(',')]);

  async function handleWizardTest() {
    setWizardTesting(true);
    setWizardTestResult(null);
    try {
      const res = await fetch('/api/client/connections/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(wizardCloud === 'aws'
          ? { cloud: 'aws', access_key_id: wizardClientId, secret_access_key: wizardClientSecret, region: wizardRegion }
          : { cloud: wizardCloud, azure_directory_id: wizardAzureDirectoryId, client_id: wizardClientId, client_secret: wizardClientSecret }),
      });
      const data = await res.json();
      setWizardTestResult(data);
      if (data.status === 'success') setWizardStep(3);
    } catch {
      setWizardTestResult({ status: 'error', message: 'Network error' });
    } finally {
      setWizardTesting(false);
    }
  }

  async function handleWizardSave() {
    setWizardSaving(true);
    try {
      const res = await fetch('/api/client/connections', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(wizardCloud === 'aws'
          ? {
              cloud: 'aws', label: wizardLabel, client_id: wizardClientId,
              client_secret: wizardClientSecret, connection_type: 'iam', status: 'connected',
              metadata: { access_key_id: wizardClientId, secret_access_key: wizardClientSecret, region: wizardRegion },
            }
          : {
              cloud: wizardCloud, label: wizardLabel, azure_directory_id: wizardAzureDirectoryId,
              client_id: wizardClientId, client_secret: wizardClientSecret,
              connection_type: 'entra', status: 'connected',
            }),
      });
      if (res.ok) {
        const data = await res.json();
        const discovered = data?.connection?.discovered_count || 0;
        fetchConnections();
        setShowAddWizard(false);
        resetWizard();
        if (discovered > 0) {
          setSuccess(`Connection added! ${discovered} subscription(s) discovered — go to Subscriptions to activate.`);
        } else {
          setSuccess('Connection added successfully');
        }
        setTimeout(() => setSuccess(null), 5000);
      } else {
        const err = await res.json().catch(() => ({}));
        setError(err.error || 'Failed to save connection');
      }
    } catch {
      setError('Failed to save connection');
    } finally {
      setWizardSaving(false);
    }
  }

  function resetWizard() {
    setWizardStep(0);
    setWizardCloud('azure');
    setWizardLabel('');
    setWizardAzureDirectoryId('');
    setWizardClientId('');
    setWizardClientSecret('');
    setWizardRegion('us-east-1');
    setWizardTestResult(null);
  }

  async function handleDeleteConnection(connId: number) {
    if (!window.confirm('Delete this connection?')) return;
    try {
      await fetch(`/api/client/connections/${connId}`, { method: 'DELETE' });
      fetchConnections();
    } catch { /* ignore */ }
  }

  async function handleRunScan(connId: number) {
    setScanningConnId(connId);
    try {
      const res = await fetch('/api/runs/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ connection_id: connId }),
      });
      if (res.ok) {
        setSuccess('Snapshot capture started for this connection.');
        // Seed activeJobs so polling starts immediately
        setActiveJobs(prev => ({ ...prev, [connId]: { status: 'queued', stage: null, progress: 0 } }));
      } else if (res.status === 409) {
        setError('A scan is already in progress for this connection.');
      } else {
        setError('Failed to trigger snapshot');
      }
    } catch {
      setError('Failed to trigger snapshot');
    } finally {
      setScanningConnId(null);
    }
  }

  async function handleUpdateDiscoverySettings(connId: number, enabled: boolean, intervalMinutes: number) {
    try {
      const res = await fetch(`/api/discovery/settings/${connId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ discovery_enabled: enabled, discovery_interval_minutes: intervalMinutes }),
      });
      if (res.ok) {
        fetchConnections();
        setSuccess(enabled ? 'Continuous discovery enabled.' : 'Continuous discovery disabled.');
      } else {
        setError('Failed to update discovery settings');
      }
    } catch {
      setError('Failed to update discovery settings');
    }
  }

  async function handleSaveAndUnlock() {
    if (!settings) return;
    setUnlocking(true);
    setError(null);
    try {
      // 1. Save settings
      const saveRes = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      });
      if (!saveRes.ok) {
        const data = await saveRes.json();
        throw new Error(data.error || 'Save failed');
      }
      // 2. Test connection
      const testRes = await fetch('/api/settings/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          azure_directory_id: settings.azure_directory_id,
          azure_client_id: settings.azure_client_id,
          azure_client_secret: settings.azure_client_secret,
        }),
      });
      const testData = await testRes.json();
      if (!testRes.ok || testData.status !== 'success') {
        throw new Error(testData.error || testData.message || 'Connection test failed. Please check your credentials.');
      }
      // 3. Update stage to active
      await fetch('/api/organization/stage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stage: 'active' }),
      });
      // 4. Auto-activate all discovered subscriptions
      try {
        await fetch('/api/subscriptions/activate-all', { method: 'POST' });
      } catch { /* ignore */ }
      // 5. Trigger first snapshot
      try {
        await fetch('/api/runs/trigger', { method: 'POST' });
      } catch { /* ignore */ }
      // 6. Navigate to subscriptions so user sees activated subs + pricing
      navigate('/subscriptions');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to save and unlock');
    } finally {
      setUnlocking(false);
    }
  }

  // Scroll to #cloud-connections anchor
  useEffect(() => {
    if (location.hash === '#cloud-connections' && cloudSectionRef.current) {
      setTimeout(() => cloudSectionRef.current?.scrollIntoView({ behavior: 'smooth' }), 300);
    }
  }, [location.hash, loading]);

  // Fetch cloud config
  useEffect(() => {
    fetch('/api/organization/config')
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
          azure_directory_id: settings.azure_directory_id,
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

  // Phase 45: Organization info
  const [currentOrg, setCurrentOrg] = useState<any>(null);
  const [orgs, setOrgs] = useState<any[]>([]);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const res = await fetch('/api/settings');
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        const data = await res.json();
        setSettings(data.settings as SettingsData);
        setStatus(data.status);
        // Populate P2 telemetry state
        const s = data.settings as any;
        if (s) {
          setP2Telemetry(prev => ({
            ...prev,
            p2_telemetry_enabled: s.p2_telemetry_enabled || 'false',
            retention_signin_events_days: s.retention_signin_events_days || '90',
            retention_workload_anomalies_days: s.retention_workload_anomalies_days || '180',
          }));
        }
      } catch (e: any) {
        setError(e?.message || 'Failed to load settings');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  // Phase 45: Load organization data
  useEffect(() => {
    async function loadOrg() {
      try {
        const res = await fetch('/api/organization');
        if (res.ok) {
          const data = await res.json();
          setCurrentOrg(data.organization);
        }
      } catch { /* ignore */ }
    }
    loadOrg();
  }, []);

  // Load organizations list for superadmin user modal
  useEffect(() => {
    if (!isSuperAdmin) return;
    fetch('/api/clients')
      .then(r => r.ok ? r.json() : { organizations: [] })
      .then(d => setOrgs(d.organizations || []))
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
  interface UserData { id: number; username: string; display_name: string; role: string; enabled: boolean; last_login_at: string | null; created_at: string | null; organization_id?: number; org_name?: string; is_superadmin?: boolean; }
  interface UserFormData { username: string; display_name: string; password: string; role: string; organization_id?: number; is_superadmin?: boolean; }

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
      setUserForm({ username: u.username, display_name: u.display_name, password: '', role: u.role, organization_id: u.organization_id, is_superadmin: u.is_superadmin });
    } else {
      setEditingUser(null);
      setUserForm({ username: '', display_name: '', password: '', role: 'compliance', organization_id: undefined, is_superadmin: false });
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
      // Phase 46: Include organization fields for superadmins
      if (isSuperAdmin) {
        if (userForm.organization_id !== undefined) payload.organization_id = userForm.organization_id;
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
    tier?: string;
    category?: string;
    short_name?: string;
    identity_controls_count?: number;
    total_framework_controls?: number;
    scope_label?: string;
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

  // P2 Telemetry
  const [p2Telemetry, setP2Telemetry] = useState({
    p2_telemetry_enabled: 'false',
    retention_signin_events_days: '90',
    retention_workload_anomalies_days: '180',
  });
  const [p2Saving, setP2Saving] = useState(false);
  const [p2Msg, setP2Msg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

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

  async function handleP2TelemetrySave() {
    setP2Saving(true);
    setP2Msg(null);
    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(p2Telemetry),
      });
      if (res.ok) {
        setP2Msg({ type: 'success', text: 'P2 Telemetry settings saved' });
      } else {
        const d = await res.json().catch(() => ({}));
        setP2Msg({ type: 'error', text: d.error || 'Save failed' });
      }
    } catch {
      setP2Msg({ type: 'error', text: 'Network error' });
    } finally {
      setP2Saving(false);
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
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-48" />
          <div className="h-48 bg-gray-100 rounded-xl" />
          <div className="h-48 bg-gray-100 rounded-xl" />
          <div className="h-48 bg-gray-100 rounded-xl" />
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-4">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Settings</h2>
        <p className="text-sm text-gray-600 mt-1">
          Configure organization, connections, and integrations
        </p>
      </div>

      {/* Tab Bar */}
      <div className="border-b border-gray-200 -mx-4 sm:-mx-6 lg:-mx-8 px-4 sm:px-6 lg:px-8">
        <nav className="flex gap-0 overflow-x-auto" aria-label="Settings tabs">
          {SETTINGS_TABS.map(t => (
            <button
              key={t.key}
              onClick={() => navigate(`/settings/${t.key}`, { replace: true })}
              className={`whitespace-nowrap px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                activeTab === t.key
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Phase 85: Locked stage banner */}
      {orgStage === 'locked' && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-center gap-3">
          <svg className="w-5 h-5 text-amber-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <div>
            <div className="text-sm font-semibold text-amber-800">Complete Cloud Setup</div>
            <p className="text-xs text-amber-700">
              Enter your cloud provider credentials below, test the connection, then click "Save &amp; Capture First Snapshot" to unlock your dashboard.
            </p>
          </div>
        </div>
      )}

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
          {/* ═══ GENERAL TAB ═══ */}
          {activeTab === 'general' && (
            <GeneralTab
              settings={settings}
              update={update}
              currentOrg={currentOrg}
              setError={setError}
              setSuccess={setSuccess}
              currentPassword={currentPassword}
              setCurrentPassword={setCurrentPassword}
              newPassword={newPassword}
              setNewPassword={setNewPassword}
              confirmPassword={confirmPassword}
              setConfirmPassword={setConfirmPassword}
              pwChanging={pwChanging}
              pwMessage={pwMessage}
              setPwMessage={setPwMessage}
              handleChangePassword={handleChangePassword}
            />
          )}

          {/* ═══ CONNECTIONS TAB ═══ */}
          {activeTab === 'connections' && (
            <ConnectionsTab
              settings={settings}
              status={status}
              cloudConfig={cloudConfig}
              cloudConnections={cloudConnections}
              isAdmin={isAdmin}
              orgStage={orgStage}
              primaryCloud={primaryCloud}
              addingCloud={addingCloud}
              setAddingCloud={setAddingCloud}
              maskCredentials={maskCredentials}
              setMaskCredentials={setMaskCredentials}
              showAddWizard={showAddWizard}
              setShowAddWizard={setShowAddWizard}
              wizardStep={wizardStep}
              setWizardStep={setWizardStep}
              wizardCloud={wizardCloud}
              setWizardCloud={setWizardCloud}
              wizardLabel={wizardLabel}
              setWizardLabel={setWizardLabel}
              wizardAzureDirectoryId={wizardAzureDirectoryId}
              setWizardAzureDirectoryId={setWizardAzureDirectoryId}
              wizardClientId={wizardClientId}
              setWizardClientId={setWizardClientId}
              wizardClientSecret={wizardClientSecret}
              setWizardClientSecret={setWizardClientSecret}
              wizardRegion={wizardRegion}
              setWizardRegion={setWizardRegion}
              wizardTesting={wizardTesting}
              wizardTestResult={wizardTestResult}
              wizardSaving={wizardSaving}
              scanningConnId={scanningConnId}
              activeJobs={activeJobs}
              connectionTestResult={connectionTestResult}
              testingConnection={testingConnection}
              unlocking={unlocking}
              handleWizardTest={handleWizardTest}
              handleWizardSave={handleWizardSave}
              resetWizard={resetWizard}
              handleDeleteConnection={handleDeleteConnection}
              handleRunScan={handleRunScan}
              handleUpdateDiscoverySettings={handleUpdateDiscoverySettings}
              handleTestConnection={handleTestConnection}
              handleSaveAndUnlock={handleSaveAndUnlock}
              update={update}
              setError={setError}
              setSuccess={setSuccess}
              cloudSectionRef={cloudSectionRef}
            />
          )}

          {/* ═══ NOTIFICATIONS TAB ═══ */}
          {activeTab === 'notifications' && (
            <NotificationsTab
              settings={settings}
              status={status}
              update={update}
              toggleBool={toggleBool}
              testingEmail={testingEmail}
              testResult={testResult}
              handleTestEmail={handleTestEmail}
              webhooks={webhooks}
              openWebhookModal={openWebhookModal}
              handleToggleWebhook={handleToggleWebhook}
              handleWebhookTest={handleWebhookTest}
              handleWebhookDelete={handleWebhookDelete}
              loadDeliveries={loadDeliveries}
              testingWebhookId={testingWebhookId}
              expandedDeliveries={expandedDeliveries}
              deliveries={deliveries}
              deleteConfirm={deleteConfirm}
              setDeleteConfirm={setDeleteConfirm}
              WEBHOOK_EVENT_LABELS={WEBHOOK_EVENT_LABELS}
            />
          )}

          {/* ═══ SCORING TAB ═══ */}
          {activeTab === 'scoring' && (
            <ScoringTab
              riskRules={riskRules}
              openRuleModal={openRuleModal}
              handleToggleRule={handleToggleRule}
              ruleDeleteConfirm={ruleDeleteConfirm}
              setRuleDeleteConfirm={setRuleDeleteConfirm}
              handleRuleDelete={handleRuleDelete}
            />
          )}

          {/* ═══ USERS TAB ═══ */}
          {activeTab === 'users' && (
            <UsersTab
              users={users}
              userError={userError}
              setUserError={setUserError}
              openUserModal={openUserModal}
              handleToggleUser={handleToggleUser}
              userDeleteConfirm={userDeleteConfirm}
              setUserDeleteConfirm={setUserDeleteConfirm}
              handleUserDelete={handleUserDelete}
              isSuperAdmin={isSuperAdmin}
            />
          )}

          {/* ═══ SECURITY TAB ═══ */}
          {activeTab === 'security' && (
            <SecurityTab
              apiKeys={apiKeys}
              apiKeyError={apiKeyError}
              setApiKeyError={setApiKeyError}
              openApiKeyModal={openApiKeyModal}
              handleToggleApiKey={handleToggleApiKey}
              apiKeyDeleteConfirm={apiKeyDeleteConfirm}
              setApiKeyDeleteConfirm={setApiKeyDeleteConfirm}
              handleApiKeyDelete={handleApiKeyDelete}
              ssoConfig={ssoConfig}
              setSsoConfig={setSsoConfig}
              ssoMessage={ssoMessage}
              ssoMetadataUrl={ssoMetadataUrl}
              setSsoMetadataUrl={setSsoMetadataUrl}
              ssoParsing={ssoParsing}
              ssoSaving={ssoSaving}
              ssoSpInfo={ssoSpInfo}
              ssoRoleMappings={ssoRoleMappings}
              setSsoRoleMappings={setSsoRoleMappings}
              handleSsoParseMetadata={handleSsoParseMetadata}
              handleSsoSave={handleSsoSave}
            />
          )}

          {/* ═══ COMPLIANCE TAB ═══ */}
          {activeTab === 'compliance' && (
            <ComplianceSettingsTab
              compFrameworks={compFrameworks}
              togglingFramework={togglingFramework}
              handleToggleFramework={handleToggleFramework}
            />
          )}

          {/* ═══ GOVERNANCE TAB ═══ */}
          {activeTab === 'governance' && (
            <GovernanceTab
              soarPlaybooks={soarPlaybooks}
              openSoarModal={openSoarModal}
              handleToggleSoar={handleToggleSoar}
              handleSoarTest={handleSoarTest}
              handleSoarDelete={handleSoarDelete}
              soarDeleteConfirm={soarDeleteConfirm}
              setSoarDeleteConfirm={setSoarDeleteConfirm}
              testingSoarId={testingSoarId}
              soarTestResult={soarTestResult}
              SOAR_TRIGGER_LABELS={SOAR_TRIGGER_LABELS}
              SOAR_ACTION_LABELS={SOAR_ACTION_LABELS}
              SOAR_INTEGRATION_LABELS={SOAR_INTEGRATION_LABELS}
              saGov={saGov}
              setSaGov={setSaGov}
              saGovMsg={saGovMsg}
              saGovSaving={saGovSaving}
              handleSaGovSave={handleSaGovSave}
            />
          )}

          {/* ═══ ADVANCED TAB ═══ */}
          {activeTab === 'advanced' && (
            <AdvancedTab
              isSuperAdmin={isSuperAdmin}
              retention={retention}
              setRetention={setRetention}
              retentionMsg={retentionMsg}
              retentionSaving={retentionSaving}
              handleRetentionSave={handleRetentionSave}
              cleanupRunning={cleanupRunning}
              cleanupResult={cleanupResult}
              handleManualCleanup={handleManualCleanup}
              storageStats={storageStats}
              settings={settings}
              update={update}
            />
          )}

          {/* ═══ INTEGRATIONS TAB ═══ */}
          {activeTab === 'integrations' && (
            <IntegrationsTab
              ticketingRef={ticketingRef}
              IntegrationsSection={IntegrationsSection}
              TicketingSection={TicketingSection}
              p2Telemetry={p2Telemetry}
              setP2Telemetry={setP2Telemetry}
              p2Saving={p2Saving}
              p2Msg={p2Msg}
              handleP2TelemetrySave={handleP2TelemetrySave}
            />
          )}

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
          <div className="relative bg-white rounded-xl shadow-lg border w-full max-w-2xl mx-4 p-6 space-y-4 max-h-[90vh] overflow-y-auto">
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
          <div className="relative bg-white rounded-xl shadow-lg border w-full max-w-lg mx-4 p-6 space-y-4">
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
          <div className="relative bg-white rounded-xl shadow-lg border w-full max-w-lg mx-4 p-6 space-y-4">
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
                {['admin', 'security_admin', 'security_analyst', 'compliance', 'reader'].map(role => (
                  <button
                    key={role}
                    onClick={() => setUserForm(prev => ({ ...prev, role }))}
                    className={`px-3 py-2 rounded-lg text-sm font-medium border transition ${
                      userForm.role === role
                        ? role === 'admin' ? 'bg-red-600 text-white border-red-600'
                          : role === 'security_admin' ? 'bg-amber-600 text-white border-amber-600'
                          : role === 'security_analyst' ? 'bg-cyan-600 text-white border-cyan-600'
                          : role === 'compliance' ? 'bg-green-600 text-white border-green-600'
                          : 'bg-blue-600 text-white border-blue-600'
                        : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    {role === 'security_admin' ? 'Security Admin'
                      : role === 'security_analyst' ? 'Security Analyst'
                      : role.charAt(0).toUpperCase() + role.slice(1)}
                  </button>
                ))}
              </div>
              <p className="text-xs text-gray-400 mt-1">
                {userForm.role === 'admin' ? 'Full access: settings, users, billing, snapshots, rules'
                  : userForm.role === 'security_admin' ? 'Activate subscriptions, manage cloud connections, capture snapshots'
                  : userForm.role === 'security_analyst' ? 'Manage findings, run simulations, export data'
                  : userForm.role === 'compliance' ? 'Read-only + compliance reports and access reviews'
                  : 'Read-only: view dashboards, identities, reports'}
              </p>
            </div>

            {/* Phase 46: Organization + Superadmin fields (superadmin only) */}
            {isSuperAdmin && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Organization</label>
                  <select
                    value={userForm.organization_id || ''}
                    onChange={e => setUserForm(prev => ({ ...prev, organization_id: e.target.value ? Number(e.target.value) : undefined }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="">-- Select Organization --</option>
                    {orgs.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
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
          <div className="relative bg-white rounded-xl shadow-lg border w-full max-w-lg mx-4 p-6 space-y-4">
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
                    {['admin', 'security_admin', 'security_analyst', 'compliance', 'reader'].map(role => (
                      <button
                        key={role}
                        onClick={() => setApiKeyForm(prev => ({ ...prev, role }))}
                        className={`px-3 py-2 rounded-lg text-sm font-medium border transition ${
                          apiKeyForm.role === role
                            ? role === 'admin' ? 'bg-red-600 text-white border-red-600'
                              : role === 'security_admin' ? 'bg-amber-600 text-white border-amber-600'
                              : role === 'security_analyst' ? 'bg-cyan-600 text-white border-cyan-600'
                              : role === 'compliance' ? 'bg-green-600 text-white border-green-600'
                              : 'bg-blue-600 text-white border-blue-600'
                            : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                        }`}
                      >
                        {role === 'security_admin' ? 'Security Admin'
                          : role === 'security_analyst' ? 'Security Analyst'
                          : role.charAt(0).toUpperCase() + role.slice(1)}
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
          <div className="relative bg-white rounded-xl shadow-lg border w-full max-w-lg mx-4 p-6 space-y-4 max-h-[90vh] overflow-y-auto">
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
  { key: 'scan_complete', label: 'Snapshot Complete' },
  { key: 'scan_failed', label: 'Snapshot Failed' },
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
