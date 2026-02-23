import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { RISK_BADGE, RISK_SOLID, safeLower } from '../constants/metrics';
import { useConnection } from '../contexts/ConnectionContext';

// ─── Types ────────────────────────────────────────────────────────

interface ResourceData {
  id: number;
  resource_id: string;
  name: string;
  resource_type: 'storage_account' | 'key_vault';
  location: string;
  resource_group: string;
  subscription_id: string;
  subscription_name: string;
  sku: string;
  risk_level: string;
  risk_score: number;
  risk_reasons?: string[];
  tags: Record<string, string>;
  // Storage account fields
  kind?: string;
  access_tier?: string;
  public_blob_access?: boolean;
  https_only?: boolean;
  minimum_tls_version?: string;
  shared_key_access?: boolean;
  allow_cross_tenant_replication?: boolean;
  infrastructure_encryption?: boolean;
  customer_managed_keys?: boolean;
  key_vault_uri?: string;
  key1_created_at?: string;
  key2_created_at?: string;
  key_rotation_stale?: boolean;
  encryption_details?: Record<string, unknown>;
  // Key vault fields
  soft_delete_enabled?: boolean;
  soft_delete_retention_days?: number;
  purge_protection?: boolean;
  enable_rbac_authorization?: boolean;
  public_network_access?: string;
  secrets_total?: number;
  secrets_expired?: number;
  secrets_expiring_soon?: number;
  keys_total?: number;
  keys_expired?: number;
  keys_expiring_soon?: number;
  certs_total?: number;
  certs_expired?: number;
  certs_expiring_soon?: number;
  access_policy_count?: number;
  access_policies?: Array<Record<string, unknown>>;
  secrets_detail?: Array<{ name: string; enabled: boolean; expires_on: string | null; created_on: string | null; content_type?: string }>;
  keys_detail?: Array<{ name: string; enabled: boolean; expires_on: string | null; created_on: string | null; key_type?: string; key_size?: number }>;
  certs_detail?: Array<{ name: string; enabled: boolean; expires_on: string | null; created_on: string | null; subject?: string; thumbprint?: string }>;
  // Storage SAS & Audit
  sas_policy_enabled?: boolean;
  sas_expiration_period?: string;
  diagnostic_logging_enabled?: boolean;
  logging_destinations?: Array<{ type: string; target?: string }>;
  sas_risk?: { level: string; factors: string[]; recommendations: string[]; audit_status?: string; audit_label?: string };
  // Network (shared)
  default_network_action?: string;
  ip_rules_count?: number;
  vnet_rules_count?: number;
  private_endpoint_count?: number;
  bypass_settings?: string;
  network_rules?: Record<string, unknown>;
  network_classification?: 'disabled' | 'restricted' | 'public';
  // Risk trend (Phase 89)
  risk_trend?: Array<{
    risk_score: number;
    risk_level: string;
    created_at: string;
    run_date?: string;
    risk_components?: Record<string, { score: number; max: number; pct: number; drivers: Array<{ name: string; points: number }> }>;
    privileged_identity_count?: number;
    blast_radius_score?: number;
  }>;
  risk_trend_delta?: number;
  risk_trend_direction?: 'up' | 'down' | 'stable';
  // Risk components (from scoring engine)
  risk_components?: Record<string, { score: number; max: number; pct: number; drivers: Array<{ name: string; points: number }> }>;
  critical_overrides?: string[];
  blast_radius_score?: number;
}

interface AccessIdentity {
  id: number;
  display_name: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  role_name?: string;
  scope?: string;
  scope_type?: string;
  access_type: 'rbac' | 'access_policy';
  over_privileged?: boolean;
  permissions_summary?: Record<string, string[]>;
  access_source?: 'direct' | 'resource_group' | 'subscription' | 'management_group' | 'inherited';
  access_source_label?: string;
  is_ghost?: boolean;
  account_state?: string;
  deleted_at?: string | null;
}

interface ResourceAnomaly {
  id: number;
  anomaly_type: string;
  severity: string;
  title: string;
  description: string;
  details: {
    resource_id?: string;
    resource_name?: string;
    resource_type?: string;
    trigger?: string;
    baseline?: string | number;
    deviation?: string | number;
    confidence?: number;
    impact?: string;
    recommended_action?: string;
    [key: string]: unknown;
  };
  resolved: boolean;
  created_at: string;
}

type Tab = 'overview' | 'security' | 'network' | 'access' | 'compliance' | 'intelligence';

// ─── Compliance Mapping ───────────────────────────────────────────

const STORAGE_COMPLIANCE: Record<string, { controls: string[]; description: string }> = {
  public_blob_access: {
    controls: ['CIS Azure 3.7', 'SOC2 CC6.1', 'HIPAA §164.312(a)(1)'],
    description: 'Public blob access must be disabled to prevent unauthorized data exposure',
  },
  https_only: {
    controls: ['CIS Azure 3.1', 'PCI-DSS 4.1', 'SOC2 CC6.7'],
    description: 'HTTPS-only transfer ensures data is encrypted in transit',
  },
  minimum_tls_version: {
    controls: ['CIS Azure 3.15', 'PCI-DSS 4.1'],
    description: 'TLS 1.2 minimum prevents use of vulnerable TLS versions',
  },
  customer_managed_keys: {
    controls: ['CIS Azure 3.9', 'HIPAA §164.312(a)(2)(iv)', 'SOC2 CC6.1'],
    description: 'Customer-managed keys provide additional control over encryption',
  },
  default_network_action: {
    controls: ['CIS Azure 3.8', 'SOC2 CC6.6', 'NIST AC-4'],
    description: 'Default deny network rules restrict access to trusted networks',
  },
  shared_key_access: {
    controls: ['CIS Azure 3.2', 'SOC2 CC6.1'],
    description: 'Disabling shared key access forces Azure AD authentication',
  },
  infrastructure_encryption: {
    controls: ['CIS Azure 3.3', 'SOC2 CC6.1'],
    description: 'Infrastructure encryption provides a second layer of encryption at the hardware level',
  },
  cross_tenant_replication: {
    controls: ['CIS Azure 3.12', 'SOC2 CC6.6'],
    description: 'Cross-tenant replication must be disabled to prevent data leakage across tenants',
  },
  key_rotation: {
    controls: ['CIS Azure 3.4', 'PCI-DSS 3.6.4'],
    description: 'Storage account keys must be rotated within 90 days',
  },
  private_endpoints: {
    controls: ['CIS Azure 3.10', 'NIST SC-7'],
    description: 'Private endpoints ensure traffic flows through Azure backbone network',
  },
  sas_policy: {
    controls: ['CIS Azure 3.13'],
    description: 'SAS expiration policy limits the lifetime of shared access signature tokens',
  },
  diagnostic_logging: {
    controls: ['CIS Azure 3.14', 'SOC2 CC7.2', 'NIST AU-2'],
    description: 'Diagnostic logging must be enabled to audit shared key and SAS token usage',
  },
  bypass_limited: {
    controls: ['CIS Azure 3.9', 'NIST AC-4'],
    description: 'Network bypass should be limited to AzureServices to minimize attack surface',
  },
};

const KEYVAULT_COMPLIANCE: Record<string, { controls: string[]; description: string }> = {
  soft_delete: {
    controls: ['CIS Azure 8.4', 'SOC2 CC6.1', 'NIST SC-12'],
    description: 'Soft delete protects against accidental or malicious secret deletion',
  },
  purge_protection: {
    controls: ['CIS Azure 8.5', 'SOC2 CC6.1'],
    description: 'Purge protection prevents permanent deletion during retention period',
  },
  rbac_authorization: {
    controls: ['CIS Azure 8.7', 'SOC2 CC6.3', 'HIPAA §164.312(a)(1)'],
    description: 'RBAC authorization provides fine-grained access control via Azure AD',
  },
  expired_secrets: {
    controls: ['CIS Azure 8.1', 'PCI-DSS 3.6.4', 'SOC2 CC6.1'],
    description: 'Expired secrets indicate poor lifecycle management and potential security gaps',
  },
  network_access: {
    controls: ['CIS Azure 8.6', 'SOC2 CC6.6', 'NIST AC-4'],
    description: 'Network restrictions limit vault access to trusted networks and endpoints',
  },
  private_endpoints: {
    controls: ['CIS Azure 8.8', 'NIST SC-7'],
    description: 'Private endpoints ensure vault traffic flows through Azure backbone network',
  },
  key_expiry_set: {
    controls: ['CIS Azure 8.1.1', 'SOC2 CC6.1'],
    description: 'All keys should have expiration dates set to enforce rotation',
  },
  secret_expiry_set: {
    controls: ['CIS Azure 8.2', 'PCI-DSS 3.6.4'],
    description: 'All secrets should have expiration dates to prevent indefinite validity',
  },
  cert_expiry_check: {
    controls: ['CIS Azure 8.3'],
    description: 'Certificates expiring within 90 days should be renewed promptly',
  },
  retention_90d: {
    controls: ['CIS Azure 8.4.1', 'SOC2 CC6.1'],
    description: 'Soft delete retention should be at least 90 days for adequate recovery window',
  },
};

// ─── Small Components ─────────────────────────────────────────────

function ScoreRing({ score, size = 64 }: { score: number; size?: number }) {
  const level = score >= 80 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : score > 0 ? 'low' : 'info';
  const solid = RISK_SOLID[level];
  const radius = (size - 8) / 2;
  const circumference = 2 * Math.PI * radius;
  const percent = Math.min(score, 100);
  const offset = circumference - (percent / 100) * circumference;

  const colorMap: Record<string, string> = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6',
  };

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="transform -rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#e5e7eb" strokeWidth={4} />
        <circle
          cx={size / 2} cy={size / 2} r={radius} fill="none"
          stroke={colorMap[level]} strokeWidth={4}
          strokeDasharray={circumference} strokeDashoffset={offset}
          strokeLinecap="round"
        />
      </svg>
      <span className={`absolute text-sm font-bold ${solid?.text === 'text-white' ? 'text-gray-800' : 'text-gray-800'}`}>{score}</span>
    </div>
  );
}

function CheckItem({ label, pass, detail }: { label: string; pass: boolean | null; detail?: string }) {
  return (
    <div className="flex items-start gap-2 py-2 border-b border-gray-100 last:border-0">
      <span className={`mt-0.5 flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold ${
        pass === null ? 'bg-gray-100 text-gray-400' : pass ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'
      }`}>
        {pass === null ? '?' : pass ? '✓' : '✗'}
      </span>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-gray-800">{label}</div>
        {detail && <div className="text-xs text-gray-500 mt-0.5">{detail}</div>}
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────

export default function ResourceDetail() {
  const [searchParams] = useSearchParams();
  const rid = searchParams.get('rid') || '';
  const { withConnection } = useConnection();

  // Build resource API path — use raw path (no encodeURIComponent) to avoid
  // Flask 308 redirect on %2F which strips the Authorization header.
  const resourcePath = rid.startsWith('/') ? rid.slice(1) : rid;

  const [resource, setResource] = useState<ResourceData | null>(null);
  const [rbacAccess, setRbacAccess] = useState<AccessIdentity[]>([]);
  const [policyAccess, setPolicyAccess] = useState<AccessIdentity[]>([]);
  const [blastRadius, setBlastRadius] = useState(0);
  const [ghostCount, setGhostCount] = useState(0);
  const [accessLoading, setAccessLoading] = useState(false);
  const [accessLoaded, setAccessLoaded] = useState(false);
  const [accessError, setAccessError] = useState(false);
  const [anomalies, setAnomalies] = useState<ResourceAnomaly[]>([]);
  const [anomaliesLoaded, setAnomaliesLoaded] = useState(false);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<Tab>('overview');

  // Fetch resource detail
  useEffect(() => {
    if (!rid) return;
    setLoading(true);
    fetch(withConnection(`/api/resources/${resourcePath}`))
      .then(r => r.json())
      .then(data => { setResource(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, [rid]);

  // Lazy-load access tab
  useEffect(() => {
    if (activeTab !== 'access' || !rid || accessLoaded) return;
    setAccessLoading(true);
    setAccessError(false);
    fetch(withConnection(`/api/resources/${resourcePath}/access`))
      .then(r => { if (!r.ok) throw new Error('Failed'); return r.json(); })
      .then(data => {
        setRbacAccess(data.rbac_access || []);
        setPolicyAccess(data.policy_access || []);
        setBlastRadius(data.blast_radius || 0);
        setGhostCount(data.ghost_count || 0);
        setAccessLoaded(true);
        setAccessLoading(false);
      })
      .catch(() => { setAccessError(true); setAccessLoading(false); setAccessLoaded(true); });
  }, [activeTab, rid, accessLoaded]);

  // Lazy-load intelligence tab anomalies
  useEffect(() => {
    if (activeTab !== 'intelligence' || !rid || anomaliesLoaded) return;
    fetch(withConnection(`/api/resources/${resourcePath}/anomalies?limit=50`))
      .then(r => r.json())
      .then(data => {
        setAnomalies(data.anomalies || []);
        setAnomaliesLoaded(true);
      })
      .catch(() => setAnomaliesLoaded(true));
  }, [activeTab, rid, anomaliesLoaded]);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-gray-400">Loading resource...</div>;
  }

  if (!resource) {
    return (
      <div className="text-center py-16">
        <p className="text-gray-500">Resource not found</p>
        <Link to="/resources" className="text-blue-600 text-sm hover:underline mt-2 inline-block">Back to Resources</Link>
      </div>
    );
  }

  const isStorage = resource.resource_type === 'storage_account';
  const tabs: { key: Tab; label: string }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'security', label: 'Security Config' },
    { key: 'network', label: 'Network' },
    { key: 'access', label: 'Access Control' },
    { key: 'compliance', label: 'Compliance' },
    { key: 'intelligence', label: 'Risk Intelligence' },
  ];

  return (
    <div className="space-y-4">
      {/* Breadcrumb */}
      <div className="flex items-center gap-1 text-xs text-gray-500">
        <Link to="/resources" className="hover:text-blue-600">Resources</Link>
        <span>/</span>
        <span className="text-gray-800 font-medium truncate max-w-xs">{resource.name}</span>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{resource.name}</h1>
          <div className="flex items-center gap-2 mt-1">
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
              isStorage ? 'bg-blue-100 text-blue-700' : 'bg-purple-100 text-purple-700'
            }`}>
              {isStorage ? 'Storage Account' : 'Key Vault'}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[safeLower(resource.risk_level)] || 'bg-gray-100 text-gray-600'}`}>
              {resource.risk_level}
            </span>
            <span className="text-xs text-gray-500">{resource.location}</span>
          </div>
        </div>
        <ScoreRing score={resource.risk_score} size={64} />
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <div className="flex gap-0">
          {tabs.map(t => (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeTab === t.key
                  ? 'border-blue-600 text-blue-700'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      <div className="min-h-[300px]">
        {activeTab === 'overview' && <OverviewTab resource={resource} />}
        {activeTab === 'security' && <SecurityTab resource={resource} />}
        {activeTab === 'network' && <NetworkTab resource={resource} />}
        {activeTab === 'access' && <AccessTab rbacAccess={rbacAccess} policyAccess={policyAccess} blastRadius={blastRadius} ghostCount={ghostCount} loading={accessLoading} isKeyVault={!isStorage} error={accessError} resourceType={resource.resource_type} />}
        {activeTab === 'compliance' && <ComplianceTab resource={resource} />}
        {activeTab === 'intelligence' && <IntelligenceTab resource={resource} anomalies={anomalies} />}
      </div>
    </div>
  );
}

// ─── Overview Tab ─────────────────────────────────────────────────

function OverviewTab({ resource }: { resource: ResourceData }) {
  const isStorage = resource.resource_type === 'storage_account';

  const infoRows: { label: string; value: string }[] = [
    { label: 'Resource ID', value: resource.resource_id },
    { label: 'Type', value: isStorage ? 'Storage Account' : 'Key Vault' },
    { label: 'Location', value: resource.location || '—' },
    { label: 'Resource Group', value: resource.resource_group || '—' },
    { label: 'Subscription', value: resource.subscription_name || resource.subscription_id || '—' },
    { label: 'SKU', value: resource.sku || '—' },
  ];
  if (isStorage) {
    infoRows.push({ label: 'Kind', value: resource.kind || '—' });
    infoRows.push({ label: 'Access Tier', value: resource.access_tier || '—' });
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      {/* Info grid */}
      <div className="lg:col-span-2 bg-white border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Resource Information</h3>
        <div className="grid grid-cols-2 gap-x-6 gap-y-2">
          {infoRows.map(r => (
            <div key={r.label} className="py-1.5 border-b border-gray-50">
              <div className="text-[10px] uppercase tracking-wider text-gray-400 font-medium">{r.label}</div>
              <div className="text-sm text-gray-800 truncate" title={r.value}>{r.value}</div>
            </div>
          ))}
        </div>

        {/* Tags */}
        {resource.tags && Object.keys(resource.tags).length > 0 && (
          <div className="mt-4">
            <div className="text-[10px] uppercase tracking-wider text-gray-400 font-medium mb-1">Tags</div>
            <div className="flex flex-wrap gap-1">
              {Object.entries(resource.tags).map(([k, v]) => (
                <span key={k} className="px-1.5 py-0.5 bg-gray-100 text-gray-600 rounded text-[10px]">{k}: {v}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Risk reasons */}
      <div className="bg-white border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Risk Analysis</h3>
        <div className="flex items-center gap-3 mb-3">
          <ScoreRing score={resource.risk_score} size={56} />
          <div>
            <div className={`text-sm font-bold uppercase ${RISK_BADGE[safeLower(resource.risk_level)]?.split(' ')[1] || 'text-gray-600'}`}>
              {resource.risk_level}
            </div>
            <div className="text-[10px] text-gray-500">{resource.risk_score} / 100 points</div>
          </div>
        </div>
        {(resource.risk_reasons || []).length > 0 ? (
          <ul className="space-y-1.5">
            {(resource.risk_reasons || []).map((reason, i) => (
              <li key={i} className="flex items-start gap-1.5 text-xs text-gray-700">
                <span className="text-red-400 mt-0.5 flex-shrink-0">●</span>
                {reason}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-green-600">No risk issues detected</p>
        )}
      </div>
    </div>
  );
}

// ─── Security Config Tab ──────────────────────────────────────────

function SecurityTab({ resource }: { resource: ResourceData }) {
  const isStorage = resource.resource_type === 'storage_account';

  if (isStorage) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-200 mb-2">Transport & Access</h3>
            <CheckItem label="HTTPS-Only Transfer" pass={resource.https_only === true} detail={resource.https_only ? 'Enabled' : 'HTTP traffic allowed'} />
            <CheckItem label="TLS Version" pass={resource.minimum_tls_version === 'TLS1_2'} detail={`Current: ${resource.minimum_tls_version || 'Unknown'}`} />
            <CheckItem label="Public Blob Access Disabled" pass={resource.public_blob_access === false} detail={resource.public_blob_access ? 'Public access enabled — containers may be exposed' : 'Disabled'} />
            <CheckItem label="Shared Key Access Disabled" pass={resource.shared_key_access === false} detail={resource.shared_key_access ? 'Enabled — consider Azure AD auth only' : 'Disabled, Azure AD auth required'} />
            <CheckItem label="Cross-Tenant Replication" pass={resource.allow_cross_tenant_replication === false} detail={resource.allow_cross_tenant_replication ? 'Enabled' : 'Disabled'} />
          </div>
          <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-200 mb-2">Encryption & Keys</h3>
            <CheckItem label="Customer-Managed Keys" pass={resource.customer_managed_keys === true} detail={resource.customer_managed_keys ? `Key Vault: ${resource.key_vault_uri || 'configured'}` : 'Using Microsoft-managed keys'} />
            <CheckItem label="Infrastructure Encryption" pass={resource.infrastructure_encryption === true} detail={resource.infrastructure_encryption ? 'Double encryption enabled' : 'Single layer encryption'} />
            <CheckItem label="Storage Key Rotation" pass={resource.key_rotation_stale === false} detail={keyRotationDetail(resource)} />
            <KeyRotationBars resource={resource} />
          </div>
        </div>

        {/* SAS & Shared Key Security Section */}
        <SasSecuritySection resource={resource} />
      </div>
    );
  }

  // Key Vault
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-200 mb-2">Vault Security</h3>
          <CheckItem label="Soft Delete" pass={resource.soft_delete_enabled === true} detail={resource.soft_delete_enabled ? `Enabled (${resource.soft_delete_retention_days || 90} day retention)` : 'Disabled — deleted secrets are permanently lost'} />
          <CheckItem label="Purge Protection" pass={resource.purge_protection === true} detail={resource.purge_protection ? 'Enabled' : 'Disabled — soft-deleted items can be purged immediately'} />
          <CheckItem label="RBAC Authorization" pass={resource.enable_rbac_authorization === true} detail={resource.enable_rbac_authorization ? 'Azure RBAC for data plane' : `Access Policies mode (${resource.access_policy_count || 0} policies)`} />
        </div>
        <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-200 mb-2">Secrets, Keys & Certificates</h3>
          <VaultItemRow label="Secrets" total={resource.secrets_total} expired={resource.secrets_expired} expiring={resource.secrets_expiring_soon} />
          <VaultItemRow label="Keys" total={resource.keys_total} expired={resource.keys_expired} expiring={resource.keys_expiring_soon} />
          <VaultItemRow label="Certificates" total={resource.certs_total} expired={resource.certs_expired} expiring={resource.certs_expiring_soon} />
        </div>
      </div>

      {/* Item-level expiry inventory */}
      <VaultItemInventory resource={resource} />
    </div>
  );
}

function VaultItemRow({ label, total, expired, expiring }: { label: string; total?: number; expired?: number; expiring?: number }) {
  const t = total ?? 0;
  const e = expired ?? 0;
  const es = expiring ?? 0;
  return (
    <div className="flex items-center justify-between py-2 border-b border-gray-100 last:border-0">
      <span className="text-sm font-medium text-gray-800">{label}</span>
      <div className="flex items-center gap-2 text-xs">
        <span className="text-gray-600">{t} total</span>
        {e > 0 && <span className="px-1.5 py-0.5 bg-red-100 text-red-700 rounded font-semibold">{e} expired</span>}
        {es > 0 && <span className="px-1.5 py-0.5 bg-yellow-100 text-yellow-700 rounded font-semibold">{es} expiring</span>}
        {e === 0 && es === 0 && t > 0 && <span className="text-green-600 font-medium">OK</span>}
      </div>
    </div>
  );
}

function keyRotationDetail(r: ResourceData): string {
  if (r.key_rotation_stale) {
    const parts: string[] = [];
    if (r.key1_created_at) parts.push(`Key1: ${new Date(r.key1_created_at).toLocaleDateString()}`);
    if (r.key2_created_at) parts.push(`Key2: ${new Date(r.key2_created_at).toLocaleDateString()}`);
    return `Stale (>90 days) — ${parts.join(', ') || 'creation dates unknown'}`;
  }
  return 'Keys rotated within 90 days';
}

function KeyRotationBars({ resource }: { resource: ResourceData }) {
  const keys = [
    { label: 'Key 1', date: resource.key1_created_at },
    { label: 'Key 2', date: resource.key2_created_at },
  ];

  return (
    <div className="mt-3 pt-3 border-t border-gray-100 dark:border-slate-700">
      <div className="text-[10px] uppercase tracking-wider text-gray-400 font-medium mb-2">Key Age (days)</div>
      {keys.map(k => {
        const ageDays = k.date ? Math.floor((Date.now() - new Date(k.date).getTime()) / 86400000) : null;
        const pct = ageDays !== null ? Math.min((ageDays / 180) * 100, 100) : 0;
        const color = ageDays === null ? 'bg-gray-200' : ageDays > 90 ? 'bg-red-500' : ageDays > 60 ? 'bg-yellow-500' : 'bg-green-500';
        return (
          <div key={k.label} className="flex items-center gap-2 mb-1.5">
            <span className="text-[10px] text-gray-500 w-10">{k.label}</span>
            <div className="flex-1 h-3 bg-gray-100 dark:bg-slate-700 rounded-full overflow-hidden relative">
              <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
              <div className="absolute left-1/2 top-0 bottom-0 w-px bg-gray-400 dark:bg-slate-500" title="90-day threshold" />
            </div>
            <span className={`text-[10px] font-medium w-14 text-right ${ageDays !== null && ageDays > 90 ? 'text-red-600' : 'text-gray-600'}`}>
              {ageDays !== null ? `${ageDays}d` : 'N/A'}
            </span>
          </div>
        );
      })}
      <div className="text-[10px] text-gray-400 mt-0.5">Center line = 90-day rotation threshold</div>
    </div>
  );
}

function SasSecuritySection({ resource }: { resource: ResourceData }) {
  const risk = resource.sas_risk;
  const riskColor = risk?.level === 'critical' ? 'border-red-300 bg-red-50' : risk?.level === 'high' ? 'border-red-200 bg-red-50' : risk?.level === 'medium' ? 'border-yellow-200 bg-yellow-50' : 'border-green-200 bg-green-50';
  const shieldColor = risk?.level === 'critical' || risk?.level === 'high' ? 'text-red-500' : risk?.level === 'medium' ? 'text-yellow-500' : 'text-green-500';

  const AUDIT_STATUS_STYLE: Record<string, string> = {
    compliant: 'bg-green-100 text-green-700 border-green-200',
    auditable: 'bg-blue-100 text-blue-700 border-blue-200',
    partial: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    unauditable: 'bg-red-100 text-red-700 border-red-200',
  };

  return (
    <div className={`border rounded-lg p-4 ${riskColor}`}>
      <div className="flex items-center gap-2 mb-3">
        <svg className={`w-5 h-5 ${shieldColor}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <h3 className="text-sm font-semibold text-gray-800">Shared Key & SAS Security</h3>
        {risk && <span className={`ml-auto px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
          risk.level === 'critical' ? 'bg-red-200 text-red-800' : risk.level === 'high' ? 'bg-red-100 text-red-700' : risk.level === 'medium' ? 'bg-yellow-100 text-yellow-700' : 'bg-green-100 text-green-700'
        }`}>{risk.level} risk</span>}
      </div>

      {/* Audit Status Banner */}
      {risk?.audit_status && (
        <div className={`border rounded-md px-3 py-2 mb-3 ${AUDIT_STATUS_STYLE[risk.audit_status] || 'bg-gray-100 text-gray-600 border-gray-200'}`}>
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold">
              {risk.audit_status === 'compliant' ? '✓' : risk.audit_status === 'auditable' ? '◉' : risk.audit_status === 'partial' ? '◎' : '✗'}
            </span>
            <div>
              <div className="text-xs font-semibold">{risk.audit_label}</div>
              <div className="text-[10px] opacity-80">
                {risk.audit_status === 'unauditable'
                  ? 'SAS tokens can be generated from account keys with no visibility into usage'
                  : risk.audit_status === 'partial'
                  ? 'Usage is logged but SAS tokens have no enforced expiration limit'
                  : risk.audit_status === 'auditable'
                  ? 'Usage is logged and SAS tokens have enforced expiration policy'
                  : 'Shared key access is disabled — only Azure AD authentication is allowed'}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-3">
        <div className="text-sm">
          <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-0.5">Shared Key Access</div>
          <span className={`font-medium ${resource.shared_key_access ? 'text-red-700' : 'text-green-700'}`}>
            {resource.shared_key_access ? 'Enabled' : 'Disabled'}
          </span>
        </div>
        <div className="text-sm">
          <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-0.5">SAS Expiration Policy</div>
          <span className={`font-medium ${resource.sas_policy_enabled ? 'text-green-700' : 'text-yellow-700'}`}>
            {resource.sas_policy_enabled ? `Enabled (${resource.sas_expiration_period || 'configured'})` : 'Not configured'}
          </span>
        </div>
        <div className="text-sm">
          <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-0.5">Diagnostic Logging</div>
          <span className={`font-medium ${resource.diagnostic_logging_enabled ? 'text-green-700' : 'text-red-700'}`}>
            {resource.diagnostic_logging_enabled ? 'Enabled' : 'Not configured'}
          </span>
          {!!resource.logging_destinations && resource.logging_destinations.length > 0 && (
            <div className="text-[10px] text-gray-500 mt-0.5">
              {resource.logging_destinations.map((d, i) => (
                <span key={i} className="inline-block mr-1 px-1 py-0.5 bg-white/60 rounded">
                  {d.type === 'log_analytics' ? 'Log Analytics' : d.type === 'event_hub' ? 'Event Hub' : d.type === 'storage_account' ? 'Storage' : d.type}
                </span>
              ))}
            </div>
          )}
        </div>
        <div className="text-sm">
          <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-0.5">Key Rotation</div>
          <span className={`font-medium ${resource.key_rotation_stale ? 'text-red-700' : 'text-green-700'}`}>
            {resource.key_rotation_stale ? 'Overdue (>90d)' : 'Current'}
          </span>
        </div>
      </div>

      {risk && risk.factors.length > 0 && (
        <div className="space-y-1 mb-2">
          <div className="text-[10px] uppercase tracking-wider text-gray-500 font-medium">Risk Factors</div>
          {risk.factors.map((f, i) => (
            <div key={i} className="flex items-center gap-1.5 text-xs text-gray-700">
              <span className="text-red-400">!</span> {f}
            </div>
          ))}
        </div>
      )}

      {risk && risk.recommendations.length > 0 && (
        <div className="space-y-1">
          <div className="text-[10px] uppercase tracking-wider text-gray-500 font-medium">Recommendations</div>
          {risk.recommendations.map((r, i) => (
            <div key={i} className="flex items-center gap-1.5 text-xs text-gray-600">
              <span className="text-blue-400">→</span> {r}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function VaultItemInventory({ resource }: { resource: ResourceData }) {
  const now = Date.now();
  const d30 = 30 * 86400000;
  const d90 = 90 * 86400000;

  type ItemRow = { name: string; type: string; enabled: boolean; expires_on: string | null; created_on: string | null; extra?: string };
  const items: ItemRow[] = [];

  (resource.secrets_detail || []).forEach(s => items.push({ name: s.name, type: 'Secret', enabled: s.enabled, expires_on: s.expires_on, created_on: s.created_on, extra: s.content_type || undefined }));
  (resource.keys_detail || []).forEach(k => items.push({ name: k.name, type: 'Key', enabled: k.enabled, expires_on: k.expires_on, created_on: k.created_on, extra: k.key_type || undefined }));
  (resource.certs_detail || []).forEach(c => items.push({ name: c.name, type: 'Certificate', enabled: c.enabled, expires_on: c.expires_on, created_on: c.created_on, extra: c.subject || undefined }));

  // Sort: expired first, then by expiry soonest
  items.sort((a, b) => {
    if (!a.expires_on && !b.expires_on) return 0;
    if (!a.expires_on) return 1;
    if (!b.expires_on) return -1;
    return new Date(a.expires_on).getTime() - new Date(b.expires_on).getTime();
  });

  if (items.length === 0) return null;

  function expiryBadge(exp: string | null) {
    if (!exp) return <span className="text-gray-400 text-[10px]">No expiry set</span>;
    const ms = new Date(exp).getTime() - now;
    const days = Math.ceil(ms / 86400000);
    if (ms < 0) return <span className="px-1.5 py-0.5 bg-red-100 text-red-700 rounded text-[10px] font-semibold">Expired {Math.abs(days)}d ago</span>;
    if (ms < d30) return <span className="px-1.5 py-0.5 bg-orange-100 text-orange-700 rounded text-[10px] font-semibold">{days}d left</span>;
    if (ms < d90) return <span className="px-1.5 py-0.5 bg-yellow-100 text-yellow-700 rounded text-[10px] font-semibold">{days}d left</span>;
    return <span className="text-green-600 text-[10px] font-medium">{days}d left</span>;
  }

  const typeColors: Record<string, string> = {
    Secret: 'bg-blue-100 text-blue-700',
    Key: 'bg-purple-100 text-purple-700',
    Certificate: 'bg-emerald-100 text-emerald-700',
  };

  return (
    <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700">
        <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-200">Secrets & Keys Inventory</h3>
        <p className="text-[10px] text-gray-500 mt-0.5">{items.length} items sorted by expiry</p>
      </div>
      <table className="min-w-full text-left text-xs">
        <thead className="bg-gray-50 dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700 text-gray-600 dark:text-slate-400 uppercase tracking-wider font-medium">
          <tr>
            <th className="px-4 py-2">Name</th>
            <th className="px-4 py-2">Type</th>
            <th className="px-4 py-2">Status</th>
            <th className="px-4 py-2">Expiry</th>
            <th className="px-4 py-2">Created</th>
            <th className="px-4 py-2">Detail</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100 dark:divide-slate-700">
          {items.slice(0, 50).map((item, i) => {
            const isExpired = item.expires_on && new Date(item.expires_on).getTime() < now;
            return (
              <tr key={`${item.type}-${item.name}-${i}`} className={isExpired ? 'bg-red-50/40 dark:bg-red-900/10' : ''}>
                <td className="px-4 py-2 font-medium text-gray-800 dark:text-slate-200">{item.name}</td>
                <td className="px-4 py-2">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${typeColors[item.type] || 'bg-gray-100 text-gray-600'}`}>{item.type}</span>
                </td>
                <td className="px-4 py-2">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${item.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                    {item.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td className="px-4 py-2">{expiryBadge(item.expires_on)}</td>
                <td className="px-4 py-2 text-gray-500">{item.created_on ? new Date(item.created_on).toLocaleDateString() : '—'}</td>
                <td className="px-4 py-2 text-gray-500 truncate max-w-[150px]" title={item.extra}>{item.extra || '—'}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {items.length > 50 && <div className="px-4 py-2 text-xs text-gray-400 border-t">Showing first 50 of {items.length} items</div>}
    </div>
  );
}

// ─── Network Tab ──────────────────────────────────────────────────

function NetworkTab({ resource }: { resource: ResourceData }) {
  const classification = resource.network_classification || (resource.default_network_action === 'Allow' ? 'public' : 'restricted');
  const isPublic = classification === 'public';

  const summaryConfig: Record<string, { bg: string; title: string; titleColor: string; textColor: string; description: string }> = {
    disabled: {
      bg: 'bg-green-50 border border-green-200',
      title: 'Network Access Disabled',
      titleColor: 'text-green-800',
      textColor: 'text-green-700',
      description: 'Public network access is completely disabled. This resource is only accessible via private endpoints.',
    },
    restricted: {
      bg: 'bg-green-50 border border-green-200',
      title: 'Network Restricted',
      titleColor: 'text-green-800',
      textColor: 'text-green-700',
      description: `Access is limited to configured IP rules (${resource.ip_rules_count || 0}), VNet rules (${resource.vnet_rules_count || 0}), and private endpoints (${resource.private_endpoint_count || 0}).`,
    },
    public: {
      bg: 'bg-red-50 border border-red-200',
      title: 'Open to All Networks',
      titleColor: 'text-red-800',
      textColor: 'text-red-700',
      description: 'This resource allows traffic from all networks by default. Consider restricting access using IP rules, VNet rules, or private endpoints.',
    },
  };

  const summary = summaryConfig[classification] || summaryConfig.public;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="bg-white border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Network Configuration</h3>

        {/* Default Action */}
        <div className="flex items-center justify-between py-2 border-b border-gray-100">
          <span className="text-sm text-gray-700">Default Action</span>
          <span className={`px-2 py-0.5 rounded text-xs font-bold ${isPublic ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
            {resource.default_network_action || 'Allow'}
          </span>
        </div>

        {resource.resource_type === 'key_vault' && (
          <div className="flex items-center justify-between py-2 border-b border-gray-100">
            <span className="text-sm text-gray-700">Public Network Access</span>
            <span className={`px-2 py-0.5 rounded text-xs font-bold ${
              resource.public_network_access === 'Disabled' ? 'bg-green-100 text-green-700' :
              resource.public_network_access === 'Enabled' ? 'bg-yellow-100 text-yellow-700' : 'bg-green-100 text-green-700'
            }`}>
              {resource.public_network_access || 'Enabled'}
            </span>
          </div>
        )}

        {/* Network Classification Badge */}
        <div className="flex items-center justify-between py-2 border-b border-gray-100">
          <span className="text-sm text-gray-700">Classification</span>
          <span className={`px-2 py-0.5 rounded text-xs font-bold ${
            classification === 'disabled' ? 'bg-green-100 text-green-700' :
            classification === 'restricted' ? 'bg-green-100 text-green-700' :
            'bg-red-100 text-red-700'
          }`}>
            {classification === 'disabled' ? 'Disabled' : classification === 'restricted' ? 'Restricted' : 'Public'}
          </span>
        </div>

        {/* Counters */}
        <div className="flex items-center justify-between py-2 border-b border-gray-100">
          <span className="text-sm text-gray-700">IP Rules</span>
          <span className="text-sm font-medium text-gray-800">{resource.ip_rules_count ?? 0}</span>
        </div>
        <div className="flex items-center justify-between py-2 border-b border-gray-100">
          <span className="text-sm text-gray-700">VNet Rules</span>
          <span className="text-sm font-medium text-gray-800">{resource.vnet_rules_count ?? 0}</span>
        </div>
        <div className="flex items-center justify-between py-2 border-b border-gray-100">
          <span className="text-sm text-gray-700">Private Endpoints</span>
          <span className={`text-sm font-medium ${(resource.private_endpoint_count ?? 0) > 0 ? 'text-green-700' : 'text-gray-400'}`}>
            {resource.private_endpoint_count ?? 0}
          </span>
        </div>

        {resource.bypass_settings && (
          <div className="flex items-center justify-between py-2">
            <span className="text-sm text-gray-700">Bypass</span>
            <span className="text-xs text-gray-600">{resource.bypass_settings}</span>
          </div>
        )}
      </div>

      <div className="bg-white border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Network Summary</h3>
        <div className={`rounded-lg p-4 text-sm ${summary.bg}`}>
          <div className={`font-semibold ${summary.titleColor} mb-1`}>{summary.title}</div>
          <p className={`${summary.textColor} text-xs`}>{summary.description}</p>
        </div>
      </div>
    </div>
  );
}

// ─── Access Control Tab ───────────────────────────────────────────

function AccessTab({ rbacAccess, policyAccess, blastRadius, ghostCount, loading, isKeyVault, error, resourceType }: {
  rbacAccess: AccessIdentity[]; policyAccess: AccessIdentity[]; blastRadius: number; ghostCount: number; loading: boolean; isKeyVault: boolean;
  error?: boolean; resourceType?: string;
}) {
  if (loading) {
    return <div className="flex items-center justify-center h-32 text-gray-400 text-sm">Loading access data...</div>;
  }

  if (error) {
    return (
      <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-6 text-center">
        <p className="text-yellow-700 dark:text-yellow-300 text-sm font-medium">Unable to load access data.</p>
        <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-1">Identity-resource cross-reference requires a completed discovery run.</p>
      </div>
    );
  }

  const total = rbacAccess.length + policyAccess.length;
  if (total === 0) {
    const emptyHint = resourceType === 'storage_account'
      ? 'Storage account access may use shared keys or SAS tokens that bypass RBAC. Check the Security tab for SAS risk assessment.'
      : resourceType === 'key_vault'
      ? 'Key Vault access may be governed by access policies instead of RBAC. Check vault configuration for access policy-based authorization.'
      : 'Identities with inherited access through parent scopes may not be shown.';
    return (
      <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg p-6 text-center">
        <p className="text-gray-500 text-sm">No identities found with RBAC access to this resource.</p>
        <p className="text-xs text-gray-400 mt-1">{emptyHint}</p>
      </div>
    );
  }

  // Compute access source breakdown
  const sourceCounts: Record<string, number> = {};
  rbacAccess.forEach(a => {
    const src = a.access_source || 'unknown';
    sourceCounts[src] = (sourceCounts[src] || 0) + 1;
  });

  const SOURCE_BADGE: Record<string, string> = {
    direct: 'bg-green-100 text-green-700',
    resource_group: 'bg-blue-100 text-blue-700',
    subscription: 'bg-yellow-100 text-yellow-700',
    management_group: 'bg-purple-100 text-purple-700',
    inherited: 'bg-gray-100 text-gray-600',
  };

  return (
    <div className="space-y-4">
      {/* Summary banner */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg px-4 py-3">
        <div className="flex items-center justify-between mb-2">
          <div className="text-sm text-blue-800 dark:text-blue-300">
            <span className="font-bold">{blastRadius}</span> unique identities have access to this resource
          </div>
          <div className="flex gap-3 text-[10px]">
            <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded font-medium">{rbacAccess.length} RBAC</span>
            {isKeyVault && <span className="px-2 py-0.5 bg-purple-100 text-purple-700 rounded font-medium">{policyAccess.length} Access Policy</span>}
          </div>
        </div>
        {/* Access source breakdown */}
        {Object.keys(sourceCounts).length > 0 && (
          <div className="flex items-center gap-2 text-[10px]">
            <span className="text-blue-600 dark:text-blue-400 font-medium">Access Source:</span>
            {sourceCounts.direct && <span className="px-1.5 py-0.5 bg-green-100 text-green-700 rounded font-semibold">{sourceCounts.direct} Direct</span>}
            {sourceCounts.resource_group && <span className="px-1.5 py-0.5 bg-blue-100 text-blue-700 rounded font-semibold">{sourceCounts.resource_group} Resource Group</span>}
            {sourceCounts.subscription && <span className="px-1.5 py-0.5 bg-yellow-100 text-yellow-700 rounded font-semibold">{sourceCounts.subscription} Subscription</span>}
            {sourceCounts.management_group && <span className="px-1.5 py-0.5 bg-purple-100 text-purple-700 rounded font-semibold">{sourceCounts.management_group} Mgmt Group</span>}
            {sourceCounts.inherited && <span className="px-1.5 py-0.5 bg-gray-100 text-gray-600 rounded font-semibold">{sourceCounts.inherited} Inherited</span>}
          </div>
        )}
      </div>

      {/* Ghost access warning banner */}
      {ghostCount > 0 && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg px-4 py-3">
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-red-600 dark:text-red-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" /></svg>
            <span className="text-sm font-semibold text-red-700 dark:text-red-300">
              {ghostCount} Ghost {ghostCount === 1 ? 'Identity' : 'Identities'} Detected
            </span>
          </div>
          <p className="text-xs text-red-600 dark:text-red-400 mt-1 ml-6">
            Disabled or deleted identities that still retain active access to this resource. These represent a critical security risk — an attacker who re-enables such an account inherits all its permissions.
          </p>
        </div>
      )}

      {/* RBAC Access table */}
      {rbacAccess.length > 0 && (
        <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700">
            <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-200">RBAC Access</h3>
          </div>
          <table className="min-w-full text-left text-xs">
            <thead className="bg-gray-50 dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700 text-gray-600 dark:text-slate-400 uppercase tracking-wider font-medium">
              <tr>
                <th className="px-4 py-2">Identity</th>
                <th className="px-4 py-2">Category</th>
                <th className="px-4 py-2">Role</th>
                <th className="px-4 py-2">Source</th>
                <th className="px-4 py-2">Scope</th>
                <th className="px-4 py-2">Risk</th>
                <th className="px-4 py-2">Flags</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-slate-700">
              {rbacAccess.map((id, i) => (
                <tr key={`rbac-${id.id}-${i}`} className={id.is_ghost ? 'bg-red-50/50 dark:bg-red-900/15' : id.over_privileged ? 'bg-red-50/40 dark:bg-red-900/10' : 'hover:bg-blue-50/40'}>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-1.5">
                      {id.id ? (
                        <Link to={`/identities/${id.id}`} className="text-blue-600 hover:underline font-medium">{id.display_name}</Link>
                      ) : (
                        <span className="text-gray-600">{id.display_name}</span>
                      )}
                      {!!id.is_ghost && (
                        <span className="px-1.5 py-0.5 bg-red-600 text-white rounded text-[9px] font-bold uppercase" title={`Account ${id.account_state || 'disabled'} — ghost access`}>Ghost</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <span className="px-1.5 py-0.5 rounded bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-slate-300 text-[10px] font-medium">
                      {(id.identity_category || '').replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-700 dark:text-slate-300">{id.role_name || '—'}</td>
                  <td className="px-4 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${SOURCE_BADGE[id.access_source || 'inherited'] || 'bg-gray-100 text-gray-600'}`}>
                      {id.access_source_label || id.access_source || '—'}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-600 dark:text-slate-400 text-[10px] truncate max-w-[180px]" title={id.scope}>{id.scope_type || '—'}</td>
                  <td className="px-4 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[safeLower(id.risk_level)] || 'bg-gray-100 text-gray-600'}`}>
                      {id.risk_level}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {!!id.over_privileged && (
                        <span className="px-1.5 py-0.5 bg-red-100 text-red-700 rounded text-[10px] font-bold">Over-Privileged</span>
                      )}
                      {!!id.is_ghost && (
                        <span className="px-1.5 py-0.5 bg-red-100 text-red-700 rounded text-[10px] font-bold">{id.account_state === 'deleted' ? 'Deleted' : 'Disabled'}</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Access Policy table (KV only) */}
      {isKeyVault && policyAccess.length > 0 && (
        <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700">
            <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-200">Access Policy Principals</h3>
          </div>
          <table className="min-w-full text-left text-xs">
            <thead className="bg-gray-50 dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700 text-gray-600 dark:text-slate-400 uppercase tracking-wider font-medium">
              <tr>
                <th className="px-4 py-2">Identity</th>
                <th className="px-4 py-2">Category</th>
                <th className="px-4 py-2">Permissions</th>
                <th className="px-4 py-2">Risk</th>
                <th className="px-4 py-2">Flags</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-slate-700">
              {policyAccess.map((id, i) => (
                <tr key={`pol-${id.id || i}`} className={id.is_ghost ? 'bg-red-50/50 dark:bg-red-900/15' : 'hover:bg-purple-50/40'}>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-1.5">
                      {id.id ? (
                        <Link to={`/identities/${id.id}`} className="text-blue-600 hover:underline font-medium">{id.display_name}</Link>
                      ) : (
                        <span className="text-gray-600 dark:text-slate-400">{id.display_name}</span>
                      )}
                      {!!id.is_ghost && (
                        <span className="px-1.5 py-0.5 bg-red-600 text-white rounded text-[9px] font-bold uppercase" title={`Account ${id.account_state || 'disabled'} — ghost access`}>Ghost</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <span className="px-1.5 py-0.5 rounded bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-slate-300 text-[10px] font-medium">
                      {(id.identity_category || '').replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {id.permissions_summary && Object.entries(id.permissions_summary).map(([cat, perms]) =>
                        (perms as string[]).length > 0 && (
                          <span key={cat} className="px-1.5 py-0.5 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 rounded text-[10px]">
                            {cat}: {(perms as string[]).join(', ')}
                          </span>
                        )
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[safeLower(id.risk_level)] || 'bg-gray-100 text-gray-600'}`}>
                      {id.risk_level}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    {!!id.is_ghost && (
                      <span className="px-1.5 py-0.5 bg-red-100 text-red-700 rounded text-[10px] font-bold">{id.account_state === 'deleted' ? 'Deleted' : 'Disabled'}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Compliance Tab ───────────────────────────────────────────────

function ComplianceTab({ resource }: { resource: ResourceData }) {
  const isStorage = resource.resource_type === 'storage_account';
  const mapping = isStorage ? STORAGE_COMPLIANCE : KEYVAULT_COMPLIANCE;

  const noExpiryKeys = (resource.keys_detail || []).filter(k => !k.expires_on).length;
  const noExpirySecrets = (resource.secrets_detail || []).filter(s => !s.expires_on).length;
  const expiringCerts90 = (resource.certs_detail || []).filter(c => {
    if (!c.expires_on) return false;
    const ms = new Date(c.expires_on).getTime() - Date.now();
    return ms > 0 && ms < 90 * 86400000;
  }).length;

  const checks: { key: string; label: string; pass: boolean }[] = isStorage ? [
    { key: 'public_blob_access', label: 'Public Blob Access Disabled', pass: resource.public_blob_access === false },
    { key: 'https_only', label: 'HTTPS-Only Transfer', pass: resource.https_only === true },
    { key: 'minimum_tls_version', label: 'TLS 1.2 Minimum', pass: resource.minimum_tls_version === 'TLS1_2' },
    { key: 'customer_managed_keys', label: 'Customer-Managed Encryption Keys', pass: resource.customer_managed_keys === true },
    { key: 'default_network_action', label: 'Network Restricted', pass: resource.network_classification !== 'public' },
    { key: 'shared_key_access', label: 'Shared Key Access Disabled', pass: resource.shared_key_access === false },
    { key: 'infrastructure_encryption', label: 'Infrastructure Encryption', pass: resource.infrastructure_encryption === true },
    { key: 'cross_tenant_replication', label: 'Cross-Tenant Replication Disabled', pass: resource.allow_cross_tenant_replication === false },
    { key: 'key_rotation', label: 'Key Rotation (≤90 days)', pass: resource.key_rotation_stale === false },
    { key: 'private_endpoints', label: 'Private Endpoints Configured', pass: (resource.private_endpoint_count ?? 0) > 0 },
    { key: 'sas_policy', label: 'SAS Expiration Policy Enabled', pass: resource.sas_policy_enabled === true },
    { key: 'diagnostic_logging', label: 'Diagnostic Logging Enabled', pass: resource.diagnostic_logging_enabled === true },
    { key: 'bypass_limited', label: 'Bypass Limited to AzureServices', pass: resource.bypass_settings === 'AzureServices' },
  ] : [
    { key: 'soft_delete', label: 'Soft Delete Enabled', pass: resource.soft_delete_enabled === true },
    { key: 'purge_protection', label: 'Purge Protection Enabled', pass: resource.purge_protection === true },
    { key: 'rbac_authorization', label: 'RBAC Authorization', pass: resource.enable_rbac_authorization === true },
    { key: 'expired_secrets', label: 'No Expired Secrets/Keys/Certs', pass: (resource.secrets_expired ?? 0) === 0 && (resource.keys_expired ?? 0) === 0 && (resource.certs_expired ?? 0) === 0 },
    { key: 'network_access', label: 'Network Restricted', pass: resource.network_classification !== 'public' },
    { key: 'private_endpoints', label: 'Private Endpoints Configured', pass: (resource.private_endpoint_count ?? 0) > 0 },
    { key: 'key_expiry_set', label: 'All Keys Have Expiry Set', pass: (resource.keys_total ?? 0) === 0 || noExpiryKeys === 0 },
    { key: 'secret_expiry_set', label: 'All Secrets Have Expiry Set', pass: (resource.secrets_total ?? 0) === 0 || noExpirySecrets === 0 },
    { key: 'cert_expiry_check', label: 'No Certificates Expiring ≤90 Days', pass: expiringCerts90 === 0 },
    { key: 'retention_90d', label: 'Soft Delete Retention ≥90 Days', pass: (resource.soft_delete_retention_days ?? 0) >= 90 },
  ];

  const passCount = checks.filter(c => c.pass).length;
  const totalCount = checks.length;
  const scorePercent = totalCount > 0 ? Math.round((passCount / totalCount) * 100) : 0;

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className={`border rounded-lg p-4 ${
        scorePercent >= 80 ? 'bg-green-50 border-green-200' :
        scorePercent >= 50 ? 'bg-yellow-50 border-yellow-200' :
        'bg-red-50 border-red-200'
      }`}>
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-semibold text-gray-800">Compliance Score</div>
            <div className="text-xs text-gray-600 mt-0.5">{passCount} of {totalCount} checks passing</div>
          </div>
          <div className="text-3xl font-bold text-gray-800">{scorePercent}%</div>
        </div>
      </div>

      {/* Checks mapped to controls */}
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        <table className="min-w-full text-left text-xs">
          <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
            <tr>
              <th className="px-4 py-2 w-8">Status</th>
              <th className="px-4 py-2">Check</th>
              <th className="px-4 py-2">Compliance Controls</th>
              <th className="px-4 py-2">Description</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {checks.map(c => {
              const m = mapping[c.key];
              return (
                <tr key={c.key} className={c.pass ? '' : 'bg-red-50/30'}>
                  <td className="px-4 py-2.5 text-center">
                    <span className={`inline-flex items-center justify-center w-5 h-5 rounded-full text-[10px] font-bold ${
                      c.pass ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'
                    }`}>
                      {c.pass ? '✓' : '✗'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-medium text-gray-800">{c.label}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {m?.controls.map(ctrl => (
                        <span key={ctrl} className="px-1.5 py-0.5 bg-indigo-50 text-indigo-700 rounded text-[10px] font-medium">{ctrl}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-gray-600 max-w-xs">{m?.description || ''}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Risk Intelligence Tab (Phase 89) ────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
};

const ANOMALY_LABELS: Record<string, string> = {
  resource_score_spike: 'Risk Spike',
  config_drift_critical: 'Config Drift',
  shadow_infrastructure: 'Shadow Infra',
  expiry_cascade: 'Expiry Cascade',
  privilege_creep: 'Privilege Creep',
  network_exposure_change: 'Network Change',
};

function IntelligenceTab({ resource, anomalies }: { resource: ResourceData; anomalies: ResourceAnomaly[] }) {
  const trend = resource.risk_trend || [];
  const delta = resource.risk_trend_delta || 0;
  const direction = resource.risk_trend_direction || 'stable';
  const components = resource.risk_components || {};
  const unresolvedAnomalies = anomalies.filter(a => !a.resolved);

  // Bar chart max for scaling
  const maxScore = Math.max(...trend.map(t => t.risk_score), 1);

  return (
    <div className="space-y-6 py-2">
      {/* Trend Summary Header */}
      <div className="flex items-center gap-6">
        <div className="bg-white border border-gray-200 rounded-lg px-5 py-4 flex items-center gap-4 flex-1">
          <ScoreRing score={resource.risk_score} size={56} />
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Current Risk Score</div>
            <div className="text-2xl font-bold text-gray-800">{resource.risk_score}</div>
          </div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg px-5 py-4 flex items-center gap-3 flex-1">
          <div className={`text-2xl ${direction === 'up' ? 'text-red-500' : direction === 'down' ? 'text-green-500' : 'text-gray-400'}`}>
            {direction === 'up' ? '\u2191' : direction === 'down' ? '\u2193' : '\u2194'}
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Trend</div>
            <div className="text-lg font-semibold text-gray-800">
              {delta > 0 ? `+${delta}` : delta < 0 ? `${delta}` : 'Stable'}
              <span className="text-xs text-gray-500 ml-1">pts</span>
            </div>
          </div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg px-5 py-4 flex items-center gap-3 flex-1">
          <div className="text-2xl text-indigo-500">&#x26A0;</div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">Active Anomalies</div>
            <div className="text-lg font-semibold text-gray-800">{unresolvedAnomalies.length}</div>
          </div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg px-5 py-4 flex items-center gap-3 flex-1">
          <div className="text-2xl text-purple-500">&#x1F4CA;</div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider font-medium">History Depth</div>
            <div className="text-lg font-semibold text-gray-800">{trend.length} runs</div>
          </div>
        </div>
      </div>

      {/* Risk Score Trajectory */}
      <div className="bg-white border border-gray-200 rounded-lg p-5">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">Risk Score Trajectory</h3>
        {trend.length < 2 ? (
          <div className="text-center py-8 text-gray-400 text-sm">
            Insufficient history — at least 2 discovery runs required for trend analysis
          </div>
        ) : (
          <div className="flex items-end gap-1.5" style={{ height: 160 }}>
            {[...trend].reverse().map((t, i) => {
              const h = Math.max((t.risk_score / maxScore) * 140, 4);
              const color = t.risk_level === 'critical' ? 'bg-red-500' : t.risk_level === 'high' ? 'bg-orange-400' : t.risk_level === 'medium' ? 'bg-yellow-400' : 'bg-green-400';
              const date = t.run_date ? new Date(t.run_date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : `Run ${i + 1}`;
              return (
                <div key={i} className="flex flex-col items-center flex-1 gap-1">
                  <div className="text-[10px] text-gray-500 font-medium">{t.risk_score}</div>
                  <div className={`w-full rounded-t ${color}`} style={{ height: h }} title={`${date}: ${t.risk_score} (${t.risk_level})`} />
                  <div className="text-[9px] text-gray-400 truncate w-full text-center">{date}</div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Component Breakdown */}
      {Object.keys(components).length > 0 && (
        <div className="bg-white border border-gray-200 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">Risk Component Breakdown</h3>
          <div className="space-y-3">
            {Object.entries(components).map(([key, comp]) => {
              const c = comp as { score: number; max: number; pct: number; drivers: Array<{ name: string; points: number }> };
              const pct = c.pct || 0;
              const barColor = pct >= 80 ? 'bg-red-500' : pct >= 50 ? 'bg-orange-400' : pct >= 25 ? 'bg-yellow-400' : 'bg-green-400';
              return (
                <div key={key}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-medium text-gray-700 capitalize">{key.replace(/_/g, ' ')}</span>
                    <span className="text-gray-500">{c.score}/{c.max} ({pct}%)</span>
                  </div>
                  <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                    <div className={`h-full ${barColor} rounded-full transition-all`} style={{ width: `${pct}%` }} />
                  </div>
                  {c.drivers && c.drivers.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {c.drivers.map((d, di) => (
                        <span key={di} className="text-[10px] px-1.5 py-0.5 bg-gray-50 text-gray-600 rounded border border-gray-100">
                          {d.name} <span className="text-red-500 font-medium">+{d.points}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Critical Overrides */}
      {!!resource.critical_overrides && resource.critical_overrides.length > 0 && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-red-800 mb-2">Critical Overrides Active</h3>
          <ul className="space-y-1">
            {resource.critical_overrides.map((o, i) => (
              <li key={i} className="text-xs text-red-700 flex items-center gap-2">
                <span className="w-1.5 h-1.5 bg-red-500 rounded-full" />
                {o}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* AI-Detected Anomalies */}
      <div className="bg-white border border-gray-200 rounded-lg p-5">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">
          AI-Detected Anomalies
          {unresolvedAnomalies.length > 0 && (
            <span className="ml-2 px-1.5 py-0.5 bg-red-100 text-red-700 rounded text-[10px] font-bold">
              {unresolvedAnomalies.length}
            </span>
          )}
        </h3>
        {anomalies.length === 0 ? (
          <div className="text-center py-8 text-gray-400 text-sm">
            No anomalies detected for this resource
          </div>
        ) : (
          <div className="space-y-3">
            {anomalies.map(a => (
              <div key={a.id} className={`border rounded-lg p-4 ${a.resolved ? 'border-gray-200 bg-gray-50 opacity-60' : 'border-gray-200'}`}>
                <div className="flex items-center gap-2 mb-2">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_BADGE[a.severity] || SEVERITY_BADGE.medium}`}>
                    {a.severity.toUpperCase()}
                  </span>
                  <span className="px-1.5 py-0.5 bg-indigo-50 text-indigo-700 rounded text-[10px] font-medium">
                    {ANOMALY_LABELS[a.anomaly_type] || a.anomaly_type}
                  </span>
                  {a.resolved && <span className="px-1.5 py-0.5 bg-green-50 text-green-700 rounded text-[10px] font-medium">Resolved</span>}
                  <span className="ml-auto text-[10px] text-gray-400">{new Date(a.created_at).toLocaleDateString()}</span>
                </div>
                <div className="text-sm font-medium text-gray-800 mb-1">{a.title}</div>
                <div className="text-xs text-gray-600 mb-3">{a.description}</div>
                {a.details && (
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    {a.details.trigger && (
                      <div className="bg-gray-50 rounded px-2.5 py-1.5">
                        <span className="text-gray-500 font-medium">Trigger:</span>{' '}
                        <span className="text-gray-700">{String(a.details.trigger)}</span>
                      </div>
                    )}
                    {a.details.baseline !== undefined && (
                      <div className="bg-gray-50 rounded px-2.5 py-1.5">
                        <span className="text-gray-500 font-medium">Baseline:</span>{' '}
                        <span className="text-gray-700">{String(a.details.baseline)}</span>
                      </div>
                    )}
                    {a.details.deviation !== undefined && (
                      <div className="bg-gray-50 rounded px-2.5 py-1.5">
                        <span className="text-gray-500 font-medium">Deviation:</span>{' '}
                        <span className="text-gray-700">{String(a.details.deviation)}</span>
                      </div>
                    )}
                    {a.details.confidence !== undefined && (
                      <div className="bg-gray-50 rounded px-2.5 py-1.5">
                        <span className="text-gray-500 font-medium">Confidence:</span>{' '}
                        <span className="text-gray-700">{a.details.confidence}%</span>
                      </div>
                    )}
                    {a.details.impact && (
                      <div className="bg-orange-50 rounded px-2.5 py-1.5 col-span-2">
                        <span className="text-orange-600 font-medium">Impact:</span>{' '}
                        <span className="text-gray-700">{String(a.details.impact)}</span>
                      </div>
                    )}
                    {a.details.recommended_action && (
                      <div className="bg-blue-50 rounded px-2.5 py-1.5 col-span-2">
                        <span className="text-blue-600 font-medium">Action:</span>{' '}
                        <span className="text-gray-700">{String(a.details.recommended_action)}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
