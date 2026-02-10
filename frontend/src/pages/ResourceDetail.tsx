import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { RISK_BADGE, RISK_SOLID, safeLower } from '../constants/metrics';

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
  risk_reasons: string[];
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
  // Network (shared)
  default_network_action?: string;
  ip_rules_count?: number;
  vnet_rules_count?: number;
  private_endpoint_count?: number;
  bypass_settings?: string;
  network_rules?: Record<string, unknown>;
}

interface AccessIdentity {
  id: number;
  display_name: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  role_name: string;
  scope: string;
  scope_type: string;
}

type Tab = 'overview' | 'security' | 'network' | 'access' | 'compliance';

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

  const [resource, setResource] = useState<ResourceData | null>(null);
  const [accessIdentities, setAccessIdentities] = useState<AccessIdentity[]>([]);
  const [accessLoading, setAccessLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<Tab>('overview');

  // Fetch resource detail
  useEffect(() => {
    if (!rid) return;
    setLoading(true);
    fetch(`/api/resources/${encodeURIComponent(rid)}`)
      .then(r => r.json())
      .then(data => { setResource(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, [rid]);

  // Lazy-load access tab
  useEffect(() => {
    if (activeTab !== 'access' || !rid || accessIdentities.length > 0) return;
    setAccessLoading(true);
    fetch(`/api/resources/${encodeURIComponent(rid)}/access`)
      .then(r => r.json())
      .then(data => { setAccessIdentities(data.identities || []); setAccessLoading(false); })
      .catch(() => setAccessLoading(false));
  }, [activeTab, rid, accessIdentities.length]);

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
        {activeTab === 'access' && <AccessTab identities={accessIdentities} loading={accessLoading} />}
        {activeTab === 'compliance' && <ComplianceTab resource={resource} />}
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
            <div className="text-[10px] text-gray-500">{resource.risk_score} / 200 points</div>
          </div>
        </div>
        {resource.risk_reasons.length > 0 ? (
          <ul className="space-y-1.5">
            {resource.risk_reasons.map((reason, i) => (
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
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-2">Transport & Access</h3>
          <CheckItem label="HTTPS-Only Transfer" pass={resource.https_only === true} detail={resource.https_only ? 'Enabled' : 'HTTP traffic allowed'} />
          <CheckItem label="TLS Version" pass={resource.minimum_tls_version === 'TLS1_2'} detail={`Current: ${resource.minimum_tls_version || 'Unknown'}`} />
          <CheckItem label="Public Blob Access Disabled" pass={resource.public_blob_access === false} detail={resource.public_blob_access ? 'Public access enabled — containers may be exposed' : 'Disabled'} />
          <CheckItem label="Shared Key Access Disabled" pass={resource.shared_key_access === false} detail={resource.shared_key_access ? 'Enabled — consider Azure AD auth only' : 'Disabled, Azure AD auth required'} />
          <CheckItem label="Cross-Tenant Replication" pass={resource.allow_cross_tenant_replication === false} detail={resource.allow_cross_tenant_replication ? 'Enabled' : 'Disabled'} />
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-2">Encryption & Keys</h3>
          <CheckItem label="Customer-Managed Keys" pass={resource.customer_managed_keys === true} detail={resource.customer_managed_keys ? `Key Vault: ${resource.key_vault_uri || 'configured'}` : 'Using Microsoft-managed keys'} />
          <CheckItem label="Infrastructure Encryption" pass={resource.infrastructure_encryption === true} detail={resource.infrastructure_encryption ? 'Double encryption enabled' : 'Single layer encryption'} />
          <CheckItem label="Storage Key Rotation" pass={resource.key_rotation_stale === false} detail={keyRotationDetail(resource)} />
        </div>
      </div>
    );
  }

  // Key Vault
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="bg-white border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-800 mb-2">Vault Security</h3>
        <CheckItem label="Soft Delete" pass={resource.soft_delete_enabled === true} detail={resource.soft_delete_enabled ? `Enabled (${resource.soft_delete_retention_days || 90} day retention)` : 'Disabled — deleted secrets are permanently lost'} />
        <CheckItem label="Purge Protection" pass={resource.purge_protection === true} detail={resource.purge_protection ? 'Enabled' : 'Disabled — soft-deleted items can be purged immediately'} />
        <CheckItem label="RBAC Authorization" pass={resource.enable_rbac_authorization === true} detail={resource.enable_rbac_authorization ? 'Azure RBAC for data plane' : `Access Policies mode (${resource.access_policy_count || 0} policies)`} />
      </div>
      <div className="bg-white border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-800 mb-2">Secrets, Keys & Certificates</h3>
        <VaultItemRow label="Secrets" total={resource.secrets_total} expired={resource.secrets_expired} expiring={resource.secrets_expiring_soon} />
        <VaultItemRow label="Keys" total={resource.keys_total} expired={resource.keys_expired} expiring={resource.keys_expiring_soon} />
        <VaultItemRow label="Certificates" total={resource.certs_total} expired={resource.certs_expired} expiring={resource.certs_expiring_soon} />
      </div>
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

// ─── Network Tab ──────────────────────────────────────────────────

function NetworkTab({ resource }: { resource: ResourceData }) {
  const isAllow = resource.default_network_action === 'Allow';

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="bg-white border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Network Configuration</h3>

        {/* Default Action */}
        <div className="flex items-center justify-between py-2 border-b border-gray-100">
          <span className="text-sm text-gray-700">Default Action</span>
          <span className={`px-2 py-0.5 rounded text-xs font-bold ${isAllow ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
            {resource.default_network_action || 'Allow'}
          </span>
        </div>

        {resource.resource_type === 'key_vault' && (
          <div className="flex items-center justify-between py-2 border-b border-gray-100">
            <span className="text-sm text-gray-700">Public Network Access</span>
            <span className={`px-2 py-0.5 rounded text-xs font-bold ${
              resource.public_network_access === 'Enabled' ? 'bg-yellow-100 text-yellow-700' : 'bg-green-100 text-green-700'
            }`}>
              {resource.public_network_access || 'Enabled'}
            </span>
          </div>
        )}

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
        <div className={`rounded-lg p-4 text-sm ${isAllow ? 'bg-red-50 border border-red-200' : 'bg-green-50 border border-green-200'}`}>
          {isAllow ? (
            <>
              <div className="font-semibold text-red-800 mb-1">Open to All Networks</div>
              <p className="text-red-700 text-xs">
                This resource allows traffic from all networks by default.
                Consider restricting access using IP rules, VNet rules, or private endpoints.
              </p>
            </>
          ) : (
            <>
              <div className="font-semibold text-green-800 mb-1">Network Restricted</div>
              <p className="text-green-700 text-xs">
                Default action is Deny. Access is limited to configured IP rules ({resource.ip_rules_count || 0}),
                VNet rules ({resource.vnet_rules_count || 0}), and private endpoints ({resource.private_endpoint_count || 0}).
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Access Control Tab ───────────────────────────────────────────

function AccessTab({ identities, loading }: { identities: AccessIdentity[]; loading: boolean }) {
  if (loading) {
    return <div className="flex items-center justify-center h-32 text-gray-400 text-sm">Loading access data...</div>;
  }

  if (identities.length === 0) {
    return (
      <div className="bg-white border border-gray-200 rounded-lg p-6 text-center">
        <p className="text-gray-500 text-sm">No identities found with direct RBAC access to this resource.</p>
        <p className="text-xs text-gray-400 mt-1">Identities with inherited access through parent scopes may not be shown.</p>
      </div>
    );
  }

  return (
    <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-800">Identities with Access</h3>
        <span className="text-xs text-gray-500">{identities.length} identities</span>
      </div>
      <table className="min-w-full text-left text-xs">
        <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
          <tr>
            <th className="px-4 py-2">Identity</th>
            <th className="px-4 py-2">Category</th>
            <th className="px-4 py-2">Role</th>
            <th className="px-4 py-2">Scope Type</th>
            <th className="px-4 py-2">Risk</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {identities.map(id => (
            <tr key={id.id} className="hover:bg-blue-50/40">
              <td className="px-4 py-2">
                <Link to={`/identities/${id.id}`} className="text-blue-600 hover:underline font-medium">
                  {id.display_name}
                </Link>
              </td>
              <td className="px-4 py-2">
                <span className="px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 text-[10px] font-medium">
                  {(id.identity_category || '').replace(/_/g, ' ')}
                </span>
              </td>
              <td className="px-4 py-2 text-gray-700">{id.role_name}</td>
              <td className="px-4 py-2 text-gray-600">{id.scope_type || '—'}</td>
              <td className="px-4 py-2">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[safeLower(id.risk_level)] || 'bg-gray-100 text-gray-600'}`}>
                  {id.risk_level}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Compliance Tab ───────────────────────────────────────────────

function ComplianceTab({ resource }: { resource: ResourceData }) {
  const isStorage = resource.resource_type === 'storage_account';
  const mapping = isStorage ? STORAGE_COMPLIANCE : KEYVAULT_COMPLIANCE;

  const checks: { key: string; label: string; pass: boolean }[] = isStorage ? [
    { key: 'public_blob_access', label: 'Public Blob Access Disabled', pass: resource.public_blob_access === false },
    { key: 'https_only', label: 'HTTPS-Only Transfer', pass: resource.https_only === true },
    { key: 'minimum_tls_version', label: 'TLS 1.2 Minimum', pass: resource.minimum_tls_version === 'TLS1_2' },
    { key: 'customer_managed_keys', label: 'Customer-Managed Encryption Keys', pass: resource.customer_managed_keys === true },
    { key: 'default_network_action', label: 'Default Network Deny', pass: resource.default_network_action === 'Deny' },
    { key: 'shared_key_access', label: 'Shared Key Access Disabled', pass: resource.shared_key_access === false },
  ] : [
    { key: 'soft_delete', label: 'Soft Delete Enabled', pass: resource.soft_delete_enabled === true },
    { key: 'purge_protection', label: 'Purge Protection Enabled', pass: resource.purge_protection === true },
    { key: 'rbac_authorization', label: 'RBAC Authorization', pass: resource.enable_rbac_authorization === true },
    { key: 'expired_secrets', label: 'No Expired Secrets/Keys/Certs', pass: (resource.secrets_expired ?? 0) === 0 && (resource.keys_expired ?? 0) === 0 && (resource.certs_expired ?? 0) === 0 },
    { key: 'network_access', label: 'Network Restricted', pass: resource.default_network_action === 'Deny' },
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
