import React, { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

type IdentityCategory =
  | 'service_principal'
  | 'managed_identity_system'
  | 'managed_identity_user'
  | 'human_user'
  | 'guest'
  | 'microsoft_internal'
  | 'unknown';

interface Owner {
  owner_object_id: string;
  owner_display_name?: string;
  owner_upn?: string;
  owner_type?: string;
  is_primary_owner?: boolean;
}

interface AttackPattern {
  attack_scenario: string;
  real_world_example: string;
  company_affected: string;
  breach_year: number;
  estimated_cost_usd: number;
}

interface HipaaViolation {
  hipaa_section: string;
  violation_explanation: string;
  violation_risk: string;
  typical_penalty_min: number;
  typical_penalty_max: number;
}

interface RoleIntelligence {
  role_name: string;
  attack_patterns: AttackPattern[];
  hipaa_violations: HipaaViolation[];
}

interface IdentityDetailsResponse {
  run_id: number;
  identity: {
    identity_id: string;
    display_name: string;
    identity_type?: string;
    identity_category?: IdentityCategory;
    risk_level?: RiskLevel;
    risk_score?: number;
    risk_reasons?: string[];

    credential_status?: string;
    credential_count?: number;
    credential_expiration?: string | null;

    created_datetime?: string | null;
    activity_status?: string | null;
    last_sign_in?: string | null;
    last_seen_auth?: string | null;

    enabled?: boolean;
    is_microsoft_system?: boolean;

    object_id?: string | null;
    app_id?: string | null;

    tags?: any;

    cloud?: string;
    normalized_identity_type?: string;
    principal_id?: string;
    tenant_or_org_id?: string;
    owner_display_name?: string | null;
    owner_count?: number;
    api_permission_count?: number;
    app_role_count?: number;
    status?: string;
  };
  roles: any[];
  graph_permissions: any[];
  app_roles: any[];
  owners: Owner[];
  role_intelligence: RoleIntelligence[];
}

type TabId = 'overview' | 'roles' | 'permissions' | 'credentials' | 'ownership' | 'compliance';

function safeLower(v: any) {
  return String(v ?? '').toLowerCase();
}

function normalizeCategoryFromBackend(raw?: any): string | undefined {
  const v = safeLower(raw).trim();
  if (!v) return undefined;

  const keys = [
    'service_principal', 'managed_identity_system', 'managed_identity_user',
    'human_user', 'guest', 'microsoft_internal', 'unknown',
  ];
  if (keys.includes(v)) return v;

  if (v.includes('user assigned') || v.includes('user-assigned')) return 'managed_identity_user';
  if (v.includes('system assigned') || v.includes('system-assigned')) return 'managed_identity_system';
  if (v === 'microsoft internal' || v.includes('microsoft')) return 'microsoft_internal';
  if (v === 'human user' || v === 'user') return 'human_user';
  if (v === 'guest') return 'guest';
  if (v === 'service principal' || v === 'serviceprincipal') return 'service_principal';

  return undefined;
}

function formatDate(iso?: string | null) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function formatUsd(n?: number): string {
  if (n == null || n === 0) return '—';
  if (n >= 1_000_000_000) return `$${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toLocaleString()}`;
}

function violationRiskColor(risk?: string): string {
  const r = (risk || '').toLowerCase();
  if (r === 'critical') return 'bg-red-100 text-red-800';
  if (r === 'high') return 'bg-orange-100 text-orange-800';
  if (r === 'medium') return 'bg-yellow-100 text-yellow-800';
  return 'bg-gray-100 text-gray-600';
}

function riskBadge(level?: string) {
  const v = safeLower(level);
  const base = 'px-2 py-1 rounded-full text-xs font-semibold inline-flex items-center';
  if (v === 'critical') return <span className={`${base} bg-red-100 text-red-700`}>CRITICAL</span>;
  if (v === 'high') return <span className={`${base} bg-orange-100 text-orange-700`}>HIGH</span>;
  if (v === 'medium') return <span className={`${base} bg-yellow-100 text-yellow-700`}>MEDIUM</span>;
  if (v === 'low') return <span className={`${base} bg-green-100 text-green-700`}>LOW</span>;
  if (v === 'info') return <span className={`${base} bg-blue-100 text-blue-700`}>INFO</span>;
  return <span className={`${base} bg-gray-100 text-gray-700`}>UNKNOWN</span>;
}

function usageStatusBadge(status?: string, redundantWith?: string) {
  const v = safeLower(status);
  const base = 'px-2 py-1 rounded-full text-xs font-semibold inline-flex items-center';

  if (v === 'orphaned') return <span className={`${base} bg-red-100 text-red-700`}>Orphaned</span>;
  if (v === 'definitely_unused') return <span className={`${base} bg-red-100 text-red-700`}>Unused</span>;
  if (v === 'likely_unused') return <span className={`${base} bg-orange-100 text-orange-700`}>Likely Unused</span>;
  if (v === 'possibly_overprivileged') {
    return (
      <span className={`${base} bg-yellow-100 text-yellow-700`} title={redundantWith ? `Redundant with: ${redundantWith}` : ''}>
        Over-Privileged
      </span>
    );
  }
  if (v === 'assumed_active') return <span className={`${base} bg-green-100 text-green-700`}>Active</span>;
  return <span className={`${base} bg-gray-100 text-gray-500`}>Unknown</span>;
}

function categoryLabel(catRaw?: any, typeRaw?: any) {
  const cat = normalizeCategoryFromBackend(catRaw) || safeLower(catRaw);
  const key = cat || safeLower(typeRaw);

  switch (key) {
    case 'service_principal': return 'Service Principal';
    case 'managed_identity_system': return 'System Assigned Identity';
    case 'managed_identity_user': return 'User Assigned Identity';
    case 'managed_identity': return 'User Assigned Identity';
    case 'human_user': return 'Human User';
    case 'guest': return 'Guest';
    case 'microsoft_internal': return 'Microsoft Internal';
    default: return 'Unknown';
  }
}

// Tab component
function TabBar({ activeTab, onTabChange, counts }: {
  activeTab: TabId;
  onTabChange: (tab: TabId) => void;
  counts: Record<TabId, number>;
}) {
  const tabs: { id: TabId; label: string; icon: string }[] = [
    { id: 'overview', label: 'Overview', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
    { id: 'roles', label: 'Roles', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
    { id: 'permissions', label: 'Permissions', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
    { id: 'credentials', label: 'Credentials', icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z' },
    { id: 'ownership', label: 'Ownership', icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z' },
    { id: 'compliance' as TabId, label: 'Compliance', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
  ];

  return (
    <div className="border-b bg-white rounded-t-xl">
      <nav className="flex -mb-px overflow-x-auto">
        {tabs.map(tab => {
          const isActive = activeTab === tab.id;
          const count = counts[tab.id];
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`
                flex items-center gap-2 px-5 py-3 text-sm font-medium border-b-2 transition whitespace-nowrap
                ${isActive
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}
              `}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
              </svg>
              {tab.label}
              {count > 0 && tab.id !== 'overview' && (
                <span className={`px-1.5 py-0.5 rounded-full text-xs ${
                  isActive ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-600'
                }`}>
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </nav>
    </div>
  );
}


export default function IdentityDetail() {
  const { id } = useParams<{ id: string }>();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<IdentityDetailsResponse | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/identities/${encodeURIComponent(id || '')}`);
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        const json = await res.json();
        if (!cancelled) setData(json);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load identity details');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    if (id) load();
    return () => { cancelled = true; };
  }, [id]);

  const identity = data?.identity;

  const groupedRoles = useMemo(() => {
    const roles = data?.roles || [];
    const azure = roles.filter((r: any) => safeLower(r.role_type) === 'azure');
    const entra = roles.filter((r: any) => safeLower(r.role_type) === 'entra');
    return { azure, entra };
  }, [data]);

  const intelByRole = useMemo(() => {
    const map: Record<string, RoleIntelligence> = {};
    (data?.role_intelligence || []).forEach(ri => { map[ri.role_name] = ri; });
    return map;
  }, [data]);

  const roleIntel = data?.role_intelligence || [];

  const tabCounts: Record<TabId, number> = {
    overview: 0,
    roles: (data?.roles || []).length,
    permissions: (data?.graph_permissions || []).length + (data?.app_roles || []).length,
    credentials: identity?.credential_count ?? 0,
    ownership: (data?.owners || []).length,
    compliance: roleIntel.length,
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="text-sm text-gray-500">
            <Link to="/identities" className="text-blue-600 hover:underline">← Back to Identities</Link>
          </div>
          <h2 className="text-2xl font-bold text-gray-900 mt-1">Identity Details</h2>
        </div>
      </div>

      {loading ? (
        <div className="animate-pulse space-y-4">
          <div className="h-32 bg-gray-100 rounded-xl" />
          <div className="h-8 bg-gray-100 rounded w-96" />
          <div className="h-64 bg-gray-100 rounded-xl" />
        </div>
      ) : error ? (
        <div className="bg-white border rounded-2xl p-6 text-red-600">{error}</div>
      ) : !identity ? (
        <div className="bg-white border rounded-2xl p-6 text-gray-600">Identity not found.</div>
      ) : (
        <>
          {/* Header card - always visible */}
          <div className="bg-white border rounded-2xl p-6 mb-4">
            <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
              <div>
                <div className="text-xl font-bold text-gray-900">{identity.display_name}</div>
                <div className="text-sm text-gray-500 mt-1 break-all font-mono">{identity.identity_id}</div>

                <div className="flex flex-wrap items-center gap-2 mt-3">
                  {riskBadge(identity.risk_level)}
                  {identity.risk_score !== undefined && (
                    <span className="px-2 py-1 rounded-full text-xs font-semibold bg-purple-100 text-purple-700">
                      {identity.risk_score} pts
                    </span>
                  )}
                  <span className="px-2 py-1 rounded-full text-xs font-semibold bg-blue-100 text-blue-700 uppercase">
                    {identity.cloud || 'azure'}
                  </span>
                  <span className="px-2 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-700">
                    {categoryLabel(identity.identity_category)}
                  </span>
                  {identity.enabled === false && (
                    <span className="px-2 py-1 rounded-full text-xs font-semibold bg-red-50 text-red-700">
                      Disabled
                    </span>
                  )}
                  {identity.is_microsoft_system && (
                    <span className="px-2 py-1 rounded-full text-xs font-semibold bg-blue-50 text-blue-700">
                      Microsoft Internal
                    </span>
                  )}
                </div>
              </div>

              {/* Key metrics */}
              <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-sm">
                <div className="text-gray-500">Created</div>
                <div className="font-medium text-gray-900">{formatDate(identity.created_datetime)}</div>

                <div className="text-gray-500">Last Sign-in</div>
                <div className="font-medium">
                  {identity.last_sign_in ? (
                    <span className="text-gray-900">{formatDate(identity.last_sign_in)}</span>
                  ) : (
                    <span className="text-gray-400 italic">Premium P1/P2 required</span>
                  )}
                </div>

                <div className="text-gray-500">Status</div>
                <div>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    identity.status === 'active' || identity.enabled !== false
                      ? 'bg-green-100 text-green-700'
                      : 'bg-red-100 text-red-700'
                  }`}>
                    {identity.status === 'active' || identity.enabled !== false ? 'Active' : 'Disabled'}
                  </span>
                </div>

                <div className="text-gray-500">Owner</div>
                <div className="font-medium text-gray-900">
                  {identity.owner_display_name || <span className="text-gray-400">No owner</span>}
                </div>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="bg-white border rounded-2xl overflow-hidden">
            <TabBar activeTab={activeTab} onTabChange={setActiveTab} counts={tabCounts} />

            <div className="p-6">
              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  {/* Quick stats grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-gray-50 rounded-xl p-4 text-center">
                      <div className="text-2xl font-bold text-gray-900">{(data?.roles || []).length}</div>
                      <div className="text-xs text-gray-500 mt-1">Total Roles</div>
                    </div>
                    <div className="bg-gray-50 rounded-xl p-4 text-center">
                      <div className="text-2xl font-bold text-purple-700">{identity.api_permission_count ?? 0}</div>
                      <div className="text-xs text-gray-500 mt-1">API Permissions</div>
                    </div>
                    <div className="bg-gray-50 rounded-xl p-4 text-center">
                      <div className="text-2xl font-bold text-gray-900">{identity.credential_count ?? 0}</div>
                      <div className="text-xs text-gray-500 mt-1">Credentials</div>
                    </div>
                    <div className="bg-gray-50 rounded-xl p-4 text-center">
                      <div className="text-2xl font-bold text-gray-900">{(data?.owners || []).length}</div>
                      <div className="text-xs text-gray-500 mt-1">Owners</div>
                    </div>
                  </div>

                  {/* Activity */}
                  <div>
                    <div className="text-sm font-semibold text-gray-900 mb-2">Activity Status</div>
                    <div className="text-sm">
                      {identity.last_sign_in ? (
                        <span className={
                          identity.activity_status === 'active' ? 'text-green-600 font-medium' :
                          identity.activity_status === 'inactive' ? 'text-yellow-600 font-medium' :
                          identity.activity_status === 'stale' ? 'text-orange-600 font-medium' :
                          'text-gray-600'
                        }>
                          {identity.activity_status === 'active' ? 'Active (signed in within 30 days)' :
                           identity.activity_status === 'inactive' ? 'Inactive (30-90 days since last sign-in)' :
                           identity.activity_status === 'stale' ? 'Stale (90+ days since last sign-in)' :
                           identity.activity_status || 'Unknown'}
                        </span>
                      ) : (
                        <span className="text-gray-400 italic">
                          Sign-in data unavailable — requires Azure AD Premium P1/P2
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Risk reasons */}
                  <div>
                    <div className="text-sm font-semibold text-gray-900 mb-2">Risk Reasons</div>
                    {identity.risk_reasons && identity.risk_reasons.length > 0 ? (
                      <ul className="space-y-2">
                        {identity.risk_reasons.map((r, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-sm text-gray-700">
                            <span className="text-red-500 mt-0.5">
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                              </svg>
                            </span>
                            {r}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="text-sm text-gray-500">No risk reasons recorded.</div>
                    )}
                  </div>
                </div>
              )}

              {/* Roles Tab */}
              {activeTab === 'roles' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Azure RBAC */}
                  <div>
                    <div className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                      Azure RBAC Roles
                      <span className="px-2 py-0.5 rounded-full text-xs bg-blue-100 text-blue-700">
                        {groupedRoles.azure.length}
                      </span>
                    </div>
                    {groupedRoles.azure.length === 0 ? (
                      <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No Azure RBAC roles assigned.</div>
                    ) : (
                      <div className="space-y-2">
                        {groupedRoles.azure.map((r: any, idx: number) => {
                          const intel = intelByRole[r.role_name];
                          return (
                          <div key={idx} className="border rounded-xl p-4">
                            <div className="flex items-center justify-between gap-2">
                              <div className="font-semibold text-gray-900 text-sm">{r.role_name}</div>
                              <div className="flex items-center gap-1">
                                {usageStatusBadge(r.usage_status, r.redundant_with)}
                                {riskBadge(r.risk_level)}
                              </div>
                            </div>
                            <div className="text-xs text-gray-500 mt-1 break-all">{r.scope}</div>
                            <div className="flex flex-wrap gap-2 mt-2 text-xs text-gray-500">
                              {r.days_since_assigned != null && (
                                <span>Assigned {r.days_since_assigned}d ago</span>
                              )}
                              {r.resource_type && <span>| {r.resource_type}</span>}
                              {!r.scope_exists && <span className="text-red-600">| Resource deleted</span>}
                              {r.redundant_with && <span className="text-yellow-600">| Redundant with {r.redundant_with}</span>}
                            </div>
                            {r.why_critical && (
                              <div className="text-xs text-gray-700 mt-2 bg-red-50 p-2 rounded">{r.why_critical}</div>
                            )}
                            {intel && (
                              <div className="flex items-center gap-2 mt-2">
                                {intel.attack_patterns.length > 0 && (
                                  <button onClick={() => setActiveTab('compliance')} className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-50 text-red-700 hover:bg-red-100 transition">
                                    {intel.attack_patterns.length} incident{intel.attack_patterns.length > 1 ? 's' : ''}
                                  </button>
                                )}
                                {intel.hipaa_violations.length > 0 && (
                                  <button onClick={() => setActiveTab('compliance')} className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-50 text-purple-700 hover:bg-purple-100 transition">
                                    {intel.hipaa_violations.length} HIPAA
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* Entra Directory Roles */}
                  <div>
                    <div className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                      Entra Directory Roles
                      <span className="px-2 py-0.5 rounded-full text-xs bg-indigo-100 text-indigo-700">
                        {groupedRoles.entra.length}
                      </span>
                    </div>
                    {groupedRoles.entra.length === 0 ? (
                      <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No Entra directory roles assigned.</div>
                    ) : (
                      <div className="space-y-2">
                        {groupedRoles.entra.map((r: any, idx: number) => {
                          const intel = intelByRole[r.role_name];
                          return (
                          <div key={idx} className="border rounded-xl p-4">
                            <div className="flex items-center justify-between gap-2">
                              <div className="font-semibold text-gray-900 text-sm">{r.role_name}</div>
                              <div className="flex items-center gap-1">
                                {usageStatusBadge(r.usage_status, r.redundant_with)}
                                {riskBadge(r.risk_level)}
                              </div>
                            </div>
                            <div className="text-xs text-gray-500 mt-1 break-all">{r.scope}</div>
                            <div className="flex flex-wrap gap-2 mt-2 text-xs text-gray-500">
                              {r.days_since_assigned != null && (
                                <span>Assigned {r.days_since_assigned}d ago</span>
                              )}
                              {r.redundant_with && <span className="text-yellow-600">| Redundant with {r.redundant_with}</span>}
                            </div>
                            {r.why_critical && (
                              <div className="text-xs text-gray-700 mt-2 bg-red-50 p-2 rounded">{r.why_critical}</div>
                            )}
                            {intel && (
                              <div className="flex items-center gap-2 mt-2">
                                {intel.attack_patterns.length > 0 && (
                                  <button onClick={() => setActiveTab('compliance')} className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-50 text-red-700 hover:bg-red-100 transition">
                                    {intel.attack_patterns.length} incident{intel.attack_patterns.length > 1 ? 's' : ''}
                                  </button>
                                )}
                                {intel.hipaa_violations.length > 0 && (
                                  <button onClick={() => setActiveTab('compliance')} className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-50 text-purple-700 hover:bg-purple-100 transition">
                                    {intel.hipaa_violations.length} HIPAA
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Permissions Tab */}
              {activeTab === 'permissions' && (
                <div className="space-y-6">
                  {/* Graph API Permissions */}
                  <div>
                    <div className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                      Microsoft Graph API Permissions
                      <span className="px-2 py-0.5 rounded-full text-xs bg-purple-100 text-purple-700">
                        {(data?.graph_permissions || []).length}
                      </span>
                    </div>
                    {(data?.graph_permissions || []).length === 0 ? (
                      <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No Graph API permissions discovered.</div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {data!.graph_permissions.map((p: any, idx: number) => (
                          <div key={idx} className="border rounded-xl p-4">
                            <div className="flex items-center justify-between gap-2">
                              <div className="font-semibold text-gray-900 text-sm">{p.permission_name}</div>
                              {riskBadge(p.risk_level)}
                            </div>
                            {p.permission_description && (
                              <div className="text-xs text-gray-600 mt-1">{p.permission_description}</div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* App Role Assignments */}
                  <div>
                    <div className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                      Application Role Assignments
                      <span className="px-2 py-0.5 rounded-full text-xs bg-indigo-100 text-indigo-700">
                        {(data?.app_roles || []).length}
                      </span>
                    </div>
                    {(data?.app_roles || []).length === 0 ? (
                      <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No custom app role assignments discovered.</div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {data!.app_roles.map((r: any, idx: number) => (
                          <div key={idx} className="border rounded-xl p-4">
                            <div className="flex items-center justify-between gap-2">
                              <div className="font-semibold text-gray-900 text-sm">{r.resource_display_name || 'App'}</div>
                              {riskBadge(r.risk_level)}
                            </div>
                            <div className="text-xs text-gray-500 mt-1 break-all">{r.resource_id}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Credentials Tab */}
              {activeTab === 'credentials' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-gray-50 rounded-xl p-4">
                      <div className="text-xs text-gray-500 mb-1">Credential Count</div>
                      <div className="text-2xl font-bold text-gray-900">{identity.credential_count ?? 0}</div>
                    </div>
                    <div className="bg-gray-50 rounded-xl p-4">
                      <div className="text-xs text-gray-500 mb-1">Status</div>
                      <div className="text-sm font-semibold">
                        {identity.credential_status ? (
                          <span className={
                            safeLower(identity.credential_status) === 'valid' ? 'text-green-700' :
                            safeLower(identity.credential_status) === 'expired' ? 'text-red-700' :
                            safeLower(identity.credential_status) === 'expiring_soon' ? 'text-orange-700' :
                            'text-gray-700'
                          }>
                            {identity.credential_status}
                          </span>
                        ) : (
                          <span className="text-gray-400">Unknown</span>
                        )}
                      </div>
                    </div>
                    <div className="bg-gray-50 rounded-xl p-4">
                      <div className="text-xs text-gray-500 mb-1">Next Expiration</div>
                      <div className="text-sm font-semibold text-gray-900">
                        {identity.credential_expiration ? (
                          <span className={
                            new Date(identity.credential_expiration) < new Date() ? 'text-red-700' :
                            new Date(identity.credential_expiration) < new Date(Date.now() + 30 * 86400000) ? 'text-orange-700' :
                            'text-green-700'
                          }>
                            {formatDate(identity.credential_expiration)}
                          </span>
                        ) : (
                          <span className="text-gray-400">No expiration</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {(identity.identity_category === 'human_user' || identity.identity_category === 'guest') && (
                    <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 text-sm text-blue-700">
                      Human users and guests authenticate via Entra ID credentials (passwords, MFA).
                      Secret/certificate tracking applies to service principals and managed identities.
                    </div>
                  )}
                </div>
              )}

              {/* Ownership Tab */}
              {activeTab === 'ownership' && (
                <div>
                  {(data?.owners || []).length === 0 ? (
                    <div className="text-center py-8">
                      <svg className="w-12 h-12 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                      </svg>
                      <div className="text-sm text-gray-500">No owners discovered for this identity.</div>
                      <div className="text-xs text-gray-400 mt-1">
                        Assigning owners ensures accountability and faster incident response.
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {data!.owners.map((o: Owner, idx: number) => (
                        <div key={idx} className="border rounded-xl p-4 flex items-center justify-between">
                          <div>
                            <div className="font-semibold text-gray-900">
                              {o.owner_display_name || o.owner_upn || o.owner_object_id}
                            </div>
                            {o.owner_upn && (
                              <div className="text-xs text-gray-500 mt-0.5">{o.owner_upn}</div>
                            )}
                            <div className="text-xs text-gray-400 mt-0.5">Type: {o.owner_type || 'user'}</div>
                          </div>
                          {o.is_primary_owner && (
                            <span className="px-2 py-1 rounded-full text-xs font-semibold bg-green-100 text-green-700">
                              Primary Owner
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Compliance & Intelligence Tab */}
              {activeTab === 'compliance' && (
                <div className="space-y-6">
                  {/* GRC Framework Summary */}
                  <div>
                    <div className="text-sm font-semibold text-gray-900 mb-3">GRC Framework Relevance</div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {(() => {
                        const risk = safeLower(identity.risk_level);
                        const hasPrivRoles = (data?.roles || []).length > 0;
                        const hasHipaa = roleIntel.some(ri => ri.hipaa_violations.length > 0);
                        const hasAttacks = roleIntel.some(ri => ri.attack_patterns.length > 0);
                        const isHuman = identity.identity_category === 'human_user' || identity.identity_category === 'guest';

                        const frameworks = [
                          {
                            name: 'SOC 2',
                            relevant: risk === 'critical' || risk === 'high' || (risk === 'medium' && hasPrivRoles),
                            reason: hasPrivRoles ? 'Privileged access requires SOC 2 CC6.1 controls' : 'Low-risk identity',
                          },
                          {
                            name: 'HIPAA',
                            relevant: hasHipaa || (isHuman && hasPrivRoles),
                            reason: hasHipaa ? `${roleIntel.reduce((s, r) => s + r.hipaa_violations.length, 0)} violation mappings found` : 'No HIPAA-relevant permissions',
                          },
                          {
                            name: 'PCI-DSS',
                            relevant: risk === 'critical' || risk === 'high',
                            reason: risk === 'critical' || risk === 'high' ? 'Req 7/8: Privileged access control' : 'Below PCI threshold',
                          },
                          {
                            name: 'NIST 800-53',
                            relevant: hasPrivRoles,
                            reason: hasPrivRoles ? 'AC-6: Least Privilege applies' : 'No privileged roles',
                          },
                        ];

                        return frameworks.map(fw => (
                          <div key={fw.name} className={`rounded-xl p-4 border ${fw.relevant ? 'bg-amber-50 border-amber-200' : 'bg-gray-50 border-gray-200'}`}>
                            <div className="flex items-center justify-between mb-1">
                              <span className="font-semibold text-sm text-gray-900">{fw.name}</span>
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${fw.relevant ? 'bg-amber-100 text-amber-800' : 'bg-gray-100 text-gray-500'}`}>
                                {fw.relevant ? 'Relevant' : 'Low'}
                              </span>
                            </div>
                            <div className="text-xs text-gray-600">{fw.reason}</div>
                          </div>
                        ));
                      })()}
                    </div>
                  </div>

                  {/* Per-Role Intelligence */}
                  {roleIntel.length === 0 ? (
                    <div className="text-center py-8">
                      <svg className="w-12 h-12 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <div className="text-sm text-gray-500">No compliance intelligence data for this identity's roles.</div>
                      <div className="text-xs text-gray-400 mt-1">
                        Attack patterns and HIPAA mappings are populated for privileged roles.
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="text-sm font-semibold text-gray-900">Per-Role Intelligence</div>
                      {roleIntel.map((ri, idx) => (
                        <div key={idx} className="border rounded-xl overflow-hidden">
                          {/* Role header */}
                          <div className="bg-gray-50 px-4 py-3 border-b flex items-center justify-between">
                            <div className="font-semibold text-gray-900 text-sm">{ri.role_name}</div>
                            <div className="flex items-center gap-2">
                              {ri.attack_patterns.length > 0 && (
                                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">
                                  {ri.attack_patterns.length} incident{ri.attack_patterns.length > 1 ? 's' : ''}
                                </span>
                              )}
                              {ri.hipaa_violations.length > 0 && (
                                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-purple-100 text-purple-700">
                                  {ri.hipaa_violations.length} HIPAA
                                </span>
                              )}
                            </div>
                          </div>

                          <div className="p-4 space-y-4">
                            {/* Attack Patterns / Real-World Incidents */}
                            {ri.attack_patterns.length > 0 && (
                              <div>
                                <div className="text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1">
                                  <svg className="w-3.5 h-3.5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                  </svg>
                                  Real-World Incidents
                                </div>
                                <div className="space-y-2">
                                  {ri.attack_patterns.map((ap, apIdx) => (
                                    <div key={apIdx} className="bg-red-50 border border-red-100 rounded-lg p-3">
                                      <div className="flex items-start justify-between gap-2">
                                        <div className="font-medium text-sm text-gray-900">{ap.attack_scenario}</div>
                                        {ap.estimated_cost_usd > 0 && (
                                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-200 text-red-900 whitespace-nowrap">
                                            {formatUsd(ap.estimated_cost_usd)}
                                          </span>
                                        )}
                                      </div>
                                      <div className="text-xs text-gray-700 mt-1">{ap.real_world_example}</div>
                                      <div className="flex items-center gap-3 mt-2 text-[10px] text-gray-500">
                                        {ap.company_affected && <span className="font-medium">{ap.company_affected}</span>}
                                        {ap.breach_year > 0 && <span>{ap.breach_year}</span>}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* HIPAA Violations */}
                            {ri.hipaa_violations.length > 0 && (
                              <div>
                                <div className="text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1">
                                  <svg className="w-3.5 h-3.5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                  </svg>
                                  HIPAA Violation Mappings
                                </div>
                                <div className="overflow-x-auto">
                                  <table className="min-w-full text-xs">
                                    <thead>
                                      <tr className="border-b text-gray-500">
                                        <th className="text-left py-1.5 pr-3 font-medium">Section</th>
                                        <th className="text-left py-1.5 pr-3 font-medium">Violation</th>
                                        <th className="text-left py-1.5 pr-3 font-medium">Risk</th>
                                        <th className="text-left py-1.5 font-medium">Penalty Range</th>
                                      </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-100">
                                      {ri.hipaa_violations.map((hv, hvIdx) => (
                                        <tr key={hvIdx}>
                                          <td className="py-2 pr-3 font-mono text-gray-700 whitespace-nowrap">{hv.hipaa_section}</td>
                                          <td className="py-2 pr-3 text-gray-700">{hv.violation_explanation}</td>
                                          <td className="py-2 pr-3">
                                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${violationRiskColor(hv.violation_risk)}`}>
                                              {hv.violation_risk}
                                            </span>
                                          </td>
                                          <td className="py-2 text-gray-700 whitespace-nowrap">
                                            {formatUsd(hv.typical_penalty_min)} – {formatUsd(hv.typical_penalty_max)}
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
