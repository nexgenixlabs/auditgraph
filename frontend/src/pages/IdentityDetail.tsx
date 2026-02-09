import React, { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useToast } from '../components/ToastProvider';
import { AccessGraphTab } from '../components/graph';
import {
  type IdentityCategory, type RiskLevel,
  RISK_BADGE, RISK_ORDER, CLOUD_BADGE, DATA_EXPLANATIONS, DORMANT_LABELS,
  safeLower, normalizeCategoryFromBackend, getCategoryLabel, getDormantStatus as getDormantStatusFromActivity,
} from '../constants/metrics';

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
  source?: string;
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

interface TrendData {
  previous_risk_level?: string | null;
  previous_risk_score?: number | null;
  risk_direction?: 'worsened' | 'improved' | 'unchanged' | 'new';
  is_new?: boolean;
}

interface EvidenceMetadata {
  run_id?: number;
  collected_at?: string | null;
  sources?: Record<string, string>;
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
    ca_coverage_status?: string | null;
    ca_mfa_enforced?: boolean;
  };
  roles: any[];
  graph_permissions: any[];
  app_roles: any[];
  owners: Owner[];
  role_intelligence: RoleIntelligence[];
  trend?: TrendData | null;
  evidence?: EvidenceMetadata;
}

type TabId = 'overview' | 'roles' | 'permissions' | 'credentials' | 'ownership' | 'access_graph' | 'compliance' | 'pim' | 'remediation' | 'lifecycle';

interface RemediationItem {
  id: number;
  title: string;
  description: string;
  steps: string[];
  impact: string;
  effort: string;
  priority_score: number;
  compliance_refs: string[];
  category: string;
  matched_reason: string;
}

interface RemediationData {
  identity_id: string;
  display_name: string;
  risk_level: string;
  remediations: RemediationItem[];
  summary: {
    total: number;
    critical_actions: number;
    quick_wins: number;
  };
}

type RemediationStatus = 'open' | 'acknowledged' | 'completed' | 'skipped';

interface RemediationAction {
  status: RemediationStatus;
  notes: string | null;
  updated_at: string | null;
}

type RemediationActionsMap = Record<number, RemediationAction>;

interface PimEligible {
  role_name: string;
  role_definition_id?: string;
  directory_scope?: string;
  assignment_type?: string;
  start_datetime?: string | null;
  end_datetime?: string | null;
  member_type?: string;
}

interface PimActivation {
  role_name: string;
  role_definition_id?: string;
  directory_scope?: string;
  status?: string;
  activation_start?: string | null;
  activation_end?: string | null;
  justification?: string | null;
  ticket_number?: string | null;
  ticket_system?: string | null;
  is_approval_required?: boolean;
  created_datetime?: string | null;
}

interface PimData {
  eligible_assignments: PimEligible[];
  activations: PimActivation[];
  overuse_metrics: {
    activation_frequency_30d: number;
    always_active_pattern: boolean;
    total_active_hours_30d: number;
  };
}

// safeLower and normalizeCategoryFromBackend imported from constants/metrics

function formatDate(iso?: string | null) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function daysUntil(iso?: string | null): number | null {
  if (!iso) return null;
  try {
    const diff = new Date(iso).getTime() - Date.now();
    return Math.ceil(diff / 86400000);
  } catch { return null; }
}

function credentialCountdown(iso?: string | null): React.ReactNode {
  const days = daysUntil(iso);
  if (days == null) return null;
  if (days < 0) return <span className="text-xs font-semibold text-red-600">Expired {Math.abs(days)}d ago</span>;
  if (days === 0) return <span className="text-xs font-semibold text-red-600">Expires today</span>;
  if (days <= 7) return <span className="text-xs font-semibold text-red-600">{days}d remaining</span>;
  if (days <= 30) return <span className="text-xs font-semibold text-orange-600">{days}d remaining</span>;
  if (days <= 90) return <span className="text-xs font-semibold text-yellow-600">{days}d remaining</span>;
  return <span className="text-xs text-green-600">{days}d remaining</span>;
}

function formatUsd(n?: number): string {
  if (n == null || n === 0) return '—';
  if (n >= 1_000_000_000) return `$${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toLocaleString()}`;
}

function violationRiskColor(risk?: string): string {
  return RISK_BADGE[safeLower(risk)] || 'bg-gray-100 text-gray-600';
}

function riskBadge(level?: string) {
  const v = safeLower(level);
  const base = 'px-2 py-1 rounded-full text-xs font-semibold inline-flex items-center';
  return <span className={`${base} ${RISK_BADGE[v] || 'bg-gray-100 text-gray-700'}`}>{(v || 'unknown').toUpperCase()}</span>;
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
  const cat = normalizeCategoryFromBackend(catRaw);
  if (cat !== 'unknown') return getCategoryLabel(cat);
  // Fallback to type-based lookup
  return getCategoryLabel(safeLower(typeRaw)) || 'Unknown';
}

// ─── Evidence / Data Source component (Pillar 5) ──────────────────

function DataSource({ label, apiSource, collectedAt }: { label: string; apiSource?: string; collectedAt?: string | null }) {
  return (
    <div className="flex items-center gap-2 text-[10px] text-gray-400 mt-1">
      <svg className="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
      <span>
        Source: <span className="text-gray-500 font-medium">{label}</span>
        {apiSource && <span className="ml-1 font-mono">{apiSource}</span>}
        {collectedAt && <span className="ml-1">· Collected {new Date(collectedAt).toLocaleDateString()}</span>}
      </span>
    </div>
  );
}

// ─── Privilege tier / Effective access helpers ─────────────────────

const TIER_CONFIG: Record<number, { label: string; name: string; color: string; borderColor: string; description: string }> = {
  0: { label: 'T0', name: 'Control Plane', color: 'bg-red-100 text-red-800 border-red-300', borderColor: 'border-red-200', description: 'Full tenant control — Global Admin, Privileged Role Admin' },
  1: { label: 'T1', name: 'Management Plane', color: 'bg-orange-100 text-orange-800 border-orange-300', borderColor: 'border-orange-200', description: 'Broad management access — User Admin, Exchange Admin, sub Owner' },
  2: { label: 'T2', name: 'Data / App Plane', color: 'bg-yellow-100 text-yellow-800 border-yellow-300', borderColor: 'border-yellow-200', description: 'Scoped data/app access — Contributor, Key Vault, risky Graph API perms' },
  3: { label: 'T3', name: 'Standard', color: 'bg-gray-100 text-gray-600 border-gray-300', borderColor: 'border-gray-200', description: 'No privileged roles — Reader, limited access' },
};

function computePrivilegeTier(roles: any[], graphPerms: any[]): { tier: number; reasons: string[] } {
  const reasons: string[] = [];
  let maxTier = 3;

  const t0Roles = ['Global Administrator', 'Privileged Role Administrator', 'Partner Tier2 Support'];
  const t1Roles = ['User Administrator', 'Exchange Administrator', 'Intune Administrator', 'Security Administrator', 'Compliance Administrator'];
  const t0Scopes = ['Owner'];
  const t1Scopes = ['Contributor'];

  for (const r of roles) {
    const name = r.role_name || '';
    const type = safeLower(r.role_type);
    const scope = r.scope || '';

    if (type === 'entra') {
      if (t0Roles.some(t => name.includes(t))) {
        if (maxTier > 0) maxTier = 0;
        reasons.push(`Entra: ${name}`);
      } else if (t1Roles.some(t => name.includes(t))) {
        if (maxTier > 1) maxTier = 1;
        reasons.push(`Entra: ${name}`);
      } else if (maxTier > 2) {
        maxTier = 2;
        reasons.push(`Entra: ${name}`);
      }
    } else {
      // Azure RBAC
      const isSubScope = scope.match(/^\/subscriptions\/[^/]+$/) || scope === '/';
      if (t0Scopes.some(t => name.includes(t)) && isSubScope) {
        if (maxTier > 0) maxTier = 0;
        reasons.push(`RBAC: ${name} at ${scope.substring(0, 60)}`);
      } else if (t1Scopes.some(t => name.includes(t)) && isSubScope) {
        if (maxTier > 1) maxTier = 1;
        reasons.push(`RBAC: ${name} at ${scope.substring(0, 60)}`);
      } else if (safeLower(r.risk_level) === 'critical' || safeLower(r.risk_level) === 'high') {
        if (maxTier > 2) maxTier = 2;
        reasons.push(`RBAC: ${name}`);
      }
    }
  }

  // Check Graph API permissions for T2 elevation
  const riskyPerms = graphPerms.filter(p => safeLower(p.risk_level) === 'critical' || safeLower(p.risk_level) === 'high');
  if (riskyPerms.length > 0 && maxTier > 2) {
    maxTier = 2;
    reasons.push(`${riskyPerms.length} high-risk Graph API permission${riskyPerms.length > 1 ? 's' : ''}`);
  }

  return { tier: maxTier, reasons: reasons.slice(0, 5) };
}

function parseEffectiveAccessScope(roles: any[]): { subscriptions: string[]; resourceGroups: string[]; tenantWide: boolean; entraScopes: string[] } {
  const subs = new Set<string>();
  const rgs = new Set<string>();
  const entraScopes = new Set<string>();
  let tenantWide = false;

  for (const r of roles) {
    const scope = r.scope || '';
    const type = safeLower(r.role_type);

    if (type === 'entra') {
      entraScopes.add(scope === '/' ? 'Tenant-wide' : scope);
      if (scope === '/') tenantWide = true;
    } else {
      const subMatch = scope.match(/\/subscriptions\/([^/]+)/);
      if (subMatch) subs.add(subMatch[1]);
      const rgMatch = scope.match(/\/resourceGroups\/([^/]+)/);
      if (rgMatch) rgs.add(rgMatch[1]);
      if (scope === '/') tenantWide = true;
    }
  }

  return { subscriptions: Array.from(subs), resourceGroups: Array.from(rgs), tenantWide, entraScopes: Array.from(entraScopes) };
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
    { id: 'access_graph' as TabId, label: 'Access Graph', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
    { id: 'pim' as TabId, label: 'PIM', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8zM10 14a2 2 0 104 0 2 2 0 00-4 0z' },
    { id: 'compliance' as TabId, label: 'Compliance', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
    { id: 'remediation' as TabId, label: 'Remediation', icon: 'M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z' },
    { id: 'lifecycle' as TabId, label: 'Lifecycle', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
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
  const { addToast } = useToast();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<IdentityDetailsResponse | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [pimData, setPimData] = useState<PimData | null>(null);
  const [pimLoading, setPimLoading] = useState(false);
  const [remediationData, setRemediationData] = useState<RemediationData | null>(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [remediationActions, setRemediationActions] = useState<RemediationActionsMap>({});
  const [actionLoading, setActionLoading] = useState<number | null>(null);
  const [lifecycleData, setLifecycleData] = useState<any>(null);
  const [lifecycleLoading, setLifecycleLoading] = useState(false);
  const [lifecycleFilter, setLifecycleFilter] = useState<string>('all');

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

  // Lazy-load PIM data when tab is selected
  useEffect(() => {
    if (activeTab !== 'pim' || pimData || pimLoading || !id) return;
    let cancelled = false;
    setPimLoading(true);
    fetch(`/api/identities/${encodeURIComponent(id)}/pim`)
      .then(res => res.ok ? res.json() : Promise.reject('PIM fetch failed'))
      .then(json => { if (!cancelled) setPimData(json); })
      .catch(() => { if (!cancelled) setPimData({ eligible_assignments: [], activations: [], overuse_metrics: { activation_frequency_30d: 0, always_active_pattern: false, total_active_hours_30d: 0 } }); })
      .finally(() => { if (!cancelled) setPimLoading(false); });
    return () => { cancelled = true; };
  }, [activeTab, id, pimData, pimLoading]);

  // Lazy-load Remediation data + action statuses when tab is selected
  useEffect(() => {
    if (activeTab !== 'remediation' || remediationData || remediationLoading || !id) return;
    let cancelled = false;
    setRemediationLoading(true);

    Promise.all([
      fetch(`/api/identities/${encodeURIComponent(id)}/remediations`).then(r => r.ok ? r.json() : null),
      fetch(`/api/identities/${encodeURIComponent(id)}/remediation-status`).then(r => r.ok ? r.json() : null),
    ])
      .then(([playbookJson, statusJson]) => {
        if (cancelled) return;
        setRemediationData(playbookJson || { identity_id: id, display_name: '', risk_level: '', remediations: [], summary: { total: 0, critical_actions: 0, quick_wins: 0 } });
        setRemediationActions(statusJson?.actions || {});
      })
      .catch(() => {
        if (!cancelled) {
          setRemediationData({ identity_id: id, display_name: '', risk_level: '', remediations: [], summary: { total: 0, critical_actions: 0, quick_wins: 0 } });
        }
      })
      .finally(() => { if (!cancelled) setRemediationLoading(false); });

    return () => { cancelled = true; };
  }, [activeTab, id, remediationData, remediationLoading]);

  // Lazy-load Lifecycle data when tab is selected
  useEffect(() => {
    if (activeTab !== 'lifecycle' || lifecycleData || lifecycleLoading || !id) return;
    let cancelled = false;
    setLifecycleLoading(true);
    fetch(`/api/identities/${encodeURIComponent(id)}/lifecycle`)
      .then(res => res.ok ? res.json() : Promise.reject('Lifecycle fetch failed'))
      .then(json => { if (!cancelled) setLifecycleData(json); })
      .catch(() => { if (!cancelled) setLifecycleData({ events: [], summary: { total_runs_observed: 0, first_seen: null, last_seen: null, risk_changes: 0, credential_events: 0, access_changes: 0, status_changes: 0 }, total_events: 0 }); })
      .finally(() => { if (!cancelled) setLifecycleLoading(false); });
    return () => { cancelled = true; };
  }, [activeTab, id, lifecycleData, lifecycleLoading]);

  const handleRemediationAction = async (playbookId: number, status: RemediationStatus, notes?: string) => {
    if (!id) return;
    setActionLoading(playbookId);
    try {
      const res = await fetch(`/api/identities/${encodeURIComponent(id)}/remediation-action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ playbook_id: playbookId, status, notes }),
      });
      if (res.ok) {
        const result = await res.json();
        setRemediationActions(prev => ({
          ...prev,
          [playbookId]: {
            status: result.status,
            notes: result.notes,
            updated_at: result.updated_at,
          },
        }));
        addToast(`Remediation marked as ${result.status}`, 'success');
      } else {
        addToast('Failed to update remediation status', 'error');
      }
    } catch {
      addToast('Failed to update remediation status', 'error');
    }
    finally {
      setActionLoading(null);
    }
  };

  const identity = data?.identity;

  const groupedRoles = useMemo(() => {
    const roles = data?.roles || [];
    const azure = roles.filter((r: any) => safeLower(r.role_type) === 'azure');
    const entra = roles.filter((r: any) => safeLower(r.role_type) === 'entra');
    return { azure, entra };
  }, [data]);

  // Pillar 4: Identity-centric computed values
  const privilegeTier = useMemo(() => computePrivilegeTier(data?.roles || [], data?.graph_permissions || []), [data]);
  const effectiveScope = useMemo(() => parseEffectiveAccessScope(data?.roles || []), [data]);

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
    access_graph: (data?.roles || []).length + (identity?.credential_count ?? 0),
    pim: (pimData?.eligible_assignments || []).length + (pimData?.activations || []).length,
    compliance: roleIntel.length,
    remediation: remediationData?.summary?.total ?? 0,
    lifecycle: lifecycleData?.total_events ?? 0,
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
                  {/* Trend badge (Pillar 6) */}
                  {data?.trend?.risk_direction === 'new' && (
                    <span className="px-2 py-1 rounded-full text-xs font-bold bg-indigo-100 text-indigo-700 border border-indigo-200">
                      NEW
                    </span>
                  )}
                  {data?.trend?.risk_direction === 'worsened' && (
                    <span className="px-2 py-1 rounded-full text-xs font-bold bg-red-100 text-red-700 border border-red-200" title={`Was ${data.trend.previous_risk_level || 'lower'} in previous run`}>
                      ↑ WORSENED
                    </span>
                  )}
                  {data?.trend?.risk_direction === 'improved' && (
                    <span className="px-2 py-1 rounded-full text-xs font-bold bg-green-100 text-green-700 border border-green-200" title={`Was ${data.trend.previous_risk_level || 'higher'} in previous run`}>
                      ↓ IMPROVED
                    </span>
                  )}
                  {identity.risk_score !== undefined && (
                    <span className="px-2 py-1 rounded-full text-xs font-semibold bg-purple-100 text-purple-700">
                      {identity.risk_score} pts
                      {data?.trend?.previous_risk_score != null && data.trend.risk_direction !== 'new' && (
                        <span className="ml-1 opacity-70">
                          (was {data.trend.previous_risk_score})
                        </span>
                      )}
                    </span>
                  )}
                  {(() => {
                    const tc = TIER_CONFIG[privilegeTier.tier];
                    return (
                      <span
                        className={`px-2 py-1 rounded-full border text-xs font-bold ${tc.color}`}
                        title={`${tc.name}: ${tc.description}`}
                      >
                        {tc.label}
                      </span>
                    );
                  })()}
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
                <div className="font-medium text-gray-900">
                  {identity.created_datetime
                    ? formatDate(identity.created_datetime)
                    : <span className="text-gray-400 italic" title="Creation date not available from Graph API for this identity type">Unknown</span>
                  }
                </div>

                <div className="text-gray-500">Last Sign-in</div>
                <div className="font-medium">
                  {identity.last_sign_in ? (
                    <span className="text-gray-900">{formatDate(identity.last_sign_in)}</span>
                  ) : (
                    <span className="text-gray-400 italic" title={DATA_EXPLANATIONS.SIGN_IN}>Unknown — P1/P2 required</span>
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
                <div className="font-medium">
                  {identity.owner_display_name
                    ? <span className="text-gray-900">{identity.owner_display_name}</span>
                    : <span className="text-orange-600" title="No owner assigned — assign an owner for accountability and incident response">Unowned</span>
                  }
                </div>
              </div>
            </div>

            {/* Evidence trail */}
            {data?.evidence && (
              <div className="mt-4 pt-3 border-t flex items-center gap-4 text-[10px] text-gray-400">
                <div className="flex items-center gap-1.5">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Run #{data.evidence.run_id}
                </div>
                {data.evidence.collected_at && (
                  <div className="flex items-center gap-1.5">
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Collected {new Date(data.evidence.collected_at).toLocaleString()}
                  </div>
                )}
                <div className="flex items-center gap-1.5">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
                  </svg>
                  Microsoft Graph API + Azure Resource Manager
                </div>
              </div>
            )}
          </div>

          {/* Tabs */}
          <div className="bg-white border rounded-2xl overflow-hidden">
            <TabBar activeTab={activeTab} onTabChange={setActiveTab} counts={tabCounts} />

            <div className="p-6">
              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  {/* Identity Security Posture — 4-quadrant view */}
                  <div>
                    <div className="text-sm font-semibold text-gray-900 mb-3">Identity Security Posture</div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {/* Activity */}
                      {(() => {
                        const dormant = getDormantStatusFromActivity(identity.activity_status || undefined);
                        const dcfg = DORMANT_LABELS[dormant];
                        return (
                          <div className="border rounded-xl p-4" title={dcfg.tooltip}>
                            <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider mb-2">Activity</div>
                            <span className={`px-2 py-1 rounded-full text-xs font-semibold ${dcfg.color}`}>{dcfg.label}</span>
                            <div className="text-[10px] text-gray-500 mt-2">
                              {identity.last_sign_in
                                ? `Last sign-in: ${formatDate(identity.last_sign_in)}`
                                : DATA_EXPLANATIONS.SIGN_IN
                              }
                            </div>
                          </div>
                        );
                      })()}

                      {/* Credentials */}
                      <div className="border rounded-xl p-4">
                        <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider mb-2">Credentials</div>
                        {(identity.identity_category === 'human_user' || identity.identity_category === 'guest') ? (
                          <span className="text-xs text-gray-400 italic">N/A (Entra ID auth)</span>
                        ) : (
                          <>
                            <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                              safeLower(identity.credential_status) === 'expired' ? 'bg-red-100 text-red-700' :
                              safeLower(identity.credential_status) === 'expiring_soon' ? 'bg-orange-100 text-orange-700' :
                              safeLower(identity.credential_status) === 'valid' ? 'bg-green-100 text-green-700' :
                              'bg-gray-100 text-gray-500'
                            }`}>
                              {identity.credential_status || 'No credentials'}
                            </span>
                            <div className="text-[10px] text-gray-500 mt-2">
                              {(identity.credential_count ?? 0)} secret{(identity.credential_count ?? 0) !== 1 ? 's' : ''}/cert{(identity.credential_count ?? 0) !== 1 ? 's' : ''}
                              {identity.credential_expiration && (
                                <span className="ml-1">· {credentialCountdown(identity.credential_expiration)}</span>
                              )}
                            </div>
                          </>
                        )}
                      </div>

                      {/* Conditional Access */}
                      <div className="border rounded-xl p-4">
                        <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider mb-2">CA Coverage</div>
                        {identity.ca_coverage_status ? (
                          <>
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                                identity.ca_coverage_status === 'covered' ? 'bg-green-100 text-green-700' :
                                identity.ca_coverage_status === 'partial' ? 'bg-yellow-100 text-yellow-700' :
                                'bg-red-100 text-red-700'
                              }`}>
                                {identity.ca_coverage_status === 'covered' ? 'Covered' :
                                 identity.ca_coverage_status === 'partial' ? 'Partial' : 'Not Covered'}
                              </span>
                            </div>
                            <div className="text-[10px] text-gray-500 mt-2">
                              {identity.ca_mfa_enforced ? 'MFA enforced' : 'No MFA requirement'}
                            </div>
                          </>
                        ) : (
                          <span className="text-xs text-gray-400 italic" title={DATA_EXPLANATIONS.CA_POLICY}>Unknown</span>
                        )}
                      </div>

                      {/* PIM */}
                      <div className="border rounded-xl p-4">
                        <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider mb-2">PIM</div>
                        {pimData ? (
                          <>
                            <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                              pimData.eligible_assignments.length > 0 ? 'bg-emerald-100 text-emerald-700' : 'bg-gray-100 text-gray-500'
                            }`}>
                              {pimData.eligible_assignments.length > 0 ? `${pimData.eligible_assignments.length} eligible` : 'None'}
                            </span>
                            {pimData.overuse_metrics.always_active_pattern && (
                              <div className="text-[10px] text-red-600 mt-2 font-medium">Always-active pattern detected</div>
                            )}
                          </>
                        ) : (
                          <button
                            onClick={() => setActiveTab('pim')}
                            className="text-xs text-blue-600 hover:underline"
                          >
                            Load PIM data
                          </button>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Privilege Tier Explanation */}
                  {(() => {
                    const tc = TIER_CONFIG[privilegeTier.tier];
                    return (
                      <div className={`border rounded-xl p-4 ${tc.borderColor}`}>
                        <div className="flex items-center gap-3 mb-2">
                          <span className={`px-2.5 py-1 rounded-full border text-sm font-bold ${tc.color}`}>{tc.label}</span>
                          <div>
                            <div className="text-sm font-semibold text-gray-900">{tc.name}</div>
                            <div className="text-xs text-gray-500">{tc.description}</div>
                          </div>
                        </div>
                        {privilegeTier.reasons.length > 0 && (
                          <div className="mt-2 space-y-1">
                            <div className="text-[10px] uppercase font-semibold text-gray-400 tracking-wider">Classification reasons</div>
                            {privilegeTier.reasons.map((r, i) => (
                              <div key={i} className="text-xs text-gray-600 flex items-center gap-1.5">
                                <span className="w-1 h-1 rounded-full bg-gray-400 flex-shrink-0" />
                                {r}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })()}

                  {/* Effective Access Scope */}
                  {(effectiveScope.subscriptions.length > 0 || effectiveScope.entraScopes.length > 0 || (data?.roles || []).length > 0) && (
                    <div>
                      <div className="text-sm font-semibold text-gray-900 mb-3">Effective Access Scope</div>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        {/* Entra Directory */}
                        <div className="bg-indigo-50 border border-indigo-200 rounded-xl p-4">
                          <div className="text-[10px] uppercase font-semibold text-indigo-400 tracking-wider mb-2">Entra Directory</div>
                          <div className="text-lg font-bold text-indigo-700">{groupedRoles.entra.length} role{groupedRoles.entra.length !== 1 ? 's' : ''}</div>
                          <div className="text-[10px] text-gray-500 mt-1">
                            {effectiveScope.tenantWide
                              ? <span className="text-red-600 font-medium">Tenant-wide scope</span>
                              : effectiveScope.entraScopes.length > 0
                                ? `${effectiveScope.entraScopes.length} scoped`
                                : 'No Entra roles'
                            }
                          </div>
                        </div>

                        {/* Azure RBAC */}
                        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
                          <div className="text-[10px] uppercase font-semibold text-blue-400 tracking-wider mb-2">Azure RBAC</div>
                          <div className="text-lg font-bold text-blue-700">{groupedRoles.azure.length} role{groupedRoles.azure.length !== 1 ? 's' : ''}</div>
                          <div className="text-[10px] text-gray-500 mt-1">
                            {effectiveScope.subscriptions.length > 0
                              ? `${effectiveScope.subscriptions.length} sub${effectiveScope.subscriptions.length !== 1 ? 's' : ''}, ${effectiveScope.resourceGroups.length} RG${effectiveScope.resourceGroups.length !== 1 ? 's' : ''}`
                              : 'No RBAC roles'
                            }
                          </div>
                        </div>

                        {/* Graph API */}
                        <div className="bg-purple-50 border border-purple-200 rounded-xl p-4">
                          <div className="text-[10px] uppercase font-semibold text-purple-400 tracking-wider mb-2">Graph API</div>
                          <div className="text-lg font-bold text-purple-700">{identity.api_permission_count ?? 0} perm{(identity.api_permission_count ?? 0) !== 1 ? 's' : ''}</div>
                          <div className="text-[10px] text-gray-500 mt-1">
                            {(identity.app_role_count ?? 0) > 0 ? `+ ${identity.app_role_count} app role${(identity.app_role_count ?? 0) !== 1 ? 's' : ''}` : 'Application-level access'}
                          </div>
                        </div>
                      </div>

                      {/* Scope details */}
                      {effectiveScope.subscriptions.length > 0 && (
                        <div className="mt-3 text-xs text-gray-500">
                          <span className="font-medium text-gray-700">Subscriptions:</span>{' '}
                          {effectiveScope.subscriptions.map((s, i) => (
                            <span key={s}>
                              <span className="font-mono text-gray-600">{s.substring(0, 8)}...</span>
                              {i < effectiveScope.subscriptions.length - 1 && ', '}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Quick stats grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <button onClick={() => setActiveTab('roles')} className="bg-gray-50 rounded-xl p-4 text-center hover:bg-gray-100 transition">
                      <div className="text-2xl font-bold text-gray-900">{(data?.roles || []).length}</div>
                      <div className="text-xs text-gray-500 mt-1">Total Roles</div>
                    </button>
                    <button onClick={() => setActiveTab('permissions')} className="bg-gray-50 rounded-xl p-4 text-center hover:bg-gray-100 transition">
                      <div className="text-2xl font-bold text-purple-700">{identity.api_permission_count ?? 0}</div>
                      <div className="text-xs text-gray-500 mt-1">API Permissions</div>
                    </button>
                    <button onClick={() => setActiveTab('credentials')} className="bg-gray-50 rounded-xl p-4 text-center hover:bg-gray-100 transition">
                      <div className="text-2xl font-bold text-gray-900">{identity.credential_count ?? 0}</div>
                      <div className="text-xs text-gray-500 mt-1">Credentials</div>
                    </button>
                    <button onClick={() => setActiveTab('ownership')} className="bg-gray-50 rounded-xl p-4 text-center hover:bg-gray-100 transition">
                      <div className="text-2xl font-bold text-gray-900">{(data?.owners || []).length}</div>
                      <div className="text-xs text-gray-500 mt-1">Owners</div>
                    </button>
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
                <div>
                  <DataSource label="Azure Resource Manager + Microsoft Graph API" apiSource="/roleAssignments, /roleManagement/directory" collectedAt={data?.evidence?.collected_at} />
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-3">
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
                </div>
              )}

              {/* Permissions Tab */}
              {activeTab === 'permissions' && (
                <div className="space-y-6">
                  <DataSource label="Microsoft Graph API" apiSource="/servicePrincipals/{id}/appRoleAssignments" collectedAt={data?.evidence?.collected_at} />
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
                  <DataSource label="Microsoft Graph API" apiSource="/applications/{id}/passwordCredentials + keyCredentials" collectedAt={data?.evidence?.collected_at} />
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-gray-50 rounded-xl p-4">
                      <div className="text-xs text-gray-500 mb-1">Credential Count</div>
                      {(identity.identity_category === 'human_user' || identity.identity_category === 'guest') ? (
                        <div className="text-sm text-gray-400 italic mt-1" title={DATA_EXPLANATIONS.CREDENTIAL_NA}>N/A — Entra ID auth</div>
                      ) : (identity.credential_count ?? 0) > 0 ? (
                        <div className="text-2xl font-bold text-gray-900">{identity.credential_count}</div>
                      ) : (
                        <div>
                          <div className="text-2xl font-bold text-gray-900">0</div>
                          <div className="text-[10px] text-gray-400">No secrets or certificates registered</div>
                        </div>
                      )}
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
                        ) : (identity.identity_category === 'human_user' || identity.identity_category === 'guest') ? (
                          <span className="text-gray-400 italic">N/A</span>
                        ) : (
                          <span className="text-gray-400 italic" title="No credentials registered for this identity">No credentials</span>
                        )}
                      </div>
                    </div>
                    <div className="bg-gray-50 rounded-xl p-4">
                      <div className="text-xs text-gray-500 mb-1">Next Expiration</div>
                      <div className="text-sm font-semibold text-gray-900">
                        {identity.credential_expiration ? (
                          <div>
                            <span className={
                              new Date(identity.credential_expiration) < new Date() ? 'text-red-700' :
                              new Date(identity.credential_expiration) < new Date(Date.now() + 30 * 86400000) ? 'text-orange-700' :
                              'text-green-700'
                            }>
                              {formatDate(identity.credential_expiration)}
                            </span>
                            <div className="mt-1">{credentialCountdown(identity.credential_expiration)}</div>
                          </div>
                        ) : (identity.credential_count ?? 0) > 0 ? (
                          <span className="text-yellow-600" title="Credentials exist but have no expiration set">No expiration set</span>
                        ) : (
                          <span className="text-gray-400 italic">N/A</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {(identity.identity_category === 'human_user' || identity.identity_category === 'guest') && (
                    <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 text-sm text-blue-700">
                      {DATA_EXPLANATIONS.CREDENTIAL_NA}.
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
                  <DataSource label="Microsoft Graph API" apiSource="/servicePrincipals/{id}/owners" collectedAt={data?.evidence?.collected_at} />
                </div>
              )}

              {/* Access Graph Tab */}
              {activeTab === 'access_graph' && identity && (
                <AccessGraphTab identityId={identity.identity_id} />
              )}

              {/* PIM Tab */}
              {activeTab === 'pim' && (
                <div className="space-y-6">
                  {pimLoading ? (
                    <div className="animate-pulse space-y-4">
                      <div className="h-20 bg-gray-100 rounded-xl" />
                      <div className="h-40 bg-gray-100 rounded-xl" />
                    </div>
                  ) : !pimData || (pimData.eligible_assignments.length === 0 && pimData.activations.length === 0) ? (
                    <div className="text-center py-8">
                      <svg className="w-12 h-12 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                      </svg>
                      <div className="text-sm text-gray-500">No PIM data available for this identity.</div>
                      <div className="text-xs text-gray-400 mt-1">
                        {DATA_EXPLANATIONS.PIM}. Eligible roles and activations will appear here when available.
                      </div>
                    </div>
                  ) : (
                    <>
                      {/* Overuse Metrics */}
                      <div>
                        <div className="text-sm font-semibold text-gray-900 mb-3">Overuse Metrics (Last 30 Days)</div>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div className="bg-gray-50 rounded-xl p-4">
                            <div className="text-xs text-gray-500 mb-1">Activations</div>
                            <div className={`text-2xl font-bold ${pimData.overuse_metrics.activation_frequency_30d > 10 ? 'text-orange-600' : 'text-gray-900'}`}>
                              {pimData.overuse_metrics.activation_frequency_30d}
                            </div>
                          </div>
                          <div className="bg-gray-50 rounded-xl p-4">
                            <div className="text-xs text-gray-500 mb-1">Total Active Hours</div>
                            <div className="text-2xl font-bold text-gray-900">
                              {pimData.overuse_metrics.total_active_hours_30d}h
                            </div>
                          </div>
                          <div className="bg-gray-50 rounded-xl p-4">
                            <div className="text-xs text-gray-500 mb-1">Always-Active Pattern</div>
                            <div className="text-sm font-semibold mt-1">
                              {pimData.overuse_metrics.always_active_pattern ? (
                                <span className="px-2 py-1 rounded-full text-xs bg-red-100 text-red-700">Detected</span>
                              ) : (
                                <span className="px-2 py-1 rounded-full text-xs bg-green-100 text-green-700">Not Detected</span>
                              )}
                            </div>
                          </div>
                        </div>
                        {pimData.overuse_metrics.always_active_pattern && (
                          <div className="mt-3 bg-red-50 border border-red-200 rounded-xl p-3 text-sm text-red-700">
                            This identity is active &gt;80% of the time via PIM. Consider converting to a permanent (non-PIM) assignment or reviewing if JIT governance is being bypassed.
                          </div>
                        )}
                      </div>

                      {/* Eligible Roles */}
                      <div>
                        <div className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
                          Eligible Roles
                          <span className="px-2 py-0.5 rounded-full text-xs bg-emerald-100 text-emerald-700">
                            {pimData.eligible_assignments.length}
                          </span>
                        </div>
                        {pimData.eligible_assignments.length === 0 ? (
                          <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No PIM eligible roles.</div>
                        ) : (
                          <div className="overflow-x-auto">
                            <table className="min-w-full text-sm">
                              <thead>
                                <tr className="border-b text-gray-500 text-xs">
                                  <th className="text-left py-2 pr-4 font-medium">Role Name</th>
                                  <th className="text-left py-2 pr-4 font-medium">Scope</th>
                                  <th className="text-left py-2 pr-4 font-medium">Type</th>
                                  <th className="text-left py-2 pr-4 font-medium">Member</th>
                                  <th className="text-left py-2 font-medium">Expiration</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-gray-100">
                                {pimData.eligible_assignments.map((ea, idx) => (
                                  <tr key={idx}>
                                    <td className="py-2.5 pr-4 font-medium text-gray-900">{ea.role_name}</td>
                                    <td className="py-2.5 pr-4 text-gray-600 text-xs font-mono">{ea.directory_scope || '/'}</td>
                                    <td className="py-2.5 pr-4">
                                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                        ea.assignment_type === 'permanent_eligible'
                                          ? 'bg-red-100 text-red-700'
                                          : 'bg-blue-100 text-blue-700'
                                      }`}>
                                        {ea.assignment_type === 'permanent_eligible' ? 'Permanent' : 'Time-Bound'}
                                      </span>
                                    </td>
                                    <td className="py-2.5 pr-4 text-gray-600 text-xs">{ea.member_type || '—'}</td>
                                    <td className="py-2.5 text-gray-600 text-xs">
                                      {ea.end_datetime ? formatDate(ea.end_datetime) : <span className="text-red-600 font-medium">No expiry</span>}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>

                      {/* Activation History */}
                      <div>
                        <div className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
                          Activation History
                          <span className="px-2 py-0.5 rounded-full text-xs bg-purple-100 text-purple-700">
                            {pimData.activations.length}
                          </span>
                        </div>
                        {pimData.activations.length === 0 ? (
                          <div className="text-sm text-gray-500 bg-gray-50 rounded-xl p-4">No PIM activation records.</div>
                        ) : (
                          <div className="overflow-x-auto">
                            <table className="min-w-full text-sm">
                              <thead>
                                <tr className="border-b text-gray-500 text-xs">
                                  <th className="text-left py-2 pr-4 font-medium">Role</th>
                                  <th className="text-left py-2 pr-4 font-medium">Status</th>
                                  <th className="text-left py-2 pr-4 font-medium">Start</th>
                                  <th className="text-left py-2 pr-4 font-medium">End</th>
                                  <th className="text-left py-2 pr-4 font-medium">Justification</th>
                                  <th className="text-left py-2 font-medium">Ticket</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-gray-100">
                                {pimData.activations.map((act, idx) => (
                                  <tr key={idx}>
                                    <td className="py-2.5 pr-4 font-medium text-gray-900">{act.role_name}</td>
                                    <td className="py-2.5 pr-4">
                                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                        act.status === 'Active' ? 'bg-green-100 text-green-700' :
                                        act.status === 'Expired' ? 'bg-gray-100 text-gray-600' :
                                        'bg-red-100 text-red-700'
                                      }`}>{act.status || '—'}</span>
                                    </td>
                                    <td className="py-2.5 pr-4 text-gray-600 text-xs">{formatDate(act.activation_start)}</td>
                                    <td className="py-2.5 pr-4 text-gray-600 text-xs">{formatDate(act.activation_end)}</td>
                                    <td className="py-2.5 pr-4 text-gray-600 text-xs max-w-[200px] truncate" title={act.justification || ''}>
                                      {act.justification || <span className="text-gray-300">—</span>}
                                    </td>
                                    <td className="py-2.5 text-gray-600 text-xs">
                                      {act.ticket_number ? (
                                        <span className="font-mono">{act.ticket_number}</span>
                                      ) : (
                                        <span className="text-gray-300">—</span>
                                      )}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    </>
                  )}
                  <DataSource label="Microsoft Graph API" apiSource="/roleManagement/directory/roleEligibilityScheduleInstances" collectedAt={data?.evidence?.collected_at} />
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
                                      {ap.source && (
                                        <div className="mt-1.5 text-[10px] text-gray-400 italic">
                                          Source: {ap.source}
                                        </div>
                                      )}
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
                  <DataSource label="AuditGraph Intelligence Engine" apiSource="Role-based GRC mapping" collectedAt={data?.evidence?.collected_at} />
                </div>
              )}

              {/* ═══ REMEDIATION TAB ═══ */}
              {activeTab === 'remediation' && (
                <div className="space-y-6">
                  {remediationLoading ? (
                    <div className="animate-pulse space-y-4">
                      {[1, 2, 3].map(i => <div key={i} className="h-32 bg-gray-100 rounded-xl" />)}
                    </div>
                  ) : !remediationData || remediationData.remediations.length === 0 ? (
                    <div className="text-center py-12">
                      <svg className="w-12 h-12 text-green-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <div className="text-sm font-medium text-gray-600">No remediations needed</div>
                      <div className="text-xs text-gray-400 mt-1">This identity has no risk factors matching the remediation playbook library.</div>
                    </div>
                  ) : (
                    <>
                      {/* Summary bar */}
                      <div className="grid grid-cols-5 gap-4">
                        <div className="bg-gray-50 rounded-xl p-4 text-center">
                          <div className="text-2xl font-bold text-gray-900">{remediationData.summary.total}</div>
                          <div className="text-xs text-gray-500 mt-1">Total Actions</div>
                        </div>
                        <div className="bg-red-50 rounded-xl p-4 text-center">
                          <div className="text-2xl font-bold text-red-700">{remediationData.summary.critical_actions}</div>
                          <div className="text-xs text-red-600 mt-1">Critical</div>
                        </div>
                        <div className="bg-green-50 rounded-xl p-4 text-center">
                          <div className="text-2xl font-bold text-green-700">{remediationData.summary.quick_wins}</div>
                          <div className="text-xs text-green-600 mt-1">Quick Wins</div>
                        </div>
                        <div className="bg-green-50 rounded-xl p-4 text-center">
                          <div className="text-2xl font-bold text-green-700">
                            {Object.values(remediationActions).filter(a => a.status === 'completed').length}
                          </div>
                          <div className="text-xs text-green-600 mt-1">Completed</div>
                        </div>
                        <div className="bg-blue-50 rounded-xl p-4 text-center">
                          <div className="text-2xl font-bold text-blue-700">
                            {Object.values(remediationActions).filter(a => a.status === 'acknowledged').length}
                          </div>
                          <div className="text-xs text-blue-600 mt-1">Acknowledged</div>
                        </div>
                      </div>

                      {/* Remediation cards */}
                      <div className="space-y-4">
                        {remediationData.remediations.map((rem, idx) => (
                          <RemediationCard
                            key={rem.id}
                            remediation={rem}
                            index={idx}
                            action={remediationActions[rem.id]}
                            onAction={(status, notes) => handleRemediationAction(rem.id, status, notes)}
                            loading={actionLoading === rem.id}
                          />
                        ))}
                      </div>
                    </>
                  )}
                  <DataSource label="AuditGraph Remediation Engine" apiSource="Pattern-matched playbook library" collectedAt={data?.evidence?.collected_at} />
                </div>
              )}

              {/* ─── Lifecycle Tab ─── */}
              {activeTab === 'lifecycle' && (
                <div className="space-y-6">
                  {lifecycleLoading ? (
                    <div className="animate-pulse space-y-4">
                      <div className="h-20 bg-gray-100 rounded-xl" />
                      {[1, 2, 3, 4].map(i => <div key={i} className="h-16 bg-gray-100 rounded-xl" />)}
                    </div>
                  ) : !lifecycleData || lifecycleData.total_events === 0 ? (
                    <div className="text-center py-12">
                      <svg className="w-12 h-12 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <div className="text-sm font-medium text-gray-600">No lifecycle events</div>
                      <div className="text-xs text-gray-400 mt-1">Run multiple discovery scans to build a change timeline.</div>
                    </div>
                  ) : (
                    <>
                      {/* Summary bar */}
                      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
                        <div className="bg-gray-50 rounded-xl p-3 text-center">
                          <div className="text-xl font-bold text-gray-900">{lifecycleData.summary.total_runs_observed}</div>
                          <div className="text-[10px] text-gray-500 mt-0.5">Runs Observed</div>
                        </div>
                        <div className="bg-gray-50 rounded-xl p-3 text-center">
                          <div className="text-xl font-bold text-gray-900">{lifecycleData.total_events}</div>
                          <div className="text-[10px] text-gray-500 mt-0.5">Total Events</div>
                        </div>
                        <div className="bg-red-50 rounded-xl p-3 text-center">
                          <div className="text-xl font-bold text-red-700">{lifecycleData.summary.risk_changes}</div>
                          <div className="text-[10px] text-red-600 mt-0.5">Risk Changes</div>
                        </div>
                        <div className="bg-orange-50 rounded-xl p-3 text-center">
                          <div className="text-xl font-bold text-orange-700">{lifecycleData.summary.credential_events}</div>
                          <div className="text-[10px] text-orange-600 mt-0.5">Credential Events</div>
                        </div>
                        <div className="bg-blue-50 rounded-xl p-3 text-center">
                          <div className="text-xl font-bold text-blue-700">{lifecycleData.summary.access_changes}</div>
                          <div className="text-[10px] text-blue-600 mt-0.5">Access Changes</div>
                        </div>
                        <div className="bg-purple-50 rounded-xl p-3 text-center">
                          <div className="text-xl font-bold text-purple-700">{lifecycleData.summary.status_changes}</div>
                          <div className="text-[10px] text-purple-600 mt-0.5">Status Changes</div>
                        </div>
                      </div>

                      {/* Date range */}
                      <div className="text-xs text-gray-500 flex items-center gap-2">
                        <span>First seen: {lifecycleData.summary.first_seen ? new Date(lifecycleData.summary.first_seen).toLocaleDateString() : 'N/A'}</span>
                        <span className="text-gray-300">|</span>
                        <span>Last seen: {lifecycleData.summary.last_seen ? new Date(lifecycleData.summary.last_seen).toLocaleDateString() : 'N/A'}</span>
                      </div>

                      {/* Category filter */}
                      <div className="flex items-center gap-2 flex-wrap">
                        {['all', 'risk', 'credential', 'access', 'lifecycle', 'activity', 'compliance'].map(cat => (
                          <button
                            key={cat}
                            onClick={() => setLifecycleFilter(cat)}
                            className={`px-3 py-1 rounded-lg text-xs font-medium border transition ${
                              lifecycleFilter === cat
                                ? 'bg-blue-600 text-white border-blue-600'
                                : 'bg-white text-gray-600 border-gray-300 hover:bg-gray-50'
                            }`}
                          >
                            {cat === 'all' ? 'All' : cat.charAt(0).toUpperCase() + cat.slice(1)}
                          </button>
                        ))}
                      </div>

                      {/* Timeline */}
                      <div className="relative">
                        {/* Vertical line */}
                        <div className="absolute left-[7px] top-2 bottom-2 w-0.5 bg-gray-200" />

                        <div className="space-y-0">
                          {(lifecycleData.events as any[])
                            .filter((ev: any) => lifecycleFilter === 'all' || ev.category === lifecycleFilter)
                            .map((ev: any, idx: number) => {
                              const sevColors: Record<string, string> = {
                                critical: 'bg-red-500',
                                high: 'bg-orange-500',
                                medium: 'bg-yellow-500',
                                info: 'bg-blue-400',
                              };
                              const catBadge: Record<string, string> = {
                                risk: 'bg-red-50 text-red-700',
                                credential: 'bg-orange-50 text-orange-700',
                                access: 'bg-blue-50 text-blue-700',
                                lifecycle: 'bg-purple-50 text-purple-700',
                                activity: 'bg-cyan-50 text-cyan-700',
                                compliance: 'bg-green-50 text-green-700',
                              };
                              return (
                                <div key={idx} className="flex items-start gap-4 py-3 group">
                                  {/* Dot */}
                                  <div className={`w-3.5 h-3.5 rounded-full flex-shrink-0 mt-0.5 ring-2 ring-white ${sevColors[ev.severity] || 'bg-gray-400'}`} />

                                  {/* Content */}
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <span className="text-sm font-medium text-gray-900">{ev.description}</span>
                                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${catBadge[ev.category] || 'bg-gray-100 text-gray-600'}`}>
                                        {ev.category}
                                      </span>
                                    </div>
                                    <div className="flex items-center gap-3 mt-0.5 text-[11px] text-gray-400">
                                      <span>{ev.timestamp ? new Date(ev.timestamp).toLocaleString() : 'Unknown'}</span>
                                      {ev.run_id && <span>Run #{ev.run_id}</span>}
                                      {ev.previous_value && ev.current_value && (
                                        <span className="font-mono text-gray-500">{ev.previous_value} &rarr; {ev.current_value}</span>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                          {(lifecycleData.events as any[]).filter((ev: any) => lifecycleFilter === 'all' || ev.category === lifecycleFilter).length === 0 && (
                            <div className="text-center py-8 text-sm text-gray-400">No events in this category.</div>
                          )}
                        </div>
                      </div>
                    </>
                  )}
                  <DataSource label="AuditGraph Lifecycle Engine" apiSource="Cross-run identity snapshot comparison" collectedAt={data?.evidence?.collected_at} />
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ═══ Remediation Card Component ═══ */

const STATUS_COLORS: Record<RemediationStatus, string> = {
  open: 'bg-gray-100 text-gray-600',
  acknowledged: 'bg-blue-100 text-blue-700',
  completed: 'bg-green-100 text-green-700',
  skipped: 'bg-yellow-100 text-yellow-700',
};

const STATUS_LABELS: Record<RemediationStatus, string> = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  completed: 'Completed',
  skipped: 'Skipped',
};

function RemediationCard({
  remediation,
  index,
  action,
  onAction,
  loading,
}: {
  remediation: RemediationItem;
  index: number;
  action?: RemediationAction;
  onAction: (status: RemediationStatus, notes?: string) => void;
  loading: boolean;
}) {
  const [expanded, setExpanded] = useState(false);

  const currentStatus: RemediationStatus = action?.status || 'open';

  const impactColors: Record<string, string> = {
    critical: 'bg-red-100 text-red-700',
    high: 'bg-orange-100 text-orange-700',
    medium: 'bg-yellow-100 text-yellow-700',
    low: 'bg-green-100 text-green-700',
  };

  const effortColors: Record<string, string> = {
    low: 'bg-green-100 text-green-700',
    medium: 'bg-yellow-100 text-yellow-700',
    high: 'bg-red-100 text-red-700',
  };

  const categoryLabels: Record<string, string> = {
    access_control: 'Access Control',
    credential_hygiene: 'Credential Hygiene',
    governance: 'Governance',
    monitoring: 'Monitoring',
  };

  // Contextual action buttons based on current status
  const availableActions: { status: RemediationStatus; label: string; color: string }[] = [];
  if (currentStatus === 'open') {
    availableActions.push(
      { status: 'acknowledged', label: 'Acknowledge', color: 'bg-blue-600 hover:bg-blue-700 text-white' },
      { status: 'completed', label: 'Mark Complete', color: 'bg-green-600 hover:bg-green-700 text-white' },
      { status: 'skipped', label: 'Skip', color: 'bg-gray-200 hover:bg-gray-300 text-gray-700' },
    );
  } else if (currentStatus === 'acknowledged') {
    availableActions.push(
      { status: 'completed', label: 'Mark Complete', color: 'bg-green-600 hover:bg-green-700 text-white' },
      { status: 'skipped', label: 'Skip', color: 'bg-gray-200 hover:bg-gray-300 text-gray-700' },
      { status: 'open', label: 'Reopen', color: 'bg-gray-200 hover:bg-gray-300 text-gray-700' },
    );
  } else if (currentStatus === 'completed') {
    availableActions.push(
      { status: 'open', label: 'Reopen', color: 'bg-gray-200 hover:bg-gray-300 text-gray-700' },
    );
  } else if (currentStatus === 'skipped') {
    availableActions.push(
      { status: 'open', label: 'Reopen', color: 'bg-gray-200 hover:bg-gray-300 text-gray-700' },
    );
  }

  return (
    <div className={`border rounded-xl overflow-hidden hover:shadow-md transition ${currentStatus === 'completed' ? 'opacity-60' : ''}`}>
      {/* Header — always visible */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left bg-white px-5 py-4 flex items-start justify-between gap-4"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-bold text-gray-400">P{index + 1}</span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${impactColors[remediation.impact] || 'bg-gray-100 text-gray-600'}`}>
              {remediation.impact}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${effortColors[remediation.effort] || 'bg-gray-100 text-gray-600'}`}>
              {remediation.effort} effort
            </span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-50 text-blue-700">
              {categoryLabels[remediation.category] || remediation.category}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${STATUS_COLORS[currentStatus]}`}>
              {STATUS_LABELS[currentStatus]}
            </span>
          </div>
          <div className="font-semibold text-sm text-gray-900">{remediation.title}</div>
          <div className="text-xs text-gray-500 mt-1 line-clamp-1">{remediation.description}</div>
        </div>
        <svg className={`w-5 h-5 text-gray-400 flex-shrink-0 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expandable content */}
      {expanded && (
        <div className="border-t bg-gray-50 px-5 py-4 space-y-4">
          <div className="text-xs text-gray-700">{remediation.description}</div>

          {/* Step-by-step instructions */}
          <div>
            <div className="text-xs font-semibold text-gray-700 mb-2">Step-by-Step Remediation</div>
            <ol className="space-y-2">
              {remediation.steps.map((step, sIdx) => (
                <li key={sIdx} className="flex gap-3 text-xs text-gray-700">
                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center font-bold text-[10px]">
                    {sIdx + 1}
                  </span>
                  <span className="pt-0.5">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          {/* Compliance references */}
          {remediation.compliance_refs.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-gray-700 mb-1.5">Compliance References</div>
              <div className="flex flex-wrap gap-1.5">
                {remediation.compliance_refs.map((ref, rIdx) => (
                  <span key={rIdx} className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-purple-50 text-purple-700 border border-purple-200">
                    {ref}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Action buttons */}
          <div className="border-t pt-3">
            <div className="flex items-center gap-2 flex-wrap">
              {availableActions.map(btn => (
                <button
                  key={btn.status}
                  onClick={(e) => { e.stopPropagation(); onAction(btn.status); }}
                  disabled={loading}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${btn.color} disabled:opacity-50`}
                >
                  {loading ? 'Updating...' : btn.label}
                </button>
              ))}
              {action?.updated_at && (
                <span className="text-[10px] text-gray-400 ml-auto">
                  Updated {new Date(action.updated_at).toLocaleString()}
                </span>
              )}
            </div>
            {action?.notes && (
              <div className="mt-2 text-[10px] text-gray-500 bg-white rounded p-2 border">
                {action.notes}
              </div>
            )}
          </div>

          {/* Matched reason */}
          <div className="text-[10px] text-gray-400 italic">
            Matched: {remediation.matched_reason}
          </div>
        </div>
      )}
    </div>
  );
}
