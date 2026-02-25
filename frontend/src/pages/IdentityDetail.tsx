import React, { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { useToast } from '../components/ToastProvider';
import { useConnection } from '../contexts/ConnectionContext';
import { AccessGraphTab } from '../components/graph';
import {
  type IdentityCategory, type RiskLevel,
  RISK_BADGE, DATA_EXPLANATIONS, DORMANT_LABELS,
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
    status_display?: { label: string; badge_class: string };
    deleted_at?: string | null;
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

type TabId = 'overview' | 'roles' | 'permissions' | 'credentials' | 'ownership' | 'access_graph' | 'anomalies' | 'compliance' | 'pim' | 'remediation' | 'lifecycle' | 'simulate' | 'timeline';

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
  execution_status?: string | null;
  execution_log?: {
    action_type?: string;
    result?: string;
    detail?: string;
    simulated?: boolean;
  } | null;
  executed_at?: string | null;
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
    { id: 'anomalies' as TabId, label: 'Anomalies', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z' },
    { id: 'pim' as TabId, label: 'PIM', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8zM10 14a2 2 0 104 0 2 2 0 00-4 0z' },
    { id: 'compliance' as TabId, label: 'Compliance', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
    { id: 'remediation' as TabId, label: 'Remediation', icon: 'M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z' },
    { id: 'lifecycle' as TabId, label: 'Lifecycle', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
    { id: 'simulate' as TabId, label: 'What If', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
    { id: 'timeline' as TabId, label: 'Timeline', icon: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' },
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
  const { withConnection } = useConnection();

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
  const [identityGroups, setIdentityGroups] = useState<{id: number; name: string; color: string; group_type: string}[]>([]);
  const [anomalyData, setAnomalyData] = useState<{anomalies: any[]; count: number} | null>(null);
  const [anomalyLoading, setAnomalyLoading] = useState(false);
  const [riskHistory, setRiskHistory] = useState<{run_id: number; date: string; risk_score: number; risk_level: string}[]>([]);
  const [correlatedAccounts, setCorrelatedAccounts] = useState<{
    human_identity: { id: number; display_name: string } | null;
    accounts: { id: number; object_id: string; display_name: string; upn: string; account_type: string; enabled: boolean; deleted: boolean; is_zombie: boolean; risk_score: number; risk_level: string; privilege_tier: string; link_method: string; link_confidence: number; verified: boolean }[];
    zombie_persona: boolean;
  } | null>(null);

  // Simulation state (What If tab)
  const [simRemovedRoles, setSimRemovedRoles] = useState<Set<string>>(new Set());
  const [simRemovedPerms, setSimRemovedPerms] = useState<Set<string>>(new Set());
  const [simAddedRoles, setSimAddedRoles] = useState<{role_name: string; role_type: string; scope_type: string}[]>([]);
  const [simAddedPerms, setSimAddedPerms] = useState<{permission_name: string; risk_level: string}[]>([]);
  const [simResult, setSimResult] = useState<{current: {risk_score: number; risk_level: string; risk_reasons: string[]}; simulated: {risk_score: number; risk_level: string; risk_reasons: string[]}; delta: number; level_change: string; removed_reasons: string[]; added_reasons: string[]} | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [simAddRoleOpen, setSimAddRoleOpen] = useState(false);
  const [simAddPermOpen, setSimAddPermOpen] = useState(false);
  const [simNewRole, setSimNewRole] = useState({role_name: '', role_type: 'azure', scope_type: 'subscription'});
  const [simNewPerm, setSimNewPerm] = useState({permission_name: '', risk_level: 'medium'});

  const runSimulation = async () => {
    if (!id) return;
    setSimulating(true);
    try {
      const res = await fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/simulate`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          remove_roles: Array.from(simRemovedRoles),
          add_roles: simAddedRoles,
          remove_permissions: Array.from(simRemovedPerms),
          add_permissions: simAddedPerms,
        }),
      });
      if (res.ok) {
        const result = await res.json();
        setSimResult(result);
      } else {
        addToast('Simulation failed', 'error');
      }
    } catch {
      addToast('Simulation failed', 'error');
    } finally {
      setSimulating(false);
    }
  };

  const resetSimulation = () => {
    setSimRemovedRoles(new Set());
    setSimRemovedPerms(new Set());
    setSimAddedRoles([]);
    setSimAddedPerms([]);
    setSimResult(null);
    setSimAddRoleOpen(false);
    setSimAddPermOpen(false);
  };

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(withConnection(`/api/identities/${encodeURIComponent(id || '')}`));
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

  // Fetch risk score history (non-blocking)
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/risk-history?limit=20`))
      .then(res => res.ok ? res.json() : null)
      .then(json => { if (!cancelled && json?.points) setRiskHistory(json.points); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [id]);

  // Fetch correlated accounts (non-blocking)
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    fetch(withConnection(`/api/correlation/accounts?identity_id=${encodeURIComponent(id)}`))
      .then(res => res.ok ? res.json() : null)
      .then(json => { if (!cancelled && json) setCorrelatedAccounts(json); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [id]);

  // Lazy-load PIM data when tab is selected
  useEffect(() => {
    if (activeTab !== 'pim' || pimData || pimLoading || !id) return;
    let cancelled = false;
    setPimLoading(true);
    fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/pim`))
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
      fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/remediations`)).then(r => r.ok ? r.json() : null),
      fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/remediation-status`)).then(r => r.ok ? r.json() : null),
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
    fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/lifecycle`))
      .then(res => res.ok ? res.json() : Promise.reject('Lifecycle fetch failed'))
      .then(json => { if (!cancelled) setLifecycleData(json); })
      .catch(() => { if (!cancelled) setLifecycleData({ events: [], summary: { total_runs_observed: 0, first_seen: null, last_seen: null, risk_changes: 0, credential_events: 0, access_changes: 0, status_changes: 0 }, total_events: 0 }); })
      .finally(() => { if (!cancelled) setLifecycleLoading(false); });
    return () => { cancelled = true; };
  }, [activeTab, id, lifecycleData, lifecycleLoading]);

  // Lazy-load Anomaly data when tab is selected
  useEffect(() => {
    if (activeTab !== 'anomalies' || anomalyData || anomalyLoading || !id) return;
    let cancelled = false;
    setAnomalyLoading(true);
    fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/anomalies`))
      .then(res => res.ok ? res.json() : Promise.reject('Anomalies fetch failed'))
      .then(json => { if (!cancelled) setAnomalyData(json); })
      .catch(() => { if (!cancelled) setAnomalyData({ anomalies: [], count: 0 }); })
      .finally(() => { if (!cancelled) setAnomalyLoading(false); });
    return () => { cancelled = true; };
  }, [activeTab, id, anomalyData, anomalyLoading]);

  // Load identity groups
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/groups`))
      .then(res => res.ok ? res.json() : Promise.reject('Groups fetch failed'))
      .then(json => { if (!cancelled) setIdentityGroups(json.groups || []); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [id]);

  const handleRemediationAction = async (playbookId: number, status: RemediationStatus, notes?: string) => {
    if (!id) return;
    setActionLoading(playbookId);
    try {
      const res = await fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/remediation-action`), {
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

  const [executeLoading, setExecuteLoading] = useState<number | null>(null);

  const handleRemediationExecute = async (playbookId: number, actionType: string) => {
    if (!id) return;
    setExecuteLoading(playbookId);
    try {
      const res = await fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/remediation-execute`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ playbook_id: playbookId, action_type: actionType }),
      });
      if (res.ok) {
        const result = await res.json();
        const act = result.action;
        setRemediationActions(prev => ({
          ...prev,
          [playbookId]: {
            status: act.status || 'completed',
            notes: act.notes,
            updated_at: act.updated_at,
            execution_status: act.execution_status,
            execution_log: act.execution_log,
            executed_at: act.executed_at,
          },
        }));
        const execLog = result.execution_log || {};
        addToast(
          `${execLog.simulated ? 'Simulated' : 'Executed'}: ${actionType.replace(/_/g, ' ')}`,
          execLog.result === 'error' ? 'error' : 'success'
        );
      } else {
        addToast('Remediation execution failed', 'error');
      }
    } catch {
      addToast('Remediation execution failed', 'error');
    } finally {
      setExecuteLoading(null);
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
    anomalies: anomalyData?.count ?? 0,
    pim: (pimData?.eligible_assignments || []).length + (pimData?.activations || []).length,
    compliance: roleIntel.length,
    remediation: remediationData?.summary?.total ?? 0,
    lifecycle: lifecycleData?.total_events ?? 0,
    simulate: 0,
    timeline: 0,
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
                    identity.status_display?.badge_class ||
                    (identity.status === 'active' ? 'bg-green-100 text-green-700' :
                     identity.status === 'disabled' ? 'bg-red-100 text-red-700' :
                     identity.status === 'deleted' ? 'bg-gray-100 text-gray-500' :
                     'bg-yellow-100 text-yellow-700')
                  }`}>
                    {identity.status_display?.label || identity.status || 'Unknown'}
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

          {/* Groups */}
          {identityGroups.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-medium text-gray-500">Groups:</span>
              {identityGroups.map(g => (
                <Link key={g.id} to={`/groups`}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium transition hover:opacity-80"
                  style={{ backgroundColor: g.color + '20', color: g.color }}>
                  {g.group_type === 'auto' && (
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                  )}
                  {g.name}
                </Link>
              ))}
            </div>
          )}

          {/* Tabs */}
          <div className="bg-white border rounded-2xl overflow-hidden">
            <TabBar activeTab={activeTab} onTabChange={setActiveTab} counts={tabCounts} />

            <div className="p-6">
              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  {/* Correlated Accounts / Zombie Warning */}
                  {correlatedAccounts && correlatedAccounts.accounts.length > 1 && (
                    <div>
                      {correlatedAccounts.zombie_persona && (
                        <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-3 flex items-start gap-3">
                          <svg className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                          </svg>
                          <div>
                            <div className="text-sm font-semibold text-red-800">Zombie Persona Detected</div>
                            <div className="text-xs text-red-600 mt-1">
                              This identity is part of a zombie persona — a disabled account retains access via this correlated active account.
                              The human behind these accounts may still have access despite their primary account being disabled.
                            </div>
                          </div>
                        </div>
                      )}
                      <div className="border rounded-xl p-4">
                        <div className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
                          Correlated Accounts
                          {correlatedAccounts.human_identity && (
                            <span className="text-xs font-normal text-gray-500">
                              — {correlatedAccounts.human_identity.display_name}
                            </span>
                          )}
                        </div>
                        <div className="space-y-2">
                          {correlatedAccounts.accounts.map((acct) => (
                            <div key={acct.id} className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-50">
                              <Link to={`/identities/${acct.id}`} className="text-sm font-medium text-blue-600 hover:underline flex-1 min-w-0 truncate">
                                {acct.display_name || acct.upn || acct.object_id}
                              </Link>
                              <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                                acct.account_type === 'privileged' ? 'bg-purple-100 text-purple-700' : 'bg-gray-100 text-gray-600'
                              }`}>
                                {acct.account_type}
                              </span>
                              {acct.enabled ? (
                                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-green-100 text-green-700">Active</span>
                              ) : (
                                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">
                                  {acct.deleted ? 'Deleted' : 'Disabled'}
                                </span>
                              )}
                              {acct.is_zombie && (
                                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700">Zombie</span>
                              )}
                              {acct.risk_level && (
                                <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                                  acct.risk_level === 'critical' ? 'bg-red-100 text-red-700' :
                                  acct.risk_level === 'high' ? 'bg-orange-100 text-orange-700' :
                                  acct.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                                  'bg-green-100 text-green-700'
                                }`}>
                                  {acct.risk_level}
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

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

                  {/* Risk Score Trajectory */}
                  {riskHistory.length >= 2 && (
                    <div className="border border-gray-200 rounded-xl p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <div className="text-sm font-semibold text-gray-900">Risk Score Trajectory</div>
                          <div className="text-[10px] text-gray-500">Score trend across discovery runs</div>
                        </div>
                        <div className="flex items-center gap-2 text-[10px] text-gray-500">
                          <span>{riskHistory.length} runs</span>
                          <span className="text-gray-300">|</span>
                          <span>
                            {riskHistory[0].risk_score} pts → {riskHistory[riskHistory.length - 1].risk_score} pts
                            {riskHistory[riskHistory.length - 1].risk_score > riskHistory[0].risk_score
                              ? <span className="text-red-500 ml-1">↑</span>
                              : riskHistory[riskHistory.length - 1].risk_score < riskHistory[0].risk_score
                                ? <span className="text-green-500 ml-1">↓</span>
                                : <span className="text-gray-400 ml-1">→</span>
                            }
                          </span>
                        </div>
                      </div>
                      <ResponsiveContainer width="100%" height={160}>
                        <LineChart data={riskHistory} margin={{ top: 5, right: 10, left: -15, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
                          <XAxis
                            dataKey="date"
                            tick={{ fontSize: 9, fill: '#9ca3af' }}
                            tickFormatter={(d: string) => {
                              try { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }); } catch { return ''; }
                            }}
                          />
                          <YAxis tick={{ fontSize: 9, fill: '#9ca3af' }} domain={[0, 'auto']} allowDecimals={false} />
                          <ReferenceLine y={70} stroke="#ef4444" strokeDasharray="3 3" strokeOpacity={0.4} label={{ value: 'Critical', fontSize: 8, fill: '#ef4444' }} />
                          <Tooltip
                            content={({ active, payload }) => {
                              if (!active || !payload?.length) return null;
                              const p = payload[0]?.payload as {date: string; risk_score: number; risk_level: string} | undefined;
                              if (!p) return null;
                              const levelColor: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
                              return (
                                <div className="bg-white border rounded-lg shadow-lg px-3 py-2 text-xs">
                                  <div className="text-gray-500 mb-1">
                                    {(() => { try { return new Date(p.date).toLocaleDateString(); } catch { return p.date; } })()}
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: levelColor[p.risk_level] || '#6b7280' }} />
                                    <span className="font-semibold">{p.risk_score}</span>
                                    <span className="capitalize text-gray-400">{p.risk_level}</span>
                                  </div>
                                </div>
                              );
                            }}
                          />
                          <Line
                            type="monotone"
                            dataKey="risk_score"
                            stroke="#7c3aed"
                            strokeWidth={2}
                            dot={{ r: 3, fill: '#7c3aed', strokeWidth: 0 }}
                            activeDot={{ r: 5, fill: '#7c3aed' }}
                          />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  )}

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

              {/* Anomalies Tab */}
              {activeTab === 'anomalies' && (
                <div className="space-y-4">
                  {anomalyLoading ? (
                    <div className="animate-pulse space-y-3">
                      <div className="h-16 bg-gray-100 rounded-xl" />
                      <div className="h-16 bg-gray-100 rounded-xl" />
                      <div className="h-16 bg-gray-100 rounded-xl" />
                    </div>
                  ) : !anomalyData || anomalyData.anomalies.length === 0 ? (
                    <div className="text-center py-8">
                      <svg className="w-12 h-12 text-green-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      <p className="text-gray-500">No anomalies detected for this identity</p>
                    </div>
                  ) : (
                    anomalyData.anomalies.map((a: any) => {
                      const severityColors: Record<string, string> = {
                        critical: 'border-red-300 bg-red-50',
                        high: 'border-orange-300 bg-orange-50',
                        medium: 'border-yellow-300 bg-yellow-50',
                        low: 'border-blue-300 bg-blue-50',
                      };
                      const dotColors: Record<string, string> = {
                        critical: 'bg-red-500',
                        high: 'bg-orange-500',
                        medium: 'bg-yellow-400',
                        low: 'bg-blue-400',
                      };
                      const typeLabels: Record<string, string> = {
                        permission_escalation: 'Permission Escalation',
                        risk_score_spike: 'Risk Spike',
                        dormant_reactivation: 'Dormant Reactivation',
                        credential_surge: 'Credential Surge',
                        off_hours_pim: 'Off-Hours PIM',
                        excessive_pim_usage: 'Excessive PIM',
                        ghost_identity: 'Ghost Identity',
                      };
                      return (
                        <div key={a.id} className={`rounded-xl border p-4 ${severityColors[a.severity] || 'border-gray-200 bg-gray-50'}`}>
                          <div className="flex items-start gap-3">
                            <span className={`w-3 h-3 rounded-full mt-1 flex-shrink-0 ${dotColors[a.severity] || 'bg-gray-400'}`} />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="text-xs font-semibold uppercase text-gray-500">
                                  {typeLabels[a.anomaly_type] || a.anomaly_type}
                                </span>
                                <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
                                  a.severity === 'critical' ? 'bg-red-200 text-red-800' :
                                  a.severity === 'high' ? 'bg-orange-200 text-orange-800' :
                                  a.severity === 'medium' ? 'bg-yellow-200 text-yellow-800' :
                                  'bg-blue-200 text-blue-800'
                                }`}>
                                  {a.severity}
                                </span>
                                {!!a.resolved && (
                                  <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-green-100 text-green-700">Resolved</span>
                                )}
                              </div>
                              <h4 className="text-sm font-medium text-gray-900">{a.title}</h4>
                              <p className="text-xs text-gray-600 mt-1">{a.description}</p>
                              {!!a.details && (
                                <details className="mt-2">
                                  <summary className="text-[11px] text-gray-500 cursor-pointer hover:text-gray-700">View details</summary>
                                  <pre className="mt-1 text-[10px] text-gray-500 bg-white/70 rounded p-2 overflow-auto max-h-32">
                                    {JSON.stringify(a.details, null, 2)}
                                  </pre>
                                </details>
                              )}
                              {!!a.created_at && (
                                <p className="text-[10px] text-gray-400 mt-2">
                                  Detected: {new Date(a.created_at).toLocaleString()}
                                </p>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
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
                        // eslint-disable-next-line @typescript-eslint/no-unused-vars
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
                            onExecute={(actionType) => handleRemediationExecute(rem.id, actionType)}
                            loading={actionLoading === rem.id}
                            executing={executeLoading === rem.id}
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

              {/* ─── What If Simulation Tab ─── */}
              {activeTab === 'simulate' && (
                <div className="space-y-6">
                  {/* Header */}
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-lg font-bold text-gray-900">What-If Risk Simulation</h3>
                      <p className="text-xs text-gray-500 mt-0.5">Toggle roles and permissions to see how the risk score would change.</p>
                    </div>
                    <button onClick={resetSimulation} className="px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-50 transition">
                      Reset
                    </button>
                  </div>

                  {/* Score comparison cards */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-gray-50 rounded-xl p-4 border">
                      <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Current</div>
                      <div className="text-3xl font-bold text-gray-900">{simResult?.current?.risk_score ?? identity?.risk_score ?? '—'}</div>
                      <div className="mt-1">{riskBadge(simResult?.current?.risk_level ?? identity?.risk_level)}</div>
                    </div>
                    <div className={`rounded-xl p-4 border ${simResult ? 'bg-blue-50 border-blue-200' : 'bg-gray-50'}`}>
                      <div className="text-xs font-semibold text-blue-600 uppercase mb-1">Simulated</div>
                      <div className="text-3xl font-bold text-gray-900">{simResult?.simulated?.risk_score ?? '—'}</div>
                      {simResult && <div className="mt-1">{riskBadge(simResult.simulated.risk_level)}</div>}
                      {!simResult && <div className="text-xs text-gray-400 mt-2">Click "Simulate" to compute</div>}
                    </div>
                    <div className={`rounded-xl p-4 border ${simResult ? (simResult.delta < 0 ? 'bg-green-50 border-green-200' : simResult.delta > 0 ? 'bg-red-50 border-red-200' : 'bg-gray-50') : 'bg-gray-50'}`}>
                      <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Delta</div>
                      {simResult ? (
                        <>
                          <div className={`text-3xl font-bold ${simResult.delta < 0 ? 'text-green-700' : simResult.delta > 0 ? 'text-red-700' : 'text-gray-500'}`}>
                            {simResult.delta > 0 ? '+' : ''}{simResult.delta}
                          </div>
                          <div className="text-xs text-gray-500 mt-1">{simResult.level_change}</div>
                        </>
                      ) : (
                        <div className="text-3xl font-bold text-gray-300">—</div>
                      )}
                    </div>
                  </div>

                  {/* Roles section */}
                  <div className="border rounded-xl overflow-hidden">
                    <div className="bg-gray-50 px-4 py-3 border-b flex items-center justify-between">
                      <div className="text-sm font-semibold text-gray-700">Roles ({(data?.roles?.length || 0) + simAddedRoles.length - simRemovedRoles.size} active)</div>
                      <button
                        onClick={() => setSimAddRoleOpen(!simAddRoleOpen)}
                        className="px-2.5 py-1 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition"
                      >
                        + Add Role
                      </button>
                    </div>
                    <div className="divide-y max-h-64 overflow-y-auto">
                      {(data?.roles || []).map((r: any, idx: number) => {
                        const key = r.role_name || `role-${idx}`;
                        const removed = simRemovedRoles.has(key);
                        return (
                          <label key={`existing-${idx}`} className={`flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-gray-50 transition ${removed ? 'opacity-50 line-through' : ''}`}>
                            <input
                              type="checkbox"
                              checked={!removed}
                              onChange={() => {
                                setSimRemovedRoles(prev => {
                                  const next = new Set(prev);
                                  if (next.has(key)) next.delete(key); else next.add(key);
                                  return next;
                                });
                                setSimResult(null);
                              }}
                              className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                            />
                            <div className="flex-1 min-w-0">
                              <span className="text-sm text-gray-900">{r.role_name}</span>
                              <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                                safeLower(r.role_type) === 'entra' ? 'bg-purple-100 text-purple-700' : 'bg-blue-100 text-blue-700'
                              }`}>
                                {(r.role_type || 'azure').toUpperCase()}
                              </span>
                              {r.scope && <span className="ml-1 text-[10px] text-gray-400 font-mono truncate">{r.scope}</span>}
                            </div>
                            {removed && <span className="text-xs font-medium text-red-500">removed</span>}
                          </label>
                        );
                      })}
                      {simAddedRoles.map((r, idx) => (
                        <div key={`added-${idx}`} className="flex items-center gap-3 px-4 py-2.5 bg-green-50">
                          <div className="w-4 h-4 rounded bg-green-500 flex items-center justify-center">
                            <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M12 4v16m8-8H4" />
                            </svg>
                          </div>
                          <div className="flex-1 min-w-0">
                            <span className="text-sm text-green-800 font-medium">{r.role_name}</span>
                            <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                              r.role_type === 'entra' ? 'bg-purple-100 text-purple-700' : 'bg-blue-100 text-blue-700'
                            }`}>
                              {r.role_type.toUpperCase()}
                            </span>
                            <span className="ml-1 text-[10px] text-gray-400">{r.scope_type}</span>
                          </div>
                          <button
                            onClick={() => { setSimAddedRoles(prev => prev.filter((_, i) => i !== idx)); setSimResult(null); }}
                            className="text-xs text-red-500 hover:text-red-700 font-medium"
                          >
                            Remove
                          </button>
                        </div>
                      ))}
                      {(data?.roles?.length || 0) === 0 && simAddedRoles.length === 0 && (
                        <div className="px-4 py-6 text-center text-sm text-gray-400">No roles assigned</div>
                      )}
                    </div>
                    {simAddRoleOpen && (
                      <div className="border-t bg-blue-50 px-4 py-3">
                        <div className="flex items-end gap-2">
                          <div className="flex-1">
                            <label className="text-[10px] font-medium text-gray-600 block mb-1">Role Name</label>
                            <input
                              type="text"
                              value={simNewRole.role_name}
                              onChange={e => setSimNewRole(prev => ({...prev, role_name: e.target.value}))}
                              placeholder="e.g. Reader, Contributor"
                              className="w-full px-2.5 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                          <div>
                            <label className="text-[10px] font-medium text-gray-600 block mb-1">Type</label>
                            <select
                              value={simNewRole.role_type}
                              onChange={e => setSimNewRole(prev => ({...prev, role_type: e.target.value}))}
                              className="px-2.5 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500"
                            >
                              <option value="azure">Azure RBAC</option>
                              <option value="entra">Entra ID</option>
                            </select>
                          </div>
                          <div>
                            <label className="text-[10px] font-medium text-gray-600 block mb-1">Scope</label>
                            <select
                              value={simNewRole.scope_type}
                              onChange={e => setSimNewRole(prev => ({...prev, scope_type: e.target.value}))}
                              className="px-2.5 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500"
                            >
                              <option value="subscription">Subscription</option>
                              <option value="resource_group">Resource Group</option>
                              <option value="resource">Resource</option>
                              <option value="management_group">Management Group</option>
                            </select>
                          </div>
                          <button
                            onClick={() => {
                              if (!simNewRole.role_name.trim()) return;
                              setSimAddedRoles(prev => [...prev, {...simNewRole}]);
                              setSimNewRole({role_name: '', role_type: 'azure', scope_type: 'subscription'});
                              setSimAddRoleOpen(false);
                              setSimResult(null);
                            }}
                            className="px-3 py-1.5 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition"
                          >
                            Add
                          </button>
                          <button
                            onClick={() => setSimAddRoleOpen(false)}
                            className="px-3 py-1.5 text-sm font-medium rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-50 transition"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Permissions section */}
                  <div className="border rounded-xl overflow-hidden">
                    <div className="bg-gray-50 px-4 py-3 border-b flex items-center justify-between">
                      <div className="text-sm font-semibold text-gray-700">Graph API Permissions ({(data?.graph_permissions?.length || 0) + simAddedPerms.length - simRemovedPerms.size} active)</div>
                      <button
                        onClick={() => setSimAddPermOpen(!simAddPermOpen)}
                        className="px-2.5 py-1 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition"
                      >
                        + Add Permission
                      </button>
                    </div>
                    <div className="divide-y max-h-48 overflow-y-auto">
                      {(data?.graph_permissions || []).map((p: any, idx: number) => {
                        const key = p.permission_name || `perm-${idx}`;
                        const removed = simRemovedPerms.has(key);
                        return (
                          <label key={`existing-perm-${idx}`} className={`flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-gray-50 transition ${removed ? 'opacity-50 line-through' : ''}`}>
                            <input
                              type="checkbox"
                              checked={!removed}
                              onChange={() => {
                                setSimRemovedPerms(prev => {
                                  const next = new Set(prev);
                                  if (next.has(key)) next.delete(key); else next.add(key);
                                  return next;
                                });
                                setSimResult(null);
                              }}
                              className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                            />
                            <div className="flex-1 min-w-0">
                              <span className="text-sm text-gray-900 font-mono">{p.permission_name}</span>
                              {p.consent_type && (
                                <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                                  p.consent_type === 'Application' ? 'bg-red-100 text-red-700' : 'bg-gray-100 text-gray-600'
                                }`}>
                                  {p.consent_type}
                                </span>
                              )}
                            </div>
                            {removed && <span className="text-xs font-medium text-red-500">removed</span>}
                          </label>
                        );
                      })}
                      {simAddedPerms.map((p, idx) => (
                        <div key={`added-perm-${idx}`} className="flex items-center gap-3 px-4 py-2.5 bg-green-50">
                          <div className="w-4 h-4 rounded bg-green-500 flex items-center justify-center">
                            <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M12 4v16m8-8H4" />
                            </svg>
                          </div>
                          <div className="flex-1 min-w-0">
                            <span className="text-sm text-green-800 font-medium font-mono">{p.permission_name}</span>
                            <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                              p.risk_level === 'high' ? 'bg-red-100 text-red-700' : p.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-700' : 'bg-gray-100 text-gray-600'
                            }`}>
                              {p.risk_level}
                            </span>
                          </div>
                          <button
                            onClick={() => { setSimAddedPerms(prev => prev.filter((_, i) => i !== idx)); setSimResult(null); }}
                            className="text-xs text-red-500 hover:text-red-700 font-medium"
                          >
                            Remove
                          </button>
                        </div>
                      ))}
                      {(data?.graph_permissions?.length || 0) === 0 && simAddedPerms.length === 0 && (
                        <div className="px-4 py-6 text-center text-sm text-gray-400">No Graph API permissions</div>
                      )}
                    </div>
                    {simAddPermOpen && (
                      <div className="border-t bg-blue-50 px-4 py-3">
                        <div className="flex items-end gap-2">
                          <div className="flex-1">
                            <label className="text-[10px] font-medium text-gray-600 block mb-1">Permission Name</label>
                            <input
                              type="text"
                              value={simNewPerm.permission_name}
                              onChange={e => setSimNewPerm(prev => ({...prev, permission_name: e.target.value}))}
                              placeholder="e.g. Mail.Read, Files.ReadWrite.All"
                              className="w-full px-2.5 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                          <div>
                            <label className="text-[10px] font-medium text-gray-600 block mb-1">Risk Level</label>
                            <select
                              value={simNewPerm.risk_level}
                              onChange={e => setSimNewPerm(prev => ({...prev, risk_level: e.target.value}))}
                              className="px-2.5 py-1.5 text-sm border rounded-lg focus:ring-2 focus:ring-blue-500"
                            >
                              <option value="high">High (Write/ReadWrite)</option>
                              <option value="medium">Medium (Read)</option>
                              <option value="low">Low</option>
                            </select>
                          </div>
                          <button
                            onClick={() => {
                              if (!simNewPerm.permission_name.trim()) return;
                              setSimAddedPerms(prev => [...prev, {...simNewPerm}]);
                              setSimNewPerm({permission_name: '', risk_level: 'medium'});
                              setSimAddPermOpen(false);
                              setSimResult(null);
                            }}
                            className="px-3 py-1.5 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition"
                          >
                            Add
                          </button>
                          <button
                            onClick={() => setSimAddPermOpen(false)}
                            className="px-3 py-1.5 text-sm font-medium rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-50 transition"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Simulate button */}
                  <div className="flex items-center gap-3">
                    <button
                      onClick={runSimulation}
                      disabled={simulating}
                      className="px-6 py-2.5 rounded-xl font-semibold text-sm bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 transition flex items-center gap-2"
                    >
                      {simulating ? (
                        <>
                          <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                            <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" className="opacity-25" />
                            <path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" fill="currentColor" className="opacity-75" />
                          </svg>
                          Simulating...
                        </>
                      ) : (
                        <>
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                          </svg>
                          Simulate
                        </>
                      )}
                    </button>
                    {(simRemovedRoles.size > 0 || simAddedRoles.length > 0 || simRemovedPerms.size > 0 || simAddedPerms.length > 0) && !simResult && (
                      <span className="text-xs text-amber-600 font-medium">
                        {simRemovedRoles.size + simRemovedPerms.size} removed, {simAddedRoles.length + simAddedPerms.length} added — click Simulate to see impact
                      </span>
                    )}
                  </div>

                  {/* Risk reasons comparison */}
                  {simResult && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="border rounded-xl p-4">
                        <div className="text-xs font-semibold text-gray-500 uppercase mb-2">Current Risk Reasons</div>
                        <div className="space-y-1.5">
                          {(simResult.current.risk_reasons || []).map((r, i) => {
                            const isRemoved = (simResult.removed_reasons || []).includes(r);
                            return (
                              <div key={i} className={`text-xs px-2 py-1.5 rounded ${isRemoved ? 'bg-red-50 text-red-700 line-through' : 'bg-gray-50 text-gray-700'}`}>
                                {r}
                                {isRemoved && <span className="ml-1 font-semibold text-red-500 no-underline">(removed)</span>}
                              </div>
                            );
                          })}
                          {(simResult.current.risk_reasons || []).length === 0 && (
                            <div className="text-xs text-gray-400">No risk factors</div>
                          )}
                        </div>
                      </div>
                      <div className="border rounded-xl p-4 border-blue-200">
                        <div className="text-xs font-semibold text-blue-600 uppercase mb-2">Simulated Risk Reasons</div>
                        <div className="space-y-1.5">
                          {(simResult.simulated.risk_reasons || []).map((r, i) => {
                            const isNew = (simResult.added_reasons || []).includes(r);
                            return (
                              <div key={i} className={`text-xs px-2 py-1.5 rounded ${isNew ? 'bg-green-50 text-green-700' : 'bg-gray-50 text-gray-700'}`}>
                                {r}
                                {isNew && <span className="ml-1 font-semibold text-green-600">(new)</span>}
                              </div>
                            );
                          })}
                          {(simResult.simulated.risk_reasons || []).length === 0 && (
                            <div className="text-xs text-gray-400">No risk factors</div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                  <DataSource label="AuditGraph Risk Simulation" apiSource="What-if analysis engine (no changes applied)" collectedAt={data?.evidence?.collected_at} />
                </div>
              )}

              {activeTab === 'timeline' && <TimelineTab identityId={id!} />}
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
  onExecute,
  loading,
  executing,
}: {
  remediation: RemediationItem;
  index: number;
  action?: RemediationAction;
  onAction: (status: RemediationStatus, notes?: string) => void;
  onExecute: (actionType: string) => void;
  loading: boolean;
  executing: boolean;
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

          {/* Execution result */}
          {action?.execution_status && (
            <div className={`border rounded-lg p-3 ${
              action.execution_status === 'success' ? 'bg-green-50 border-green-200' :
              action.execution_status === 'simulated' ? 'bg-amber-50 border-amber-200' :
              'bg-red-50 border-red-200'
            }`}>
              <div className="flex items-center gap-2">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                  action.execution_status === 'success' ? 'bg-green-200 text-green-800' :
                  action.execution_status === 'simulated' ? 'bg-amber-200 text-amber-800' :
                  'bg-red-200 text-red-800'
                }`}>
                  {action.execution_status}
                </span>
                {action.execution_log?.action_type && (
                  <span className="text-[10px] text-gray-500">{action.execution_log.action_type.replace(/_/g, ' ')}</span>
                )}
                {action.executed_at && (
                  <span className="text-[10px] text-gray-400 ml-auto">
                    {new Date(action.executed_at).toLocaleString()}
                  </span>
                )}
              </div>
              {action.execution_log?.detail && (
                <p className="text-xs text-gray-600 mt-1">{action.execution_log.detail}</p>
              )}
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

              {/* Execute dropdown */}
              {currentStatus !== 'completed' && currentStatus !== 'skipped' && !action?.execution_status && (
                <>
                  <span className="text-gray-300 mx-1">|</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); onExecute('flag_for_review'); }}
                    disabled={executing}
                    className="px-3 py-1.5 rounded-lg text-xs font-medium transition bg-purple-600 hover:bg-purple-700 text-white disabled:opacity-50"
                  >
                    {executing ? 'Executing...' : 'Flag for Review'}
                  </button>
                  {(remediation.category === 'governance') && (
                    <button
                      onClick={(e) => { e.stopPropagation(); if (window.confirm('This will simulate disabling the identity. Continue?')) onExecute('disable_identity'); }}
                      disabled={executing}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition bg-red-600 hover:bg-red-700 text-white disabled:opacity-50"
                    >
                      {executing ? 'Executing...' : 'Disable Identity'}
                    </button>
                  )}
                  {(remediation.category === 'credential_hygiene') && (
                    <button
                      onClick={(e) => { e.stopPropagation(); if (window.confirm('This will simulate credential rotation. Continue?')) onExecute('rotate_credential'); }}
                      disabled={executing}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition bg-orange-600 hover:bg-orange-700 text-white disabled:opacity-50"
                    >
                      {executing ? 'Executing...' : 'Rotate Credential'}
                    </button>
                  )}
                  {(remediation.category === 'access_control') && (
                    <button
                      onClick={(e) => { e.stopPropagation(); if (window.confirm('This will simulate role removal. Continue?')) onExecute('remove_role'); }}
                      disabled={executing}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition bg-red-600 hover:bg-red-700 text-white disabled:opacity-50"
                    >
                      {executing ? 'Executing...' : 'Remove Role'}
                    </button>
                  )}
                </>
              )}

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

/* ═══ Phase 80: Timeline Tab Component ═══ */

const EVENT_COLORS: Record<string, { dot: string; bg: string }> = {
  anomaly: { dot: 'bg-red-500', bg: 'bg-red-50 border-red-200' },
  drift: { dot: 'bg-blue-500', bg: 'bg-blue-50 border-blue-200' },
  risk_change: { dot: 'bg-gray-400', bg: 'bg-gray-50 border-gray-200' },
  pim_activation: { dot: 'bg-amber-500', bg: 'bg-amber-50 border-amber-200' },
  soar_action: { dot: 'bg-purple-500', bg: 'bg-purple-50 border-purple-200' },
  remediation: { dot: 'bg-green-500', bg: 'bg-green-50 border-green-200' },
};

const EVENT_LABELS: Record<string, string> = {
  anomaly: 'Anomaly',
  drift: 'Drift',
  risk_change: 'Risk Change',
  pim_activation: 'PIM Activation',
  soar_action: 'SOAR Action',
  remediation: 'Remediation',
};

function TimelineTab({ identityId }: { identityId: string }) {
  const { withConnection } = useConnection();
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState<Set<string>>(new Set());
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: '100' });
    if (filters.size > 0) params.set('event_types', Array.from(filters).join(','));
    if (fromDate) params.set('from', fromDate);
    if (toDate) params.set('to', toDate);
    fetch(withConnection(`/api/identities/${encodeURIComponent(identityId)}/timeline?${params}`))
      .then(r => r.ok ? r.json() : { events: [], total: 0 })
      .then(d => { setEvents(d.events || []); setTotal(d.total || 0); })
      .catch(() => { setEvents([]); setTotal(0); })
      .finally(() => setLoading(false));
  }, [identityId, filters, fromDate, toDate]);

  function toggleFilter(type: string) {
    setFilters(prev => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type); else next.add(type);
      return next;
    });
  }

  function exportCSV() {
    const header = 'Timestamp,Event Type,Severity,Title,Description\n';
    const rows = events.map(e =>
      `"${e.timestamp || ''}","${e.event_type}","${e.severity}","${(e.title || '').replace(/"/g, '""')}","${(e.description || '').replace(/"/g, '""')}"`
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `timeline-${identityId}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function relativeTime(ts: string) {
    const diff = Date.now() - new Date(ts).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  if (loading) {
    return <div className="animate-pulse space-y-3">{[1,2,3,4].map(i => <div key={i} className="h-16 bg-gray-100 rounded-lg" />)}</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-bold text-gray-900">Identity Timeline</h3>
          <p className="text-xs text-gray-500">{total} events recorded</p>
        </div>
        <button onClick={exportCSV} disabled={events.length === 0}
          className="px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-50 transition disabled:opacity-50">
          Export CSV
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        {Object.entries(EVENT_LABELS).map(([key, label]) => {
          const colors = EVENT_COLORS[key];
          const active = filters.size === 0 || filters.has(key);
          return (
            <button key={key} onClick={() => toggleFilter(key)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border transition ${
                active ? 'border-gray-300 bg-white text-gray-800' : 'border-gray-200 bg-gray-50 text-gray-400'
              }`}>
              <span className={`w-2 h-2 rounded-full ${colors?.dot || 'bg-gray-400'}`} />
              {label}
            </button>
          );
        })}
        <div className="flex items-center gap-1 ml-auto">
          <input type="date" value={fromDate} onChange={e => setFromDate(e.target.value)}
            className="px-2 py-1 border border-gray-300 rounded text-[10px] text-gray-600" />
          <span className="text-[10px] text-gray-400">to</span>
          <input type="date" value={toDate} onChange={e => setToDate(e.target.value)}
            className="px-2 py-1 border border-gray-300 rounded text-[10px] text-gray-600" />
        </div>
      </div>

      {/* Timeline */}
      {events.length === 0 ? (
        <div className="bg-gray-50 border rounded-xl p-8 text-center">
          <div className="text-sm text-gray-500 font-medium">No events recorded for this identity</div>
          <div className="text-xs text-gray-400 mt-1">Events will appear here as they are detected</div>
        </div>
      ) : (
        <div className="relative">
          {/* Vertical line */}
          <div className="absolute left-[84px] top-0 bottom-0 w-px bg-gray-200" />

          <div className="space-y-2">
            {events.map((event, idx) => {
              const colors = EVENT_COLORS[event.event_type] || EVENT_COLORS.risk_change;
              return (
                <div key={idx} className="flex items-start gap-3 group">
                  {/* Timestamp column */}
                  <div className="w-[72px] flex-shrink-0 text-right pt-1">
                    <div className="text-[10px] text-gray-500 font-mono">
                      {event.timestamp ? new Date(event.timestamp).toLocaleDateString() : '—'}
                    </div>
                    <div className="text-[9px] text-gray-400">
                      {event.timestamp ? relativeTime(event.timestamp) : ''}
                    </div>
                  </div>

                  {/* Dot */}
                  <div className="relative flex-shrink-0 mt-2">
                    <div className={`w-3 h-3 rounded-full border-2 border-white shadow ${colors.dot}`} />
                  </div>

                  {/* Event card */}
                  <div className={`flex-1 rounded-lg border px-3 py-2 ${colors.bg}`}>
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[10px] font-bold uppercase text-gray-500">
                        {EVENT_LABELS[event.event_type] || event.event_type}
                      </span>
                      {event.severity && (
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                          event.severity === 'critical' ? 'bg-red-100 text-red-700' :
                          event.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                          event.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                          'bg-gray-100 text-gray-600'
                        }`}>
                          {event.severity}
                        </span>
                      )}
                    </div>
                    <div className="text-xs font-medium text-gray-900">{event.title}</div>
                    {event.description && (
                      <div className="text-[11px] text-gray-600 mt-0.5 line-clamp-2">{event.description}</div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
