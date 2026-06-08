import React, { useEffect, useMemo, useState } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { useToast } from '../components/ToastProvider';
import { useConnection } from '../contexts/ConnectionContext';
import { useCopilot } from '../contexts/CopilotContext';
import { AccessGraphTab } from '../components/graph';
import {
  type IdentityCategory, type RiskLevel,
  RISK_BADGE, DATA_EXPLANATIONS,
  safeLower, normalizeCategoryFromBackend, getCategoryLabel,
  TIME_MS,
} from '../constants/metrics';
import OverviewTab from '../components/identity-detail/OverviewTab';
import { RolesTab } from '../components/identity-detail/RolesTab';
import { PermissionsTab } from '../components/identity-detail/PermissionsTab';
import { CredentialsTab } from '../components/identity-detail/CredentialsTab';
import { OwnershipTab } from '../components/identity-detail/OwnershipTab';
import { EffectiveAccessTab } from '../components/identity-detail/EffectiveAccessTab';
import { AnomaliesTab } from '../components/identity-detail/AnomaliesTab';
import { PimTab } from '../components/identity-detail/PimTab';
import { IdentityComplianceTab } from '../components/identity-detail/ComplianceTab';
import { RemediationTab } from '../components/identity-detail/RemediationTab';
import { LifecycleTab } from '../components/identity-detail/LifecycleTab';
import { SimulateTab } from '../components/identity-detail/SimulateTab';
import { EntraGroupsTab } from '../components/identity-detail/EntraGroupsTab';

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
    is_discovery_connector?: boolean;

    // Effective last used (MAX of observed + Azure sign-in)
    effective_last_used?: string | null;
    effective_last_used_source?: 'auditgraph' | 'azure_signin' | 'inferred_federated' | null;

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
    group_count?: number;
  };
  roles: any[];
  graph_permissions: any[];
  app_roles: any[];
  owners: Owner[];
  role_intelligence: RoleIntelligence[];
  trend?: TrendData | null;
  evidence?: EvidenceMetadata;
}

type TabId = 'overview' | 'roles' | 'permissions' | 'credentials' | 'ownership' | 'effective_access' | 'access_graph' | 'anomalies' | 'compliance' | 'pim' | 'remediation' | 'lifecycle' | 'simulate' | 'timeline' | 'sensitive_access' | 'entra_groups' | 'attack_paths' | 'consents';

interface EffectiveAccessEntry {
  role_name: string;
  role_source: 'azure_rbac' | 'entra_directory';
  access_level: 'Admin' | 'Write' | 'Read';
  category: string;
  scope: string;
  scope_display: string;
  scope_type: string;
  resource_type: string | null;
  risk_level: string;
  assigned_on: string | null;
  permissions: string[];
  why_critical: string | null;
}

interface EffectiveAccessData {
  identity_id: string;
  display_name: string;
  effective_access: EffectiveAccessEntry[];
  summary: {
    admin_scopes: number;
    write_scopes: number;
    read_scopes: number;
    total_roles: number;
    total_permissions: number;
    categories: string[];
  };
}

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

function formatLastUsed(iso?: string | null): string {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    const now = new Date();
    const diffDays = Math.floor((now.getTime() - d.getTime()) / TIME_MS.DAY);
    const absolute = d.toLocaleString(undefined, {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: 'numeric', minute: '2-digit',
    });
    if (diffDays <= 0) return `Today · ${absolute}`;
    if (diffDays === 1) return `1d ago · ${absolute}`;
    if (diffDays < 30) return `${diffDays}d ago · ${absolute}`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo ago · ${absolute}`;
    return `${Math.floor(diffDays / 365)}y ago · ${absolute}`;
  } catch {
    return iso;
  }
}

function formatDate(iso?: string | null) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function riskBadge(level?: string) {
  const v = safeLower(level);
  const base = 'px-2 py-1 rounded-full text-xs font-semibold inline-flex items-center';
  return <span className={`${base} ${RISK_BADGE[v] || 'bg-gray-100 text-gray-700'}`}>{(v || 'unknown').toUpperCase()}</span>;
}

function categoryLabel(catRaw?: any, typeRaw?: any) {
  const cat = normalizeCategoryFromBackend(catRaw);
  if (cat !== 'unknown') return getCategoryLabel(cat);
  // Fallback to type-based lookup
  return getCategoryLabel(safeLower(typeRaw)) || 'Unknown';
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
function TabBar({ activeTab, onTabChange, counts, labelOverrides, hideTabs }: {
  activeTab: TabId;
  onTabChange: (tab: TabId) => void;
  counts: Record<TabId, number>;
  labelOverrides?: Partial<Record<TabId, string>>;
  hideTabs?: TabId[];
}) {
  const tabs: { id: TabId; label: string; icon: string }[] = [
    { id: 'overview', label: 'Overview', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
    { id: 'roles', label: 'Roles', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
    { id: 'permissions', label: 'Permissions', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
    { id: 'credentials', label: 'Credentials', icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z' },
    { id: 'consents' as TabId, label: 'OAuth Consents', icon: 'M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z' },
    { id: 'ownership', label: 'Ownership', icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z' },
    { id: 'entra_groups' as TabId, label: 'Groups', icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z' },
    { id: 'effective_access' as TabId, label: 'Effective Access', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4' },
    { id: 'access_graph' as TabId, label: 'Access Graph', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
    { id: 'anomalies' as TabId, label: 'Anomalies', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z' },
    { id: 'pim' as TabId, label: 'PIM', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8zM10 14a2 2 0 104 0 2 2 0 00-4 0z' },
    { id: 'compliance' as TabId, label: 'Compliance', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
    { id: 'remediation' as TabId, label: 'Remediation', icon: 'M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z' },
    { id: 'lifecycle' as TabId, label: 'Lifecycle', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
    { id: 'sensitive_access' as TabId, label: 'Sensitive Access', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
    { id: 'simulate' as TabId, label: 'What If', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
    { id: 'attack_paths' as TabId, label: 'Attack Paths', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z' },
    { id: 'timeline' as TabId, label: 'Timeline', icon: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' },
  ];

  const visibleTabs = hideTabs && hideTabs.length > 0
    ? tabs.filter(t => !hideTabs.includes(t.id))
    : tabs;

  return (
    <div className="border-b bg-white rounded-t-xl">
      <nav className="flex -mb-px overflow-x-auto">
        {visibleTabs.map(tab => {
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
              {labelOverrides?.[tab.id] || tab.label}
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
  const { openCopilot } = useCopilot();

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
  const [entraGroupMeta, setEntraGroupMeta] = useState<{total: number; withAccess: number}>({total: 0, withAccess: 0});
  const [anomalyData, setAnomalyData] = useState<{anomalies: any[]; count: number} | null>(null);
  const [anomalyLoading, setAnomalyLoading] = useState(false);
  const [effectiveAccessData, setEffectiveAccessData] = useState<EffectiveAccessData | null>(null);
  const [effectiveAccessLoading, setEffectiveAccessLoading] = useState(false);
  const [sensitiveAccessData, setSensitiveAccessData] = useState<any>(null);
  const [riskHistory, setRiskHistory] = useState<{run_id: number; date: string; risk_score: number; risk_level: string}[]>([]);
  const [correlatedAccounts, setCorrelatedAccounts] = useState<{
    human_identity: { id: number; display_name: string } | null;
    accounts: { id: number; identity_id?: string; object_id: string; display_name: string; upn: string; account_type: string; enabled: boolean; deleted: boolean; is_zombie: boolean; risk_score: number; risk_level: string; privilege_tier: string; link_method: string; link_confidence: number; verified: boolean }[];
    zombie_persona: boolean;
  } | null>(null);

  // AI Agent Evidence
  const [aiEvidence, setAiEvidence] = useState<{
    classified: boolean;
    agent_identity_type: string;
    classification?: { confidence: number; reason: string; platform: string; pattern_version: string; classified_at: string };
    evidence_signals: { signal_type: string; confidence: number; platform: string; evidence_text: string; is_primary: boolean }[];
    ai_connections: { type: string; role_name?: string; scope?: string; permission?: string; platform?: string; match_type?: string; last_used_at?: string | null; source_of_evidence?: string }[];
    risk_context?: { risk_score: number; risk_level: string; identity_type: string; identity_category: string };
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

  // Lazy-load PIM data when tab is selected.
  // BUGFIX (2026-05-30): removed `pimLoading` from deps. Including it caused
  // a self-cancellation race: setPimLoading(true) ↑ retriggers effect ↑
  // cleanup sets cancelled=true ↑ in-flight fetch's .finally is skipped ↑
  // pimLoading stuck true → skeleton renders forever even though the API
  // returned a successful response. The pimData truthy check is enough to
  // prevent duplicate fetches.
  useEffect(() => {
    // AG-118: also fetch on Roles tab so per-role PIM badges render
    // without forcing the user to visit Pim tab first.
    if (!['pim', 'roles'].includes(activeTab) || pimData || !id) return;
    let cancelled = false;
    setPimLoading(true);
    fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/pim`))
      .then(res => res.ok ? res.json() : Promise.reject('PIM fetch failed'))
      .then(json => { if (!cancelled) setPimData(json); })
      .catch(() => { if (!cancelled) setPimData({ eligible_assignments: [], activations: [], overuse_metrics: { activation_frequency_30d: 0, always_active_pattern: false, total_active_hours_30d: 0 } }); })
      .finally(() => { if (!cancelled) setPimLoading(false); });
    return () => { cancelled = true; };
  }, [activeTab, id, pimData]);

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
  }, [activeTab, id, remediationData]); // BUGFIX (2026-05-30): remediationLoading intentionally excluded — including it causes self-cancellation race, see effective_access effect comment

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
  }, [activeTab, id, lifecycleData]); // BUGFIX (2026-05-30): lifecycleLoading intentionally excluded — self-cancellation race, see effective_access effect

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
  }, [activeTab, id, anomalyData]); // BUGFIX (2026-05-30): anomalyLoading intentionally excluded — self-cancellation race, see effective_access effect

  // Lazy-load Effective Access data when tab is selected
  useEffect(() => {
    if (activeTab !== 'effective_access' || effectiveAccessData || effectiveAccessLoading || !id) return;
    let cancelled = false;
    setEffectiveAccessLoading(true);
    fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/effective-access`))
      .then(res => res.ok ? res.json() : Promise.reject('Effective access fetch failed'))
      .then(json => { if (!cancelled) setEffectiveAccessData(json); })
      .catch(() => { if (!cancelled) setEffectiveAccessData({ identity_id: id, display_name: '', effective_access: [], summary: { admin_scopes: 0, write_scopes: 0, read_scopes: 0, total_roles: 0, total_permissions: 0, categories: [] } }); })
      .finally(() => { if (!cancelled) setEffectiveAccessLoading(false); });
    return () => { cancelled = true; };
  }, [activeTab, id, effectiveAccessData]); // effectiveAccessLoading intentionally excluded — including it causes a dep-change re-run that cancels the in-flight fetch before .finally() can clear loading

  // Fetch sensitive access data for effective_access and sensitive_access tabs
  useEffect(() => {
    if ((activeTab !== 'effective_access' && activeTab !== 'sensitive_access') || sensitiveAccessData || !id) return;
    fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/sensitive-access`))
      .then(res => res.ok ? res.json() : null)
      .then(json => { if (json) setSensitiveAccessData(json); })
      .catch(() => {});
  }, [activeTab, id, sensitiveAccessData, withConnection]);

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

  // Load entra group counts for tab label
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/entra-groups`))
      .then(res => res.ok ? res.json() : Promise.reject())
      .then(json => {
        if (cancelled) return;
        setEntraGroupMeta({ total: json.total_groups || json.count || 0, withAccess: json.with_azure_access || 0 });
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [id, withConnection]);

  // Fetch AI agent evidence (non-blocking)
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    fetch(withConnection(`/api/identities/${encodeURIComponent(id)}/ai-evidence`))
      .then(res => res.ok ? res.json() : null)
      .then(json => { if (!cancelled && json?.classified) setAiEvidence(json); })
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
    consents: 0,  // Populated by ConsentGrantsPanel on tab open; tab badge stays unset
    ownership: (data?.owners || []).length,
    effective_access: effectiveAccessData?.summary?.total_roles ?? (data?.roles || []).length,
    access_graph: (data?.roles || []).length + (identity?.credential_count ?? 0),
    anomalies: anomalyData?.count ?? 0,
    pim: (pimData?.eligible_assignments || []).length + (pimData?.activations || []).length,
    compliance: roleIntel.length,
    remediation: remediationData?.summary?.total ?? 0,
    lifecycle: lifecycleData?.total_events ?? 0,
    entra_groups: 0,  // count embedded in dynamic tab label
    sensitive_access: 0,
    simulate: 0,
    attack_paths: 0,
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
        {identity && (
          <button
            onClick={() => openCopilot({
              contextType: 'identity',
              contextId: String(id),
              contextLabel: identity.display_name,
            })}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-indigo-700 bg-indigo-50 hover:bg-indigo-100 rounded-lg border border-indigo-200 transition"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            Investigate with Argus
          </button>
        )}
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
                  {data?.trend?.risk_direction === 'worsened' && (data?.trend as any)?.score_delta_valid !== false && (
                    <span className="px-2 py-1 rounded-full text-xs font-bold bg-red-100 text-red-700 border border-red-200" title={`Was ${data.trend.previous_risk_level || 'lower'} in previous snapshot`}>
                      ↑ WORSENED
                    </span>
                  )}
                  {data?.trend?.risk_direction === 'improved' && (data?.trend as any)?.score_delta_valid !== false && (
                    <span className="px-2 py-1 rounded-full text-xs font-bold bg-green-100 text-green-700 border border-green-200" title={`Was ${data.trend.previous_risk_level || 'higher'} in previous snapshot`}>
                      ↓ IMPROVED
                    </span>
                  )}
                  {identity.risk_score !== undefined && (
                    <span className="px-2 py-1 rounded-full text-xs font-semibold bg-purple-100 text-purple-700">
                      {((identity as any).risk_label || identity.risk_level || 'unknown').toUpperCase()}
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
                  {!!(identity as any).telemetry_coverage && (
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                      (identity as any).telemetry_coverage === 'full' ? 'bg-green-50 text-green-700 border border-green-200' :
                      (identity as any).telemetry_coverage === 'partial' ? 'bg-yellow-50 text-yellow-700 border border-yellow-200' :
                      'bg-red-50 text-red-700 border border-red-200'
                    }`} title={
                      (identity as any).telemetry_coverage === 'full' ? 'All telemetry sources active' :
                      (identity as any).telemetry_coverage === 'partial' ? 'Some telemetry sources active' :
                      'No telemetry — activity cannot be determined'
                    }>
                      {(identity as any).telemetry_coverage === 'full' ? 'Full Telemetry' :
                       (identity as any).telemetry_coverage === 'partial' ? 'Partial Telemetry' : 'Telemetry Blind'}
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

                <div className="text-gray-500">Last Used</div>
                <div className="font-medium">
                  {(() => {
                    const authActivity = (identity as any).auth_activity;
                    const lastSeenAvailable = (identity as any).last_seen_available;
                    const activityLabel = (identity as any).activity_label;

                    // If canonical state says "Never Used" / "Not Observed", respect it
                    if (activityLabel === 'Never Used' || activityLabel === 'Not Observed') {
                      const detail = (identity as any).activity_detail;
                      return <span className="text-gray-400 italic" title={detail || undefined}>No activity observed</span>;
                    }

                    // Priority 1: canonical timestamp from build_identity_state()
                    const lastSeenTs = (identity as any).last_seen_timestamp;
                    // Priority 2: last_activity_date (direct column)
                    const lastActivityDate = (identity as any).last_activity_date;
                    // Priority 3: effective_last_used (legacy computed)
                    const isConnector = !!identity.is_discovery_connector;
                    const elu = isConnector
                      ? (identity.effective_last_used || new Date().toISOString())
                      : identity.effective_last_used;

                    // Pick best available timestamp
                    const bestTs = lastSeenTs || lastActivityDate || elu;

                    if (bestTs) {
                      // Determine source badge
                      let srcBadge: React.ReactNode = null;
                      if (lastSeenAvailable && authActivity) {
                        if (authActivity.interactive_signin) {
                          srcBadge = <span className="px-1 py-0.5 rounded text-[8px] font-semibold bg-blue-100 text-blue-700">Sign-in</span>;
                        } else if (authActivity.arm_activity) {
                          srcBadge = <span className="px-1 py-0.5 rounded text-[8px] font-semibold bg-emerald-100 text-emerald-700">ARM</span>;
                        } else if (authActivity.non_interactive_signin) {
                          srcBadge = <span className="px-1 py-0.5 rounded text-[8px] font-semibold bg-blue-50 text-blue-600">Non-interactive</span>;
                        }
                      }
                      if (!srcBadge && !lastSeenTs && !lastActivityDate && elu) {
                        const eluSrc = identity.effective_last_used_source;
                        if (eluSrc === 'auditgraph') {
                          srcBadge = <span className="px-1 py-0.5 rounded text-[8px] font-semibold bg-emerald-100 text-emerald-700">AG</span>;
                        } else if (eluSrc === 'azure_signin') {
                          srcBadge = <span className="px-1 py-0.5 rounded text-[8px] font-semibold bg-blue-100 text-blue-700">Azure</span>;
                        }
                      }
                      return (
                        <span className="text-gray-900 inline-flex items-center gap-1">
                          {formatLastUsed(bestTs)}
                          {srcBadge}
                        </span>
                      );
                    }

                    return <span className="text-gray-400 italic">No activity observed</span>;
                  })()}
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
                  Snapshot #{data.evidence.run_id}
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

          {/* AI Agent Evidence Panel — only for classified identities */}
          {!!aiEvidence && aiEvidence.classified && (
            <div className="bg-gradient-to-r from-violet-50 to-indigo-50 border border-violet-200 rounded-2xl p-5 mb-4">
              <div className="flex items-center gap-2 mb-3">
                <svg className="w-5 h-5 text-violet-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
                <h3 className="text-sm font-bold text-violet-900">AI Agent Evidence</h3>
                <span className={`ml-2 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                  aiEvidence.agent_identity_type === 'ai_agent'
                    ? 'bg-violet-200 text-violet-800'
                    : aiEvidence.agent_identity_type === 'ai_privileged_human'
                    ? 'bg-indigo-200 text-indigo-800'
                    : 'bg-amber-200 text-amber-800'
                }`}>
                  {aiEvidence.agent_identity_type === 'ai_agent' ? 'Confirmed AI Agent'
                    : aiEvidence.agent_identity_type === 'ai_privileged_human' ? 'AI-Privileged Human'
                    : 'Possible AI Agent'}
                </span>
                {!!aiEvidence.classification && (
                  <span className="ml-auto text-[10px] text-gray-500">
                    Patterns v{aiEvidence.classification.pattern_version}
                  </span>
                )}
              </div>

              {/* Evidence signals */}
              <div className="space-y-2">
                {aiEvidence.evidence_signals.map((sig, i) => (
                  <div key={i} className={`flex items-start gap-2 text-sm ${sig.is_primary ? 'text-violet-900' : 'text-gray-700'}`}>
                    <span className={`mt-0.5 flex-shrink-0 w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold ${
                      sig.is_primary ? 'bg-violet-600 text-white' : 'bg-gray-300 text-gray-600'
                    }`}>
                      {sig.is_primary ? '!' : '+'}
                    </span>
                    <div className="flex-1">
                      <span className={sig.is_primary ? 'font-semibold' : ''}>{sig.evidence_text}</span>
                      <span className="ml-2 text-[10px] text-gray-500">
                        ({Math.round(sig.confidence * 100)}% confidence)
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              {/* AI Connections — per-role evidence */}
              {aiEvidence.ai_connections.length > 0 && (
                <div className="mt-3 pt-3 border-t border-violet-200">
                  <div className="text-[11px] font-semibold text-violet-700 uppercase mb-1.5">AI Service Connections</div>
                  <div className="space-y-1">
                    {aiEvidence.ai_connections.slice(0, 6).map((conn, i) => (
                      <div key={i} className="flex items-center gap-2 px-2 py-1 rounded bg-white border border-violet-100 text-[11px]">
                        {conn.type === 'rbac_role' ? (
                          <>
                            <svg className="w-3 h-3 text-violet-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                            <span className="font-medium text-violet-800 truncate max-w-[140px]" title={conn.role_name}>{conn.role_name}</span>
                            <span className="text-gray-400 truncate max-w-[180px]" title={conn.scope}>{conn.scope ? conn.scope.split('/').slice(-2).join('/') : ''}</span>
                            <span className="ml-auto text-gray-400 whitespace-nowrap">{(conn as any).source_of_evidence || 'ARM role assignment \u00b7 Static analysis'}</span>
                          </>
                        ) : (
                          <>
                            <svg className="w-3 h-3 text-violet-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                            </svg>
                            <span className="font-medium text-violet-800">{conn.permission}</span>
                            <span className="ml-auto text-gray-400 whitespace-nowrap">{(conn as any).source_of_evidence || 'ARM role assignment \u00b7 Static analysis'}</span>
                          </>
                        )}
                      </div>
                    ))}
                    {aiEvidence.ai_connections.length > 6 && (
                      <div className="text-[10px] text-gray-500 px-2">
                        +{aiEvidence.ai_connections.length - 6} more connections
                      </div>
                    )}
                  </div>
                  <div className="mt-1.5 text-[9px] text-gray-400 italic">
                    Role assignment IS the evidence — no logs needed to prove AI access exists.
                  </div>
                </div>
              )}

              {/* Classification metadata */}
              {!!aiEvidence.classification && (
                <div className="mt-3 pt-2 border-t border-violet-200 flex items-center gap-4 text-[10px] text-gray-500">
                  <span>Platform: <strong className="text-violet-700">{aiEvidence.classification.platform}</strong></span>
                  <span>Classified: {new Date(aiEvidence.classification.classified_at).toLocaleDateString()}</span>
                </div>
              )}
            </div>
          )}

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
            <TabBar
              activeTab={activeTab}
              onTabChange={setActiveTab}
              counts={tabCounts}
              labelOverrides={{
                entra_groups: entraGroupMeta.total > 0
                  ? `Groups (${entraGroupMeta.total})${entraGroupMeta.withAccess > 0 ? ` \u00b7 ${entraGroupMeta.withAccess} with Azure access` : ''}`
                  : undefined,
              }}
              /* Humans authenticate via Entra ID, not app secrets/certificates,
                 so the Credentials tab is always N/A for them \u2014 hide it. They
                 also don't have "owners" in the SPN sense (the existing
                 Ownership tab is built around appOwners); hide it for humans
                 until a reversed "Owns N service principals" view is built. */
              hideTabs={
                identity && (identity.identity_category === 'human_user' || identity.identity_category === 'guest')
                  // OAuth Consents tab makes sense only for client SPN identities
                  // (App Reg / Service Principal / Managed Identity acting as a
                  // client). Humans don't hold OAuth consent grants as the client
                  // side — they're principals on delegated grants instead.
                  ? ['credentials', 'ownership', 'consents']
                  : undefined
              }
            />

            <div className="p-6">
              {/* ═══ OVERVIEW TAB ═══ */}
              {activeTab === 'overview' && (
                <OverviewTab
                  identity={identity}
                  data={data!}
                  roles={data?.roles || []}
                  graphPermissions={data?.graph_permissions || []}
                  appRoles={data?.app_roles || []}
                  owners={data?.owners || []}
                  groupedRoles={groupedRoles}
                  privilegeTier={privilegeTier}
                  effectiveScope={effectiveScope}
                  riskHistory={riskHistory}
                  correlatedAccounts={correlatedAccounts}
                  roleIntel={roleIntel}
                  pimData={pimData}
                  onTabChange={setActiveTab}
                />
              )}

              {/* ═══ ROLES TAB ═══ */}
              {activeTab === 'roles' && (
                <RolesTab
                  identity={identity}
                  data={data!}
                  groupedRoles={groupedRoles}
                  intelByRole={intelByRole}
                  setActiveTab={setActiveTab}
                  pimData={pimData}
                />
              )}

              {/* ═══ PERMISSIONS TAB ═══ */}
              {activeTab === 'permissions' && (
                <PermissionsTab data={data!} />
              )}

              {/* ═══ CREDENTIALS TAB ═══ */}
              {activeTab === 'credentials' && (
                <CredentialsTab identity={identity} data={data!} />
              )}

              {/* ═══ OAUTH CONSENTS TAB (AG-81) ═══ */}
              {activeTab === 'consents' && identity && (
                <ConsentGrantsPanel
                  clientLookupIds={[
                    (identity as any).app_id,
                    (identity as any).object_id,
                    identity.identity_id,
                  ].filter(Boolean) as string[]}
                />
              )}

              {/* ═══ OWNERSHIP TAB ═══ */}
              {activeTab === 'ownership' && (
                <OwnershipTab data={data!} identity={identity} />
              )}

              {/* ═══ EFFECTIVE ACCESS TAB ═══ */}
              {activeTab === 'effective_access' && (
                <EffectiveAccessTab
                  effectiveAccessData={effectiveAccessData}
                  effectiveAccessLoading={effectiveAccessLoading}
                  sensitiveAccessData={sensitiveAccessData}
                  data={data!}
                />
              )}

              {/* ═══ ACCESS GRAPH TAB ═══ */}
              {activeTab === 'access_graph' && identity && (
                <AccessGraphTab identityId={identity.identity_id} />
              )}

              {/* ═══ ANOMALIES TAB ═══ */}
              {activeTab === 'anomalies' && (
                <AnomaliesTab
                  anomalyData={anomalyData}
                  anomalyLoading={anomalyLoading}
                  data={data!}
                />
              )}

              {/* ═══ PIM TAB ═══ */}
              {activeTab === 'pim' && (
                <PimTab
                  pimData={pimData}
                  pimLoading={pimLoading}
                  data={data!}
                  identity={identity}
                  riskLevel={identity.risk_level}
                  identityCategory={identity.identity_category}
                />
              )}

              {/* ═══ COMPLIANCE TAB ═══ */}
              {activeTab === 'compliance' && (
                <IdentityComplianceTab
                  roleIntel={roleIntel}
                  data={data!}
                />
              )}

              {/* ═══ REMEDIATION TAB ═══ */}
              {activeTab === 'remediation' && (
                <RemediationTab
                  remediationData={remediationData}
                  remediationLoading={remediationLoading}
                  remediationActions={remediationActions}
                  actionLoading={actionLoading}
                  executeLoading={executeLoading}
                  handleRemediationAction={handleRemediationAction}
                  handleRemediationExecute={handleRemediationExecute}
                  data={data!}
                />
              )}

              {/* ═══ LIFECYCLE TAB ═══ */}
              {activeTab === 'lifecycle' && (
                <LifecycleTab
                  lifecycleData={lifecycleData}
                  lifecycleLoading={lifecycleLoading}
                  lifecycleFilter={lifecycleFilter}
                  setLifecycleFilter={setLifecycleFilter}
                  data={data!}
                />
              )}

              {/* ═══ SIMULATE TAB ═══ */}
              {activeTab === 'simulate' && (
                <SimulateTab
                  identity={identity}
                  data={data!}
                  simRemovedRoles={simRemovedRoles}
                  setSimRemovedRoles={setSimRemovedRoles}
                  simRemovedPerms={simRemovedPerms}
                  setSimRemovedPerms={setSimRemovedPerms}
                  simAddedRoles={simAddedRoles}
                  setSimAddedRoles={setSimAddedRoles}
                  simAddedPerms={simAddedPerms}
                  setSimAddedPerms={setSimAddedPerms}
                  simResult={simResult}
                  setSimResult={setSimResult}
                  simulating={simulating}
                  simAddRoleOpen={simAddRoleOpen}
                  setSimAddRoleOpen={setSimAddRoleOpen}
                  simAddPermOpen={simAddPermOpen}
                  setSimAddPermOpen={setSimAddPermOpen}
                  simNewRole={simNewRole}
                  setSimNewRole={setSimNewRole}
                  simNewPerm={simNewPerm}
                  setSimNewPerm={setSimNewPerm}
                  runSimulation={runSimulation}
                  resetSimulation={resetSimulation}
                />
              )}

              {/* ═══ ENTRA GROUPS TAB ═══ */}
              {activeTab === 'entra_groups' && <EntraGroupsTab identityId={id!} riskLevel={identity.risk_level} />}

              {/* ═══ SENSITIVE ACCESS TAB ═══ */}
              {activeTab === 'sensitive_access' && <SensitiveAccessTab identityId={id!} roleBasedFallback={(data as any)?.sensitive_access_from_roles} identityCategory={identity.identity_category} />}

              {/* ═══ ATTACK PATHS TAB ═══ */}
              {activeTab === 'attack_paths' && <AttackPathsTab identityId={id!} />}

              {/* ═══ TIMELINE TAB ═══ */}
              {activeTab === 'timeline' && <TimelineTab identityId={id!} />}

            </div>
          </div>
        </>
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
  security_finding: { dot: 'bg-cyan-500', bg: 'bg-cyan-50 border-cyan-200' },
};

const EVENT_LABELS: Record<string, string> = {
  anomaly: 'Anomaly',
  drift: 'Drift',
  risk_change: 'Risk Change',
  pim_activation: 'PIM Activation',
  soar_action: 'SOAR Action',
  remediation: 'Remediation',
  security_finding: 'Security Finding',
};

const SENS_CLASS_COLORS: Record<string, { bg: string; fg: string }> = {
  PHI: { bg: 'rgba(239,68,68,0.12)', fg: '#F87171' },
  PCI: { bg: 'rgba(251,191,36,0.12)', fg: '#FBBF24' },
  PII: { bg: 'rgba(96,165,250,0.12)', fg: '#60A5FA' },
};

// AG-81: OAuth Consents tab — lists every consent grant where THIS identity
// is the client. Tries app_id first (the canonical OAuth client id for SPNs),
// falls back to object_id then identity_id. The /api/consent-grants endpoint
// filters server-side on whichever the consent_grants.client_app_id row
// happens to be populated with (Graph discovery uses object_id for delegated,
// app_id for application; demo seeder uses app_id-or-identity_id).
function ConsentGrantsPanel({ clientLookupIds }: { clientLookupIds: string[] }) {
  const [grants, setGrants] = useState<any[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!clientLookupIds.length) {
      setGrants([]);
      return;
    }
    let cancelled = false;
    // Try each lookup id in order — first non-empty result wins. This handles
    // the SPN-with-multiple-ids case without N round-trips when the first hits.
    const tryNext = async (idx: number) => {
      if (idx >= clientLookupIds.length) {
        if (!cancelled) setGrants([]);
        return;
      }
      try {
        const r = await fetch(`/api/consent-grants?client_app_id=${encodeURIComponent(clientLookupIds[idx])}&limit=100`);
        if (!r.ok) throw new Error('fetch_failed');
        const d = await r.json();
        if (cancelled) return;
        if ((d.grants || []).length > 0) {
          setGrants(d.grants);
        } else {
          await tryNext(idx + 1);
        }
      } catch {
        if (!cancelled) setError('Could not load consent grants.');
      }
    };
    tryNext(0);
    return () => { cancelled = true; };
  }, [clientLookupIds.join('|')]);

  if (error) {
    return <p className="text-xs text-red-600">{error}</p>;
  }
  if (grants === null) {
    return (
      <div className="space-y-2 p-4">
        <div className="h-4 w-1/2 bg-gray-100 dark:bg-slate-800 rounded animate-pulse" />
        <div className="h-4 w-3/4 bg-gray-100 dark:bg-slate-800 rounded animate-pulse" />
      </div>
    );
  }
  if (grants.length === 0) {
    return (
      <div className="p-6 text-center">
        <div className="text-sm text-gray-500 dark:text-slate-400 mb-2">
          No OAuth consent grants discovered for this identity.
        </div>
        <div className="text-xs text-gray-400 dark:text-slate-500">
          Source: Microsoft Graph <span className="font-mono">/oauth2PermissionGrants</span> (delegated)
          + <span className="font-mono">/servicePrincipals/{'{id}'}/appRoleAssignments</span> (application).
        </div>
        <div className="text-xs text-gray-400 dark:text-slate-500 mt-1">
          Requires a discovery scan with <span className="font-mono">Directory.Read.All</span> +{' '}
          <span className="font-mono">Application.Read.All</span>.
        </div>
      </div>
    );
  }

  const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const sorted = grants.slice().sort((a, b) => {
    const r = (sevRank[b.risk_level] || 0) - (sevRank[a.risk_level] || 0);
    return r !== 0 ? r : (b.age_days || 0) - (a.age_days || 0);
  });

  const sevPill = (lvl: string) => {
    const cls =
      lvl === 'critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' :
      lvl === 'high'     ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300' :
      lvl === 'medium'   ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300' :
                           'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300';
    return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide ${cls}`}>{lvl}</span>;
  };

  // AG-85: publisher trust banner — derive from the consent grants themselves
  // (publisher_name / verified_publisher are denormalised onto each grant
  // at discovery time so we don't need a separate API call).
  const firstWithPub = sorted.find(g => g.publisher_name || g.verified_publisher !== null);
  const publisherName: string | null = firstWithPub?.publisher_name || null;
  const isMicrosoft = (publisherName || '').toLowerCase().startsWith('microsoft');
  const verifiedRaw = firstWithPub?.verified_publisher;
  const verified: boolean | null = isMicrosoft ? true : (verifiedRaw === true ? true : verifiedRaw === false ? false : null);
  const trustBadge = isMicrosoft
    ? { tone: 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300', label: 'Microsoft', why: 'First-party Microsoft publisher.' }
    : verified === true
      ? { tone: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300', label: 'Verified publisher', why: 'Publisher attested via MS Verified Publisher.' }
      : verified === false
        ? { tone: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300', label: 'Unverified publisher', why: 'Publisher not verified by Microsoft — high-risk consent grants are consent-phishing indicators.' }
        : { tone: 'bg-gray-100 text-gray-700 dark:bg-slate-800 dark:text-slate-300', label: 'Publisher unknown', why: 'Publisher trust not yet enriched. Re-run discovery to populate.' };

  return (
    <div className="space-y-3 p-4">
      <div className="text-xs text-gray-500 dark:text-slate-400">
        {sorted.length} grant{sorted.length !== 1 ? 's' : ''} —
        {' '}{sorted.filter(g => g.grant_type === 'application').length} application,
        {' '}{sorted.filter(g => g.grant_type === 'delegated').length} delegated
      </div>

      {/* AG-85 publisher trust banner */}
      <div className="flex items-center gap-2 text-xs">
        <span className={`px-2 py-0.5 rounded font-semibold uppercase tracking-wide ${trustBadge.tone}`}>
          {trustBadge.label}
        </span>
        {publisherName && (
          <span className="text-gray-600 dark:text-slate-300">
            {publisherName}
          </span>
        )}
        <span className="text-gray-500 dark:text-slate-500 truncate">{trustBadge.why}</span>
      </div>

      <div className="overflow-x-auto border border-gray-200 dark:border-slate-700 rounded-lg">
        <table className="w-full text-xs">
          <thead className="bg-gray-50 dark:bg-slate-800 text-gray-500 dark:text-slate-400">
            <tr>
              <th className="text-left px-3 py-2 font-medium">Risk</th>
              <th className="text-left px-3 py-2 font-medium">Resource</th>
              <th className="text-left px-3 py-2 font-medium">Scopes</th>
              <th className="text-left px-3 py-2 font-medium">Consent</th>
              <th className="text-left px-3 py-2 font-medium">Approver</th>
              <th className="text-right px-3 py-2 font-medium">Age</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-slate-800">
            {sorted.map((g: any) => (
              <tr key={g.id} className="hover:bg-gray-50 dark:hover:bg-slate-800/50 align-top">
                <td className="px-3 py-2">
                  {sevPill(g.risk_level)}
                  <div className="text-[10px] text-gray-400 dark:text-slate-500 mt-0.5">
                    score {g.risk_score}/100
                  </div>
                </td>
                <td className="px-3 py-2">
                  <div className="text-gray-800 dark:text-slate-200 font-medium">
                    {g.resource_display_name || g.resource_app_id || '—'}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-1 max-w-[420px]">
                    {(g.scopes || []).map((s: string, i: number) => {
                      const isHigh = (g.high_risk_scopes || []).includes(s);
                      const cls = isHigh
                        ? 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800'
                        : 'bg-gray-50 dark:bg-slate-800 text-gray-600 dark:text-slate-300 border border-gray-200 dark:border-slate-700';
                      return (
                        <span key={i} className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${cls}`}>
                          {s}
                        </span>
                      );
                    })}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <div className={g.consent_type === 'AllPrincipals' ? 'text-orange-600 dark:text-orange-400 font-medium' : 'text-gray-600 dark:text-slate-300'}>
                    {g.consent_type === 'AllPrincipals' ? 'Admin (tenant-wide)' :
                     g.consent_type === 'Principal'     ? 'User' :
                     g.consent_type || '—'}
                  </div>
                  <div className="text-[10px] text-gray-400 dark:text-slate-500">
                    {g.grant_type}
                  </div>
                </td>
                <td className="px-3 py-2 text-gray-600 dark:text-slate-300">
                  {g.principal_display_name || (g.consent_type === 'AllPrincipals' ? 'Tenant admin' : '—')}
                </td>
                <td className="px-3 py-2 text-right">
                  {typeof g.age_days === 'number' ? (
                    <span className={
                      g.age_days > 365 ? 'text-red-600 dark:text-red-400 font-medium' :
                      g.age_days > 180 ? 'text-amber-600 dark:text-amber-400' :
                      'text-gray-600 dark:text-slate-300'
                    }>
                      {g.age_days}d
                    </span>
                  ) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="text-[10px] text-gray-400 dark:text-slate-500">
        Source: Microsoft Graph <span className="font-mono">/oauth2PermissionGrants</span> +{' '}
        <span className="font-mono">/servicePrincipals/{'{id}'}/appRoleAssignments</span> ·
        Scope-breadth risk per CVSS-aligned scoring (high-risk scopes highlighted in red)
      </div>
    </div>
  );
}

function SensitiveAccessTab({ identityId, roleBasedFallback, identityCategory }: { identityId: string; roleBasedFallback?: Array<{ role: string; scope: string; description: string; sensitivity: string }>; identityCategory?: string }) {
  const { withConnection } = useConnection();
  const navigate = useNavigate();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const res = await fetch(withConnection(`/api/identities/${identityId}/sensitive-access`));
        if (res.ok) setData(await res.json());
      } catch { /* ignore */ }
      setLoading(false);
    })();
  }, [identityId, withConnection]);

  if (loading) return <div className="p-8 text-center text-gray-500">Loading sensitive access data...</div>;
  if (!data || !data.sensitive_resources || data.sensitive_resources.length === 0) {
    // Role-based fallback: show sensitive roles even without classified resources
    if (roleBasedFallback && roleBasedFallback.length > 0) {
      const sensColor: Record<string, string> = {
        High: 'bg-red-100 text-red-700',
        Medium: 'bg-orange-100 text-orange-700',
      };
      return (
        <div className="p-6">
          <div className="text-xs text-gray-400 uppercase tracking-wider font-semibold mb-3">Sensitive Access (Role-Based Analysis)</div>
          <div className="text-xs text-gray-500 mb-4">No classified resources found, but this identity holds roles that grant access to sensitive resource types.</div>
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 border-b">
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500">Role</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500">Scope</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500">Implication</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500">Sensitivity</th>
              </tr>
            </thead>
            <tbody>
              {roleBasedFallback.map((r, i) => (
                <tr key={i} className="border-b">
                  <td className="px-4 py-3 font-medium text-gray-900">{r.role}</td>
                  <td className="px-4 py-3 text-gray-600 text-xs font-mono truncate max-w-[200px]" title={r.scope}>{r.scope || '—'}</td>
                  <td className="px-4 py-3 text-gray-600 text-xs">{r.description}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-semibold ${sensColor[r.sensitivity] || 'bg-gray-100 text-gray-600'}`}>{r.sensitivity}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }

    return (
      <div className="p-8 text-center">
        <div className="text-gray-400 text-lg mb-2">No Sensitive Access Detected</div>
        <div className="text-gray-500 text-sm">
          This identity does not have RBAC access to any classified resources and holds no roles matching sensitive patterns.
          <br />
          <button onClick={() => navigate('/data-security')} className="text-blue-500 mt-2 text-sm cursor-pointer hover:opacity-80">
            Classify resources in Data Security
          </button>
        </div>
      </div>
    );
  }

  const br = data.blast_radius || {};
  const resources = data.sensitive_resources;
  const isHuman = identityCategory === 'human_user' || identityCategory === 'guest';
  const phiCount = (br.by_classification || {}).PHI || 0;
  const pciCount = (br.by_classification || {}).PCI || 0;
  const piiCount = (br.by_classification || {}).PII || 0;

  return (
    <div className="p-6">
      {/* Human user summary callout */}
      {isHuman && (br.total_sensitive || 0) > 0 && (
        <div className="border-l-4 border-l-amber-400 bg-amber-50 rounded-r-lg p-4 mb-6">
          <div className="text-sm text-amber-800">
            This human user has direct access to <span className="font-bold">{br.total_sensitive}</span> sensitive resources
            {(phiCount > 0 || pciCount > 0 || piiCount > 0) && (
              <> including {phiCount > 0 && <><span className="font-bold">{phiCount}</span> PHI</>}{phiCount > 0 && (pciCount > 0 || piiCount > 0) ? ', ' : ''}{pciCount > 0 && <><span className="font-bold">{pciCount}</span> PCI</>}{pciCount > 0 && piiCount > 0 ? ', and ' : ''}{piiCount > 0 && <><span className="font-bold">{piiCount}</span> PII</>} classified assets</>
            )}.
            Per HIPAA §164.312, access should be reviewed quarterly.
          </div>
        </div>
      )}

      {/* Blast Radius Summary */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        <div className="rounded-lg p-4" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
          <div className="text-2xl font-bold font-mono" style={{ color: '#F87171' }}>{br.total_sensitive || 0}</div>
          <div className="text-xs text-gray-500">Sensitive Resources</div>
        </div>
        {(['PHI', 'PCI', 'PII'] as const).map(cls => {
          const count = (br.by_classification || {})[cls] || 0;
          const c = SENS_CLASS_COLORS[cls];
          return (
            <div key={cls} className="rounded-lg p-4" style={{ background: c.bg, border: `1px solid ${c.fg}33` }}>
              <div className="text-2xl font-bold font-mono" style={{ color: c.fg }}>{count}</div>
              <div className="text-xs text-gray-500">{cls} Resources</div>
            </div>
          );
        })}
      </div>

      {/* Access Table */}
      <div className="bg-white rounded-lg border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 border-b">
              {['Resource', 'Type', 'Classification', 'Access Level', 'Role', 'Access Source', 'Risk'].map(h => (
                <th key={h} className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {resources.map((r: any, i: number) => (
              <tr key={i} className="border-b hover:bg-gray-50 cursor-pointer"
                onClick={() => navigate(`/resources/detail?rid=${encodeURIComponent(r.resource_path)}`)}>
                <td className="px-4 py-3 font-medium">{r.resource_name}</td>
                <td className="px-4 py-3">
                  <span className="px-2 py-0.5 rounded text-xs font-medium"
                    style={{
                      background: r.resource_type === 'storage_account' ? 'rgba(59,130,246,0.12)' : 'rgba(139,92,246,0.12)',
                      color: r.resource_type === 'storage_account' ? '#60A5FA' : '#A78BFA',
                    }}>
                    {r.resource_type === 'storage_account' ? 'Storage' : 'Key Vault'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="px-2 py-0.5 rounded text-xs font-bold font-mono"
                    style={{
                      background: SENS_CLASS_COLORS[r.classification]?.bg || 'rgba(255,255,255,0.06)',
                      color: SENS_CLASS_COLORS[r.classification]?.fg || '#999',
                    }}>
                    {r.classification}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="px-2 py-0.5 rounded text-xs font-semibold"
                    style={{
                      background: r.access_level === 'Admin' ? 'rgba(239,68,68,0.12)' : r.access_level === 'Write' ? 'rgba(251,191,36,0.12)' : 'rgba(96,165,250,0.12)',
                      color: r.access_level === 'Admin' ? '#F87171' : r.access_level === 'Write' ? '#FBBF24' : '#60A5FA',
                    }}>
                    {r.access_level}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-600 text-xs">{r.role_name}</td>
                <td className="px-4 py-3 text-gray-500 text-xs capitalize">{r.access_source?.replace('_', ' ')}</td>
                <td className="px-4 py-3">
                  <span className="px-2 py-0.5 rounded text-xs font-bold uppercase"
                    style={{
                      background: r.resource_risk_level === 'critical' ? 'rgba(255,23,68,0.12)' : r.resource_risk_level === 'high' ? 'rgba(255,109,0,0.12)' : 'rgba(255,179,0,0.12)',
                      color: r.resource_risk_level === 'critical' ? '#FF1744' : r.resource_risk_level === 'high' ? '#FF6D00' : '#FFB300',
                    }}>
                    {r.resource_risk_level}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

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
          <div className="text-sm text-gray-500 font-medium">No timeline events detected yet</div>
          <div className="text-xs text-gray-400 mt-1">Anomalies, PIM activations, risk changes, and drift events will appear here after the next discovery scan.</div>
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
                  {/* AG-PILOT-TIMELINE-CONTRAST (2026-06-08): customer
                      reported timeline text was hardly visible. Bumped
                      ink + sizes for the whole row. */}
                  {/* Timestamp column */}
                  <div className="w-[72px] flex-shrink-0 text-right pt-1">
                    <div className="text-[11px] text-slate-700 font-mono font-medium">
                      {event.timestamp ? new Date(event.timestamp).toLocaleDateString() : '—'}
                    </div>
                    <div className="text-[10px] text-slate-500">
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
                      <span className="text-[11px] font-bold uppercase text-slate-700 tracking-wide">
                        {EVENT_LABELS[event.event_type] || event.event_type}
                      </span>
                      {event.severity && (
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                          event.severity === 'critical' ? 'bg-red-100 text-red-700' :
                          event.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                          event.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                          'bg-gray-100 text-gray-700'
                        }`}>
                          {event.severity}
                        </span>
                      )}
                    </div>
                    <div className="text-sm font-semibold text-slate-900">{event.title}</div>
                    {event.description && (
                      <div className="text-xs text-slate-700 mt-0.5 line-clamp-2">{event.description}</div>
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

/* ═══ Attack Paths Tab Component ═══ */

const AP_TIER_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-700',
  HIGH: 'bg-orange-100 text-orange-700',
  MEDIUM: 'bg-yellow-100 text-yellow-700',
  LOW: 'bg-blue-100 text-blue-700',
};

function AttackPathsTab({ identityId }: { identityId: string }) {
  const { withConnection } = useConnection();
  const navigate = useNavigate();
  const [paths, setPaths] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/identities/${identityId}/persisted-attack-paths?${withConnection('')}`)
      .then(r => r.ok ? r.json() : { paths: [] })
      .then(d => setPaths(d.paths || d.attack_paths || []))
      .finally(() => setLoading(false));
  }, [identityId, withConnection]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="animate-spin h-6 w-6 border-2 border-blue-600 border-t-transparent rounded-full" />
      </div>
    );
  }

  if (paths.length === 0) {
    return (
      <div className="text-center py-16 text-sm text-gray-500">
        No attack paths found for this identity.
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-gray-900">{paths.length} Attack Path{paths.length !== 1 ? 's' : ''}</h3>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b text-left">
            <th className="px-4 py-2 text-xs font-medium text-gray-500">Path</th>
            <th className="px-4 py-2 text-xs font-medium text-gray-500">Target</th>
            <th className="px-4 py-2 text-xs font-medium text-gray-500">Severity</th>
            <th className="px-4 py-2 text-xs font-medium text-gray-500">Score</th>
            <th className="px-4 py-2 text-xs font-medium text-gray-500">Indicators</th>
          </tr>
        </thead>
        <tbody>
          {paths.map((p: any) => {
            // Canonical field resolution — read keys defensively with fallback chains.
            const pathSource =
              p.source_entity_name ||
              p.highest_role ||
              p.source_entity_type ||
              p.path_type ||
              '—';

            // target_resource_name is not a stored column; derive from
            // path_nodes[-1].name/label/id or fall back to target_resource_id.
            let pathTarget: string = '—';
            if (p.target_resource_name) {
              pathTarget = p.target_resource_name;
            } else if (Array.isArray(p.path_nodes) && p.path_nodes.length > 0) {
              const tail = p.path_nodes[p.path_nodes.length - 1] || {};
              pathTarget = tail.name || tail.label || tail.id || p.target_resource_id || p.target_resource_type || p.highest_scope_level || '—';
            } else {
              pathTarget = p.target_resource_id || p.target_resource_type || p.highest_scope_level || '—';
            }

            const pathSeverity = (
              p.path_risk_tier ||
              p.risk_tier ||
              p.severity ||
              '—'
            ).toUpperCase();

            const pathScore =
              (p.path_risk_score ?? p.risk_score ?? p.blast_radius_score ?? p.exploitability ?? 0) as number;

            const pathFlags: string[] = [
              p.has_keyvault_access && 'Key Vault',
              p.has_subscription_scope && 'Subscription scope',
              p.has_no_owner && 'No owner',
              p.has_expired_credentials && 'Expired creds',
            ].filter(Boolean) as string[];

            // privilege_chain — may be array, string, or derived from path_nodes
            let chainSteps: string | null = null;
            if (Array.isArray(p.privilege_chain)) {
              chainSteps = p.privilege_chain.join(' → ');
            } else if (typeof p.privilege_chain === 'string' && p.privilege_chain) {
              chainSteps = p.privilege_chain;
            } else if (Array.isArray(p.path_nodes) && p.path_nodes.length > 1) {
              chainSteps = p.path_nodes
                .map((n: any) => n.name || n.label || n.id || n.type)
                .filter(Boolean)
                .join(' → ');
            }

            const pathDescription = p.description || chainSteps || null;

            return (
              <tr
                key={p.id}
                onClick={() => navigate(`/attack-paths/${p.id}`)}
                className="border-b cursor-pointer hover:bg-gray-50 transition-colors"
              >
                <td className="px-4 py-3 text-gray-900 align-top">
                  <div className="font-medium">{pathSource}</div>
                  {pathDescription && (
                    <div className="text-xs text-gray-500 mt-0.5 line-clamp-2">{pathDescription}</div>
                  )}
                </td>
                <td className="px-4 py-3 text-gray-600 align-top">{pathTarget}</td>
                <td className="px-4 py-3 align-top">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${AP_TIER_BADGE[pathSeverity] || 'bg-gray-100 text-gray-600'}`}>
                    {pathSeverity}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-xs align-top">
                  {pathScore > 0 ? pathScore : 'Computing'}
                </td>
                <td className="px-4 py-3 align-top">
                  <div className="flex flex-wrap gap-1">
                    {pathFlags.length > 0
                      ? pathFlags.map((f) => (
                          <span
                            key={f}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-700 border border-gray-200"
                          >
                            {f}
                          </span>
                        ))
                      : <span className="text-xs text-gray-400">—</span>}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
