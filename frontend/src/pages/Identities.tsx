import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useToast } from '../components/ToastProvider';
import { useAuth } from '../contexts/AuthContext';
import { useConnection } from '../contexts/ConnectionContext';
import { useFeatureFlag } from '../contexts/FeatureFlagContext';
import QueryBuilder from '../components/QueryBuilder';
import type { AdvancedQuery, QueryFieldDefinition } from '../types';
import { queryIdentities, getQueryFields } from '../services/api';
import Sparkline from '../components/Sparkline';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { downloadCSV, downloadJSON, exportFilename, IDENTITY_CSV_COLUMNS, buildExportMeta } from '../utils/exportUtils';
import { MultiSelectFilter, type SelectOption } from '../components/ui/MultiSelectFilter';
import { maskCredential } from '../utils/maskCredential';
import { STATUS_BADGE, type IdentityStatus } from '../utils/resolveStatus';
import IdentityDrawer from '../components/IdentityDrawer';
import ExposureGraph from '../components/graph/ExposureGraph';
import { OrphanBadgeCompact } from '../components/lineage';
import LineageDetailPanel from '../components/LineageDetailPanel';
import {
  type IdentityCategory, type RiskLevel, type DormantStatus,
  type PrivilegedLevel, type EffectiveScope, type CredentialHealth,
  CATEGORY_FILTER_OPTIONS, RISK_FILTER_OPTIONS, RISK_ORDER, RISK_BADGE, RISK_SOLID, CLOUD_BADGE,
  THRESHOLDS, DORMANT_LABELS, DATA_EXPLANATIONS,
  PRIVILEGED_LEVELS, EFFECTIVE_SCOPE_CONFIG, EFFECTIVE_SCOPE_ORDER, CREDENTIAL_HEALTH_CONFIG,
  SCOPE_LABELS, CATEGORY_LABELS_MULTI, IDENTITY_CATEGORIES,
  safeLower, normalizeCategoryFromBackend, getCategoryLabel, getCategoryShortLabel, getDormantStatus as getDormantStatusFromActivity,
  getCategoriesForClouds, MANAGED_IDENTITY_GROUP,
} from '../constants/metrics';

interface IdentityRow {
  identity_id: string;
  display_name: string;
  identity_type?: string;
  identity_category?: IdentityCategory;
  cloud?: string;
  created_datetime?: string | null;
  last_seen_auth?: string | null;
  last_sign_in?: string | null;
  api_permission_count?: number;
  role_count?: number;
  rbac_role_count?: number;
  entra_role_count?: number;
  rbac_max_risk?: RiskLevel;
  entra_max_risk?: RiskLevel;
  graph_max_risk?: RiskLevel;
  app_role_count?: number;
  credential_count?: number;
  credential_expiration?: string | null;
  credential_status?: string | null;
  owner_display_name?: string | null;
  owner_count?: number;
  status?: IdentityStatus;
  enabled?: boolean;
  risk_level?: RiskLevel;
  risk_score?: number;
  activity_status?: string;
  privilege_tier?: number;
  pim_eligible_count?: number;
  has_permanent_assignment?: boolean;
  ca_coverage_status?: string | null;
  ca_mfa_enforced?: boolean;
  subscription_id?: string | null;
  subscription_name?: string | null;
  primary_subscription_id?: string | null;
  additional_subscription_count?: number;
  effective_scope?: EffectiveScope;
  privileged_level?: PrivilegedLevel;
  credential_health?: CredentialHealth;
  identity_age_days?: number | null;
  // AI Agent Governance (additive only)
  agent_identity_type?: string | null;
  detected_platform?: string | null;
  classification_confidence?: number | null;
  // Identity Lineage (Phase 91)
  lineage_score?: number | null;
  orphan_status?: string | null;
  // Discovery connector flag
  is_discovery_connector?: boolean;
  // App Registration lineage
  app_registration_object_id?: string | null;
  app_registration_name?: string | null;
  is_external_app?: boolean;
  app_reg_publisher_domain?: string | null;
  app_reg_sign_in_audience?: string | null;
  app_reg_owner_display_name?: string | null;
  app_reg_owner_id?: string | null;
  // Workload topology inference
  workload_type?: string | null;
  workload_confidence?: number;
  role_pattern_matched?: string | null;
  workload_risk_flags?: string[];
  // App Registration metadata signals
  app_reg_reply_url_hostnames?: string[] | null;
  app_reg_likely_service?: string | null;
  app_reg_likely_service_type?: string | null;
  app_reg_identifier_uris?: string[] | null;
  app_reg_notes?: string | null;
  app_reg_required_apis?: string[] | null;
  // Sign-in pattern fields
  signin_pattern?: string | null;
  last_delegated_signin?: string | null;
  last_noninteractive_signin?: string | null;
  days_since_last_signin?: number | null;
  // Verdict assembly fields (Prompt 5)
  verdict_confidence?: string | null;
  verdict_score?: number;
  workload_origin?: string | null;
  workload_origin_source?: string | null;
  recommended_action?: string | null;
  verdict_action_text?: string | null;
  verdict_signals?: Array<{ source: string; weight: number; detail: string }>;
  verdict_risk_summary?: string[];
  // Federated credential classification
  federated_workload_type?: string | null;
  federated_workload_name?: string | null;
  // Dependency impact
  dependency_impact?: string | null;
  // Observed usage tracking
  observed_last_used?: string | null;
  // Sign-in authentication provenance
  last_signin_at?: string | null;
  last_signin_ip?: string | null;
  auth_source?: string | null;
}

interface SavedView {
  id: number;
  name: string;
  description: string | null;
  filters: Record<string, any>;
  sort_field: string | null;
  sort_direction: string | null;
  is_default: boolean;
  is_shared: boolean;
  user_id: number;
  creator_name?: string;
}

const WORKLOAD_BADGE: Record<string, { label: string; badgeClass: string; short: string }> = {
  container_workload: { label: 'Container / AKS', badgeClass: 'bg-blue-100 text-blue-700', short: 'Container' },
  cicd_pipeline:      { label: 'CI/CD Pipeline', badgeClass: 'bg-purple-100 text-purple-700', short: 'CI/CD' },
  data_pipeline:      { label: 'Data Pipeline', badgeClass: 'bg-teal-100 text-teal-700', short: 'Data' },
  config_reader:      { label: 'Config Reader', badgeClass: 'bg-gray-100 text-gray-600', short: 'Reader' },
  monitoring_agent:   { label: 'Monitoring Agent', badgeClass: 'bg-gray-100 text-gray-600', short: 'Monitor' },
  audit_connector:    { label: 'Audit Connector', badgeClass: 'bg-amber-100 text-amber-700', short: 'Audit' },
  admin_identity:     { label: 'Admin / Privileged', badgeClass: 'bg-red-100 text-red-700', short: 'Admin' },
  storage_workload:   { label: 'Storage Workload', badgeClass: 'bg-cyan-100 text-cyan-700', short: 'Storage' },
};

type SortField =
  | 'display_name'
  | 'identity_type'
  | 'identity_category'
  | 'subscription_id'
  | 'subscription_name'
  | 'cloud'
  | 'risk_level'
  | 'entra_role_count'
  | 'rbac_role_count'
  | 'api_permission_count'
  | 'privilege_tier'
  | 'credential_expiration'
  | 'created_datetime'
  | 'last_seen_auth'
  | 'dormant'
  | 'effective_scope'
  | 'credential_health'
  | 'status'
  | 'owner_display_name'
  | 'last_signin_at'
  | 'last_signin_ip'
  | 'recommended_action';

// ─── Helpers ───────────────────────────────────────────────────────

function formatDate(d?: string | null): string {
  if (!d) return '—';
  try { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }); }
  catch { return d; }
}

function formatAge(days: number | null | undefined): string {
  if (days == null) return '—';
  if (days < 30) return `${days}d`;
  if (days < 365) return `${Math.floor(days / 30)}mo`;
  const yrs = Math.floor(days / 365);
  const mos = Math.floor((days % 365) / 30);
  return mos > 0 ? `${yrs}y ${mos}mo` : `${yrs}y`;
}

function formatLastSeen(dateStr?: string | null): { label: string; colorClass: string } {
  if (!dateStr) return { label: 'Never', colorClass: 'text-gray-400 italic' };
  try {
    const days = Math.floor((Date.now() - new Date(dateStr).getTime()) / 86400000);
    if (days === 0) return { label: 'Today', colorClass: 'text-green-500' };
    if (days <= 6) return { label: `${days}d ago`, colorClass: 'text-green-500' };
    if (days <= 29) return { label: `${Math.floor(days / 7)}w ago`, colorClass: 'text-green-500' };
    if (days <= 89) return { label: `${Math.floor(days / 30)}mo ago`, colorClass: 'text-yellow-500' };
    return {
      label: new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
      colorClass: 'text-red-400',
    };
  } catch {
    return { label: dateStr, colorClass: 'text-gray-500' };
  }
}

function credentialCountdownText(iso?: string | null): { text: string; color: string } | null {
  if (!iso) return null;
  try {
    const days = Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
    if (days < 0) return { text: `Expired ${Math.abs(days)}d ago`, color: 'text-red-600' };
    if (days === 0) return { text: 'Expires today', color: 'text-red-600' };
    if (days <= 30) return { text: `${days}d left`, color: days <= 7 ? 'text-red-600' : 'text-orange-600' };
    return { text: `${days}d left`, color: 'text-green-600' };
  } catch { return null; }
}

function getPrivilegeTier(row: IdentityRow): number {
  // Use backend-computed tier (role-name-based) when available
  if (row.privilege_tier != null) return row.privilege_tier;
  // Fallback: derive from max risk level
  const rbac = RISK_ORDER[safeLower(row.rbac_max_risk)] || 0;
  const entra = RISK_ORDER[safeLower(row.entra_max_risk)] || 0;
  const graph = RISK_ORDER[safeLower(row.graph_max_risk)] || 0;
  const maxRisk = Math.max(rbac, entra, graph);
  if (maxRisk >= 5) return 0;
  if (maxRisk >= 4) return 1;
  if (maxRisk >= 3) return 2;
  return 3;
}

function getDormantStatus(row: IdentityRow): DormantStatus {
  return getDormantStatusFromActivity(row.activity_status);
}

function getComplianceRelevance(i: IdentityRow): string {
  const frameworks: string[] = [];
  const risk = i.risk_level || 'unknown';
  const hasPrivilegedRoles = (i.entra_role_count ?? 0) > 0 || (i.rbac_role_count ?? 0) > 0;
  if (risk === 'critical' || risk === 'high') frameworks.push('SOC2', 'HIPAA', 'PCI-DSS');
  else if (risk === 'medium' && hasPrivilegedRoles) frameworks.push('SOC2');
  if ((i.identity_category === 'human_user' || i.identity_category === 'guest') && hasPrivilegedRoles)
    frameworks.push('HIPAA §164.312');
  return frameworks.length > 0 ? Array.from(new Set(frameworks)).join(', ') : 'Low Priority';
}

// ─── Small presentational components ───────────────────────────────

function SortHeader({ label, field, currentField, currentDir, onSort }: {
  label: string; field: SortField; currentField: SortField; currentDir: 'asc' | 'desc'; onSort: (f: SortField) => void;
}) {
  const isActive = currentField === field;
  return (
    <th className="px-2 py-2.5 cursor-pointer select-none hover:bg-gray-100 whitespace-nowrap text-xs" onClick={() => onSort(field)}>
      <div className="flex items-center gap-0.5">
        <span>{label}</span>
        <span className={`text-[10px] ${isActive ? 'text-blue-600' : 'text-gray-400'}`}>
          {isActive ? (currentDir === 'asc' ? '▲' : '▼') : '↕'}
        </span>
      </div>
    </th>
  );
}

function CloudBadge({ cloud }: { cloud?: string }) {
  const c = safeLower(cloud) || 'azure';
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${CLOUD_BADGE[c] || CLOUD_BADGE.azure}`}>{c}</span>;
}

function StatusBadge({ status }: { status?: IdentityStatus }) {
  const s = (status || 'unknown') as IdentityStatus;
  const display = STATUS_BADGE[s] || STATUS_BADGE.unknown;
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${display.badge_class}`}>{display.label}</span>;
}

function RiskBadge({ level, score }: { level?: RiskLevel; score?: number }) {
  const risk = safeLower(level);
  return (
    <div className="flex items-center gap-1">
      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[risk] || 'bg-gray-100 text-gray-600'}`}>
        {risk || '?'}
      </span>
      {score !== undefined && score > 0 && <span className="text-[10px] text-gray-400 font-mono">{score}</span>}
    </div>
  );
}

function RiskDot({ level }: { level?: string }) {
  const s = RISK_SOLID[safeLower(level)];
  return <span className={`inline-block w-1.5 h-1.5 rounded-full ${s?.bg || 'bg-gray-300'}`} />;
}

function TierBadge({ tier }: { tier: number }) {
  const cfg: Record<number, { label: string; color: string; title: string }> = {
    0: { label: 'T0', color: 'bg-red-100 text-red-800 border-red-300', title: 'T0 Control Plane — Global Admin, Privileged Role Admin, tenant-wide Owner' },
    1: { label: 'T1', color: 'bg-orange-100 text-orange-800 border-orange-300', title: 'T1 Management Plane — User Admin, Exchange Admin, subscription Owner/Contributor' },
    2: { label: 'T2', color: 'bg-yellow-100 text-yellow-800 border-yellow-300', title: 'T2 Data/App Plane — scoped roles, risky Graph API permissions' },
    3: { label: 'T3', color: 'bg-gray-100 text-gray-600 border-gray-300', title: 'T3 Standard — no privileged roles' },
  };
  const c = cfg[tier] || cfg[3];
  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold ${c.color}`} title={c.title}>
      {c.label}
    </span>
  );
}

function DormantBadge({ status }: { status: DormantStatus }) {
  const cfg = DORMANT_LABELS[status];
  return (
    <span
      className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${cfg.color}`}
      title={cfg.tooltip}
    >
      {cfg.label}
    </span>
  );
}

const CATEGORY_BADGE_COLORS: Record<string, string> = {
  service_principal: 'bg-purple-50 text-purple-700',
  managed_identity_system: 'bg-cyan-50 text-cyan-700',
  managed_identity_user: 'bg-teal-50 text-teal-700',
  human_user: 'bg-indigo-50 text-indigo-700',
  guest: 'bg-pink-50 text-pink-700',
};

function CategoryBadge({ category, cloud }: { category?: IdentityCategory; cloud?: string }) {
  const color = CATEGORY_BADGE_COLORS[category || ''] || 'bg-gray-50 text-gray-600';
  const cloudLabels = cloud && CATEGORY_LABELS_MULTI[cloud.toLowerCase()];
  const label = (cloudLabels && cloudLabels[category || '']) || getCategoryShortLabel(category);
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${color}`}>{label}</span>;
}

function PrivilegedBadge({ level }: { level?: PrivilegedLevel }) {
  const cfg = PRIVILEGED_LEVELS[level || 'standard'];
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${cfg.color}`} title={cfg.tooltip}>{cfg.label}</span>;
}

function ScopeBadge({ scope, cloud }: { scope?: EffectiveScope; cloud?: string }) {
  const cfg = EFFECTIVE_SCOPE_CONFIG[scope || 'none'];
  const cloudLabels = cloud && SCOPE_LABELS[cloud.toLowerCase()];
  const label = (cloudLabels && cloudLabels[scope || '']) || cfg.label;
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${cfg.color}`}>{label}</span>;
}

function CredentialHealthBadge({ health }: { health?: CredentialHealth }) {
  const cfg = CREDENTIAL_HEALTH_CONFIG[health || 'none'];
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${cfg.color}`}>{cfg.label}</span>;
}

function TypeLabel({ type }: { type?: string }) {
  const t = safeLower(type);
  const labels: Record<string, string> = {
    serviceprincipal: 'App',
    service_principal: 'App',
    user: 'User',
    group: 'Group',
    managed_identity: 'MI',
  };
  return <span className="text-[11px] text-gray-600">{labels[t] || type || '—'}</span>;
}

// ─── Main component ────────────────────────────────────────────────

export default function IdentitiesPage() {
  const { selectedConnectionId, connectionParam, withConnection } = useConnection();
  const [identities, setIdentities] = useState<IdentityRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showMicrosoft, setShowMicrosoft] = useState(false);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [multiRiskFilter, setMultiRiskFilter] = useState<string[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<IdentityCategory | 'all'>('all');
  const [multiCategoryFilter, setMultiCategoryFilter] = useState<string[]>([]);
  const [ownerFilter, setOwnerFilter] = useState<'all' | 'unowned'>('all');
  const [activityFilter, setActivityFilter] = useState<'all' | 'dormant' | 'dormant_strict'>('all');
  const [tierFilter, setTierFilter] = useState<number[] | 'all'>('all');
  const [credentialFilter, setCredentialFilter] = useState<'all' | 'expired' | 'expiring_soon' | 'valid' | 'none'>('all');
  const [caFilter, setCaFilter] = useState<'all' | 'covered' | 'not_covered'>('all');
  const [subscriptionFilter, setSubscriptionFilter] = useState<string>('all');
  const [multiSubscriptionFilter, setMultiSubscriptionFilter] = useState<string[]>([]);
  const [allSubscriptions, setAllSubscriptions] = useState<{subscription_id: string; subscription_name: string; monitored?: boolean; status?: string}[]>([]);
  // Defense-in-depth: only show activated (monitored) subscriptions in dropdown,
  // even if the API response includes non-monitored ones (e.g. fallback path).
  const activatedSubscriptions = useMemo(
    () => allSubscriptions.filter(s => s.monitored !== false),
    [allSubscriptions]
  );
  const [groupFilter, setGroupFilter] = useState<number | 'all'>('all');
  const [multiGroupFilter, setMultiGroupFilter] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [multiStatusFilter, setMultiStatusFilter] = useState<string[]>([]);
  const [hasRolesFilter, setHasRolesFilter] = useState(false);
  const [workloadFilter, setWorkloadFilter] = useState(false);
  const [contextBanner, setContextBanner] = useState<string | null>(null);
  const [contributingPillar, setContributingPillar] = useState<string | null>(null);
  const [agirsFactor, setAgirsFactor] = useState<string | null>(null);
  const [showDeleted, setShowDeleted] = useState(false);
  // Identity Lineage orphan filter
  const [orphanFilter, setOrphanFilter] = useState(false);
  // AI Agent Governance filter state (additive, gated by feature flag)
  const agentFilterEnabled = useFeatureFlag('ai_agent_governance');
  const [agentFilter, setAgentFilter] = useState(false);              // filter active
  const [agentCount, setAgentCount] = useState(0);                    // badge count
  const [allGroups, setAllGroups] = useState<{id: number; name: string; color: string; group_type: string; member_count: number}[]>([]);
  const [groupMemberIds, setGroupMemberIds] = useState<Set<string> | null>(null);
  const [sortField, setSortField] = useState<SortField>('recommended_action');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkMenuOpen, setBulkMenuOpen] = useState(false);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkConfirm, setBulkConfirm] = useState<{ status: string; label: string } | null>(null);
  const [addToGroupOpen, setAddToGroupOpen] = useState(false);
  const bulkMenuRef = useRef<HTMLDivElement>(null);

  // Saved Views state (Phase 34)
  const [savedViews, setSavedViews] = useState<SavedView[]>([]);
  const [activeViewId, setActiveViewId] = useState<number | null>(null);
  const [saveModalOpen, setSaveModalOpen] = useState(false);
  const [editingView, setEditingView] = useState<SavedView | null>(null);
  const [viewForm, setViewForm] = useState({ name: '', description: '', is_shared: false });
  const [viewSaving, setViewSaving] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<number | null>(null);

  // Phase 39: Advanced Query Builder state
  const [queryMode, setQueryMode] = useState<'simple' | 'advanced'>('simple');
  const [advancedQuery, setAdvancedQuery] = useState<AdvancedQuery>({ groups: [] });
  const [queryFields, setQueryFields] = useState<QueryFieldDefinition[]>([]);
  const [valueSuggestions, setValueSuggestions] = useState<Record<string, string[]>>({});
  const [queryLoading, setQueryLoading] = useState(false);
  const [queryResults, setQueryResults] = useState<IdentityRow[] | null>(null);
  const [queryTotal, setQueryTotal] = useState(0);
  const [riskHistories, setRiskHistories] = useState<Record<string, number[]>>({});

  // V2: Drawer + view mode state
  const [drawerIdentityId, setDrawerIdentityId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'table' | 'graph'>('table');

  // Lineage detail panel
  const [lineagePanelIdentity, setLineagePanelIdentity] = useState<IdentityRow | null>(null);

  // Enabled cloud providers (drives category filter options)
  const [enabledClouds, setEnabledClouds] = useState<string[]>([]);
  const [cloudFilter, setCloudFilter] = useState<string>('all');

  // Subscription scope summary for tenant scope bar
  const [scopeSummary, setScopeSummary] = useState<{ activated: number; discovered: number; tenant_name: string } | null>(null);

  // Phase 7: Snapshot selector state
  const [snapshots, setSnapshots] = useState<{ id: number; status: string; completed_at: string | null; total_identities: number }[]>([]);

  const { addToast } = useToast();
  const { user, isAdmin, activeOrgId, activeOrgName } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Dynamic column labels based on active cloud filter
  function accountLabel(suffix: 'ID' | 'Name'): string {
    const params = new URLSearchParams(location.search);
    const cloud = params.get('cloud');
    if (cloud === 'aws') return `Account ${suffix}`;
    if (cloud === 'gcp') return `Project ${suffix}`;
    return `Subscription ${suffix}`;
  }

  // Build category filter options from enabled clouds only, with "Managed Identities" group
  const MI_GROUP_KEY = '__managed_identities__';
  const categoryOptions = useMemo(() => {
    const cats = getCategoriesForClouds(enabledClouds);
    const hasBothMI = MANAGED_IDENTITY_GROUP.every(c => cats.includes(c));
    const opts: { value: string; label: string }[] = [
      { value: 'all', label: 'All Categories' },
    ];
    for (const key of cats) {
      // Insert the group option before the first individual MI option
      if (key === MANAGED_IDENTITY_GROUP[0] && hasBothMI) {
        opts.push({ value: MI_GROUP_KEY, label: 'Managed Identities' });
      }
      opts.push({ value: key, label: IDENTITY_CATEGORIES[key].label });
    }
    return opts;
  }, [enabledClouds]);

  // URL param sync — supports both legacy param names and CISO Dashboard param names
  useEffect(() => {
    const params = new URLSearchParams(location.search);

    // Reset pillar filter (only set if ?pillar=X is present)
    if (!params.get('pillar')) setContributingPillar(null);

    // AGIRS factor drill-down (exact-match server-side filter)
    const agirsParam = params.get('agirs_factor');
    setAgirsFactor(agirsParam || null);
    setShowDeleted(params.get('show_deleted') === 'true');

    // Category: identity_category, category (also map CISO values: Human→human_user, ServicePrincipal→service_principal)
    const catParam = params.get('identity_category') || params.get('category');
    const CISO_CAT_MAP: Record<string, string> = {
      'Human': 'human_user', 'ServicePrincipal': 'service_principal',
      'ManagedIdentity': 'managed_identity', 'Guest': 'guest',
    };
    const mappedCat = catParam ? (CISO_CAT_MAP[catParam] || catParam) : null;
    if (mappedCat === 'managed_identity') {
      // "Managed Identities" group — select both MI types
      setMultiCategoryFilter([...MANAGED_IDENTITY_GROUP]);
      setCategoryFilter('all');
    } else if (mappedCat && CATEGORY_FILTER_OPTIONS.find(o => o.value === mappedCat)) {
      setCategoryFilter(mappedCat as IdentityCategory);
      setMultiCategoryFilter([]);
    } else {
      setCategoryFilter('all');
      // Don't clear multiCategoryFilter from URL — it's set via dropdown only
    }

    // Risk: risk_level, risk (supports comma-separated: risk=critical,high)
    const riskParam = params.get('risk_level') || params.get('risk');
    if (riskParam) {
      const riskValues = riskParam.split(',').map(r => r.toLowerCase().trim()).filter(r => RISK_FILTER_OPTIONS.some(o => o.value === r));
      if (riskValues.length === 1) {
        setRiskFilter(riskValues[0] as RiskLevel);
        setMultiRiskFilter([]);
      } else if (riskValues.length > 1) {
        setRiskFilter('all');
        setMultiRiskFilter(riskValues);
      } else {
        setRiskFilter('all');
        setMultiRiskFilter([]);
      }
    } else {
      setRiskFilter('all');
      setMultiRiskFilter([]);
    }

    // Owner: owner_status=unowned, owner=none
    const ownerParam = params.get('owner_status') || params.get('owner');
    setOwnerFilter(ownerParam === 'unowned' || ownerParam === 'none' ? 'unowned' : 'all');

    // Activity/Dormant: activity_status=dormant|dormant_strict, dormant=true
    const activityParam = params.get('activity_status');
    const dormantParam = params.get('dormant');
    if (activityParam === 'dormant_strict') {
      setActivityFilter('dormant_strict');
    } else if (activityParam === 'dormant' || dormantParam === 'true') {
      setActivityFilter('dormant');
    } else {
      setActivityFilter('all');
    }

    // Privilege tier
    const tierParam = params.get('privilege_tier');
    const privilegedParam = params.get('privileged');
    if (privilegedParam === 'true') {
      setTierFilter([0, 1]); // T0 + T1 = Privileged + Elevated
    } else if (tierParam != null) {
      const tiers = tierParam.split(',').map(Number).filter(t => [0, 1, 2, 3].includes(t));
      setTierFilter(tiers.length > 0 ? tiers : 'all');
    } else {
      setTierFilter('all');
    }

    // Credential
    const credParam = params.get('credential_status') || params.get('credential_expiry');
    setCredentialFilter(credParam && ['expired', 'expiring_soon', 'valid', 'none'].includes(credParam) ? credParam as any : 'all');

    // CA coverage
    const caParam = params.get('ca_coverage');
    setCaFilter(caParam === 'covered' ? 'covered' : caParam === 'not_covered' ? 'not_covered' : 'all');

    // Status (e.g., ?status=Disabled)
    const statusParam = params.get('status');
    if (statusParam) {
      setStatusFilter(statusParam.toLowerCase());
      setMultiStatusFilter([]);
    } else {
      setStatusFilter('all');
    }

    // hasRoles (e.g., ?hasRoles=true)
    setHasRolesFilter(params.get('hasRoles') === 'true');

    // Workload identities (e.g., ?workload=true → SP + managed identity types)
    setWorkloadFilter(params.get('workload') === 'true');

    // Search
    const searchParam = params.get('search');
    if (searchParam) setSearch(searchParam);

    // Context banner for combined filter params from CISO dashboard drill-downs
    const pillarParam = params.get('pillar');
    const remParam = params.get('remediation');
    const workloadParam = params.get('workload');
    const activityParamForBanner = params.get('activity_status');
    const hasRolesParam = params.get('hasRoles');
    const statusParamForBanner = params.get('status');
    const catParamForBanner = params.get('category') || params.get('identity_category');
    // AGIRS factor banners
    const AGIRS_BANNER: Record<string, string> = {
      h1_ghost: 'HIRI — Ghost Humans: disabled/deleted accounts with active role assignments',
      h2_dormant_priv: 'HIRI — Dormant Privileged: stale/never-used humans with privileged roles',
      h3_over_priv: 'HIRI — Over-Privileged: humans with risk score \u226570 or T0 tier',
      h4_ext_guest: 'HIRI — Privileged Guests: external guests with privileged role assignments',
      n1_orphaned: 'NHIRI — Orphaned: non-human identities with no assigned owner',
      n2_dormant: 'NHIRI — Dormant NHIs: inactive non-human identities with active roles',
      n3_zombie: 'NHIRI — Zombie NHIs: stale + high-risk + valid credentials',
      n4_expired: 'NHIRI — Expired Credentials: NHIs with credentials expiring within 30 days',
    };
    if (agirsParam && AGIRS_BANNER[agirsParam]) {
      setContextBanner(AGIRS_BANNER[agirsParam]);
    } else if (activityParamForBanner === 'dormant_strict' && params.get('privileged') === 'true') {
      setContextBanner('Dormant accounts with active privileged roles (stale or never used)');
    } else if (activityParamForBanner === 'dormant_strict') {
      setContextBanner('Dormant identities (stale or never used — excludes idle)');
    } else if (statusParamForBanner?.toLowerCase() === 'disabled' && hasRolesParam === 'true') {
      setContextBanner('Ghost accounts — disabled in Entra ID but retain active RBAC roles');
    } else if (catParamForBanner === 'guest' && hasRolesParam === 'true') {
      setContextBanner('Guest users with active role assignments');
    } else if (workloadParam === 'true' && ownerParam === 'none') {
      setContextBanner('Unowned workload identities (Service Principals + Managed Identities)');
    } else if (workloadParam === 'true') {
      setContextBanner('Showing workload identities (Service Principals + Managed Identities)');
    } else if (riskParam && riskParam.includes(',')) {
      setContextBanner(`Showing ${riskParam.split(',').join(' + ')} risk identities`);
    } else if (pillarParam) {
      // Map URL slug to API pillar name and trigger server-side filtering
      const PILLAR_API_MAP: Record<string, string> = {
        'effective-privilege': 'effective_privilege',
        'credential-risk': 'credential_risk',
        'trust-federation': 'trust_federation',
        'usage-dormancy': 'usage_dormancy',
        'ownership-governance': 'ownership_governance',
        'external-exposure': 'external_exposure',
      };
      const apiPillar = PILLAR_API_MAP[pillarParam] || pillarParam.replace(/-/g, '_');
      setContributingPillar(apiPillar);
      const label = pillarParam.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      setContextBanner(`Showing identities flagged by ${label} pillar`);
    } else if (remParam) {
      setContextBanner(`Showing identities affected by remediation ${remParam}`);
    } else {
      setContextBanner(null);
    }
  }, [location.search]);

  // Fetch
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        // When agent filter is active, fetch from agent-identities endpoint
        if (agentFilter) {
          const resp = await fetch('/api/agent-identities?per_page=500&sort_by=agirs_score&sort_dir=desc');
          if (!resp.ok) throw new Error('Failed to fetch agent identities');
          const data = await resp.json();
          const rows: IdentityRow[] = (data.items || []).map((raw: any) => ({
            identity_id: raw.identity_id || '',
            display_name: raw.display_name || '',
            identity_type: raw.identity_type,
            identity_category: normalizeCategoryFromBackend(raw.identity_category),
            cloud: raw.cloud || 'azure',
            created_datetime: raw.created_datetime || null,
            last_seen_auth: raw.last_sign_in || null,
            last_sign_in: raw.last_sign_in || null,
            credential_count: raw.credential_count ?? 0,
            credential_status: raw.credential_risk || raw.credential_status || null,
            owner_display_name: raw.owner_display_name || null,
            owner_count: raw.owner_count ?? 0,
            status: raw.enabled === false ? 'disabled' : 'active',
            enabled: raw.enabled,
            risk_level: safeLower(raw.risk_level || 'unknown') as RiskLevel,
            risk_score: raw.risk_score ?? 0,
            activity_status: raw.activity_status || 'unknown',
            privilege_tier: raw.privilege_tier ?? undefined,
            pim_eligible_count: raw.pim_eligible_count ?? 0,
            ca_coverage_status: raw.ca_coverage_status || null,
            primary_subscription_id: raw.primary_subscription_id || null,
            additional_subscription_count: raw.additional_subscription_count ?? 0,
            // AI Agent fields (additive)
            agent_identity_type: raw.agent_identity_type || null,
            detected_platform: raw.detected_platform || null,
            classification_confidence: raw.classification_confidence ?? null,
            // Lineage fields
            workload_type: raw.workload_type || null,
            workload_confidence: raw.workload_confidence ?? 0,
            workload_origin: raw.workload_origin || null,
            verdict_confidence: raw.verdict_confidence || null,
            recommended_action: raw.recommended_action || null,
            federated_workload_type: raw.federated_workload_type || null,
            federated_workload_name: raw.federated_workload_name || null,
            dependency_impact: raw.dependency_impact || null,
            is_discovery_connector: raw.is_discovery_connector ?? false,
            app_registration_object_id: raw.app_registration_object_id || null,
            is_external_app: raw.is_external_app ?? false,
            app_reg_owner_display_name: raw.app_reg_owner_display_name || null,
            signin_pattern: raw.signin_pattern || null,
            last_noninteractive_signin: raw.last_noninteractive_signin || null,
            days_since_last_signin: raw.days_since_last_signin ?? null,
            observed_last_used: raw.observed_last_used || null,
            last_signin_at: raw.last_signin_at || null,
            last_signin_ip: raw.last_signin_ip || null,
            auth_source: raw.auth_source || null,
          }));
          if (!cancelled) setIdentities(rows);
          return;
        }

        const params = new URLSearchParams();
        params.set('hide_microsoft', String(!showMicrosoft));
        params.set('activated_only', 'true');
        if (contributingPillar) params.set('contributing_pillar', contributingPillar);
        if (agirsFactor) params.set('agirs_factor', agirsFactor);
        if (showDeleted) params.set('show_deleted', 'true');
        if (connectionParam) params.append(...connectionParam.split('=') as [string, string]);
        // Wire filters to backend — server-side filtering for correct pagination
        if (multiRiskFilter.length === 1) params.set('risk_level', multiRiskFilter[0]);
        else if (riskFilter !== 'all') params.set('risk_level', riskFilter);
        if (multiCategoryFilter.length === 1) params.set('identity_category', multiCategoryFilter[0]);
        else if (categoryFilter !== 'all') params.set('identity_category', categoryFilter);
        if (cloudFilter !== 'all') params.set('cloud', cloudFilter);
        if (search) params.set('search', search);
        const resp = await fetch(`/api/identities?${params}`);
        if (!resp.ok) throw new Error('Failed to fetch identities');
        const data = await resp.json();
        const rows: IdentityRow[] = (data.identities || []).map((raw: any) => ({
          identity_id: raw.identity_id || '',
          display_name: raw.display_name || '',
          identity_type: raw.identity_type,
          identity_category: normalizeCategoryFromBackend(raw.identity_category),
          cloud: raw.cloud || 'azure',
          created_datetime: raw.created_datetime || null,
          last_seen_auth: raw.last_seen_auth || raw.last_sign_in || null,
          last_sign_in: raw.last_sign_in || null,
          api_permission_count: raw.api_permission_count ?? 0,
          role_count: raw.role_count ?? 0,
          rbac_role_count: raw.rbac_role_count ?? 0,
          entra_role_count: raw.entra_role_count ?? 0,
          rbac_max_risk: safeLower(raw.rbac_max_risk || 'info') as RiskLevel,
          entra_max_risk: safeLower(raw.entra_max_risk || 'info') as RiskLevel,
          graph_max_risk: safeLower(raw.graph_max_risk || 'info') as RiskLevel,
          app_role_count: raw.app_role_count ?? 0,
          credential_count: raw.credential_count ?? 0,
          credential_expiration: raw.credential_expiration || raw.next_expiry || null,
          credential_status: raw.credential_status,
          owner_display_name: raw.owner_display_name || null,
          owner_count: raw.owner_count ?? 0,
          status: raw.status || (raw.enabled === false ? 'disabled' : 'active'),
          enabled: raw.enabled,
          risk_level: safeLower(raw.risk_level || 'unknown') as RiskLevel,
          risk_score: raw.risk_score ?? 0,
          activity_status: raw.activity_status || 'unknown',
          privilege_tier: raw.privilege_tier ?? undefined,
          pim_eligible_count: raw.pim_eligible_count ?? 0,
          has_permanent_assignment: raw.has_permanent_assignment ?? false,
          ca_coverage_status: raw.ca_coverage_status || null,
          ca_mfa_enforced: raw.ca_mfa_enforced ?? false,
          subscription_id: raw.subscription_id || null,
          subscription_name: raw.subscription_name || null,
          primary_subscription_id: raw.primary_subscription_id || null,
          additional_subscription_count: raw.additional_subscription_count ?? 0,
          effective_scope: raw.effective_scope || 'none',
          privileged_level: raw.privileged_level || 'standard',
          credential_health: raw.credential_health || 'none',
          identity_age_days: raw.identity_age_days ?? null,
          is_discovery_connector: raw.is_discovery_connector ?? false,
          app_registration_object_id: raw.app_registration_object_id || null,
          app_registration_name: raw.app_registration_name || null,
          is_external_app: raw.is_external_app ?? false,
          app_reg_publisher_domain: raw.app_reg_publisher_domain || null,
          app_reg_sign_in_audience: raw.app_reg_sign_in_audience || null,
          app_reg_owner_display_name: raw.app_reg_owner_display_name || null,
          app_reg_owner_id: raw.app_reg_owner_id || null,
          // Workload + verdict lineage fields
          workload_type: raw.workload_type || null,
          workload_confidence: raw.workload_confidence ?? 0,
          role_pattern_matched: raw.role_pattern_matched || null,
          workload_risk_flags: raw.workload_risk_flags || [],
          app_reg_reply_url_hostnames: raw.app_reg_reply_url_hostnames || null,
          app_reg_likely_service: raw.app_reg_likely_service || null,
          app_reg_likely_service_type: raw.app_reg_likely_service_type || null,
          signin_pattern: raw.signin_pattern || null,
          last_noninteractive_signin: raw.last_noninteractive_signin || null,
          last_delegated_signin: raw.last_delegated_signin || null,
          days_since_last_signin: raw.days_since_last_signin ?? null,
          verdict_confidence: raw.verdict_confidence || null,
          verdict_score: raw.verdict_score ?? 0,
          workload_origin: raw.workload_origin || null,
          workload_origin_source: raw.workload_origin_source || null,
          recommended_action: raw.recommended_action || null,
          verdict_action_text: raw.verdict_action_text || null,
          verdict_signals: raw.verdict_signals || [],
          verdict_risk_summary: raw.verdict_risk_summary || [],
          federated_workload_type: raw.federated_workload_type || null,
          federated_workload_name: raw.federated_workload_name || null,
          dependency_impact: raw.dependency_impact || null,
          observed_last_used: raw.observed_last_used || null,
          last_signin_at: raw.last_signin_at || null,
          last_signin_ip: raw.last_signin_ip || null,
          auth_source: raw.auth_source || null,
        }));
        if (!cancelled) setIdentities(rows);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load identities');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [showMicrosoft, selectedConnectionId, contributingPillar, agirsFactor, showDeleted, activeOrgId, agentFilter,
      riskFilter, multiRiskFilter, categoryFilter, multiCategoryFilter, cloudFilter, search]);

  // ─── Batch risk histories for sparkline column ─────────────────
  useEffect(() => {
    if (identities.length === 0) return;
    let cancelled = false;
    (async () => {
      try {
        const ids = identities.map(i => i.identity_id);
        const resp = await fetch('/api/identities/risk-history/batch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ identity_ids: ids.slice(0, 200), limit: 10 }),
        });
        if (resp.ok) {
          const data = await resp.json();
          if (!cancelled) setRiskHistories(data.histories || {});
        }
      } catch { /* non-blocking */ }
    })();
    return () => { cancelled = true; };
  }, [identities]);

  // ─── Saved Views (Phase 34) ─────────────────────────────────────
  const loadViews = useCallback(async () => {
    try {
      const res = await fetch('/api/saved-views');
      if (res.ok) {
        const data = await res.json();
        setSavedViews(data.views || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { loadViews(); }, [loadViews]);

  // Load distinct subscriptions for filter — only activated (monitored) ones
  useEffect(() => {
    setSubscriptionFilter('all');
    fetch(withConnection('/api/subscriptions/distinct?activated_only=true'))
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => setAllSubscriptions(d.subscriptions || []))
      .catch(() => setAllSubscriptions([]));
  }, [activeOrgId, selectedConnectionId, withConnection]);

  // Load subscription scope summary for tenant scope bar
  useEffect(() => {
    fetch(withConnection('/api/subscriptions/scope-summary'))
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => setScopeSummary(d))
      .catch(() => setScopeSummary(null));
  }, [activeOrgId, selectedConnectionId, withConnection]);

  // Load enabled cloud providers for category filter
  useEffect(() => {
    fetch('/api/tenant/config')
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(cfg => {
        const clouds = ['azure', 'aws', 'gcp'].filter(k => cfg?.cloud_providers?.[k]?.enabled);
        setEnabledClouds(clouds);
      })
      .catch(() => setEnabledClouds([]));
  }, [activeOrgId]);

  // Fetch agent count when feature flag is enabled
  useEffect(() => {
    if (!agentFilterEnabled) return;
    fetch('/api/agent-identities/count')
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) setAgentCount(data.ai_agent || 0); })
      .catch(() => {});
  }, [agentFilterEnabled]);

  // Load groups for filter (refetch on org/connection switch, deduplicate by name)
  useEffect(() => {
    setGroupFilter('all');
    setMultiGroupFilter([]);
    fetch(withConnection('/api/groups'))
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => {
        const raw = d.groups || [];
        // Deduplicate by group name — combine counts across subscriptions
        const byName = new Map<string, { id: number; name: string; color: string; group_type: string; member_count: number }>();
        for (const g of raw) {
          const key = (g.name || g.display_name || '').toLowerCase();
          if (byName.has(key)) {
            const existing = byName.get(key)!;
            existing.member_count = Math.max(existing.member_count, g.member_count || 0);
          } else {
            byName.set(key, { id: g.id, name: g.name || g.display_name, color: g.color || '', group_type: g.group_type || '', member_count: g.member_count || 0 });
          }
        }
        setAllGroups(Array.from(byName.values()));
      })
      .catch(() => setAllGroups([]));
  }, [activeOrgId, selectedConnectionId, withConnection]);

  // Phase 7: Load snapshots for selector (refetch on org switch)
  useEffect(() => {
    fetch('/api/runs')
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => setSnapshots((d.runs || []).filter((r: any) => r.status === 'completed').slice(0, 10)))
      .catch(() => setSnapshots([]));
  }, [activeOrgId]);

  // When group filter changes, fetch members (supports multi-group)
  useEffect(() => {
    const activeGroups = multiGroupFilter.length > 0 ? multiGroupFilter : (groupFilter !== 'all' ? [String(groupFilter)] : []);
    if (activeGroups.length === 0) { setGroupMemberIds(null); return; }
    Promise.all(activeGroups.map(gid =>
      fetch(`/api/groups/${gid}`)
        .then(r => r.ok ? r.json() : Promise.reject())
        .then(d => (d.members || []).map((m: any) => m.identity_id as string))
        .catch(() => [] as string[])
    )).then(results => {
      const ids = new Set<string>(results.flat());
      setGroupMemberIds(ids);
    });
  }, [groupFilter, multiGroupFilter]);

  // Fetch query field definitions for advanced mode
  useEffect(() => {
    getQueryFields()
      .then((data: any) => {
        setQueryFields(data.fields || []);
        setValueSuggestions(data.value_suggestions || {});
      })
      .catch(() => {});
  }, []);

  // Execute advanced query (debounced)
  useEffect(() => {
    if (queryMode !== 'advanced') { setQueryResults(null); return; }
    const hasConditions = advancedQuery.groups.some(g => g.conditions.some(c => c.field));
    if (!hasConditions) { setQueryResults(null); setQueryTotal(0); return; }

    const timer = setTimeout(async () => {
      setQueryLoading(true);
      try {
        const payload = advancedQuery.groups
          .map(g => ({
            conditions: g.conditions
              .filter(c => c.field && (c.operator === 'is_empty' || c.operator === 'is_not_empty' || c.value !== ''))
              .map(c => ({ field: c.field, operator: c.operator, value: c.value })),
          }))
          .filter(g => g.conditions.length > 0);

        if (payload.length === 0) { setQueryResults(null); setQueryTotal(0); setQueryLoading(false); return; }

        const data = await queryIdentities(payload, sortField, sortDir);
        const rows: IdentityRow[] = (data.identities || []).map((raw: any) => ({
          identity_id: raw.identity_id || '',
          display_name: raw.display_name || '',
          identity_type: raw.identity_type,
          identity_category: normalizeCategoryFromBackend(raw.identity_category),
          cloud: raw.cloud || 'azure',
          created_datetime: raw.created_datetime || null,
          last_seen_auth: raw.last_seen_auth || raw.last_sign_in || null,
          last_sign_in: raw.last_sign_in || null,
          api_permission_count: raw.api_permission_count ?? 0,
          role_count: raw.role_count ?? 0,
          rbac_role_count: raw.rbac_role_count ?? 0,
          entra_role_count: raw.entra_role_count ?? 0,
          rbac_max_risk: safeLower(raw.rbac_max_risk || 'info') as RiskLevel,
          entra_max_risk: safeLower(raw.entra_max_risk || 'info') as RiskLevel,
          graph_max_risk: safeLower(raw.graph_max_risk || 'info') as RiskLevel,
          app_role_count: raw.app_role_count ?? 0,
          credential_count: raw.credential_count ?? 0,
          credential_expiration: raw.credential_expiration || raw.next_expiry || null,
          credential_status: raw.credential_status,
          owner_display_name: raw.owner_display_name || null,
          owner_count: raw.owner_count ?? 0,
          status: raw.status || (raw.enabled === false ? 'disabled' : 'active'),
          enabled: raw.enabled,
          risk_level: safeLower(raw.risk_level || 'unknown') as RiskLevel,
          risk_score: raw.risk_score ?? 0,
          activity_status: raw.activity_status || 'unknown',
          privilege_tier: raw.privilege_tier ?? undefined,
          pim_eligible_count: raw.pim_eligible_count ?? 0,
          has_permanent_assignment: raw.has_permanent_assignment ?? false,
          ca_coverage_status: raw.ca_coverage_status || null,
          ca_mfa_enforced: raw.ca_mfa_enforced ?? false,
          subscription_id: raw.subscription_id || null,
          subscription_name: raw.subscription_name || null,
          primary_subscription_id: raw.primary_subscription_id || null,
          additional_subscription_count: raw.additional_subscription_count ?? 0,
          effective_scope: raw.effective_scope || 'none',
          privileged_level: raw.privileged_level || 'standard',
          credential_health: raw.credential_health || 'none',
          identity_age_days: raw.identity_age_days ?? null,
          is_discovery_connector: raw.is_discovery_connector ?? false,
          app_registration_object_id: raw.app_registration_object_id || null,
          app_registration_name: raw.app_registration_name || null,
          is_external_app: raw.is_external_app ?? false,
          app_reg_publisher_domain: raw.app_reg_publisher_domain || null,
          app_reg_sign_in_audience: raw.app_reg_sign_in_audience || null,
          app_reg_owner_display_name: raw.app_reg_owner_display_name || null,
          app_reg_owner_id: raw.app_reg_owner_id || null,
          workload_type: raw.workload_type || null,
          workload_confidence: raw.workload_confidence ?? 0,
          app_reg_likely_service: raw.app_reg_likely_service || null,
          signin_pattern: raw.signin_pattern || null,
          last_noninteractive_signin: raw.last_noninteractive_signin || null,
          days_since_last_signin: raw.days_since_last_signin ?? null,
          verdict_confidence: raw.verdict_confidence || null,
          verdict_score: raw.verdict_score ?? 0,
          workload_origin: raw.workload_origin || null,
          workload_origin_source: raw.workload_origin_source || null,
          recommended_action: raw.recommended_action || null,
          federated_workload_type: raw.federated_workload_type || null,
          federated_workload_name: raw.federated_workload_name || null,
          dependency_impact: raw.dependency_impact || null,
          observed_last_used: raw.observed_last_used || null,
        }));
        setQueryResults(rows);
        setQueryTotal(data.total ?? rows.length);
      } catch (e: any) {
        const msg = e?.response?.data?.error || e?.message || 'Query failed';
        addToast(msg, 'error');
        setQueryResults(null);
        setQueryTotal(0);
      } finally {
        setQueryLoading(false);
      }
    }, 500);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queryMode, advancedQuery, sortField, sortDir]);

  // Auto-apply default view on mount (only if no URL params)
  useEffect(() => {
    if (savedViews.length === 0 || location.search) return;
    const defaultView = savedViews.find(v => v.is_default && v.user_id === user?.id);
    if (defaultView) applyView(defaultView);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [savedViews.length]);

  function getCurrentFilters(): Record<string, any> {
    if (queryMode === 'advanced') {
      return {
        _query_mode: 'advanced',
        _advanced_query: {
          groups: advancedQuery.groups.map(g => ({
            conditions: g.conditions.map(c => ({
              field: c.field, operator: c.operator, value: c.value,
            })),
          })),
        },
      };
    }
    const f: Record<string, any> = {};
    if (search) f.search = search;
    if (multiRiskFilter.length > 0) f.risk_levels = multiRiskFilter;
    else if (riskFilter !== 'all') f.risk_level = riskFilter;
    if (multiCategoryFilter.length > 0) f.categories = multiCategoryFilter;
    else if (categoryFilter !== 'all') f.category = categoryFilter;
    if (multiSubscriptionFilter.length > 0) f.subscription_ids = multiSubscriptionFilter;
    else if (subscriptionFilter !== 'all') f.subscription_id = subscriptionFilter;
    if (multiGroupFilter.length > 0) f.group_ids = multiGroupFilter;
    if (multiStatusFilter.length > 0) f.statuses = multiStatusFilter;
    if (ownerFilter !== 'all') f.owner_status = ownerFilter;
    if (activityFilter !== 'all') f.activity_status = activityFilter;
    if (tierFilter !== 'all') f.privilege_tier = tierFilter.join(',');
    if (credentialFilter !== 'all') f.credential_status = credentialFilter;
    if (caFilter !== 'all') f.ca_coverage = caFilter;
    return f;
  }

  function applyView(view: SavedView) {
    const f = view.filters || {};
    if (f._query_mode === 'advanced' && f._advanced_query) {
      setQueryMode('advanced');
      const aq = f._advanced_query;
      setAdvancedQuery({
        groups: (aq.groups || []).map((g: any) => ({
          id: Math.random().toString(36).slice(2, 10),
          conditions: (g.conditions || []).map((c: any) => ({
            id: Math.random().toString(36).slice(2, 10),
            field: c.field, operator: c.operator, value: c.value,
          })),
        })),
      });
      if (view.sort_field) setSortField(view.sort_field as SortField);
      if (view.sort_direction) setSortDir(view.sort_direction as 'asc' | 'desc');
      setActiveViewId(view.id);
      return;
    }
    setQueryMode('simple');
    setSearch(f.search || '');
    // Restore multi-select risk
    if (Array.isArray(f.risk_levels) && f.risk_levels.length > 0) {
      setMultiRiskFilter(f.risk_levels);
      setRiskFilter('all');
    } else {
      setMultiRiskFilter([]);
      setRiskFilter((f.risk_level as RiskLevel) || 'all');
    }
    // Restore multi-select category
    if (Array.isArray(f.categories) && f.categories.length > 0) {
      setMultiCategoryFilter(f.categories);
      setCategoryFilter('all');
    } else {
      setMultiCategoryFilter([]);
      setCategoryFilter((f.category as IdentityCategory) || 'all');
    }
    // Restore multi-select subscriptions
    if (Array.isArray(f.subscription_ids) && f.subscription_ids.length > 0) {
      setMultiSubscriptionFilter(f.subscription_ids);
      setSubscriptionFilter('all');
    } else {
      setMultiSubscriptionFilter([]);
      setSubscriptionFilter(f.subscription_id || 'all');
    }
    // Restore multi-select groups
    setMultiGroupFilter(Array.isArray(f.group_ids) ? f.group_ids : []);
    setGroupFilter('all');
    // Restore multi-select statuses
    setMultiStatusFilter(Array.isArray(f.statuses) ? f.statuses : []);
    setStatusFilter('all');
    setOwnerFilter(f.owner_status === 'unowned' ? 'unowned' : 'all');
    setActivityFilter(f.activity_status === 'dormant' ? 'dormant' : 'all');
    if (f.privilege_tier) {
      const tierStr = typeof f.privilege_tier === 'string' ? f.privilege_tier : '';
      const tiers = tierStr.split(',').map(Number).filter((t: number) => [0, 1, 2, 3].includes(t));
      setTierFilter(tiers.length > 0 ? tiers : 'all');
    } else {
      setTierFilter('all');
    }
    setCredentialFilter((f.credential_status as any) || 'all');
    setCaFilter((f.ca_coverage as any) || 'all');
    if (view.sort_field) setSortField(view.sort_field as SortField);
    if (view.sort_direction) setSortDir(view.sort_direction as 'asc' | 'desc');
    setActiveViewId(view.id);
  }

  async function saveView() {
    if (!viewForm.name.trim()) return;
    setViewSaving(true);
    try {
      const body: any = {
        name: viewForm.name.trim(),
        description: viewForm.description.trim() || null,
        filters: getCurrentFilters(),
        sort_field: sortField,
        sort_direction: sortDir,
        is_shared: viewForm.is_shared,
      };

      const isEdit = !!editingView;
      const url = isEdit ? `/api/saved-views/${editingView!.id}` : '/api/saved-views';
      const method = isEdit ? 'PUT' : 'POST';

      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => null);
        throw new Error(err?.error || 'Failed to save view');
      }
      const saved = await res.json();
      addToast(`View "${saved.name}" ${isEdit ? 'updated' : 'saved'}`, 'success');
      setSaveModalOpen(false);
      setEditingView(null);
      setViewForm({ name: '', description: '', is_shared: false });
      setActiveViewId(saved.id);
      await loadViews();
    } catch (e: any) {
      addToast(e?.message || 'Failed to save view', 'error');
    } finally {
      setViewSaving(false);
    }
  }

  async function deleteView(viewId: number) {
    try {
      const res = await fetch(`/api/saved-views/${viewId}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed to delete');
      addToast('View deleted', 'success');
      if (activeViewId === viewId) setActiveViewId(null);
      setDeleteConfirmId(null);
      await loadViews();
    } catch (e: any) {
      addToast(e?.message || 'Failed to delete view', 'error');
    }
  }

  async function toggleDefault(view: SavedView) {
    try {
      if (view.is_default) {
        // Unset default by updating is_default to false
        await fetch(`/api/saved-views/${view.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ is_default: false }),
        });
      } else {
        await fetch(`/api/saved-views/${view.id}/default`, { method: 'POST' });
      }
      await loadViews();
    } catch { /* ignore */ }
  }

  // Clear activeViewId when filters change manually
  function clearActiveView() {
    if (activeViewId !== null) setActiveViewId(null);
  }

  // Filter & sort
  const filtered = useMemo(() => {
    // In advanced mode, use server-filtered results
    if (queryMode === 'advanced' && queryResults !== null) {
      const result = [...queryResults];
      // Client-side sort for instant re-sort without re-querying
      result.sort((a, b) => {
        let aVal: any, bVal: any;
        switch (sortField) {
          case 'display_name': aVal = safeLower(a.display_name); bVal = safeLower(b.display_name); break;
          case 'identity_type': aVal = safeLower(a.identity_type); bVal = safeLower(b.identity_type); break;
          case 'identity_category': aVal = safeLower(a.identity_category); bVal = safeLower(b.identity_category); break;
          case 'cloud': aVal = safeLower(a.cloud); bVal = safeLower(b.cloud); break;
          case 'entra_role_count': aVal = a.entra_role_count ?? 0; bVal = b.entra_role_count ?? 0; break;
          case 'rbac_role_count': aVal = a.rbac_role_count ?? 0; bVal = b.rbac_role_count ?? 0; break;
          case 'api_permission_count': aVal = a.api_permission_count ?? 0; bVal = b.api_permission_count ?? 0; break;
          case 'privilege_tier': aVal = getPrivilegeTier(a); bVal = getPrivilegeTier(b); break;
          case 'effective_scope': aVal = EFFECTIVE_SCOPE_ORDER[a.effective_scope || 'none']; bVal = EFFECTIVE_SCOPE_ORDER[b.effective_scope || 'none']; break;
          case 'credential_health': {
            const chOrder: Record<string, number> = { expired: 4, expiring: 3, ok: 2, none: 1 };
            aVal = chOrder[a.credential_health || 'none'] || 0; bVal = chOrder[b.credential_health || 'none'] || 0; break;
          }
          case 'credential_expiration':
            aVal = a.credential_expiration ? new Date(a.credential_expiration).getTime() : Infinity;
            bVal = b.credential_expiration ? new Date(b.credential_expiration).getTime() : Infinity;
            break;
          case 'created_datetime':
            aVal = a.created_datetime ? new Date(a.created_datetime).getTime() : 0;
            bVal = b.created_datetime ? new Date(b.created_datetime).getTime() : 0;
            break;
          case 'last_seen_auth':
            aVal = a.last_seen_auth ? new Date(a.last_seen_auth).getTime() : 0;
            bVal = b.last_seen_auth ? new Date(b.last_seen_auth).getTime() : 0;
            break;
          case 'dormant':
            const dormOrderAdv: Record<string, number> = { yes: 4, never: 3, idle: 2, no: 1, 'new': 1, unknown: 0 };
            aVal = dormOrderAdv[getDormantStatus(a)] || 0;
            bVal = dormOrderAdv[getDormantStatus(b)] || 0;
            break;
          case 'status': {
            const stOrder: Record<string, number> = { deleted: 4, disabled: 3, unknown: 2, active: 1 };
            aVal = stOrder[a.status || 'active'] || 0; bVal = stOrder[b.status || 'active'] || 0; break;
          }
          case 'last_signin_at':
            aVal = a.last_signin_at ? new Date(a.last_signin_at).getTime() : 0;
            bVal = b.last_signin_at ? new Date(b.last_signin_at).getTime() : 0;
            break;
          case 'last_signin_ip':
            aVal = safeLower(a.last_signin_ip); bVal = safeLower(b.last_signin_ip); break;
          case 'recommended_action': {
            const vOrd: Record<string, number> = { ORPHANED: 5, AT_RISK: 4, UNUSED: 3, STALE: 2, NEEDS_REVIEW: 1, HEALTHY: 0 };
            aVal = vOrd[a.recommended_action || ''] ?? -1; bVal = vOrd[b.recommended_action || ''] ?? -1;
            if (aVal === bVal) {
              // Tiebreak: longest-unseen first (asc by last_signin_at)
              const aTime = a.last_signin_at ? new Date(a.last_signin_at).getTime() : 0;
              const bTime = b.last_signin_at ? new Date(b.last_signin_at).getTime() : 0;
              return aTime - bTime;
            }
            break;
          }
          case 'risk_level':
          default:
            aVal = RISK_ORDER[safeLower(a.risk_level)] || 0;
            bVal = RISK_ORDER[safeLower(b.risk_level)] || 0;
        }
        if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
        return 0;
      });
      return result;
    }

    // Simple filter mode (existing logic)
    let result = [...identities];

    // Client-side safety net: exclude identities from non-activated subscriptions
    if (allSubscriptions.length > 0) {
      const activatedSubIds = new Set(allSubscriptions.filter(s => s.monitored).map(s => s.subscription_id));
      if (activatedSubIds.size > 0) {
        result = result.filter(i => {
          const subId = i.primary_subscription_id || i.subscription_id;
          return !subId || activatedSubIds.has(subId);
        });
      }
    }

    const s = safeLower(search);
    if (s) result = result.filter(i => safeLower(i.display_name).includes(s) || safeLower(i.identity_id).includes(s) || safeLower(i.owner_display_name).includes(s));
    if (cloudFilter !== 'all') result = result.filter(i => safeLower(i.cloud) === cloudFilter);
    if (multiRiskFilter.length > 0) {
      result = result.filter(i => multiRiskFilter.includes(safeLower(i.risk_level)));
    } else if (riskFilter !== 'all') {
      result = result.filter(i => safeLower(i.risk_level) === safeLower(riskFilter));
    }
    if (multiCategoryFilter.length > 0) {
      result = result.filter(i => multiCategoryFilter.includes(i.identity_category || ''));
    } else if (categoryFilter !== 'all') {
      result = result.filter(i => i.identity_category === categoryFilter);
    }
    if (workloadFilter) result = result.filter(i => ['service_principal', 'managed_identity_system', 'managed_identity_user'].includes(i.identity_category || ''));
    if (multiSubscriptionFilter.length > 0) {
      result = result.filter(i => multiSubscriptionFilter.includes(i.subscription_id || '') || multiSubscriptionFilter.includes(i.primary_subscription_id || ''));
    } else if (subscriptionFilter !== 'all') {
      result = result.filter(i => i.subscription_id === subscriptionFilter);
    }
    if (ownerFilter === 'unowned') result = result.filter(i => !i.owner_display_name && (i.owner_count ?? 0) === 0);
    if (activityFilter === 'dormant_strict') {
      // Strict dormant: matches backend attack-surface-score logic (stale + never_used only)
      result = result.filter(i => {
        const act = safeLower(i.activity_status);
        return act === 'stale' || act === 'never_used';
      });
    } else if (activityFilter === 'dormant') {
      result = result.filter(i => { const d = getDormantStatus(i); return d === 'yes' || d === 'idle' || d === 'never'; });
    }
    if (tierFilter !== 'all') result = result.filter(i => tierFilter.includes(getPrivilegeTier(i)));
    if (credentialFilter !== 'all') {
      const now = Date.now();
      const thirtyDays = THRESHOLDS.CREDENTIAL_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
      result = result.filter(i => {
        if (credentialFilter === 'none') return (i.credential_count ?? 0) === 0;
        if (credentialFilter === 'expired') return i.credential_status === 'expired' || (i.credential_expiration && new Date(i.credential_expiration).getTime() < now);
        if (credentialFilter === 'expiring_soon') return i.credential_expiration && new Date(i.credential_expiration).getTime() > now && new Date(i.credential_expiration).getTime() < now + thirtyDays;
        if (credentialFilter === 'valid') return i.credential_expiration && new Date(i.credential_expiration).getTime() > now + thirtyDays;
        return true;
      });
    }
    if (caFilter !== 'all') {
      result = result.filter(i => {
        if (caFilter === 'covered') return i.ca_coverage_status === 'covered';
        if (caFilter === 'not_covered') return !i.ca_coverage_status || i.ca_coverage_status === 'no_coverage' || i.ca_coverage_status === 'excluded';
        return true;
      });
    }
    if ((groupFilter !== 'all' || multiGroupFilter.length > 0) && groupMemberIds) {
      result = result.filter(i => groupMemberIds.has(i.identity_id));
    }
    if (multiStatusFilter.length > 0) {
      result = result.filter(i => multiStatusFilter.includes(safeLower(i.status)) || (multiStatusFilter.includes('disabled') && i.enabled === false));
    } else if (statusFilter !== 'all') {
      result = result.filter(i => safeLower(i.status) === statusFilter || (statusFilter === 'disabled' && i.enabled === false));
    }
    if (hasRolesFilter) {
      result = result.filter(i => (i.rbac_role_count ?? 0) + (i.entra_role_count ?? 0) > 0);
    }
    if (orphanFilter) {
      result = result.filter(i => {
        const os = i.orphan_status || '';
        return os === 'SAFE_TO_RETIRE' || os === 'CAUTION' || os === 'BLOCKED';
      });
    }

    result.sort((a, b) => {
      let aVal: any, bVal: any;
      switch (sortField) {
        case 'display_name': aVal = safeLower(a.display_name); bVal = safeLower(b.display_name); break;
        case 'identity_type': aVal = safeLower(a.identity_type); bVal = safeLower(b.identity_type); break;
        case 'identity_category': aVal = safeLower(a.identity_category); bVal = safeLower(b.identity_category); break;
        case 'subscription_id': aVal = safeLower(a.subscription_id); bVal = safeLower(b.subscription_id); break;
        case 'subscription_name': aVal = safeLower(a.subscription_name); bVal = safeLower(b.subscription_name); break;
        case 'cloud': aVal = safeLower(a.cloud); bVal = safeLower(b.cloud); break;
        case 'entra_role_count': aVal = a.entra_role_count ?? 0; bVal = b.entra_role_count ?? 0; break;
        case 'rbac_role_count': aVal = a.rbac_role_count ?? 0; bVal = b.rbac_role_count ?? 0; break;
        case 'api_permission_count': aVal = a.api_permission_count ?? 0; bVal = b.api_permission_count ?? 0; break;
        case 'privilege_tier': aVal = getPrivilegeTier(a); bVal = getPrivilegeTier(b); break;
        case 'effective_scope': aVal = EFFECTIVE_SCOPE_ORDER[a.effective_scope || 'none']; bVal = EFFECTIVE_SCOPE_ORDER[b.effective_scope || 'none']; break;
        case 'credential_health': {
          const chOrd: Record<string, number> = { expired: 4, expiring: 3, ok: 2, none: 1 };
          aVal = chOrd[a.credential_health || 'none'] || 0; bVal = chOrd[b.credential_health || 'none'] || 0; break;
        }
        case 'credential_expiration':
          aVal = a.credential_expiration ? new Date(a.credential_expiration).getTime() : Infinity;
          bVal = b.credential_expiration ? new Date(b.credential_expiration).getTime() : Infinity;
          break;
        case 'created_datetime':
          aVal = a.created_datetime ? new Date(a.created_datetime).getTime() : 0;
          bVal = b.created_datetime ? new Date(b.created_datetime).getTime() : 0;
          break;
        case 'last_seen_auth':
          aVal = a.last_seen_auth ? new Date(a.last_seen_auth).getTime() : 0;
          bVal = b.last_seen_auth ? new Date(b.last_seen_auth).getTime() : 0;
          break;
        case 'dormant':
          const dormOrder: Record<string, number> = { yes: 4, never: 3, idle: 2, no: 1, 'new': 1, unknown: 0 };
          aVal = dormOrder[getDormantStatus(a)] || 0;
          bVal = dormOrder[getDormantStatus(b)] || 0;
          break;
        case 'owner_display_name': aVal = safeLower(a.owner_display_name) || '\uffff'; bVal = safeLower(b.owner_display_name) || '\uffff'; break;
        case 'status': {
          const stOrd: Record<string, number> = { deleted: 4, disabled: 3, unknown: 2, active: 1 };
          aVal = stOrd[a.status || 'active'] || 0; bVal = stOrd[b.status || 'active'] || 0; break;
        }
        case 'last_signin_at':
          aVal = a.last_signin_at ? new Date(a.last_signin_at).getTime() : 0;
          bVal = b.last_signin_at ? new Date(b.last_signin_at).getTime() : 0;
          break;
        case 'last_signin_ip':
          aVal = safeLower(a.last_signin_ip); bVal = safeLower(b.last_signin_ip); break;
        case 'recommended_action': {
          const vOrd2: Record<string, number> = { ORPHANED: 5, AT_RISK: 4, UNUSED: 3, STALE: 2, NEEDS_REVIEW: 1, HEALTHY: 0 };
          aVal = vOrd2[a.recommended_action || ''] ?? -1; bVal = vOrd2[b.recommended_action || ''] ?? -1;
          if (aVal === bVal) {
            const aTime2 = a.last_signin_at ? new Date(a.last_signin_at).getTime() : 0;
            const bTime2 = b.last_signin_at ? new Date(b.last_signin_at).getTime() : 0;
            return aTime2 - bTime2;
          }
          break;
        }
        case 'risk_level':
        default:
          aVal = RISK_ORDER[safeLower(a.risk_level)] || 0;
          bVal = RISK_ORDER[safeLower(b.risk_level)] || 0;
      }
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return result;
  }, [queryMode, queryResults, identities, search, cloudFilter, riskFilter, multiRiskFilter, categoryFilter, multiCategoryFilter, workloadFilter, subscriptionFilter, multiSubscriptionFilter, allSubscriptions, ownerFilter, activityFilter, tierFilter, credentialFilter, caFilter, groupFilter, multiGroupFilter, groupMemberIds, statusFilter, multiStatusFilter, hasRolesFilter, sortField, sortDir]);

  function handleSort(field: SortField) {
    if (field === sortField) setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
    else {
      setSortField(field);
      setSortDir(['risk_level', 'entra_role_count', 'rbac_role_count', 'api_permission_count', 'privilege_tier', 'dormant', 'effective_scope', 'credential_health', 'status', 'recommended_action'].includes(field) ? 'desc' : 'asc');
    }
  }

  function toggleSelect(id: string) { setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; }); }
  function selectAll() { selectedIds.size === filtered.length ? setSelectedIds(new Set()) : setSelectedIds(new Set(filtered.map(i => i.identity_id))); }
  function selectCompliance() {
    setSelectedIds(new Set(filtered.filter(i => i.risk_level === 'critical' || i.risk_level === 'high' || (i.risk_level === 'medium' && ((i.entra_role_count ?? 0) > 0 || (i.rbac_role_count ?? 0) > 0))).map(i => i.identity_id)));
  }

  const selectedIdentities = useMemo(() => selectedIds.size === 0 ? [] : filtered.filter(i => selectedIds.has(i.identity_id)), [filtered, selectedIds]);

  // Close bulk menu on click outside
  useEffect(() => {
    if (!bulkMenuOpen) return;
    function handleClick(e: MouseEvent) {
      if (bulkMenuRef.current && !bulkMenuRef.current.contains(e.target as Node)) {
        setBulkMenuOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [bulkMenuOpen]);

  // Bulk remediation action
  async function executeBulkAction(status: string) {
    setBulkLoading(true);
    setBulkConfirm(null);
    try {
      const res = await fetch('/api/bulk/remediation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity_ids: Array.from(selectedIds),
          status,
          notes: `Bulk ${status} from identities table`,
        }),
      });
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const result = await res.json();
      addToast(`${result.updated_count} remediations marked as ${status} across ${result.identity_count} identities`, 'success');
    } catch (e: any) {
      addToast(e?.message || 'Bulk action failed', 'error');
    } finally {
      setBulkLoading(false);
      setBulkMenuOpen(false);
    }
  }

  // Export CSV
  function exportToCSV() {
    if (selectedIds.size === 0) { alert('Select identities first.'); return; }
    const headers = ['Display Name','Identity ID','Type','Category','Subscription Name','Subscription ID','Cloud','Risk','Score','Tier','Entra Roles','RBAC Roles','Graph Perms','Secret/Expiry','Created','Last Used','Dormant','Compliance','Owner'];
    const rows = selectedIdentities.map(i => [
      i.display_name, i.identity_id, i.identity_type || '', getCategoryLabel(i.identity_category),
      i.subscription_name || '', i.subscription_id || '',
      i.cloud || 'azure', (i.risk_level || 'unknown').toUpperCase(), i.risk_score ?? 0,
      `T${getPrivilegeTier(i)}`, i.entra_role_count ?? 0, i.rbac_role_count ?? 0,
      i.api_permission_count ?? 0, i.credential_expiration || '', i.created_datetime || '',
      i.last_seen_auth || 'N/A', getDormantStatus(i), getComplianceRelevance(i), i.owner_display_name || '',
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `auditgraph-report-${new Date().toISOString().split('T')[0]}.csv`; a.click();
    URL.revokeObjectURL(url);
  }

  // Export PDF
  function exportToPDF() {
    if (selectedIds.size === 0) { alert('Select identities first.'); return; }
    const doc = new jsPDF({ orientation: 'landscape' });
    doc.setFontSize(18); doc.setTextColor(30, 64, 175); doc.text('AuditGraph GRC Compliance Report', 14, 18);
    doc.setFontSize(9); doc.setTextColor(100);
    doc.text(`Generated: ${new Date().toLocaleString()} | Identities: ${selectedIdentities.length}`, 14, 25);
    const critical = selectedIdentities.filter(i => i.risk_level === 'critical').length;
    const high = selectedIdentities.filter(i => i.risk_level === 'high').length;
    doc.text(`Risk: ${critical} Critical, ${high} High | Frameworks: SOC2, HIPAA, PCI-DSS, NIST 800-53`, 14, 30);

    autoTable(doc, {
      startY: 35,
      head: [['Identity', 'Category', 'Risk', 'Score', 'Tier', 'Roles', 'Perms', 'Dormant', 'Compliance']],
      body: selectedIdentities.map(i => [
        i.display_name.substring(0, 28) + (i.display_name.length > 28 ? '..' : ''),
        getCategoryLabel(i.identity_category), (i.risk_level || '?').toUpperCase(),
        String(i.risk_score ?? 0), `T${getPrivilegeTier(i)}`,
        String((i.entra_role_count ?? 0) + (i.rbac_role_count ?? 0)),
        String(i.api_permission_count ?? 0), getDormantStatus(i).toUpperCase(),
        getComplianceRelevance(i),
      ]),
      styles: { fontSize: 7, cellPadding: 1.5 },
      headStyles: { fillColor: [30, 64, 175], textColor: 255 },
      alternateRowStyles: { fillColor: [245, 247, 250] },
      didParseCell: (data) => {
        if (data.column.index === 2 && data.section === 'body') {
          const r = String(data.cell.raw).toLowerCase();
          if (r === 'critical') { data.cell.styles.fillColor = [254,226,226]; data.cell.styles.textColor = [185,28,28]; }
          else if (r === 'high') { data.cell.styles.fillColor = [255,237,213]; data.cell.styles.textColor = [194,65,12]; }
        }
      },
    });
    doc.save(`auditgraph-grc-report-${new Date().toISOString().split('T')[0]}.pdf`);
  }

  // Export All (filtered, no selection required)
  function exportAllCSV() {
    const data = filtered.map(i => ({
      ...i,
      privilege_tier: `T${getPrivilegeTier(i)}`,
      activity_status: getDormantStatus(i),
    }));
    const meta = buildExportMeta(snapshots[0]?.id ?? null, activeOrgId ?? user?.organization_id ?? null, activeOrgName ?? user?.org_name ?? null);
    downloadCSV(data as Record<string, unknown>[], IDENTITY_CSV_COLUMNS, exportFilename('identities', 'csv'), meta);
    addToast(`Exported ${data.length} identities as CSV`, 'success');
  }

  function exportAllJSON() {
    const meta = buildExportMeta(snapshots[0]?.id ?? null, activeOrgId ?? user?.organization_id ?? null, activeOrgName ?? user?.org_name ?? null);
    downloadJSON(filtered, exportFilename('identities', 'json'), meta);
    addToast(`Exported ${filtered.length} identities as JSON`, 'success');
  }

  const colSpan = 13; // checkbox + 11 primary columns + lineage

  return (
    <div className="max-w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-4">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            {new URLSearchParams(location.search).get('identity_category') === 'guest'
              ? 'External & Guest Identities'
              : 'Identity Inventory'}
          </h2>
          <p className="text-sm text-gray-500">
            {new URLSearchParams(location.search).get('identity_category') === 'guest'
              ? 'External users, guests, and B2B collaborators'
              : 'Canonical identity listing — click any row for deep-dive'}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Snapshot selector */}
          {snapshots.length > 0 && (
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] text-gray-500 uppercase font-semibold tracking-wide">Snapshot:</span>
              <select
                className="text-xs border border-gray-300 rounded-lg px-2 py-1 bg-white text-gray-700 font-medium"
                value={snapshots[0]?.id ?? ''}
                onChange={() => {/* display-only — API always returns latest snapshot */}}
              >
                {snapshots.map((run, idx) => (
                  <option key={run.id} value={run.id}>
                    #{run.id} · {run.completed_at ? formatDate(run.completed_at) : 'In progress'} · {run.total_identities} identities{idx === 0 ? ' (latest)' : ''}
                  </option>
                ))}
              </select>
              <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[9px] font-semibold uppercase tracking-wide" title="Snapshot data is immutable — it reflects the state at capture time">
                <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                Immutable
              </span>
            </div>
          )}
          <span className="w-px h-5 bg-gray-300" />
          {/* View toggle */}
          <div className="flex border rounded-lg overflow-hidden">
            <button
              onClick={() => setViewMode('table')}
              className={`px-2.5 py-1 text-xs font-medium transition-colors ${viewMode === 'table' ? 'bg-blue-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
            >
              Table
            </button>
            <button
              onClick={() => setViewMode('graph')}
              className={`px-2.5 py-1 text-xs font-medium transition-colors ${viewMode === 'graph' ? 'bg-blue-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
            >
              Graph
            </button>
          </div>
          <span className="text-sm text-gray-600">
            {loading ? 'Loading…' : subscriptionFilter !== 'all'
              ? `${filtered.length} of ${identities.length} identities in ${allSubscriptions.find(s => s.subscription_id === subscriptionFilter)?.subscription_name || subscriptionFilter}`
              : `${filtered.length} of ${identities.length}`}
            {selectedIds.size > 0 && <span className="ml-1 text-blue-600 font-semibold">({selectedIds.size} sel)</span>}
          </span>
          {!loading && filtered.length > 0 && (
            <>
              <button onClick={selectCompliance} className="px-2.5 py-1 text-xs font-medium text-purple-700 bg-purple-50 border border-purple-200 rounded-lg hover:bg-purple-100" title="Select GRC-relevant identities">
                GRC Select
              </button>
              {selectedIds.size > 0 && (
                <button onClick={() => setSelectedIds(new Set())} className="px-2.5 py-1 text-xs font-medium text-gray-600 bg-gray-50 border border-gray-200 rounded-lg hover:bg-gray-100">Clear</button>
              )}
              {selectedIds.size === 2 && (
                <button
                  onClick={() => {
                    const ids = Array.from(selectedIds);
                    navigate(`/identities/compare?ids=${encodeURIComponent(ids[0])},${encodeURIComponent(ids[1])}`);
                  }}
                  className="px-2.5 py-1 text-xs font-medium text-blue-700 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100"
                >
                  Compare
                </button>
              )}
              {selectedIds.size > 0 && (
                <div className="relative" ref={bulkMenuRef}>
                  <button
                    onClick={() => setBulkMenuOpen(!bulkMenuOpen)}
                    disabled={bulkLoading}
                    className="px-2.5 py-1 text-xs font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg hover:bg-emerald-100 disabled:opacity-50"
                  >
                    {bulkLoading ? 'Applying…' : 'Bulk Actions \u25BE'}
                  </button>
                  {bulkMenuOpen && (
                    <div className="absolute right-0 mt-1 w-56 bg-white border rounded-xl shadow-lg z-20 py-1">
                      <button
                        onClick={() => { setBulkMenuOpen(false); setBulkConfirm({ status: 'acknowledged', label: 'Acknowledge' }); }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-blue-50 hover:text-blue-700 transition"
                      >
                        Acknowledge All Remediations
                      </button>
                      <button
                        onClick={() => { setBulkMenuOpen(false); setBulkConfirm({ status: 'completed', label: 'Complete' }); }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-green-50 hover:text-green-700 transition"
                      >
                        Mark All Remediated
                      </button>
                      <button
                        onClick={() => { setBulkMenuOpen(false); setBulkConfirm({ status: 'skipped', label: 'Skip' }); }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-yellow-50 hover:text-yellow-700 transition"
                      >
                        Skip All Remediations
                      </button>
                      <div className="border-t my-1" />
                      <button
                        onClick={() => { setBulkMenuOpen(false); setAddToGroupOpen(true); }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-indigo-50 hover:text-indigo-700 transition"
                      >
                        Add to Group...
                      </button>
                    </div>
                  )}
                </div>
              )}
              <span className="w-px h-5 bg-gray-300" />
              <button onClick={exportToCSV} className="px-2.5 py-1 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">CSV</button>
              <button onClick={exportToPDF} className="px-2.5 py-1 text-xs font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700">PDF</button>
              <span className="w-px h-5 bg-gray-300" />
              <button onClick={exportAllCSV} className="px-2.5 py-1 text-xs font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg hover:bg-emerald-100">Export All CSV</button>
              <button onClick={exportAllJSON} className="px-2.5 py-1 text-xs font-medium text-purple-700 bg-purple-50 border border-purple-200 rounded-lg hover:bg-purple-100">Export All JSON</button>
            </>
          )}
        </div>
      </div>

      {/* Tenant Scope Bar */}
      {scopeSummary && scopeSummary.discovered > 0 && (
        <div className="flex items-center gap-2 px-3 py-2 mb-3 rounded-lg bg-blue-50 border border-blue-200 text-sm text-blue-800">
          <svg className="w-4 h-4 flex-shrink-0 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>
            Tenant-scoped view: Showing identities from <strong>{scopeSummary.activated}</strong> activated subscriptions only.{' '}
            <Link to="/subscriptions" className="font-semibold hover:opacity-80">
              {scopeSummary.discovered} discovered subscription{scopeSummary.discovered !== 1 ? 's' : ''}
            </Link>{' '}
            {scopeSummary.discovered === 1 ? 'is' : 'are'} excluded until activated.
          </span>
        </div>
      )}

      {/* Export Metadata Strip */}
      {snapshots.length > 0 && (
        <div className="flex items-center gap-4 text-[10px] text-gray-500 border border-gray-200 rounded-lg px-3 py-1.5 bg-gray-50 mb-1">
          <span className="font-semibold uppercase tracking-wide text-gray-400">Export Metadata</span>
          <span>Snapshot: <span className="font-mono font-semibold text-gray-700">#{snapshots[0]?.id}</span></span>
          <span>Captured: <span className="font-mono font-semibold text-gray-700">{snapshots[0]?.completed_at ? new Date(snapshots[0].completed_at).toLocaleString() : 'In progress'}</span></span>
          <span>Organization: <span className="font-mono font-semibold text-gray-700">{activeOrgId ?? user?.organization_id ?? 'N/A'}</span></span>
          <span>Schema: <span className="font-mono font-semibold text-gray-700">v1.0</span></span>
        </div>
      )}

      {/* Saved Views Bar */}
      {savedViews.length > 0 || !loading ? (
        <div className="flex items-center gap-2 mb-3 overflow-x-auto pb-1">
          <span className="text-[10px] text-gray-500 uppercase font-semibold flex-shrink-0">Views:</span>
          {savedViews.map(v => (
            <div key={v.id} className="flex items-center gap-0.5 flex-shrink-0 group">
              <button
                onClick={() => applyView(v)}
                className={`px-2.5 py-1 rounded-l-lg text-xs font-medium border transition ${
                  activeViewId === v.id
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                }`}
                title={v.description || v.name}
              >
                {v.is_default && <span className="mr-1 text-yellow-300">&#9733;</span>}
                {v.name}
                {v.is_shared && v.user_id !== user?.id && (
                  <span className="ml-1 text-[9px] opacity-60">({v.creator_name})</span>
                )}
              </button>
              <div className="flex border-y border-r border-gray-300 rounded-r-lg overflow-hidden">
                <button
                  onClick={(e) => { e.stopPropagation(); toggleDefault(v); }}
                  className={`px-1 py-1 text-[10px] hover:bg-yellow-50 transition ${v.is_default ? 'text-yellow-500' : 'text-gray-300 hover:text-yellow-400'}`}
                  title={v.is_default ? 'Remove default' : 'Set as default'}
                >
                  &#9733;
                </button>
                {(v.user_id === user?.id || isAdmin) && (
                  <>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setEditingView(v);
                        setViewForm({ name: v.name, description: v.description || '', is_shared: v.is_shared });
                        setSaveModalOpen(true);
                      }}
                      className="px-1 py-1 text-[10px] text-gray-400 hover:text-blue-600 hover:bg-blue-50 transition"
                      title="Edit view"
                    >
                      &#9998;
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); setDeleteConfirmId(v.id); }}
                      className="px-1 py-1 text-[10px] text-gray-400 hover:text-red-600 hover:bg-red-50 transition"
                      title="Delete view"
                    >
                      &times;
                    </button>
                  </>
                )}
              </div>
            </div>
          ))}
          <button
            onClick={() => {
              setEditingView(null);
              setViewForm({ name: '', description: '', is_shared: false });
              setSaveModalOpen(true);
            }}
            className="px-2.5 py-1 rounded-lg text-xs font-medium text-blue-700 bg-blue-50 border border-blue-200 hover:bg-blue-100 flex-shrink-0 flex items-center gap-1"
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Save Current
          </button>
        </div>
      ) : null}

      {/* Delete Confirmation */}
      {deleteConfirmId !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-xl shadow-lg w-full max-w-sm mx-4 p-5">
            <h3 className="text-base font-bold text-gray-900 mb-2">Delete View?</h3>
            <p className="text-sm text-gray-600 mb-4">
              This saved view will be permanently removed.
            </p>
            <div className="flex justify-end gap-2">
              <button onClick={() => setDeleteConfirmId(null)} className="px-3 py-1.5 text-sm text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200">Cancel</button>
              <button onClick={() => deleteView(deleteConfirmId)} className="px-3 py-1.5 text-sm text-white bg-red-600 rounded-lg hover:bg-red-700">Delete</button>
            </div>
          </div>
        </div>
      )}

      {/* Save View Modal */}
      {saveModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-2xl shadow-lg w-full max-w-md mx-4 p-6">
            <h3 className="text-lg font-bold text-gray-900 mb-4">
              {editingView ? 'Edit View' : 'Save Current Filters as View'}
            </h3>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
                <input
                  value={viewForm.name}
                  onChange={e => setViewForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="e.g., Critical T0 SPNs"
                  className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500"
                  autoFocus
                  maxLength={100}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Description (optional)</label>
                <input
                  value={viewForm.description}
                  onChange={e => setViewForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="What this view shows…"
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                />
              </div>
              {isAdmin && (
                <label className="flex items-center gap-2 text-sm text-gray-700">
                  <input
                    type="checkbox"
                    checked={viewForm.is_shared}
                    onChange={e => setViewForm(f => ({ ...f, is_shared: e.target.checked }))}
                    className="w-4 h-4 text-blue-600 rounded"
                  />
                  Share with all users
                </label>
              )}
              {!editingView && (
                <div className="bg-gray-50 rounded-lg p-3 text-xs text-gray-500">
                  <span className="font-medium text-gray-700">Current filters:</span>{' '}
                  {(() => {
                    const f = getCurrentFilters();
                    const keys = Object.keys(f);
                    return keys.length > 0
                      ? keys.map(k => `${k}=${f[k]}`).join(', ')
                      : 'No filters (all identities)';
                  })()}
                  <br />
                  <span className="font-medium text-gray-700">Sort:</span> {sortField} ({sortDir})
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2 mt-5">
              <button
                onClick={() => { setSaveModalOpen(false); setEditingView(null); }}
                className="px-4 py-2 text-sm text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200"
              >
                Cancel
              </button>
              <button
                onClick={saveView}
                disabled={viewSaving || !viewForm.name.trim()}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
              >
                {viewSaving && (
                  <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                )}
                {editingView ? 'Update' : 'Save View'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Context banner for CISO Dashboard drill-down */}
      {contextBanner && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl px-4 py-2.5 mb-3 flex items-center justify-between">
          <span className="text-sm text-blue-800 font-medium">{contextBanner}</span>
          <button
            onClick={() => { setContextBanner(null); navigate('/identities', { replace: true }); }}
            className="text-xs text-blue-600 hover:text-blue-800 font-medium"
          >
            Clear filter
          </button>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white border rounded-xl p-3 mb-3 shadow-sm">
        {/* Mode toggle */}
        <div className="flex items-center gap-2 mb-2">
          <button
            onClick={() => { setQueryMode('simple'); clearActiveView(); }}
            className={`px-3 py-1 text-xs font-medium rounded-lg transition-colors ${
              queryMode === 'simple' ? 'bg-blue-600 text-white' : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            Simple Filters
          </button>
          <button
            onClick={() => { setQueryMode('advanced'); clearActiveView(); }}
            className={`px-3 py-1 text-xs font-medium rounded-lg transition-colors ${
              queryMode === 'advanced' ? 'bg-blue-600 text-white' : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            Advanced Query
          </button>
        </div>

        {queryMode === 'simple' ? (
        <div className="grid grid-cols-1 md:grid-cols-6 gap-2">
          <input value={search} onChange={e => { setSearch(e.target.value); clearActiveView(); }} placeholder="Search name, ID, owner…"
            className="border rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 md:col-span-2" />
          <MultiSelectFilter
            options={RISK_FILTER_OPTIONS.filter(o => o.value !== 'all').map(o => ({ value: o.value, label: o.label }))}
            selected={multiRiskFilter}
            onChange={(vals) => { setMultiRiskFilter(vals); setRiskFilter('all'); clearActiveView(); }}
            label="Level"
            placeholder="Search levels…"
            searchable={false}
          />
          <MultiSelectFilter
            options={activatedSubscriptions.map(s => ({ value: s.subscription_id, label: s.subscription_name || s.subscription_id }))}
            selected={multiSubscriptionFilter}
            onChange={(vals) => { setMultiSubscriptionFilter(vals); setSubscriptionFilter('all'); clearActiveView(); }}
            label={accountLabel('Name')}
            placeholder={`Search ${accountLabel('Name').toLowerCase()}s…`}
            header={`Showing ${activatedSubscriptions.length} activated subscription${activatedSubscriptions.length !== 1 ? 's' : ''}`}
          />
          <MultiSelectFilter
            options={allGroups.map(g => ({ value: String(g.id), label: `${g.name} (${g.member_count})` }))}
            selected={multiGroupFilter}
            onChange={(vals) => { setMultiGroupFilter(vals); setGroupFilter('all'); clearActiveView(); }}
            label="Group"
            placeholder="Search groups…"
          />
          <div className="flex items-center gap-2">
            <MultiSelectFilter
              options={[
                { value: 'active', label: 'Active' },
                { value: 'disabled', label: 'Disabled' },
                { value: 'deleted', label: 'Deleted' },
                { value: 'unknown', label: 'Unknown' },
              ]}
              selected={multiStatusFilter}
              onChange={(vals) => { setMultiStatusFilter(vals); setStatusFilter('all'); clearActiveView(); }}
              label="Status"
              placeholder="Search status…"
              searchable={false}
            />
            <button onClick={() => {
              setSearch(''); setRiskFilter('all'); setMultiRiskFilter([]); setCategoryFilter('all'); setMultiCategoryFilter([]);
              setWorkloadFilter(false); setSubscriptionFilter('all'); setMultiSubscriptionFilter([]);
              setOwnerFilter('all'); setActivityFilter('all'); setTierFilter('all'); setCredentialFilter('all');
              setCaFilter('all'); setGroupFilter('all'); setMultiGroupFilter([]); setStatusFilter('all'); setMultiStatusFilter([]);
              setHasRolesFilter(false); setContextBanner(null); setActiveViewId(null); navigate('/identities', { replace: true });
            }}
              className="px-3 py-1.5 text-sm text-blue-600 border border-blue-200 rounded-lg hover:bg-blue-50 whitespace-nowrap">
              Clear
            </button>
          </div>
          <label className="flex items-center gap-1.5 text-sm text-gray-600 dark:text-slate-400 cursor-pointer whitespace-nowrap">
            <input type="checkbox" checked={showMicrosoft} onChange={e => setShowMicrosoft(e.target.checked)}
              className="rounded border-gray-300" />
            Show Microsoft
          </label>
        </div>
        ) : (
          <QueryBuilder
            query={advancedQuery}
            onChange={(q) => { setAdvancedQuery(q); clearActiveView(); }}
            fields={queryFields}
            valueSuggestions={valueSuggestions}
            resultCount={queryTotal}
            loading={queryLoading}
          />
        )}
        {/* Active filter chips (simple mode only) */}
        {queryMode === 'simple' && (multiRiskFilter.length > 0 || multiCategoryFilter.length > 0 || multiSubscriptionFilter.length > 0 || multiGroupFilter.length > 0 || multiStatusFilter.length > 0 || subscriptionFilter !== 'all' || ownerFilter !== 'all' || activityFilter !== 'all' || tierFilter !== 'all' || credentialFilter !== 'all' || caFilter !== 'all' || agentFilter) && (
          <div className="flex items-center gap-1.5 mt-2 flex-wrap">
            <span className="text-[10px] text-gray-500 uppercase font-semibold">Active filters:</span>
            {/* Multi-select risk chips */}
            {multiRiskFilter.map(r => (
              <span key={`risk-${r}`} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                {RISK_FILTER_OPTIONS.find(o => o.value === r)?.label || r}
                <button onClick={() => setMultiRiskFilter(prev => prev.filter(v => v !== r))} className="hover:text-red-600">&times;</button>
              </span>
            ))}
            {/* Multi-select category chips */}
            {multiCategoryFilter.map(c => (
              <span key={`cat-${c}`} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                {getCategoryLabel(c)}
                <button onClick={() => setMultiCategoryFilter(prev => prev.filter(v => v !== c))} className="hover:text-purple-600">&times;</button>
              </span>
            ))}
            {/* Multi-select subscription chips */}
            {multiSubscriptionFilter.map(s => (
              <span key={`sub-${s}`} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800">
                {allSubscriptions.find(sub => sub.subscription_id === s)?.subscription_name || s}
                <button onClick={() => setMultiSubscriptionFilter(prev => prev.filter(v => v !== s))} className="hover:text-indigo-600">&times;</button>
              </span>
            ))}
            {/* Legacy single subscription chip */}
            {subscriptionFilter !== 'all' && multiSubscriptionFilter.length === 0 && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800">
                {accountLabel('Name')}: {allSubscriptions.find(s => s.subscription_id === subscriptionFilter)?.subscription_name || subscriptionFilter}
                <button onClick={() => { setSubscriptionFilter('all'); }} className="hover:text-indigo-600">&times;</button>
              </span>
            )}
            {/* Multi-select group chips */}
            {multiGroupFilter.map(g => (
              <span key={`grp-${g}`} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-teal-100 text-teal-800">
                {allGroups.find(grp => String(grp.id) === g)?.name || `Group ${g}`}
                <button onClick={() => setMultiGroupFilter(prev => prev.filter(v => v !== g))} className="hover:text-teal-600">&times;</button>
              </span>
            ))}
            {/* Multi-select status chips */}
            {multiStatusFilter.map(s => (
              <span key={`st-${s}`} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-gray-200 text-gray-800">
                {s.charAt(0).toUpperCase() + s.slice(1)}
                <button onClick={() => setMultiStatusFilter(prev => prev.filter(v => v !== s))} className="hover:text-gray-600">&times;</button>
              </span>
            ))}
            {ownerFilter === 'unowned' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                No Owner
                <button onClick={() => { setOwnerFilter('all'); }} className="hover:text-yellow-600">&times;</button>
              </span>
            )}
            {activityFilter === 'dormant' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                Dormant
                <button onClick={() => { setActivityFilter('all'); }} className="hover:text-red-600">&times;</button>
              </span>
            )}
            {tierFilter !== 'all' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                Tier {tierFilter.map(t => `T${t}`).join('/')}
                <button onClick={() => { setTierFilter('all'); }} className="hover:text-purple-600">&times;</button>
              </span>
            )}
            {credentialFilter !== 'all' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                Cred: {credentialFilter === 'expired' ? 'Expired' : credentialFilter === 'expiring_soon' ? 'Expiring Soon' : credentialFilter === 'none' ? 'No Credentials' : 'Valid'}
                <button onClick={() => { setCredentialFilter('all'); }} className="hover:text-orange-600">&times;</button>
              </span>
            )}
            {caFilter !== 'all' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                CA: {caFilter === 'covered' ? 'Covered' : 'Not Covered'}
                <button onClick={() => { setCaFilter('all'); }} className="hover:text-blue-600">&times;</button>
              </span>
            )}
            {agentFilter && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-violet-100 text-violet-800">
                AI Agents
                <button onClick={() => { setAgentFilter(false); }} className="hover:text-violet-600">&times;</button>
              </span>
            )}
            {orphanFilter && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800">
                Orphaned
                <button onClick={() => { setOrphanFilter(false); }} className="hover:text-amber-600">&times;</button>
              </span>
            )}
          </div>
        )}
      </div>

      {/* Cloud Selector Tabs */}
      {!loading && enabledClouds.length > 1 && (
        <div className="flex items-center gap-1 mb-2">
          {[
            { key: 'all', label: 'All Clouds', color: 'bg-violet-600' },
            ...(enabledClouds.includes('azure') ? [{ key: 'azure', label: 'Azure', color: 'bg-blue-600' }] : []),
            ...(enabledClouds.includes('aws') ? [{ key: 'aws', label: 'AWS', color: 'bg-amber-600' }] : []),
            ...(enabledClouds.includes('gcp') ? [{ key: 'gcp', label: 'GCP', color: 'bg-red-600' }] : []),
          ].map(tab => (
            <button
              key={tab.key}
              onClick={() => setCloudFilter(tab.key)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                cloudFilter === tab.key
                  ? `${tab.color} text-white shadow-sm`
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      )}

      {/* Category Filter Tabs */}
      {!loading && identities.length > 0 && (
        <div className="flex items-center gap-1.5 mb-3">
          {[
            { key: 'all', label: 'All Identities', multi: [] as string[] },
            { key: 'human_user', label: 'Human Users', multi: [] as string[] },
            { key: 'service_principal', label: 'Service Principals', multi: [] as string[] },
            { key: 'managed_ids', label: 'Managed IDs', multi: [...MANAGED_IDENTITY_GROUP] },
            { key: 'guest', label: 'Guest', multi: [] as string[] },
          ].map(tab => {
            const isActive = !workloadFilter && (
              tab.multi.length > 0
                ? tab.multi.every(c => multiCategoryFilter.includes(c)) && multiCategoryFilter.length === tab.multi.length
                : multiCategoryFilter.length === 0 && categoryFilter === tab.key
            );
            return (
              <button
                key={tab.key}
                onClick={() => {
                  setWorkloadFilter(false);
                  clearActiveView();
                  if (tab.multi.length > 0) {
                    setMultiCategoryFilter(tab.multi);
                    setCategoryFilter('all');
                    navigate('/identities?identity_category=managed_identity', { replace: true });
                  } else {
                    setMultiCategoryFilter([]);
                    setCategoryFilter(tab.key as any);
                    if (tab.key === 'all') {
                      navigate('/identities', { replace: true });
                    } else {
                      navigate(`/identities?identity_category=${tab.key}`, { replace: true });
                    }
                  }
                }}
                className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-violet-600 text-white shadow-sm'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
          <button
            onClick={() => {
              setWorkloadFilter(true);
              setCategoryFilter('all');
              setMultiCategoryFilter([]);
              clearActiveView();
              navigate('/identities?workload=true', { replace: true });
            }}
            className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
              workloadFilter
                ? 'bg-violet-600 text-white shadow-sm'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            NHI (All Non-Human)
          </button>
          {/* AI Agent Governance: filter pill (only when feature flag enabled) */}
          {agentFilterEnabled && (
            <button
              onClick={() => {
                setAgentFilter(!agentFilter);
                if (!agentFilter) {
                  setWorkloadFilter(false);
                  setCategoryFilter('all');
                  setMultiCategoryFilter([]);
                  clearActiveView();
                }
              }}
              className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors inline-flex items-center gap-1.5 ${
                agentFilter
                  ? 'bg-violet-600 text-white shadow-sm'
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              AI Agents
              {agentCount > 0 && (
                <span className={`inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full text-[10px] font-bold ${
                  agentFilter ? 'bg-white/20 text-white' : 'bg-violet-100 text-violet-700'
                }`}>
                  {agentCount}
                </span>
              )}
            </button>
          )}
          <button
            onClick={() => setOrphanFilter(!orphanFilter)}
            className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors inline-flex items-center gap-1.5 ${
              orphanFilter
                ? 'bg-amber-500 text-white shadow-sm'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Orphaned
          </button>
        </div>
      )}

      {/* KPI Summary Strip — removed in Phase 4 (enterprise cleanup) */}

      {/* Exposure Graph (V2 Phase 5) */}
      {viewMode === 'graph' && (
        <ExposureGraph
          identityIds={filtered.map(i => i.identity_id)}
          onNodeClick={(id) => setDrawerIdentityId(id)}
        />
      )}

      {/* Table */}
      {viewMode === 'table' && (<>
      <div className="bg-white border rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full text-[12px]">
            <thead className="bg-gray-50 border-b text-left font-semibold text-gray-600 uppercase tracking-wider">
              <tr>
                <th className="px-2 py-2.5 w-8">
                  <input type="checkbox" checked={filtered.length > 0 && selectedIds.size === filtered.length} onChange={selectAll}
                    className="w-3.5 h-3.5 text-blue-600 rounded cursor-pointer" />
                </th>
                <SortHeader label="Identity" field="display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Type" field="identity_category" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Cloud" field="cloud" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Owner" field="owner_display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Status" field="status" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Risk" field="risk_level" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Last Auth" field="last_signin_at" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Last Auth IP" field="last_signin_ip" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Effective Access" field="privilege_tier" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Sensitive Access" field="effective_scope" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Last Seen" field="last_seen_auth" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="First Seen" field="created_datetime" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <th className="px-2 py-2.5 text-xs whitespace-nowrap">Lineage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={colSpan} className="px-3 py-6 text-center text-gray-500">Loading…</td></tr>
              ) : error ? (
                <tr><td colSpan={colSpan} className="px-3 py-6 text-center text-red-600">{error}</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={colSpan} className="px-3 py-6 text-center text-gray-500">No identities match filters.</td></tr>
              ) : filtered.map(i => (
                  <tr key={i.identity_id}
                    className={`hover:bg-blue-50 cursor-pointer transition-colors ${selectedIds.has(i.identity_id) ? 'bg-blue-50' : ''} ${drawerIdentityId === i.identity_id ? 'bg-blue-100' : ''}`}
                    onClick={() => setDrawerIdentityId(i.identity_id)}
                  >
                    {/* Checkbox */}
                    <td className="px-2 py-2" onClick={e => e.stopPropagation()}>
                      <input type="checkbox" checked={selectedIds.has(i.identity_id)} onChange={() => toggleSelect(i.identity_id)}
                        className="w-3.5 h-3.5 text-blue-600 rounded cursor-pointer" />
                    </td>

                    {/* Identity (name + type icon + ID snippet) */}
                    <td className="px-2 py-2 max-w-[220px]">
                      <div className="flex items-center gap-1.5">
                        <TypeLabel type={i.identity_type} />
                        <div className="min-w-0">
                          <div className="font-medium text-gray-900 truncate flex items-center gap-1" title={i.display_name}>
                            {i.display_name}
                            {!!i.agent_identity_type && i.agent_identity_type === 'ai_agent' && (
                              <span className="inline-flex items-center px-1 py-0 rounded text-[9px] font-bold bg-violet-100 text-violet-700 flex-shrink-0" title={`AI Agent (${i.detected_platform || 'detected'})`}>AI</span>
                            )}
                            {!!i.is_discovery_connector && (
                              <span className="inline-flex items-center px-1 py-0 rounded text-[9px] font-bold bg-amber-100 text-amber-700 border border-amber-300 flex-shrink-0" title="This SPN is the AuditGraph discovery connector">Discovery Connector</span>
                            )}
                          </div>
                          <div className="text-[10px] text-gray-400 font-mono truncate">{i.identity_id.substring(0, 12)}…</div>
                        </div>
                      </div>
                    </td>

                    {/* Type (Category) */}
                    <td className="px-2 py-2"><CategoryBadge category={i.identity_category} cloud={i.cloud} /></td>

                    {/* Cloud */}
                    <td className="px-2 py-2"><CloudBadge cloud={i.cloud} /></td>

                    {/* Owner */}
                    <td className="px-2 py-2">
                      {i.owner_display_name ? (
                        <span className="text-gray-700 text-[11px] truncate block max-w-[140px]" title={i.owner_display_name}>{i.owner_display_name}</span>
                      ) : (
                        <span className="text-[10px] text-gray-400 italic">No owner</span>
                      )}
                    </td>

                    {/* Status */}
                    <td className="px-2 py-2">
                      <StatusBadge status={i.status} />
                    </td>

                    {/* Risk Level */}
                    <td className="px-2 py-2">
                      <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[i.risk_level || 'info'] || RISK_BADGE.info}`}>
                        {i.risk_level || 'info'}
                      </span>
                    </td>

                    {/* Last Auth */}
                    <td className="px-2 py-2 whitespace-nowrap">
                      {(() => {
                        if (!i.last_signin_at) {
                          return <span className="text-red-600 text-xs font-medium">Never</span>;
                        }
                        const diff = Date.now() - new Date(i.last_signin_at).getTime();
                        const days = Math.floor(diff / 86400000);
                        const relText = days === 0 ? 'Today' : days === 1 ? '1d ago' : `${days}d ago`;
                        return (
                          <span className="flex items-center gap-1">
                            <span
                              className={`text-xs ${days > 90 ? 'text-red-600' : days > 30 ? 'text-amber-600' : 'text-gray-700'}`}
                              title={new Date(i.last_signin_at).toLocaleString()}
                            >
                              {relText}
                            </span>
                            {i.auth_source === 'static_analysis_only' && (
                              <span className="text-gray-400 text-[10px] cursor-help" title="No diagnostic logs — static analysis only">&#9432;</span>
                            )}
                          </span>
                        );
                      })()}
                    </td>

                    {/* Last Auth IP */}
                    <td className="px-2 py-2 whitespace-nowrap">
                      {(() => {
                        if (!i.last_signin_ip) {
                          return <span className="text-gray-400 text-xs">&mdash;</span>;
                        }
                        const ip = i.last_signin_ip;
                        const isInternal = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip);
                        const isMsRange = /^(20\.|40\.|52\.)/.test(ip);
                        return (
                          <span className="flex items-center gap-1" title={isMsRange ? 'Microsoft-owned IP range' : undefined}>
                            <span className={`inline-block w-1.5 h-1.5 rounded-full flex-shrink-0 ${isInternal ? 'bg-green-500' : 'bg-blue-500'}`} />
                            <span className="font-mono text-[11px] text-gray-700">{ip}</span>
                          </span>
                        );
                      })()}
                    </td>

                    {/* Effective Access Level (Privilege Tier) */}
                    <td className="px-2 py-2">
                      <PrivilegedBadge level={i.privileged_level} />
                    </td>

                    {/* Sensitive Access (Scope) */}
                    <td className="px-2 py-2"><ScopeBadge scope={i.effective_scope} cloud={i.cloud} /></td>

                    {/* Last Seen — uses effective_last_used with connector fallback */}
                    <td className="px-2 py-2 whitespace-nowrap">
                      {(() => {
                        const isConnector = !!i.is_discovery_connector;

                        // Demo safety: connector is always active
                        const obsDate = isConnector
                          ? (i.observed_last_used || new Date().toISOString())
                          : (i.observed_last_used || null);
                        const authDate = i.last_seen_auth || i.last_noninteractive_signin || null;

                        // Pick the most recent (effective_last_used)
                        let bestDate: string | null = null;
                        let source: 'auditgraph' | 'azure' | null = null;
                        if (obsDate && authDate) {
                          bestDate = new Date(obsDate) >= new Date(authDate) ? obsDate : authDate;
                          source = new Date(obsDate) >= new Date(authDate) ? 'auditgraph' : 'azure';
                        } else if (obsDate) {
                          bestDate = obsDate;
                          source = 'auditgraph';
                        } else if (authDate) {
                          bestDate = authDate;
                          source = 'azure';
                        }

                        if (bestDate) {
                          const ls = formatLastSeen(bestDate);
                          return (
                            <span className={`text-xs ${ls.colorClass}`} title={bestDate}>
                              {ls.label}
                              {source === 'auditgraph' && <span className="ml-1 text-[8px] text-emerald-600 font-semibold align-super">AG</span>}
                            </span>
                          );
                        }
                        if (i.days_since_last_signin != null && i.days_since_last_signin >= 0) {
                          const d = i.days_since_last_signin;
                          const color = d <= 30 ? 'text-green-600' : d <= 90 ? 'text-yellow-600' : 'text-red-500';
                          return <span className={`text-xs ${color}`}>{d === 0 ? 'Today' : `${d}d ago`}</span>;
                        }
                        return <span className="text-[10px] text-gray-400 italic">No activity observed</span>;
                      })()}
                    </td>

                    {/* First Seen */}
                    <td className="px-2 py-2 whitespace-nowrap">
                      {i.created_datetime ? (
                        <span className="text-gray-600">{formatDate(i.created_datetime)}</span>
                      ) : (
                        <span className="text-[10px] text-gray-400 italic">—</span>
                      )}
                    </td>

                    {/* Lineage — Priority: connector > federated > workload_origin > external > owner > ownerless > system */}
                    <td className="px-2 py-2 max-w-[200px]">
                      {(() => {
                        // Confidence badge: high=green, medium=amber, low=gray
                        const confBadge = i.verdict_confidence === 'high'
                          ? <span className="px-1 py-0 rounded text-[7px] font-bold bg-green-100 text-green-700 border border-green-300 flex-shrink-0">HIGH</span>
                          : i.verdict_confidence === 'medium'
                          ? <span className="px-1 py-0 rounded text-[7px] font-bold bg-amber-100 text-amber-700 border border-amber-200 flex-shrink-0">MED</span>
                          : i.verdict_confidence === 'low'
                          ? <span className="px-1 py-0 rounded text-[7px] font-bold bg-gray-100 text-gray-500 border border-gray-200 flex-shrink-0">LOW</span>
                          : null;

                        // Dependency impact indicator
                        const depBadge = i.dependency_impact === 'high'
                          ? <span className="px-1 py-0 rounded text-[7px] font-bold bg-red-100 text-red-700 border border-red-300 flex-shrink-0" title="High dependency impact">DEP</span>
                          : i.dependency_impact === 'medium'
                          ? <span className="px-1 py-0 rounded text-[7px] font-bold bg-amber-100 text-amber-700 border border-amber-200 flex-shrink-0" title="Medium dependency impact">DEP</span>
                          : null;

                        const lineageBtn = (primary: React.ReactNode, subtitle: string) => (
                          <button
                            onClick={(e) => { e.stopPropagation(); setLineagePanelIdentity(i); }}
                            className="flex flex-col gap-0 text-left hover:bg-gray-50 rounded px-1 py-0.5 -mx-1 transition group w-full"
                            title="Click to view lineage details"
                          >
                            <div className="flex items-center gap-1 min-w-0">
                              {primary}
                              {confBadge}
                              {depBadge}
                            </div>
                            <span className="text-[9px] text-gray-400">{subtitle}</span>
                          </button>
                        );

                        // P1: Discovery connector
                        if (i.is_discovery_connector) {
                          return lineageBtn(
                            <span className="text-[10px] text-amber-700 font-semibold truncate group-hover:text-amber-800">AuditGraph Connector</span>,
                            'Discovery SPN'
                          );
                        }

                        // P2: Federated credential (GitHub Actions, AKS, etc.)
                        if (i.federated_workload_type) {
                          const fedLabel = i.federated_workload_type === 'github_actions'
                            ? `GitHub Actions${i.federated_workload_name ? ` · ${i.federated_workload_name}` : ' (OIDC)'}`
                            : i.federated_workload_type === 'aks'
                            ? `AKS Workload${i.federated_workload_name ? ` · ${i.federated_workload_name}` : ''}`
                            : i.federated_workload_name || i.federated_workload_type;
                          return lineageBtn(
                            <span className="text-[10px] text-purple-700 font-semibold truncate group-hover:text-purple-800">{fedLabel}</span>,
                            'Federated Credential'
                          );
                        }

                        // P3: Workload origin from verdict (reply_url, ARM binding, etc.)
                        if (i.workload_origin && !['role_inference', 'heuristic_github', 'heuristic_terraform', 'heuristic_automation', 'display_name_fallback', 'signin_pattern_fallback'].includes(i.workload_origin_source || '')) {
                          return lineageBtn(
                            <span className="text-[10px] text-blue-700 font-medium truncate group-hover:text-blue-800">{i.workload_origin}</span>,
                            i.workload_origin_source === 'reply_url' ? 'Reply URL' : i.workload_origin_source === 'arm_binding' ? 'ARM Binding' : 'Verified Origin'
                          );
                        }

                        // P3.5: Heuristic detection (GitHub, Terraform, automation)
                        if (i.workload_origin && (i.workload_origin_source || '').startsWith('heuristic_')) {
                          const hLabel = i.workload_origin_source === 'heuristic_github' ? 'Inferred: GitHub'
                            : i.workload_origin_source === 'heuristic_terraform' ? 'Inferred: IaC'
                            : 'Inferred: Automation';
                          return lineageBtn(
                            <>
                              <span className="text-[10px] text-indigo-700 font-semibold truncate group-hover:text-indigo-800">{i.workload_origin}</span>
                              <span className="px-1 py-0 rounded text-[7px] font-bold bg-indigo-100 text-indigo-700 border border-indigo-300 flex-shrink-0">INF</span>
                            </>,
                            hLabel
                          );
                        }

                        // P4: External app
                        if (i.is_external_app) {
                          return lineageBtn(
                            <>
                              <span className="text-[10px] text-gray-700 font-medium truncate group-hover:text-blue-600">
                                {i.app_reg_publisher_domain || i.app_registration_name || 'External'}
                              </span>
                              <span className="px-1 py-0 rounded text-[8px] font-bold bg-orange-100 text-orange-700 border border-orange-300 flex-shrink-0">Ext</span>
                            </>,
                            'External App'
                          );
                        }

                        // P5: Workload origin from role inference (lower priority)
                        if (i.workload_origin && i.workload_origin_source === 'role_inference') {
                          return lineageBtn(
                            <span className="text-[10px] text-gray-700 font-medium truncate group-hover:text-blue-600">{i.workload_origin}</span>,
                            'Role Pattern'
                          );
                        }

                        // P6: App reg with owner
                        if (i.app_reg_owner_display_name) {
                          return lineageBtn(
                            <>
                              <span className="text-[10px] text-gray-700 font-medium truncate group-hover:text-blue-600">{i.app_reg_owner_display_name}</span>
                              <span className="text-[9px] text-gray-400 group-hover:text-blue-500 flex-shrink-0">{'\u2197'}</span>
                            </>,
                            i.app_reg_likely_service || 'Owner'
                          );
                        }

                        // P7: App reg without owner (ownerless)
                        if (i.app_registration_object_id) {
                          return lineageBtn(
                            <>
                              <span className="text-[10px] text-red-600 font-medium group-hover:text-red-700">No owner</span>
                              <span className="px-1 py-0 rounded text-[8px] font-bold bg-amber-50 text-amber-700 border border-amber-200 flex-shrink-0">Ownerless</span>
                            </>,
                            i.app_reg_likely_service || 'App Registration'
                          );
                        }

                        // P8: Microsoft system SPN
                        if (i.identity_category === 'service_principal' && i.identity_type !== 'ManagedIdentity') {
                          return (
                            <div className="flex items-center gap-1">
                              <span className="text-[10px] text-gray-400">Microsoft</span>
                              <span className="px-1 py-0 rounded text-[8px] font-bold bg-blue-50 text-blue-600 border border-blue-200 flex-shrink-0">System</span>
                            </div>
                          );
                        }

                        // Fallback
                        return <span className="text-[10px] text-gray-300">{'\u2014'}</span>;
                      })()}
                      {/* Workload type badge (always shown below lineage if classified) */}
                      {!!i.workload_type && i.workload_type !== 'unknown' && (() => {
                        const wb = WORKLOAD_BADGE[i.workload_type!];
                        return wb ? (
                          <span className={`mt-0.5 inline-block px-1 py-0 rounded text-[8px] font-semibold ${wb.badgeClass}`} title={`${wb.label} (${i.workload_confidence || 0}% confidence)`}>
                            {wb.short}
                          </span>
                        ) : null;
                      })()}
                    </td>

                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="mt-3 text-[11px] text-gray-400 text-center">
        Click any row to inspect.
      </div>
      </>)}

      {/* Bulk Action Confirmation Modal */}
      {bulkConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-2xl shadow-lg w-full max-w-md mx-4 p-6">
            <h3 className="text-lg font-bold text-gray-900 mb-2">Confirm Bulk Action</h3>
            <p className="text-sm text-gray-600 mb-4">
              Apply <span className="font-semibold text-gray-900">{bulkConfirm.label}</span> to
              all matched remediations for <span className="font-semibold text-blue-600">{selectedIds.size}</span> selected
              {selectedIds.size === 1 ? ' identity' : ' identities'}?
            </p>
            <p className="text-xs text-gray-400 mb-5">
              This will find all matching remediation playbooks for each selected identity and update their status.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setBulkConfirm(null)}
                disabled={bulkLoading}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={() => executeBulkAction(bulkConfirm.status)}
                disabled={bulkLoading}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition disabled:opacity-50 flex items-center gap-2"
              >
                {bulkLoading && (
                  <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                )}
                {bulkLoading ? 'Applying…' : `${bulkConfirm.label} All`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Identity Detail Drawer */}
      {drawerIdentityId && (
        <>
          <div className="fixed inset-0 bg-black/20 z-40" onClick={() => setDrawerIdentityId(null)} />
          <IdentityDrawer identityId={drawerIdentityId} onClose={() => setDrawerIdentityId(null)} />
        </>
      )}

      {/* Add to Group Modal */}
      {addToGroupOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={() => setAddToGroupOpen(false)}>
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-sm p-6" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-gray-900 mb-3">Add {selectedIds.size} identities to group</h3>
            {allGroups.filter(g => g.group_type === 'custom').length === 0 ? (
              <div className="text-xs text-gray-400 py-4 text-center">No custom groups. <Link to="/groups" className="text-blue-600 hover:underline">Create one</Link></div>
            ) : (
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {allGroups.filter(g => g.group_type === 'custom').map(g => (
                  <button
                    key={g.id}
                    onClick={async () => {
                      try {
                        const res = await fetch(`/api/groups/${g.id}/members`, {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({ identity_ids: Array.from(selectedIds) }),
                        });
                        if (!res.ok) throw new Error('Failed');
                        const data = await res.json();
                        setAddToGroupOpen(false);
                        setSelectedIds(new Set());
                        alert(`Added ${data.added} identities to "${g.name}"`);
                      } catch {
                        alert('Failed to add to group');
                      }
                    }}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-gray-50 transition flex items-center gap-2 border"
                  >
                    <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: g.color || '#3B82F6' }} />
                    <span className="text-sm font-medium text-gray-900">{g.name}</span>
                    <span className="text-xs text-gray-400 ml-auto">{g.member_count} members</span>
                  </button>
                ))}
              </div>
            )}
            <button onClick={() => setAddToGroupOpen(false)} className="mt-4 w-full py-2 text-sm text-gray-500 hover:text-gray-700 transition">Cancel</button>
          </div>
        </div>
      )}

      {/* Lineage Detail Panel */}
      {lineagePanelIdentity && (
        <LineageDetailPanel identity={lineagePanelIdentity} onClose={() => setLineagePanelIdentity(null)} />
      )}
    </div>
  );
}
