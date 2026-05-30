import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useToast } from '../components/ToastProvider';
import { useAuth } from '../contexts/AuthContext';
import { useConnection } from '../contexts/ConnectionContext';
import EmptyState from '../components/ui/EmptyState';
import { useFeatureFlag } from '../contexts/FeatureFlagContext';
import QueryBuilder from '../components/QueryBuilder';
import type { AdvancedQuery, QueryFieldDefinition } from '../types';
import { queryIdentities, getQueryFields } from '../services/api';
import Sparkline from '../components/Sparkline';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { deriveIdentityState } from '../constants/identityState';
import { normalizeScore } from '../utils/identityRiskScore';
import { formatRelativeDate, lastSeenColor, SOURCE_LABELS, enrichIpLabel } from '../constants/activitySignals';
import { downloadCSV, downloadJSON, exportFilename, IDENTITY_CSV_COLUMNS, buildExportMeta } from '../utils/exportUtils';
import { MultiSelectFilter, type SelectOption } from '../components/ui/MultiSelectFilter';
import { maskCredential } from '../utils/maskCredential';
import { STATUS_BADGE, type IdentityStatus } from '../utils/resolveStatus';
import IdentityDrawer from '../components/IdentityDrawer';
import FilterableColumnHeader, { type FilterOption } from '../components/identity/FilterableColumnHeader';
import ActiveFilterChips from '../components/identity/ActiveFilterChips';
import ExposureGraph from '../components/graph/ExposureGraph';
import { OrphanBadgeCompact } from '../components/lineage';
import LineageDetailPanel from '../components/LineageDetailPanel';
import {
  type IdentityCategory, type RiskLevel, type DormantStatus,
  type PrivilegedLevel, type EffectiveScope, type CredentialHealth,
  type LifecycleState, type GovernanceState, type PrivilegeLevel,
  CATEGORY_FILTER_OPTIONS, RISK_FILTER_OPTIONS, RISK_ORDER, RISK_BADGE, RISK_SOLID, CLOUD_BADGE,
  THRESHOLDS, DORMANT_LABELS, DATA_EXPLANATIONS,
  PRIVILEGED_LEVELS, EFFECTIVE_SCOPE_CONFIG, EFFECTIVE_SCOPE_ORDER, CREDENTIAL_HEALTH_CONFIG,
  LIFECYCLE_STATE_DISPLAY, GOVERNANCE_STATE_DISPLAY, PRIVILEGE_LEVEL_DISPLAY,
  SCOPE_LABELS, CATEGORY_LABELS_MULTI, IDENTITY_CATEGORIES,
  safeLower, normalizeCategoryFromBackend, getCategoryLabel, getCategoryShortLabel, getDormantStatus as getDormantStatusFromActivity,
  getCategoriesForClouds, MANAGED_IDENTITY_GROUP, TIME_MS,
} from '../constants/metrics';

interface IdentityRow {
  // Core identity fields
  id?: string;
  identity_id: string;
  principal_id?: string;
  display_name: string;
  identity_type?: string;
  identity_category?: IdentityCategory;
  cloud?: string;
  owner_display_name?: string | null;
  owner_count?: number;
  account_enabled?: boolean;
  enabled?: boolean;
  user_type?: string | null;
  privilege_tier?: number;
  highest_role?: string | null;
  assigned_roles?: number;
  blast_scope?: string | null;
  federated_credential_issuer?: string | null;
  inferred_origin?: string | null;
  associated_resource?: string | null;
  lineage_verdict?: string | null;
  owner_deleted?: boolean;
  app_id?: string | null;
  status?: IdentityStatus;

  // Risk fields
  risk_level?: RiskLevel;
  risk_score?: number;

  // Canonical SSOT activity fields
  last_activity_date?: string | null;
  last_activity_source?: string | null;
  last_activity_confidence?: string | null;
  last_activity_note?: string | null;
  activity_status?: string;
  days_inactive?: number | null;
  role_assignment_date?: string | null;

  // IP observation fields (ARM Activity Log)
  last_observed_ip?: string | null;
  last_observed_ip_source?: string | null;
  last_observed_ip_date?: string | null;
  last_observed_operation?: string | null;

  // Access fields
  effective_access?: string | null;
  sensitive_access?: string | null;
  effective_scope?: EffectiveScope;
  privileged_level?: PrivilegedLevel;

  // Snapshot fields
  first_seen?: string | null;
  created_date?: string | null;
  created_datetime?: string | null;
  snapshot_id?: string | null;

  // Legacy / existing fields (backward compat)
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
  credential_health?: CredentialHealth;
  pim_eligible_count?: number;
  has_permanent_assignment?: boolean;
  ca_coverage_status?: string | null;
  ca_mfa_enforced?: boolean;
  subscription_id?: string | null;
  subscription_name?: string | null;
  primary_subscription_id?: string | null;
  additional_subscription_count?: number;
  identity_age_days?: number | null;
  // AI Agent Governance
  agent_identity_type?: string | null;
  detected_platform?: string | null;
  classification_confidence?: number | null;
  // Identity Lineage
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
  // Verdict assembly fields
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
  has_federated_credentials?: boolean;
  federated_issuer_types?: string[];
  // NHI enrichment (AG-159)
  secret_expiry_earliest?: string | null;
  secret_expiry_status?: string | null;
  federated_cred_count?: number;
  owner_resolved?: string | null;
  // Humans enrichment (AG-160)
  mfa_status?: string | null;
  mfa_methods?: string[];
  department?: string | null;
  manager_id?: string | null;
  job_title?: string | null;
  upn?: string | null;
  // Access path classification (P0-A 2026-05-30) — lets CISO views show
  // "174 direct · 949 via group" instead of conflating both into 977.
  has_direct_rbac_path?: boolean;
  has_direct_entra_path?: boolean;
  has_pim_eligible_path?: boolean;
  has_group_inherited_path?: boolean;
  access_depth?: 'direct' | 'group_inherited' | 'none';
  // Dependency impact
  dependency_impact?: string | null;
  // Observed usage tracking
  observed_last_used?: string | null;
  // Sign-in authentication provenance
  last_signin_at?: string | null;
  last_signin_ip?: string | null;
  auth_source?: string | null;
  // Three-dimension identity classification
  lifecycle_state?: string | null;
  governance_state?: string | null;
  privilege_level?: string | null;
  access_tier?: 'control_plane' | 'data_plane';
  // Canonical identity state fields (from build_identity_state)
  activity_label?: string | null;
  activity_detail?: string | null;
  auth_activity?: {
    interactive_signin: boolean;
    non_interactive_signin: boolean;
    arm_activity: boolean;
    token_usage: boolean;
    lineage_activity: boolean;
    any_activity_observed: boolean;
    confidence: string;
  } | null;
  is_dormant?: boolean;
  last_seen?: string | null;
  last_seen_source?: string | null;
  last_seen_available?: boolean;
  last_seen_confidence?: string | null;
  risk_label?: string | null;
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
  | 'last_activity_date'
  | 'recommended_action'
  | 'lifecycle_state'
  | 'governance_state';

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

function formatLastSeen(dateStr?: string | null, authSource?: string | null): { label: string; colorClass: string } {
  if (!dateStr) {
    return authSource === 'static_analysis_only'
      ? { label: 'Provisioned', colorClass: 'text-amber-500' }
      : { label: 'Idle', colorClass: 'text-amber-400' };
  }
  try {
    const days = Math.floor((Date.now() - new Date(dateStr).getTime()) / TIME_MS.DAY);
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
    const days = Math.ceil((new Date(iso).getTime() - Date.now()) / TIME_MS.DAY);
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
  service_principal: 'badge-type-purple',
  managed_identity_system: 'badge-type-cyan',
  managed_identity_user: 'badge-type-teal',
  human_user: 'badge-type-indigo',
  guest: 'badge-type-pink',
};

function CategoryBadge({ category, cloud }: { category?: IdentityCategory; cloud?: string }) {
  const color = CATEGORY_BADGE_COLORS[category || ''] || 'badge-type-indigo';
  const cloudLabels = cloud && CATEGORY_LABELS_MULTI[cloud.toLowerCase()];
  const label = (cloudLabels && cloudLabels[category || '']) || getCategoryShortLabel(category);
  return <span className={color}>{label}</span>;
}

function PrivilegedBadge({ level }: { level?: PrivilegedLevel }) {
  const cfg = PRIVILEGED_LEVELS[level || 'standard'];
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${cfg.color}`} title={cfg.tooltip}>{cfg.label}</span>;
}

function LifecycleLabel({ state }: { state?: string | null }) {
  const cfg = LIFECYCLE_STATE_DISPLAY[(state || 'Unknown') as LifecycleState] || LIFECYCLE_STATE_DISPLAY.Unknown;
  const isDisabled = state === 'Disabled';
  return (
    <span style={{
      fontSize: '11px',
      color: isDisabled ? 'var(--text-tertiary, #6b7280)' : 'var(--text-secondary, #9ca3af)',
      fontWeight: isDisabled ? 500 : 400,
      opacity: isDisabled ? 0.7 : 0.85,
    }} title={cfg.tooltip}>
      {cfg.label}
    </span>
  );
}

function GovernanceBadge({ state }: { state?: string | null }) {
  const key = (state || 'Governed') as GovernanceState;
  const cfg = GOVERNANCE_STATE_DISPLAY[key] || GOVERNANCE_STATE_DISPLAY.Governed;
  const dotColor: Record<string, string> = {
    'Policy Violation': '#f87171',
    'Ungoverned': '#f87171',
    'Orphaned': '#fbbf24',
    'Governed': '#6ee7b7',
  };
  return (
    <span style={{ fontSize: '11px', color: 'var(--text-secondary, #9ca3af)', fontWeight: 400, display: 'inline-flex', alignItems: 'center', gap: '4px' }} title={cfg.tooltip}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: dotColor[key] || '#6ee7b7', flexShrink: 0 }} />
      {cfg.label}
    </span>
  );
}

function PrivilegeLevelBadge({ level }: { level?: string | null }) {
  const key = (level || 'Standard') as PrivilegeLevel;
  const cfg = PRIVILEGE_LEVEL_DISPLAY[key] || PRIVILEGE_LEVEL_DISPLAY.Standard;
  return (
    <span style={{
      fontSize: '11px',
      color: 'var(--text-secondary, #9ca3af)',
      fontWeight: key === 'Highly Privileged' ? 600 : 400,
    }} title={cfg.tooltip}>
      {cfg.label}
    </span>
  );
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

// ─── Tab scope definitions ─────────────────────────────────────────

export type TabScope = 'humans' | 'nhi' | 'all';

const TAB_SCOPE_CATEGORIES: Record<TabScope, IdentityCategory[] | null> = {
  humans: ['human_user', 'guest'],
  nhi: ['service_principal', 'managed_identity_system', 'managed_identity_user'],
  all: null, // no pre-filter
};

// ─── Main component ────────────────────────────────────────────────

export default function IdentitiesPage({ tabScope = 'all' as TabScope }: { tabScope?: TabScope }) {
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
  const [tabSubPill, setTabSubPill] = useState<string>('all');
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
  const [logIndependentChipDismissed, setLogIndependentChipDismissed] = useState(false);
  // Identity Lineage orphan filter
  const [orphanFilter, setOrphanFilter] = useState(false);
  // Three-dimension signal chip filter (single-select toggle)
  const [signalChip, setSignalChip] = useState<'ungoverned' | 'orphaned' | 'priv_ungoverned' | 'privileged' | 'data_plane' | 'no_mfa' | 'unknown_mfa' | 'stale' | 'joiners' | 'secrets' | 'no_owner' | 'federated' | 'direct_access' | 'group_inherited' | null>(null);
  // Governance summary from backend — SSOT, avoids frontend recomputation
  const [governanceSummary, setGovernanceSummary] = useState<{
    orphaned: number; ungoverned: number; policy_violation: number; privileged: number; combo: number; data_plane: number;
  } | null>(null);
  // AG-162: Column-level filters (field → selected values)
  const [columnFilters, setColumnFilters] = useState<Record<string, string[]>>({});

  // AI Agent Governance filter state (additive, gated by feature flag)
  const agentFilterEnabled = useFeatureFlag('ai_agent_governance');
  const [agentFilter, setAgentFilter] = useState(false);              // filter active
  const [agentCount, setAgentCount] = useState(0);                    // badge count
  const [allGroups, setAllGroups] = useState<{id: number | string; name: string; color: string; group_type: string; member_count: number}[]>([]);
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
  const [snapshots, setSnapshots] = useState<{ id: number; status: string; completed_at: string | null; total_identities: number; component_status?: Record<string, string> }[]>([]);

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
      h2_dormant_priv: 'HIRI — Dormant Privileged: stale/no-activity humans with privileged roles',
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
      setContextBanner('Dormant accounts with active privileged roles (stale or no activity observed)');
    } else if (activityParamForBanner === 'dormant_strict') {
      setContextBanner('Dormant identities (stale or no activity observed — excludes idle)');
    } else if (statusParamForBanner?.toLowerCase() === 'disabled' && hasRolesParam === 'true') {
      setContextBanner('Ghost identities — disabled in Entra ID but retain active RBAC roles');
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
            last_activity_date: raw.last_activity_date || null,
            last_activity_source: raw.last_activity_source || null,
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
            has_federated_credentials: raw.has_federated_credentials ?? false,
            has_direct_rbac_path: raw.has_direct_rbac_path ?? false,
            has_direct_entra_path: raw.has_direct_entra_path ?? false,
            has_pim_eligible_path: raw.has_pim_eligible_path ?? false,
            has_group_inherited_path: raw.has_group_inherited_path ?? false,
            access_depth: (raw.access_depth as 'direct' | 'group_inherited' | 'none') || 'none',
            federated_issuer_types: raw.federated_issuer_types || [],
            secret_expiry_earliest: raw.secret_expiry_earliest || null,
            secret_expiry_status: raw.secret_expiry_status || null,
            federated_cred_count: raw.federated_cred_count ?? 0,
            owner_resolved: raw.owner_resolved || null,
            mfa_status: raw.mfa_status || null,
            mfa_methods: raw.mfa_methods || [],
            department: raw.department || null,
            job_title: raw.job_title || null,
            upn: raw.upn || null,
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
            // Three-dimension governance fields — SSOT from backend
            lifecycle_state: raw.lifecycle_state || null,
            governance_state: raw.governance_state || null,
            privilege_level: raw.privilege_level || null,
            access_tier: raw.access_tier || 'control_plane',
            // Canonical identity state fields
            activity_label: raw.activity_label || null,
            activity_detail: raw.activity_detail || null,
            auth_activity: raw.auth_activity || null,
            is_dormant: raw.is_dormant ?? false,
            last_seen: raw.last_seen || null,
            last_seen_source: raw.last_seen_source || null,
            last_seen_available: raw.last_seen_available ?? false,
            last_seen_confidence: raw.last_seen_confidence || null,
            risk_label: raw.risk_label || null,
          }));
          if (!cancelled) {
            setIdentities(rows);
            if (data.governance_summary) setGovernanceSummary(data.governance_summary);
          }
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
          last_activity_date: raw.last_activity_date || null,
          last_activity_source: raw.last_activity_source || null,
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
          has_federated_credentials: raw.has_federated_credentials ?? false,
          has_direct_rbac_path: raw.has_direct_rbac_path ?? false,
          has_direct_entra_path: raw.has_direct_entra_path ?? false,
          has_pim_eligible_path: raw.has_pim_eligible_path ?? false,
          has_group_inherited_path: raw.has_group_inherited_path ?? false,
          access_depth: (raw.access_depth as 'direct' | 'group_inherited' | 'none') || 'none',
          federated_issuer_types: raw.federated_issuer_types || [],
          // NHI enrichment (AG-159)
          secret_expiry_earliest: raw.secret_expiry_earliest || null,
          secret_expiry_status: raw.secret_expiry_status || null,
          federated_cred_count: raw.federated_cred_count ?? 0,
          owner_resolved: raw.owner_resolved || null,
          // Humans enrichment (AG-160)
          mfa_status: raw.mfa_status || null,
          mfa_methods: raw.mfa_methods || [],
          department: raw.department || null,
          job_title: raw.job_title || null,
          upn: raw.upn || null,
          dependency_impact: raw.dependency_impact || null,
          observed_last_used: raw.observed_last_used || null,
          last_signin_at: raw.last_signin_at || null,
          last_signin_ip: raw.last_signin_ip || null,
          auth_source: raw.auth_source || null,
          // Three-dimension governance fields — SSOT from backend
          lifecycle_state: raw.lifecycle_state || null,
          governance_state: raw.governance_state || null,
          privilege_level: raw.privilege_level || null,
          access_tier: raw.access_tier || 'control_plane',
          // Canonical identity state fields
          activity_label: raw.activity_label || null,
          activity_detail: raw.activity_detail || null,
          auth_activity: raw.auth_activity || null,
          is_dormant: raw.is_dormant ?? false,
          last_seen: raw.last_seen || null,
          last_seen_source: raw.last_seen_source || null,
          last_seen_available: raw.last_seen_available ?? false,
          last_seen_confidence: raw.last_seen_confidence || null,
          risk_label: raw.risk_label || null,
        }));
        if (!cancelled) {
          setIdentities(rows);
          if (data.governance_summary) setGovernanceSummary(data.governance_summary);
        }
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

  // Derive static category groups from loaded identities (5 fixed options)
  useEffect(() => {
    if (identities.length === 0) { setAllGroups([]); return; }
    const counts = { guest: 0, human_user: 0, managed_identity: 0, service_principal: 0, nhi_other: 0 };
    for (const i of identities) {
      const cat = i.identity_category || '';
      if (cat === 'guest') counts.guest++;
      else if (cat === 'human_user') counts.human_user++;
      else if (cat === 'managed_identity_system' || cat === 'managed_identity_user') counts.managed_identity++;
      else if (cat === 'service_principal') counts.service_principal++;
      else counts.nhi_other++;
    }
    setAllGroups([
      { id: 'cat_guest', name: 'All Guest Users', color: '', group_type: 'auto', member_count: counts.guest },
      { id: 'cat_human_user', name: 'All Human Users', color: '', group_type: 'auto', member_count: counts.human_user },
      { id: 'cat_managed_identity', name: 'All Managed Identities', color: '', group_type: 'auto', member_count: counts.managed_identity },
      { id: 'cat_service_principal', name: 'All Service Principals', color: '', group_type: 'auto', member_count: counts.service_principal },
      { id: 'cat_nhi_other', name: 'All SPNs / Workloads', color: '', group_type: 'auto', member_count: counts.nhi_other },
    ]);
  }, [identities]);

  // Phase 7: Load snapshots for selector (refetch on org switch)
  useEffect(() => {
    fetch('/api/runs')
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => setSnapshots((d.runs || []).filter((r: any) => r.status === 'completed' || r.status === 'partial' || r.status === 'failed').slice(0, 10)))
      .catch(() => setSnapshots([]));
  }, [activeOrgId]);

  // When group filter changes, resolve members locally by identity_category
  useEffect(() => {
    const activeGroups = multiGroupFilter.length > 0 ? multiGroupFilter : (groupFilter !== 'all' ? [String(groupFilter)] : []);
    if (activeGroups.length === 0) { setGroupMemberIds(null); return; }
    const catMap: Record<string, (cat: string) => boolean> = {
      cat_guest: (c) => c === 'guest',
      cat_human_user: (c) => c === 'human_user',
      cat_managed_identity: (c) => c === 'managed_identity_system' || c === 'managed_identity_user',
      cat_service_principal: (c) => c === 'service_principal',
      cat_nhi_other: (c) => c !== 'guest' && c !== 'human_user' && c !== 'managed_identity_system' && c !== 'managed_identity_user' && c !== 'service_principal',
    };
    const ids = new Set<string>();
    for (const i of identities) {
      const cat = i.identity_category || '';
      for (const gid of activeGroups) {
        const matcher = catMap[gid];
        if (matcher && matcher(cat)) { ids.add(i.identity_id); break; }
      }
    }
    setGroupMemberIds(ids);
  }, [groupFilter, multiGroupFilter, identities]);

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
          last_activity_date: raw.last_activity_date || null,
          last_activity_source: raw.last_activity_source || null,
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
          has_federated_credentials: raw.has_federated_credentials ?? false,
          has_direct_rbac_path: raw.has_direct_rbac_path ?? false,
          has_direct_entra_path: raw.has_direct_entra_path ?? false,
          has_pim_eligible_path: raw.has_pim_eligible_path ?? false,
          has_group_inherited_path: raw.has_group_inherited_path ?? false,
          access_depth: (raw.access_depth as 'direct' | 'group_inherited' | 'none') || 'none',
          federated_issuer_types: raw.federated_issuer_types || [],
          secret_expiry_earliest: raw.secret_expiry_earliest || null,
          secret_expiry_status: raw.secret_expiry_status || null,
          federated_cred_count: raw.federated_cred_count ?? 0,
          owner_resolved: raw.owner_resolved || null,
          mfa_status: raw.mfa_status || null,
          mfa_methods: raw.mfa_methods || [],
          department: raw.department || null,
          job_title: raw.job_title || null,
          upn: raw.upn || null,
          dependency_impact: raw.dependency_impact || null,
          observed_last_used: raw.observed_last_used || null,
          // Three-dimension governance fields — SSOT from backend
          lifecycle_state: raw.lifecycle_state || null,
          governance_state: raw.governance_state || null,
          privilege_level: raw.privilege_level || null,
          access_tier: raw.access_tier || 'control_plane',
          // Canonical identity state fields
          activity_label: raw.activity_label || null,
          activity_detail: raw.activity_detail || null,
          auth_activity: raw.auth_activity || null,
          is_dormant: raw.is_dormant ?? false,
          last_seen: raw.last_seen || null,
          last_seen_source: raw.last_seen_source || null,
          last_seen_available: raw.last_seen_available ?? false,
          last_seen_confidence: raw.last_seen_confidence || null,
          risk_label: raw.risk_label || null,
        }));
        setQueryResults(rows);
        setQueryTotal(data.total ?? rows.length);
        if (data.governance_summary) setGovernanceSummary(data.governance_summary);
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
    // AG-162: column filters
    const activeColFilters = Object.entries(columnFilters).filter(([, v]) => v.length > 0);
    if (activeColFilters.length > 0) {
      f.column_filters = Object.fromEntries(activeColFilters);
    }
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
    // AG-162: restore column filters
    setColumnFilters(f.column_filters && typeof f.column_filters === 'object' ? f.column_filters : {});
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
          case 'last_activity_date':
            aVal = a.last_activity_date ? new Date(a.last_activity_date).getTime() : 0;
            bVal = b.last_activity_date ? new Date(b.last_activity_date).getTime() : 0;
            break;
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
          if (!subId) return true;
          // subscription_id may be comma-separated for multi-sub discovery runs
          return subId.split(',').some(s => activatedSubIds.has(s.trim()));
        });
      }
    }

    // Tab-scope pre-filter: restrict to tab's identity categories
    const scopeCats = TAB_SCOPE_CATEGORIES[tabScope];
    if (scopeCats) {
      result = result.filter(i => scopeCats.includes(i.identity_category as IdentityCategory));
    }

    // Tab sub-pill filter (within-tab drill-down)
    if (tabSubPill !== 'all') {
      if (tabSubPill === 'members') result = result.filter(i => i.identity_category === 'human_user');
      else if (tabSubPill === 'guests') result = result.filter(i => i.identity_category === 'guest');
      else if (tabSubPill === 'stale') result = result.filter(i => {
        const act = safeLower(i.activity_status);
        return act === 'stale' || act === 'never_used';
      });
      else if (tabSubPill === 'no_mfa') result = result.filter(i => i.mfa_status === 'not_enrolled');
      else if (tabSubPill === 'app_spn') result = result.filter(i => i.identity_category === 'service_principal');
      else if (tabSubPill === 'sys_msi') result = result.filter(i => i.identity_category === 'managed_identity_system');
      else if (tabSubPill === 'usr_msi') result = result.filter(i => i.identity_category === 'managed_identity_user');
      else if (tabSubPill === 'federated') result = result.filter(i => (i as any).federated_cred_count > 0 || (i as any).is_federated);
      else if (tabSubPill === 'orphaned') result = result.filter(i => i.recommended_action === 'ORPHANED' || i.governance_state === 'Orphaned');
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
      result = result.filter(i => {
        if (multiSubscriptionFilter.includes(i.primary_subscription_id || '')) return true;
        const subs = (i.subscription_id || '').split(',').map(s => s.trim());
        return subs.some(s => multiSubscriptionFilter.includes(s));
      });
    } else if (subscriptionFilter !== 'all') {
      result = result.filter(i => {
        const subs = (i.subscription_id || '').split(',').map(s => s.trim());
        return subs.includes(subscriptionFilter) || i.primary_subscription_id === subscriptionFilter;
      });
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
      const thirtyDays = THRESHOLDS.CREDENTIAL_EXPIRY_DAYS * TIME_MS.DAY;
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
      result = result.filter(i => {
        // SSOT: enabled boolean is the ONLY source for disabled/active status
        const resolved = i.enabled === false ? 'disabled' : 'active';
        return multiStatusFilter.includes(resolved);
      });
    } else if (statusFilter !== 'all') {
      result = result.filter(i => {
        const resolved = i.enabled === false ? 'disabled' : 'active';
        return resolved === statusFilter;
      });
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
    // Three-dimension signal chip filters
    if (signalChip === 'ungoverned') result = result.filter(i => i.governance_state === 'Ungoverned');
    if (signalChip === 'orphaned') result = result.filter(i => i.governance_state === 'Orphaned');
    if (signalChip === 'privileged') result = result.filter(i => i.privilege_level === 'Privileged' || i.privilege_level === 'Highly Privileged');
    if (signalChip === 'priv_ungoverned') result = result.filter(i =>
      (i.governance_state === 'Ungoverned' || i.governance_state === 'Orphaned' || i.governance_state === 'Policy Violation')
      && (i.privilege_level === 'Privileged' || i.privilege_level === 'Highly Privileged')
    );
    if (signalChip === 'data_plane') result = result.filter(i => i.access_tier === 'data_plane');
    // Tab-scoped KPI chip filters
    if (signalChip === 'no_mfa') result = result.filter(i => i.mfa_status === 'not_enrolled');
    if (signalChip === 'unknown_mfa') result = result.filter(i => !i.mfa_status || i.mfa_status === 'unknown');
    if (signalChip === 'stale') result = result.filter(i => { const a = safeLower(i.activity_status); return a === 'stale' || a === 'never_used'; });
    if (signalChip === 'joiners') result = result.filter(i => i.created_datetime && new Date(i.created_datetime).getTime() >= Date.now() - 30 * 24 * 60 * 60 * 1000);
    if (signalChip === 'secrets') result = result.filter(i => i.credential_status === 'expired' || (i.credential_expiration && new Date(i.credential_expiration).getTime() < Date.now() + 30 * 24 * 60 * 60 * 1000));
    if (signalChip === 'no_owner') result = result.filter(i => !i.owner_display_name && (i.owner_count ?? 0) === 0);
    if (signalChip === 'federated') result = result.filter(i => (i as any).federated_cred_count > 0 || (i as any).is_federated);
    // P0-A (2026-05-30): access-path filters — Direct narrows to actual
    // Azure-access holders; Group filters to passive members of role-bearing
    // groups (the inflation source CISOs were misled by).
    if (signalChip === 'direct_access') result = result.filter(i =>
      i.has_direct_rbac_path || i.has_direct_entra_path || i.has_pim_eligible_path
    );
    if (signalChip === 'group_inherited') result = result.filter(i =>
      !i.has_direct_rbac_path && !i.has_direct_entra_path && !i.has_pim_eligible_path
      && i.has_group_inherited_path
    );

    // AG-162: Column-level filters
    for (const [field, vals] of Object.entries(columnFilters)) {
      if (vals.length > 0) {
        result = result.filter(i => vals.includes(getFieldValue(i, field)));
      }
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
        case 'last_activity_date':
          aVal = a.last_activity_date ? new Date(a.last_activity_date).getTime() : 0;
          bVal = b.last_activity_date ? new Date(b.last_activity_date).getTime() : 0;
          break;
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
        case 'lifecycle_state': {
          const lcOrd: Record<string, number> = { Disabled: 1, Dormant: 2, Provisioned: 3, Active: 4 };
          aVal = lcOrd[a.lifecycle_state || 'Provisioned'] || 0;
          bVal = lcOrd[b.lifecycle_state || 'Provisioned'] || 0;
          break;
        }
        case 'governance_state': {
          const gsOrd: Record<string, number> = { Orphaned: 1, 'Policy Violation': 2, Ungoverned: 3, Governed: 4 };
          aVal = gsOrd[a.governance_state || 'Governed'] || 0;
          bVal = gsOrd[b.governance_state || 'Governed'] || 0;
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
    if (result.length === 0 && identities.length > 0) {
    }
    return result;
  }, [queryMode, queryResults, identities, search, cloudFilter, riskFilter, multiRiskFilter, categoryFilter, multiCategoryFilter, workloadFilter, subscriptionFilter, multiSubscriptionFilter, allSubscriptions, ownerFilter, activityFilter, tierFilter, credentialFilter, caFilter, groupFilter, multiGroupFilter, groupMemberIds, statusFilter, multiStatusFilter, hasRolesFilter, signalChip, columnFilters, sortField, sortDir, tabScope, tabSubPill]);

  // AG-162: Compute filter options with live counts from visible data
  const columnFilterOptions = useMemo(() => {
    const countValues = (field: string): FilterOption[] => {
      const counts: Record<string, number> = {};
      for (const row of filtered) {
        const v = getFieldValue(row, field);
        counts[v] = (counts[v] || 0) + 1;
      }
      // Also include values from current active filter that may have been filtered out (show as 0)
      for (const v of (columnFilters[field] || [])) {
        if (!(v in counts)) counts[v] = 0;
      }
      return Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .map(([value, count]) => ({ value, label: value, count }));
    };

    // Compute for filterable columns relevant to current tab
    const opts: Record<string, FilterOption[]> = {
      risk_level: countValues('risk_level'),
      status: countValues('status'),
      lifecycle_state: countValues('lifecycle_state'),
      governance_state: countValues('governance_state'),
      privilege_level: countValues('privilege_level'),
      cloud: countValues('cloud'),
    };
    if (tabScope === 'humans') {
      opts.mfa_status = countValues('mfa_status');
    }
    if (tabScope === 'nhi') {
      opts.secret_expiry_status = countValues('secret_expiry_status');
    }
    return opts;
  }, [filtered, columnFilters, tabScope]);

  // AG-162: Column filter handler
  function handleColumnFilter(field: string, values: string[]) {
    setColumnFilters(prev => {
      const next = { ...prev };
      if (values.length === 0) delete next[field];
      else next[field] = values;
      return next;
    });
  }

  function removeColumnFilterValue(field: string, value: string) {
    setColumnFilters(prev => {
      const vals = (prev[field] || []).filter(v => v !== value);
      const next = { ...prev };
      if (vals.length === 0) delete next[field];
      else next[field] = vals;
      return next;
    });
  }

  function clearAllColumnFilters() {
    setColumnFilters({});
  }

  // AG-162: Extract filterable field value from an identity row
  function getFieldValue(row: IdentityRow, field: string): string {
    switch (field) {
      case 'risk_level': return safeLower(row.risk_level) || 'unknown';
      case 'status': return row.enabled === false ? 'disabled' : 'active';
      case 'mfa_status': return row.mfa_status || 'unknown';
      case 'secret_expiry_status': return row.secret_expiry_status || 'no_secret';
      case 'lifecycle_state': return row.lifecycle_state || 'Provisioned';
      case 'governance_state': return row.governance_state || 'Governed';
      case 'privilege_level': return row.privilege_level || 'Standard';
      case 'activity_status': return safeLower(row.activity_status) || 'unknown';
      case 'cloud': return safeLower(row.cloud) || 'azure';
      case 'identity_category': return row.identity_category || 'unknown';
      default: return String((row as any)[field] ?? 'unknown');
    }
  }

  // AG-162: Human-readable labels for column filter chip display
  const COLUMN_FIELD_LABELS: Record<string, string> = {
    risk_level: 'Risk',
    status: 'Status',
    mfa_status: 'MFA',
    secret_expiry_status: 'Secret Expiry',
    lifecycle_state: 'Lifecycle',
    governance_state: 'Governance',
    privilege_level: 'Privilege',
    activity_status: 'Activity',
    cloud: 'Cloud',
    identity_category: 'Type',
  };

  function handleSort(field: SortField) {
    if (field === sortField) setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
    else {
      setSortField(field);
      setSortDir(['risk_level', 'entra_role_count', 'rbac_role_count', 'api_permission_count', 'privilege_tier', 'dormant', 'effective_scope', 'credential_health', 'status', 'recommended_action', 'lifecycle_state', 'governance_state'].includes(field) ? 'desc' : 'asc');
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
    const headers = ['Display Name','Identity ID','Type','Category','Subscription Name','Subscription ID','Cloud','Risk','Score (0-10)','Tier','Entra Roles','RBAC Roles','Graph Perms','Secret/Expiry','Created','Last Used','Dormant','Compliance','Owner'];
    const rows = selectedIdentities.map(i => [
      i.display_name, i.identity_id, i.identity_type || '', getCategoryLabel(i.identity_category),
      i.subscription_name || '', i.subscription_id || '',
      i.cloud || 'azure', (i.risk_level || 'unknown').toUpperCase(), normalizeScore(i.risk_score, 10).toFixed(1),
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
        normalizeScore(i.risk_score, 10).toFixed(1), `T${getPrivilegeTier(i)}`,
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

  const colSpan = tabScope === 'nhi' ? 15 : tabScope === 'humans' ? 15 : 12; // +3 for NHI/Humans tab columns

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

      {/* Tenant Scope Pill — compact scope indicator. Was a 23-word prose banner;
          collapsed to an at-a-glance "N of M · activate K more →" pattern. */}
      {scopeSummary && scopeSummary.discovered > 0 && (
        <div className="inline-flex items-center gap-2 px-3 py-1.5 mb-3 rounded-lg bg-blue-50 border border-blue-200 text-xs text-blue-800">
          <svg className="w-3.5 h-3.5 flex-shrink-0 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>
            Scope: <strong>{scopeSummary.activated}</strong> of <strong>{scopeSummary.activated + scopeSummary.discovered}</strong> subscription{(scopeSummary.activated + scopeSummary.discovered) !== 1 ? 's' : ''}
            <span className="mx-1.5 text-blue-300" aria-hidden="true">·</span>
            <Link to="/subscriptions" className="font-semibold hover:opacity-80">
              Activate {scopeSummary.discovered} more →
            </Link>
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

      {/* Failed Scan Error Banner */}
      {snapshots.length > 0 && snapshots[0]?.status === 'failed' && (() => {
        const cs = snapshots[0].component_status;
        return (
          <div className="px-3 py-2 rounded-lg border border-red-300 bg-red-50 text-red-800 text-xs mb-1">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <svg className="w-4 h-4 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd"/></svg>
                <span className="font-semibold">Scan Failed</span>
                <span>Critical components could not be collected. Data below may be from a previous scan.</span>
              </div>
              <button
                onClick={() => fetch('/api/runs/trigger', { method: 'POST' }).then(() => window.location.reload())}
                className="ml-3 px-2.5 py-1 bg-red-700 text-white rounded text-xs font-medium hover:bg-red-800 transition flex-shrink-0"
              >
                Retry Scan
              </button>
            </div>
            {cs && Object.keys(cs).length > 0 && (
              <div className="flex flex-wrap gap-x-4 gap-y-0.5 mt-1.5 ml-6">
                {Object.entries(cs).map(([name, status]) => (
                  <span key={name} className="inline-flex items-center gap-1">
                    <span className="capitalize">{name.replace(/_/g, ' ')}:</span>
                    <span className={status === 'success' ? 'text-green-700 font-medium' : 'text-red-700 font-medium'}>
                      {status === 'success' ? 'OK' : status.toUpperCase()} {status === 'success' ? '\u2705' : '\u274C'}
                    </span>
                  </span>
                ))}
              </div>
            )}
          </div>
        );
      })()}

      {/* Partial Scan Warning Banner */}
      {snapshots.length > 0 && snapshots[0]?.status === 'partial' && (() => {
        const cs = snapshots[0].component_status;
        return (
          <div className="px-3 py-2 rounded-lg border border-amber-300 bg-amber-50 text-amber-800 text-xs mb-1">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <svg className="w-4 h-4 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd"/></svg>
                <span className="font-semibold">Partial Scan</span>
                <span>Some data could not be collected. Results may not reflect your full environment.</span>
              </div>
              <button
                onClick={() => fetch('/api/runs/trigger', { method: 'POST' }).then(() => window.location.reload())}
                className="ml-3 px-2.5 py-1 bg-amber-700 text-white rounded text-xs font-medium hover:bg-amber-800 transition flex-shrink-0"
              >
                Retry Scan
              </button>
            </div>
            {cs && Object.keys(cs).length > 0 && (
              <div className="flex flex-wrap gap-x-4 gap-y-0.5 mt-1.5 ml-6">
                {Object.entries(cs).map(([name, status]) => (
                  <span key={name} className="inline-flex items-center gap-1">
                    <span className="capitalize">{name.replace(/_/g, ' ')}:</span>
                    <span className={status === 'success' ? 'text-green-700 font-medium' : 'text-amber-700 font-medium'}>
                      {status === 'success' ? 'OK' : status.toUpperCase()} {status === 'success' ? '\u2705' : '\u26A0\uFE0F'}
                    </span>
                  </span>
                ))}
              </div>
            )}
          </div>
        );
      })()}

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
                AI Identities
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

      {/* Tab-scoped sub-pills */}
      {!loading && identities.length > 0 && (() => {
        // Define sub-pills per tab scope
        const subPills: { key: string; label: string }[] =
          tabScope === 'humans' ? [
            { key: 'all', label: 'All Humans' },
            { key: 'members', label: 'Members' },
            { key: 'guests', label: 'Guests' },
            { key: 'stale', label: 'Stale > 90d' },
            { key: 'no_mfa', label: 'No MFA' },
          ] : tabScope === 'nhi' ? [
            { key: 'all', label: 'All NHI' },
            { key: 'app_spn', label: 'App SPNs' },
            { key: 'sys_msi', label: 'System MSI' },
            { key: 'usr_msi', label: 'User MSI' },
            { key: 'federated', label: 'Federated' },
            { key: 'orphaned', label: 'Orphaned' },
          ] : [
            // "All Identities" tab — original category pills
            { key: 'all', label: 'All Identities' },
            { key: 'human_user', label: 'Human Users' },
            { key: 'service_principal', label: 'Service Principals' },
            { key: 'managed_ids', label: 'Managed IDs' },
            { key: 'guest', label: 'Guest' },
          ];

        return (
          <div className="flex items-center gap-1.5 mb-3">
            {subPills.map(pill => {
              // For "all" tab, use legacy category filter; for scoped tabs, use tabSubPill
              const isActive = tabScope === 'all'
                ? (pill.key === 'all' ? categoryFilter === 'all' && !workloadFilter :
                   pill.key === 'managed_ids' ? multiCategoryFilter.length === 2 && multiCategoryFilter.includes('managed_identity_system') :
                   categoryFilter === pill.key && !workloadFilter)
                : tabSubPill === pill.key;

              return (
                <button
                  key={pill.key}
                  onClick={() => {
                    if (tabScope === 'all') {
                      // Legacy behavior for All Identities tab
                      setWorkloadFilter(false);
                      clearActiveView();
                      if (pill.key === 'managed_ids') {
                        setMultiCategoryFilter([...MANAGED_IDENTITY_GROUP]);
                        setCategoryFilter('all');
                      } else {
                        setMultiCategoryFilter([]);
                        setCategoryFilter(pill.key as any);
                      }
                    } else {
                      setTabSubPill(tabSubPill === pill.key ? 'all' : pill.key);
                    }
                  }}
                  className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-violet-600 text-white shadow-sm'
                      : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                  }`}
                >
                  {pill.label}
                </button>
              );
            })}
            {/* NHI + Orphaned pills only on All tab */}
            {tabScope === 'all' && (<>
              <button
                onClick={() => {
                  setWorkloadFilter(!workloadFilter);
                  if (!workloadFilter) { setCategoryFilter('all'); setMultiCategoryFilter([]); clearActiveView(); }
                }}
                className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
                  workloadFilter ? 'bg-violet-600 text-white shadow-sm' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                NHI (All Non-Human)
              </button>
              <button
                onClick={() => setOrphanFilter(!orphanFilter)}
                className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors inline-flex items-center gap-1.5 ${
                  orphanFilter ? 'bg-amber-500 text-white shadow-sm' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                Orphaned
              </button>
            </>)}
          </div>
        );
      })()}

      {/* Tab-scoped KPI tiles */}
      {queryMode === 'simple' && (() => {
        // Compute tab-scoped counts from filtered array (already tab-scoped by pre-filter)
        const privilegedCount = filtered.filter(i => i.privilege_level === 'Privileged' || i.privilege_level === 'Highly Privileged').length;
        const ungovernedCount = governanceSummary?.ungoverned ?? filtered.filter(i => i.governance_state === 'Ungoverned').length;
        const orphanedCount = governanceSummary?.orphaned ?? filtered.filter(i => i.governance_state === 'Orphaned').length;

        // Define KPI tiles per tab
        type KpiTile = { key: string; label: string; count: number; color: string };
        let tiles: KpiTile[];

        if (tabScope === 'humans') {
          // AG-161: Only count verified not_enrolled, not unknown/null
          const noMfaCount = filtered.filter(i => i.mfa_status === 'not_enrolled').length;
          const unknownMfaCount = filtered.filter(i => !i.mfa_status || i.mfa_status === 'unknown').length;
          const staleCount = filtered.filter(i => {
            const act = safeLower(i.activity_status);
            return act === 'stale' || act === 'never_used';
          }).length;
          const joinersCount = filtered.filter(i => {
            if (!i.created_datetime) return false;
            const created = new Date(i.created_datetime).getTime();
            return created >= Date.now() - 30 * 24 * 60 * 60 * 1000;
          }).length;
          tiles = [
            { key: 'no_mfa', label: 'No MFA', count: noMfaCount, color: '#ef4444' },
            ...(unknownMfaCount > 0 ? [{ key: 'unknown_mfa', label: 'Unknown MFA', count: unknownMfaCount, color: '#9ca3af' }] : []),
            { key: 'stale', label: 'Stale', count: staleCount, color: '#f59e0b' },
            { key: 'ungoverned', label: 'Ungoverned', count: ungovernedCount, color: '#f87171' },
            { key: 'privileged', label: 'Privileged', count: privilegedCount, color: '#a78bfa' },
            { key: 'joiners', label: 'Joiners 30d', count: joinersCount, color: '#34d399' },
          ];
        } else if (tabScope === 'nhi') {
          const noOwnerCount = filtered.filter(i => !i.owner_display_name && (i.owner_count ?? 0) === 0).length;
          const federatedCount = filtered.filter(i => (i as any).federated_cred_count > 0 || (i as any).is_federated).length;
          const secretsUrgentCount = filtered.filter(i =>
            i.credential_status === 'expired' || (i.credential_expiration && new Date(i.credential_expiration).getTime() < Date.now() + 30 * 24 * 60 * 60 * 1000)
          ).length;
          tiles = [
            { key: 'secrets', label: 'Secrets < 30d', count: secretsUrgentCount, color: '#ef4444' },
            { key: 'orphaned', label: 'Orphaned', count: orphanedCount, color: '#fbbf24' },
            { key: 'no_owner', label: 'No Owner', count: noOwnerCount, color: '#fb923c' },
            { key: 'privileged', label: 'Privileged', count: privilegedCount, color: '#a78bfa' },
            { key: 'federated', label: 'Federated', count: federatedCount, color: '#34d399' },
          ];
        } else {
          // All Identities — original KPI tiles
          const privUngovernedCount = governanceSummary?.combo ?? filtered.filter(i =>
            (i.governance_state === 'Ungoverned' || i.governance_state === 'Orphaned' || i.governance_state === 'Policy Violation')
            && (i.privilege_level === 'Privileged' || i.privilege_level === 'Highly Privileged')
          ).length;
          tiles = [
            { key: 'ungoverned', label: 'Ungoverned', count: ungovernedCount, color: '#f87171' },
            { key: 'orphaned', label: 'Orphaned', count: orphanedCount, color: '#fbbf24' },
            { key: 'privileged', label: 'Privileged', count: privilegedCount, color: '#a78bfa' },
            { key: 'priv_ungoverned', label: 'Priv + Ungoverned', count: privUngovernedCount, color: '#fca5a5' },
            { key: 'data_plane', label: 'Data Plane', count: governanceSummary?.data_plane ?? filtered.filter(i => i.access_tier === 'data_plane').length, color: '#38bdf8' },
          ];
        }

        return (
          <div className="mb-3 space-y-2">
            {/* P0-A (2026-05-30): Access-path breakdown for the Humans tab.
                CISOs were misled by the conflated 977 count; the real "direct
                Azure access" count is dramatically smaller. Showing both
                turns the misleading single number into truthful triage info. */}
            {tabScope === 'humans' && (() => {
              const directHumans = filtered.filter(i =>
                i.has_direct_rbac_path || i.has_direct_entra_path || i.has_pim_eligible_path
              );
              const groupOnlyHumans = filtered.filter(i =>
                !i.has_direct_rbac_path && !i.has_direct_entra_path && !i.has_pim_eligible_path
                && i.has_group_inherited_path
              );
              if (groupOnlyHumans.length === 0) return null;
              const directRbacCount  = filtered.filter(i => i.has_direct_rbac_path).length;
              const directEntraCount = filtered.filter(i => i.has_direct_entra_path).length;
              const pimCount         = filtered.filter(i => i.has_pim_eligible_path).length;
              return (
                <div className="flex items-center flex-wrap gap-x-3 gap-y-1 text-[11px] text-slate-400 px-1">
                  <span className="font-semibold uppercase tracking-wider text-slate-500">Access depth:</span>
                  <button
                    onClick={() => setSignalChip(s => s === 'direct_access' ? null : 'direct_access' as any)}
                    className={`px-2 py-0.5 rounded-md transition-colors ${signalChip === 'direct_access' ? 'bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-500/40' : 'hover:bg-slate-800/60 text-slate-300'}`}
                    title="Identities with direct RBAC, Entra role, or PIM eligibility — the real Azure-access count"
                  >
                    {directHumans.length} direct
                  </button>
                  <span className="text-slate-600">
                    ({directRbacCount} RBAC{directEntraCount > 0 ? ` · ${directEntraCount} Entra` : ''}{pimCount > 0 ? ` · ${pimCount} PIM` : ''})
                  </span>
                  <span className="text-slate-700">·</span>
                  <button
                    onClick={() => setSignalChip(s => s === 'group_inherited' ? null : 'group_inherited' as any)}
                    className={`px-2 py-0.5 rounded-md transition-colors ${signalChip === 'group_inherited' ? 'bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/40' : 'hover:bg-slate-800/60 text-slate-300'}`}
                    title="Passive members of role-bearing groups — included for coverage but typically lower-signal"
                  >
                    {groupOnlyHumans.length} via group
                  </button>
                  <span className="text-slate-600">·</span>
                  <span className="text-slate-500">{filtered.length} total</span>
                </div>
              );
            })()}
            <div className={`grid gap-2 ${tiles.length <= 5 ? 'grid-cols-5' : 'grid-cols-6'}`}>
              {tiles.map(tile => (
                <button key={tile.key}
                  onClick={() => setSignalChip(s => s === tile.key ? null : tile.key as any)}
                  className={`signal-chip rounded-lg px-3 py-2 text-left ${signalChip === tile.key ? 'ring-2 ring-white/30' : ''}`}>
                  <div className="text-[10px] font-semibold uppercase" style={{ opacity: 0.7 }}>{tile.label}</div>
                  <div className="text-lg font-bold" style={{ color: tile.color }}>{tile.count}</div>
                </button>
              ))}
            </div>
          </div>
        );
      })()}

      {/* Exposure Graph (V2 Phase 5) */}
      {viewMode === 'graph' && (
        <ExposureGraph
          identityIds={filtered.map(i => i.identity_id)}
          onNodeClick={(id) => setDrawerIdentityId(id)}
        />
      )}

      {/* Log-independent positioning chip — Humans tab only */}
      {tabScope === 'humans' && !logIndependentChipDismissed && viewMode === 'table' && (
        <div className="flex justify-end mb-1.5">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-xl text-[11px] text-gray-500 border border-gray-200/60 bg-transparent">
            <svg className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            MFA, Department, Job Title collected log-independently · no Entra P2
            <button onClick={() => setLogIndependentChipDismissed(true)} className="ml-1 text-gray-400 hover:text-gray-600">&times;</button>
          </span>
        </div>
      )}

      {/* AG-162: Active column filter chips */}
      <ActiveFilterChips
        columnFilters={columnFilters}
        fieldLabels={COLUMN_FIELD_LABELS}
        onRemove={removeColumnFilterValue}
        onClearAll={clearAllColumnFilters}
      />

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
                {tabScope === 'nhi' && <>
                  <FilterableColumnHeader
                    label="Secret Expiry" field="secret_expiry_status"
                    options={columnFilterOptions.secret_expiry_status}
                    currentSortField={sortField} currentSortDir={sortDir} onSort={f => handleSort(f as SortField)}
                    activeValues={columnFilters.secret_expiry_status || []}
                    onFilterApply={handleColumnFilter}
                  />
                  <th className="px-2 py-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500 whitespace-nowrap">Owner</th>
                  <th className="px-2 py-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500 whitespace-nowrap">Federated</th>
                </>}
                {tabScope === 'humans' && <>
                  <FilterableColumnHeader
                    label="MFA" field="mfa_status"
                    options={columnFilterOptions.mfa_status}
                    currentSortField={sortField} currentSortDir={sortDir} onSort={f => handleSort(f as SortField)}
                    activeValues={columnFilters.mfa_status || []}
                    onFilterApply={handleColumnFilter}
                    title="Collected from Microsoft Graph authentication methods — no Entra P2 required."
                    labelSuffix={<span className="text-gray-400 normal-case cursor-help ml-0.5">&#9432;</span>}
                  />
                  <th className="px-2 py-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500 whitespace-nowrap">Department</th>
                  <th className="px-2 py-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500 whitespace-nowrap">Job Title</th>
                </>}
                <FilterableColumnHeader
                  label="Cloud" field="cloud"
                  options={columnFilterOptions.cloud}
                  currentSortField={sortField} currentSortDir={sortDir} onSort={f => handleSort(f as SortField)}
                  activeValues={columnFilters.cloud || []}
                  onFilterApply={handleColumnFilter}
                />
                <FilterableColumnHeader
                  label="Status" field="status"
                  options={columnFilterOptions.status}
                  currentSortField={sortField} currentSortDir={sortDir} onSort={f => handleSort(f as SortField)}
                  activeValues={columnFilters.status || []}
                  onFilterApply={handleColumnFilter}
                />
                <FilterableColumnHeader
                  label="Lifecycle" field="lifecycle_state"
                  options={columnFilterOptions.lifecycle_state}
                  currentSortField={sortField} currentSortDir={sortDir} onSort={f => handleSort(f as SortField)}
                  activeValues={columnFilters.lifecycle_state || []}
                  onFilterApply={handleColumnFilter}
                  labelSuffix={<span className="text-gray-400 normal-case ml-0.5" title="Disabled > Dormant > Active > Provisioned — derived from enabled status and activity">&#9432;</span>}
                />
                <FilterableColumnHeader
                  label="Governance" field="governance_state"
                  options={columnFilterOptions.governance_state}
                  currentSortField={sortField} currentSortDir={sortDir} onSort={f => handleSort(f as SortField)}
                  activeValues={columnFilters.governance_state || []}
                  onFilterApply={handleColumnFilter}
                  labelSuffix={<span className="text-gray-400 normal-case ml-0.5" title="Orphaned > Ungoverned > Governed — derived from owner status and recommended action">&#9432;</span>}
                />
                <FilterableColumnHeader
                  label="Risk" field="risk_level"
                  options={columnFilterOptions.risk_level}
                  currentSortField={sortField} currentSortDir={sortDir} onSort={f => handleSort(f as SortField)}
                  activeValues={columnFilters.risk_level || []}
                  onFilterApply={handleColumnFilter}
                />
                <FilterableColumnHeader
                  label="Privilege" field="privilege_level"
                  options={columnFilterOptions.privilege_level}
                  sortable={false}
                  currentSortField={sortField} currentSortDir={sortDir} onSort={f => handleSort(f as SortField)}
                  activeValues={columnFilters.privilege_level || []}
                  onFilterApply={handleColumnFilter}
                  title="Highly Privileged (T0) > Privileged (T1) > Standard (T2/T3) — derived from privilege tier"
                />
                <SortHeader label="Effective Access" field="privilege_tier" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Last Seen" field="last_activity_date" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <th className="px-2 py-2.5 text-xs whitespace-nowrap">Lineage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={colSpan} className="px-3 py-6 text-center text-gray-500">Loading…</td></tr>
              ) : error ? (
                <tr><td colSpan={colSpan} className="px-3 py-6 text-center text-red-600">{error}</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={colSpan}><EmptyState compact title="No identities match filters." /></td></tr>
              ) : filtered.map(i => {
                const isComboRisk = (i.governance_state === 'Ungoverned' || i.governance_state === 'Orphaned' || i.governance_state === 'Policy Violation')
                  && (i.privilege_level === 'Privileged' || i.privilege_level === 'Highly Privileged');
                return (
                  <tr key={i.identity_id}
                    className={`cursor-pointer transition-colors ${isComboRisk ? 'row-tint-danger' : 'hover:bg-blue-50'} ${selectedIds.has(i.identity_id) ? 'bg-blue-50' : ''} ${drawerIdentityId === i.identity_id ? 'bg-blue-100' : ''}`}
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

                    {/* NHI-specific columns (AG-159) */}
                    {tabScope === 'nhi' && <>
                      <td className="px-2 py-2 whitespace-nowrap">
                        {i.secret_expiry_status === 'expired' ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-700">Expired</span>
                        ) : i.secret_expiry_status === 'expiring_soon' ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-100 text-amber-700">{'< 30d'}</span>
                        ) : i.secret_expiry_status === 'expiring_90d' ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold bg-yellow-50 text-yellow-700">{'< 90d'}</span>
                        ) : i.secret_expiry_status === 'valid' ? (
                          <span className="text-[10px] text-green-600">Valid</span>
                        ) : (
                          <span className="text-[10px] text-gray-400">—</span>
                        )}
                      </td>
                      <td className="px-2 py-2 max-w-[150px]">
                        <span className="text-[11px] text-gray-700 truncate block" title={i.owner_resolved || i.owner_display_name || ''}>
                          {i.owner_resolved || i.owner_display_name || <span className="text-gray-400">No owner</span>}
                        </span>
                      </td>
                      <td className="px-2 py-2 whitespace-nowrap">
                        {(i.federated_cred_count ?? 0) > 0 ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-100 text-purple-700">
                            {i.federated_cred_count} FIC
                          </span>
                        ) : (
                          <span className="text-[10px] text-gray-400">—</span>
                        )}
                      </td>
                    </>}

                    {/* Humans-specific columns (AG-160 / AG-161 four-state MFA) */}
                    {tabScope === 'humans' && <>
                      <td className="px-2 py-2 whitespace-nowrap">
                        {i.mfa_status === 'enrolled' || (i.mfa_status === 'registered' && i.ca_mfa_enforced) ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold bg-green-100 text-green-700" title="MFA enrolled">MFA ✓</span>
                        ) : i.mfa_status === 'not_enrolled' ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-700" title="Verified: no MFA methods registered">No MFA</span>
                        ) : i.mfa_status === 'conditional' ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-100 text-amber-700" title="CA policy enforces MFA">Conditional</span>
                        ) : (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold bg-gray-100 text-gray-500" title="MFA status not yet collected">Unknown</span>
                        )}
                      </td>
                      <td className="px-2 py-2 max-w-[120px]">
                        <span className="text-[11px] text-gray-700 truncate block" title={i.department || ''}>
                          {i.department || <span className="text-gray-400">—</span>}
                        </span>
                      </td>
                      <td className="px-2 py-2 max-w-[120px]">
                        <span className="text-[11px] text-gray-700 truncate block" title={i.job_title || ''}>
                          {i.job_title || <span className="text-gray-400">—</span>}
                        </span>
                      </td>
                    </>}

                    {/* Cloud */}
                    <td className="px-2 py-2"><CloudBadge cloud={i.cloud} /></td>

                    {/* Status */}
                    <td className="px-2 py-2">
                      <StatusBadge status={i.status} />
                    </td>

                    {/* Lifecycle State */}
                    <td className="px-2 py-2 whitespace-nowrap">
                      <LifecycleLabel state={i.lifecycle_state} />
                    </td>

                    {/* Governance State */}
                    <td className="px-2 py-2 whitespace-nowrap">
                      <GovernanceBadge state={i.governance_state} />
                    </td>

                    {/* Risk Level */}
                    <td className="px-2 py-2">
                      {(i.risk_level === 'low' || i.risk_level === 'info' || !i.risk_level) ? (
                        <span className="text-[11px] uppercase" style={{ color: 'var(--text-tertiary, #9ca3af)' }}>{i.risk_level || 'info'}</span>
                      ) : (
                        <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[i.risk_level] || RISK_BADGE.info}`}>
                          {i.risk_level}
                        </span>
                      )}
                    </td>

                    {/* Privilege Level */}
                    <td className="px-2 py-2 whitespace-nowrap">
                      <PrivilegeLevelBadge level={i.privilege_level} />
                    </td>

                    {/* Effective Access Level (Privilege Tier) */}
                    <td className="px-2 py-2">
                      <PrivilegedBadge level={i.privileged_level} />
                    </td>

                    {/* Last Seen */}
                    <td
                      className="col-last-seen px-2 py-2 whitespace-nowrap"
                      title={[
                        i.last_activity_date
                          ? new Date(i.last_activity_date).toLocaleString('en-US', {
                              month: 'short', day: 'numeric', year: 'numeric',
                              hour: '2-digit', minute: '2-digit',
                            })
                          : null,
                        i.last_activity_source
                          ? `Source: ${SOURCE_LABELS[i.last_activity_source] ?? i.last_activity_source}`
                          : null,
                      ].filter(Boolean).join(' \u00b7 ')}
                    >
                      <span className={`last-seen-${lastSeenColor(i.last_activity_date)}`}>
                        {formatRelativeDate(i.last_activity_date)}
                      </span>
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

                        // P2.5: AG-148 — has_federated_credentials but no federated_workload_type
                        if (i.has_federated_credentials && !i.federated_workload_type) {
                          const issuerTypes = i.federated_issuer_types || [];
                          const label = Array.isArray(issuerTypes) && issuerTypes.length > 0
                            ? issuerTypes[0].replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase())
                            : 'External OIDC';
                          return lineageBtn(
                            <span className="text-[10px] text-purple-700 font-semibold truncate group-hover:text-purple-800">{label}</span>,
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
                );
              })}
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
