import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useToast } from '../components/ToastProvider';
import { useAuth } from '../contexts/AuthContext';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { downloadCSV, downloadJSON, exportFilename, IDENTITY_CSV_COLUMNS } from '../utils/exportUtils';
import {
  type IdentityCategory, type RiskLevel, type DormantStatus,
  CATEGORY_FILTER_OPTIONS, RISK_FILTER_OPTIONS, RISK_ORDER, RISK_BADGE, RISK_SOLID, CLOUD_BADGE,
  THRESHOLDS, DORMANT_LABELS, DATA_EXPLANATIONS,
  safeLower, normalizeCategoryFromBackend, getCategoryLabel, getCategoryShortLabel, getDormantStatus as getDormantStatusFromActivity,
} from '../constants/metrics';

type IdentityStatus = 'active' | 'disabled' | 'deleted';

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
}

interface SavedView {
  id: number;
  name: string;
  description: string | null;
  filters: Record<string, string>;
  sort_field: string | null;
  sort_direction: string | null;
  is_default: boolean;
  is_shared: boolean;
  user_id: number;
  creator_name?: string;
}

type SortField =
  | 'display_name'
  | 'identity_type'
  | 'identity_category'
  | 'cloud'
  | 'risk_level'
  | 'entra_role_count'
  | 'rbac_role_count'
  | 'api_permission_count'
  | 'privilege_tier'
  | 'credential_expiration'
  | 'created_datetime'
  | 'last_seen_auth'
  | 'dormant';

// ─── Helpers ───────────────────────────────────────────────────────

function formatDate(d?: string | null): string {
  if (!d) return '—';
  try { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }); }
  catch { return d; }
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

function CategoryBadge({ category }: { category?: IdentityCategory }) {
  const color = CATEGORY_BADGE_COLORS[category || ''] || 'bg-gray-50 text-gray-600';
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${color}`}>{getCategoryShortLabel(category)}</span>;
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
  const [identities, setIdentities] = useState<IdentityRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [categoryFilter, setCategoryFilter] = useState<IdentityCategory | 'all'>('all');
  const [ownerFilter, setOwnerFilter] = useState<'all' | 'unowned'>('all');
  const [activityFilter, setActivityFilter] = useState<'all' | 'dormant'>('all');
  const [tierFilter, setTierFilter] = useState<number[] | 'all'>('all');
  const [credentialFilter, setCredentialFilter] = useState<'all' | 'expired' | 'expiring_soon' | 'valid' | 'none'>('all');
  const [caFilter, setCaFilter] = useState<'all' | 'covered' | 'not_covered'>('all');
  const [sortField, setSortField] = useState<SortField>('risk_level');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkMenuOpen, setBulkMenuOpen] = useState(false);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkConfirm, setBulkConfirm] = useState<{ status: string; label: string } | null>(null);
  const bulkMenuRef = useRef<HTMLDivElement>(null);

  // Saved Views state (Phase 34)
  const [savedViews, setSavedViews] = useState<SavedView[]>([]);
  const [activeViewId, setActiveViewId] = useState<number | null>(null);
  const [saveModalOpen, setSaveModalOpen] = useState(false);
  const [editingView, setEditingView] = useState<SavedView | null>(null);
  const [viewForm, setViewForm] = useState({ name: '', description: '', is_shared: false });
  const [viewSaving, setViewSaving] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<number | null>(null);

  const { addToast } = useToast();
  const { user, isAdmin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // URL param sync
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const catParam = params.get('identity_category') || params.get('category');
    const riskParam = params.get('risk_level');
    const ownerParam = params.get('owner_status');
    const activityParam = params.get('activity_status');
    const tierParam = params.get('privilege_tier');
    const credParam = params.get('credential_status') || params.get('credential_expiry');
    const caParam = params.get('ca_coverage');
    setCategoryFilter(catParam && CATEGORY_FILTER_OPTIONS.find(o => o.value === catParam) ? catParam as IdentityCategory : 'all');
    setRiskFilter(riskParam && RISK_FILTER_OPTIONS.find(o => o.value === riskParam) ? riskParam as RiskLevel : 'all');
    setOwnerFilter(ownerParam === 'unowned' ? 'unowned' : 'all');
    setActivityFilter(activityParam === 'dormant' ? 'dormant' : 'all');
    if (tierParam != null) {
      const tiers = tierParam.split(',').map(Number).filter(t => [0, 1, 2, 3].includes(t));
      setTierFilter(tiers.length > 0 ? tiers : 'all');
    } else {
      setTierFilter('all');
    }
    setCredentialFilter(credParam && ['expired', 'expiring_soon', 'valid', 'none'].includes(credParam) ? credParam as any : 'all');
    setCaFilter(caParam === 'covered' ? 'covered' : caParam === 'not_covered' ? 'not_covered' : 'all');
  }, [location.search]);

  // Fetch
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const resp = await fetch('http://localhost:5001/api/identities');
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
  }, []);

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

  // Auto-apply default view on mount (only if no URL params)
  useEffect(() => {
    if (savedViews.length === 0 || location.search) return;
    const defaultView = savedViews.find(v => v.is_default && v.user_id === user?.id);
    if (defaultView) applyView(defaultView);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [savedViews.length]);

  function getCurrentFilters(): Record<string, string> {
    const f: Record<string, string> = {};
    if (search) f.search = search;
    if (riskFilter !== 'all') f.risk_level = riskFilter;
    if (categoryFilter !== 'all') f.category = categoryFilter;
    if (ownerFilter !== 'all') f.owner_status = ownerFilter;
    if (activityFilter !== 'all') f.activity_status = activityFilter;
    if (tierFilter !== 'all') f.privilege_tier = tierFilter.join(',');
    if (credentialFilter !== 'all') f.credential_status = credentialFilter;
    if (caFilter !== 'all') f.ca_coverage = caFilter;
    return f;
  }

  function applyView(view: SavedView) {
    const f = view.filters || {};
    setSearch(f.search || '');
    setRiskFilter((f.risk_level as RiskLevel) || 'all');
    setCategoryFilter((f.category as IdentityCategory) || 'all');
    setOwnerFilter(f.owner_status === 'unowned' ? 'unowned' : 'all');
    setActivityFilter(f.activity_status === 'dormant' ? 'dormant' : 'all');
    if (f.privilege_tier) {
      const tiers = f.privilege_tier.split(',').map(Number).filter(t => [0, 1, 2, 3].includes(t));
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
    let result = [...identities];
    const s = safeLower(search);
    if (s) result = result.filter(i => safeLower(i.display_name).includes(s) || safeLower(i.identity_id).includes(s) || safeLower(i.owner_display_name).includes(s));
    if (riskFilter !== 'all') result = result.filter(i => safeLower(i.risk_level) === safeLower(riskFilter));
    if (categoryFilter !== 'all') result = result.filter(i => i.identity_category === categoryFilter);
    if (ownerFilter === 'unowned') result = result.filter(i => !i.owner_display_name && (i.owner_count ?? 0) === 0);
    if (activityFilter === 'dormant') result = result.filter(i => { const d = getDormantStatus(i); return d === 'yes' || d === 'idle' || d === 'never'; });
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
  }, [identities, search, riskFilter, categoryFilter, ownerFilter, activityFilter, tierFilter, credentialFilter, caFilter, sortField, sortDir]);

  function handleSort(field: SortField) {
    if (field === sortField) setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
    else {
      setSortField(field);
      setSortDir(['risk_level', 'entra_role_count', 'rbac_role_count', 'api_permission_count', 'privilege_tier', 'dormant'].includes(field) ? 'desc' : 'asc');
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
    const headers = ['Display Name','Identity ID','Type','Category','Cloud','Risk','Score','Tier','Entra Roles','RBAC Roles','Graph Perms','Secret/Expiry','Created','Last Used','Dormant','Compliance','Owner'];
    const rows = selectedIdentities.map(i => [
      i.display_name, i.identity_id, i.identity_type || '', getCategoryLabel(i.identity_category),
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
    downloadCSV(data as Record<string, unknown>[], IDENTITY_CSV_COLUMNS, exportFilename('identities', 'csv'));
    addToast(`Exported ${data.length} identities as CSV`, 'success');
  }

  function exportAllJSON() {
    downloadJSON(filtered, exportFilename('identities', 'json'));
    addToast(`Exported ${filtered.length} identities as JSON`, 'success');
  }

  const colSpan = 14; // checkbox + 13 data cols

  return (
    <div className="max-w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-4">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">All Identities</h2>
          <p className="text-sm text-gray-500">Full identity inventory — click any row for deep-dive</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-gray-600">
            {loading ? 'Loading…' : `${filtered.length} of ${identities.length}`}
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
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-sm mx-4 p-5">
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
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md mx-4 p-6">
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

      {/* Filters */}
      <div className="bg-white border rounded-xl p-3 mb-3 shadow-sm">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
          <input value={search} onChange={e => { setSearch(e.target.value); clearActiveView(); }} placeholder="Search name, ID, owner…"
            className="border rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500" />
          <select value={riskFilter} onChange={e => { setRiskFilter(e.target.value as any); clearActiveView(); }} className="border rounded-lg px-3 py-1.5 text-sm">
            {RISK_FILTER_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <select value={categoryFilter} onChange={e => { setCategoryFilter(e.target.value as any); clearActiveView(); }} className="border rounded-lg px-3 py-1.5 text-sm">
            {CATEGORY_FILTER_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <button onClick={() => { setSearch(''); setRiskFilter('all'); setCategoryFilter('all'); setOwnerFilter('all'); setActivityFilter('all'); setTierFilter('all'); setCredentialFilter('all'); setCaFilter('all'); setActiveViewId(null); navigate('/identities', { replace: true }); }}
            className="px-3 py-1.5 text-sm text-blue-600 border border-blue-200 rounded-lg hover:bg-blue-50">
            Clear
          </button>
        </div>
        {/* Active filter chips from recommendations */}
        {(ownerFilter !== 'all' || activityFilter !== 'all' || tierFilter !== 'all' || credentialFilter !== 'all' || caFilter !== 'all') && (
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <span className="text-[10px] text-gray-500 uppercase font-semibold">Active filters:</span>
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
          </div>
        )}
      </div>

      {/* Table */}
      <div className="bg-white border rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full text-[12px]">
            <thead className="bg-gray-50 border-b text-left font-semibold text-gray-600 uppercase tracking-wider">
              <tr>
                <th className="px-2 py-2.5 w-8">
                  <input type="checkbox" checked={filtered.length > 0 && selectedIds.size === filtered.length} onChange={selectAll}
                    className="w-3.5 h-3.5 text-blue-600 rounded cursor-pointer" />
                </th>
                <SortHeader label="Identity Name" field="display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Type" field="identity_type" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Category" field="identity_category" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Cloud" field="cloud" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Risk" field="risk_level" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Entra" field="entra_role_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="RBAC" field="rbac_role_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Graph API" field="api_permission_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Tier" field="privilege_tier" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Secret/Expiry" field="credential_expiration" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Created" field="created_datetime" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Last Used" field="last_seen_auth" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Activity" field="dormant" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={colSpan} className="px-4 py-8 text-center text-gray-500">Loading…</td></tr>
              ) : error ? (
                <tr><td colSpan={colSpan} className="px-4 py-8 text-center text-red-600">{error}</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={colSpan} className="px-4 py-8 text-center text-gray-500">No identities match filters.</td></tr>
              ) : filtered.map(i => {
                const tier = getPrivilegeTier(i);
                const dormant = getDormantStatus(i);
                return (
                  <tr key={i.identity_id}
                    className={`hover:bg-blue-50 cursor-pointer transition-colors ${selectedIds.has(i.identity_id) ? 'bg-blue-50' : ''}`}
                    onClick={() => navigate(`/identities/${encodeURIComponent(i.identity_id)}`)}
                  >
                    {/* Checkbox */}
                    <td className="px-2 py-2" onClick={e => e.stopPropagation()}>
                      <input type="checkbox" checked={selectedIds.has(i.identity_id)} onChange={() => toggleSelect(i.identity_id)}
                        className="w-3.5 h-3.5 text-blue-600 rounded cursor-pointer" />
                    </td>

                    {/* Name */}
                    <td className="px-2 py-2 max-w-[180px]">
                      <div className="font-medium text-gray-900 truncate" title={i.display_name}>{i.display_name}</div>
                      <div className="text-[10px] text-gray-400 font-mono">{i.identity_id.substring(0, 8)}…</div>
                    </td>

                    {/* Type */}
                    <td className="px-2 py-2"><TypeLabel type={i.identity_type} /></td>

                    {/* Category */}
                    <td className="px-2 py-2"><CategoryBadge category={i.identity_category} /></td>

                    {/* Cloud */}
                    <td className="px-2 py-2"><CloudBadge cloud={i.cloud} /></td>

                    {/* Risk */}
                    <td className="px-2 py-2">
                      <div className="flex items-center gap-1">
                        <RiskBadge level={i.risk_level} score={i.risk_score} />
                        <span title={
                          i.ca_coverage_status
                            ? `CA: ${i.ca_coverage_status}${i.ca_mfa_enforced ? ' + MFA' : ''}`
                            : DATA_EXPLANATIONS.CA_POLICY
                        }>
                          <svg className={`w-3.5 h-3.5 ${
                            !i.ca_coverage_status ? 'text-gray-300' :
                            i.ca_coverage_status === 'covered' && i.ca_mfa_enforced ? 'text-green-500' :
                            i.ca_coverage_status === 'covered' ? 'text-yellow-500' :
                            'text-red-400'
                          }`} fill="currentColor" viewBox="0 0 24 24">
                            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
                          </svg>
                        </span>
                      </div>
                    </td>

                    {/* Entra Roles */}
                    <td className="px-2 py-2 text-center">
                      {(i.entra_role_count ?? 0) > 0 ? (
                        <div className="flex items-center justify-center gap-1">
                          <RiskDot level={i.entra_max_risk} />
                          <span className="font-semibold text-indigo-700">{i.entra_role_count}</span>
                          {(i.pim_eligible_count ?? 0) > 0 && (
                            <span className="px-1 py-0.5 rounded text-[8px] font-bold bg-emerald-100 text-emerald-700" title={`${i.pim_eligible_count} PIM eligible role(s)`}>PIM</span>
                          )}
                        </div>
                      ) : (
                        <div className="flex items-center justify-center gap-1">
                          <span className="text-gray-300">0</span>
                          {(i.pim_eligible_count ?? 0) > 0 && (
                            <span className="px-1 py-0.5 rounded text-[8px] font-bold bg-emerald-100 text-emerald-700" title={`${i.pim_eligible_count} PIM eligible role(s)`}>PIM</span>
                          )}
                        </div>
                      )}
                    </td>

                    {/* RBAC Roles */}
                    <td className="px-2 py-2 text-center">
                      {(i.rbac_role_count ?? 0) > 0 ? (
                        <div className="flex items-center justify-center gap-1">
                          <RiskDot level={i.rbac_max_risk} />
                          <span className="font-semibold text-blue-700">{i.rbac_role_count}</span>
                        </div>
                      ) : <span className="text-gray-300">0</span>}
                    </td>

                    {/* Graph API */}
                    <td className="px-2 py-2 text-center">
                      {(i.api_permission_count ?? 0) > 0 ? (
                        <div className="flex items-center justify-center gap-1">
                          <RiskDot level={i.graph_max_risk} />
                          <span className="font-semibold text-purple-700">{i.api_permission_count}</span>
                        </div>
                      ) : <span className="text-gray-300">0</span>}
                    </td>

                    {/* Privilege Tier */}
                    <td className="px-2 py-2 text-center"><TierBadge tier={tier} /></td>

                    {/* Secret/Expiry */}
                    <td className="px-2 py-2">
                      {i.identity_category === 'human_user' || i.identity_category === 'guest' ? (
                        <span className="text-[10px] text-gray-300" title={DATA_EXPLANATIONS.CREDENTIAL_NA}>N/A</span>
                      ) : (i.credential_count ?? 0) > 0 ? (
                        <div>
                          <span className="text-gray-600">{i.credential_count}</span>
                          {(() => {
                            const cd = credentialCountdownText(i.credential_expiration);
                            return cd ? <div className={`text-[10px] font-medium ${cd.color}`}>{cd.text}</div> : null;
                          })()}
                        </div>
                      ) : (
                        <span className="text-[10px] text-gray-400" title="No secrets or certificates registered">0</span>
                      )}
                    </td>

                    {/* Created */}
                    <td className="px-2 py-2 text-gray-600 whitespace-nowrap">{formatDate(i.created_datetime)}</td>

                    {/* Last Used */}
                    <td className="px-2 py-2 whitespace-nowrap">
                      {i.last_seen_auth ? (
                        <span className="text-gray-600">{formatDate(i.last_seen_auth)}</span>
                      ) : (
                        <span className="text-[10px] text-gray-400 italic" title={DATA_EXPLANATIONS.SIGN_IN}>
                          Unknown<span className="text-gray-300 ml-0.5">(P1/P2)</span>
                        </span>
                      )}
                    </td>

                    {/* Dormant */}
                    <td className="px-2 py-2 text-center"><DormantBadge status={dormant} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="mt-3 text-[11px] text-gray-400 text-center">
        T0 = Control Plane (Global Admin, Priv Role Admin, tenant Owner) |
        T1 = Management Plane (User/Exchange/Intune Admin, sub Owner/Contributor) |
        T2 = Data/App (scoped roles, risky perms) |
        T3 = Standard.
        Activity: Stale 90d+ = no sign-in 90+ days | Never Used = created &gt;30d, no sign-in | Idle 30-90d | New = created &lt;30d.
      </div>

      {/* Bulk Action Confirmation Modal */}
      {bulkConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md mx-4 p-6">
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
    </div>
  );
}
