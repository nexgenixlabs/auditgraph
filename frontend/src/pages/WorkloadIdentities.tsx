import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { WORKLOAD_TYPE_CONFIG, LIFECYCLE_STATE_CONFIG, OWNER_STATUS_CONFIG, SCOPE_FLAG_CONFIG } from '../constants/metrics';
import { verdictBadgeClasses, verdictLabel } from '../constants/verdicts';

// ── Types ────────────────────────────────────────────────────────────

interface WorkloadRow {
  id: number;
  workload_id: string;
  identity_id: string;
  display_name: string;
  identity_type: string;
  identity_category: string;
  source_table: string;
  risk_level: string;
  risk_score: number;
  activity_status: string;
  exposure_score: number;
  privilege_score: number;
  credential_risk_score: number;
  exposure_subscore: number;
  lifecycle_score: number;
  visibility_score: number;
  lifecycle_state: string;
  can_escalate: boolean;
  owner_status: string;
  owner_display_name?: string | null;
  owner_count?: number;
  effective_scope_flag: string;
  cross_subscription: boolean;
  credential_age_days: number;
  created_datetime: string;
  last_sign_in?: string | null;
  sign_ins_30d?: number | null;
  anomaly_count?: number;
  next_expiry?: string | null;
  credential_count?: number;
  has_expired_credentials?: boolean;
  recommended_action?: string | null;
  verdict_confidence?: string | null;
  workload_type?: string | null;
}

interface WorkloadStats {
  total: number;
  by_type: { spn: number; managed_identity: number; app_registration: number };
  exposure_critical: number;
  can_escalate_count: number;
  orphaned_count: number;
  ungoverned_count: number;
  blind_count: number;
  stale_credentials: number;
  zombie_count: number;
  by_risk: Record<string, number>;
  avg_exposure_score: number;
  top_findings: Array<{
    finding_type: string;
    severity: string;
    title: string;
    score_impact: number;
    display_name: string;
    source_type: string;
  }>;
  p2_enabled?: boolean;
  telemetry?: {
    total_sign_ins_30d: number;
    active_identities: number;
    dormant_confirmed: number;
    risky_sign_ins: number;
    ca_failures: number;
    anomaly_count: number;
    unresolved_anomalies: number;
  };
}

// ── Helpers ──────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-600',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-400',
};

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
  high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300',
  low: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
};

function formatDate(d?: string | null): string {
  if (!d) return '—';
  try { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }); }
  catch { return d; }
}

function formatDateTime(d?: string | null): string {
  if (!d) return '—';
  try { return new Date(d).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }); }
  catch { return d; }
}

function formatSecretExpiry(expiryDate?: string | null, hasExpired?: boolean, credCount?: number): { label: string; colorClass: string } {
  if (hasExpired) return { label: 'Expired', colorClass: 'text-red-500 dark:text-red-400 font-semibold' };
  if (!expiryDate) {
    if (!credCount) return { label: 'No secrets', colorClass: 'text-gray-400 dark:text-slate-500' };
    return { label: 'No expiry', colorClass: 'text-gray-400 dark:text-slate-500' };
  }
  const daysUntil = Math.round((new Date(expiryDate).getTime() - Date.now()) / 86400000);
  if (daysUntil < 0) return { label: `Expired ${Math.abs(daysUntil)}d ago`, colorClass: 'text-red-500 dark:text-red-400 font-semibold' };
  if (daysUntil <= 30) return { label: `${daysUntil}d left`, colorClass: 'text-red-500 dark:text-red-400' };
  if (daysUntil <= 90) return { label: `${daysUntil}d left`, colorClass: 'text-yellow-500 dark:text-yellow-400' };
  return { label: formatDate(expiryDate), colorClass: 'text-green-500 dark:text-green-400' };
}

function formatLastActive(d?: string | null, createdAt?: string | null): { label: string; colorClass: string; tooltip?: string } {
  if (!d) {
    // No sign-in data — provide meaningful context from creation date
    if (createdAt) {
      const ageDays = Math.round((Date.now() - new Date(createdAt).getTime()) / 86400000);
      if (ageDays <= 30) {
        return { label: 'Recently created', colorClass: 'text-gray-400 dark:text-slate-500 italic', tooltip: `Created ${ageDays}d ago. No sign-in data yet.` };
      }
      return { label: 'No activity recorded', colorClass: 'text-gray-400 dark:text-slate-500 italic', tooltip: `Account is ${formatCreatedAge(createdAt)} old. Sign-in logs unavailable — enable P2 license to collect SPN activity.` };
    }
    return { label: 'No activity', colorClass: 'text-gray-400 dark:text-slate-500 italic' };
  }
  const daysAgo = Math.round((Date.now() - new Date(d).getTime()) / 86400000);
  if (daysAgo < 0) return { label: 'Today', colorClass: 'text-green-500 dark:text-green-400' };
  if (daysAgo === 0) return { label: 'Today', colorClass: 'text-green-500 dark:text-green-400' };
  if (daysAgo <= 7) return { label: `${daysAgo}d ago`, colorClass: 'text-green-500 dark:text-green-400' };
  if (daysAgo <= 30) return { label: `${daysAgo}d ago`, colorClass: 'text-green-500 dark:text-green-400' };
  if (daysAgo <= 90) return { label: `${daysAgo}d ago`, colorClass: 'text-yellow-500 dark:text-yellow-400' };
  return { label: `${daysAgo}d ago`, colorClass: 'text-red-500 dark:text-red-400' };
}

function formatCreatedAge(d?: string | null): string {
  if (!d) return '—';
  const days = Math.round((Date.now() - new Date(d).getTime()) / 86400000);
  if (days < 30) return `${days}d`;
  if (days < 365) return `${Math.floor(days / 30)}mo`;
  const yrs = Math.floor(days / 365);
  const mos = Math.floor((days % 365) / 30);
  return mos > 0 ? `${yrs}y ${mos}mo` : `${yrs}y`;
}

function exposureColor(score: number): string {
  if (score >= 80) return 'text-red-600 dark:text-red-400';
  if (score >= 60) return 'text-orange-500 dark:text-orange-400';
  if (score >= 35) return 'text-yellow-500 dark:text-yellow-400';
  return 'text-green-500 dark:text-green-400';
}

function exposureRingColor(score: number): string {
  if (score >= 80) return '#dc2626';
  if (score >= 60) return '#f97316';
  if (score >= 35) return '#eab308';
  return '#22c55e';
}

function ExposureRing({ score, size = 36 }: { score: number; size?: number }) {
  const r = (size - 4) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.min(score, 100) / 100;
  return (
    <svg width={size} height={size} className="transform -rotate-90">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={3} className="text-gray-200 dark:text-slate-700" />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={exposureRingColor(score)} strokeWidth={3}
        strokeDasharray={`${c * pct} ${c * (1 - pct)}`} strokeLinecap="round" />
      <text x={size / 2} y={size / 2} textAnchor="middle" dominantBaseline="central"
        className="text-[10px] font-bold fill-current" transform={`rotate(90 ${size / 2} ${size / 2})`}
        style={{ fill: exposureRingColor(score) }}>{score}</text>
    </svg>
  );
}

// ── Page Component ───────────────────────────────────────────────────

const WorkloadIdentities: React.FC = () => {
  const { withConnection, selectedConnectionId } = useConnection();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const activeType = searchParams.get('type') || 'all';
  const [stats, setStats] = useState<WorkloadStats | null>(null);
  const [items, setItems] = useState<WorkloadRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  const [sortCol, setSortCol] = useState('display_name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [debouncedSearch, setDebouncedSearch] = useState(search);
  const searchTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => {
    searchTimerRef.current = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(searchTimerRef.current);
  }, [search]);
  const [exposureLevel, setExposureLevel] = useState(searchParams.get('exposure') || '');
  const [lifecycleFilter, setLifecycleFilter] = useState(searchParams.get('lifecycle') || '');
  const [ownerFilter, setOwnerFilter] = useState(searchParams.get('owner') || '');
  const [canEscalate, setCanEscalate] = useState(searchParams.get('escalate') === 'true');
  const [scopeFilter, setScopeFilter] = useState(searchParams.get('scope') || '');
  const [crossSub, setCrossSub] = useState(searchParams.get('cross_subscription') === 'true');
  const [riskLevel, setRiskLevel] = useState(searchParams.get('risk_level') || '');
  const [credentialFilter, setCredentialFilter] = useState(searchParams.get('credential_filter') || '');
  const [hideMicrosoft, setHideMicrosoft] = useState(true);
  const [offset, setOffset] = useState(0);
  const limit = 50;

  // Sync URL params
  const updateParams = useCallback((key: string, value: string) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      if (value) next.set(key, value);
      else next.delete(key);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const setType = (t: string) => {
    updateParams('type', t === 'all' ? '' : t);
    setOffset(0);
  };

  // Fetch stats
  useEffect(() => {
    fetch(withConnection('/api/workload-identities/stats'))
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setStats(d))
      .catch(() => {});
  }, [selectedConnectionId]);

  // Fetch list
  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (activeType !== 'all') params.set('type', activeType);
    if (exposureLevel) params.set('exposure_level', exposureLevel);
    if (lifecycleFilter) params.set('lifecycle_state', lifecycleFilter);
    if (ownerFilter) params.set('owner_status', ownerFilter);
    if (canEscalate) params.set('can_escalate', 'true');
    if (scopeFilter) params.set('scope', scopeFilter);
    if (crossSub) params.set('cross_subscription', 'true');
    if (riskLevel) params.set('risk_level', riskLevel);
    if (credentialFilter) params.set('credential_filter', credentialFilter);
    if (debouncedSearch) params.set('search', debouncedSearch);
    params.set('sort', sortCol);
    params.set('dir', sortDir);
    params.set('limit', String(limit));
    params.set('offset', String(offset));
    params.set('hide_microsoft', String(hideMicrosoft));

    fetch(withConnection(`/api/workload-identities?${params}`))
      .then(r => r.ok ? r.json() : { items: [], total: 0 })
      .then(d => { setItems(d.items || []); setTotal(d.total || 0); })
      .catch(() => { setItems([]); setTotal(0); })
      .finally(() => setLoading(false));
  }, [activeType, exposureLevel, lifecycleFilter, ownerFilter, canEscalate, scopeFilter, crossSub, riskLevel, credentialFilter, debouncedSearch, sortCol, sortDir, offset, hideMicrosoft, selectedConnectionId]);

  const openDetail = (row: WorkloadRow) => {
    // Normalize type: backend detail handler expects 'app_reg', not 'app_registration'
    const typeParam = row.identity_type === 'app_registration' ? 'app_reg' : row.identity_type;
    navigate(`/workload-identities/${row.workload_id}?type=${typeParam}`);
  };

  const handleSort = (col: string) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
    setOffset(0);
  };

  const SortIcon = ({ col }: { col: string }) => (
    <span className="ml-1 text-gray-400">{sortCol === col ? (sortDir === 'asc' ? '↑' : '↓') : '↕'}</span>
  );

  const typePills = [
    { key: 'all', label: 'All' },
    { key: 'spn', label: 'SPNs' },
    { key: 'app_reg', label: 'App Regs' },
    { key: 'managed_identity', label: 'Managed IDs' },
  ];

  const TypeBadge = ({ type }: { type: string }) => {
    const cfg = WORKLOAD_TYPE_CONFIG[type] || WORKLOAD_TYPE_CONFIG.spn;
    return <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold ${cfg.badgeClass}`}>{cfg.shortLabel}</span>;
  };

  const FilterChip = ({ label, onRemove }: { label: string; onRemove: () => void }) => (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800/40 text-[10px] text-blue-700 dark:text-blue-300 font-medium">
      {label}
      <button onClick={onRemove} className="ml-0.5 hover:text-blue-900 dark:hover:text-white">&times;</button>
    </span>
  );

  // ── Render ───────────────────────────────────────────────────────

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Non-Human Identity Inventory</h1>
          <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">
            Service principals, app registrations, and managed identities — audit-ready view
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-slate-400 cursor-pointer">
            <input type="checkbox" checked={hideMicrosoft} onChange={e => setHideMicrosoft(e.target.checked)}
              className="rounded border-gray-300 text-blue-600" />
            Hide Microsoft
          </label>
        </div>
      </div>

      {/* Type filter pills */}
      <div className="flex gap-1.5 mb-5">
        {typePills.map(p => (
          <button key={p.key} onClick={() => setType(p.key)}
            className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
              activeType === p.key
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-slate-300 hover:bg-gray-200 dark:hover:bg-slate-700'
            }`}>
            {p.label}
            {stats && p.key === 'all' && <span className="ml-1 opacity-70">{stats.total}</span>}
            {stats && p.key === 'spn' && <span className="ml-1 opacity-70">{stats.by_type.spn}</span>}
            {stats && p.key === 'app_reg' && <span className="ml-1 opacity-70">{stats.by_type.app_registration}</span>}
            {stats && p.key === 'managed_identity' && <span className="ml-1 opacity-70">{stats.by_type.managed_identity}</span>}
          </button>
        ))}
      </div>

      {/* Active Filter Chips */}
      {(exposureLevel || lifecycleFilter || ownerFilter || canEscalate || scopeFilter || crossSub || riskLevel) && (
        <div className="flex flex-wrap gap-1.5 mb-3 items-center">
          <span className="text-[10px] text-gray-400 dark:text-slate-500 uppercase mr-1">Filters:</span>
          {exposureLevel && <FilterChip label={`Exposure: ${exposureLevel}`} onRemove={() => { setExposureLevel(''); updateParams('exposure', ''); }} />}
          {lifecycleFilter && <FilterChip label={`Lifecycle: ${lifecycleFilter.replace(/_/g, ' ')}`} onRemove={() => { setLifecycleFilter(''); updateParams('lifecycle', ''); }} />}
          {ownerFilter && <FilterChip label={`Owner: ${ownerFilter}`} onRemove={() => { setOwnerFilter(''); updateParams('owner', ''); }} />}
          {canEscalate && <FilterChip label="Can Escalate" onRemove={() => { setCanEscalate(false); updateParams('escalate', ''); }} />}
          {scopeFilter && <FilterChip label={`Scope: ${scopeFilter.replace(/_/g, ' ')}`} onRemove={() => { setScopeFilter(''); updateParams('scope', ''); }} />}
          {crossSub && <FilterChip label="Cross-Subscription" onRemove={() => { setCrossSub(false); updateParams('cross_subscription', ''); }} />}
          {riskLevel && <FilterChip label={`Risk: ${riskLevel}`} onRemove={() => { setRiskLevel(''); updateParams('risk_level', ''); }} />}
          <button onClick={() => {
            setExposureLevel(''); setLifecycleFilter(''); setOwnerFilter(''); setCanEscalate(false);
            setScopeFilter(''); setCrossSub(false); setRiskLevel('');
            setSearchParams(prev => {
              const next = new URLSearchParams(prev);
              ['exposure', 'lifecycle', 'owner', 'escalate', 'scope', 'cross_subscription', 'risk_level'].forEach(k => next.delete(k));
              return next;
            }, { replace: true });
          }} className="text-xs text-blue-500 hover:underline ml-2">Clear All</button>
        </div>
      )}

      {/* Top 4 Audit Metrics */}
      {stats && (
        <div className="grid grid-cols-5 gap-3 mb-5">
          <button onClick={() => { setOwnerFilter('orphaned'); updateParams('owner', 'orphaned'); }}
            className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-3 text-left cursor-pointer hover:shadow-sm transition">
            <p className="text-xs text-gray-500 dark:text-slate-400">Orphaned</p>
            <p className="text-2xl font-bold mt-1 text-red-600 dark:text-red-400" style={{ width: 'fit-content', borderBottom: '1px dashed currentColor' }}>{stats.orphaned_count}</p>
            <p className="text-[10px] text-gray-400 dark:text-slate-500 mt-0.5">No owner + inactive</p>
          </button>
          <button onClick={() => { setOwnerFilter('ungoverned'); updateParams('owner', 'ungoverned'); }}
            className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-3 text-left cursor-pointer hover:shadow-sm transition">
            <p className="text-xs text-gray-500 dark:text-slate-400">Ungoverned</p>
            <p className="text-2xl font-bold mt-1 text-amber-600 dark:text-amber-400" style={{ width: 'fit-content', borderBottom: '1px dashed currentColor' }}>{stats.ungoverned_count}</p>
            <p className="text-[10px] text-gray-400 dark:text-slate-500 mt-0.5">Active but no owner</p>
          </button>
          <button onClick={() => { setLifecycleFilter('likely_dormant'); updateParams('lifecycle', 'likely_dormant'); }}
            className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-3 text-left cursor-pointer hover:shadow-sm transition">
            <p className="text-xs text-gray-500 dark:text-slate-400">Dormant &gt; 30 Days</p>
            <p className="text-2xl font-bold mt-1 text-orange-600 dark:text-orange-400" style={{ width: 'fit-content', borderBottom: '1px dashed currentColor' }}>{stats.zombie_count}</p>
            <p className="text-[10px] text-gray-400 dark:text-slate-500 mt-0.5">Inactive or never used</p>
          </button>
          <button onClick={() => { setCanEscalate(true); updateParams('escalate', 'true'); }}
            className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-3 text-left cursor-pointer hover:shadow-sm transition">
            <p className="text-xs text-gray-500 dark:text-slate-400">Admin Scope</p>
            <p className="text-2xl font-bold mt-1 text-purple-600 dark:text-purple-400" style={{ width: 'fit-content', borderBottom: '1px dashed currentColor' }}>{stats.can_escalate_count}</p>
            <p className="text-[10px] text-gray-400 dark:text-slate-500 mt-0.5">Can escalate privileges</p>
          </button>
          <button onClick={() => { setExposureLevel('critical'); updateParams('exposure', 'critical'); }}
            className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-3 text-left cursor-pointer hover:shadow-sm transition">
            <p className="text-xs text-gray-500 dark:text-slate-400">Sensitive Access</p>
            <p className="text-2xl font-bold mt-1 text-yellow-600 dark:text-yellow-400" style={{ width: 'fit-content', borderBottom: '1px dashed currentColor' }}>{stats.exposure_critical}</p>
            <p className="text-[10px] text-gray-400 dark:text-slate-500 mt-0.5">Critical exposure (score &ge; 80)</p>
          </button>
        </div>
      )}

      {/* Filter Bar */}
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <select value={exposureLevel} onChange={e => { setExposureLevel(e.target.value); updateParams('exposure', e.target.value); setOffset(0); }}
          className="text-xs border border-gray-300 dark:border-slate-600 rounded px-2 py-1.5 bg-white dark:bg-slate-800 text-gray-700 dark:text-slate-300">
          <option value="">All Exposure</option>
          <option value="critical">Critical (80+)</option>
          <option value="high">High (60-79)</option>
          <option value="medium">Medium (35-59)</option>
          <option value="low">Low (0-34)</option>
        </select>

        <select value={lifecycleFilter} onChange={e => { setLifecycleFilter(e.target.value); updateParams('lifecycle', e.target.value); setOffset(0); }}
          className="text-xs border border-gray-300 dark:border-slate-600 rounded px-2 py-1.5 bg-white dark:bg-slate-800 text-gray-700 dark:text-slate-300">
          <option value="">All Lifecycle</option>
          <option value="active">Active</option>
          <option value="possibly_active">Possibly Active</option>
          <option value="likely_dormant">Likely Dormant</option>
          <option value="blind">Blind</option>
        </select>

        <select value={ownerFilter} onChange={e => { setOwnerFilter(e.target.value); updateParams('owner', e.target.value); setOffset(0); }}
          className="text-xs border border-gray-300 dark:border-slate-600 rounded px-2 py-1.5 bg-white dark:bg-slate-800 text-gray-700 dark:text-slate-300">
          <option value="">All Owners</option>
          <option value="orphaned">Orphaned</option>
          <option value="ungoverned">Ungoverned</option>
          <option value="single_owner">Single Owner</option>
          <option value="owned">Owned</option>
          <option value="resource_bound">Resource Bound</option>
        </select>

        <label className="flex items-center gap-1 text-xs text-gray-500 dark:text-slate-400 cursor-pointer">
          <input type="checkbox" checked={canEscalate} onChange={e => { setCanEscalate(e.target.checked); updateParams('escalate', e.target.checked ? 'true' : ''); setOffset(0); }}
            className="rounded border-gray-300 text-blue-600" />
          Can Escalate
        </label>

        <div className="flex-1" />
        <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..."
          className="text-xs border border-gray-300 dark:border-slate-600 rounded px-2 py-1.5 bg-white dark:bg-slate-800 text-gray-700 dark:text-slate-300 w-48" />
        <span className="text-xs text-gray-400 dark:text-slate-500">
          {total} {total === 1 ? 'identity' : 'identities'}
          {(exposureLevel || lifecycleFilter || ownerFilter || canEscalate || scopeFilter || crossSub || riskLevel) && stats
            ? ` of ${stats.total} total`
            : ''}
        </span>
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700">
              <th className="text-left px-3 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer" onClick={() => handleSort('display_name')}>
                Identity <SortIcon col="display_name" />
              </th>
              <th className="text-left px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-32">Owner</th>
              <th className="text-left px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-28">Purpose</th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-28" onClick={() => handleSort('privilege_score')}>
                Effective Privilege <SortIcon col="privilege_score" />
              </th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-24">Sensitive Scope</th>
              <th className="text-left px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-24" onClick={() => handleSort('next_expiry')}>
                Secret Expiry <SortIcon col="next_expiry" />
              </th>
              <th className="text-left px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-20" onClick={() => handleSort('created_datetime')}>
                Created <SortIcon col="created_datetime" />
              </th>
              <th className="text-left px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-24" onClick={() => handleSort('last_sign_in')}>
                Last Active <SortIcon col="last_sign_in" />
              </th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-28">Ownership Confidence</th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-24">Lineage</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={10} className="text-center py-8">
                <div className="animate-spin h-6 w-6 border-2 border-blue-600 border-t-transparent rounded-full mx-auto" />
              </td></tr>
            )}
            {!loading && items.length === 0 && (
              <tr><td colSpan={10} className="text-center py-8 text-sm text-gray-400 dark:text-slate-500">No non-human identities found</td></tr>
            )}
            {!loading && items.map(row => {
              const owCfg = OWNER_STATUS_CONFIG[row.owner_status] || OWNER_STATUS_CONFIG.unknown;
              const scCfg = SCOPE_FLAG_CONFIG[row.effective_scope_flag] || SCOPE_FLAG_CONFIG.resource;
              const typeCfg = WORKLOAD_TYPE_CONFIG[row.identity_type] || WORKLOAD_TYPE_CONFIG.spn;
              return (
                <tr key={`${row.source_table}-${row.workload_id}`}
                  className="border-b border-gray-100 dark:border-slate-800 hover:bg-gray-50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors"
                  onClick={() => openDetail(row)}>
                  {/* Identity */}
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <TypeBadge type={row.identity_type} />
                      <span className="font-medium text-gray-800 dark:text-slate-200 truncate max-w-[260px]" title={row.display_name}>{row.display_name}</span>
                    </div>
                  </td>
                  {/* Owner */}
                  <td className="px-2 py-2">
                    {row.owner_display_name ? (
                      <span className="text-xs text-gray-700 dark:text-slate-300 truncate block max-w-[140px]" title={row.owner_display_name}>{row.owner_display_name}</span>
                    ) : (
                      <span className="text-[10px] text-gray-400 dark:text-slate-500 italic">No owner</span>
                    )}
                  </td>
                  {/* Purpose */}
                  <td className="px-2 py-2">
                    <span className="text-xs text-gray-600 dark:text-slate-300">{typeCfg.label}</span>
                  </td>
                  {/* Effective Privilege */}
                  <td className="text-center px-2 py-2">
                    <span className={`text-xs font-medium ${row.privilege_score >= 30 ? 'text-red-600 dark:text-red-400' : row.privilege_score >= 15 ? 'text-orange-500 dark:text-orange-400' : 'text-gray-600 dark:text-slate-300'}`}>
                      {row.privilege_score}/40
                    </span>
                  </td>
                  {/* Sensitive Scope */}
                  <td className="text-center px-2 py-2">
                    <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${scCfg.badgeClass}`}>{scCfg.label}</span>
                  </td>
                  {/* Secret Expiry */}
                  <td className="px-2 py-2 whitespace-nowrap">
                    {(() => {
                      const exp = formatSecretExpiry(row.next_expiry, row.has_expired_credentials, row.credential_count);
                      return <span className={`text-xs ${exp.colorClass}`}>{exp.label}</span>;
                    })()}
                  </td>
                  {/* Created */}
                  <td className="px-2 py-2 whitespace-nowrap">
                    <span className="text-xs text-gray-500 dark:text-slate-400" title={row.created_datetime ? formatDate(row.created_datetime) : undefined}>
                      {formatCreatedAge(row.created_datetime)}
                    </span>
                  </td>
                  {/* Last Active */}
                  <td className="px-2 py-2 whitespace-nowrap">
                    {(() => {
                      const la = formatLastActive(row.last_sign_in, row.created_datetime);
                      return <span className={`text-xs ${la.colorClass}`} title={la.tooltip}>{la.label}</span>;
                    })()}
                  </td>
                  {/* Ownership Confidence */}
                  <td className="text-center px-2 py-2">
                    <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${owCfg.badgeClass}`}>{owCfg.label}</span>
                  </td>
                  {/* Lineage */}
                  <td className="text-center px-2 py-2">
                    {(() => {
                      const v = row.recommended_action;
                      if (!v) return <span className="text-[10px] text-gray-300">—</span>;
                      return <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${verdictBadgeClasses(v)}`}>{verdictLabel(v)}</span>;
                    })()}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {/* Pagination */}
        {total > limit && (
          <div className="flex items-center justify-between px-3 py-2 border-t border-gray-200 dark:border-slate-700 bg-gray-50 dark:bg-slate-800">
            <span className="text-xs text-gray-500 dark:text-slate-400">
              {offset + 1}–{Math.min(offset + limit, total)} of {total}
            </span>
            <div className="flex gap-1">
              <button onClick={() => setOffset(Math.max(0, offset - limit))} disabled={offset === 0}
                className="px-2 py-1 text-xs rounded border border-gray-300 dark:border-slate-600 disabled:opacity-40 hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-600 dark:text-slate-300">
                Prev
              </button>
              <button onClick={() => setOffset(offset + limit)} disabled={offset + limit >= total}
                className="px-2 py-1 text-xs rounded border border-gray-300 dark:border-slate-600 disabled:opacity-40 hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-600 dark:text-slate-300">
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="mt-3 text-[11px] text-gray-400 dark:text-slate-500 text-center">
        Click any row to inspect.
      </div>
    </div>
  );
};

export default WorkloadIdentities;
