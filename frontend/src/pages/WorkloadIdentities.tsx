import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { WORKLOAD_TYPE_CONFIG, LIFECYCLE_STATE_CONFIG, OWNER_STATUS_CONFIG, SCOPE_FLAG_CONFIG } from '../constants/metrics';

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
  sign_ins_30d?: number | null;
  anomaly_count?: number;
}

interface WorkloadStats {
  total: number;
  by_type: { spn: number; managed_identity: number; app_registration: number };
  exposure_critical: number;
  can_escalate_count: number;
  orphaned_count: number;
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

  const [sortCol, setSortCol] = useState('exposure_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [exposureLevel, setExposureLevel] = useState(searchParams.get('exposure') || '');
  const [lifecycleFilter, setLifecycleFilter] = useState(searchParams.get('lifecycle') || '');
  const [ownerFilter, setOwnerFilter] = useState(searchParams.get('owner') || '');
  const [canEscalate, setCanEscalate] = useState(searchParams.get('escalate') === 'true');
  const [scopeFilter, setScopeFilter] = useState(searchParams.get('scope') || '');
  const [crossSub, setCrossSub] = useState(searchParams.get('cross_subscription') === 'true');
  const [riskLevel, setRiskLevel] = useState(searchParams.get('risk_level') || '');
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
    if (search) params.set('search', search);
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
  }, [activeType, exposureLevel, lifecycleFilter, ownerFilter, canEscalate, scopeFilter, crossSub, riskLevel, search, sortCol, sortDir, offset, hideMicrosoft, selectedConnectionId]);

  const openDetail = (row: WorkloadRow) => {
    navigate(`/workload-identities/${row.workload_id}?type=${row.identity_type}`);
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
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Workload Identity Exposure</h1>
          <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">
            Unified view of service principals, app registrations, and managed identities
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

      {/* Alert Banner — P2 active vs visibility gap */}
      {stats && !!stats.p2_enabled && !!stats.telemetry && (
        <div className="mb-5 rounded-lg bg-gradient-to-r from-emerald-50 to-green-50 dark:from-emerald-900/20 dark:to-green-900/20 border border-emerald-200 dark:border-emerald-800/40 p-3">
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-emerald-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <span className="text-sm font-medium text-emerald-700 dark:text-emerald-300">
              P2 Telemetry Active &mdash; {stats.telemetry.active_identities} active, {stats.telemetry.dormant_confirmed} confirmed dormant
            </span>
            <span className="text-xs text-gray-500 dark:text-slate-400 ml-2">
              {stats.telemetry.risky_sign_ins} risky sign-ins &middot; {stats.telemetry.unresolved_anomalies} unresolved anomalies
            </span>
          </div>
        </div>
      )}
      {stats && !stats.p2_enabled && stats.blind_count > 0 && (
        <div className="mb-5 rounded-lg bg-gradient-to-r from-red-50 to-amber-50 dark:from-red-900/20 dark:to-amber-900/20 border border-red-200 dark:border-red-800/40 p-3">
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-red-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <span className="text-sm font-medium text-red-700 dark:text-red-300">
              {stats.blind_count} Workload {stats.blind_count === 1 ? 'Identity Lacks' : 'Identities Lack'} Activity Telemetry
            </span>
            {stats.orphaned_count > 0 && (
              <span className="text-xs text-gray-500 dark:text-slate-400 ml-2">
                {stats.orphaned_count} orphaned &middot; {stats.stale_credentials} stale credentials
              </span>
            )}
          </div>
        </div>
      )}

      {/* Exposure Summary Cards */}
      {stats && (
        <div className={`grid gap-3 mb-5 ${stats.p2_enabled && stats.telemetry ? 'grid-cols-7' : 'grid-cols-5'}`}>
          {[
            { label: 'Critical Exposure', value: stats.exposure_critical, color: 'text-red-600 dark:text-red-400', sub: 'Score ≥ 80', show: true },
            { label: 'Orphaned', value: stats.orphaned_count, color: 'text-orange-600 dark:text-orange-400', sub: 'No owner', show: true },
            { label: 'Stale Credentials', value: stats.stale_credentials, color: 'text-yellow-600 dark:text-yellow-400', sub: '> 365 days', show: true },
            { label: 'Can Escalate', value: stats.can_escalate_count, color: 'text-purple-600 dark:text-purple-400', sub: 'Priv escalation', show: true },
            { label: 'Zombie', value: stats.zombie_count, color: 'text-gray-600 dark:text-gray-400', sub: 'Dormant + risky', show: true },
            { label: 'Risky Sign-Ins', value: stats.telemetry?.risky_sign_ins ?? 0, color: 'text-red-500 dark:text-red-400', sub: 'P2 risk detection', show: !!stats.p2_enabled && !!stats.telemetry },
            { label: 'Anomalies', value: stats.telemetry?.unresolved_anomalies ?? 0, color: 'text-violet-600 dark:text-violet-400', sub: 'Unresolved', show: !!stats.p2_enabled && !!stats.telemetry },
          ].filter(c => c.show).map(c => (
            <div key={c.label} className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-3">
              <p className="text-xs text-gray-500 dark:text-slate-400">{c.label}</p>
              <p className={`text-2xl font-bold mt-1 ${c.color}`}>{c.value}</p>
              <p className="text-[10px] text-gray-400 dark:text-slate-500 mt-0.5">{c.sub}</p>
            </div>
          ))}
        </div>
      )}

      {/* Risk Distribution + Top Findings */}
      {stats && (
        <div className="grid grid-cols-[220px_1fr] gap-3 mb-5">
          {/* Risk Distribution */}
          <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-3">
            <h3 className="text-xs font-semibold text-gray-700 dark:text-slate-300 mb-2">Risk Distribution</h3>
            {['critical', 'high', 'medium', 'low', 'info'].map(level => (
              <div key={level} className="flex items-center justify-between py-0.5">
                <span className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-slate-400 capitalize">
                  <span className={`w-2 h-2 rounded-full ${SEV_COLOR[level] || 'bg-gray-300'}`} />
                  {level}
                </span>
                <span className="text-xs font-medium text-gray-700 dark:text-slate-300">
                  {stats.by_risk[level] || 0}
                </span>
              </div>
            ))}
            <div className="mt-2 pt-2 border-t border-gray-100 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-gray-400 dark:text-slate-500">Avg Score</span>
                <span className={`text-sm font-bold ${exposureColor(stats.avg_exposure_score)}`}>
                  {stats.avg_exposure_score}
                </span>
              </div>
            </div>
          </div>

          {/* Top Findings */}
          <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-3">
            <h3 className="text-xs font-semibold text-gray-700 dark:text-slate-300 mb-2">Top Findings</h3>
            {stats.top_findings.length === 0 && (
              <p className="text-xs text-gray-400 dark:text-slate-500">No findings detected</p>
            )}
            <div className="space-y-1.5">
              {stats.top_findings.slice(0, 7).map((f, i) => (
                <div key={i} className="flex items-start gap-2">
                  <span className={`mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-semibold ${SEV_BADGE[f.severity] || 'bg-gray-100 text-gray-500'}`}>
                    {f.severity.toUpperCase()}
                  </span>
                  <div className="flex-1 min-w-0">
                    <span className="text-xs text-gray-700 dark:text-slate-300">{f.title}</span>
                    <span className="text-[10px] text-gray-400 dark:text-slate-500 ml-1.5">— {f.display_name}</span>
                  </div>
                  <span className="text-[10px] text-gray-400 dark:text-slate-500 flex-shrink-0">+{f.score_impact}</span>
                </div>
              ))}
            </div>
          </div>
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
                Name <SortIcon col="display_name" />
              </th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-16" onClick={() => handleSort('exposure_score')}>
                Exp <SortIcon col="exposure_score" />
              </th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-14" onClick={() => handleSort('privilege_score')}>
                Priv <SortIcon col="privilege_score" />
              </th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-16" onClick={() => handleSort('credential_risk_score')}>
                Cred <SortIcon col="credential_risk_score" />
              </th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-20">Lifecycle</th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-20">Owner</th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-20">Scope</th>
              {!!stats?.p2_enabled && (
                <>
                  <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-[72px]">Sign-Ins</th>
                  <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-14">Anom</th>
                </>
              )}
              <th className="w-8" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={stats?.p2_enabled ? 10 : 8} className="text-center py-8">
                <div className="animate-spin h-6 w-6 border-2 border-blue-600 border-t-transparent rounded-full mx-auto" />
              </td></tr>
            )}
            {!loading && items.length === 0 && (
              <tr><td colSpan={stats?.p2_enabled ? 10 : 8} className="text-center py-8 text-sm text-gray-400 dark:text-slate-500">No workload identities found</td></tr>
            )}
            {!loading && items.map(row => {
              const lcCfg = LIFECYCLE_STATE_CONFIG[row.lifecycle_state] || LIFECYCLE_STATE_CONFIG.blind;
              const owCfg = OWNER_STATUS_CONFIG[row.owner_status] || OWNER_STATUS_CONFIG.unknown;
              const scCfg = SCOPE_FLAG_CONFIG[row.effective_scope_flag] || SCOPE_FLAG_CONFIG.resource;
              const isMI = row.identity_type === 'managed_identity';
              return (
                <tr key={`${row.source_table}-${row.workload_id}`}
                  className="border-b border-gray-100 dark:border-slate-800 hover:bg-gray-50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors"
                  onClick={() => openDetail(row)}>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <TypeBadge type={row.identity_type} />
                      <span className="font-medium text-gray-800 dark:text-slate-200 truncate max-w-[260px]" title={row.display_name}>{row.display_name}</span>
                      {row.can_escalate && (
                        <span className="px-1 py-0.5 rounded text-[9px] font-bold bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300">ESC</span>
                      )}
                    </div>
                  </td>
                  <td className="text-center px-2 py-2">
                    <ExposureRing score={row.exposure_score} size={32} />
                  </td>
                  <td className="text-center px-2 py-2">
                    <span className={`text-xs font-medium ${exposureColor(row.privilege_score * 2.5)}`}>{row.privilege_score}/40</span>
                  </td>
                  <td className="text-center px-2 py-2">
                    {isMI ? (
                      <span className="text-[10px] text-teal-600 dark:text-teal-400 font-medium">Managed</span>
                    ) : (
                      <span className={`text-xs font-medium ${exposureColor(row.credential_risk_score * 4)}`}>{row.credential_risk_score}/25</span>
                    )}
                  </td>
                  <td className="text-center px-2 py-2">
                    <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${lcCfg.badgeClass}`}>{lcCfg.label}</span>
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex flex-col items-center gap-0.5">
                      <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${owCfg.badgeClass}`}>{owCfg.label}</span>
                      {row.owner_display_name && (
                        <span className="text-[10px] text-gray-500 dark:text-slate-400 truncate max-w-[120px]" title={row.owner_display_name}>{row.owner_display_name}</span>
                      )}
                    </div>
                  </td>
                  <td className="text-center px-2 py-2">
                    <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${scCfg.badgeClass}`}>{scCfg.label}</span>
                  </td>
                  {!!stats?.p2_enabled && (
                    <>
                      <td className="text-center px-2 py-2">
                        <span className="text-xs text-gray-600 dark:text-slate-300">
                          {row.sign_ins_30d != null ? row.sign_ins_30d.toLocaleString() : '—'}
                        </span>
                      </td>
                      <td className="text-center px-2 py-2">
                        {(row.anomaly_count ?? 0) > 0 ? (
                          <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-violet-100 text-violet-700 dark:bg-violet-900/40 dark:text-violet-300">
                            {row.anomaly_count}
                          </span>
                        ) : (
                          <span className="text-xs text-gray-400 dark:text-slate-500">0</span>
                        )}
                      </td>
                    </>
                  )}
                  <td className="px-2 py-2 text-gray-400">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
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

      {/* Footer Legend */}
      <div className="mt-4 text-[10px] text-gray-400 dark:text-slate-500">
        Exposure = Privilege (40) + Credential Risk (25) + Exposure (20) + Lifecycle (10) + Visibility (5). Score ≥ 80 = Critical. Override conditions force score to 100.
      </div>
    </div>
  );
};

export default WorkloadIdentities;
