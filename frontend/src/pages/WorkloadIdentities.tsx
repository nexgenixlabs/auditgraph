import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
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
  effective_scope_flag: string;
  cross_subscription: boolean;
  credential_age_days: number;
  created_datetime: string;
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
}

interface WorkloadDetail {
  identity_type: string;
  display_name: string;
  exposure: {
    total: number;
    privilege: number;
    credential_risk: number;
    exposure: number;
    lifecycle: number;
    visibility: number;
    can_escalate: boolean;
    effective_scope_flag: string;
    lifecycle_state: string;
    owner_status: string;
    federated_trust: boolean;
    cross_subscription: boolean;
    credential_age_days: number;
    critical_overrides: Array<{ type: string; description: string }>;
  };
  findings: Array<{
    finding_type: string;
    severity: string;
    title: string;
    description: string;
    remediation: string;
    component: string;
    score_impact: number;
  }>;
  activity_inference: { confidence: number; classification: string };
  recommendations: Array<{ priority: string; action: string }>;
  detail: Record<string, any>;
  roles?: any[];
  entra_roles?: any[];
  credentials?: any[];
  owners?: any[];
  blast_radius?: string;
  critical_roles?: string[];
  linked_spn?: any;
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

function ComponentBar({ label, score, max }: { label: string; score: number; max: number }) {
  const pct = max > 0 ? Math.min((score / max) * 100, 100) : 0;
  const color = pct >= 80 ? 'bg-red-500' : pct >= 50 ? 'bg-orange-400' : pct >= 25 ? 'bg-yellow-400' : 'bg-green-400';
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-20 text-gray-500 dark:text-slate-400 text-right">{label}</span>
      <div className="flex-1 h-2 bg-gray-100 dark:bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-10 text-gray-600 dark:text-slate-300 text-right font-medium">{score}/{max}</span>
    </div>
  );
}

// ── Page Component ───────────────────────────────────────────────────

const WorkloadIdentities: React.FC = () => {
  const { withConnection, selectedConnectionId } = useConnection();
  const [searchParams, setSearchParams] = useSearchParams();

  const activeType = searchParams.get('type') || 'all';
  const [stats, setStats] = useState<WorkloadStats | null>(null);
  const [items, setItems] = useState<WorkloadRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [selectedDetail, setSelectedDetail] = useState<WorkloadDetail | null>(null);

  const [sortCol, setSortCol] = useState('exposure_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [exposureLevel, setExposureLevel] = useState(searchParams.get('exposure') || '');
  const [lifecycleFilter, setLifecycleFilter] = useState(searchParams.get('lifecycle') || '');
  const [ownerFilter, setOwnerFilter] = useState(searchParams.get('owner') || '');
  const [canEscalate, setCanEscalate] = useState(searchParams.get('escalate') === 'true');
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
  }, [activeType, exposureLevel, lifecycleFilter, ownerFilter, canEscalate, search, sortCol, sortDir, offset, hideMicrosoft, selectedConnectionId]);

  const openDetail = (row: WorkloadRow) => {
    setDetailLoading(true);
    fetch(withConnection(`/api/workload-identities/${row.workload_id}?type=${row.identity_type}`))
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setSelectedDetail(d))
      .catch(() => {})
      .finally(() => setDetailLoading(false));
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

      {/* Alert Banner */}
      {stats && stats.blind_count > 0 && (
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

      {/* 5 Exposure Summary Cards */}
      {stats && (
        <div className="grid grid-cols-5 gap-3 mb-5">
          {[
            { label: 'Critical Exposure', value: stats.exposure_critical, color: 'text-red-600 dark:text-red-400', sub: 'Score ≥ 80' },
            { label: 'Orphaned', value: stats.orphaned_count, color: 'text-orange-600 dark:text-orange-400', sub: 'No owner' },
            { label: 'Stale Credentials', value: stats.stale_credentials, color: 'text-yellow-600 dark:text-yellow-400', sub: '> 365 days' },
            { label: 'Can Escalate', value: stats.can_escalate_count, color: 'text-purple-600 dark:text-purple-400', sub: 'Priv escalation' },
            { label: 'Zombie', value: stats.zombie_count, color: 'text-gray-600 dark:text-gray-400', sub: 'Dormant + risky' },
          ].map(c => (
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
        <span className="text-xs text-gray-400 dark:text-slate-500">{total} {total === 1 ? 'identity' : 'identities'}</span>
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
              <th className="w-8" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={8} className="text-center py-8">
                <div className="animate-spin h-6 w-6 border-2 border-blue-600 border-t-transparent rounded-full mx-auto" />
              </td></tr>
            )}
            {!loading && items.length === 0 && (
              <tr><td colSpan={8} className="text-center py-8 text-sm text-gray-400 dark:text-slate-500">No workload identities found</td></tr>
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
                  <td className="text-center px-2 py-2">
                    <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${owCfg.badgeClass}`}>{owCfg.label}</span>
                  </td>
                  <td className="text-center px-2 py-2">
                    <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${scCfg.badgeClass}`}>{scCfg.label}</span>
                  </td>
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

      {/* Detail Modal */}
      {(selectedDetail || detailLoading) && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => { setSelectedDetail(null); }}>
          <div className="bg-white dark:bg-slate-900 rounded-xl shadow-2xl max-w-xl w-full max-h-[85vh] overflow-y-auto m-4" onClick={e => e.stopPropagation()}>
            {detailLoading && !selectedDetail ? (
              <div className="p-8 text-center">
                <div className="animate-spin h-8 w-8 border-2 border-blue-600 border-t-transparent rounded-full mx-auto" />
              </div>
            ) : selectedDetail && (
              <>
                {/* Modal Header */}
                <div className="sticky top-0 bg-white dark:bg-slate-900 border-b border-gray-200 dark:border-slate-700 px-5 py-3 flex items-center justify-between z-10">
                  <div className="flex items-center gap-2 min-w-0">
                    <TypeBadge type={selectedDetail.identity_type} />
                    <h2 className="text-lg font-bold text-gray-900 dark:text-white truncate">{selectedDetail.display_name}</h2>
                  </div>
                  <button onClick={() => setSelectedDetail(null)} className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-slate-300">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                  </button>
                </div>

                {/* Exposure Score Header */}
                <div className="px-5 py-4 flex items-center gap-4 border-b border-gray-100 dark:border-slate-800">
                  <ExposureRing score={selectedDetail.exposure.total} size={56} />
                  <div>
                    <p className="text-sm text-gray-500 dark:text-slate-400">Exposure Score</p>
                    <p className={`text-2xl font-bold ${exposureColor(selectedDetail.exposure.total)}`}>{selectedDetail.exposure.total}/100</p>
                  </div>
                  {selectedDetail.exposure.critical_overrides.length > 0 && (
                    <span className="ml-auto px-2 py-1 rounded text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300">
                      OVERRIDE: 100
                    </span>
                  )}
                </div>

                {/* 5 Component Bars */}
                <div className="px-5 py-3 space-y-1.5 border-b border-gray-100 dark:border-slate-800">
                  <ComponentBar label="Privilege" score={selectedDetail.exposure.privilege} max={40} />
                  <ComponentBar label="Cred Risk" score={selectedDetail.exposure.credential_risk} max={25} />
                  <ComponentBar label="Exposure" score={selectedDetail.exposure.exposure} max={20} />
                  <ComponentBar label="Lifecycle" score={selectedDetail.exposure.lifecycle} max={10} />
                  <ComponentBar label="Visibility" score={selectedDetail.exposure.visibility} max={5} />
                </div>

                {/* Derived Flags */}
                <div className="px-5 py-3 flex flex-wrap gap-1.5 border-b border-gray-100 dark:border-slate-800">
                  {selectedDetail.exposure.can_escalate && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300">Can Escalate</span>
                  )}
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                    LIFECYCLE_STATE_CONFIG[selectedDetail.exposure.lifecycle_state]?.badgeClass || 'bg-gray-100 text-gray-500'
                  }`}>{LIFECYCLE_STATE_CONFIG[selectedDetail.exposure.lifecycle_state]?.label || selectedDetail.exposure.lifecycle_state}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                    OWNER_STATUS_CONFIG[selectedDetail.exposure.owner_status]?.badgeClass || 'bg-gray-100 text-gray-500'
                  }`}>{OWNER_STATUS_CONFIG[selectedDetail.exposure.owner_status]?.label || selectedDetail.exposure.owner_status}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                    SCOPE_FLAG_CONFIG[selectedDetail.exposure.effective_scope_flag]?.badgeClass || 'bg-gray-100 text-gray-500'
                  }`}>{SCOPE_FLAG_CONFIG[selectedDetail.exposure.effective_scope_flag]?.label || selectedDetail.exposure.effective_scope_flag}</span>
                  {selectedDetail.exposure.cross_subscription && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300">Cross-Sub</span>
                  )}
                  {selectedDetail.exposure.federated_trust && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">Federated</span>
                  )}
                </div>

                {/* Activity Inference */}
                <div className="px-5 py-3 border-b border-gray-100 dark:border-slate-800">
                  <h4 className="text-xs font-semibold text-gray-700 dark:text-slate-300 mb-1">Activity Inference</h4>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 h-2 bg-gray-100 dark:bg-slate-700 rounded-full overflow-hidden">
                      <div className="h-full bg-blue-500 rounded-full" style={{ width: `${selectedDetail.activity_inference.confidence}%` }} />
                    </div>
                    <span className="text-xs text-gray-600 dark:text-slate-300 font-medium">
                      {selectedDetail.activity_inference.confidence}% — {selectedDetail.activity_inference.classification.replace(/_/g, ' ')}
                    </span>
                  </div>
                </div>

                {/* Findings */}
                {selectedDetail.findings.length > 0 && (
                  <div className="px-5 py-3 border-b border-gray-100 dark:border-slate-800">
                    <h4 className="text-xs font-semibold text-gray-700 dark:text-slate-300 mb-2">Findings ({selectedDetail.findings.length})</h4>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {selectedDetail.findings.map((f, i) => (
                        <div key={i} className="text-xs">
                          <div className="flex items-start gap-1.5">
                            <span className={`mt-0.5 px-1 py-0.5 rounded text-[9px] font-bold ${SEV_BADGE[f.severity] || 'bg-gray-100 text-gray-500'}`}>
                              {f.severity.toUpperCase()}
                            </span>
                            <div>
                              <p className="font-medium text-gray-700 dark:text-slate-300">{f.title}</p>
                              <p className="text-gray-500 dark:text-slate-400 mt-0.5">{f.description}</p>
                              {f.remediation && (
                                <p className="text-blue-600 dark:text-blue-400 mt-0.5">{f.remediation}</p>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                {selectedDetail.recommendations.length > 0 && (
                  <div className="px-5 py-3 border-b border-gray-100 dark:border-slate-800">
                    <h4 className="text-xs font-semibold text-gray-700 dark:text-slate-300 mb-2">Recommendations</h4>
                    <ul className="space-y-1">
                      {selectedDetail.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start gap-1.5 text-xs">
                          <span className={`mt-0.5 px-1 py-0.5 rounded text-[9px] font-bold ${SEV_BADGE[rec.priority] || 'bg-gray-100 text-gray-500'}`}>
                            {rec.priority.toUpperCase()}
                          </span>
                          <span className="text-gray-600 dark:text-slate-400">{rec.action}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Critical Overrides */}
                {selectedDetail.exposure.critical_overrides.length > 0 && (
                  <div className="px-5 py-3 border-b border-gray-100 dark:border-slate-800 bg-red-50 dark:bg-red-900/10">
                    <h4 className="text-xs font-semibold text-red-700 dark:text-red-300 mb-1">Critical Overrides (Score Forced to 100)</h4>
                    {selectedDetail.exposure.critical_overrides.map((ov, i) => (
                      <p key={i} className="text-xs text-red-600 dark:text-red-400">{ov.description}</p>
                    ))}
                  </div>
                )}

                {/* Footer: View Full Detail link */}
                <div className="px-5 py-3 flex justify-between items-center">
                  {selectedDetail.identity_type !== 'app_registration' && selectedDetail.detail?.id && (
                    <a href={`/identities/${selectedDetail.detail.id}`}
                      className="text-xs text-blue-600 dark:text-blue-400 hover:underline">
                      Open Full Identity Detail →
                    </a>
                  )}
                  <button onClick={() => setSelectedDetail(null)}
                    className="ml-auto px-3 py-1.5 rounded text-xs font-medium bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-slate-300 hover:bg-gray-200 dark:hover:bg-slate-700">
                    Close
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Footer Legend */}
      <div className="mt-4 text-[10px] text-gray-400 dark:text-slate-500">
        Exposure = Privilege (40) + Credential Risk (25) + Exposure (20) + Lifecycle (10) + Visibility (5). Score ≥ 80 = Critical. Override conditions force score to 100.
      </div>
    </div>
  );
};

export default WorkloadIdentities;
