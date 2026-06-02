import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { TIME_MS } from '../constants/metrics';
import {
  formatAccessLevel,
  accessLevelBadge,
  formatPlatform,
  ACCESS_CATEGORIES,
} from '../constants/aiRisk';
import AIInvestigateDrawer from '../components/AIInvestigateDrawer';

interface RiskDimension {
  score: number;
  level: string;
}

interface AgentRow {
  identity_id: string;
  display_name: string;
  identity_category: string;
  agent_identity_type: string;
  classification_confidence: number;
  classification_reason: string;
  detected_platform: string;
  risk_score: number;
  risk_level: string;
  activity_status: string;
  effective_last_active: string | null;
  owner_display_name: string | null;
  credential_count: number;
  credential_risk: string;
  privilege_tier: string;
  blast_radius_score: number | null;
  // New enriched columns
  model_access: string;
  key_vault_access: string;
  data_access: string;
  telemetry: string;
  internet_egress: string;
  ai_risk_score: number;
  ai_risk_severity: string;
  risk_dimensions: Record<string, RiskDimension>;
  role_count: number;
  role_names?: string[];   // AG-162: exposed for URL ?role= filtering
}

const NHI_CATEGORIES = new Set(['service_principal', 'managed_identity_system', 'managed_identity_user', 'app', 'workload']);

const CATEGORY_LABELS: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'System MSI',
  managed_identity_user: 'User MSI',
  human_user: 'Human',
  guest: 'Guest',
};

function formatLastActive(d: string | null): string {
  if (!d) return 'Unknown';
  const dt = new Date(d);
  const days = Math.round((Date.now() - dt.getTime()) / TIME_MS.DAY);
  if (days <= 0) return 'Today';
  if (days === 1) return '1d ago';
  if (days < 30) return `${days}d ago`;
  if (days < 365) return `${Math.floor(days / 30)}mo ago`;
  return `${Math.floor(days / 365)}y ago`;
}

function riskColor(score: number): string {
  if (score >= 75) return 'bg-red-900/40 text-red-300';
  if (score >= 50) return 'bg-orange-900/40 text-orange-300';
  if (score >= 25) return 'bg-yellow-900/40 text-yellow-300';
  return 'bg-green-900/40 text-green-300';
}

type SortKey = 'display_name' | 'risk_score' | 'ai_risk_score' | 'model_access' | 'key_vault_access' | 'data_access' | 'effective_last_active';

export default function AIAgents() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  // AG-162: URL-driven filtering — `?role=X` from AI Access "Most Common Roles"
  // and `?filter=metric` from tone cards. Both filter the agent list and show
  // a clear-filter chip above the table.
  const [searchParams, setSearchParams] = useSearchParams();
  const roleFilter = searchParams.get('role') || '';
  const metricFilter = searchParams.get('filter') || '';
  const clearFilters = () => {
    const next = new URLSearchParams(searchParams);
    next.delete('role'); next.delete('filter');
    setSearchParams(next, { replace: true });
  };
  const [items, setItems] = useState<AgentRow[]>([]);
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortCol, setSortCol] = useState<SortKey>('risk_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [humanSectionOpen, setHumanSectionOpen] = useState(false);
  const [investigateId, setInvestigateId] = useState<string | null>(null);

  const PER_PAGE = 500;

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(withConnection(`/api/ai-agents/enriched?include_possible=true&per_page=${PER_PAGE}`))
      .then(r => {
        if (r.status === 404) { setError('not_found'); return null; }
        if (!r.ok) { setError('fetch_error'); return null; }
        return r.json();
      })
      .then(d => {
        if (!d) { setItems([]); return; }
        const list = Array.isArray(d?.items) ? d.items : Array.isArray(d) ? d : [];
        setItems(list);
        setTotalCount(d?.total ?? null);
      })
      .catch(() => {
        setError('fetch_error');
        setItems([]);
      })
      .finally(() => setLoading(false));
  }, [withConnection, selectedConnectionId]);

  const { nhiAgents, humanAgents } = useMemo(() => {
    const nhi: AgentRow[] = [];
    const human: AgentRow[] = [];
    // AG-162: predicate from URL filters. Both apply if both set (AND).
    const matchesFilters = (a: AgentRow): boolean => {
      if (roleFilter && !(a.role_names || []).includes(roleFilter)) return false;
      if (metricFilter) {
        const lvl = (a as any)[metricFilter];
        if (!lvl || lvl === 'none') return false;
      }
      return true;
    };
    for (const item of items) {
      if (!matchesFilters(item)) continue;
      if (item.agent_identity_type === 'ai_privileged_human' || item.identity_category === 'human_user') {
        human.push(item);
      } else if (NHI_CATEGORIES.has(item.identity_category) || item.agent_identity_type === 'ai_agent' || item.agent_identity_type === 'possible_ai_agent') {
        nhi.push(item);
      }
    }
    return { nhiAgents: nhi, humanAgents: human };
  }, [items, roleFilter, metricFilter]);

  const sortItems = (list: AgentRow[]) => {
    const copy = [...list];
    copy.sort((a, b) => {
      const rawA = (a as Record<string, any>)[sortCol];
      const rawB = (b as Record<string, any>)[sortCol];
      if (sortCol === 'effective_last_active') {
        const ta = rawA ? new Date(rawA).getTime() : 0;
        const tb = rawB ? new Date(rawB).getTime() : 0;
        return sortDir === 'asc' ? ta - tb : tb - ta;
      }
      let av: string | number = rawA ?? '';
      let bv: string | number = rawB ?? '';
      if (typeof av === 'string') av = av.toLowerCase();
      if (typeof bv === 'string') bv = bv.toLowerCase();
      if (av < bv) return sortDir === 'asc' ? -1 : 1;
      if (av > bv) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return copy;
  };

  const sortedNhi = useMemo(() => sortItems(nhiAgents), [nhiAgents, sortCol, sortDir]);
  const sortedHumans = useMemo(() => sortItems(humanAgents), [humanAgents, sortCol, sortDir]);

  const stats = useMemo(() => {
    const agentCount = nhiAgents.length;
    const humanCount = humanAgents.length;
    const avgRisk = nhiAgents.length > 0
      ? Math.round(nhiAgents.reduce((s, i) => s + (i.risk_score || 0), 0) / nhiAgents.length)
      : 0;
    const withModel = nhiAgents.filter(a => a.model_access && a.model_access !== 'none').length;
    const withKv = nhiAgents.filter(a => a.key_vault_access && a.key_vault_access !== 'none').length;
    return { agentCount, humanCount, avgRisk, withModel, withKv };
  }, [nhiAgents, humanAgents]);

  const handleSort = (col: SortKey) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
  };

  const SortIcon = ({ col }: { col: string }) => (
    <span className="ml-1 text-slate-500">{sortCol === col ? (sortDir === 'asc' ? '\u2191' : '\u2193') : '\u21C5'}</span>
  );

  // Compact access badge
  const AccessBadge = ({ level }: { level: string | null | undefined }) => {
    if (!level || level === 'none') return <span className="text-[10px] text-slate-600">{'\u2014'}</span>;
    return (
      <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium border ${accessLevelBadge(level)}`}>
        {formatAccessLevel(level)}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="p-6 max-w-[1600px] mx-auto">
        <div className="flex items-center justify-center py-20">
          <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
        </div>
      </div>
    );
  }

  if (error === 'not_found') {
    return (
      <div className="p-6 max-w-[1600px] mx-auto">
        <h1 className="text-2xl font-bold text-white mb-2">AI Identity Governance</h1>
        <div className="rounded-lg border p-10 text-center mt-6" style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
          <div className="w-14 h-14 mx-auto mb-4 rounded-full bg-slate-800 flex items-center justify-center">
            <svg className="w-7 h-7 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-white mb-2">Feature Not Enabled</h3>
          <p className="text-sm text-slate-400 max-w-md mx-auto">
            AI Identity classification requires a discovery scan with agent detection enabled.
            Run a discovery scan to populate this view.
          </p>
        </div>
      </div>
    );
  }

  const renderTableRow = (row: AgentRow) => (
    <tr key={row.identity_id}
      className="border-b hover:bg-slate-800/50 cursor-pointer transition-colors"
      style={{ borderColor: 'var(--border-subtle)' }}
      onClick={() => setInvestigateId(row.identity_id)}>
      <td className="px-3 py-2">
        <div className="font-medium text-slate-200 truncate max-w-[200px]" title={row.display_name}>{row.display_name}</div>
        <div className="text-[10px] text-slate-500">{CATEGORY_LABELS[row.identity_category] || row.identity_category}</div>
      </td>
      <td className="px-2 py-2">
        <span className="text-xs text-slate-300">{formatPlatform(row.detected_platform)}</span>
      </td>
      <td className="px-2 py-2">
        {/* AG-AI-RBAC: show RBAC role chips alongside model provider so the
            row tells both stories — "this is an Azure OpenAI agent AND it
            holds Contributor on prod-rg." */}
        {(row.role_names && row.role_names.length > 0) ? (
          <div className="flex flex-wrap gap-1 max-w-[160px]">
            {row.role_names.slice(0, 2).map(rn => (
              <span
                key={rn}
                className="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-800/70 text-slate-300 border border-slate-700 truncate max-w-[140px]"
                title={rn}
              >
                {rn}
              </span>
            ))}
            {row.role_names.length > 2 && (
              <span className="text-[10px] text-slate-500" title={row.role_names.slice(2).join(', ')}>
                +{row.role_names.length - 2}
              </span>
            )}
          </div>
        ) : row.role_count > 0 ? (
          <span className="text-[10px] text-slate-500">{row.role_count} role{row.role_count !== 1 ? 's' : ''}</span>
        ) : (
          <span className="text-[10px] text-slate-600">—</span>
        )}
      </td>
      <td className="text-center px-2 py-2"><AccessBadge level={row.model_access} /></td>
      <td className="text-center px-2 py-2"><AccessBadge level={row.key_vault_access} /></td>
      <td className="text-center px-2 py-2"><AccessBadge level={row.data_access} /></td>
      <td className="text-center px-2 py-2"><AccessBadge level={row.telemetry} /></td>
      <td className="text-center px-2 py-2"><AccessBadge level={row.internet_egress} /></td>
      <td className="text-center px-2 py-2">
        <div className="relative group inline-block">
          <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold ${riskColor(row.risk_score)}`}>
            {row.risk_score}
          </span>
          {/* Risk breakdown tooltip */}
          {row.risk_dimensions && (
            <div className="absolute bottom-full right-0 mb-1 hidden group-hover:block z-50 w-48 rounded-lg border p-2 shadow-xl"
              style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-subtle)' }}
            >
              <p className="text-[10px] font-semibold text-slate-300 mb-1">Risk Breakdown</p>
              {ACCESS_CATEGORIES.map(cat => {
                const dim = row.risk_dimensions?.[cat.key];
                return dim ? (
                  <div key={cat.key} className="flex items-center justify-between text-[10px] py-0.5">
                    <span className="text-slate-400">{cat.label}</span>
                    <span className="font-mono text-slate-300">{dim.score}/10</span>
                  </div>
                ) : null;
              })}
              <div className="mt-1 pt-1 border-t flex items-center justify-between text-[10px]" style={{ borderColor: 'var(--border-subtle)' }}>
                <span className="text-slate-400 font-medium">AI Risk</span>
                <span className={`font-mono font-bold ${row.ai_risk_score >= 75 ? 'text-red-400' : row.ai_risk_score >= 50 ? 'text-orange-400' : row.ai_risk_score >= 25 ? 'text-yellow-400' : 'text-green-400'}`}>
                  {row.ai_risk_score?.toFixed(1) || '0.0'}
                </span>
              </div>
            </div>
          )}
        </div>
      </td>
      <td className="text-center px-2 py-2" onClick={e => e.stopPropagation()}>
        <button
          onClick={() => setInvestigateId(row.identity_id)}
          className="px-2 py-1 text-[10px] font-medium rounded bg-violet-900/30 text-violet-300 border border-violet-800/40 hover:bg-violet-900/50 transition"
        >
          Investigate
        </button>
      </td>
    </tr>
  );

  const tableHeader = (
    <thead>
      <tr className="border-b" style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-subtle)' }}>
        <th className="text-left px-3 py-2 text-xs font-medium text-slate-400 cursor-pointer" onClick={() => handleSort('display_name')}>
          Identity <SortIcon col="display_name" />
        </th>
        <th className="text-left px-2 py-2 text-xs font-medium text-slate-400 w-28">AI Service</th>
        <th className="text-left px-2 py-2 text-xs font-medium text-slate-400 w-40">RBAC Roles</th>
        <th className="text-center px-2 py-2 text-xs font-medium text-slate-400 cursor-pointer w-20" onClick={() => handleSort('model_access')}>
          Model <SortIcon col="model_access" />
        </th>
        <th className="text-center px-2 py-2 text-xs font-medium text-slate-400 cursor-pointer w-20" onClick={() => handleSort('key_vault_access')}>
          Key Vault <SortIcon col="key_vault_access" />
        </th>
        <th className="text-center px-2 py-2 text-xs font-medium text-slate-400 w-20">Data</th>
        <th className="text-center px-2 py-2 text-xs font-medium text-slate-400 w-20">Telemetry</th>
        <th className="text-center px-2 py-2 text-xs font-medium text-slate-400 w-20">Egress</th>
        <th className="text-center px-2 py-2 text-xs font-medium text-slate-400 cursor-pointer w-16" onClick={() => handleSort('risk_score')}>
          Risk <SortIcon col="risk_score" />
        </th>
        <th className="text-center px-2 py-2 text-xs font-medium text-slate-400 w-20">Action</th>
      </tr>
    </thead>
  );

  return (
    <div className={`p-6 mx-auto ${investigateId ? 'max-w-[1200px]' : 'max-w-[1600px]'}`}>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">AI Identity Governance</h1>
        <p className="text-sm text-slate-400 mt-1">
          Behavioral intelligence for AI agent identities — confirmed and inferred classifications
        </p>
      </div>

      {/* AG-162: Active filter chip — shown when arriving via "Most Common Roles" click or a tone-card filter */}
      {(roleFilter || metricFilter) && (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <span className="text-xs uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
            Filtered by:
          </span>
          {roleFilter && (
            <span
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border"
              style={{
                backgroundColor: 'rgba(36, 162, 161, 0.12)',
                borderColor: 'rgba(36, 162, 161, 0.4)',
                color: '#24A2A1',
              }}
            >
              Role: {roleFilter}
            </span>
          )}
          {metricFilter && (
            <span
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border"
              style={{
                backgroundColor: 'rgba(139, 92, 246, 0.12)',
                borderColor: 'rgba(139, 92, 246, 0.4)',
                color: '#a78bfa',
              }}
            >
              Has {metricFilter.replace(/_/g, ' ')}
            </span>
          )}
          <button
            onClick={clearFilters}
            className="text-xs px-2 py-1 rounded hover:bg-slate-700/40 transition"
            style={{ color: 'var(--text-tertiary)' }}
          >
            Clear filter ×
          </button>
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
            · {nhiAgents.length + humanAgents.length} match{nhiAgents.length + humanAgents.length === 1 ? '' : 'es'}
          </span>
        </div>
      )}

      {/* AG-165: KPI cards are filter affordances. Click sets the URL filter
          which `nhiAgents`/`humanAgents` already consume (see AG-162 wiring).
          Active card shows a colored ring; "Clear filter ×" chip lives above
          the table when any filter is active. */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
        {/* AI Agents (NHI) — clear all filters; humans section auto-collapsed */}
        <button
          onClick={() => { clearFilters(); setHumanSectionOpen(false); }}
          className={`rounded-lg border p-4 text-left transition hover:scale-[1.01] ${
            !roleFilter && !metricFilter && !humanSectionOpen ? 'ring-2 ring-teal-400/60' : ''
          }`}
          style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}
          title="Show all AI agents (NHI) · clear filters"
        >
          <p className="text-xs text-slate-400">AI Agents (NHI)</p>
          <p className="text-2xl font-bold mt-1 text-teal-400">{stats.agentCount}</p>
          <p className="text-[10px] text-slate-600 mt-0.5">click to view all</p>
        </button>

        {/* AI-Privileged Humans — opens the humans section */}
        <button
          onClick={() => setHumanSectionOpen(prev => !prev)}
          className={`rounded-lg border p-4 text-left transition hover:scale-[1.01] ${
            humanSectionOpen ? 'ring-2 ring-violet-400/60' : ''
          }`}
          style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}
          title="Toggle the AI-Privileged Humans section"
        >
          <p className="text-xs text-slate-400">AI-Privileged Humans</p>
          <p className="text-2xl font-bold mt-1 text-violet-400">{stats.humanCount}</p>
          <p className="text-[10px] text-slate-600 mt-0.5">{humanSectionOpen ? 'hide section' : 'click to expand'}</p>
        </button>

        {/* Avg Risk Score — sort table by risk_score DESC */}
        <button
          onClick={() => { setSortCol('risk_score'); setSortDir('desc'); }}
          className={`rounded-lg border p-4 text-left transition hover:scale-[1.01] ${
            sortCol === 'risk_score' && sortDir === 'desc' ? 'ring-2 ring-white/40' : ''
          }`}
          style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}
          title="Sort table by risk score (highest first)"
        >
          <p className="text-xs text-slate-400">Avg Risk Score</p>
          <p className="text-2xl font-bold mt-1 text-white">{stats.avgRisk}</p>
          <p className="text-[10px] text-slate-600 mt-0.5">click to sort by risk</p>
        </button>

        {/* With Model Access — filter ?filter=model_access */}
        <button
          onClick={() => {
            const next = new URLSearchParams(searchParams);
            if (metricFilter === 'model_access') next.delete('filter');
            else next.set('filter', 'model_access');
            next.delete('role');
            setSearchParams(next, { replace: true });
          }}
          className={`rounded-lg border p-4 text-left transition hover:scale-[1.01] ${
            metricFilter === 'model_access' ? 'ring-2 ring-violet-400/60' : ''
          }`}
          style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}
          title="Filter table to agents with Model Access"
        >
          <p className="text-xs text-slate-400">With Model Access</p>
          <p className="text-2xl font-bold mt-1 text-violet-400">{stats.withModel}</p>
          <p className="text-[10px] text-slate-600 mt-0.5">
            {metricFilter === 'model_access' ? '✓ filtering · click to clear' : 'click to filter'}
          </p>
        </button>

        {/* With Key Vault — filter ?filter=key_vault_access */}
        <button
          onClick={() => {
            const next = new URLSearchParams(searchParams);
            if (metricFilter === 'key_vault_access') next.delete('filter');
            else next.set('filter', 'key_vault_access');
            next.delete('role');
            setSearchParams(next, { replace: true });
          }}
          className={`rounded-lg border p-4 text-left transition hover:scale-[1.01] ${
            metricFilter === 'key_vault_access' ? 'ring-2 ring-red-400/60' : ''
          }`}
          style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}
          title="Filter table to agents with Key Vault access"
        >
          <p className="text-xs text-slate-400">With Key Vault</p>
          <p className="text-2xl font-bold mt-1 text-red-400">{stats.withKv}</p>
          <p className="text-[10px] text-slate-600 mt-0.5">
            {metricFilter === 'key_vault_access' ? '✓ filtering · click to clear' : 'click to filter'}
          </p>
        </button>
      </div>

      {/* Truncation warning */}
      {totalCount != null && totalCount > PER_PAGE && (
        <div className="mb-3 px-4 py-2 rounded-lg bg-amber-900/20 border border-amber-800/40 text-xs text-amber-300">
          Showing {PER_PAGE} of {totalCount} AI identities.
        </div>
      )}

      {/* Section A — AI Agent Identities (NHI) */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-2">
          <h2 className="text-sm font-bold text-white">AI Agent Identities</h2>
          <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-teal-900/40 text-teal-300">
            {nhiAgents.length} NHI
          </span>
        </div>
        <p className="text-[11px] text-slate-400 mb-2">
          Machine identities operating AI services — no human accountable for their actions
        </p>
        <div className="rounded-lg border overflow-hidden" style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              {tableHeader}
              <tbody>
                {sortedNhi.length === 0 && (
                  <tr><td colSpan={9} className="text-center py-8 text-sm text-slate-500">No AI agent identities found</td></tr>
                )}
                {sortedNhi.map(renderTableRow)}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Section B — AI-Privileged Humans (collapsed by default) */}
      {humanAgents.length > 0 && (
        <div>
          <button
            onClick={() => setHumanSectionOpen(o => !o)}
            className="flex items-center gap-2 mb-2 group"
          >
            <svg className={`w-4 h-4 text-slate-500 transition-transform ${humanSectionOpen ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
            <h2 className="text-sm font-bold text-white group-hover:text-violet-400">AI-Privileged Humans</h2>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-violet-900/40 text-violet-300">
              {humanAgents.length}
            </span>
          </button>

          <div className="mb-2 px-3 py-1.5 rounded-lg bg-amber-900/20 border border-amber-800/40 text-[11px] text-amber-300 inline-flex items-center gap-1.5">
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            These humans have direct access to AI services — review for least privilege
          </div>

          {humanSectionOpen && (
            <div className="rounded-lg border overflow-hidden" style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  {tableHeader}
                  <tbody>
                    {sortedHumans.map(renderTableRow)}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* AI Investigate Drawer */}
      {investigateId && (
        <AIInvestigateDrawer
          identityId={investigateId}
          onClose={() => setInvestigateId(null)}
        />
      )}
    </div>
  );
}
