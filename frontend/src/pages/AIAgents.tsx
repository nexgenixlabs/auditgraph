import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { TIME_MS } from '../constants/metrics';

interface RoleSummary {
  total_roles: number;
  never_used: number;
  stale_90d: number;
  last_role_active: string | null;
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
  activity_status: string;
  effective_last_active: string | null;
  activity_detection_source: string | null;
  last_activity_confidence: string | null;
  dormancy_status: string | null;
  blast_radius_score: number;
  owner_display_name: string | null;
  credential_count: number;
  credential_risk: string;
  privilege_tier: string;
  additional_subscription_count: number;
  agent_penalty_score: number;
  agent_penalty_reason: string;
  role_summary: RoleSummary;
}

const NHI_CATEGORIES = new Set(['service_principal', 'managed_identity_system', 'managed_identity_user', 'app', 'workload']);

const CATEGORY_LABELS: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'System MSI',
  managed_identity_user: 'User MSI',
  human_user: 'Human',
  guest: 'Guest',
};

function formatLastActive(d: string | null, _source: string): string {
  if (!d) {
    return 'Not observed (log-independent)';
  }
  const dt = new Date(d);
  const days = Math.round((Date.now() - dt.getTime()) / TIME_MS.DAY);
  const absolute = dt.toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: 'numeric', minute: '2-digit',
  });
  let relative: string;
  if (days <= 0) relative = 'Today';
  else if (days === 1) relative = '1d ago';
  else if (days < 30) relative = `${days}d ago`;
  else if (days < 365) relative = `${Math.floor(days / 30)}mo ago`;
  else relative = `${Math.floor(days / 365)}y ago`;
  return `${relative} · ${absolute}`;
}

function riskColor(score: number): string {
  if (score >= 80) return 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300';
  if (score >= 60) return 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300';
  if (score >= 40) return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300';
  return 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300';
}

function formatPlatform(p: string | null): string {
  if (!p) return '\u2014';
  const map: Record<string, string> = {
    openai: 'OpenAI',
    azure_openai: 'Azure OpenAI',
    azure_ai: 'Azure AI',
    azure_cognitive: 'Azure Cognitive',
    azure_ml: 'Azure ML',
    azure_ai_studio: 'Azure AI Studio',
    anthropic: 'Anthropic',
    copilot_studio: 'Copilot Studio',
    power_virtual_agents: 'Power VA',
    bot_framework: 'Bot Framework',
  };
  return map[p] || p.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function roleSummaryText(rs: RoleSummary): string {
  if (!rs || rs.total_roles === 0) return '0 roles';
  const parts = [`${rs.total_roles} role${rs.total_roles !== 1 ? 's' : ''}`];
  if (rs.never_used > 0) parts.push(`${rs.never_used} never used`);
  if (rs.stale_90d > 0) parts.push(`${rs.stale_90d} used >90d ago`);
  if (rs.never_used === 0 && rs.stale_90d === 0 && !rs.last_role_active) {
    parts.push('activity via ARM snapshot');
  }
  return parts.join(' \u00b7 ');
}

type SortKey = 'display_name' | 'classification_confidence' | 'detected_platform' | 'risk_score' | 'effective_last_active' | 'credential_count';

export default function AIAgents() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  const [items, setItems] = useState<AgentRow[]>([]);
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortCol, setSortCol] = useState<SortKey>('risk_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [humanSectionOpen, setHumanSectionOpen] = useState(false);

  const PER_PAGE = 500;

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(withConnection(`/api/agent-identities?include_possible=true&per_page=${PER_PAGE}`))
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

  // Split into Section A (NHI agents) and Section B (AI-privileged humans)
  const { nhiAgents, humanAgents } = useMemo(() => {
    const nhi: AgentRow[] = [];
    const human: AgentRow[] = [];
    for (const item of items) {
      if (item.agent_identity_type === 'ai_privileged_human' || item.identity_category === 'human_user') {
        human.push(item);
      } else if (NHI_CATEGORIES.has(item.identity_category) || item.agent_identity_type === 'ai_agent' || item.agent_identity_type === 'possible_ai_agent') {
        nhi.push(item);
      }
    }
    return { nhiAgents: nhi, humanAgents: human };
  }, [items]);

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
    return { agentCount, humanCount, avgRisk };
  }, [nhiAgents, humanAgents]);

  const handleSort = (col: SortKey) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
  };

  const SortIcon = ({ col }: { col: string }) => (
    <span className="ml-1 text-gray-400">{sortCol === col ? (sortDir === 'asc' ? '\u2191' : '\u2193') : '\u21C5'}</span>
  );

  if (loading) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto">
        <div className="flex items-center justify-center py-20">
          <div className="animate-spin h-8 w-8 border-2 border-blue-600 border-t-transparent rounded-full" />
        </div>
      </div>
    );
  }

  if (error === 'not_found') {
    return (
      <div className="p-6 max-w-[1400px] mx-auto">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">AI Identity Governance</h1>
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-10 text-center mt-6">
          <div className="w-14 h-14 mx-auto mb-4 rounded-full bg-gray-100 dark:bg-slate-800 flex items-center justify-center">
            <svg className="w-7 h-7 text-gray-400 dark:text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Feature Not Enabled</h3>
          <p className="text-sm text-gray-500 dark:text-slate-400 max-w-md mx-auto">
            AI Identity classification requires a discovery scan with agent detection enabled.
            Run a discovery scan to populate this view.
          </p>
        </div>
      </div>
    );
  }

  const renderTableRow = (row: AgentRow) => (
    <tr key={row.identity_id}
      className="border-b border-gray-100 dark:border-slate-800 hover:bg-gray-50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors"
      onClick={() => navigate(`/identities/${encodeURIComponent(row.identity_id)}`)}>
      <td className="px-3 py-2">
        <div className="font-medium text-gray-800 dark:text-slate-200 truncate max-w-[260px]" title={row.display_name}>{row.display_name}</div>
        <div className="text-[10px] text-gray-400 dark:text-slate-500">{CATEGORY_LABELS[row.identity_category] || row.identity_category}</div>
        {/* Role mini-summary */}
        {!!row.role_summary && row.role_summary.total_roles > 0 && (
          <div className="text-[10px] text-gray-500 dark:text-slate-500 mt-0.5">
            {roleSummaryText(row.role_summary)}
          </div>
        )}
      </td>
      <td className="px-2 py-2">
        <span className="text-xs text-gray-600 dark:text-slate-300">{formatPlatform(row.detected_platform)}</span>
      </td>
      <td className="text-center px-2 py-2">
        <span className="text-xs font-mono text-gray-700 dark:text-slate-300">
          {row.classification_confidence != null ? `${Math.round(row.classification_confidence * 100)}%` : '\u2014'}
        </span>
      </td>
      <td className="px-2 py-2 whitespace-nowrap">
        {row.effective_last_active ? (
          <>
            <div className="text-xs text-gray-600 dark:text-slate-300">
              {formatLastActive(row.effective_last_active, row.activity_detection_source || '')}
            </div>
            <div className="text-[9px] text-gray-400 dark:text-slate-500">
              {row.activity_detection_source || 'AuditGraph snapshot'}
            </div>
          </>
        ) : row.dormancy_status === 'Active' ? (
          <>
            <div className="text-xs text-gray-600 dark:text-slate-300">Active (no date)</div>
            <div className="text-[9px] text-gray-400 dark:text-slate-500">ARM deployment observed</div>
          </>
        ) : (
          <>
            <div className="text-xs text-gray-500 dark:text-slate-400">Not observed</div>
            <div className="text-[9px] text-gray-400 dark:text-slate-500">Log-independent — role exists = access exists</div>
          </>
        )}
      </td>
      <td className="text-center px-2 py-2">
        <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold ${riskColor(row.risk_score)}`}>
          {row.risk_score}
        </span>
      </td>
      <td className="text-center px-2 py-2" onClick={e => e.stopPropagation()}>
        <button
          onClick={() => navigate(`/identities/${encodeURIComponent(row.identity_id)}`)}
          className="px-2 py-1 text-[10px] font-medium rounded bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300 border border-blue-200 dark:border-blue-800/40 hover:bg-blue-100 dark:hover:bg-blue-900/50 transition"
        >
          Investigate
        </button>
      </td>
    </tr>
  );

  const tableHeader = (
    <thead>
      <tr className="bg-gray-50 dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700">
        <th className="text-left px-3 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer" onClick={() => handleSort('display_name')}>
          Identity <SortIcon col="display_name" />
        </th>
        <th className="text-left px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-28" onClick={() => handleSort('detected_platform')}>
          AI Service <SortIcon col="detected_platform" />
        </th>
        <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-24" onClick={() => handleSort('classification_confidence')}>
          Confidence <SortIcon col="classification_confidence" />
        </th>
        <th className="text-left px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-36" onClick={() => handleSort('effective_last_active')}>
          Last Role Active <SortIcon col="effective_last_active" />
        </th>
        <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-20" onClick={() => handleSort('risk_score')}>
          Risk <SortIcon col="risk_score" />
        </th>
        <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-24">Action</th>
      </tr>
    </thead>
  );

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">AI Identity Governance</h1>
        <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">
          Behavioral intelligence for AI agent identities — confirmed and inferred classifications
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-6">
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-4">
          <p className="text-xs text-gray-500 dark:text-slate-400">AI Agent Identities (NHI)</p>
          <p className="text-2xl font-bold mt-1 text-teal-600 dark:text-teal-400">{stats.agentCount}</p>
        </div>
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-4">
          <p className="text-xs text-gray-500 dark:text-slate-400">AI-Privileged Humans</p>
          <p className="text-2xl font-bold mt-1 text-violet-600 dark:text-violet-400">{stats.humanCount}</p>
        </div>
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-4">
          <p className="text-xs text-gray-500 dark:text-slate-400">Avg Risk Score (NHI)</p>
          <p className="text-2xl font-bold mt-1 text-gray-900 dark:text-white">{stats.avgRisk}</p>
        </div>
      </div>

      {/* Truncation warning */}
      {totalCount != null && totalCount > PER_PAGE && (
        <div className="mb-3 px-4 py-2 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/40 text-xs text-amber-700 dark:text-amber-300">
          Showing {PER_PAGE} of {totalCount} AI identities.
        </div>
      )}

      {/* Section A — AI Agent Identities (NHI) */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-2">
          <h2 className="text-sm font-bold text-gray-900 dark:text-white">AI Agent Identities</h2>
          <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-300">
            {nhiAgents.length} NHI
          </span>
        </div>
        <p className="text-[11px] text-gray-500 dark:text-slate-400 mb-2">
          Machine identities operating AI services — no human accountable for their actions
        </p>
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 overflow-hidden">
          <table className="w-full text-sm">
            {tableHeader}
            <tbody>
              {sortedNhi.length === 0 && (
                <tr><td colSpan={6} className="text-center py-8 text-sm text-gray-400 dark:text-slate-500">No AI agent identities found</td></tr>
              )}
              {sortedNhi.map(renderTableRow)}
            </tbody>
          </table>
        </div>
      </div>

      {/* Section B — AI-Privileged Humans (collapsed by default) */}
      {humanAgents.length > 0 && (
        <div>
          <button
            onClick={() => setHumanSectionOpen(o => !o)}
            className="flex items-center gap-2 mb-2 group"
          >
            <svg className={`w-4 h-4 text-gray-500 transition-transform ${humanSectionOpen ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
            <h2 className="text-sm font-bold text-gray-900 dark:text-white group-hover:text-violet-700">AI-Privileged Humans</h2>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-violet-100 text-violet-700 dark:bg-violet-900/40 dark:text-violet-300">
              {humanAgents.length}
            </span>
          </button>

          {/* Warning badge */}
          <div className="mb-2 px-3 py-1.5 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/40 text-[11px] text-amber-700 dark:text-amber-300 inline-flex items-center gap-1.5">
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            These humans have direct access to AI services — review for least privilege
          </div>

          {humanSectionOpen && (
            <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 overflow-hidden">
              <table className="w-full text-sm">
                {tableHeader}
                <tbody>
                  {sortedHumans.map(renderTableRow)}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
