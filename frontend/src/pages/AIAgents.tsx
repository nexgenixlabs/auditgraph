import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';

interface AgentRow {
  id: number;
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
  blast_radius_score: number;
  owner_display_name: string | null;
  credential_count: number;
  credential_risk: string;
  privilege_tier: string;
  additional_subscription_count: number;
  agent_penalty_score: number;
  agent_penalty_reason: string;
}

const CATEGORY_LABELS: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'System MSI',
  managed_identity_user: 'User MSI',
  human_user: 'Human',
  guest: 'Guest',
};

function formatRelativeTime(d: string | null): string {
  if (!d) return 'Never';
  const days = Math.round((Date.now() - new Date(d).getTime()) / 86400000);
  if (days <= 0) return 'Today';
  if (days === 1) return '1d ago';
  if (days < 30) return `${days}d ago`;
  if (days < 365) return `${Math.floor(days / 30)}mo ago`;
  return `${Math.floor(days / 365)}y ago`;
}

function riskColor(score: number): string {
  if (score >= 80) return 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300';
  if (score >= 60) return 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300';
  if (score >= 40) return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300';
  return 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300';
}

function credColor(count: number, risk: string): string {
  if (risk === 'critical' || risk === 'high') return 'text-red-600 dark:text-red-400';
  if (count > 3) return 'text-orange-500 dark:text-orange-400';
  return 'text-gray-600 dark:text-slate-300';
}

function formatPlatform(p: string | null): string {
  if (!p) return '—';
  const map: Record<string, string> = {
    openai: 'OpenAI',
    azure_openai: 'Azure OpenAI',
    anthropic: 'Anthropic',
    google_ai: 'Google AI',
    aws_bedrock: 'AWS Bedrock',
    huggingface: 'Hugging Face',
    langchain: 'LangChain',
    semantic_kernel: 'Semantic Kernel',
    copilot: 'Copilot',
  };
  return map[p] || p.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

type SortKey = 'display_name' | 'agent_identity_type' | 'classification_confidence' | 'detected_platform' | 'risk_score' | 'effective_last_active' | 'credential_count';

export default function AIAgents() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  const [items, setItems] = useState<AgentRow[]>([]);
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortCol, setSortCol] = useState<SortKey>('risk_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

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

  const sorted = useMemo(() => {
    const copy = [...items];
    copy.sort((a, b) => {
      const rawA = (a as Record<string, any>)[sortCol];
      const rawB = (b as Record<string, any>)[sortCol];
      // Date columns: compare as timestamps
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
  }, [items, sortCol, sortDir]);

  const stats = useMemo(() => {
    const confirmed = items.filter(i => i.agent_identity_type === 'ai_agent').length;
    const inferred = items.filter(i => i.agent_identity_type === 'possible_ai_agent').length;
    const avgRisk = items.length > 0
      ? Math.round(items.reduce((s, i) => s + (i.risk_score || 0), 0) / items.length)
      : 0;
    return { confirmed, inferred, avgRisk };
  }, [items]);

  const handleSort = (col: SortKey) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
  };

  const SortIcon = ({ col }: { col: string }) => (
    <span className="ml-1 text-gray-400">{sortCol === col ? (sortDir === 'asc' ? '↑' : '↓') : '↕'}</span>
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
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">AI Agent Identity Governance</h1>
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-10 text-center mt-6">
          <div className="w-14 h-14 mx-auto mb-4 rounded-full bg-gray-100 dark:bg-slate-800 flex items-center justify-center">
            <svg className="w-7 h-7 text-gray-400 dark:text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Feature Not Enabled</h3>
          <p className="text-sm text-gray-500 dark:text-slate-400 max-w-md mx-auto">
            AI Agent classification requires a discovery scan with agent detection enabled.
            Run a discovery scan to populate this view.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">AI Agent Identity Governance</h1>
        <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">
          Behavioral intelligence for AI agent identities — confirmed and inferred classifications
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-6">
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-4">
          <p className="text-xs text-gray-500 dark:text-slate-400">Confirmed AI Agents</p>
          <p className="text-2xl font-bold mt-1 text-teal-600 dark:text-teal-400">{stats.confirmed}</p>
        </div>
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-4">
          <p className="text-xs text-gray-500 dark:text-slate-400">Inferred AI Agents</p>
          <p className="text-2xl font-bold mt-1 text-amber-600 dark:text-amber-400">{stats.inferred}</p>
        </div>
        <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-4">
          <p className="text-xs text-gray-500 dark:text-slate-400">Avg Risk Score</p>
          <p className="text-2xl font-bold mt-1 text-gray-900 dark:text-white">{stats.avgRisk}</p>
        </div>
      </div>

      {/* Truncation warning */}
      {totalCount != null && totalCount > PER_PAGE && (
        <div className="mb-3 px-4 py-2 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/40 text-xs text-amber-700 dark:text-amber-300">
          Showing {PER_PAGE} of {totalCount} AI agent identities.
        </div>
      )}

      {/* Table */}
      <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700">
              <th className="text-left px-3 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer" onClick={() => handleSort('display_name')}>
                Identity <SortIcon col="display_name" />
              </th>
              <th className="text-left px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-28" onClick={() => handleSort('agent_identity_type')}>
                Type <SortIcon col="agent_identity_type" />
              </th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-24" onClick={() => handleSort('classification_confidence')}>
                Confidence <SortIcon col="classification_confidence" />
              </th>
              <th className="text-left px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-28" onClick={() => handleSort('detected_platform')}>
                AI Service <SortIcon col="detected_platform" />
              </th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-20">Scope</th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-24" onClick={() => handleSort('credential_count')}>
                Credentials <SortIcon col="credential_count" />
              </th>
              <th className="text-left px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-24" onClick={() => handleSort('effective_last_active')}>
                Last Active <SortIcon col="effective_last_active" />
              </th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 cursor-pointer w-20" onClick={() => handleSort('risk_score')}>
                Risk <SortIcon col="risk_score" />
              </th>
              <th className="text-center px-2 py-2 text-xs font-medium text-gray-500 dark:text-slate-400 w-24">Action</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 && (
              <tr><td colSpan={9} className="text-center py-8 text-sm text-gray-400 dark:text-slate-500">No AI agent identities found</td></tr>
            )}
            {sorted.map(row => (
              <tr key={row.id}
                className="border-b border-gray-100 dark:border-slate-800 hover:bg-gray-50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors"
                onClick={() => navigate(`/identities/${row.id}`)}>
                <td className="px-3 py-2">
                  <div className="font-medium text-gray-800 dark:text-slate-200 truncate max-w-[280px]" title={row.display_name}>{row.display_name}</div>
                  <div className="text-[10px] text-gray-400 dark:text-slate-500">{CATEGORY_LABELS[row.identity_category] || row.identity_category}</div>
                </td>
                <td className="px-2 py-2">
                  {row.agent_identity_type === 'ai_agent' ? (
                    <span className="inline-block px-2 py-0.5 rounded text-[10px] font-semibold bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-300">Confirmed</span>
                  ) : (
                    <span className="inline-block px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300">Inferred</span>
                  )}
                </td>
                <td className="text-center px-2 py-2">
                  <span className="text-xs font-mono text-gray-700 dark:text-slate-300">
                    {row.classification_confidence != null ? `${Math.round(row.classification_confidence * 100)}%` : '—'}
                  </span>
                </td>
                <td className="px-2 py-2">
                  <span className="text-xs text-gray-600 dark:text-slate-300">{formatPlatform(row.detected_platform)}</span>
                </td>
                <td className="text-center px-2 py-2">
                  {row.additional_subscription_count > 0 ? (
                    <span className="text-xs text-gray-700 dark:text-slate-300">+{row.additional_subscription_count} sub{row.additional_subscription_count !== 1 ? 's' : ''}</span>
                  ) : (
                    <span className="text-xs text-gray-400 dark:text-slate-500">1 sub</span>
                  )}
                </td>
                <td className="text-center px-2 py-2">
                  <span className={`text-xs font-medium ${credColor(row.credential_count, row.credential_risk)}`}>
                    {row.credential_count}
                  </span>
                </td>
                <td className="px-2 py-2 whitespace-nowrap">
                  <span className="text-xs text-gray-500 dark:text-slate-400">{formatRelativeTime(row.effective_last_active)}</span>
                </td>
                <td className="text-center px-2 py-2">
                  <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold ${riskColor(row.risk_score)}`}>
                    {row.risk_score}
                  </span>
                </td>
                <td className="text-center px-2 py-2" onClick={e => e.stopPropagation()}>
                  <button
                    onClick={() => navigate(`/identities/${row.id}`)}
                    className="px-2 py-1 text-[10px] font-medium rounded bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300 border border-blue-200 dark:border-blue-800/40 hover:bg-blue-100 dark:hover:bg-blue-900/50 transition"
                  >
                    Investigate
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
