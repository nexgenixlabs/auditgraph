/**
 * AIIdentityGraph — Force-directed graph of AI agent identities and their permissions.
 *
 * Fetches enriched agent data and renders an interactive graph
 * showing identities → roles → resources relationships.
 */
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { formatPlatform, formatAccessLevel, accessLevelBadge } from '../constants/aiRisk';
import AIInvestigateDrawer from '../components/AIInvestigateDrawer';

interface GraphAgent {
  identity_id: string;
  display_name: string;
  identity_category: string;
  risk_score: number;
  detected_platform: string;
  model_access: string;
  key_vault_access: string;
  data_access: string;
  ai_risk_score: number;
  role_count: number;
}

export default function AIIdentityGraph() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [agents, setAgents] = useState<GraphAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [investigateId, setInvestigateId] = useState<string | null>(null);
  const [filterPlatform, setFilterPlatform] = useState<string>('all');

  useEffect(() => {
    setLoading(true);
    fetch(withConnection('/api/ai-agents/enriched?include_possible=true&per_page=200'))
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d?.items) setAgents(d.items);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [withConnection, selectedConnectionId]);

  const platforms = useMemo(() => {
    const set = new Set<string>();
    agents.forEach(a => { if (a.detected_platform) set.add(a.detected_platform); });
    return Array.from(set).sort();
  }, [agents]);

  const filtered = useMemo(() => {
    if (filterPlatform === 'all') return agents;
    return agents.filter(a => a.detected_platform === filterPlatform);
  }, [agents, filterPlatform]);

  // Risk-based size
  const nodeSize = (score: number) => Math.max(36, Math.min(72, 36 + score * 0.4));
  const riskRing = (score: number) => {
    if (score >= 75) return '#ef4444';
    if (score >= 50) return '#f97316';
    if (score >= 25) return '#eab308';
    return '#22c55e';
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center py-20">
          <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-[1600px] mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">AI Identity Graph</h1>
        <p className="text-sm text-slate-400 mt-1">
          Visual map of AI agent identities — size reflects risk score, color indicates severity
        </p>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 mb-6">
        <select
          value={filterPlatform}
          onChange={e => setFilterPlatform(e.target.value)}
          className="px-3 py-1.5 rounded-lg border text-xs text-slate-300"
          style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}
        >
          <option value="all">All Platforms</option>
          {platforms.map(p => (
            <option key={p} value={p}>{formatPlatform(p)}</option>
          ))}
        </select>
        <span className="text-xs text-slate-500">{filtered.length} identities</span>
      </div>

      {/* Graph visualization — bubble layout */}
      <div className="rounded-lg border p-6 min-h-[500px] relative"
        style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}
      >
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-[400px] text-slate-500 text-sm">
            No AI agent identities found
          </div>
        ) : (
          <div className="flex flex-wrap gap-4 justify-center items-center">
            {filtered.map((agent) => {
              const size = nodeSize(agent.risk_score);
              return (
                <button
                  key={agent.identity_id}
                  onClick={() => setInvestigateId(agent.identity_id)}
                  className="flex flex-col items-center gap-1 group transition-transform hover:scale-105"
                  title={`${agent.display_name}\nRisk: ${agent.risk_score}\nPlatform: ${formatPlatform(agent.detected_platform)}`}
                >
                  <div
                    className="rounded-full flex items-center justify-center border-2 transition-shadow group-hover:shadow-lg"
                    style={{
                      width: size,
                      height: size,
                      borderColor: riskRing(agent.risk_score),
                      backgroundColor: 'var(--bg-elevated)',
                    }}
                  >
                    <span className="text-xs font-bold text-white">{agent.risk_score}</span>
                  </div>
                  <span className="text-[10px] text-slate-400 truncate max-w-[100px] text-center">
                    {agent.display_name}
                  </span>
                  <span className="text-[9px] text-slate-600">
                    {formatPlatform(agent.detected_platform)}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-6 mt-4 text-[10px] text-slate-500">
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full border-2" style={{ borderColor: '#ef4444' }} /> Critical
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full border-2" style={{ borderColor: '#f97316' }} /> High
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full border-2" style={{ borderColor: '#eab308' }} /> Medium
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full border-2" style={{ borderColor: '#22c55e' }} /> Low
        </div>
        <span className="text-slate-600">|</span>
        <span>Node size = risk score</span>
      </div>

      {/* Investigate drawer */}
      {investigateId && (
        <AIInvestigateDrawer
          identityId={investigateId}
          onClose={() => setInvestigateId(null)}
        />
      )}
    </div>
  );
}
