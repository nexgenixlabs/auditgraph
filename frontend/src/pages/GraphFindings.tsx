import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';

// ─── Types ────────────────────────────────────────────────────────

interface PathNode {
  id: string;
  type: string;
  label: string;
  detail?: string;
}

interface AttackPath {
  id: number;
  path_id: string;
  discovery_run_id: number | null;
  source_entity_id: string;
  source_entity_name: string | null;  // Resolved via JOIN at query time
  source_entity_type: string | null;  // Resolved via JOIN at query time
  target_resource_id: string | null;
  target_resource_type: string | null;
  path_type: string;
  risk_score: number;
  severity: string;
  path_nodes: PathNode[];
  description: string;
  narrative: string | null;
  impact: string | null;
  path_length: number;
  occurrence_count: number;
  affected_resource_count: number;
  first_detected_at: string | null;
  last_detected_at: string | null;
  created_at: string;
}

interface AttackPathStats {
  total: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
}

// ─── Constants ────────────────────────────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
};

const TYPE_LABEL: Record<string, string> = {
  direct_escalation: 'Direct Escalation',
  ownership_chain: 'Ownership Chain',
  pim_escalation: 'PIM Escalation',
  lateral_movement: 'Lateral Movement',
  sensitive_data_exposure: 'Sensitive Data Exposure',
  external_identity_risk: 'External Identity Risk',
  privilege_escalation: 'Privilege Escalation',
  keyvault_secret_access: 'KeyVault Secret Access',
  spn_secret_exposure: 'SPN Secret Exposure',
  role_chaining: 'Role Chaining',
  cross_cloud_escalation: 'Cross-Cloud Escalation',
};

const TYPE_BADGE: Record<string, string> = {
  direct_escalation: 'bg-red-500/15 text-red-400 border border-red-500/25',
  ownership_chain: 'bg-purple-500/15 text-purple-400 border border-purple-500/25',
  pim_escalation: 'bg-amber-500/15 text-amber-400 border border-amber-500/25',
  lateral_movement: 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/25',
  sensitive_data_exposure: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25',
  external_identity_risk: 'bg-rose-500/15 text-rose-400 border border-rose-500/25',
  privilege_escalation: 'bg-red-500/15 text-red-400 border border-red-500/25',
  keyvault_secret_access: 'bg-purple-500/15 text-purple-400 border border-purple-500/25',
  spn_secret_exposure: 'bg-orange-500/15 text-orange-400 border border-orange-500/25',
  role_chaining: 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/25',
  cross_cloud_escalation: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25',
};

const NODE_COLOR: Record<string, string> = {
  identity: '#3b82f6',
  entra_role: '#f59e0b',
  rbac_role: '#f59e0b',
  permission: '#8b5cf6',
  target: '#ef4444',
  owned_spn: '#06b6d4',
  pim: '#d97706',
  subscription: '#6366f1',
  storage_account: '#10b981',
  key_vault: '#ec4899',
  User: '#3b82f6',
  ServicePrincipal: '#8b5cf6',
  ManagedIdentity: '#06b6d4',
  Role: '#f59e0b',
  Resource: '#10b981',
  Subscription: '#6366f1',
  KeyVault: '#ec4899',
};

const selectCls = 'bg-slate-800 border border-slate-700 text-white text-sm rounded-lg px-3 py-2 focus:ring-blue-500 focus:border-blue-500';

/** Extract the target privilege from an attack path.
 *  Prefers the resolved target_resource_id over stored path_nodes labels. */
function extractTarget(path: AttackPath): string {
  const nodes = path.path_nodes || [];
  if (nodes.length === 0) return path.target_resource_id || 'Unknown';
  const last = nodes[nodes.length - 1];
  // For conceptual targets (directory, tenant, activated_role), use the label
  // For real resources, the id is authoritative (label may be stale)
  if (last.type === 'target' || last.type === 'pim') {
    return last.label || last.id || 'Unknown';
  }
  return last.label || path.target_resource_id || last.id || 'Unknown';
}

// ─── Main Component ──────────────────────────────────────────────

export default function GraphFindings() {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [stats, setStats] = useState<AttackPathStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeResult, setAnalyzeResult] = useState<string | null>(null);

  const fetchPaths = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (severityFilter) params.set('severity', severityFilter);
      if (typeFilter) params.set('type', typeFilter);
      params.set('limit', '100');
      const res = await fetch(`/api/attack-paths?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setPaths(data.paths || []);
        setStats(data.stats || null);
      }
    } catch (err) {
      console.error('Failed to fetch attack paths:', err);
    } finally {
      setLoading(false);
    }
  }, [severityFilter, typeFilter]);

  useEffect(() => { fetchPaths(); }, [fetchPaths]);

  const runAnalysis = async () => {
    setAnalyzing(true);
    setAnalyzeResult(null);
    try {
      const res = await fetch('/api/attack-paths/analyze', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setAnalyzeResult(data.message || 'Analysis complete');
        fetchPaths();
      } else {
        const err = await res.json().catch(() => null);
        setAnalyzeResult(err?.error || `Analysis failed (${res.status})`);
      }
    } catch {
      setAnalyzeResult('Failed to trigger analysis');
    } finally {
      setAnalyzing(false);
    }
  };

  // Unique path types for filter dropdown
  const availableTypes = stats?.by_type ? Object.keys(stats.by_type) : [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Attack Paths</h1>
          <p className="text-sm text-slate-400 mt-1">
            Privilege escalation paths detected via graph analysis
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={runAnalysis}
            disabled={analyzing}
            className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white text-sm rounded-lg transition-colors disabled:opacity-50 flex items-center gap-1.5"
          >
            {analyzing ? (
              <>
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Analyzing...
              </>
            ) : (
              'Run Attack Path Analysis'
            )}
          </button>
          <button onClick={fetchPaths} className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors">
            Refresh
          </button>
        </div>
      </div>

      {/* Analysis result toast */}
      {analyzeResult && (
        <div className="flex items-center justify-between px-4 py-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-sm text-blue-300">
          <span>{analyzeResult}</span>
          <button onClick={() => setAnalyzeResult(null)} className="text-blue-500 hover:text-blue-400 text-xs ml-4">Dismiss</button>
        </div>
      )}

      {/* Stats Cards */}
      {stats && stats.total > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <MetricCard label="Total Paths" value={stats.total} color="text-white" bg="bg-slate-700/30 border-slate-600/30" />
          <MetricCard label="Critical" value={stats.by_severity?.critical || 0} color="text-red-400" bg="bg-red-500/10 border-red-500/20" />
          <MetricCard label="High" value={stats.by_severity?.high || 0} color="text-orange-400" bg="bg-orange-500/10 border-orange-500/20" />
          <MetricCard label="Medium" value={stats.by_severity?.medium || 0} color="text-yellow-400" bg="bg-yellow-500/10 border-yellow-500/20" />
          <MetricCard label="Path Types" value={Object.keys(stats.by_type || {}).length} color="text-blue-400" bg="bg-blue-500/10 border-blue-500/20" />
        </div>
      )}

      {/* Filters */}
      {stats && stats.total > 0 && (
        <div className="flex gap-3 flex-wrap">
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className={selectCls}>
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className={selectCls}>
            <option value="">All Types</option>
            {availableTypes.map(t => (
              <option key={t} value={t}>{TYPE_LABEL[t] || t}</option>
            ))}
          </select>
        </div>
      )}

      {/* Main content */}
      {loading ? (
        <div className="text-center text-slate-400 py-12">Loading attack paths...</div>
      ) : paths.length === 0 ? (
        <div className="text-center py-16 bg-slate-800/50 rounded-xl border border-slate-700/50">
          <svg className="w-16 h-16 text-slate-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
          <p className="text-lg font-medium text-slate-300">No attack paths detected</p>
          <p className="text-sm text-slate-500 mt-1 mb-6">
            Run attack path analysis to discover privilege escalation chains
          </p>
          <button
            onClick={runAnalysis}
            disabled={analyzing}
            className="px-6 py-3 bg-amber-600 hover:bg-amber-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
          >
            {analyzing ? 'Analyzing...' : 'Run Attack Path Analysis'}
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {paths.map((p) => (
            <AttackPathCard
              key={p.id}
              path={p}
              expanded={expandedId === p.id}
              onToggle={() => setExpandedId(expandedId === p.id ? null : p.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ──────────────────────────────────────────────

function MetricCard({ label, value, color, bg }: { label: string; value: string | number; color: string; bg: string }) {
  return (
    <div className={`rounded-xl p-4 border ${bg}`}>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-400 mt-1">{label}</div>
    </div>
  );
}

function AttackPathCard({ path, expanded, onToggle }: { path: AttackPath; expanded: boolean; onToggle: () => void }) {
  const target = extractTarget(path);
  const nodes = path.path_nodes || [];

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden">
      {/* Header row */}
      <button onClick={onToggle} className="w-full px-4 py-3 flex items-center gap-2 hover:bg-slate-700/30 transition-colors text-left">
        <span className={`px-2 py-0.5 text-xs font-medium rounded ${SEVERITY_BADGE[path.severity] || 'bg-slate-600 text-slate-300'}`}>
          {(path.severity || 'medium').toUpperCase()}
        </span>
        <span className={`px-2 py-0.5 text-xs font-medium rounded ${TYPE_BADGE[path.path_type] || 'bg-slate-600 text-slate-300'}`}>
          {TYPE_LABEL[path.path_type] || path.path_type}
        </span>
        <span className="text-sm text-white font-medium flex-1 truncate">{path.description}</span>
        <span className="text-xs text-slate-500 whitespace-nowrap">
          {path.path_length || nodes.length} steps
        </span>
        <span className="text-xs text-slate-500 whitespace-nowrap">
          Risk {path.risk_score}
        </span>
        {path.occurrence_count > 1 && (
          <span className="px-1.5 py-0.5 text-[10px] bg-slate-600/50 text-slate-400 rounded">
            x{path.occurrence_count}
          </span>
        )}
        <svg className={`w-4 h-4 text-slate-500 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700/50 space-y-4 mt-0">
          {/* Identity + Target summary */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
            <div className="bg-slate-900/40 rounded-lg p-3 border border-slate-700/30">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Start Identity</div>
              <Link
                to={`/identities/${path.source_entity_id}`}
                className="text-sm text-blue-400 hover:text-blue-300 hover:underline font-medium"
              >
                {path.source_entity_name || path.source_entity_id}
              </Link>
              {path.source_entity_type && (
                <div className="text-[10px] text-slate-500 mt-0.5">{path.source_entity_type.replace(/_/g, ' ')}</div>
              )}
            </div>
            <div className="bg-slate-900/40 rounded-lg p-3 border border-slate-700/30">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Target Privilege</div>
              <div className="text-sm text-red-400 font-medium">{target}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">
                Risk Score: {path.risk_score} / Path Length: {path.path_length || nodes.length}
              </div>
            </div>
          </div>

          {/* Path nodes visualization */}
          {nodes.length > 0 && (
            <div>
              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">
                Attack Path ({nodes.length} nodes)
              </div>
              <div className="bg-slate-900/60 rounded-lg p-4 overflow-x-auto">
                <div className="flex items-center gap-2 min-w-max">
                  {nodes.map((node, idx) => (
                    <React.Fragment key={`${node.id}-${idx}`}>
                      <div
                        className="flex flex-col items-center gap-1 px-3 py-2 rounded-lg border min-w-[100px]"
                        style={{
                          borderColor: NODE_COLOR[node.type] || '#64748b',
                          backgroundColor: `${NODE_COLOR[node.type] || '#64748b'}15`,
                        }}
                      >
                        <span
                          className="text-[10px] font-mono uppercase tracking-wider"
                          style={{ color: NODE_COLOR[node.type] || '#94a3b8' }}
                        >
                          {node.type.replace(/_/g, ' ')}
                        </span>
                        <span className="text-xs text-white font-medium max-w-[160px] truncate text-center" title={node.label}>
                          {node.label || node.id}
                        </span>
                        {node.detail && (
                          <span className="text-[9px] text-slate-500 max-w-[160px] truncate" title={node.detail}>
                            {node.detail}
                          </span>
                        )}
                      </div>
                      {idx < nodes.length - 1 && (
                        <svg className="w-5 h-3 text-slate-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 20 12">
                          <path d="M0 6h16m0 0l-4-4m4 4l-4 4" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Narrative */}
          {path.narrative && (
            <div>
              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Attack Narrative</div>
              <p className="text-sm text-slate-300 leading-relaxed">{path.narrative}</p>
            </div>
          )}

          {/* Impact */}
          {path.impact && (
            <div>
              <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Impact</div>
              <p className="text-sm text-red-400/90 bg-red-500/10 rounded-lg px-3 py-2 border border-red-500/20">
                {path.impact}
              </p>
            </div>
          )}

          {/* Metadata footer */}
          <div className="flex flex-wrap gap-4 text-[10px] text-slate-600 pt-2 border-t border-slate-700/30">
            {path.first_detected_at && (
              <span>First detected: {new Date(path.first_detected_at).toLocaleString()}</span>
            )}
            {path.last_detected_at && (
              <span>Last seen: {new Date(path.last_detected_at).toLocaleString()}</span>
            )}
            {path.affected_resource_count > 0 && (
              <span>Affected resources: {path.affected_resource_count}</span>
            )}
            {path.discovery_run_id && (
              <span>Run #{path.discovery_run_id}</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
