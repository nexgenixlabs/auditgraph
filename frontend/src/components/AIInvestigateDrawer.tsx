/**
 * AIInvestigateDrawer — Right-side drawer for AI agent investigation.
 *
 * 7 sections:
 *  1. Identity Summary
 *  2. Permission Intelligence
 *  3. Blast Radius
 *  4. Evidence Chain
 *  5. AI Permission Graph
 *  6. Attack Path Preview
 *  7. Remediation Recommendations
 */
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import {
  formatAccessLevel,
  accessLevelBadge,
  ACCESS_CATEGORIES,
  formatPlatform,
  confidenceLabel,
  confidenceColor,
} from '../constants/aiRisk';

interface AIInvestigateDrawerProps {
  identityId: string | null;
  onClose: () => void;
}

function riskColor(score: number): string {
  if (score >= 75) return 'text-red-400';
  if (score >= 50) return 'text-orange-400';
  if (score >= 25) return 'text-yellow-400';
  return 'text-green-400';
}

function riskBg(score: number): string {
  if (score >= 75) return 'bg-red-900/40 border-red-800/40';
  if (score >= 50) return 'bg-orange-900/40 border-orange-800/40';
  if (score >= 25) return 'bg-yellow-900/40 border-yellow-800/40';
  return 'bg-green-900/40 border-green-800/40';
}

function severityBadge(level: string | null): string {
  const map: Record<string, string> = {
    critical: 'bg-red-900/40 text-red-300 border-red-800/40',
    high: 'bg-orange-900/40 text-orange-300 border-orange-800/40',
    medium: 'bg-yellow-900/40 text-yellow-300 border-yellow-800/40',
    low: 'bg-green-900/40 text-green-300 border-green-800/40',
  };
  return map[(level || '').toLowerCase()] || 'bg-slate-800 text-slate-400 border-slate-700';
}

interface InvestigateData {
  summary: any;
  permissions: any;
  blast_radius: any;
  evidence: any;
  graph: any;
  attack_paths: any[];
  remediation: any;
}

export default function AIInvestigateDrawer({ identityId, onClose }: AIInvestigateDrawerProps) {
  const { withConnection } = useConnection();
  const navigate = useNavigate();
  const [data, setData] = useState<InvestigateData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    summary: true,
    permissions: true,
    blast_radius: false,
    evidence: false,
    graph: false,
    attack_paths: false,
    remediation: true,
  });

  useEffect(() => {
    if (!identityId) return;
    setLoading(true);
    setError(null);
    fetch(withConnection(`/api/ai-agents/${encodeURIComponent(identityId)}/investigate`))
      .then(r => {
        if (!r.ok) throw new Error('Failed to load investigation data');
        return r.json();
      })
      .then(d => setData(d))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [identityId, withConnection]);

  const toggleSection = (key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  if (!identityId) return null;

  const SectionHeader = ({ id, title, badge }: { id: string; title: string; badge?: React.ReactNode }) => (
    <button
      onClick={() => toggleSection(id)}
      className="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-slate-800/50 transition-colors"
    >
      <svg
        className={`w-3.5 h-3.5 text-slate-500 transition-transform ${expandedSections[id] ? 'rotate-90' : ''}`}
        fill="none" stroke="currentColor" viewBox="0 0 24 24"
      >
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
      </svg>
      <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</span>
      {badge}
    </button>
  );

  return (
    <div className="fixed inset-y-0 right-0 w-[480px] z-40 flex flex-col border-l"
      style={{ backgroundColor: 'var(--bg-deep)', borderColor: 'var(--border-subtle)', top: 'var(--header-height, 56px)' }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
        <div className="flex items-center gap-2 min-w-0">
          <div className="w-7 h-7 rounded-lg bg-violet-900/40 flex items-center justify-center flex-shrink-0">
            <svg className="w-4 h-4 text-violet-400" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 8V4H8" />
              <rect x="4" y="8" width="16" height="12" rx="2" />
              <path d="M15 13v2" />
              <path d="M9 13v2" />
            </svg>
          </div>
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-white truncate">
              {loading ? 'Loading...' : data?.summary?.display_name || 'AI Investigation'}
            </h2>
            <p className="text-[10px] text-slate-500">AI Identity Investigation</p>
          </div>
        </div>
        <div className="flex items-center gap-1">
          {data?.summary && (
            <button
              onClick={() => navigate(`/identities/${encodeURIComponent(identityId)}`)}
              className="px-2 py-1 text-[10px] font-medium rounded bg-blue-900/30 text-blue-300 border border-blue-800/40 hover:bg-blue-900/50 transition"
            >
              Full Detail
            </button>
          )}
          <button onClick={onClose} className="p-1.5 rounded hover:bg-slate-800 transition-colors">
            <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="flex items-center justify-center py-20">
            <div className="animate-spin h-6 w-6 border-2 border-violet-500 border-t-transparent rounded-full" />
          </div>
        )}

        {error && (
          <div className="p-4 text-sm text-red-400">{error}</div>
        )}

        {data && !loading && (
          <>
            {/* 1. Identity Summary */}
            <SectionHeader id="summary" title="Identity Summary" />
            {expandedSections.summary && (
              <div className="px-4 pb-3 space-y-2">
                <div className="grid grid-cols-2 gap-2">
                  <div className="rounded-lg border p-2.5" style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
                    <p className="text-[10px] text-slate-500">Risk Score</p>
                    <p className={`text-lg font-bold ${riskColor(data.summary.risk_score)}`}>{data.summary.risk_score}</p>
                  </div>
                  <div className="rounded-lg border p-2.5" style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
                    <p className="text-[10px] text-slate-500">Risk Level</p>
                    <span className={`inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-semibold border ${severityBadge(data.summary.risk_level)}`}>
                      {(data.summary.risk_level || 'Unknown').toUpperCase()}
                    </span>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-slate-500">Category: </span>
                    <span className="text-slate-300">{data.summary.identity_category || 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Privilege: </span>
                    <span className="text-slate-300">{data.summary.privilege_tier || 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Owner: </span>
                    <span className="text-slate-300">{data.summary.owner_display_name || 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Credentials: </span>
                    <span className="text-slate-300">{data.summary.credential_count}</span>
                  </div>
                </div>
                {data.summary.classification && (
                  <div className="mt-1 flex items-center gap-2 text-xs">
                    <span className="px-1.5 py-0.5 rounded bg-violet-900/30 text-violet-300 border border-violet-800/40 text-[10px] font-medium">
                      {formatPlatform(data.summary.classification.platform)}
                    </span>
                    <span className={`text-[10px] ${confidenceColor(data.summary.classification.confidence)}`}>
                      {confidenceLabel(data.summary.classification.confidence)} confidence ({Math.round(data.summary.classification.confidence * 100)}%)
                    </span>
                  </div>
                )}
              </div>
            )}

            {/* 2. Permission Intelligence */}
            <SectionHeader id="permissions" title="Permission Intelligence"
              badge={
                <span className="ml-auto text-[10px] font-mono text-slate-500">{data.permissions.role_count} roles</span>
              }
            />
            {expandedSections.permissions && (
              <div className="px-4 pb-3 space-y-2">
                {/* Access level badges */}
                <div className="grid grid-cols-1 gap-1.5">
                  {ACCESS_CATEGORIES.map(cat => {
                    const level = data.permissions.access_levels?.[cat.key] || 'none';
                    const dim = data.permissions.risk_dimensions?.[cat.key];
                    return (
                      <div key={cat.key} className="flex items-center justify-between rounded-lg border px-3 py-2"
                        style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
                      >
                        <div className="flex items-center gap-2">
                          <svg className="w-3.5 h-3.5" style={{ color: cat.color }} fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                            <path d={cat.icon} />
                          </svg>
                          <span className="text-xs text-slate-400">{cat.label}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${accessLevelBadge(level)}`}>
                            {formatAccessLevel(level)}
                          </span>
                          {dim && (
                            <span className="text-[10px] font-mono text-slate-500">{dim.score}/10</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
                {/* AI Risk Score */}
                <div className="flex items-center justify-between rounded-lg border px-3 py-2"
                  style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
                >
                  <span className="text-xs font-medium text-slate-300">AI Risk Score</span>
                  <span className={`text-sm font-bold ${riskColor(data.permissions.ai_risk_score || 0)}`}>
                    {data.permissions.ai_risk_score?.toFixed(1) || '0.0'}
                  </span>
                </div>
              </div>
            )}

            {/* 3. Blast Radius */}
            <SectionHeader id="blast_radius" title="Blast Radius"
              badge={
                data.blast_radius.reachable_resource_count > 0 ? (
                  <span className={`ml-auto px-1.5 py-0.5 rounded text-[10px] font-semibold border ${severityBadge(data.blast_radius.identity_exposure_level)}`}>
                    {data.blast_radius.identity_exposure_level || 'Unknown'}
                  </span>
                ) : undefined
              }
            />
            {expandedSections.blast_radius && (
              <div className="px-4 pb-3">
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { label: 'Reachable Resources', value: data.blast_radius.reachable_resource_count },
                    { label: 'Subscriptions', value: data.blast_radius.reachable_subscription_count },
                    { label: 'Sensitive Resources', value: data.blast_radius.sensitive_resource_count },
                    { label: 'Priv Escalation Paths', value: data.blast_radius.privilege_escalation_paths },
                  ].map(item => (
                    <div key={item.label} className="rounded-lg border p-2" style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
                      <p className="text-[10px] text-slate-500">{item.label}</p>
                      <p className="text-sm font-bold text-slate-200">{item.value ?? 0}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 4. Evidence Chain */}
            <SectionHeader id="evidence" title="Evidence Chain"
              badge={
                <span className="ml-auto text-[10px] font-mono text-slate-500">{data.evidence.signal_count} signal{data.evidence.signal_count !== 1 ? 's' : ''}</span>
              }
            />
            {expandedSections.evidence && (
              <div className="px-4 pb-3 space-y-1.5">
                {data.evidence.signals.map((signal: any, i: number) => (
                  <div key={i} className="rounded-lg border px-3 py-2" style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
                    <div className="flex items-center gap-2 mb-1">
                      {signal.is_primary && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-violet-900/40 text-violet-300 border border-violet-800/40">PRIMARY</span>
                      )}
                      <span className="text-[10px] text-slate-500">{signal.signal_type?.replace(/_/g, ' ')}</span>
                      <span className={`ml-auto text-[10px] ${confidenceColor(signal.confidence)}`}>
                        {Math.round(signal.confidence * 100)}%
                      </span>
                    </div>
                    <p className="text-xs text-slate-300">{signal.evidence_text}</p>
                  </div>
                ))}
                {data.evidence.signals.length === 0 && (
                  <p className="text-xs text-slate-500 py-2">No classification evidence available</p>
                )}
              </div>
            )}

            {/* 5. AI Permission Graph */}
            <SectionHeader id="graph" title="AI Permission Graph"
              badge={
                <span className="ml-auto text-[10px] font-mono text-slate-500">{data.graph.node_count} nodes</span>
              }
            />
            {expandedSections.graph && (
              <div className="px-4 pb-3">
                {data.graph.node_count > 0 ? (
                  <div className="space-y-1">
                    {data.graph.nodes.slice(0, 15).map((node: any) => (
                      <div key={node.id} className="flex items-center gap-2 rounded px-2 py-1.5 text-xs"
                        style={{ backgroundColor: 'var(--bg-surface)' }}
                      >
                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${
                          node.type === 'identity' ? 'bg-violet-400' :
                          node.type === 'role' ? 'bg-blue-400' : 'bg-teal-400'
                        }`} />
                        <span className="text-slate-300 truncate">{node.data?.label || 'Unknown'}</span>
                        <span className="ml-auto text-[10px] text-slate-500">{node.type}</span>
                      </div>
                    ))}
                    {data.graph.node_count > 15 && (
                      <p className="text-[10px] text-slate-500 pl-2">+{data.graph.node_count - 15} more nodes</p>
                    )}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 py-2">No graph data available</p>
                )}
              </div>
            )}

            {/* 6. Attack Path Preview */}
            <SectionHeader id="attack_paths" title="Attack Paths"
              badge={
                data.attack_paths.length > 0 ? (
                  <span className="ml-auto px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-900/40 text-red-300 border border-red-800/40">
                    {data.attack_paths.length}
                  </span>
                ) : undefined
              }
            />
            {expandedSections.attack_paths && (
              <div className="px-4 pb-3 space-y-1.5">
                {data.attack_paths.map((ap: any, i: number) => (
                  <div key={i} className="rounded-lg border px-3 py-2" style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
                    <div className="flex items-center justify-between mb-1">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold border ${severityBadge(ap.severity)}`}>
                        {(ap.severity || 'Unknown').toUpperCase()}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">Score: {ap.risk_score ?? 0}</span>
                    </div>
                    <p className="text-xs text-slate-300 truncate">
                      {ap.source_display_name || 'Source'} → {ap.target_display_name || 'Target'}
                    </p>
                    {ap.technique_name && (
                      <p className="text-[10px] text-slate-500 mt-0.5">{ap.technique_id}: {ap.technique_name}</p>
                    )}
                  </div>
                ))}
                {data.attack_paths.length === 0 && (
                  <p className="text-xs text-slate-500 py-2">No attack paths detected</p>
                )}
              </div>
            )}

            {/* 7. Remediation Recommendations */}
            <SectionHeader id="remediation" title="Remediation"
              badge={
                data.remediation.actions.length > 0 ? (
                  <span className={`ml-auto px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                    data.remediation.priority === 'p0' ? 'bg-red-900/40 text-red-300 border-red-800/40' :
                    data.remediation.priority === 'p1' ? 'bg-orange-900/40 text-orange-300 border-orange-800/40' :
                    'bg-slate-800 text-slate-400 border-slate-700'
                  }`}>
                    {data.remediation.priority.toUpperCase()}
                  </span>
                ) : undefined
              }
            />
            {expandedSections.remediation && (
              <div className="px-4 pb-3 space-y-1.5">
                {data.remediation.actions.map((action: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 rounded-lg border px-3 py-2"
                    style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
                  >
                    <span className={`mt-0.5 px-1.5 py-0.5 rounded text-[9px] font-semibold border flex-shrink-0 ${
                      action.priority === 0 ? 'bg-red-900/40 text-red-300 border-red-800/40' :
                      action.priority === 1 ? 'bg-orange-900/40 text-orange-300 border-orange-800/40' :
                      'bg-slate-800 text-slate-400 border-slate-700'
                    }`}>
                      P{action.priority}
                    </span>
                    <div className="min-w-0">
                      <p className="text-xs text-slate-300">{action.description}</p>
                      {action.auto_fixable && (
                        <span className="text-[9px] text-teal-400 mt-0.5 inline-block">Auto-fixable</span>
                      )}
                    </div>
                  </div>
                ))}
                {data.remediation.actions.length === 0 && (
                  <p className="text-xs text-slate-500 py-2">No remediation actions required</p>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
