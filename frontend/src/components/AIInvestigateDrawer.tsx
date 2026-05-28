/**
 * AIInvestigateDrawer — Right-side drawer for AI agent investigation.
 *
 * Sections:
 *  1. Identity Summary
 *  2. Permission Intelligence
 *  2b. Actual Access (30d)               — AG-167: AI Runtime Phase 1
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

// Phase 1.5: CVSS-aligned 0–10 color mapping (matches AI Inventory legend)
function cvssColor(score: number): string {
  if (score >= 9.0) return 'text-red-400';
  if (score >= 7.0) return 'text-orange-400';
  if (score >= 4.0) return 'text-yellow-400';
  if (score >= 0.1) return 'text-green-400';
  return 'text-slate-500';
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

// AG-167: separate fetch for actual-access (runtime telemetry).
interface ActualAccessResource {
  role_name: string;
  scope: string;
  resource_type: string;
  last_used_at: string | null;
  in_window: boolean;
}
interface ActualAccessData {
  identity: { identity_id: string; display_name: string; last_sign_in: string | null; last_activity_date: string | null };
  window_days: number;
  resources_touched: ActualAccessResource[];
  coverage: {
    roles_total: number;
    roles_with_usage_data: number;
    roles_used_in_window: number;
    window_days: number;
    // Reframed per no-logs principle: architecture-derived, telemetry optional
    architecture_sources: string[];
    telemetry_optional: string[];
    notice: string;
  };
}

export default function AIInvestigateDrawer({ identityId, onClose }: AIInvestigateDrawerProps) {
  const { withConnection } = useConnection();
  const navigate = useNavigate();
  const [data, setData] = useState<InvestigateData | null>(null);
  const [actual, setActual] = useState<ActualAccessData | null>(null);  // AG-167
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    summary: true,
    permissions: true,
    signal_breakdown: true,  // Phase 1.5: open by default — answers "why is this score what it is"
    actual_access: true,  // AG-167: open by default — this is the "moat" section
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
    // AG-167: side fetch — actual access. Failure is non-fatal (panel just shows nothing).
    setActual(null);
    fetch(withConnection(`/api/ai-agents/${encodeURIComponent(identityId)}/actual-access`))
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setActual(d as ActualAccessData); })
      .catch(() => {});
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
            {/* 1. Identity Summary — Phase 1.5: CVSS score is canonical */}
            <SectionHeader id="summary" title="Identity Summary" />
            {expandedSections.summary && (
              <div className="px-4 pb-3 space-y-2">
                {/* Canonical AI risk: CVSS-aligned 0–10 score from signal-sum model (AG-164) */}
                <div className="grid grid-cols-2 gap-2">
                  <div className="rounded-lg border p-2.5"
                    style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
                    title="CVSS v3.1-aligned 0–10 score. Computed from signal-sum model citing NIST SP 800-53 + MITRE ATT&CK per signal.">
                    <p className="text-[10px] text-slate-500">AI Risk · CVSS 0–10</p>
                    <p className={`text-lg font-bold ${cvssColor(data.permissions?.cvss_score ?? 0)}`}>
                      {(data.permissions?.cvss_score ?? 0).toFixed(1)}
                    </p>
                    <p className="text-[9px] text-slate-600 mt-0.5">{data.permissions?.signal_breakdown?.length || 0} signals fired</p>
                  </div>
                  <div className="rounded-lg border p-2.5"
                    style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
                    <p className="text-[10px] text-slate-500">Severity</p>
                    <span className={`inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-semibold border ${severityBadge(data.permissions?.cvss_severity || data.summary.risk_level)}`}>
                      {(data.permissions?.cvss_severity || data.summary.risk_level || 'Unknown').toUpperCase()}
                    </span>
                    <p className="text-[9px] text-slate-600 mt-0.5">CVSS v3.1 band</p>
                  </div>
                </div>
                {/* Legacy scores — kept visible as a footnote for users who knew the old numbers */}
                <p className="text-[9px] text-slate-600 italic">
                  Legacy scores · platform risk: {data.summary.risk_score} · dimensional AI score: {(data.permissions?.ai_risk_score ?? 0).toFixed(1)}
                </p>
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
                {/* Access level badges — Phase 1.7: now shows WHICH resources behind each category */}
                <div className="grid grid-cols-1 gap-1.5">
                  {ACCESS_CATEGORIES.map(cat => {
                    const level = data.permissions.access_levels?.[cat.key] || 'none';
                    const dim = data.permissions.risk_dimensions?.[cat.key];
                    const resources: any[] = data.permissions.resources_by_category?.[cat.key] || [];
                    return (
                      <div key={cat.key} className="rounded-lg border px-3 py-2"
                        style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
                      >
                        <div className="flex items-center justify-between">
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
                        {/* Phase 1.7: list the actual resources this category is rooted in. */}
                        {resources.length > 0 && (
                          <div className="mt-1.5 pt-1.5 border-t flex flex-wrap gap-1"
                            style={{ borderColor: 'var(--border-subtle)' }}>
                            {resources.slice(0, 4).map((r, i) => (
                              <span key={i}
                                className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
                                style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-deep)' }}
                                title={`${r.resource_type}: ${r.resource_name}\nRole: ${r.role_name}`}
                              >
                                {r.resource_type === 'Subscription' || r.resource_type === 'Resource Group' || r.resource_type === 'Tenant Root'
                                  ? `${r.resource_type}`
                                  : `${r.resource_type}: ${r.resource_name}`}
                              </span>
                            ))}
                            {resources.length > 4 && (
                              <span className="text-[10px] text-slate-500">+{resources.length - 4} more</span>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

                {/* Phase 2.2: Network Exposure — egress verdict derived from each
                    touched resource's architecture (firewall / Private Endpoint /
                    public access). No logs. */}
                {data.permissions.network_exposure && data.permissions.network_exposure.resources_evaluated > 0 && (
                  <div className="rounded-lg border p-3 mt-2"
                    style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
                    <div className="flex items-center justify-between mb-2">
                      <p className="text-[10px] font-semibold uppercase tracking-wider"
                        style={{ color: 'var(--text-tertiary)' }}>
                        Network Exposure
                      </p>
                      {(() => {
                        const sev = data.permissions.network_exposure.worst_egress_severity;
                        const colorMap: Record<string, string> = {
                          concerning: '#f87171', borderline: '#fbbf24', healthy: '#4ade80', unknown: '#9ca3af',
                        };
                        const c = colorMap[sev] || '#9ca3af';
                        return (
                          <span className="text-[10px] font-semibold px-2 py-0.5 rounded border"
                            style={{ color: c, borderColor: `${c}55`, backgroundColor: `${c}1a` }}>
                            {data.permissions.network_exposure.worst_egress_verdict}
                          </span>
                        );
                      })()}
                    </div>
                    <div className="space-y-1">
                      {data.permissions.network_exposure.by_resource.map((r: any, i: number) => {
                        const colorMap: Record<string, string> = {
                          concerning: '#f87171', borderline: '#fbbf24', healthy: '#4ade80', unknown: '#9ca3af',
                        };
                        const c = colorMap[r.severity] || '#9ca3af';
                        return (
                          <div key={i} className="flex items-center justify-between gap-2 text-[11px]">
                            <span className="font-mono truncate max-w-[210px]" style={{ color: 'var(--text-secondary)' }}
                              title={r.resource_id}>
                              {r.resource_type}: {r.resource_name}
                            </span>
                            <span className="text-[10px] whitespace-nowrap" style={{ color: c }}>
                              {r.verdict}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                    <p className="text-[9px] mt-2 pt-1.5 border-t" style={{ color: 'var(--text-tertiary)', borderColor: 'var(--border-subtle)' }}>
                      Derived from resource network config (firewall / Private Endpoint / public access) — no logs required.
                    </p>
                  </div>
                )}

                {/* Phase 2.1: Models Reachable — which LLM deployments this agent can invoke,
                    derived from RBAC scope → Cognitive Services account → deployments (no logs). */}
                {data.permissions.model_deployments && data.permissions.model_deployments.length > 0 && (
                  <div className="rounded-lg border p-3 mt-2"
                    style={{ borderColor: 'rgba(139, 92, 246, 0.3)', backgroundColor: 'rgba(139, 92, 246, 0.06)' }}>
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-2"
                      style={{ color: '#a78bfa' }}>
                      Models Reachable ({data.permissions.model_deployments.length})
                    </p>
                    <div className="space-y-1.5">
                      {data.permissions.model_deployments.map((m: any, i: number) => (
                        <div key={i} className="flex items-center justify-between gap-2 text-[11px]">
                          <div className="min-w-0">
                            <span className="font-semibold font-mono" style={{ color: 'var(--text-primary)' }}>
                              {m.model_name}{m.model_version ? ` (${m.model_version})` : ''}
                            </span>
                            <span className="text-[10px] ml-2" style={{ color: 'var(--text-tertiary)' }}>
                              deployment: {m.deployment_name} · {m.account_name}
                            </span>
                          </div>
                          {m.sku_capacity != null && (
                            <span className="text-[9px] font-mono whitespace-nowrap px-1.5 py-0.5 rounded border"
                              style={{ color: '#a78bfa', borderColor: 'rgba(139, 92, 246, 0.35)' }}
                              title="Provisioned throughput (capacity) — higher = larger blast radius">
                              {m.sku_name || 'cap'}: {m.sku_capacity}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Phase 1.7: Resources Touched — grouped by type, distinct list across all roles */}
                {data.permissions.resources_by_type && data.permissions.resources_by_type.length > 0 && (
                  <div className="rounded-lg border p-3 mt-2"
                    style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-2"
                      style={{ color: 'var(--text-tertiary)' }}>
                      Resources Touched
                    </p>
                    <div className="space-y-1.5">
                      {data.permissions.resources_by_type.map((group: any) => (
                        <div key={group.resource_type}>
                          <p className="text-[10px] font-semibold" style={{ color: 'var(--text-secondary)' }}>
                            {group.resource_type} <span className="font-mono text-slate-500">({group.resources.length})</span>
                          </p>
                          <ul className="ml-2 mt-0.5 space-y-0.5">
                            {group.resources.slice(0, 5).map((r: any, i: number) => (
                              <li key={i} className="text-[11px] flex items-center gap-2"
                                style={{ color: 'var(--text-primary)' }}>
                                <span className="font-mono truncate max-w-[200px]">{r.resource_name}</span>
                                <span className="text-[9px] truncate" style={{ color: 'var(--text-tertiary)' }}>
                                  via {r.role_names.slice(0, 2).join(', ')}{r.role_names.length > 2 ? ` +${r.role_names.length - 2}` : ''}
                                </span>
                              </li>
                            ))}
                            {group.resources.length > 5 && (
                              <li className="text-[10px] text-slate-500 ml-2">+{group.resources.length - 5} more</li>
                            )}
                          </ul>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {/* Phase 1.5: legacy dimensional AI Risk Score — kept as a sub-metric */}
                <div className="flex items-center justify-between rounded-lg border px-3 py-2"
                  style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
                >
                  <span className="text-xs font-medium text-slate-300">Dimensional AI Risk (0–100)</span>
                  <span className={`text-sm font-bold ${riskColor(data.permissions.ai_risk_score || 0)}`}>
                    {data.permissions.ai_risk_score?.toFixed(1) || '0.0'}
                  </span>
                </div>
              </div>
            )}

            {/* Phase 1.5: Risk Breakdown — fired signals with NIST / CVSS / MITRE refs */}
            <SectionHeader id="signal_breakdown" title="Risk Breakdown"
              badge={
                <span className="ml-auto px-1.5 py-0.5 rounded text-[10px] font-mono"
                  style={{ color: '#a78bfa', backgroundColor: 'rgba(139, 92, 246, 0.12)', border: '1px solid rgba(139, 92, 246, 0.3)' }}>
                  {data.permissions?.signal_breakdown?.length || 0} signals
                </span>
              }
            />
            {expandedSections.signal_breakdown && (
              <div className="px-4 pb-3 space-y-2">
                {!data.permissions?.signal_breakdown?.length ? (
                  <p className="text-xs text-emerald-400/80 py-2 text-center">
                    ✓ No risk signals fired for this identity
                  </p>
                ) : (
                  data.permissions.signal_breakdown.map((s: any, i: number) => (
                    <div key={i} className="rounded-lg border p-3 space-y-1.5"
                      style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>{s.title}</p>
                          {s.evidence && (
                            <p className="text-[10px] mt-0.5 font-mono truncate" style={{ color: 'var(--text-tertiary)' }} title={s.evidence}>
                              {s.evidence}
                            </p>
                          )}
                        </div>
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded whitespace-nowrap"
                          style={{ color: '#fbbf24', backgroundColor: 'rgba(245, 158, 11, 0.12)', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
                          +{s.weight}
                        </span>
                      </div>
                      <p className="text-[10px] leading-snug" style={{ color: 'var(--text-secondary)' }}>
                        {s.rationale}
                      </p>
                      {/* Standards chips */}
                      <div className="flex flex-wrap gap-1 mt-1.5">
                        {(s.mitre || []).map((m: string) => (
                          <span key={`m-${m}`} className="text-[9px] font-mono px-1.5 py-0.5 rounded border"
                            style={{ color: '#a78bfa', borderColor: 'rgba(139, 92, 246, 0.35)', backgroundColor: 'rgba(139, 92, 246, 0.08)' }}
                            title={`MITRE ATT&CK ${m}`}>
                            {m}
                          </span>
                        ))}
                        {(s.nist || []).map((n: string) => (
                          <span key={`n-${n}`} className="text-[9px] font-mono px-1.5 py-0.5 rounded border"
                            style={{ color: '#60a5fa', borderColor: 'rgba(59, 130, 246, 0.35)', backgroundColor: 'rgba(59, 130, 246, 0.08)' }}
                            title={`NIST SP 800-53: ${n}`}>
                            NIST · {n.split(' ')[0]}
                          </span>
                        ))}
                        {s.cvss_vector && (
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border"
                            style={{ color: '#4ade80', borderColor: 'rgba(34, 197, 94, 0.35)', backgroundColor: 'rgba(34, 197, 94, 0.08)' }}
                            title={s.cvss_vector}>
                            CVSS
                          </span>
                        )}
                      </div>
                      {s.remediation && (
                        <p className="text-[10px] mt-1.5 pt-1.5 border-t leading-snug"
                          style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-subtle)' }}>
                          <span className="font-semibold" style={{ color: '#4ade80' }}>Fix: </span>{s.remediation}
                        </p>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}

            {/* AG-167: Actual Access (Runtime Phase 1) — what the agent is REALLY touching */}
            <SectionHeader id="actual_access" title="Actual Access (30d)"
              badge={
                actual ? (
                  <span className="ml-auto px-1.5 py-0.5 rounded text-[10px] font-semibold border bg-teal-900/40 text-teal-300 border-teal-800/40">
                    {actual.coverage.roles_used_in_window} active · {actual.coverage.roles_with_usage_data}/{actual.coverage.roles_total} with telemetry
                  </span>
                ) : (
                  <span className="ml-auto px-1.5 py-0.5 rounded text-[10px] text-slate-500 border border-slate-700/40">loading…</span>
                )
              }
            />
            {expandedSections.actual_access && actual && (
              <div className="px-4 pb-3 space-y-2.5">
                {/* Coverage notice — reframed: architecture-derived (always
                    available); telemetry is optional confirmation only. */}
                <div className="rounded-lg border p-2.5 text-[10px] leading-snug"
                  style={{
                    borderColor: 'rgba(36, 162, 161, 0.3)',
                    backgroundColor: 'rgba(36, 162, 161, 0.06)',
                  }}
                  title={actual.coverage.notice}
                >
                  <div className="font-semibold mb-1" style={{ color: '#24A2A1' }}>
                    Architecture-derived access
                  </div>
                  <div style={{ color: 'var(--text-secondary)' }}>{actual.coverage.notice}</div>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {(actual.coverage.architecture_sources || []).map(s => (
                      <span key={s} className="px-1.5 py-0.5 rounded border text-[9px] font-mono"
                        style={{ color: '#24A2A1', borderColor: 'rgba(36, 162, 161, 0.45)', backgroundColor: 'rgba(36, 162, 161, 0.08)' }}
                        title="Always-available source — read from the cloud control plane">
                        ✓ {s}
                      </span>
                    ))}
                    {(actual.coverage.telemetry_optional || []).map(s => (
                      <span key={s} className="px-1.5 py-0.5 rounded border text-[9px] font-mono"
                        style={{ color: '#94a3b8', borderColor: 'rgba(148, 163, 184, 0.3)', backgroundColor: 'rgba(148, 163, 184, 0.06)' }}
                        title="Optional source — if your tenant has it configured we surface confirmation timestamps">
                        ○ {s} (optional)
                      </span>
                    ))}
                  </div>
                </div>

                {/* Resources touched list */}
                {actual.resources_touched.length === 0 ? (
                  <p className="text-xs text-slate-500 py-2">No role-usage telemetry available for this identity.</p>
                ) : (
                  <div className="space-y-1">
                    {actual.resources_touched.slice(0, 12).map((r, i) => (
                      <div key={i}
                        className="rounded px-2.5 py-1.5 text-[11px] border"
                        style={{
                          borderColor: r.in_window ? 'rgba(36, 162, 161, 0.3)' : 'var(--border-subtle)',
                          backgroundColor: r.in_window ? 'rgba(36, 162, 161, 0.06)' : 'var(--bg-surface)',
                        }}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold truncate" style={{ color: 'var(--text-primary)' }}>{r.role_name}</span>
                          {r.last_used_at ? (
                            <span className="text-[10px] font-mono whitespace-nowrap"
                              style={{ color: r.in_window ? '#24A2A1' : 'var(--text-tertiary)' }}>
                              {new Date(r.last_used_at).toLocaleDateString()}
                            </span>
                          ) : (
                            <span className="text-[9px] uppercase text-slate-600">no telemetry</span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-[9px] uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>{r.resource_type}</span>
                          <span className="text-[10px] truncate" style={{ color: 'var(--text-secondary)' }} title={r.scope}>
                            {r.scope.split('/').slice(-2).join('/') || r.scope}
                          </span>
                        </div>
                      </div>
                    ))}
                    {actual.resources_touched.length > 12 && (
                      <p className="text-[10px] text-slate-500 pl-2">+{actual.resources_touched.length - 12} more roles</p>
                    )}
                  </div>
                )}
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
                  // Phase 1.7: honest empty state. A high CVSS score does NOT
                  // mean an attack path will exist — these are pattern-matched
                  // multi-step paths. The Risk Breakdown section above is the
                  // primary risk view; attack paths are a complementary lens.
                  <div className="rounded-lg border border-dashed p-3 text-[11px] leading-snug"
                    style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)', color: 'var(--text-tertiary)' }}>
                    <p className="font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>
                      ✓ No attack paths detected for this identity
                    </p>
                    <p>
                      Attack paths are <em>multi-step</em> exploitation patterns the engine has matched
                      (e.g. SPN → privileged role → cross-tenant scope). Absence does not imply low risk —
                      review the Risk Breakdown above for direct findings that warrant action regardless.
                    </p>
                  </div>
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
