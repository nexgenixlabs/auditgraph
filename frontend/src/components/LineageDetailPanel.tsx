import React, { useEffect, useState } from 'react';
import { useConnection } from '../contexts/ConnectionContext';

/* ────────────────────────────────────────────────────────────────────────────
 * LineageDetailPanel — Verdict-first identity lineage slide-out panel
 *
 * Fetches from GET /api/identities/{id}/lineage (unified endpoint).
 * Shows: Verdict header, Origin, Evidence signals, App Registration,
 * Connection Source, Sign-in Activity, Dependency Impact, Risk Flags,
 * Recommended Action.
 * ──────────────────────────────────────────────────────────────────────────── */

interface Props {
  identity: { identity_id: string; display_name: string };
  onClose: () => void;
  onBackToDetail?: () => void;
}

// Unified lineage response subset needed by this panel
interface LineageSignal {
  type: 'ARM' | 'FEDERATED' | 'HEURISTIC' | 'ROLE' | 'SIGNIN' | 'OWNER' | 'OBSERVED' | 'INFERRED';
  label: string;
  value: string;
  confidence: 'high' | 'medium' | 'low';
}

interface LineageResponse {
  identity_id: string;
  display_name: string;
  workload_origin: {
    origin: string;
    source: string;
    workload_type: string | null;
    workload_confidence: number;
    is_discovery_connector: boolean;
  };
  confidence: {
    level: string;
    score: number;
    enrichment_tier: string;
    signals: Array<{ source: string; weight: number; detail: string }>;
  };
  dependency_impact: {
    level: string;
    resources: Array<{ resource_name: string; resource_type: string; impact_level: string }>;
    statement: string;
    total_bound: number;
  };
  recommended_action: {
    action: string;
    action_text: string;
    orphan_status: string;
    risk_summary: string[];
    active_role_count: number;
  };
  app_registration: {
    object_id: string | null;
    display_name: string;
    is_external: boolean;
    publisher_domain: string | null;
    sign_in_audience: string | null;
    owners: Array<{ display_name: string; id?: string }>;
    likely_service: string | null;
    reply_url_hostnames: string[];
    notes: string;
    required_apis: string[] | null;
    created_at: string | null;
  } | null;
  sign_in: {
    pattern: string;
    dormancy_days: number;
    last_sign_in: string | null;
  } | null;
  // Effective last used (MAX of observed + Azure sign-in)
  effective_last_used?: string | null;
  effective_last_used_source?: 'auditgraph' | 'azure_signin' | 'inferred_federated' | null;
  // Human-readable lineage (executive display)
  lineage_signals?: LineageSignal[];
  lineage_narrative?: string;
  lineage_warnings?: string[];
}

// ── Verdict badge config ─────────────────────────────────────────────────────

const VERDICT_BADGE: Record<string, { label: string; cls: string; icon: string }> = {
  ORPHANED:                { label: 'Orphaned',                cls: 'bg-red-100 text-red-700',       icon: '\u26a0\ufe0f' },
  GHOST_MSI:               { label: 'Ghost MSI',               cls: 'bg-purple-100 text-purple-700', icon: '\ud83d\udc7b' },
  FEDERATED_MISCONFIGURED: { label: 'Federated Misconfigured', cls: 'bg-orange-100 text-orange-700', icon: '\ud83d\udd17' },
  AT_RISK:                 { label: 'At Risk',                 cls: 'bg-amber-100 text-amber-700',   icon: '\u26a0' },
  STALE:                   { label: 'Stale',                   cls: 'bg-amber-100 text-amber-700',   icon: '\u23f3' },
  UNUSED:                  { label: 'Unused',                  cls: 'bg-gray-100 text-gray-600',     icon: '\u2013' },
  NEEDS_REVIEW:            { label: 'Needs Review',            cls: 'bg-blue-100 text-blue-700',     icon: '\ud83d\udd0d' },
  HEALTHY:                 { label: 'Healthy',                 cls: 'bg-green-100 text-green-700',   icon: '\u2713' },
};

const CONFIDENCE_DOT: Record<string, string> = {
  high:   'bg-green-500',
  medium: 'bg-amber-500',
  low:    'bg-red-400',
};

const SIGNAL_TYPE_BADGE: Record<string, { icon: string; cls: string }> = {
  ARM:       { icon: '\u2693',   cls: 'bg-blue-100 text-blue-700 border-blue-300' },
  FEDERATED: { icon: '\ud83d\udd17', cls: 'bg-purple-100 text-purple-700 border-purple-300' },
  HEURISTIC: { icon: '\ud83d\udd0d', cls: 'bg-indigo-100 text-indigo-700 border-indigo-300' },
  ROLE:      { icon: '\ud83d\udee1\ufe0f', cls: 'bg-teal-100 text-teal-700 border-teal-300' },
  SIGNIN:    { icon: '\ud83d\udcca', cls: 'bg-green-100 text-green-700 border-green-300' },
  OWNER:     { icon: '\ud83d\udc64', cls: 'bg-gray-100 text-gray-600 border-gray-300' },
  OBSERVED:  { icon: '\ud83d\udccd', cls: 'bg-emerald-100 text-emerald-700 border-emerald-300' },
  INFERRED:  { icon: '\u2728', cls: 'bg-purple-100 text-purple-700 border-purple-300' },
};

const CONFIDENCE_LABEL: Record<string, { cls: string }> = {
  high:   { cls: 'text-green-600' },
  medium: { cls: 'text-amber-600' },
  low:    { cls: 'text-gray-400' },
};

const SIGNIN_BADGE: Record<string, { label: string; cls: string }> = {
  machine_only:                { label: 'Machine Only',                cls: 'bg-blue-100 text-blue-700' },
  human_delegated_only:        { label: 'Human Delegated Only',        cls: 'bg-green-100 text-green-700' },
  hybrid_concurrent:           { label: 'Hybrid Concurrent',           cls: 'bg-red-100 text-red-700' },
  hybrid_delegated_recent:     { label: 'Hybrid — Delegated Recent',   cls: 'bg-amber-100 text-amber-700' },
  hybrid_noninteractive_recent:{ label: 'Hybrid — Non-Interactive Recent', cls: 'bg-purple-100 text-purple-700' },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(iso: string): string {
  try { return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }); }
  catch { return iso; }
}

function Row({ label, value, valueClass }: { label: string; value: React.ReactNode; valueClass?: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-gray-500 text-xs">{label}</span>
      <span className={`text-xs font-medium truncate max-w-[220px] ${valueClass || 'text-gray-700'}`}>{value}</span>
    </div>
  );
}

// ── Component ────────────────────────────────────────────────────────────────

export default function LineageDetailPanel({ identity: identityProp, onClose, onBackToDetail }: Props) {
  const { withConnection } = useConnection();
  const [data, setData] = useState<LineageResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // ESC to close
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  // Fetch from unified lineage endpoint
  useEffect(() => {
    if (!identityProp.identity_id) return;
    setLoading(true);
    const abort = new AbortController();
    fetch(withConnection(`/api/identities/${identityProp.identity_id}/lineage`), { signal: abort.signal })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setData(d); setLoading(false); })
      .catch(e => { if (e.name !== 'AbortError') setLoading(false); });
    return () => abort.abort();
  }, [identityProp.identity_id, withConnection]);

  // Loading state
  if (loading) {
    return (
      <div className="fixed inset-0 z-50 flex justify-end">
        <div className="absolute inset-0 bg-black/20" onClick={onClose} />
        <div className="relative w-[420px] bg-white shadow-2xl border-l border-gray-200 flex items-center justify-center">
          <div className="animate-spin h-6 w-6 border-2 border-blue-600 border-t-transparent rounded-full" />
        </div>
      </div>
    );
  }

  // Fallback if fetch failed
  if (!data) {
    return (
      <div className="fixed inset-0 z-50 flex justify-end">
        <div className="absolute inset-0 bg-black/20" onClick={onClose} />
        <div className="relative w-[420px] bg-white shadow-2xl border-l border-gray-200 flex flex-col">
          <div className="px-5 py-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
            <h3 className="text-sm font-bold text-gray-900">{identityProp.display_name}</h3>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-lg font-bold p-1">{'\u00d7'}</button>
          </div>
          <div className="flex-1 flex items-center justify-center">
            <p className="text-xs text-gray-400">No lineage data available.</p>
          </div>
        </div>
      </div>
    );
  }

  const action = data.recommended_action.action || 'NEEDS_REVIEW';
  const badge = VERDICT_BADGE[action] || VERDICT_BADGE.NEEDS_REVIEW;
  const confidence = data.confidence.level || 'low';
  const score = data.confidence.score ?? 0;
  const riskSummary = data.recommended_action.risk_summary || [];
  const appReg = data.app_registration;
  const lineageSignals = data.lineage_signals || [];
  const lineageNarrative = data.lineage_narrative || '';
  const lineageWarnings = data.lineage_warnings || [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/20" onClick={onClose} />

      {/* Panel */}
      <div className="relative w-[440px] bg-white shadow-2xl border-l border-gray-200 flex flex-col animate-slide-in-right overflow-y-auto">

        {/* ── Header: AuditGraph Identity Lineage ─────────────────── */}
        <div className="px-5 py-4 border-b border-gray-200 bg-gradient-to-r from-gray-50 to-white shrink-0">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-2">
              {onBackToDetail && (
                <button onClick={onBackToDetail} className="text-gray-400 hover:text-blue-600 text-xs mr-1" title="Back to detail">
                  {'\u2190'}
                </button>
              )}
              <div>
                <div className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">AuditGraph Identity Lineage</div>
                <h3 className="text-sm font-bold text-gray-900 mt-0.5 truncate max-w-[320px]">{data.display_name}</h3>
              </div>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-lg font-bold p-1">{'\u00d7'}</button>
          </div>

          {/* Verdict badge + confidence + score */}
          <div className="flex items-center gap-2 mt-2">
            <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold ${badge.cls}`}>
              <span>{badge.icon}</span> {badge.label}
            </span>
            <span className="flex items-center gap-1 text-[10px] text-gray-500">
              <span className={`inline-block w-2 h-2 rounded-full ${CONFIDENCE_DOT[confidence] || CONFIDENCE_DOT.low}`} />
              {confidence} confidence
            </span>
            <span className="text-[10px] font-bold text-gray-500 ml-auto">{score}/100</span>
          </div>
          <div className="mt-1.5 w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${score >= 60 ? 'bg-green-500' : score >= 30 ? 'bg-amber-500' : 'bg-red-400'}`}
              style={{ width: `${score}%` }}
            />
          </div>
        </div>

        <div className="px-5 py-4 space-y-4 text-sm">

          {/* ── Section 1: Lineage Signals (CRITICAL — top of panel) ── */}
          {lineageSignals.length > 0 && (
            <div>
              <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">Lineage Signals</div>
              <div className="space-y-2">
                {lineageSignals.map((sig, idx) => {
                  const typeBadge = SIGNAL_TYPE_BADGE[sig.type] || SIGNAL_TYPE_BADGE.ROLE;
                  const confLabel = CONFIDENCE_LABEL[sig.confidence] || CONFIDENCE_LABEL.low;
                  return (
                    <div key={idx} className={`flex items-start gap-2.5 px-3 py-2 rounded-lg border ${typeBadge.cls}`}>
                      <span className="text-sm mt-0.5 flex-shrink-0">{typeBadge.icon}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] font-bold uppercase tracking-wide">{sig.label}:</span>
                          <span className={`text-[9px] font-medium ${confLabel.cls}`}>{sig.confidence}</span>
                        </div>
                        <div className="text-xs text-gray-700 mt-0.5 leading-relaxed" title={sig.value}>
                          {sig.value}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ── Section 2: Warning Badges ────────────────────────── */}
          {lineageWarnings.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {lineageWarnings.map((w, idx) => (
                <span key={idx} className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-bold bg-red-50 text-red-700 border border-red-200">
                  <span className="text-red-500">[!]</span> {w}
                </span>
              ))}
            </div>
          )}

          {/* ── Section 3: Narrative ──────────────────────────────── */}
          {!!lineageNarrative && (
            <div className="px-3 py-3 rounded-lg bg-slate-50 border border-slate-200">
              <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1.5">Analysis</div>
              <p className="text-xs text-slate-700 leading-relaxed">{lineageNarrative}</p>
            </div>
          )}

          {/* ── Section 4: Verdict Block ─────────────────────────── */}
          <div className={`px-3 py-3 rounded-lg border-2 ${
            action === 'ORPHANED' ? 'bg-red-50 border-red-300' :
            action === 'AT_RISK'  ? 'bg-amber-50 border-amber-300' :
            action === 'STALE'    ? 'bg-amber-50 border-amber-300' :
            action === 'UNUSED'   ? 'bg-gray-50 border-gray-300' :
            action === 'HEALTHY'  ? 'bg-green-50 border-green-300' :
                                    'bg-blue-50 border-blue-300'
          }`}>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-bold uppercase">{action}</span>
              <span className="text-[10px] text-gray-500">{'\u2014'}</span>
              <span className={`text-[10px] font-medium ${
                action === 'ORPHANED' ? 'text-red-700' :
                action === 'AT_RISK'  ? 'text-amber-700' :
                action === 'STALE'    ? 'text-amber-700' :
                action === 'HEALTHY'  ? 'text-green-700' :
                                        'text-blue-700'
              }`}>
                {data.recommended_action.action_text}
              </span>
            </div>
            {riskSummary.length > 0 && (
              <div className="mt-1.5 space-y-0.5">
                {riskSummary.map((flag, idx) => (
                  <div key={idx} className="flex items-start gap-1.5 text-[10px] text-gray-600">
                    <span className="text-red-400 mt-px">{'\u25cf'}</span>
                    <span>{flag}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ── Section 5: Origin (if not already shown in signals) ── */}
          {!!data.workload_origin.origin && data.workload_origin.origin !== 'Unknown' && lineageSignals.length === 0 && (
            <div className="px-3 py-2.5 rounded-lg bg-teal-50 border border-teal-200">
              <div className="text-[10px] font-bold text-teal-800 uppercase tracking-wider">Workload Origin</div>
              <div className="text-xs font-semibold text-teal-900 mt-0.5">
                {data.workload_origin.origin}
                {!!data.workload_origin.source && data.workload_origin.source !== 'none' && (
                  <span className="ml-1.5 text-[10px] font-normal text-teal-600">
                    (via {data.workload_origin.source.replace(/_/g, ' ')})
                  </span>
                )}
              </div>
            </div>
          )}

          {/* ── Section 6: Dependency Impact ────────────────────────── */}
          {data.dependency_impact.level !== 'none_detected' && (
            <div className="border-t border-gray-200 pt-3">
              <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Dependency Impact</div>
              <div className={`px-3 py-2 rounded border ${
                data.dependency_impact.level === 'high' ? 'bg-red-50 border-red-200' :
                data.dependency_impact.level === 'medium' ? 'bg-amber-50 border-amber-200' :
                'bg-gray-50 border-gray-200'
              }`}>
                <p className={`text-[10px] whitespace-pre-line ${
                  data.dependency_impact.level === 'high' ? 'text-red-700' :
                  data.dependency_impact.level === 'medium' ? 'text-amber-700' :
                  'text-gray-600'
                }`}>
                  {data.dependency_impact.statement}
                </p>
              </div>
            </div>
          )}

          {/* ── Section 7: App Registration (collapsed detail) ───── */}
          {!!appReg && (
            <div className="border-t border-gray-200 pt-3">
              <div className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider mb-2">App Registration</div>
              <div className="space-y-1.5">
                <Row label="Name" value={appReg.display_name || '\u2014'} />
                <Row
                  label="Owner"
                  value={appReg.owners.length > 0 ? appReg.owners[0].display_name : 'None assigned'}
                  valueClass={appReg.owners.length > 0 ? 'text-gray-700' : 'text-red-500'}
                />
                {!!appReg.likely_service && <Row label="Service" value={appReg.likely_service} />}
                {!!appReg.publisher_domain && <Row label="Publisher" value={appReg.publisher_domain} />}
                {!!appReg.is_external && (
                  <div className="px-2 py-1 rounded bg-orange-50 border border-orange-200">
                    <span className="text-[10px] font-bold text-orange-700">External App</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Section 8: Connection Source ──────────────────────── */}
          {!!data.workload_origin.is_discovery_connector && (
            <div className="border-t border-gray-200 pt-3">
              <div className="text-[10px] font-semibold text-amber-700 uppercase tracking-wider mb-2">Connection Source</div>
              <div className="space-y-1.5 bg-amber-50 border border-amber-200 rounded px-3 py-2">
                <Row label="Connected as" value="AuditGraph Discovery Connector" />
                <Row label="Method" value="OAuth 2.0 Client Credentials" />
                <p className="text-[10px] text-amber-700 mt-1 leading-relaxed">
                  This SPN was created when you registered AuditGraph in your Azure AD tenant.
                </p>
              </div>
            </div>
          )}

          {/* ── Section 9: Sign-in Activity ──────────────────────── */}
          {!!data.sign_in && data.sign_in.pattern !== 'never_used' && (
            <div className="border-t border-gray-200 pt-3">
              <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Sign-in Activity</div>
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  {(() => {
                    const sb = SIGNIN_BADGE[data.sign_in!.pattern];
                    return sb ? (
                      <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold ${sb.cls}`}>{sb.label}</span>
                    ) : null;
                  })()}
                </div>
                {data.sign_in.dormancy_days >= 0 && (
                  <Row label="Last seen" value={data.sign_in.dormancy_days === 0 ? 'Today' : `${data.sign_in.dormancy_days}d ago`} />
                )}
                {data.sign_in.pattern === 'hybrid_concurrent' && (
                  <div className="px-2 py-1 bg-red-50 border border-red-200 rounded">
                    <p className="text-[10px] text-red-600">Both human and machine sign-ins within 7 days — possible shared credential.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Section 9b: Effective Last Used ──────────────────── */}
          {!!data.effective_last_used && (
            <div className="border-t border-gray-200 pt-3">
              <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Last Used</div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-900 font-medium">
                  {(() => {
                    if (data.effective_last_used_source === 'inferred_federated') return 'Likely active';
                    const d = new Date(data.effective_last_used!);
                    const now = new Date();
                    const diffDays = Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));
                    if (diffDays === 0) return 'Today';
                    if (diffDays === 1) return 'Yesterday';
                    return `${diffDays}d ago`;
                  })()}
                </span>
                <span className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-semibold ${
                  data.effective_last_used_source === 'auditgraph'
                    ? 'bg-emerald-100 text-emerald-700'
                    : data.effective_last_used_source === 'inferred_federated'
                    ? 'bg-purple-100 text-purple-700'
                    : 'bg-blue-100 text-blue-700'
                }`}>
                  {data.effective_last_used_source === 'auditgraph' ? 'via AuditGraph'
                    : data.effective_last_used_source === 'inferred_federated' ? 'Inferred'
                    : 'via Azure'}
                </span>
              </div>
            </div>
          )}

          {/* Azure Portal link */}
          {!!appReg?.object_id && (
            <div className="border-t border-gray-200 pt-3">
              <a
                href={`https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/${appReg.object_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-600 bg-blue-50 border border-blue-200 rounded hover:bg-blue-100 transition"
              >
                View in Azure Portal {'\u2197'}
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
