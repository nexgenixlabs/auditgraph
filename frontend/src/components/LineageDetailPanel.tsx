import React, { useEffect, useState } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { normalizeIssuer } from '../constants/identityState';
import { getSourceLabel } from '../constants/activitySignals';
import { normalizeScore } from '../utils/identityRiskScore';

/* ────────────────────────────────────────────────────────────────────────────
 * LineageDetailPanel — Redesigned identity lineage slide-out panel
 *
 * 320px right drawer with strict information hierarchy:
 * 1. Identity Header  2. Verdict Bar  3. Verdict Detail (collapsible)
 * 4. Auth History  5. Role Bindings  6. Ownership  7. Workload Origin
 * 8. Dependency Impact  9. Analysis (collapsible)  10. Footer
 *
 * Brand colors: Navy #15306A, Teal #24A2A1, Orange #FF7216
 * ──────────────────────────────────────────────────────────────────────────── */

// ── Brand palette ────────────────────────────────────────────────────────────

const BRAND = {
  navy:      '#15306A',
  navyLight: '#1e407a',
  teal:      '#24A2A1',
  tealLight: '#2fb8b7',
  orange:    '#FF7216',
  orangeLight: '#ff8c3f',
} as const;

// ── Types ────────────────────────────────────────────────────────────────────

interface Props {
  identity: { identity_id: string; display_name: string };
  onClose: () => void;
  onBackToDetail?: () => void;
}

interface LineageSignal {
  type: 'ARM' | 'FEDERATED' | 'HEURISTIC' | 'ROLE' | 'SIGNIN' | 'OWNER' | 'OBSERVED' | 'INFERRED' | 'API' | 'PROVENANCE' | 'PLATFORM' | 'ALERT';
  label: string;
  value: string;
  confidence: 'high' | 'medium' | 'low';
}

interface RoleAssignment {
  role_name: string;
  scope: string;
  scope_type?: string;
  resource_type?: string;
  resource_name?: string;
}

interface LineageResponse {
  identity_id: string;
  display_name: string;
  identity_category?: string;
  cloud?: string;
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
    resources: Array<{ resource_name: string; resource_type: string; impact_level: string; region?: string }>;
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
  role_topology?: {
    workload_type: string;
    workload_confidence: number;
    role_pattern_matched?: string;
    role_assignments: RoleAssignment[];
  } | null;
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
    last_delegated?: string | null;
    last_noninteractive?: string | null;
    observed_last_used?: string | null;
  } | null;
  effective_last_used?: string | null;
  effective_last_used_source?: 'auditgraph' | 'azure_signin' | 'inferred_federated' | null;
  auth_history?: Array<{
    signed_in_at: string | null;
    ip_address: string | null;
    location: string | null;
    app_used: string | null;
  }>;
  last_signin_at?: string | null;
  last_signin_ip?: string | null;
  auth_source?: 'entra_signin_log' | 'aad_audit' | 'static_analysis_only';
  signal_conflicts?: Array<{
    conflict_type: string;
    description: string;
    severity: 'critical' | 'warning' | 'info';
    resolution: string;
  }>;
  lineage_signals?: LineageSignal[];
  lineage_narrative?: string;
  lineage_warnings?: string[];
}

// ── Verdict configuration ────────────────────────────────────────────────────

type VerdictKey = 'ORPHANED' | 'GHOST_MSI' | 'FEDERATED_MISCONFIGURED' | 'PAT_GOVERNANCE_RISK' | 'AT_RISK' | 'STALE' | 'UNUSED' | 'NEEDS_REVIEW' | 'HEALTHY';

const VERDICT_CONFIG: Record<string, { label: string; pillBg: string; pillText: string; group: 'red' | 'amber' | 'green' | 'blue' | 'purple' }> = {
  ORPHANED:                { label: 'Orphaned',                pillBg: '#fde8e8', pillText: '#b91c1c', group: 'red' },
  GHOST_MSI:               { label: 'Ghost MSI',               pillBg: '#f3e8ff', pillText: '#7c3aed', group: 'purple' },
  FEDERATED_MISCONFIGURED: { label: 'Federated Misconfigured', pillBg: '#fff3e0', pillText: '#c2410c', group: 'amber' },
  PAT_GOVERNANCE_RISK:     { label: 'PAT Governance Risk',     pillBg: '#fff3e0', pillText: '#c2410c', group: 'amber' },
  AT_RISK:                 { label: 'At Risk',                 pillBg: '#fde8e8', pillText: '#b91c1c', group: 'red' },
  STALE:                   { label: 'Stale',                   pillBg: '#fff3e0', pillText: '#92400e', group: 'amber' },
  UNUSED:                  { label: 'Unused',                  pillBg: '#fff3e0', pillText: '#92400e', group: 'amber' },
  NEEDS_REVIEW:            { label: 'Needs Review',            pillBg: '#dbeafe', pillText: '#1e40af', group: 'blue' },
  HEALTHY:                 { label: 'Healthy',                 pillBg: '#dcfce7', pillText: '#166534', group: 'green' },
};

const CONFIDENCE_DOT: Record<string, string> = { high: '#22c55e', medium: '#f59e0b', low: '#ef4444' };

// (Signal flag descriptions removed — raw internal keys are no longer displayed)

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '\u2014';
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return iso;
  }
}

function fmtDateShort(iso: string | null | undefined): string {
  if (!iso) return '\u2014';
  try {
    return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  } catch {
    return iso;
  }
}

function extractSubscriptionName(roles: RoleAssignment[]): string | null {
  for (const r of roles) {
    const scope = r.scope || '';
    const match = scope.match(/\/subscriptions\/([^/]+)/);
    if (match) {
      const subId = match[1];
      return r.resource_name || subId.substring(0, 12) + '...';
    }
  }
  return null;
}

// ── Collapsible section ──────────────────────────────────────────────────────

function Section({ title, defaultOpen = false, children, titleStyle }: {
  title: string; defaultOpen?: boolean; children: React.ReactNode; titleStyle?: React.CSSProperties;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between py-1.5 group"
      >
        <span className="text-[10px] font-bold uppercase tracking-wider" style={titleStyle || { color: '#6b7280' }}>
          {title}
        </span>
        <span className="text-[10px] text-gray-400 group-hover:text-gray-600 transition-colors">
          {open ? '\u25B2' : '\u25BC'}
        </span>
      </button>
      {open && <div className="mt-1">{children}</div>}
    </div>
  );
}

// ── Component ────────────────────────────────────────────────────────────────

export default function LineageDetailPanel({ identity: identityProp, onClose, onBackToDetail }: Props) {
  const { withConnection } = useConnection();
  const [data, setData] = useState<LineageResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [rolesExpanded, setRolesExpanded] = useState(false);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

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

  // ── Loading ────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="fixed inset-0 z-50 flex justify-end">
        <div className="absolute inset-0 bg-black/20" onClick={onClose} />
        <div className="relative w-80 bg-white shadow-2xl border-l flex items-center justify-center"
             style={{ borderColor: '#e5e7eb' }}>
          <div className="animate-spin h-5 w-5 rounded-full border-2 border-t-transparent"
               style={{ borderColor: BRAND.teal, borderTopColor: 'transparent' }} />
        </div>
      </div>
    );
  }

  // ── Error fallback ─────────────────────────────────────────────────────
  if (!data) {
    return (
      <div className="fixed inset-0 z-50 flex justify-end">
        <div className="absolute inset-0 bg-black/20" onClick={onClose} />
        <div className="relative w-80 bg-white shadow-2xl border-l flex flex-col"
             style={{ borderColor: '#e5e7eb' }}>
          <div className="px-4 py-3 flex justify-between items-center"
               style={{ background: BRAND.navy }}>
            <span className="text-xs font-semibold text-white truncate max-w-[220px]">
              {identityProp.display_name}
            </span>
            <button onClick={onClose} className="text-white/60 hover:text-white text-sm font-bold p-0.5">{'\u00d7'}</button>
          </div>
          <div className="flex-1 flex items-center justify-center">
            <p className="text-xs text-gray-400">No lineage data available.</p>
          </div>
        </div>
      </div>
    );
  }

  // ── Derived state ──────────────────────────────────────────────────────
  const rawAction = data.recommended_action.action || 'NEEDS_REVIEW';
  const depResources = data.dependency_impact.resources || [];
  const hasDeps = depResources.length > 0;

  // CRITICAL: if verdict is UNUSED but deps exist, override to AT_RISK
  const hasConflict = rawAction === 'UNUSED' && hasDeps;
  const action = hasConflict ? 'AT_RISK' : rawAction;
  const verdict = VERDICT_CONFIG[action] || VERDICT_CONFIG.NEEDS_REVIEW;

  const confidence = data.confidence.level || 'low';
  const score = data.confidence.score ?? 0;
  const riskSummary = data.recommended_action.risk_summary || [];
  const roleAssignments = data.role_topology?.role_assignments || [];
  const appReg = data.app_registration;
  const owners = appReg?.owners || [];
  const lineageNarrative = data.lineage_narrative || '';
  const authHistory = (data.auth_history || []).slice(0, 3);
  const signalConflicts = data.signal_conflicts || [];
  const subscriptionName = extractSubscriptionName(roleAssignments);

  // Score bar color
  const scoreBarColor = score >= 60 ? '#22c55e' : score >= 30 ? '#f59e0b' : '#ef4444';

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/25" onClick={onClose} />

      {/* Panel */}
      <div className="relative w-80 bg-white shadow-2xl border-l flex flex-col animate-slide-in-right"
           style={{ borderColor: '#e2e5ea' }}>

        {/* ─── S1: IDENTITY HEADER ─────────────────────────────────── */}
        <div className="shrink-0 px-4 py-3" style={{ background: `linear-gradient(135deg, ${BRAND.navy}, ${BRAND.navyLight})` }}>
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0 flex-1">
              {onBackToDetail && (
                <button onClick={onBackToDetail}
                  className="text-white/50 hover:text-white text-[10px] mb-1 flex items-center gap-1">
                  {'\u2190'} Back
                </button>
              )}
              <h3 className="text-sm font-bold text-white truncate" title={data.display_name}>
                {data.display_name}
              </h3>
              <p className="text-[9px] font-mono text-white/40 mt-0.5 truncate" title={data.identity_id}>
                {data.identity_id}
              </p>
              {!!subscriptionName && (
                <span className="inline-block mt-1.5 px-2 py-0.5 rounded text-[9px] font-semibold text-white/90"
                      style={{ background: 'rgba(255,255,255,0.15)' }}>
                  {subscriptionName}
                </span>
              )}
            </div>
            <button onClick={onClose}
              className="text-white/50 hover:text-white text-base font-bold p-0.5 shrink-0 leading-none mt-0.5">
              {'\u00d7'}
            </button>
          </div>
        </div>

        {/* ─── S2: VERDICT BAR ──────────────────────────────────────── */}
        <div className="shrink-0 px-4 py-2.5 border-b" style={{ borderColor: '#e5e7eb' }}>
          <div className="flex items-center gap-2">
            {/* Verdict pill */}
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-bold"
                  style={{ background: verdict.pillBg, color: verdict.pillText }}>
              {verdict.label}
            </span>
            {/* Confidence */}
            <span className="flex items-center gap-1 text-[10px] text-gray-500">
              <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ background: CONFIDENCE_DOT[confidence] || CONFIDENCE_DOT.low }} />
              {confidence}
            </span>
            {/* Score */}
            <span className="ml-auto text-[10px] font-bold" style={{ color: BRAND.navy }}>{normalizeScore(score, 10).toFixed(1)}/10</span>
          </div>
          {/* Score progress bar */}
          <div className="mt-1.5 w-full h-1 bg-gray-100 rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all duration-500" style={{ width: `${score}%`, background: scoreBarColor }} />
          </div>
        </div>

        {/* ─── SCROLLABLE BODY ──────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto">
          <div className="px-4 py-3 space-y-3 text-xs">

            {/* ─── S3: VERDICT DETAIL (collapsible, open by default) ── */}
            <Section title="Verdict Detail" defaultOpen={true} titleStyle={{ color: BRAND.navy }}>
              {/* Action text */}
              <p className="text-[11px] text-gray-700 leading-relaxed mb-2">
                {data.recommended_action.action_text}
              </p>

              {/* Signal conflicts (from backend conflict detection) */}
              {signalConflicts.length > 0 && (
                <div className="space-y-1.5 mb-2">
                  {signalConflicts.map((c, idx) => {
                    const sev = c.severity || 'info';
                    const style = sev === 'critical'
                      ? { bg: '#fde8e8', border: '#fca5a5', text: '#991b1b', dot: '#ef4444' }
                      : sev === 'warning'
                      ? { bg: '#fef9c3', border: '#fde047', text: '#854d0e', dot: '#f59e0b' }
                      : { bg: '#eff6ff', border: '#bfdbfe', text: '#1e40af', dot: '#3b82f6' };
                    return (
                      <div key={idx} className="px-2.5 py-2 rounded border text-[10px] leading-relaxed"
                           style={{ background: style.bg, borderColor: style.border, color: style.text }}>
                        <div className="flex items-start gap-1.5">
                          <span className="mt-[3px] shrink-0 inline-block w-1.5 h-1.5 rounded-full" style={{ background: style.dot }} />
                          <div>
                            <span className="font-bold">Signal conflict:</span>{' '}{c.description}
                            <div className="mt-1 text-[9px] opacity-80">{c.resolution}</div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Trust Signals — structured rows instead of raw internal keys */}
              <div className="space-y-1.5 mt-1">
                {/* Workload Origin */}
                <div className="flex justify-between text-[10px]">
                  <span className="text-gray-400">Workload Origin</span>
                  <span className="font-medium text-gray-700 text-right max-w-[55%] truncate"
                        title={data.workload_origin.origin || 'Unknown'}>
                    {data.workload_origin.origin && data.workload_origin.origin !== 'Unknown'
                      ? data.workload_origin.origin
                      : data.identity_category === 'managed_identity_system'
                        ? 'System-assigned MSI'
                        : data.identity_category === 'managed_identity_user'
                          ? 'User-assigned MSI'
                          : !!data.workload_origin.workload_type
                            ? normalizeIssuer(data.workload_origin.workload_type)
                            : 'Entra ID registration'}
                  </span>
                </div>
                {/* Last Seen */}
                <div className="flex justify-between text-[10px]">
                  <span className="text-gray-400">Last Seen</span>
                  <span className="font-medium text-gray-700">
                    {data.effective_last_used
                      ? fmtDate(data.effective_last_used)
                      : data.last_signin_at
                        ? fmtDate(data.last_signin_at)
                        : data.sign_in?.last_sign_in
                          ? fmtDate(data.sign_in.last_sign_in)
                          : <span style={{ color: '#d97706' }}>No auth observed</span>}
                  </span>
                </div>
                {/* Last Seen From */}
                <div className="flex justify-between text-[10px]">
                  <span className="text-gray-400">Last Seen From</span>
                  <span className="font-medium text-gray-700">
                    {data.last_signin_ip
                      ? <span className="font-mono text-gray-600">{data.last_signin_ip}</span>
                      : <span className="text-gray-300">
                          {getSourceLabel(data.auth_source || data.effective_last_used_source || null)}
                        </span>}
                  </span>
                </div>
              </div>
            </Section>

            {/* ─── S4: AUTHENTICATION HISTORY ──────────────────────── */}
            <div className="border-t pt-2.5" style={{ borderColor: '#f0f0f0' }}>
              <div className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: BRAND.navy }}>
                Authentication
              </div>
              <div className="space-y-1.5">
                {/* Last sign-in */}
                <div className="flex justify-between">
                  <span className="text-gray-400 text-[10px]">Last sign-in</span>
                  {data.last_signin_at ? (
                    <span className="text-[10px] font-medium text-gray-700">{fmtDate(data.last_signin_at)}</span>
                  ) : (
                    <span className="text-[10px] font-medium" style={{ color: '#d97706' }}>Provisioned — no auth observed</span>
                  )}
                </div>
                {/* Last IP */}
                <div className="flex justify-between">
                  <span className="text-gray-400 text-[10px]">Last IP</span>
                  {data.last_signin_ip ? (
                    <span className="text-[10px] font-mono text-gray-600">{data.last_signin_ip}</span>
                  ) : (
                    <span className="text-[10px] text-gray-300">No IP on record</span>
                  )}
                </div>
                {/* Auth source */}
                <div className="flex justify-between">
                  <span className="text-gray-400 text-[10px]">Source</span>
                  <span className="text-[10px] font-medium" style={{
                    color: data.auth_source === 'entra_signin_log' ? BRAND.teal
                      : data.auth_source === 'aad_audit' ? '#3b82f6'
                      : '#9ca3af'
                  }}>
                    {data.auth_source === 'entra_signin_log' ? 'Entra ID sign-in log'
                      : data.auth_source === 'aad_audit' ? 'AAD audit log'
                      : 'Static analysis only'}
                  </span>
                </div>
              </div>

              {/* Mini timeline (last 3 events) */}
              {authHistory.length > 0 && (
                <div className="mt-2.5 pl-2 border-l-2" style={{ borderColor: BRAND.teal + '40' }}>
                  {authHistory.map((evt, i) => (
                    <div key={i} className="relative flex items-start gap-2 pb-2 last:pb-0">
                      <span className="absolute -left-[9px] top-[3px] w-2 h-2 rounded-full border-2 bg-white"
                            style={{ borderColor: BRAND.teal }} />
                      <div className="pl-2 min-w-0">
                        <div className="text-[10px] text-gray-600 truncate">
                          <span className="font-medium text-gray-700">{fmtDateShort(evt.signed_in_at)}</span>
                          {!!evt.ip_address && <span className="ml-1.5 font-mono text-gray-400">{evt.ip_address}</span>}
                        </div>
                        {!!evt.app_used && (
                          <div className="text-[9px] text-gray-400 truncate">{evt.app_used}</div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* ─── S5: ACTIVE ROLE BINDINGS ─────────────────────────── */}
            {roleAssignments.length > 0 && (
              <div className="border-t pt-2.5" style={{ borderColor: '#f0f0f0' }}>
                <div className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: BRAND.navy }}>
                  Active Roles
                  <span className="ml-1.5 font-normal text-gray-400">({roleAssignments.length})</span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {(rolesExpanded ? roleAssignments : roleAssignments.slice(0, 3)).map((r, idx) => {
                    const scopeShort = r.resource_name || r.scope_type || r.scope?.split('/').pop() || '';
                    return (
                      <span key={idx}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] border max-w-full"
                        style={{ background: '#f0f9ff', borderColor: '#bae6fd', color: BRAND.navy }}
                        title={`${r.role_name} \u2192 ${r.scope || 'unknown scope'}`}>
                        <span className="font-semibold truncate max-w-[100px]">{r.role_name}</span>
                        {!!scopeShort && (
                          <span className="text-[9px] text-gray-400 truncate max-w-[80px]">{scopeShort}</span>
                        )}
                      </span>
                    );
                  })}
                  {!rolesExpanded && roleAssignments.length > 3 && (
                    <button
                      onClick={() => setRolesExpanded(true)}
                      className="px-2 py-1 rounded text-[10px] font-semibold border border-dashed"
                      style={{ borderColor: BRAND.teal, color: BRAND.teal }}>
                      +{roleAssignments.length - 3} more
                    </button>
                  )}
                  {rolesExpanded && roleAssignments.length > 3 && (
                    <button
                      onClick={() => setRolesExpanded(false)}
                      className="px-2 py-1 rounded text-[10px] font-semibold border border-dashed text-gray-400 border-gray-300">
                      Show less
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* ─── S6: OWNERSHIP ──────────────────────────────────────── */}
            {owners.length > 0 && (
              <div className="border-t pt-2.5" style={{ borderColor: '#f0f0f0' }}>
                <div className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: BRAND.navy }}>
                  Ownership
                </div>
                {owners.map((o, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-bold text-white shrink-0"
                          style={{ background: BRAND.teal }}>
                      {(o.display_name || '?')[0].toUpperCase()}
                    </span>
                    <div>
                      <span className="text-[11px] font-medium text-gray-800">{o.display_name}</span>
                      <span className="ml-1.5 text-[9px] text-gray-400">direct</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* ─── S7: WORKLOAD ORIGIN ────────────────────────────────── */}
            {!!data.workload_origin.origin && data.workload_origin.origin !== 'Unknown' && (
              <div className="border-t pt-2.5" style={{ borderColor: '#f0f0f0' }}>
                <div className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: BRAND.teal }}>
                  Workload Origin
                </div>
                <div className="px-2.5 py-2 rounded border" style={{ background: '#f0fdfa', borderColor: '#99f6e4' }}>
                  <div className="text-[11px] font-semibold" style={{ color: BRAND.navy }}>
                    {data.workload_origin.origin}
                  </div>
                  {!!data.workload_origin.source && data.workload_origin.source !== 'none' && (
                    <div className="text-[9px] mt-0.5" style={{ color: BRAND.teal }}>
                      via {data.workload_origin.source.replace(/_/g, ' ')}
                      {!!data.workload_origin.workload_type && data.workload_origin.workload_type !== 'unknown' && (
                        <span className="ml-1 text-gray-400">
                          ({data.workload_origin.workload_type.replace(/_/g, ' ')})
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ─── S8: DEPENDENCY IMPACT ──────────────────────────────── */}
            {hasDeps && (
              <div className="border-t pt-2.5" style={{ borderColor: '#f0f0f0' }}>
                <div className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: BRAND.orange }}>
                  Dependency Impact
                </div>
                <div className="px-2.5 py-2 rounded border"
                     style={{
                       background: data.dependency_impact.level === 'high' ? '#fff7ed' : '#fffbeb',
                       borderColor: data.dependency_impact.level === 'high' ? BRAND.orange + '60' : '#fde68a',
                     }}>
                  <p className="text-[10px] font-semibold mb-1.5" style={{ color: '#92400e' }}>
                    If deleted, this will impact:
                  </p>
                  <div className="space-y-1">
                    {depResources.map((r, idx) => (
                      <div key={idx} className="flex items-center gap-1.5 text-[10px]">
                        <span className="w-1 h-1 rounded-full shrink-0"
                              style={{
                                background: r.impact_level === 'high' ? '#ef4444'
                                  : r.impact_level === 'critical' ? '#dc2626'
                                  : r.impact_level === 'medium' ? '#f59e0b'
                                  : '#9ca3af'
                              }} />
                        <span className="font-medium text-gray-700 truncate">{r.resource_name}</span>
                        <span className="text-gray-400 text-[9px] shrink-0">{r.resource_type}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ─── S9: ANALYSIS (collapsible) ─────────────────────────── */}
            {!!lineageNarrative && (
              <div className="border-t pt-2.5" style={{ borderColor: '#f0f0f0' }}>
                <Section title="Analysis" defaultOpen={false}>
                  <div className="px-2.5 py-2 rounded" style={{ background: '#f8fafc' }}>
                    <p className="text-[11px] text-gray-600 leading-relaxed">{lineageNarrative}</p>
                  </div>
                </Section>
              </div>
            )}
          </div>
        </div>

        {/* ─── S10: FOOTER ──────────────────────────────────────────── */}
        <div className="shrink-0 px-4 py-3 border-t flex flex-col gap-2" style={{ borderColor: '#e5e7eb', background: '#fafbfc' }}>
          <div className="flex gap-2">
            {/* Azure Portal link */}
            {!!appReg?.object_id && (
              <a
                href={`https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/${appReg.object_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex-1 inline-flex items-center justify-center gap-1 px-2 py-1.5 rounded text-[10px] font-semibold text-white transition-colors"
                style={{ background: BRAND.navy }}
                onMouseEnter={e => (e.currentTarget.style.background = BRAND.navyLight)}
                onMouseLeave={e => (e.currentTarget.style.background = BRAND.navy)}>
                View in Azure Portal {'\u2197'}
              </a>
            )}
            {/* Add to Remediation */}
            <button
              className="flex-1 inline-flex items-center justify-center gap-1 px-2 py-1.5 rounded text-[10px] font-semibold transition-colors"
              style={{ background: BRAND.teal, color: 'white' }}
              onMouseEnter={e => (e.currentTarget.style.background = BRAND.tealLight)}
              onMouseLeave={e => (e.currentTarget.style.background = BRAND.teal)}
              title="Add identity to remediation plan">
              + Remediation
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
