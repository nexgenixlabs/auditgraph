/**
 * AI Governance — policy compliance for AI agents.
 *
 * "Are you within policy?" — evaluates every AI agent against the governance
 * policy catalog (no Owner, must have human owner, no KV admin, etc.) using the
 * same architecture-derived signals the risk score is built from. No telemetry.
 *
 * Two tabs:
 *   • Policies   — per-policy compliance + per-agent Request Exception flow
 *   • Exceptions — pending / approved / expired / revoked waiver workflow
 *
 * Falls back to a Coming Soon preview if the feature/data isn't available.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import AIInvestigateDrawer from '../components/AIInvestigateDrawer';
import ComingSoonPage from '../components/ComingSoonPage';

interface ExceptionAgent { identity_id: string; display_name: string; exception_expires_at?: string; approved_by_name?: string; }
interface Violator { identity_id: string; display_name: string; }
interface PolicyResult {
  policy_id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  framework: string[];
  rationale: string;
  remediation: string;
  violating_count: number;
  exception_count?: number;
  compliant_count: number;
  compliance_pct: number;
  top_violators: Violator[];
  exception_agents?: ExceptionAgent[];
}
interface GovernanceData {
  summary: {
    total_agents: number;
    agents_in_violation: number;
    total_violations: number;
    exceptions_active?: number;
    policy_count: number;
    overall_compliance_pct: number;
  };
  policies: PolicyResult[];
}

interface ExceptionRow {
  id: number;
  identity_id: string;
  identity_display_name?: string;
  policy_id: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'revoked';
  justification: string;
  business_owner: string | null;
  requested_by: number | null;
  requested_by_name?: string | null;
  requested_at: string | null;
  approved_by_name?: string | null;
  approved_at: string | null;
  rejected_by_name?: string | null;
  rejected_at: string | null;
  rejection_reason: string | null;
  expires_at: string;
  revoked_by_name?: string | null;
  revoked_at: string | null;
}

const SEV_STYLE: Record<string, { text: string; bg: string; border: string }> = {
  critical: { text: '#f87171', bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.35)' },
  high:     { text: '#fb923c', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.35)' },
  medium:   { text: '#facc15', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.35)' },
  low:      { text: '#4ade80', bg: 'rgba(34,197,94,0.10)',  border: 'rgba(34,197,94,0.35)' },
};

const STATUS_STYLE: Record<string, { text: string; bg: string; border: string; label: string }> = {
  pending:  { text: '#fbbf24', bg: 'rgba(251,191,36,0.10)',  border: 'rgba(251,191,36,0.35)',  label: 'PENDING'  },
  approved: { text: '#34d399', bg: 'rgba(52,211,153,0.10)',  border: 'rgba(52,211,153,0.35)',  label: 'APPROVED' },
  rejected: { text: '#9ca3af', bg: 'rgba(156,163,175,0.10)', border: 'rgba(156,163,175,0.35)', label: 'REJECTED' },
  expired:  { text: '#fb7185', bg: 'rgba(251,113,133,0.10)', border: 'rgba(251,113,133,0.35)', label: 'EXPIRED'  },
  revoked:  { text: '#94a3b8', bg: 'rgba(148,163,184,0.10)', border: 'rgba(148,163,184,0.35)', label: 'REVOKED'  },
};

const EXPIRY_OPTIONS = [
  { value: 30,  label: '30 days' },
  { value: 60,  label: '60 days' },
  { value: 90,  label: '90 days' },
  { value: 180, label: '180 days' },
];

function complianceColor(pct: number): string {
  if (pct >= 95) return '#4ade80';
  if (pct >= 80) return '#facc15';
  if (pct >= 50) return '#fb923c';
  return '#f87171';
}

function fmtDate(iso?: string | null): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch { return iso; }
}

type TabKey = 'policies' | 'exceptions';

export default function AIGovernance() {
  const { withConnection, selectedConnectionId } = useConnection();
  const { isAdmin, isSuperAdmin } = useAuth();
  const adminMode = isAdmin || isSuperAdmin;

  const [tab, setTab] = useState<TabKey>('policies');
  const [data, setData] = useState<GovernanceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [investigateId, setInvestigateId] = useState<string | null>(null);

  const [exceptions, setExceptions] = useState<ExceptionRow[]>([]);
  const [excLoading, setExcLoading] = useState(false);
  const [excError, setExcError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Request modal
  const [requestModal, setRequestModal] = useState<{ identity_id: string; display_name: string; policy_id: string } | null>(null);
  const [reqJustification, setReqJustification] = useState('');
  const [reqOwner, setReqOwner] = useState('');
  const [reqDays, setReqDays] = useState<number>(90);
  const [reqSubmitting, setReqSubmitting] = useState(false);
  const [reqError, setReqError] = useState<string | null>(null);

  // Reject modal
  const [rejectModal, setRejectModal] = useState<ExceptionRow | null>(null);
  const [rejReason, setRejReason] = useState('');
  const [rejSubmitting, setRejSubmitting] = useState(false);
  const [rejError, setRejError] = useState<string | null>(null);

  // ---------- Data fetchers ----------
  const loadGovernance = useCallback(() => {
    setLoading(true); setError(null);
    fetch(withConnection('/api/ai-security/governance'))
      .then(r => {
        if (r.status === 404) { setError('not_found'); return null; }
        if (!r.ok) { setError('fetch_error'); return null; }
        return r.json();
      })
      .then(d => { if (d) setData(d as GovernanceData); })
      .catch(() => setError('fetch_error'))
      .finally(() => setLoading(false));
  }, [withConnection]);

  const loadExceptions = useCallback(() => {
    setExcLoading(true); setExcError(null);
    const qs = statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : '';
    fetch(`/api/ai-security/governance/exceptions${qs}`)
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d && Array.isArray(d.exceptions)) setExceptions(d.exceptions as ExceptionRow[]);
        else if (d) setExceptions([]);
      })
      .catch(() => setExcError('fetch_error'))
      .finally(() => setExcLoading(false));
  }, [statusFilter]);

  useEffect(() => {
    loadGovernance();
  }, [loadGovernance, selectedConnectionId]);

  useEffect(() => {
    // Also pull exceptions on first load so the Policies tab can render
    // inline "Exception · expires X" badges next to violating agents.
    loadExceptions();
  }, [loadExceptions]);

  // ---------- Derived lookups ----------
  /** Map (identity_id, policy_id) → active approved exception so we can render
   * an inline badge next to violating agents instead of the request button. */
  const activeExceptionMap = useMemo(() => {
    const m = new Map<string, ExceptionRow>();
    for (const e of exceptions) {
      if (e.status !== 'approved') continue;
      if (e.expires_at && new Date(e.expires_at) <= new Date()) continue;
      m.set(`${e.identity_id}::${e.policy_id}`, e);
    }
    return m;
  }, [exceptions]);

  /** Identities that have a pending request for a given policy — used to
   * disable the Request Exception button on a re-click. */
  const pendingRequestMap = useMemo(() => {
    const m = new Map<string, ExceptionRow>();
    for (const e of exceptions) {
      if (e.status !== 'pending') continue;
      m.set(`${e.identity_id}::${e.policy_id}`, e);
    }
    return m;
  }, [exceptions]);

  // ---------- Mutations ----------
  const submitRequest = async () => {
    if (!requestModal) return;
    setReqError(null);
    if (reqJustification.trim().length < 20) {
      setReqError('Justification must be at least 20 characters.');
      return;
    }
    if (!reqOwner.trim()) {
      setReqError('Business owner is required.');
      return;
    }
    setReqSubmitting(true);
    try {
      const r = await fetch('/api/ai-security/governance/exceptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity_id: requestModal.identity_id,
          policy_id: requestModal.policy_id,
          justification: reqJustification.trim(),
          business_owner: reqOwner.trim(),
          expires_in_days: reqDays,
        }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        setReqError(body.error || `Failed: HTTP ${r.status}`);
      } else {
        setRequestModal(null);
        setReqJustification(''); setReqOwner(''); setReqDays(90);
        loadExceptions();
      }
    } catch {
      setReqError('Network error');
    } finally {
      setReqSubmitting(false);
    }
  };

  const approveException = async (exc: ExceptionRow) => {
    const r = await fetch(`/api/ai-security/governance/exceptions/${exc.id}/approve`, { method: 'POST' });
    if (r.ok) { loadExceptions(); loadGovernance(); }
  };

  const submitReject = async () => {
    if (!rejectModal) return;
    setRejError(null);
    if (!rejReason.trim()) { setRejError('Reason required.'); return; }
    setRejSubmitting(true);
    try {
      const r = await fetch(`/api/ai-security/governance/exceptions/${rejectModal.id}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: rejReason.trim() }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        setRejError(body.error || `Failed: HTTP ${r.status}`);
      } else {
        setRejectModal(null);
        setRejReason('');
        loadExceptions();
      }
    } catch {
      setRejError('Network error');
    } finally {
      setRejSubmitting(false);
    }
  };

  const revokeException = async (exc: ExceptionRow) => {
    const r = await fetch(`/api/ai-security/governance/exceptions/${exc.id}/revoke`, { method: 'POST' });
    if (r.ok) { loadExceptions(); loadGovernance(); }
  };

  // ---------- Render gates ----------
  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center py-20">
        <div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  if (error || !data || data.summary.total_agents === 0) {
    return (
      <ComingSoonPage
        pillar="AI Governance"
        tagline="Policies, exceptions, and audit-grade evidence for every AI agent in your tenant."
        overview="AI Governance evaluates every AI agent against a policy catalog (no Owner role on AI identities, mandatory human owner, no Key Vault admin, no unrestricted egress) using the same architecture-derived signals as the risk score. Run a discovery scan with AI agents to populate live compliance posture."
        capabilities={[
          { title: 'Policy library', description: '7 built-in policies mapped to NIST SP 800-53, CIS Azure, ISO 27001 controls.' },
          { title: 'Violation tracking', description: 'Every AI agent evaluated; violations flagged with severity + remediation.' },
          { title: 'Compliance scoring', description: 'Per-policy and overall compliance %, audit-ready.' },
          { title: 'Exception workflow', description: 'Risk-accepted exceptions with expiry + approver — request, approve, revoke, expire.' },
          { title: 'Evidence export', description: 'One-click compliance pack for SOC 2 / ISO / FedRAMP auditors (coming next).' },
        ]}
        targetWindow="Live once AI agents are discovered"
        roadmapRef="AI Governance pillar"
      />
    );
  }

  const s = data.summary;
  const overallColor = complianceColor(s.overall_compliance_pct);

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">AI Governance</h1>
        <p className="text-sm text-slate-400 mt-1">
          Policy compliance across {s.total_agents} AI agent{s.total_agents === 1 ? '' : 's'} —
          derived from architecture, mapped to NIST / CIS / ISO controls
        </p>
      </div>

      {/* Tab strip */}
      <div className="flex items-end border-b" style={{ borderColor: 'var(--border-default)' }}>
        <div className="flex gap-1">
          {(['policies', 'exceptions'] as TabKey[]).map(k => {
            const active = k === tab;
            const label = k === 'policies' ? 'Policies' : 'Exceptions';
            return (
              <button
                key={k}
                onClick={() => setTab(k)}
                className="px-4 py-2.5 text-xs font-semibold transition border-b-2"
                style={{
                  color: active ? 'var(--text-primary)' : 'var(--text-tertiary)',
                  borderBottomColor: active ? '#24A2A1' : 'transparent',
                  backgroundColor: active ? 'var(--bg-hover)' : 'transparent',
                }}
              >
                {label}
                {k === 'exceptions' && exceptions.length > 0 && (
                  <span className="ml-1.5 text-[10px] font-mono px-1.5 py-0.5 rounded"
                    style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-raised)' }}>
                    {exceptions.length}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {tab === 'policies' && (
        <>
          {/* Summary strip */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="rounded-xl border p-4" style={{ borderColor: `${overallColor}55`, backgroundColor: `${overallColor}14` }}>
              <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Overall Compliance</p>
              <p className="text-3xl font-bold font-mono mt-1" style={{ color: overallColor }}>{s.overall_compliance_pct}%</p>
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>mean across {s.policy_count} policies</p>
            </div>
            <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
              <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Agents in Violation</p>
              <p className="text-3xl font-bold font-mono mt-1" style={{ color: '#f87171' }}>{s.agents_in_violation}</p>
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>of {s.total_agents} agents</p>
            </div>
            <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
              <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Total Violations</p>
              <p className="text-3xl font-bold font-mono mt-1" style={{ color: '#fb923c' }}>{s.total_violations}</p>
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>across all policies</p>
            </div>
            <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
              <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Active Exceptions</p>
              <p className="text-3xl font-bold font-mono mt-1" style={{ color: '#34d399' }}>{s.exceptions_active ?? 0}</p>
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>risk-accepted &amp; in force</p>
            </div>
            <div className="rounded-xl border p-4" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
              <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Active Policies</p>
              <p className="text-3xl font-bold font-mono mt-1 text-white">{s.policy_count}</p>
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>NIST / CIS / ISO mapped</p>
            </div>
          </div>

          {/* Policy compliance table */}
          <div className="rounded-xl border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
            <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
              <h3 className="text-sm font-semibold text-white">Policy Compliance</h3>
              <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>Most-violated first · click a policy to see violating agents</p>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
              {data.policies.map(p => {
                const sev = SEV_STYLE[p.severity] || SEV_STYLE.low;
                const isOpen = expanded === p.policy_id;
                const barColor = complianceColor(p.compliance_pct);
                const excCount = p.exception_count ?? 0;
                return (
                  <div key={p.policy_id}>
                    <button
                      onClick={() => setExpanded(isOpen ? null : p.policy_id)}
                      className="w-full text-left px-4 py-3 hover:bg-slate-800/30 transition"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border flex-shrink-0"
                            style={{ color: sev.text, backgroundColor: sev.bg, borderColor: sev.border }}>
                            {p.severity}
                          </span>
                          <span className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)' }}>{p.name}</span>
                        </div>
                        <div className="flex items-center gap-3 flex-shrink-0">
                          {p.violating_count > 0 ? (
                            <span className="text-xs font-mono" style={{ color: '#f87171' }}>{p.violating_count} violating</span>
                          ) : (
                            <span className="text-xs font-mono" style={{ color: '#4ade80' }}>compliant</span>
                          )}
                          {excCount > 0 && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
                              style={{ color: '#34d399', borderColor: 'rgba(52,211,153,0.35)', backgroundColor: 'rgba(52,211,153,0.10)' }}>
                              {excCount} exception
                            </span>
                          )}
                          <div className="w-24 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                            <div className="h-full rounded-full" style={{ width: `${p.compliance_pct}%`, backgroundColor: barColor }} />
                          </div>
                          <span className="text-xs font-mono w-12 text-right" style={{ color: barColor }}>{p.compliance_pct}%</span>
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-1 mt-1.5 ml-1">
                        {p.framework.map(f => (
                          <span key={f} className="text-[9px] font-mono px-1.5 py-0.5 rounded border"
                            style={{ color: '#60a5fa', borderColor: 'rgba(59,130,246,0.3)', backgroundColor: 'rgba(59,130,246,0.07)' }}>
                            {f}
                          </span>
                        ))}
                      </div>
                    </button>
                    {isOpen && (
                      <div className="px-4 pb-3 space-y-2" style={{ backgroundColor: 'var(--bg-surface)' }}>
                        <p className="text-[11px] leading-snug pt-2" style={{ color: 'var(--text-secondary)' }}>{p.rationale}</p>
                        <p className="text-[11px] leading-snug" style={{ color: 'var(--text-secondary)' }}>
                          <span className="font-semibold" style={{ color: '#4ade80' }}>Remediation: </span>{p.remediation}
                        </p>
                        {p.top_violators.length > 0 ? (
                          <div>
                            <p className="text-[10px] uppercase tracking-wider font-semibold mt-2 mb-1" style={{ color: 'var(--text-tertiary)' }}>
                              Violating agents ({p.violating_count})
                            </p>
                            <div className="flex flex-col gap-1.5">
                              {p.top_violators.map(v => {
                                const exc = activeExceptionMap.get(`${v.identity_id}::${p.policy_id}`);
                                const pending = pendingRequestMap.get(`${v.identity_id}::${p.policy_id}`);
                                return (
                                  <div key={v.identity_id} className="flex items-center gap-2 flex-wrap">
                                    <button onClick={() => setInvestigateId(v.identity_id)}
                                      className="text-[10px] px-2 py-1 rounded border hover:bg-slate-700/40 transition"
                                      style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-subtle)' }}>
                                      {v.display_name}
                                    </button>
                                    {exc ? (
                                      <span className="text-[10px] px-2 py-1 rounded border"
                                        style={{ color: '#34d399', backgroundColor: 'rgba(52,211,153,0.10)', borderColor: 'rgba(52,211,153,0.35)' }}>
                                        Exception · expires {fmtDate(exc.expires_at)}
                                        {exc.approved_by_name && ` · approved by ${exc.approved_by_name}`}
                                      </span>
                                    ) : pending ? (
                                      <span className="text-[10px] px-2 py-1 rounded border"
                                        style={{ color: '#fbbf24', backgroundColor: 'rgba(251,191,36,0.10)', borderColor: 'rgba(251,191,36,0.35)' }}>
                                        Exception requested · awaiting approval
                                      </span>
                                    ) : (
                                      <button
                                        onClick={() => {
                                          setRequestModal({ identity_id: v.identity_id, display_name: v.display_name, policy_id: p.policy_id });
                                          setReqJustification(''); setReqOwner(''); setReqDays(90); setReqError(null);
                                        }}
                                        className="text-[10px] px-2 py-1 rounded border transition"
                                        style={{ color: '#60a5fa', borderColor: 'rgba(59,130,246,0.35)', backgroundColor: 'rgba(59,130,246,0.07)' }}>
                                        Request Exception
                                      </button>
                                    )}
                                  </div>
                                );
                              })}
                              {p.violating_count > p.top_violators.length && (
                                <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                                  +{p.violating_count - p.top_violators.length} more
                                </span>
                              )}
                            </div>
                          </div>
                        ) : (
                          <p className="text-[11px] pt-1" style={{ color: '#4ade80' }}>All agents compliant with this policy</p>
                        )}
                        {(p.exception_agents && p.exception_agents.length > 0) && (
                          <div>
                            <p className="text-[10px] uppercase tracking-wider font-semibold mt-3 mb-1" style={{ color: 'var(--text-tertiary)' }}>
                              Agents under exception ({excCount})
                            </p>
                            <div className="flex flex-wrap gap-1.5">
                              {p.exception_agents.map(a => (
                                <button key={a.identity_id} onClick={() => setInvestigateId(a.identity_id)}
                                  className="text-[10px] px-2 py-1 rounded border hover:bg-slate-700/40 transition"
                                  style={{ color: '#34d399', borderColor: 'rgba(52,211,153,0.35)', backgroundColor: 'rgba(52,211,153,0.10)' }}>
                                  {a.display_name}
                                  {a.exception_expires_at && (
                                    <span className="ml-1" style={{ color: 'var(--text-tertiary)' }}>· expires {fmtDate(a.exception_expires_at)}</span>
                                  )}
                                </button>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}

      {tab === 'exceptions' && (
        <div className="rounded-xl border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
          <div className="px-4 py-3 border-b flex items-center gap-3 flex-wrap" style={{ borderColor: 'var(--border-subtle)' }}>
            <div className="flex-1 min-w-0">
              <h3 className="text-sm font-semibold text-white">Exception Workflow</h3>
              <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                Risk-accepted policy waivers · requesters provide justification + business owner · admins approve / reject / revoke
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              {['', 'pending', 'approved', 'rejected', 'expired', 'revoked'].map(s2 => {
                const active = statusFilter === s2;
                const label = s2 === '' ? 'All' : (STATUS_STYLE[s2]?.label || s2);
                return (
                  <button
                    key={s2 || 'all'}
                    onClick={() => setStatusFilter(s2)}
                    className="text-[10px] px-2 py-1 rounded border transition"
                    style={{
                      color: active ? 'var(--text-primary)' : 'var(--text-tertiary)',
                      borderColor: active ? '#24A2A1' : 'var(--border-subtle)',
                      backgroundColor: active ? 'var(--bg-hover)' : 'transparent',
                    }}
                  >
                    {label}
                  </button>
                );
              })}
            </div>
          </div>
          {excLoading ? (
            <div className="py-12 flex items-center justify-center">
              <div className="animate-spin h-6 w-6 border-2 border-violet-500 border-t-transparent rounded-full" />
            </div>
          ) : excError ? (
            <p className="px-4 py-6 text-xs" style={{ color: '#f87171' }}>Failed to load exceptions.</p>
          ) : exceptions.length === 0 ? (
            <p className="px-4 py-6 text-xs" style={{ color: 'var(--text-tertiary)' }}>
              No exceptions{statusFilter ? ` matching status "${statusFilter}"` : ''}. Request one from a violating agent on the Policies tab.
            </p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr style={{ color: 'var(--text-tertiary)' }} className="text-left">
                  <th className="px-4 py-2 font-semibold uppercase text-[10px]">Agent</th>
                  <th className="px-4 py-2 font-semibold uppercase text-[10px]">Policy</th>
                  <th className="px-4 py-2 font-semibold uppercase text-[10px]">Status</th>
                  <th className="px-4 py-2 font-semibold uppercase text-[10px]">Expires</th>
                  <th className="px-4 py-2 font-semibold uppercase text-[10px]">Requested by</th>
                  <th className="px-4 py-2 font-semibold uppercase text-[10px]">Approved by</th>
                  <th className="px-4 py-2 font-semibold uppercase text-[10px]">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
                {exceptions.map(e => {
                  const st = STATUS_STYLE[e.status] || STATUS_STYLE.pending;
                  return (
                    <tr key={e.id} style={{ color: 'var(--text-secondary)' }}>
                      <td className="px-4 py-2">
                        <button onClick={() => setInvestigateId(e.identity_id)}
                          className="text-left hover:underline" style={{ color: 'var(--text-primary)' }}>
                          {e.identity_display_name || e.identity_id}
                        </button>
                        {e.business_owner && (
                          <div className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                            owner: {e.business_owner}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-2 font-mono text-[10px]">{e.policy_id}</td>
                      <td className="px-4 py-2">
                        <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border"
                          style={{ color: st.text, backgroundColor: st.bg, borderColor: st.border }}>
                          {st.label}
                        </span>
                      </td>
                      <td className="px-4 py-2 font-mono text-[10px]">{fmtDate(e.expires_at)}</td>
                      <td className="px-4 py-2 text-[10px]">{e.requested_by_name || '—'}</td>
                      <td className="px-4 py-2 text-[10px]">{e.approved_by_name || '—'}</td>
                      <td className="px-4 py-2">
                        {adminMode && e.status === 'pending' && (
                          <div className="flex gap-1.5">
                            <button onClick={() => approveException(e)}
                              className="text-[10px] px-2 py-1 rounded border transition"
                              style={{ color: '#34d399', borderColor: 'rgba(52,211,153,0.35)', backgroundColor: 'rgba(52,211,153,0.10)' }}>
                              Approve
                            </button>
                            <button onClick={() => { setRejectModal(e); setRejReason(''); setRejError(null); }}
                              className="text-[10px] px-2 py-1 rounded border transition"
                              style={{ color: '#f87171', borderColor: 'rgba(248,113,113,0.35)', backgroundColor: 'rgba(248,113,113,0.10)' }}>
                              Reject
                            </button>
                          </div>
                        )}
                        {adminMode && e.status === 'approved' && (
                          <button onClick={() => revokeException(e)}
                            className="text-[10px] px-2 py-1 rounded border transition"
                            style={{ color: '#94a3b8', borderColor: 'rgba(148,163,184,0.35)', backgroundColor: 'rgba(148,163,184,0.10)' }}>
                            Revoke
                          </button>
                        )}
                        {!adminMode && e.status === 'pending' && (
                          <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                            admin only
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Request Exception modal */}
      {requestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.7)' }}
          onClick={() => !reqSubmitting && setRequestModal(null)}>
          <div className="max-w-lg w-full rounded-xl border p-5 space-y-3" onClick={e => e.stopPropagation()}
            style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
            <div>
              <h3 className="text-sm font-semibold text-white">Request Exception</h3>
              <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                For agent <span className="text-white">{requestModal.display_name}</span> on policy <span className="font-mono">{requestModal.policy_id}</span>
              </p>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
                Justification <span style={{ color: '#f87171' }}>*</span>
              </label>
              <textarea value={reqJustification} onChange={e => setReqJustification(e.target.value)}
                rows={4}
                placeholder="Why is this risk acceptable? Tied to which business outcome?"
                className="w-full mt-1 px-2 py-1.5 text-xs rounded border"
                style={{ color: 'var(--text-primary)', backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-default)' }}
              />
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>
                {reqJustification.trim().length} / 20 chars min
              </p>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
                Business owner <span style={{ color: '#f87171' }}>*</span>
              </label>
              <input value={reqOwner} onChange={e => setReqOwner(e.target.value)}
                placeholder="Accountable human or team"
                className="w-full mt-1 px-2 py-1.5 text-xs rounded border"
                style={{ color: 'var(--text-primary)', backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-default)' }}
              />
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
                Expires in
              </label>
              <select value={reqDays} onChange={e => setReqDays(Number(e.target.value))}
                className="w-full mt-1 px-2 py-1.5 text-xs rounded border"
                style={{ color: 'var(--text-primary)', backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-default)' }}>
                {EXPIRY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            {reqError && (
              <p className="text-[11px]" style={{ color: '#f87171' }}>{reqError}</p>
            )}
            <div className="flex justify-end gap-2 pt-2">
              <button onClick={() => setRequestModal(null)} disabled={reqSubmitting}
                className="text-xs px-3 py-1.5 rounded border transition"
                style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}>
                Cancel
              </button>
              <button onClick={submitRequest} disabled={reqSubmitting}
                className="text-xs px-3 py-1.5 rounded border transition"
                style={{ color: '#60a5fa', borderColor: 'rgba(59,130,246,0.35)', backgroundColor: 'rgba(59,130,246,0.10)' }}>
                {reqSubmitting ? 'Submitting…' : 'Submit Request'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reject modal */}
      {rejectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.7)' }}
          onClick={() => !rejSubmitting && setRejectModal(null)}>
          <div className="max-w-md w-full rounded-xl border p-5 space-y-3" onClick={e => e.stopPropagation()}
            style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
            <div>
              <h3 className="text-sm font-semibold text-white">Reject Exception</h3>
              <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                Reject the exception request for <span className="text-white">{rejectModal.identity_display_name || rejectModal.identity_id}</span> · <span className="font-mono">{rejectModal.policy_id}</span>
              </p>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>
                Reason <span style={{ color: '#f87171' }}>*</span>
              </label>
              <textarea value={rejReason} onChange={e => setRejReason(e.target.value)} rows={3}
                placeholder="Why is the risk not acceptable?"
                className="w-full mt-1 px-2 py-1.5 text-xs rounded border"
                style={{ color: 'var(--text-primary)', backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-default)' }}
              />
            </div>
            {rejError && (
              <p className="text-[11px]" style={{ color: '#f87171' }}>{rejError}</p>
            )}
            <div className="flex justify-end gap-2 pt-2">
              <button onClick={() => setRejectModal(null)} disabled={rejSubmitting}
                className="text-xs px-3 py-1.5 rounded border transition"
                style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}>
                Cancel
              </button>
              <button onClick={submitReject} disabled={rejSubmitting}
                className="text-xs px-3 py-1.5 rounded border transition"
                style={{ color: '#f87171', borderColor: 'rgba(248,113,113,0.35)', backgroundColor: 'rgba(248,113,113,0.10)' }}>
                {rejSubmitting ? 'Submitting…' : 'Reject'}
              </button>
            </div>
          </div>
        </div>
      )}

      {investigateId && (
        <AIInvestigateDrawer identityId={investigateId} onClose={() => setInvestigateId(null)} />
      )}
    </div>
  );
}
