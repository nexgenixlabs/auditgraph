/**
 * AG-IA-P1 (2026-06-10) — Human Governance page.
 *
 * Frames the human-identity posture signals (MFA enforcement, PIM-eligible
 * access, stale account hygiene, guest expiry) as policy compliance — so
 * a CISO who lands here sees a SailPoint-style policy scorecard, not an
 * AI Governance dashboard.
 *
 * Policies are NOT customisable in this view — they encode the Entra +
 * NIST AC-2 / AC-6 minimums we'd flag in any audit. Customer-defined
 * policies will land in a later iteration.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import LoadingState from '../components/LoadingState';
import { NoDataInScopeState } from '../components/EmptyState';

interface HumanRow {
  id: number;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  mfa_status?: string | null;
  last_seen_at?: string | null;
  pim_eligible?: boolean | null;
  status: string;
}

interface Policy {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  rationale: string;
  benchmark: string[];
  evaluate: (rows: HumanRow[]) => { violators: number; total: number };
  drillTo: string;
}

const POLICIES: Policy[] = [
  {
    id: 'mfa_required',
    severity: 'critical',
    title: 'Every human account must have MFA enforced',
    rationale: 'Credential phishing remains the #1 initial-access vector. Disabled or unknown MFA is the gap.',
    benchmark: ['NIST AC-2(11)', 'Entra Identity Protection'],
    evaluate: rows => {
      const total = rows.length;
      const violators = rows.filter(r => {
        const m = (r.mfa_status || '').toLowerCase();
        return m === 'disabled' || m === '' || m === 'unknown';
      }).length;
      return { violators, total };
    },
    drillTo: '/identity-explorer/humans?mfa=disabled',
  },
  {
    id: 'no_standing_admin',
    severity: 'critical',
    title: 'No human should hold standing Owner/Contributor/UAA roles',
    rationale: 'Use PIM-eligible elevation for privileged roles. Standing admin = breach blast radius.',
    benchmark: ['NIST AC-6', 'CIS Azure 1.21', 'ISO 27001 A.9.2.3'],
    evaluate: rows => {
      const total = rows.length;
      const violators = rows.filter(r => (r.risk_score || 0) >= 70 && !r.pim_eligible).length;
      return { violators, total };
    },
    drillTo: '/identity-security/pim?type=human',
  },
  {
    id: 'no_stale_humans',
    severity: 'high',
    title: 'Humans inactive for 90+ days must be reviewed for offboarding',
    rationale: 'Inactive accounts are credential reservoirs for attackers. Disable or re-certify.',
    benchmark: ['NIST AC-2(3)', 'ISO 27001 A.9.2.6'],
    evaluate: rows => {
      const total = rows.length;
      const now = Date.now();
      const violators = rows.filter(r => {
        if (!r.last_seen_at) return false;
        const t = new Date(r.last_seen_at).getTime();
        return Number.isFinite(t) && (now - t) > 90 * 24 * 60 * 60 * 1000;
      }).length;
      return { violators, total };
    },
    drillTo: '/identity-explorer/humans?status=stale',
  },
  {
    id: 'guest_lifecycle',
    severity: 'high',
    title: 'Guest accounts must be time-bound or quarterly re-certified',
    rationale: 'Permanent guest access is a common audit finding. Cap with sponsorship + expiry.',
    benchmark: ['ISO 27001 A.9.2.5', 'CIS Azure 1.23'],
    evaluate: rows => {
      const guests = rows.filter(r => r.identity_category === 'guest');
      return { violators: guests.length, total: guests.length };
    },
    drillTo: '/identity-explorer/humans?identity_category=guest',
  },
  {
    id: 'no_critical_human',
    severity: 'critical',
    title: 'No human identity should be classified critical risk',
    rationale: 'A human at critical risk indicates compounding posture failures (no MFA + privileged + stale).',
    benchmark: ['NIST RA-3'],
    evaluate: rows => {
      const total = rows.length;
      const violators = rows.filter(r => r.risk_level === 'critical').length;
      return { violators, total };
    },
    drillTo: '/identity-explorer/humans?risk_level=critical',
  },
];

const SEVERITY_STYLE: Record<Policy['severity'], { bg: string; text: string; border: string }> = {
  critical: { bg: 'rgba(239,68,68,0.10)',  text: '#f87171', border: 'rgba(239,68,68,0.40)' },
  high:     { bg: 'rgba(251,146,60,0.10)', text: '#fb923c', border: 'rgba(251,146,60,0.40)' },
  medium:   { bg: 'rgba(245,158,11,0.10)', text: '#fbbf24', border: 'rgba(245,158,11,0.40)' },
  low:      { bg: 'rgba(156,163,175,0.10)',text: '#9ca3af', border: 'rgba(156,163,175,0.40)' },
};

export default function HumanGovernance() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  const [rows, setRows] = useState<HumanRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch(withConnection('/api/identities?identity_category=human_user,guest&limit=500'))
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (cancelled) return;
        if (!d || !Array.isArray(d.identities)) { setError('no_data'); return; }
        setRows(d.identities);
      })
      .catch(() => { if (!cancelled) setError('fetch_error'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  const evaluated = useMemo(() => {
    return POLICIES.map(p => ({ ...p, ...p.evaluate(rows) }));
  }, [rows]);

  const overall = useMemo(() => {
    const totalChecks = evaluated.reduce((a, p) => a + p.total, 0);
    const totalViolations = evaluated.reduce((a, p) => a + p.violators, 0);
    const compliancePct = totalChecks > 0 ? Math.round(((totalChecks - totalViolations) / totalChecks) * 100) : 0;
    const violatingPolicies = evaluated.filter(p => p.violators > 0).length;
    return { totalChecks, totalViolations, compliancePct, violatingPolicies };
  }, [evaluated]);

  if (loading) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto">
        <LoadingState message="Loading human identity governance posture..." />
      </div>
    );
  }

  if (error || rows.length === 0) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto space-y-4">
        <div className="px-1">
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Human Governance</h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
            Policy compliance scorecard for human identities — MFA, standing admin, stale,
            guest lifecycle. Mapped to NIST AC-2 / AC-6 / ISO 27001 A.9.
          </p>
        </div>
        <NoDataInScopeState title="No human identities in scope" subjects="human identities" />
      </div>
    );
  }

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span style={{ color: 'var(--accent-primary)' }}>Identity</span>
          <span>·</span>
          <span>Human</span>
          <span>·</span>
          <span>Governance</span>
        </div>
        <h1 className="text-2xl font-bold mt-1" style={{ color: 'var(--text-primary)' }}>Human Governance</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Policy compliance scorecard for{' '}
          <strong style={{ color: 'var(--text-primary)' }}>{rows.length}</strong>{' '}
          human identities — NIST AC-2 / AC-6 / ISO 27001 A.9 mapped. Derived from architecture (no log dependency).
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Overall Compliance</p>
          <p className="text-3xl font-bold font-mono mt-2" style={{ color: overall.compliancePct >= 80 ? '#4ade80' : overall.compliancePct >= 50 ? '#fbbf24' : '#f87171' }}>{overall.compliancePct}%</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>mean across {POLICIES.length} policies</p>
        </div>
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Humans in Violation</p>
          <p className="text-3xl font-bold font-mono mt-2" style={{ color: '#f87171' }}>{overall.totalViolations}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>of {overall.totalChecks} policy checks</p>
        </div>
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Violating Policies</p>
          <p className="text-3xl font-bold font-mono mt-2" style={{ color: '#fb923c' }}>{overall.violatingPolicies}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>of {POLICIES.length} active</p>
        </div>
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Active Policies</p>
          <p className="text-3xl font-bold font-mono mt-2" style={{ color: 'var(--text-primary)' }}>{POLICIES.length}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>NIST / CIS / ISO mapped</p>
        </div>
      </div>

      <div className="rounded-xl border" style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
        <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
          <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Policy Compliance</h3>
          <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
            Most-violated first · click a policy to drill into the violators
          </p>
        </div>
        <div className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
          {evaluated
            .sort((a, b) => b.violators - a.violators)
            .map(p => {
              const sty = SEVERITY_STYLE[p.severity];
              const compliancePct = p.total > 0 ? Math.round(((p.total - p.violators) / p.total) * 100) : 100;
              const barColor = compliancePct >= 80 ? '#4ade80' : compliancePct >= 50 ? '#fbbf24' : '#f87171';
              return (
                <button
                  key={p.id}
                  onClick={() => p.violators > 0 && navigate(p.drillTo)}
                  className="w-full px-4 py-3 flex items-center gap-4 hover:bg-slate-800/30 transition-colors text-left"
                  disabled={p.violators === 0}
                >
                  <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded flex-shrink-0"
                    style={{ backgroundColor: sty.bg, color: sty.text, border: `1px solid ${sty.border}` }}>
                    {p.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{p.title}</p>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {p.benchmark.map((b, bi) => (
                        <span key={bi} className="text-[9px] font-mono px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-elevated)', color: 'var(--text-muted)' }}>{b}</span>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    <span className="text-xs font-mono" style={{ color: p.violators > 0 ? '#f87171' : '#4ade80' }}>
                      {p.violators > 0 ? `${p.violators} violating` : 'compliant'}
                    </span>
                    <div className="w-24 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full rounded-full" style={{ backgroundColor: barColor, width: `${compliancePct}%` }} />
                    </div>
                    <span className="text-xs font-mono w-12 text-right" style={{ color: 'var(--text-secondary)' }}>{compliancePct}%</span>
                  </div>
                </button>
              );
            })}
        </div>
      </div>
    </div>
  );
}
