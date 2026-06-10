/**
 * AG-IA-P1 (2026-06-10) — NHI Governance page.
 *
 * Same scorecard pattern as HumanGovernance but the policy catalog is
 * NHI-specific: ownership, credential rotation, blast-radius caps,
 * federated-only trust. Mapped to NIST AC-3 / AC-6 / SC-12 and the
 * NSA/CISA Identity-and-Access SP-800-207 NHI guidance.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import LoadingState from '../components/LoadingState';
import { NoDataInScopeState } from '../components/EmptyState';

interface SpnStats {
  total: number;
  custom: number;
  critical: number;
  high_risk: number;
  expired_credentials: number;
  expiring_soon: number;
  by_blast_radius: Record<string, number>;
  by_risk: Record<string, number>;
  can_escalate_count: number;
  orphaned_privileged: number;
}

interface Policy {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  rationale: string;
  benchmark: string[];
  evaluate: (s: SpnStats) => { violators: number; total: number };
  drillTo: string;
}

const POLICIES: Policy[] = [
  {
    id: 'human_owner',
    severity: 'critical',
    title: 'Every NHI must have an accountable human owner',
    rationale: 'When the incident pages, the response team needs a name. Orphaned NHIs stall incident response.',
    benchmark: ['NIST AC-2', 'NIST PM-15', 'ISO 27001 A.9.2.1'],
    evaluate: s => ({ violators: s.orphaned_privileged, total: s.custom }),
    drillTo: '/ownership?type=nhi',
  },
  {
    id: 'no_expired_creds',
    severity: 'critical',
    title: 'No active NHI may hold an expired client secret',
    rationale: 'Expired secrets on enabled identities are credential time-bombs — rotate or revoke.',
    benchmark: ['NIST IA-5', 'NIST SC-12', 'CIS Azure 1.20'],
    evaluate: s => ({ violators: s.expired_credentials, total: s.custom }),
    drillTo: '/spns?credential_filter=expired',
  },
  {
    id: 'no_subscription_owner',
    severity: 'critical',
    title: 'NHIs must not hold Owner / Contributor / UAA at subscription scope',
    rationale: 'Standing high-privilege roles on automation accounts violate least-privilege guidance.',
    benchmark: ['NIST AC-6', 'CIS Azure 1.23', 'ISO 27001 A.9.2.3'],
    evaluate: s => ({ violators: s.can_escalate_count, total: s.custom }),
    drillTo: '/attack-paths?source_type=nhi',
  },
  {
    id: 'blast_radius_cap',
    severity: 'high',
    title: 'NHIs must not exceed high/critical blast radius without exception',
    rationale: 'A single credential compromise should not unwind the tenant. Scope down.',
    benchmark: ['NIST AC-6', 'NSA/CISA Identity Guidance'],
    evaluate: s => {
      const violators = (s.by_blast_radius?.['high'] || 0) + (s.by_blast_radius?.['critical'] || 0);
      return { violators, total: s.custom };
    },
    drillTo: '/spns?blast_radius=high,critical',
  },
  {
    id: 'rotate_before_expiry',
    severity: 'medium',
    title: 'Client secrets must be rotated more than 30 days before expiry',
    rationale: 'Last-minute rotation causes outages. Triggered rotation is the goal.',
    benchmark: ['NIST IA-5', 'CIS Azure 1.21'],
    evaluate: s => ({ violators: s.expiring_soon, total: s.custom }),
    drillTo: '/spns?credential_filter=expiring_soon',
  },
];

const SEVERITY_STYLE: Record<Policy['severity'], { bg: string; text: string; border: string }> = {
  critical: { bg: 'rgba(239,68,68,0.10)',  text: '#f87171', border: 'rgba(239,68,68,0.40)' },
  high:     { bg: 'rgba(251,146,60,0.10)', text: '#fb923c', border: 'rgba(251,146,60,0.40)' },
  medium:   { bg: 'rgba(245,158,11,0.10)', text: '#fbbf24', border: 'rgba(245,158,11,0.40)' },
  low:      { bg: 'rgba(156,163,175,0.10)',text: '#9ca3af', border: 'rgba(156,163,175,0.40)' },
};

export default function NHIGovernance() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  const [stats, setStats] = useState<SpnStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch(withConnection('/api/spns/stats'))
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (cancelled) return;
        if (!d) { setError('fetch_error'); return; }
        setStats(d);
      })
      .catch(() => { if (!cancelled) setError('fetch_error'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  const evaluated = useMemo(() => {
    if (!stats) return [];
    return POLICIES.map(p => ({ ...p, ...p.evaluate(stats) }));
  }, [stats]);

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
        <LoadingState message="Loading non-human identity governance posture..." />
      </div>
    );
  }

  if (error || !stats || stats.custom === 0) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto space-y-4">
        <div className="px-1">
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Non-Human Identity Governance</h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
            Policy compliance scorecard for NHIs — ownership, credential rotation,
            blast-radius caps. Mapped to NIST AC-3 / AC-6 / SC-12 + NSA/CISA NHI guidance.
          </p>
        </div>
        <NoDataInScopeState title="No non-human identities in scope" subjects="non-human identities" />
      </div>
    );
  }

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span style={{ color: '#fb923c' }}>Identity</span>
          <span>·</span>
          <span>Non-Human</span>
          <span>·</span>
          <span>Governance</span>
        </div>
        <h1 className="text-2xl font-bold mt-1" style={{ color: 'var(--text-primary)' }}>Non-Human Identity Governance</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Policy compliance scorecard for{' '}
          <strong style={{ color: 'var(--text-primary)' }}>{stats.custom}</strong>{' '}
          non-human identities — NIST AC-3 / AC-6 / SC-12 mapped. Derived from architecture (no log dependency).
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>Overall Compliance</p>
          <p className="text-3xl font-bold font-mono mt-2" style={{ color: overall.compliancePct >= 80 ? '#4ade80' : overall.compliancePct >= 50 ? '#fbbf24' : '#f87171' }}>{overall.compliancePct}%</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>mean across {POLICIES.length} policies</p>
        </div>
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold" style={{ color: 'var(--text-tertiary)' }}>NHIs in Violation</p>
          <p className="text-3xl font-bold font-mono mt-2" style={{ color: '#f87171' }}>{overall.totalViolations}</p>
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-muted)' }}>across all policies</p>
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
