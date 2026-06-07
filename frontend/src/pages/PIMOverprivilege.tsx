/**
 * PIMOverprivilege — PIM Overprivilege Detection page (AG-PIM-OVERPRIV, 2026-06-07)
 *
 * Surfaces three finding types from eligible-vs-active analysis:
 *   pim_unused_eligibility       — eligible but never activated (cleanup target)
 *   pim_low_frequency_activation — rare activation pattern (time-bound candidate)
 *   pim_weak_activation_control  — activation policy bypasses MFA (config tightening)
 *
 * Source: GET /api/identity-security/pim/overprivilege?identity=&severity=
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';

type Severity = 'critical' | 'high' | 'medium' | 'low';

interface PimIdentity {
  identity_db_id: number;
  identity_id: string;
  display_name: string;
  identity_category: string;
  role_name: string;
  scope: string;
  scope_type: string;
  assignment_type: string;
  days_eligible: number;
  activations_90d: number;
  activations_all_time: number;
  days_since_last_activation: number | null;
  requires_mfa_on_activation: boolean;
  requires_approval: boolean;
  classification: string;
  finding_types: string[];
}

interface PimFinding {
  finding_type: string;
  severity: Severity;
  identity_id: string;
  display_name: string;
  identity_db_id: number;
  title: string;
  evidence: Record<string, unknown>;
  recommendation: string;
}

interface PimResponse {
  identities: PimIdentity[];
  findings: PimFinding[];
  summary: {
    total_eligible_assignments: number;
    total_findings: number;
    by_finding_type: Record<string, number>;
    by_severity: Record<Severity, number>;
  };
  computed_at: string;
}

const SEV_STYLE: Record<Severity, { text: string; bg: string; border: string; dot: string }> = {
  critical: { text: 'text-red-300',     bg: 'bg-red-900/30',     border: 'border-red-800/50',     dot: 'bg-red-400'     },
  high:     { text: 'text-orange-300',  bg: 'bg-orange-900/30',  border: 'border-orange-800/50',  dot: 'bg-orange-400'  },
  medium:   { text: 'text-amber-300',   bg: 'bg-amber-900/30',   border: 'border-amber-800/50',   dot: 'bg-amber-400'   },
  low:      { text: 'text-emerald-300', bg: 'bg-emerald-900/30', border: 'border-emerald-800/50', dot: 'bg-emerald-400' },
};

const FINDING_LABEL: Record<string, string> = {
  pim_unused_eligibility:       'Unused eligibility',
  pim_low_frequency_activation: 'Low-frequency activation',
  pim_weak_activation_control:  'Weak activation control (no MFA)',
};

export default function PIMOverprivilege() {
  const [data, setData] = useState<PimResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [activeFinding, setActiveFinding] = useState<PimFinding | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams();
    if (severity) params.set('severity', severity);
    fetch(`/api/identity-security/pim/overprivilege?${params.toString()}`)
      .then(r => r.json())
      .then((d: PimResponse) => { setData(d); setLoading(false); })
      .catch((e: Error) => { setError(e.message); setLoading(false); });
  }, [severity]);

  useEffect(() => { load(); }, [load]);

  const headlineCopy = useMemo(() => {
    if (!data) return '';
    const s = data.summary;
    if (s.total_findings === 0) {
      return `All ${s.total_eligible_assignments} PIM-eligible assignments look healthy.`;
    }
    const crit = s.by_severity.critical || 0;
    const high = s.by_severity.high || 0;
    return `${s.total_findings} PIM overprivilege findings across ${s.total_eligible_assignments} eligible assignments` +
           ` — ${crit} critical · ${high} high.`;
  }, [data]);

  if (loading && !data) return <div className="p-6 text-sm text-slate-400">Analyzing PIM assignments…</div>;
  if (error) return <div className="p-6 text-sm text-rose-400">{error}</div>;
  if (!data) return null;

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        <p className="text-[10px] uppercase tracking-[0.2em] font-bold text-violet-400">
          Identity Security · PIM Overprivilege
        </p>
        <h1 className="text-2xl font-bold text-slate-100 mt-1">PIM Overprivilege Detection</h1>
        <p className="text-sm text-slate-400 max-w-3xl mt-1">
          Identifies privileged eligibility customers carry but never exercise.
          Reads PIM eligible + active assignments + activation policy. Activation
          history requires Entra ID P2 (centralized auditLogs) — gracefully degrades
          when unavailable.
        </p>
      </div>

      {/* Headline */}
      <div className={`rounded-xl border p-5 ${
        (data.summary.by_severity.critical || 0) > 0
          ? 'border-rose-800/40 bg-rose-900/10'
          : (data.summary.total_findings > 0
              ? 'border-amber-800/40 bg-amber-900/10'
              : 'border-emerald-800/40 bg-emerald-900/10')
      }`}>
        <p className="text-[10px] uppercase tracking-wider font-bold text-slate-300 mb-1">Headline</p>
        <p className="text-xl font-semibold text-slate-100 leading-snug">{headlineCopy}</p>
      </div>

      {/* Summary strip — by finding type */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <SummaryCard label="Eligible assignments" value={data.summary.total_eligible_assignments} />
        <SummaryCard label="Critical" value={data.summary.by_severity.critical || 0}
                     valueClass="text-red-300" />
        <SummaryCard label="High" value={data.summary.by_severity.high || 0}
                     valueClass="text-orange-300" />
        <SummaryCard label="Medium" value={data.summary.by_severity.medium || 0}
                     valueClass="text-amber-300" />
      </div>

      {/* Filter chips */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Severity</span>
        {(['', 'critical','high','medium','low'] as const).map(s => (
          <button key={s || 'all'} onClick={() => setSeverity(s as Severity | '')}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    severity === s
                      ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                      : 'border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}>
            {s || 'all'}
          </button>
        ))}
      </div>

      {/* Findings table */}
      <div className="rounded-xl border border-white/5 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="text-left px-3 py-2 w-24">Severity</th>
              <th className="text-left px-3 py-2 w-48">Finding</th>
              <th className="text-left px-3 py-2">Title</th>
              <th className="text-left px-3 py-2">Identity</th>
              <th className="px-3 py-2 w-20" />
            </tr>
          </thead>
          <tbody>
            {data.findings.map((f, i) => {
              const st = SEV_STYLE[f.severity];
              return (
                <tr key={i}
                    onClick={() => setActiveFinding(f)}
                    className="border-t border-white/5 hover:bg-slate-900/40 transition cursor-pointer">
                  <td className="px-3 py-2">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border font-bold uppercase text-[10px] ${st.bg} ${st.text} ${st.border}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${st.dot}`} />
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-300 font-mono">
                    {FINDING_LABEL[f.finding_type] || f.finding_type}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-200">{f.title}</td>
                  <td className="px-3 py-2 text-xs text-slate-400 font-mono truncate max-w-[240px]">
                    {f.display_name || f.identity_id}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <span className="text-xs text-violet-300">Open →</span>
                  </td>
                </tr>
              );
            })}
            {data.findings.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-8 text-center text-sm text-slate-500">
                  No PIM overprivilege findings at this severity.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* All eligibility table (collapsed below findings) */}
      <details className="rounded-xl border border-white/5 bg-slate-900/40">
        <summary className="px-4 py-3 cursor-pointer text-xs uppercase tracking-wider text-slate-400 font-semibold">
          All PIM-eligible assignments ({data.identities.length})
        </summary>
        <table className="w-full text-xs border-t border-white/5">
          <thead className="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="text-left px-3 py-2">Identity</th>
              <th className="text-left px-3 py-2 w-44">Role</th>
              <th className="text-right px-3 py-2 w-20">Eligible (d)</th>
              <th className="text-right px-3 py-2 w-20">Act 90d</th>
              <th className="text-right px-3 py-2 w-24">Since last</th>
              <th className="text-left px-3 py-2 w-16">MFA</th>
              <th className="text-left px-3 py-2 w-32">Classification</th>
            </tr>
          </thead>
          <tbody>
            {data.identities.map(i => (
              <tr key={i.identity_db_id + ':' + i.role_name}
                  className="border-t border-white/5">
                <td className="px-3 py-2 font-mono text-slate-300 truncate max-w-[280px]">
                  {i.display_name || i.identity_id}
                </td>
                <td className="px-3 py-2 text-slate-300">{i.role_name}</td>
                <td className="px-3 py-2 text-right font-mono text-slate-400">{i.days_eligible}</td>
                <td className="px-3 py-2 text-right font-mono text-slate-400">{i.activations_90d}</td>
                <td className="px-3 py-2 text-right font-mono text-slate-400">
                  {i.days_since_last_activation == null ? '—' : `${i.days_since_last_activation}d`}
                </td>
                <td className="px-3 py-2 text-center">
                  {i.requires_mfa_on_activation
                    ? <span className="text-emerald-400">✓</span>
                    : <span className="text-rose-400 font-bold">✗</span>}
                </td>
                <td className="px-3 py-2 text-[10px] font-mono text-slate-400">
                  {i.classification.replace('_', ' ')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>

      {/* Detail modal */}
      {activeFinding && (
        <FindingDetailModal finding={activeFinding} onClose={() => setActiveFinding(null)} />
      )}
    </div>
  );
}

function SummaryCard({ label, value, valueClass }: { label: string; value: number; valueClass?: string }) {
  return (
    <div className="rounded-xl border border-white/5 bg-slate-900/40 p-3">
      <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">{label}</p>
      <p className={`text-3xl font-bold font-mono mt-1 ${valueClass || 'text-slate-100'}`}>{value}</p>
    </div>
  );
}

function FindingDetailModal({ finding, onClose }: { finding: PimFinding; onClose: () => void }) {
  const st = SEV_STYLE[finding.severity];
  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4"
         onClick={onClose}>
      <div className="bg-[#0f172a] rounded-xl border border-white/10 max-w-2xl w-full max-h-[90vh] overflow-y-auto"
           onClick={e => e.stopPropagation()}>
        <div className="p-5 border-b border-white/5">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <span className={`text-xs font-bold px-2 py-0.5 rounded uppercase ${st.bg} ${st.text} ${st.border} border`}>
              {finding.severity}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              {FINDING_LABEL[finding.finding_type] || finding.finding_type}
            </span>
          </div>
          <h2 className="text-base font-bold text-slate-100">{finding.title}</h2>
          <p className="text-xs text-slate-400 font-mono mt-1">{finding.display_name || finding.identity_id}</p>
        </div>
        <div className="p-5 space-y-3 text-sm">
          <div>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Recommendation</p>
            <p className="text-slate-200 leading-relaxed">{finding.recommendation}</p>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Evidence</p>
            <pre className="text-[11px] text-slate-300 font-mono bg-slate-900/60 border border-white/5 rounded p-2 overflow-x-auto">
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          </div>
        </div>
        <div className="p-3 border-t border-white/5 flex justify-end">
          <button onClick={onClose} className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1">Close</button>
        </div>
      </div>
    </div>
  );
}
