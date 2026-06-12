/**
 * IdentityTrust — Week 2 of the brand/IA pivot
 *
 * Org-wide Identity Trust rollup across ALL non-human identities
 * (SPNs + MIs + AI agents). The 9-dim Trust Score engine was built
 * in Tier 1.3 for AI agents; Week 2 extends the API gate to cover
 * any NHI and surfaces this page as the executive landing for the
 * Identity Security section.
 *
 * Source: GET /api/identity-trust/rollup?threshold=50
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
// AG-POLISH-C (2026-06-10): jargon tooltips
import { TermTooltip } from '../components/TermTooltip';

interface WorstIdentity {
  identity_db_id: number;
  identity_id: string;
  display_name: string;
  trust_score: number;
  failing_dims: string[];
  failing_count: number;
}

interface TrustRollup {
  total_evaluated: number;
  by_band: { strong: number; good: number; elevated: number; critical: number };
  by_dim_failing: Record<string, number>;
  below_threshold_count: number;
  threshold: number;
  worst_identities: WorstIdentity[];
  computed_at: string;
}

const BAND_STYLE = {
  strong:   { text: 'text-emerald-300', bg: 'bg-emerald-900/30', border: 'border-emerald-800/40', dot: 'bg-emerald-400', label: 'Strong'   },
  good:     { text: 'text-blue-300',    bg: 'bg-blue-900/30',    border: 'border-blue-800/40',    dot: 'bg-blue-400',    label: 'Good'     },
  elevated: { text: 'text-amber-300',   bg: 'bg-amber-900/30',   border: 'border-amber-800/40',   dot: 'bg-amber-400',   label: 'Elevated' },
  critical: { text: 'text-red-300',     bg: 'bg-red-900/30',     border: 'border-red-800/40',     dot: 'bg-red-400',     label: 'Critical' },
} as const;

const DIM_LABEL: Record<string, string> = {
  ownership: 'Ownership', secrets: 'Secrets', egress: 'Egress',
  telemetry: 'Telemetry', oversight: 'Oversight',
  data_access: 'Data Access', network: 'Network',
  model_exposure: 'Model Exposure', supply_chain: 'Supply Chain',
};

interface IdentityTrustProps { forceType?: string }

export default function IdentityTrust({ forceType }: IdentityTrustProps = {}) {
  const [data, setData] = useState<TrustRollup | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [threshold, setThreshold] = useState<number>(50);

  // AG-PHASE2 (2026-06-09): scope-aware Trust page. Reads ?type=
  // so Human / NHI / AI tabs all use the same component.
  // Lock-V2 (2026-06-11) — `forceType` prop lets bucket pages embed this
  // without depending on URL query params (the parent owns ?tab= state).
  const params = new URLSearchParams(window.location.search);
  const scope = (forceType || params.get('type') || params.get('scope') || 'nhi').toLowerCase();
  const scopeLabel = ({
    human: 'Human Trust',
    nhi: 'Non-Human Identity Trust',
    ai: 'AI Identity Trust',
    all: 'Identity Trust',
  } as Record<string, string>)[scope] || 'Identity Trust';

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    fetch(`/api/identity-trust/rollup?threshold=${threshold}&type=${encodeURIComponent(scope)}`)
      .then(r => r.json())
      .then((d: TrustRollup) => { setData(d); setLoading(false); })
      .catch((e: Error) => { setError(e.message); setLoading(false); });
  }, [threshold, scope]);

  useEffect(() => { load(); }, [load]);

  const summary = useMemo(() => {
    if (!data) return null;
    const total = data.total_evaluated;
    const failPct = total > 0 ? Math.round((data.below_threshold_count / total) * 100) : 0;
    return { total, failPct };
  }, [data]);

  if (loading && !data) return <div className="p-6 text-sm text-slate-400">Computing org-wide Identity Trust…</div>;
  if (error) return <div className="p-6 text-sm text-rose-400">{error}</div>;
  if (!data || !summary) return null;

  const topFailingDims = Object.entries(data.by_dim_failing)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        {/* AG-PHASE2 (2026-06-09): scope-aware title + copy */}
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span style={{ color: scope === 'human' ? '#3b82f6' : scope === 'ai' ? '#a78bfa' : '#f97316' }}>Identity</span>
          <span>·</span>
          <span>{scope === 'human' ? 'Human' : scope === 'ai' ? 'AI Identity' : scope === 'all' ? 'All Types' : 'Non-Human'}</span>
          <span>·</span>
          <span>Trust</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-100 mt-1">{scopeLabel}</h1>
        <p className="text-sm text-slate-400 max-w-3xl mt-1">
          {scope === 'human' ? (
            <>Trust Score (0-100) across every human identity in your tenant — employees, contractors, and guests. 9 dimensions: Ownership · Secrets (MFA + credential rotation) · Egress · Telemetry · Oversight · Data Access · Network · <TermTooltip term="Blast Radius">Privileged Reach</TermTooltip> · Origin.</>
          ) : scope === 'ai' ? (
            <>Trust Score (0-100) across every AI agent identity in your tenant. 9 dimensions: Ownership · Secrets · Egress · Telemetry · Oversight · Data Access · Network · Model Exposure · Supply Chain.</>
          ) : scope === 'all' ? (
            <>Trust Score (0-100) across every identity in your tenant — humans, <TermTooltip term="NHI">NHIs</TermTooltip>, and AI. 9 dimensions universal across types.</>
          ) : (
            <>Trust Score (0-100) across every non-human identity in your tenant — <TermTooltip term="SPN">service principals</TermTooltip>, <TermTooltip term="MI">managed identities</TermTooltip>, workloads, CI/CD identities, and AI agents. 9 dimensions: Ownership · Secrets · Egress · Telemetry · Oversight · Data Access · Network · <TermTooltip term="Blast Radius">Privileged Reach</TermTooltip> · Supply Chain.</>
          )}
        </p>
      </div>

      {/* Headline — exec-language summary */}
      <div className="rounded-xl border border-rose-800/40 bg-rose-900/10 p-5">
        <p className="text-[10px] uppercase tracking-wider text-rose-300 font-bold mb-1">Headline</p>
        <p className="text-xl font-semibold text-rose-100 leading-snug">
          <span className="font-mono">{data.below_threshold_count}</span> of{' '}
          <span className="font-mono">{summary.total}</span>{' '}
          {scope === 'human' ? 'human identities' : scope === 'ai' ? 'AI agent identities' : scope === 'all' ? 'identities' : 'non-human identities'}
          {' '}have Trust below {threshold} ({summary.failPct}%) — review the worst
          {' '}to remediate first.
        </p>
      </div>

      {/* Band distribution */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {(['strong','good','elevated','critical'] as const).map(band => {
          const st = BAND_STYLE[band];
          const count = data.by_band[band];
          const pct = summary.total > 0 ? Math.round((count / summary.total) * 100) : 0;
          return (
            <div key={band} className={`rounded-xl border ${st.border} ${st.bg} p-3`}>
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${st.dot}`} />
                <p className={`text-[10px] uppercase tracking-wider font-bold ${st.text}`}>
                  {st.label}
                </p>
              </div>
              <p className={`text-3xl font-bold font-mono mt-1 ${st.text}`}>{count}</p>
              <p className="text-[10px] text-slate-500 mt-0.5">
                {pct}% of {scope === 'human' ? 'humans' : scope === 'ai' ? 'AI agents' : scope === 'all' ? 'identities' : 'NHIs'}
              </p>
            </div>
          );
        })}
      </div>

      {/* Threshold control */}
      <div className="flex items-center gap-3">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Trust below</span>
        {[40, 50, 65, 80].map(t => (
          <button key={t} onClick={() => setThreshold(t)}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    threshold === t
                      ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                      : 'border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}>
            {t}
          </button>
        ))}
      </div>

      {/* Top failing dimensions */}
      {topFailingDims.length > 0 && (
        <div className="rounded-xl border border-white/5 bg-slate-900/40 p-4">
          <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 mb-3">
            Top failing dimensions
          </p>
          <div className="space-y-2">
            {topFailingDims.map(([dim, count]) => {
              const pct = summary.total > 0 ? Math.round((count / summary.total) * 100) : 0;
              return (
                <div key={dim} className="flex items-center gap-3">
                  <span className="text-xs text-slate-300 w-32">{DIM_LABEL[dim] || dim}</span>
                  <div className="flex-1 h-2 bg-slate-800 rounded overflow-hidden">
                    <div className="h-full bg-rose-500/70" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-xs font-mono text-rose-300 w-16 text-right">{count}</span>
                  <span className="text-[10px] font-mono text-slate-500 w-10 text-right">{pct}%</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Worst 25 */}
      <div className="rounded-xl border border-white/5 overflow-hidden">
        <div className="bg-slate-900/60 px-3 py-2 border-b border-white/5 text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
          Worst identities — lowest Trust first
        </div>
        <table className="w-full text-sm">
          <thead className="bg-slate-900/40 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="text-left px-3 py-2">Identity</th>
              <th className="text-right px-3 py-2 w-20">Trust</th>
              <th className="text-left px-3 py-2">Failing dimensions</th>
              <th className="px-3 py-2 w-24" />
            </tr>
          </thead>
          <tbody>
            {data.worst_identities.map(w => {
              const band = w.trust_score >= 80 ? 'strong'
                         : w.trust_score >= 65 ? 'good'
                         : w.trust_score >= 40 ? 'elevated' : 'critical';
              const st = BAND_STYLE[band];
              return (
                <tr key={w.identity_db_id} className="border-t border-white/5">
                  <td className="px-3 py-2">
                    <p className="font-mono text-xs text-slate-200">{w.display_name || w.identity_id}</p>
                    <p className="text-[10px] text-slate-500 font-mono mt-0.5">{w.identity_id}</p>
                  </td>
                  <td className="px-3 py-2 text-right">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border font-bold font-mono text-xs ${st.bg} ${st.text} ${st.border}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${st.dot}`} />
                      {w.trust_score}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {w.failing_dims.map(d => (
                        <span key={d} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-900/30 text-rose-300 border border-rose-800/40">
                          {DIM_LABEL[d] || d}
                        </span>
                      ))}
                      {w.failing_dims.length === 0 && (
                        <span className="text-[10px] text-slate-500">—</span>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-right">
                    {/* AG-PILOT-TRUST-ROUTE (2026-06-08): was routing every
                        click to /ai-inventory even for non-AI identities.
                        Route to the canonical identity detail page instead. */}
                    <Link to={`/identities/${encodeURIComponent(w.identity_id)}`}
                          className="text-xs text-violet-300 hover:text-violet-200">
                      Inspect →
                    </Link>
                  </td>
                </tr>
              );
            })}
            {data.worst_identities.length === 0 && (
              <tr>
                <td colSpan={4} className="px-3 py-8 text-center text-sm text-slate-500">
                  No {scope === 'human' ? 'humans' : scope === 'ai' ? 'AI agents' : scope === 'all' ? 'identities' : 'NHIs'} evaluated yet — run a discovery scan.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
