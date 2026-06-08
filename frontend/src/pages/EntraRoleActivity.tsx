/**
 * EntraRoleActivity — Feature E Phase 2 page (AG-FEATURE-E-P2, 2026-06-07)
 *
 * For every Entra directory role assignment, shows per-role last-used
 * activity inferred from auditLogs/directoryAudits.
 *
 * Source: GET /api/identity-security/entra-role-activity?dormancy=
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';

type Band = 'high' | 'medium' | 'low' | 'unknown';
type Bucket = 'daily' | 'weekly' | 'monthly' | 'rare' | 'dormant' | 'unknown';

interface ActivityRow {
  identity_db_id: number;
  identity_id: string;
  display_name: string;
  identity_category: string;
  role_name: string;
  role_template_id: string | null;
  last_action_at: string | null;
  days_since_last_action: number | null;
  activities_30d: number | null;
  activities_90d: number | null;
  activity_bucket: Bucket;
  dormancy_band: Band;
  inferred_from: string;
  inference_confidence: string;
}

interface Finding {
  finding_type: string;
  severity: string;
  identity_db_id: number;
  identity_id: string;
  display_name: string;
  title: string;
  evidence: Record<string, unknown>;
  recommendation: string;
}

interface FeatureEResponse {
  rows: ActivityRow[];
  findings: Finding[];
  summary: {
    total_assignments: number;
    by_bucket: Record<string, number>;
    by_dormancy: Record<string, number>;
    total_findings: number;
  };
  computed_at: string;
}

const BAND_STYLE: Record<Band, { text: string; bg: string; border: string }> = {
  high:    { text: 'text-red-300',     bg: 'bg-red-900/30',     border: 'border-red-800/50' },
  medium:  { text: 'text-amber-300',   bg: 'bg-amber-900/30',   border: 'border-amber-800/50' },
  low:     { text: 'text-emerald-300', bg: 'bg-emerald-900/30', border: 'border-emerald-800/50' },
  unknown: { text: 'text-slate-300',   bg: 'bg-slate-800/40',   border: 'border-slate-700/50' },
};

const BUCKET_LABEL: Record<Bucket, string> = {
  daily: 'Daily',  weekly: 'Weekly',  monthly: 'Monthly',
  rare: 'Rare',    dormant: 'Dormant', unknown: 'Unknown',
};

export default function EntraRoleActivity() {
  const [data, setData] = useState<FeatureEResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [band, setBand] = useState<Band | ''>('');

  const load = useCallback(() => {
    setLoading(true); setError(null);
    const params = new URLSearchParams();
    if (band) params.set('dormancy', band);
    fetch(`/api/identity-security/entra-role-activity?${params.toString()}`)
      .then(r => r.json())
      .then((d: FeatureEResponse) => { setData(d); setLoading(false); })
      .catch((e: Error) => { setError(e.message); setLoading(false); });
  }, [band]);

  useEffect(() => { load(); }, [load]);

  const headline = useMemo(() => {
    if (!data) return '';
    const s = data.summary;
    const high = s.by_dormancy.high || 0;
    if (high > 0) {
      return `${high} privileged directory role assignment${high > 1 ? 's' : ''} with no observed activity in 90+ days — review for least-privilege cleanup.`;
    }
    return `All ${s.total_assignments} directory role assignments show recent activity.`;
  }, [data]);

  if (loading && !data) return <div className="p-6 text-sm text-slate-400">Inferring role activity…</div>;
  if (error) return <div className="p-6 text-sm text-rose-400">{error}</div>;
  if (!data) return null;

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        <p className="text-[10px] uppercase tracking-[0.2em] font-bold text-violet-400">
          Identity Security · Entra Role Activity
        </p>
        <h1 className="text-2xl font-bold text-slate-100 mt-1">
          Entra Directory Role Last-Used
        </h1>
        <p className="text-sm text-slate-400 max-w-3xl mt-1">
          Per-role activity inferred from <code className="text-slate-300">auditLogs/directoryAudits</code> via
          the CATEGORIES_REQUIRING(role) cross-product. Identifies privileged directory role assignments
          that haven't been exercised but are still active grants. Requires Entra ID P2 for full inference;
          gracefully shows "unknown" on tenants without it.
        </p>
      </div>

      {/* Headline */}
      <div className={`rounded-xl border p-5 ${
        (data.summary.by_dormancy.high || 0) > 0
          ? 'border-rose-800/40 bg-rose-900/10'
          : 'border-emerald-800/40 bg-emerald-900/10'
      }`}>
        <p className="text-[10px] uppercase tracking-wider font-bold text-slate-300 mb-1">Headline</p>
        <p className="text-xl font-semibold text-slate-100 leading-snug">{headline}</p>
      </div>

      {/* Summary strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <SumCard label="Role assignments" value={data.summary.total_assignments} />
        <SumCard label="High dormancy (90+ days)" value={data.summary.by_dormancy.high || 0}
                 valueClass="text-red-300" />
        <SumCard label="Medium (30-90 days)" value={data.summary.by_dormancy.medium || 0}
                 valueClass="text-amber-300" />
        <SumCard label="Active (<30 days)" value={data.summary.by_dormancy.low || 0}
                 valueClass="text-emerald-300" />
      </div>

      {/* Filter chips */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Dormancy</span>
        {(['', 'high', 'medium', 'low', 'unknown'] as const).map(b => (
          <button key={b || 'all'} onClick={() => setBand(b as Band | '')}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    band === b
                      ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                      : 'border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}>
            {b || 'all'}
          </button>
        ))}
      </div>

      {/* Assignments table */}
      <div className="rounded-xl border border-white/5 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="text-left px-3 py-2 w-24">Dormancy</th>
              <th className="text-left px-3 py-2">Identity</th>
              <th className="text-left px-3 py-2 w-56">Directory Role</th>
              <th className="text-right px-3 py-2 w-28">Days since last</th>
              <th className="text-right px-3 py-2 w-20">90d acts</th>
              <th className="text-left px-3 py-2 w-24">Bucket</th>
              <th className="text-left px-3 py-2 w-24">Source</th>
            </tr>
          </thead>
          <tbody>
            {data.rows.map(r => {
              const bs = BAND_STYLE[r.dormancy_band];
              return (
                <tr key={r.identity_db_id + ':' + r.role_name}
                    className="border-t border-white/5">
                  <td className="px-3 py-2">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${bs.bg} ${bs.text} ${bs.border} border`}>
                      {r.dormancy_band}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-200 font-mono truncate max-w-[260px]">
                    {r.display_name || r.identity_id}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-200">{r.role_name}</td>
                  <td className="px-3 py-2 text-right font-mono text-slate-300">
                    {r.days_since_last_action == null ? '—' : `${r.days_since_last_action}d`}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-slate-400">
                    {r.activities_90d == null ? '—' : r.activities_90d}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-400">
                    {BUCKET_LABEL[r.activity_bucket] || r.activity_bucket}
                  </td>
                  <td className="px-3 py-2 text-[10px] text-slate-500 font-mono">
                    {r.inference_confidence === 'observed'
                      ? <span className="text-emerald-400">auditLogs</span>
                      : <span className="text-amber-400">unknown</span>}
                  </td>
                </tr>
              );
            })}
            {data.rows.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-sm text-slate-500">
                  No directory role assignments visible at this filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Findings */}
      {data.findings.length > 0 && (
        <div className="rounded-xl border border-rose-800/30 bg-rose-900/10 p-4">
          <p className="text-[10px] uppercase tracking-wider font-bold text-rose-300 mb-2">
            Dormant Privileged Assignments ({data.findings.length})
          </p>
          <div className="space-y-3">
            {data.findings.map((f, i) => (
              <div key={i} className="border border-white/5 bg-slate-900/40 rounded p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                    f.severity === 'critical' ? 'bg-red-900/30 text-red-300 border-red-800/50'
                    : 'bg-orange-900/30 text-orange-300 border-orange-800/50'
                  }`}>{f.severity}</span>
                  <span className="text-xs font-mono text-slate-400">{f.finding_type}</span>
                </div>
                <p className="text-sm text-slate-200 mb-1">{f.title}</p>
                <p className="text-xs text-slate-400 font-mono mb-2">{f.display_name || f.identity_id}</p>
                <p className="text-xs text-slate-300 leading-relaxed">
                  <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mr-1">
                    Recommendation:
                  </span>
                  {f.recommendation}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SumCard({ label, value, valueClass }: { label: string; value: number; valueClass?: string }) {
  return (
    <div className="rounded-xl border border-white/5 bg-slate-900/40 p-3">
      <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">{label}</p>
      <p className={`text-3xl font-bold font-mono mt-1 ${valueClass || 'text-slate-100'}`}>{value}</p>
    </div>
  );
}
