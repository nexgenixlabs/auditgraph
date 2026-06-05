/**
 * PeerBenchmarking — Week 7 of the IA roadmap (network-effect moat)
 *
 * Per peer review v3/v4: "peer benchmarking page may become more valuable
 * than patents over time." Customers stop scrolling when they see they're
 * in the 12th percentile for AI agent ownership coverage.
 *
 * Sources:
 *   GET  /api/peer-benchmarking/snapshot?industry=X&size_band=Y
 *   POST /api/peer-benchmarking/seed-demo  (demo-only)
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';

type Band = 'top_10' | 'top_25' | 'above_median' | 'below_median'
          | 'bottom_25' | 'bottom_10' | 'unknown';

interface PeerStats {
  n: number;
  p10: number; p25: number; p50: number; p75: number; p90: number;
}

interface Metric {
  metric_key: string;
  label: string;
  description: string;
  unit: string;
  higher_is_better: boolean;
  your_value: number | null;
  peers: PeerStats | null;
  percentile_band: Band | null;
  narrative: string;
}

interface BenchmarkResponse {
  industry: string;
  org_size_band: string;
  metrics: Metric[];
}

const BAND_STYLE: Record<Band, { text: string; bg: string; border: string; label: string }> = {
  top_10:        { text: 'text-emerald-200', bg: 'bg-emerald-900/30', border: 'border-emerald-700/50', label: 'Top 10%' },
  top_25:        { text: 'text-emerald-300', bg: 'bg-emerald-900/20', border: 'border-emerald-800/40', label: 'Top 25%' },
  above_median:  { text: 'text-blue-300',    bg: 'bg-blue-900/20',    border: 'border-blue-800/40',    label: 'Above median' },
  below_median:  { text: 'text-amber-300',   bg: 'bg-amber-900/20',   border: 'border-amber-800/40',   label: 'Below median' },
  bottom_25:     { text: 'text-orange-300',  bg: 'bg-orange-900/30',  border: 'border-orange-800/40',  label: 'Bottom 25%' },
  bottom_10:     { text: 'text-red-300',     bg: 'bg-red-900/30',     border: 'border-red-800/40',     label: 'Bottom 10%' },
  unknown:       { text: 'text-slate-400',   bg: 'bg-slate-800/30',   border: 'border-slate-700/50',   label: '—' },
};

const INDUSTRIES = ['tech', 'healthcare', 'financial_services', 'retail'] as const;
const SIZE_BANDS = ['smb_under_500', 'mid_500_5000', 'ent_5000_50000'] as const;
const SIZE_LABEL: Record<string, string> = {
  smb_under_500:    'SMB (<500)',
  mid_500_5000:     'Mid (500-5K)',
  ent_5000_50000:   'Enterprise (5K-50K)',
};

export default function PeerBenchmarking() {
  const [data, setData] = useState<BenchmarkResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [industry, setIndustry] = useState<string>('tech');
  const [sizeBand, setSizeBand] = useState<string>('mid_500_5000');
  const [seeding, setSeeding] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    fetch(`/api/peer-benchmarking/snapshot?industry=${industry}&size_band=${sizeBand}`)
      .then(r => r.json())
      .then((d: BenchmarkResponse) => { setData(d); setLoading(false); })
      .catch((e: Error) => { setError(e.message); setLoading(false); });
  }, [industry, sizeBand]);

  useEffect(() => { load(); }, [load]);

  const seedDemo = async () => {
    if (seeding) return;
    setSeeding(true);
    try {
      const r = await fetch(`/api/peer-benchmarking/seed-demo?industry=${industry}&size_band=${sizeBand}`, {
        method: 'POST',
      });
      if (!r.ok) {
        const body = await r.json().catch(() => null);
        throw new Error(body?.error || `Seed failed (${r.status})`);
      }
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSeeding(false);
    }
  };

  const summary = useMemo(() => {
    if (!data) return null;
    const m = data.metrics;
    const placed = m.filter(x => x.percentile_band && x.percentile_band !== 'unknown');
    const top  = placed.filter(x => x.percentile_band === 'top_10' || x.percentile_band === 'top_25').length;
    const bot  = placed.filter(x => x.percentile_band === 'bottom_10' || x.percentile_band === 'bottom_25').length;
    return { total: m.length, placed: placed.length, top, bot };
  }, [data]);

  if (loading && !data) return <div className="p-6 text-sm text-slate-400">Computing peer benchmarks…</div>;
  if (error) return <div className="p-6 text-sm text-rose-400">{error}</div>;
  if (!data) return null;

  const noPeers = data.metrics.every(m => !m.peers);

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        <p className="text-[10px] uppercase tracking-[0.2em] font-bold text-violet-400">
          Governance &amp; Assurance · Peer Benchmarking
        </p>
        <h1 className="text-2xl font-bold text-slate-100 mt-1">Peer Benchmarking</h1>
        <p className="text-sm text-slate-400 max-w-3xl mt-1">
          See where your identity-security posture lands vs. anonymized peers
          in your industry and org size. Aggregates require ≥10 contributing
          orgs per bucket — smaller buckets return no comparison.
        </p>
      </div>

      {/* Industry + size selector */}
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Industry</span>
        {INDUSTRIES.map(i => (
          <button key={i} onClick={() => setIndustry(i)}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    industry === i ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                                   : 'border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}>
            {i.replace('_', ' ')}
          </button>
        ))}
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold ml-3">Size</span>
        {SIZE_BANDS.map(s => (
          <button key={s} onClick={() => setSizeBand(s)}
                  className={`text-xs px-2 py-1 rounded border transition ${
                    sizeBand === s ? 'border-violet-700 bg-violet-900/30 text-violet-200'
                                   : 'border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}>
            {SIZE_LABEL[s] || s}
          </button>
        ))}
      </div>

      {/* No peers yet — offer seed (demo only) */}
      {noPeers && (
        <div className="rounded-xl border border-amber-800/40 bg-amber-900/10 p-4 flex items-center justify-between gap-3">
          <div>
            <p className="text-sm text-amber-200">
              No peer aggregates yet for {industry.replace('_', ' ')} · {SIZE_LABEL[sizeBand]}.
            </p>
            <p className="text-xs text-amber-300/70 mt-1">
              In production, peer data accumulates as customers run their nightly snapshot
              job. For the demo, you can seed a synthetic bucket below.
            </p>
          </div>
          <button onClick={seedDemo} disabled={seeding}
                  className="text-xs px-3 py-1.5 rounded bg-amber-700 hover:bg-amber-600 text-white font-semibold whitespace-nowrap disabled:opacity-50">
            {seeding ? 'Seeding…' : 'Seed demo data'}
          </button>
        </div>
      )}

      {/* Summary card */}
      {summary && summary.placed > 0 && (
        <div className="rounded-xl border border-violet-800/40 bg-violet-900/10 p-5">
          <p className="text-[10px] uppercase tracking-wider text-violet-300 font-bold mb-1">Headline</p>
          <p className="text-xl font-semibold text-violet-100 leading-snug">
            <span className="font-mono">{summary.top}</span> of <span className="font-mono">{summary.placed}</span> tracked
            metrics put you in the top quartile.{' '}
            {summary.bot > 0 && (
              <span className="text-rose-300">
                <span className="font-mono">{summary.bot}</span> in the bottom quartile.
              </span>
            )}
          </p>
        </div>
      )}

      {/* Per-metric cards */}
      <div className="space-y-3">
        {data.metrics.map(m => (
          <MetricCard key={m.metric_key} metric={m} />
        ))}
      </div>
    </div>
  );
}

function MetricCard({ metric: m }: { metric: Metric }) {
  const band = (m.percentile_band || 'unknown') as Band;
  const st = BAND_STYLE[band];
  const peers = m.peers;
  const v = m.your_value;

  // For the visual bar: place "you" relative to p10..p90
  const placeOnBar = (val: number, p10: number, p90: number): number => {
    if (p90 <= p10) return 50;
    return Math.max(0, Math.min(100, ((val - p10) / (p90 - p10)) * 100));
  };

  return (
    <div className={`rounded-xl border ${st.border} bg-slate-900/40 p-4`}>
      <div className="flex items-start justify-between gap-4 mb-2">
        <div>
          <p className="text-sm font-semibold text-slate-100">{m.label}</p>
          <p className="text-xs text-slate-400 mt-0.5">{m.description}</p>
        </div>
        <div className="text-right">
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${st.bg} ${st.text} ${st.border} border uppercase`}>
            {st.label}
          </span>
          <p className="text-[10px] text-slate-500 mt-1">
            {m.higher_is_better ? 'higher is better' : 'lower is better'}
          </p>
        </div>
      </div>

      {peers && v !== null ? (
        <>
          <div className="flex items-baseline gap-4 mt-3">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Your value</p>
              <p className={`text-2xl font-bold font-mono ${st.text}`}>{v}{m.unit === '%' ? '%' : ''}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Peer median</p>
              <p className="text-2xl font-bold font-mono text-slate-300">{peers.p50.toFixed(1)}{m.unit === '%' ? '%' : ''}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Sample</p>
              <p className="text-2xl font-bold font-mono text-slate-400">n={peers.n}</p>
            </div>
          </div>

          {/* Percentile distribution bar */}
          <div className="mt-4 relative">
            <div className="flex h-2.5 rounded-full overflow-hidden">
              <div className="bg-red-900/40"     style={{ flex: 1 }} title={`<= p10 (${peers.p10.toFixed(1)})`} />
              <div className="bg-orange-900/40"  style={{ flex: 1.5 }} title={`p10-p25 (${peers.p10.toFixed(1)}-${peers.p25.toFixed(1)})`} />
              <div className="bg-amber-900/40"   style={{ flex: 2.5 }} title={`p25-p50 (${peers.p25.toFixed(1)}-${peers.p50.toFixed(1)})`} />
              <div className="bg-blue-900/40"    style={{ flex: 2.5 }} title={`p50-p75 (${peers.p50.toFixed(1)}-${peers.p75.toFixed(1)})`} />
              <div className="bg-emerald-900/40" style={{ flex: 1.5 }} title={`p75-p90 (${peers.p75.toFixed(1)}-${peers.p90.toFixed(1)})`} />
              <div className="bg-emerald-700/40" style={{ flex: 1 }} title={`>= p90 (${peers.p90.toFixed(1)})`} />
            </div>
            <div className="absolute top-[-4px] -translate-x-1/2"
                 style={{ left: `${placeOnBar(v, peers.p10, peers.p90)}%` }}>
              <div className="w-3 h-3 bg-white rounded-full border-2 border-slate-900 shadow" title={`You: ${v}`} />
            </div>
            <div className="flex justify-between mt-1 text-[9px] font-mono text-slate-500">
              <span>p10: {peers.p10.toFixed(1)}</span>
              <span>p25: {peers.p25.toFixed(1)}</span>
              <span>p50: {peers.p50.toFixed(1)}</span>
              <span>p75: {peers.p75.toFixed(1)}</span>
              <span>p90: {peers.p90.toFixed(1)}</span>
            </div>
          </div>
        </>
      ) : (
        <div className="mt-3 text-xs text-slate-500">{m.narrative}</div>
      )}

      {peers && (
        <p className="mt-3 text-xs text-slate-300 leading-relaxed"
           dangerouslySetInnerHTML={{ __html: m.narrative.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') }} />
      )}
    </div>
  );
}
