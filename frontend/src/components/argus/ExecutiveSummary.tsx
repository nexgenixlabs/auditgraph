/**
 * ExecutiveSummary (AG-191) — Argus Layer 7 UI.
 *
 * Board-ready, one-paragraph executive narrative for one of the four
 * canonical topics. Self-fetches GET /api/argus/executive-summary?topic=…
 * and renders the prose verbatim alongside the underlying stats (score,
 * compliant/critical counts, regulated-data reachability, optional trend).
 *
 * Honesty: trend_delta_pct / trend_days are OPTIONAL on the backend —
 * we only show the trend chip when both are present. Score is the mean
 * of the five canonical board-scorecard KPIs as persisted in
 * ai_board_scorecard_snapshots.
 */
import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useConnection } from '../../contexts/ConnectionContext';

interface TopicDef {
  topic: string;
  label: string;
  hint: string;
}

const TOPICS: TopicDef[] = [
  { topic: 'ai_agents_secure', label: 'Are our AI agents secure?',          hint: 'AI-agent population — direct projection' },
  { topic: 'nhi_secure',       label: 'Are our NHIs secure?',               hint: 'AI-classified non-human identity subset' },
  { topic: 'oauth_secure',     label: 'Are our OAuth integrations secure?', hint: 'OAuth-capable identities — policy_compliant_pct' },
  { topic: 'overall_posture',  label: 'How is our overall posture?',        hint: 'Five board-scorecard KPIs averaged' },
];

interface ExecStats {
  total?: number;
  compliant?: number;
  critical?: number;
  regulated_data_reaching?: number;
  score?: number;
  trend_delta_pct?: number;
  trend_days?: number;
}

interface ExecResponse {
  topic: string;
  prose?: string;
  stats?: ExecStats | null;
  citation_link?: string;
  generated_at?: string;
  reason?: string;
}

interface FetchState {
  loading: boolean;
  error: string | null;
  data: ExecResponse | null;
}

function useCountUp(target: number, durationMs: number = 700): number {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!Number.isFinite(target) || target <= 0) {
      setVal(target);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const step = (t: number) => {
      const pct = Math.min(1, (t - start) / durationMs);
      const eased = 1 - Math.pow(1 - pct, 3);
      setVal(Math.round(eased * target));
      if (pct < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs]);
  return val;
}

export default function ExecutiveSummary() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [topic, setTopic] = useState<string>(TOPICS[0].topic);
  const [state, setState] = useState<FetchState>({
    loading: false, error: null, data: null,
  });

  useEffect(() => {
    let cancelled = false;
    setState({ loading: true, error: null, data: null });
    fetch(withConnection(`/api/argus/executive-summary?topic=${encodeURIComponent(topic)}`))
      .then(async r => {
        if (!r.ok) throw new Error(`Executive summary failed (${r.status})`);
        return r.json() as Promise<ExecResponse>;
      })
      .then(d => { if (!cancelled) setState({ loading: false, error: null, data: d }); })
      .catch((e: Error) => {
        if (!cancelled) setState({ loading: false, error: e.message, data: null });
      });
    return () => { cancelled = true; };
  }, [topic, withConnection, selectedConnectionId]);

  return (
    <div className="space-y-4">
      {/* Topic picker */}
      <div className="rounded-xl border p-4"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <label className="text-[10px] uppercase tracking-wider font-semibold block mb-1"
               style={{ color: 'var(--text-tertiary)' }}>
          Topic
        </label>
        <select
          value={topic}
          onChange={e => setTopic(e.target.value)}
          className="w-full text-xs px-2 py-1.5 rounded border max-w-md"
          style={{
            borderColor: 'var(--border-default)',
            backgroundColor: 'var(--bg-raised)',
            color: 'var(--text-primary)',
          }}
        >
          {TOPICS.map(t => (
            <option key={t.topic} value={t.topic}>{t.label}</option>
          ))}
        </select>
        <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>
          {(TOPICS.find(t => t.topic === topic) || TOPICS[0]).hint}
        </p>
      </div>

      {state.loading && (
        <div className="rounded-lg border p-4 flex items-center justify-center"
             style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
          <div className="animate-spin h-5 w-5 border-2 border-violet-500 border-t-transparent rounded-full" />
          <span className="ml-3 text-xs" style={{ color: 'var(--text-tertiary)' }}>
            Pulling board-scorecard snapshot…
          </span>
        </div>
      )}

      {state.error && !state.loading && (
        <div className="rounded-lg border p-3 text-xs text-red-400"
             style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
          {state.error}
        </div>
      )}

      {state.data && !state.loading && (
        <ExecBody data={state.data} />
      )}
    </div>
  );
}

function ExecBody({ data }: { data: ExecResponse }) {
  const stats = data.stats || {};
  const total = useCountUp(Number(stats.total || 0));
  const compliant = useCountUp(Number(stats.compliant || 0));
  const critical = useCountUp(Number(stats.critical || 0));
  const regulated = useCountUp(Number(stats.regulated_data_reaching || 0));
  const score = useCountUp(Number(stats.score || 0), 900);

  const hasTrend =
    typeof stats.trend_delta_pct === 'number' &&
    typeof stats.trend_days === 'number';

  // No prose AND no stats => engine could not pull a snapshot.
  const empty =
    !data.prose &&
    !stats.total &&
    !stats.compliant &&
    !stats.critical;

  if (empty) {
    return (
      <div className="rounded-xl border border-dashed p-6 text-center"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>
          No executive narrative available yet
        </p>
        <p className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>
          {data.reason ||
            'No board-scorecard snapshots persisted yet — the next nightly job will populate this view.'}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3 animate-[fadeIn_280ms_ease-out]">
      {/* Prose paragraph */}
      <div className="rounded-xl border p-4"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <p className="text-[10px] uppercase tracking-wider font-semibold mb-2"
           style={{ color: 'var(--text-tertiary)' }}>
          Argus L7 — board narrative
        </p>
        <p className="text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
          {data.prose || '—'}
        </p>
        {data.citation_link && (
          <Link
            to={data.citation_link}
            className="text-[10px] uppercase tracking-wider font-medium hover:underline mt-2 inline-block"
            style={{ color: '#a78bfa' }}
          >
            See the underlying scorecard →
          </Link>
        )}
      </div>

      {/* Stat grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
        <BigStat label="Score" value={`${score}`} accent />
        <BigStat label="Cohort total"          value={total.toLocaleString()} />
        <BigStat label="Compliant"             value={compliant.toLocaleString()} />
        <BigStat label="Critical"              value={critical.toLocaleString()} alarm />
        <BigStat label="Reach regulated data"  value={regulated.toLocaleString()} />
      </div>

      {/* Trend */}
      {hasTrend && (
        <div className="rounded-xl border px-3 py-2 inline-flex items-center gap-2"
             style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
          <span className="text-[10px] uppercase tracking-wider font-semibold"
                style={{ color: 'var(--text-tertiary)' }}>
            Trend
          </span>
          <span className="text-xs font-mono tabular-nums"
                style={{
                  color: (stats.trend_delta_pct ?? 0) >= 0 ? '#4ade80' : '#f87171',
                }}>
            {(stats.trend_delta_pct ?? 0) >= 0 ? '+' : ''}
            {(stats.trend_delta_pct ?? 0).toFixed(1)}
          </span>
          <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
            over {stats.trend_days} days
          </span>
        </div>
      )}
    </div>
  );
}

function BigStat({
  label, value, accent, alarm,
}: { label: string; value: string; accent?: boolean; alarm?: boolean }) {
  const color = accent ? '#a78bfa' : alarm ? '#f87171' : 'var(--text-primary)';
  return (
    <div className="rounded-xl border p-3"
         style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
      <p className="text-[10px] uppercase tracking-wider font-semibold"
         style={{ color: 'var(--text-tertiary)' }}>
        {label}
      </p>
      <p className="text-xl font-bold tabular-nums mt-0.5" style={{ color }}>
        {value}
      </p>
    </div>
  );
}
