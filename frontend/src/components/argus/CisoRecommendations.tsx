/**
 * CisoRecommendations (AG-188) — Argus Layer 4 UI.
 *
 * Self-fetches GET /api/argus/recommendations and renders the top-N
 * board-ready remediation priorities. Each card carries title, impact,
 * affected count, max blast radius, signal key, suggested action, and
 * the framework refs (NIST / CIS Azure / MITRE) the backend returned.
 *
 * Honesty: when `priorities` is empty we render the backend's `message`
 * verbatim — we never invent a "you're fine!" string. No fake counts.
 */
import React, { useEffect, useState } from 'react';
import { useConnection } from '../../contexts/ConnectionContext';

interface FrameworkRefs {
  nist?: string[] | null;
  cis_azure?: string[] | null;
  mitre?: string[] | null;
}

interface Priority {
  rank: number;
  signal: string;
  title: string;
  impact: string;
  affected_count: number;
  max_blast_radius: number;
  signal_count: number;
  priority_score: number;
  remediation_action: string;
  link_to_queue?: string | null;
  framework_refs?: FrameworkRefs | null;
}

interface RecommendationsResponse {
  priorities: Priority[];
  message?: string | null;
  method?: string;
  total_identities?: number;
  generated_at?: string;
  duration_ms?: number;
}

interface FetchState {
  loading: boolean;
  error: string | null;
  data: RecommendationsResponse | null;
}

// ─── Tiny count-up — runs once when a card mounts ───────────────────────

function useCountUp(target: number, durationMs: number = 600): number {
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
      // ease-out cubic
      const eased = 1 - Math.pow(1 - pct, 3);
      setVal(Math.round(eased * target));
      if (pct < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs]);
  return val;
}

function rankTone(rank: number): { fg: string; bg: string; border: string } {
  if (rank === 1) return { fg: '#f87171', bg: 'rgba(239,68,68,0.10)', border: 'rgba(239,68,68,0.40)' };
  if (rank === 2) return { fg: '#fb923c', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.40)' };
  if (rank === 3) return { fg: '#facc15', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.40)' };
  return { fg: '#94a3b8', bg: 'rgba(148,163,184,0.10)', border: 'rgba(148,163,184,0.30)' };
}

export default function CisoRecommendations() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [state, setState] = useState<FetchState>({
    loading: true, error: null, data: null,
  });

  useEffect(() => {
    let cancelled = false;
    setState({ loading: true, error: null, data: null });

    fetch(withConnection('/api/argus/recommendations'))
      .then(async r => {
        if (!r.ok) throw new Error(`Recommendations failed (${r.status})`);
        return r.json() as Promise<RecommendationsResponse>;
      })
      .then(d => {
        if (!cancelled) setState({ loading: false, error: null, data: d });
      })
      .catch((e: Error) => {
        if (!cancelled) setState({ loading: false, error: e.message, data: null });
      });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  if (state.loading) {
    return (
      <div className="rounded-lg border p-4 flex items-center justify-center"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <div className="animate-spin h-5 w-5 border-2 border-violet-500 border-t-transparent rounded-full" />
        <span className="ml-3 text-xs" style={{ color: 'var(--text-tertiary)' }}>
          Ranking remediation priorities…
        </span>
      </div>
    );
  }

  if (state.error || !state.data) {
    return (
      <div className="rounded-lg border p-3 text-xs text-red-400"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        {state.error ?? 'Failed to load recommendations'}
      </div>
    );
  }

  const { priorities, message, total_identities } = state.data;

  if (!priorities || priorities.length === 0) {
    return (
      <div className="rounded-xl border border-dashed p-6 text-center"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>
          {message || 'No critical fixes recommended.'}
        </p>
        <p className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>
          {typeof total_identities === 'number'
            ? `Scanned ${total_identities.toLocaleString()} identities. None of the ranked signals fired this run.`
            : 'No ranked signals fired this run.'}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="rounded-xl border p-4"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <p className="text-[10px] uppercase tracking-wider font-semibold"
           style={{ color: 'var(--text-tertiary)' }}>
          Argus L4 — top {priorities.length} priorit{priorities.length === 1 ? 'y' : 'ies'} this week
        </p>
        <p className="text-sm font-medium mt-0.5" style={{ color: 'var(--text-primary)' }}>
          What you should fix first — ranked by affected × blast radius
        </p>
        {typeof total_identities === 'number' && (
          <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>
            Scope: {total_identities.toLocaleString()} identities in latest run
          </p>
        )}
      </div>

      <ol className="space-y-2">
        {priorities.map((p, idx) => (
          <PriorityCard key={`${p.rank}-${p.signal}`} priority={p} cascadeMs={idx * 70} />
        ))}
      </ol>
    </div>
  );
}

function PriorityCard({ priority, cascadeMs }: { priority: Priority; cascadeMs: number }) {
  const tone = rankTone(priority.rank);
  const affected = useCountUp(priority.affected_count);
  return (
    <li
      className="rounded-xl border p-4 opacity-0 animate-[fadeIn_360ms_ease-out_forwards]"
      style={{
        animationDelay: `${cascadeMs}ms`,
        borderColor: 'var(--border-subtle)',
        backgroundColor: 'var(--bg-surface)',
      }}
    >
      <div className="flex items-start gap-3">
        <span
          className="flex-shrink-0 inline-flex items-center justify-center w-9 h-9 rounded-lg text-sm font-bold border tabular-nums"
          style={{ borderColor: tone.border, backgroundColor: tone.bg, color: tone.fg }}
        >
          P{priority.rank}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold leading-snug" style={{ color: 'var(--text-primary)' }}>
            {priority.title}
          </p>
          {priority.impact && (
            <p className="text-xs leading-relaxed mt-1" style={{ color: 'var(--text-secondary)' }}>
              {priority.impact}
            </p>
          )}

          {/* Stat strip */}
          <div className="mt-2 flex flex-wrap gap-3 text-[11px]">
            <StatPill label="affected" value={affected.toLocaleString()} mono />
            <StatPill label="max blast" value={priority.max_blast_radius.toLocaleString()} mono />
            <StatPill label="signal" value={priority.signal} />
            <StatPill label="score" value={priority.priority_score.toLocaleString()} mono />
          </div>

          {/* Recommended action */}
          {priority.remediation_action && (
            <div className="mt-2 text-[11px] leading-relaxed"
                 style={{ color: 'var(--text-tertiary)' }}>
              <span className="font-semibold uppercase tracking-wider text-[9px] mr-1.5"
                    style={{ color: 'var(--text-tertiary)' }}>
                Action
              </span>
              {priority.remediation_action}
            </div>
          )}

          {/* Framework refs */}
          {priority.framework_refs && (
            <FrameworkStrip refs={priority.framework_refs} />
          )}
        </div>
      </div>
    </li>
  );
}

function StatPill({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border"
          style={{
            borderColor: 'var(--border-subtle)',
            backgroundColor: 'rgba(15,23,42,0.30)',
            color: 'var(--text-secondary)',
          }}>
      <span className="uppercase tracking-wider text-[9px]"
            style={{ color: 'var(--text-tertiary)' }}>{label}</span>
      <span className={mono ? 'font-mono tabular-nums' : ''}
            style={{ color: 'var(--text-primary)' }}>{value}</span>
    </span>
  );
}

function FrameworkStrip({ refs }: { refs: FrameworkRefs }) {
  const items: Array<{ label: string; tone: string }> = [];
  (refs.nist || []).forEach(n =>
    items.push({ label: `NIST ${n}`, tone: 'bg-blue-500/10 text-blue-300 border-blue-500/30' }));
  (refs.cis_azure || []).forEach(c =>
    items.push({ label: c, tone: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30' }));
  (refs.mitre || []).forEach(m =>
    items.push({ label: `MITRE ${m}`, tone: 'bg-pink-500/10 text-pink-300 border-pink-500/30' }));
  if (items.length === 0) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-1">
      {items.map((it, i) => (
        <span key={i}
              className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${it.tone}`}>
          {it.label}
        </span>
      ))}
    </div>
  );
}
