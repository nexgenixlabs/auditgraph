/**
 * WhoCanReach (AG-192) — Argus XGRAPH UI.
 *
 * Picks a data classification (PHI, PCI, PII, …) and shows the cohort
 * rollup of identities that can reach any resource in that classification.
 *
 * Endpoint: GET /api/argus/who-can-reach?classification=<CLS>
 *
 * Honesty: `total_records_exposed=None` (rendered "—") means at least
 * one contributing resource has unknown record counts; we never fake a
 * number. Empty cohorts render the backend's `why` string verbatim and
 * carry the backend's `confidence` label.
 */
import React, { useEffect, useState } from 'react';
import { useConnection } from '../../contexts/ConnectionContext';

// Canonical taxonomy from backend constants/data_classification.py
const CLASSIFICATIONS = [
  'PHI', 'PCI', 'PII', 'SOURCE', 'HR', 'FINANCIAL', 'CONFIDENTIAL',
];

interface CommonPathNode {
  node_type: string;
  label: string;
}

interface TopResource {
  resource_id: string;
  classification?: string;
  est_records?: number | null;
}

interface ByCategory {
  human_user: number;
  service_principal: number;
  ai_agent: number;
  oauth_app: number;
}

interface XGraphResponse {
  classification: string;
  by_category?: Partial<ByCategory>;
  total_identities?: number;
  common_path?: CommonPathNode[];
  total_records_exposed?: number | null;
  top_resources?: TopResource[];
  confidence?: 'high' | 'medium' | 'low' | string;
  why?: string;
  resources_in_class?: number;
  duration_ms?: number;
}

interface FetchState {
  loading: boolean;
  error: string | null;
  data: XGraphResponse | null;
}

const CONFIDENCE_TONE: Record<string, string> = {
  high:   'text-emerald-300 bg-emerald-500/10 border-emerald-500/40',
  medium: 'text-amber-300   bg-amber-500/10   border-amber-500/40',
  low:    'text-slate-300   bg-slate-500/10   border-slate-500/40',
};

function useCountUp(target: number, durationMs: number = 600): number {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!Number.isFinite(target) || target <= 0) {
      setVal(target || 0);
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

function categoryColor(key: keyof ByCategory): string {
  switch (key) {
    case 'human_user':        return '#60a5fa';
    case 'service_principal': return '#a78bfa';
    case 'ai_agent':          return '#f9a8d4';
    case 'oauth_app':         return '#fbbf24';
  }
}

function prettyCategory(key: string): string {
  switch (key) {
    case 'human_user':        return 'Human users';
    case 'service_principal': return 'Service principals';
    case 'ai_agent':          return 'AI agents';
    case 'oauth_app':         return 'OAuth apps';
    default: return key;
  }
}

export default function WhoCanReach() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [classification, setClassification] = useState<string>('PHI');
  const [state, setState] = useState<FetchState>({
    loading: false, error: null, data: null,
  });

  useEffect(() => {
    let cancelled = false;
    setState({ loading: true, error: null, data: null });
    fetch(withConnection(`/api/argus/who-can-reach?classification=${encodeURIComponent(classification)}`))
      .then(async r => {
        if (!r.ok) throw new Error(`Reach query failed (${r.status})`);
        return r.json() as Promise<XGraphResponse>;
      })
      .then(d => { if (!cancelled) setState({ loading: false, error: null, data: d }); })
      .catch((e: Error) => {
        if (!cancelled) setState({ loading: false, error: e.message, data: null });
      });
    return () => { cancelled = true; };
  }, [classification, withConnection, selectedConnectionId]);

  return (
    <div className="space-y-4">
      {/* Classification picker */}
      <div className="rounded-xl border p-4"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <p className="text-[11px] mb-2" style={{ color: 'var(--text-secondary)' }}>
          Pick a data classification. Argus traces every identity (human, SP, AI
          agent, OAuth app) whose RBAC reaches a resource in that class and
          reports the cohort split + estimated record exposure.
        </p>
        <div className="flex flex-wrap gap-1.5">
          {CLASSIFICATIONS.map(c => {
            const active = c === classification;
            return (
              <button
                key={c}
                onClick={() => setClassification(c)}
                className={`text-[11px] px-2.5 py-1 rounded border font-mono transition ${
                  active ? 'border-violet-500/60 bg-violet-500/15 text-violet-200'
                         : 'border-slate-700 hover:border-violet-500/40'
                }`}
                style={!active ? { color: 'var(--text-secondary)' } : undefined}
              >
                {c}
              </button>
            );
          })}
        </div>
      </div>

      {state.loading && (
        <div className="rounded-lg border p-4 flex items-center justify-center"
             style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
          <div className="animate-spin h-5 w-5 border-2 border-violet-500 border-t-transparent rounded-full" />
          <span className="ml-3 text-xs" style={{ color: 'var(--text-tertiary)' }}>
            Traversing reach graph…
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
        <ReachBody data={state.data} />
      )}
    </div>
  );
}

function ReachBody({ data }: { data: XGraphResponse }) {
  const totals = data.by_category || {};
  const buckets: Array<{ key: keyof ByCategory; count: number }> = [
    { key: 'human_user',        count: Number(totals.human_user || 0) },
    { key: 'service_principal', count: Number(totals.service_principal || 0) },
    { key: 'ai_agent',          count: Number(totals.ai_agent || 0) },
    { key: 'oauth_app',         count: Number(totals.oauth_app || 0) },
  ];
  const total = useCountUp(Number(data.total_identities || 0));
  const conf = (data.confidence || 'low') as 'high' | 'medium' | 'low';
  const confTone = CONFIDENCE_TONE[conf] || CONFIDENCE_TONE.low;
  const records = data.total_records_exposed;
  const maxBucket = Math.max(1, ...buckets.map(b => b.count));

  const noReach = (data.total_identities || 0) === 0;

  return (
    <div className="space-y-3 animate-[fadeIn_280ms_ease-out]">
      {/* Headline */}
      <div className="rounded-xl border p-4"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <div className="flex items-center flex-wrap gap-2 mb-2">
          <span className="text-[10px] uppercase tracking-wider font-semibold"
                style={{ color: 'var(--text-tertiary)' }}>
            Reach to
          </span>
          <span className="text-sm font-bold font-mono"
                style={{ color: '#a78bfa' }}>
            {data.classification}
          </span>
          <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${confTone}`}>
            {conf} confidence
          </span>
        </div>
        <p className="text-3xl font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>
          {total.toLocaleString()}
          <span className="text-sm font-medium ml-2" style={{ color: 'var(--text-tertiary)' }}>
            identit{total === 1 ? 'y' : 'ies'}
          </span>
        </p>
        {data.why && (
          <p className="text-[11px] mt-1" style={{ color: 'var(--text-tertiary)' }}>
            {data.why}
          </p>
        )}
      </div>

      {/* Empty cohort = stop here, honestly */}
      {noReach ? (
        <div className="rounded-xl border border-dashed p-6 text-center text-xs"
             style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-tertiary)' }}>
          No identity reaches {data.classification}-classified resources in the latest run.
        </div>
      ) : (
        <>
          {/* Cohort split — proportional bars */}
          <div className="rounded-xl border p-4 space-y-2"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <p className="text-[10px] uppercase tracking-wider font-semibold mb-1"
               style={{ color: 'var(--text-tertiary)' }}>
              By identity category
            </p>
            {buckets.map((b, i) => (
              <div
                key={b.key}
                className="opacity-0 animate-[fadeIn_320ms_ease-out_forwards]"
                style={{ animationDelay: `${i * 70}ms` }}
              >
                <div className="flex items-center justify-between text-[11px] mb-0.5">
                  <span style={{ color: 'var(--text-secondary)' }}>{prettyCategory(b.key)}</span>
                  <span className="font-mono tabular-nums" style={{ color: 'var(--text-primary)' }}>
                    {b.count.toLocaleString()}
                  </span>
                </div>
                <div className="h-2 w-full rounded overflow-hidden border"
                     style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'rgba(15,23,42,0.45)' }}>
                  <div
                    className="h-full transition-all duration-500 ease-out"
                    style={{
                      width: `${Math.max(2, (b.count / maxBucket) * 100)}%`,
                      backgroundColor: categoryColor(b.key),
                      opacity: 0.85,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Headline stats: records + scope */}
          <div className="grid grid-cols-3 gap-2">
            <Stat label="Records exposed"
                  value={records === null || records === undefined ? '—' : records.toLocaleString()}
                  hint={records === null || records === undefined
                    ? 'at least one resource missing record_count_estimate'
                    : 'sum across reached resources'} />
            <Stat label="Resources in class"
                  value={(data.resources_in_class || 0).toLocaleString()} />
            <Stat label="Reached"
                  value={(data.top_resources || []).length.toLocaleString()}
                  hint="resources rolled up below" />
          </div>

          {/* Common path */}
          {(data.common_path || []).length > 0 && (
            <div className="rounded-xl border p-4"
                 style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
              <p className="text-[10px] uppercase tracking-wider font-semibold mb-2"
                 style={{ color: 'var(--text-tertiary)' }}>
                Common path
              </p>
              <div className="flex flex-wrap items-center gap-1.5">
                {(data.common_path || []).map((n, i) => (
                  <React.Fragment key={i}>
                    <span className="text-[11px] px-2 py-0.5 rounded border font-mono"
                          style={{
                            borderColor: 'rgba(139,92,246,0.35)',
                            backgroundColor: 'rgba(139,92,246,0.10)',
                            color: '#c4b5fd',
                          }}
                          title={n.node_type}>
                      {n.label}
                    </span>
                    {i < (data.common_path || []).length - 1 && (
                      <span style={{ color: 'var(--text-tertiary)' }}>→</span>
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {/* Top resources */}
          {(data.top_resources || []).length > 0 && (
            <div className="rounded-xl border p-4"
                 style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
              <p className="text-[10px] uppercase tracking-wider font-semibold mb-2"
                 style={{ color: 'var(--text-tertiary)' }}>
                Top {(data.top_resources || []).length} reached resources
              </p>
              <ul className="space-y-1">
                {(data.top_resources || []).map((r, i) => (
                  <li key={`${r.resource_id}-${i}`}
                      className="text-[11px] font-mono truncate"
                      style={{ color: 'var(--text-secondary)' }}
                      title={r.resource_id}>
                    <span className="tabular-nums mr-2" style={{ color: 'var(--text-tertiary)' }}>
                      {r.est_records === null || r.est_records === undefined
                        ? '—'
                        : r.est_records.toLocaleString()}
                    </span>
                    {r.resource_id}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-xl border p-3"
         style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
      <p className="text-[10px] uppercase tracking-wider font-semibold"
         style={{ color: 'var(--text-tertiary)' }}>
        {label}
      </p>
      <p className="text-xl font-bold tabular-nums mt-0.5"
         style={{ color: 'var(--text-primary)' }}>
        {value}
      </p>
      {hint && (
        <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
          {hint}
        </p>
      )}
    </div>
  );
}
