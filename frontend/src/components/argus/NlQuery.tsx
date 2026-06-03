/**
 * NlQuery (AG-185) — Argus Layer 1 UI.
 *
 * Plain-English question → structured identity list. Posts to
 * /api/argus/nl-query and renders:
 *   - the interpreted filter chips (what Argus thought the user meant)
 *   - the identity table (display_name + risk_level + category)
 *   - the backend's `why` string + confidence
 *
 * Honest empty state: backend returns identities=[] with `why="Argus could
 * not match this question to a known intent…"` when the translator
 * couldn't parse the query. We render that string verbatim.
 */
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useConnection } from '../../contexts/ConnectionContext';

interface NlFilter {
  field?: string;
  operator?: string;
  value?: string | number | boolean | null;
  description?: string;
}

interface NlIdentity {
  identity_id: string;
  display_name: string;
  identity_category?: string | null;
  risk_level?: string | null;
  risk_score?: number | null;
}

interface NlQueryResponse {
  query: string;
  filters_interpreted?: NlFilter[] | null;
  identities?: NlIdentity[];
  count?: number;
  total?: number;
  why?: string | null;
  confidence?: 'high' | 'medium' | 'low' | null;
  intent?: string | null;
  unknown_fields?: string[] | null;
  limit?: number;
  offset?: number;
  has_more?: boolean;
  meta_question?: string | null;
  meta_route?: string | null;
}

interface FetchState {
  loading: boolean;
  error: string | null;
  data: NlQueryResponse | null;
}

const CONFIDENCE_TONE: Record<string, string> = {
  high:   'text-emerald-300 bg-emerald-500/10 border-emerald-500/40',
  medium: 'text-amber-300   bg-amber-500/10   border-amber-500/40',
  low:    'text-slate-300   bg-slate-500/10   border-slate-500/40',
};

const RISK_TONE: Record<string, string> = {
  critical: 'text-red-300    bg-red-500/10    border-red-500/40',
  high:     'text-orange-300 bg-orange-500/10 border-orange-500/40',
  medium:   'text-amber-300  bg-amber-500/10  border-amber-500/40',
  low:      'text-emerald-300 bg-emerald-500/10 border-emerald-500/40',
};

const EXAMPLES: string[] = [
  'AI agents with KV admin',
  'Ownerless AI agents',
  'OAuth apps with dangerous Graph permissions',
  'Service principals with expired credentials',
  'Critical identities reaching PHI',
];

export default function NlQuery() {
  const { withConnection } = useConnection();
  const [text, setText] = useState<string>('');
  const [state, setState] = useState<FetchState>({
    loading: false, error: null, data: null,
  });

  const run = async (override?: string) => {
    const q = (override ?? text).trim();
    if (!q) return;
    setText(q);
    setState({ loading: true, error: null, data: null });
    try {
      const r = await fetch(withConnection('/api/argus/nl-query'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q, limit: 50 }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => null);
        throw new Error((body && body.error) || `NL query failed (${r.status})`);
      }
      const d = (await r.json()) as NlQueryResponse;
      setState({ loading: false, error: null, data: d });
    } catch (e) {
      setState({
        loading: false,
        error: e instanceof Error ? e.message : 'NL query failed',
        data: null,
      });
    }
  };

  const data = state.data;
  const conf = (data?.confidence || 'low') as 'high' | 'medium' | 'low';
  const confTone = CONFIDENCE_TONE[conf] || CONFIDENCE_TONE.low;
  const identities = data?.identities || [];

  return (
    <div className="space-y-4">
      {/* Query input + examples */}
      <div className="rounded-xl border p-4 space-y-3"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <div className="flex gap-2">
          <input
            value={text}
            onChange={e => setText(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); run(); } }}
            placeholder="Ask a question in plain English…"
            className="flex-1 text-sm px-3 py-2 rounded border"
            style={{
              borderColor: 'var(--border-default)',
              backgroundColor: 'var(--bg-raised)',
              color: 'var(--text-primary)',
            }}
          />
          <button
            onClick={() => run()}
            disabled={state.loading || !text.trim()}
            className="px-3 py-2 rounded text-xs font-semibold border transition disabled:opacity-50"
            style={{
              borderColor: 'rgba(139,92,246,0.40)',
              backgroundColor: 'rgba(139,92,246,0.18)',
              color: '#c4b5fd',
            }}
          >
            {state.loading ? 'Asking…' : 'Ask Argus'}
          </button>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <span className="text-[10px] uppercase tracking-wider font-semibold"
                style={{ color: 'var(--text-tertiary)' }}>
            Try
          </span>
          {EXAMPLES.map(ex => (
            <button
              key={ex}
              onClick={() => run(ex)}
              className="text-[11px] px-2 py-0.5 rounded border transition hover:border-violet-500/40"
              style={{
                borderColor: 'var(--border-subtle)',
                color: 'var(--text-secondary)',
              }}
            >
              {ex}
            </button>
          ))}
        </div>
      </div>

      {/* Loading */}
      {state.loading && (
        <div className="rounded-lg border p-4 flex items-center justify-center"
             style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
          <div className="animate-spin h-5 w-5 border-2 border-violet-500 border-t-transparent rounded-full" />
          <span className="ml-3 text-xs" style={{ color: 'var(--text-tertiary)' }}>
            Interpreting question + running query…
          </span>
        </div>
      )}

      {/* Error */}
      {state.error && !state.loading && (
        <div className="rounded-lg border p-3 text-xs text-red-400"
             style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
          {state.error}
        </div>
      )}

      {/* Result */}
      {data && !state.loading && (
        <div className="space-y-3 animate-[fadeIn_280ms_ease-out]">
          {/* Interpretation banner */}
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <div className="flex items-center flex-wrap gap-2 mb-2">
              <span className="text-[10px] uppercase tracking-wider font-semibold"
                    style={{ color: 'var(--text-tertiary)' }}>
                Argus interpretation
              </span>
              <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${confTone}`}>
                {conf} confidence
              </span>
              {data.intent && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded border"
                      style={{
                        borderColor: 'rgba(139,92,246,0.30)',
                        color: '#c4b5fd',
                      }}>
                  intent: {data.intent}
                </span>
              )}
            </div>
            {data.why && (
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                {data.why}
              </p>
            )}
            {(data.filters_interpreted || []).length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {(data.filters_interpreted || []).map((f, i) => (
                  <span key={i}
                        className="text-[10px] px-1.5 py-0.5 rounded border font-mono"
                        style={{
                          borderColor: 'var(--border-subtle)',
                          color: 'var(--text-secondary)',
                          backgroundColor: 'rgba(15,23,42,0.30)',
                        }}>
                    {f.field || ''} {f.operator || ''} {String(f.value ?? '')}
                  </span>
                ))}
              </div>
            )}
            {(data.unknown_fields || []).length > 0 && (
              <p className="text-[10px] mt-1 italic" style={{ color: 'var(--text-tertiary)' }}>
                Skipped unsupported fields: {(data.unknown_fields || []).join(', ')}
              </p>
            )}
            {data.meta_question && data.meta_route && (
              <Link
                to={data.meta_route}
                className="text-[10px] uppercase tracking-wider font-medium hover:underline mt-2 inline-block"
                style={{ color: '#a78bfa' }}
              >
                Open the dedicated answer surface →
              </Link>
            )}
          </div>

          {/* Results */}
          <div className="rounded-xl border"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <div className="px-4 py-2 border-b flex items-center justify-between"
                 style={{ borderColor: 'var(--border-subtle)' }}>
              <span className="text-[10px] uppercase tracking-wider font-semibold"
                    style={{ color: 'var(--text-tertiary)' }}>
                Identities matched
              </span>
              <span className="text-[11px] font-mono tabular-nums"
                    style={{ color: 'var(--text-secondary)' }}>
                {identities.length} of {(data.total ?? identities.length).toLocaleString()}
                {data.has_more ? ' · more available' : ''}
              </span>
            </div>
            {identities.length === 0 ? (
              <div className="px-4 py-6 text-center text-xs"
                   style={{ color: 'var(--text-tertiary)' }}>
                No identities matched. {data.why || 'Try one of the example questions above.'}
              </div>
            ) : (
              <ul className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
                {identities.map((id, i) => {
                  const tone = RISK_TONE[(id.risk_level || '').toLowerCase()] || '';
                  return (
                    <li
                      key={`${id.identity_id}-${i}`}
                      className="px-4 py-2 flex items-center gap-3 opacity-0 animate-[fadeIn_300ms_ease-out_forwards]"
                      style={{ animationDelay: `${i * 30}ms` }}
                    >
                      <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border min-w-[60px] text-center ${tone}`}>
                        {id.risk_level || '—'}
                      </span>
                      <div className="min-w-0 flex-1">
                        <Link
                          to={`/identities/${encodeURIComponent(id.identity_id)}`}
                          className="text-sm font-medium hover:underline truncate block"
                          style={{ color: 'var(--text-primary)' }}
                        >
                          {id.display_name}
                        </Link>
                        <p className="text-[10px] font-mono truncate"
                           style={{ color: 'var(--text-tertiary)' }}>
                          {id.identity_category || ''}{id.identity_category ? ' · ' : ''}{id.identity_id}
                        </p>
                      </div>
                      {typeof id.risk_score === 'number' && (
                        <span className="text-[11px] font-mono tabular-nums"
                              style={{ color: 'var(--text-secondary)' }}>
                          {id.risk_score.toFixed(1)}
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      )}

      {/* Empty state */}
      {!data && !state.loading && !state.error && (
        <div className="rounded-xl border border-dashed p-6 text-center text-xs"
             style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-tertiary)' }}>
          Ask any of the example questions above, or type your own. Argus will
          translate it into a query against the latest discovery.
        </div>
      )}
    </div>
  );
}
