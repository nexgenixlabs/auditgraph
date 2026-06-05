/**
 * ReasonChain (AG-186) — Argus Layer 2 UI.
 *
 * Lets the user pick a "board-level" question (highest_business_risk,
 * phi_exposure, …), POSTs to /api/argus/reason, and renders the 3-5 hop
 * synthesised narrative with cited evidence.
 *
 * Honesty contract is enforced by the backend (every claim is backed by
 * a row in `evidence`; sub-queries that return 0 are reported as 0). The
 * UI does not invent or reformat any of those numbers — we just render
 * the dict shape verbatim and surface the backend's `confidence` string.
 */
import React, { useState } from 'react';
import { useConnection } from '../../contexts/ConnectionContext';

// ─── Catalog (matches backend QUESTION_TYPES) ───────────────────────────

interface QuestionDef {
  type: string;
  label: string;
  hint: string;
}

const QUESTIONS: QuestionDef[] = [
  {
    type:  'highest_business_risk',
    label: 'What is my highest business risk right now?',
    hint:  'PHI reach × ownership gaps × egress posture',
  },
  {
    type:  'phi_exposure',
    label: 'Who can reach PHI?',
    hint:  'AI agents + identities with read/write to PHI-classified resources',
  },
  {
    type:  'ownership_gaps',
    label: 'Which AI agents have no owner?',
    hint:  'identities + sp_ownership join, gated by classified data reach',
  },
  {
    type:  'recent_intake_risk',
    label: 'What recently-added identities are risky?',
    hint:  'last 14 days · critical or high posture',
  },
  {
    type:  'oauth_scope_sprawl',
    label: 'Which OAuth apps have dangerous Graph scopes?',
    hint:  'graph_api_permissions matching the dangerous-perm allowlist',
  },
  {
    type:  'posture_drop',
    label: 'Did our posture drop recently?',
    hint:  'posture_scores delta ≥ 5 points between the two latest rows',
  },
];

// ─── API shape (matches backend reason_about envelope) ──────────────────

interface EvidenceRow {
  citation: string;
  count: number | null;
  type?: string | null;
  link?: string | null;
}

interface FrameworkRefs {
  nist?: string[] | null;
  cis_azure?: string[] | null;
  mitre?: string[] | null;
}

interface ReasonResult {
  question?: string;
  question_type?: string;
  conclusion?: string;
  evidence?: EvidenceRow[] | null;
  framework_refs?: FrameworkRefs | null;
  confidence?: 'high' | 'medium' | 'low' | string;
  cached?: boolean;
  generated_at?: string | null;
  duration_ms?: number | null;
  latest_run_id?: number | null;
}

interface FetchState {
  loading: boolean;
  error: string | null;
  data: ReasonResult | null;
}

const CONFIDENCE_TONE: Record<string, string> = {
  high:   'text-emerald-300 bg-emerald-500/10 border-emerald-500/40',
  medium: 'text-amber-300   bg-amber-500/10   border-amber-500/40',
  low:    'text-slate-300   bg-slate-500/10   border-slate-500/40',
};

function fmtCount(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—';
  if (!Number.isFinite(n)) return '—';
  return n.toLocaleString();
}

export default function ReasonChain() {
  const { withConnection } = useConnection();
  const [questionType, setQuestionType] = useState<string>(QUESTIONS[0].type);
  const [state, setState] = useState<FetchState>({
    loading: false, error: null, data: null,
  });

  const run = async () => {
    setState({ loading: true, error: null, data: null });
    try {
      const r = await fetch(withConnection('/api/argus/reason'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question_type: questionType }),
      });
      if (!r.ok) {
        throw new Error(`Argus reason failed (${r.status})`);
      }
      const d = (await r.json()) as ReasonResult;
      setState({ loading: false, error: null, data: d });
    } catch (e) {
      setState({
        loading: false,
        error: e instanceof Error ? e.message : 'Failed to run reasoning',
        data: null,
      });
    }
  };

  const def = QUESTIONS.find(q => q.type === questionType);
  const data = state.data;
  const evidence = (data?.evidence ?? []).filter(Boolean);
  const refs = data?.framework_refs || {};
  const totalRefs =
    (refs.nist?.length || 0) +
    (refs.cis_azure?.length || 0) +
    (refs.mitre?.length || 0);
  const conf = (data?.confidence || 'low') as 'high' | 'medium' | 'low';
  const confTone = CONFIDENCE_TONE[conf] || CONFIDENCE_TONE.low;

  return (
    <div className="space-y-4">
      {/* Question picker + Run */}
      <div className="rounded-xl border p-4"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[280px]">
            <label className="text-[10px] uppercase tracking-wider font-semibold block mb-1"
                   style={{ color: 'var(--text-tertiary)' }}>
              Reasoning question
            </label>
            <select
              value={questionType}
              onChange={e => setQuestionType(e.target.value)}
              className="w-full text-xs px-2 py-1.5 rounded border"
              style={{
                borderColor: 'var(--border-default)',
                backgroundColor: 'var(--bg-raised)',
                color: 'var(--text-primary)',
              }}
            >
              {QUESTIONS.map(q => (
                <option key={q.type} value={q.type}>{q.label}</option>
              ))}
            </select>
            {def && (
              <p className="text-[10px] mt-1" style={{ color: 'var(--text-tertiary)' }}>
                Chain hint: {def.hint}
              </p>
            )}
          </div>
          <button
            onClick={run}
            disabled={state.loading}
            className="px-3 py-1.5 rounded text-xs font-semibold border transition disabled:opacity-50"
            style={{
              borderColor: 'rgba(139,92,246,0.40)',
              backgroundColor: 'rgba(139,92,246,0.18)',
              color: '#c4b5fd',
            }}
          >
            {state.loading ? 'Reasoning…' : 'Run reasoning chain'}
          </button>
        </div>
      </div>

      {/* Loading skeleton */}
      {state.loading && (
        <div className="rounded-lg border p-4 flex items-center justify-center"
             style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
          <div className="animate-spin h-5 w-5 border-2 border-violet-500 border-t-transparent rounded-full" />
          <span className="ml-3 text-xs" style={{ color: 'var(--text-tertiary)' }}>
            Running 3-5 hop chain over the latest run…
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
          {/* Conclusion banner */}
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <div className="flex items-center flex-wrap gap-2 mb-2">
              <span className="text-[10px] uppercase tracking-wider font-semibold"
                    style={{ color: 'var(--text-tertiary)' }}>
                Argus conclusion
              </span>
              <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${confTone}`}>
                {conf} confidence
              </span>
              {data.cached && (
                <span className="text-[10px] uppercase font-medium px-2 py-0.5 rounded border"
                      style={{
                        borderColor: 'rgba(148,163,184,0.30)',
                        color: 'var(--text-tertiary)',
                      }}>
                  cached
                </span>
              )}
              {typeof data.duration_ms === 'number' && (
                <span className="text-[10px] font-mono"
                      style={{ color: 'var(--text-tertiary)' }}>
                  {data.duration_ms} ms
                </span>
              )}
            </div>
            {data.question && (
              <p className="text-[11px] mb-1 italic" style={{ color: 'var(--text-tertiary)' }}>
                Q: {data.question}
              </p>
            )}
            <p className="text-sm leading-relaxed font-medium"
               style={{ color: 'var(--text-primary)' }}>
              {data.conclusion || '—'}
            </p>
          </div>

          {/* Evidence ladder */}
          <div className="rounded-xl border p-4"
               style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
            <div className="text-[10px] uppercase tracking-wider font-semibold mb-2"
                 style={{ color: 'var(--text-tertiary)' }}>
              Evidence ({evidence.length} sub-quer{evidence.length === 1 ? 'y' : 'ies'})
            </div>
            {evidence.length === 0 ? (
              <p className="text-xs italic" style={{ color: 'var(--text-tertiary)' }}>
                No sub-queries were executed.
              </p>
            ) : (
              <ol className="space-y-2">
                {evidence.map((row, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-3 opacity-0 animate-[fadeIn_320ms_ease-out_forwards]"
                    style={{ animationDelay: `${i * 60}ms` }}
                  >
                    <span className="flex-shrink-0 inline-flex items-center justify-center w-6 h-6 rounded-full text-[10px] font-bold border tabular-nums"
                          style={{
                            borderColor: 'rgba(139,92,246,0.35)',
                            backgroundColor: 'rgba(139,92,246,0.15)',
                            color: '#c4b5fd',
                          }}>
                      {i + 1}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs" style={{ color: 'var(--text-primary)' }}>
                        <span className="font-mono tabular-nums font-semibold mr-1"
                              style={{ color: '#a78bfa' }}>
                          {fmtCount(row.count)}
                        </span>
                        <span style={{ color: 'var(--text-secondary)' }}>{row.citation}</span>
                      </p>
                      {row.link && (
                        <a
                          href={row.link}
                          className="text-[10px] underline-offset-2 hover:underline"
                          style={{ color: 'var(--text-tertiary)' }}
                        >
                          {row.link}
                        </a>
                      )}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </div>

          {/* Framework refs */}
          {totalRefs > 0 && (
            <div className="rounded-xl border p-4"
                 style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
              <div className="text-[10px] uppercase tracking-wider font-semibold mb-2"
                   style={{ color: 'var(--text-tertiary)' }}>
                Control framework references
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(refs.nist || []).map(n => (
                  <span key={`nist-${n}`}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
                        style={{
                          borderColor: 'rgba(59,130,246,0.35)',
                          backgroundColor: 'rgba(59,130,246,0.10)',
                          color: '#93c5fd',
                        }}>
                    NIST {n}
                  </span>
                ))}
                {(refs.cis_azure || []).map(c => (
                  <span key={`cis-${c}`}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
                        style={{
                          borderColor: 'rgba(16,185,129,0.35)',
                          backgroundColor: 'rgba(16,185,129,0.10)',
                          color: '#6ee7b7',
                        }}>
                    {c}
                  </span>
                ))}
                {(refs.mitre || []).map(m => (
                  <span key={`mitre-${m}`}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
                        style={{
                          borderColor: 'rgba(244,114,182,0.35)',
                          backgroundColor: 'rgba(244,114,182,0.10)',
                          color: '#f9a8d4',
                        }}>
                    MITRE {m}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!data && !state.loading && !state.error && (
        <div className="rounded-xl border border-dashed p-6 text-center text-xs"
             style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-tertiary)' }}>
          Pick a question above and hit <span className="font-semibold">Run reasoning chain</span>.
          Argus will run 3-5 SQL sub-queries against the latest discovery and synthesise the answer.
        </div>
      )}
    </div>
  );
}
