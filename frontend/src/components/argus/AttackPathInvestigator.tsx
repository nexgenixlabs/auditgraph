/**
 * AttackPathInvestigator (AG-187) — Argus Layer 3 UI.
 *
 * Free-text "source → target" investigation against the persisted
 * attack-path catalog, with optional live fallback. Hits
 * POST /api/argus/investigate-attack-path and renders the strongest
 * match, the resolution narration, and a fallback banner when the
 * backend had to compute live.
 *
 * Honest by construction: when found=false we render the backend's
 * `why` string and stop — never a fabricated chain.
 *
 * Theme: dark + violet accent to match the Argus pane.
 */
import React, { useCallback, useMemo, useState, lazy, Suspense } from 'react';
import type { PathNode } from '../../types/security_events';
import { MitreChipStrip } from '../security/MitreChip';

// Defer the cinematic chain visualization — keeps ReactFlow off the
// initial bundle until the user actually runs an investigation that
// returns a path.
const AttackPathView = lazy(() => import('../graph/AttackPathView'));

// ─── API contract (matches argus_investigate_attack_path_handler) ───────

interface ResolvedEntity {
  kind: string;
  // `id` is either a single string (high-confidence single match) or
  // an array of strings (medium-confidence "N matches" fanout).
  id?: string | string[] | null;
  label: string;
  confidence?: 'high' | 'medium' | 'low' | null;
}

interface InvestigationPath {
  id?: number;
  path_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  risk_score: number;
  description?: string | null;
  narrative?: string | null;
  impact?: string | null;
  source_entity_id?: string | null;
  source_entity_name?: string | null;
  source_entity_type?: string | null;
  target_resource_id?: string | null;
  target_resource_type?: string | null;
  path_nodes?: PathNode[];
  rollup?: {
    vault_count?: number;
    secret_count?: number;
    storage_count?: number;
    records_estimate?: number | null;
    classification?: string | null;
    egress_status?: 'open' | 'restricted' | null;
  };
}

interface InvestigationResult {
  found: boolean;
  path: InvestigationPath | null;
  source_resolved: ResolvedEntity | null;
  target_resolved: ResolvedEntity | null;
  resolution_confidence: 'high' | 'medium' | 'low' | null;
  fallback_used: boolean;
  why: string;
}

// ─── AttackPathView prop shape (must match its contract) ────────────────

interface ViewStep {
  node_type: string;
  node_id: string;
  node_label: string;
  description: string;
  mitre_techniques?: Array<string | { id: string }>;
  classification?: string;
  cloud?: string;
}

interface ViewPath {
  type: string;
  risk_level: string;
  steps: ViewStep[];
  impact: string;
  narrative: string;
  rollup?: InvestigationPath['rollup'];
}

// ─── Example queries (empty-state chips) ────────────────────────────────

const EXAMPLE_QUERIES: Array<{ source: string; target: string; label: string }> = [
  {
    source: 'any AI agent',
    target: 'subscription',
    label: 'Can an AI agent take over my subscription?',
  },
  {
    source: 'any AI agent',
    target: 'PHI data',
    label: 'Show attack paths from AI agents to PHI',
  },
  {
    source: 'any identity',
    target: 'Key Vault admin',
    label: 'Can any identity reach Key Vault admin?',
  },
  {
    source: 'alexander agent',
    target: '',
    label: 'What can the alexander agent reach?',
  },
];

// ─── Display helpers ────────────────────────────────────────────────────

const SEVERITY_TONE: Record<string, { text: string; bg: string; border: string }> = {
  critical: { text: '#f87171', bg: 'rgba(239,68,68,0.10)', border: 'rgba(239,68,68,0.40)' },
  high:     { text: '#fb923c', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.40)' },
  medium:   { text: '#facc15', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.40)' },
  low:      { text: '#4ade80', bg: 'rgba(34,197,94,0.10)', border: 'rgba(34,197,94,0.40)' },
};

const CONFIDENCE_TONE: Record<string, string> = {
  high:   'bg-emerald-500/10 text-emerald-300 border-emerald-500/40',
  medium: 'bg-amber-500/10 text-amber-300 border-amber-500/40',
  low:    'bg-slate-500/10 text-slate-300 border-slate-500/40',
};

function prettyKind(kind: string | undefined | null): string {
  if (!kind) return 'entity';
  return kind.replace(/_/g, ' ');
}

function prettyType(t: string | undefined | null): string {
  if (!t) return 'Attack Path';
  return t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

/** Map the backend InvestigationPath into the AttackPathView contract. */
function toViewPath(p: InvestigationPath): ViewPath {
  const nodes = p.path_nodes || [];
  const steps: ViewStep[] = nodes.map((n, i) => {
    const mt = (n.mitre_techniques || []).map((t) =>
      typeof t === 'string' ? t : { id: (t as { id: string }).id }
    );
    return {
      node_type: n.node_type as string,
      node_id: (n.evidence_id as string) || `${p.id ?? 'path'}-${i}`,
      node_label: n.label || '',
      description: (n.description as string) || '',
      mitre_techniques: mt,
      classification: (n.classification as string) || undefined,
      cloud: 'azure',
    };
  });
  return {
    type: p.path_type,
    risk_level: (p.severity || 'medium') as string,
    steps,
    impact: p.impact || p.description || '',
    narrative: p.narrative || '',
    rollup: p.rollup,
  };
}

/** Collect deduped MITRE technique IDs from the path's nodes. */
function collectMitreIds(p: InvestigationPath): string[] {
  const ids: string[] = [];
  for (const n of p.path_nodes || []) {
    for (const t of n.mitre_techniques || []) {
      const id = typeof t === 'string' ? t : (t as { id: string }).id;
      if (id && !ids.includes(id)) ids.push(id);
    }
  }
  return ids;
}

// ─── Sub-components ─────────────────────────────────────────────────────

/** Resolution narration: "We interpreted 'X' as <kind>: <label> (confidence)". */
function ResolutionLine({
  rawQuery, resolved, role,
}: { rawQuery: string; resolved: ResolvedEntity | null; role: 'source' | 'target' }) {
  if (!rawQuery) return null;
  if (!resolved) {
    return (
      <div className="text-[11px]" style={{ color: '#94a3b8' }}>
        <span className="uppercase tracking-wider text-[9px] font-semibold mr-2"
              style={{ color: '#64748b' }}>{role}</span>
        We could not resolve <span className="font-mono px-1 py-0.5 rounded bg-slate-800 text-slate-200">{rawQuery}</span>
      </div>
    );
  }
  const conf = (resolved.confidence || 'low') as 'high' | 'medium' | 'low';
  const confTone = CONFIDENCE_TONE[conf] || CONFIDENCE_TONE.low;
  return (
    <div className="text-[11px] leading-relaxed" style={{ color: '#cbd5e1' }}>
      <span className="uppercase tracking-wider text-[9px] font-semibold mr-2"
            style={{ color: '#64748b' }}>{role}</span>
      We interpreted{' '}
      <span className="font-mono px-1 py-0.5 rounded bg-slate-800 text-slate-200">{rawQuery}</span>{' '}
      as <span style={{ color: '#a78bfa' }}>{prettyKind(resolved.kind)}</span>:{' '}
      <span className="font-medium" style={{ color: '#e2e8f0' }}>{resolved.label}</span>
      <span className={`ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-semibold border ${confTone}`}>
        {conf} confidence
      </span>
    </div>
  );
}

/** "Not found" gray card — renders ONLY the backend's `why` string. */
function NotFoundCard({ why }: { why: string }) {
  return (
    <div className="rounded-xl border p-4"
         style={{ borderColor: 'rgba(148,163,184,0.30)', backgroundColor: 'rgba(30,41,59,0.60)' }}>
      <div className="flex items-start gap-3">
        <div className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center"
             style={{ backgroundColor: 'rgba(148,163,184,0.15)' }}>
          <svg className="w-4 h-4" fill="none" stroke="#94a3b8" strokeWidth={2}
               viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: '#94a3b8' }}>
            No attack path matched
          </div>
          <p className="text-sm leading-relaxed" style={{ color: '#cbd5e1' }}>{why}</p>
        </div>
      </div>
    </div>
  );
}

/** Compact summary header above the chain — severity + risk + MITRE strip. */
function PathHeader({ path }: { path: InvestigationPath }) {
  const sev = SEVERITY_TONE[path.severity] || SEVERITY_TONE.low;
  const mitreIds = useMemo(() => collectMitreIds(path), [path]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-bold uppercase px-2 py-0.5 rounded border"
              style={{ color: sev.text, backgroundColor: sev.bg, borderColor: sev.border }}>
          {path.severity}
        </span>
        <span className="text-sm font-semibold" style={{ color: '#e2e8f0' }}>
          {prettyType(path.path_type)}
        </span>
        <span className="text-xs font-mono tabular-nums px-2 py-0.5 rounded border"
              style={{
                color: sev.text,
                backgroundColor: 'rgba(15,23,42,0.6)',
                borderColor: 'rgba(148,163,184,0.20)',
              }}
              title="CVSS-aligned 0-10">
          risk {(path.risk_score ?? 0).toFixed(1)}
        </span>
        {path.source_entity_name && (
          <span className="text-[11px]" style={{ color: '#94a3b8' }}>
            <span style={{ color: '#a78bfa' }}>{path.source_entity_name}</span>
            {path.target_resource_id ? (
              <>
                {' → '}
                <span style={{ color: '#e2e8f0' }}>{path.target_resource_id}</span>
              </>
            ) : null}
          </span>
        )}
      </div>

      {(path.impact || path.description) && (
        <p className="text-xs leading-relaxed" style={{ color: '#cbd5e1' }}>
          {path.impact || path.description}
        </p>
      )}

      {mitreIds.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: '#64748b' }}>
            MITRE ATT&amp;CK
          </span>
          <MitreChipStrip ids={mitreIds} size="sm" />
        </div>
      )}
    </div>
  );
}

/** Fallback summary view for the path — used while the lazy AttackPathView
 *  is loading, or if it fails. Renders the hop chain as plain text. No
 *  fake numbers — only what the backend supplied. */
function PathSummary({ path }: { path: InvestigationPath }) {
  const nodes = path.path_nodes || [];
  return (
    <div className="space-y-3">
      <ol className="space-y-1.5">
        {nodes.map((n, i) => (
          <li key={i} className="flex items-start gap-2 text-xs leading-relaxed">
            <span className="font-mono text-[10px] mt-0.5 flex-shrink-0" style={{ color: '#64748b' }}>
              {String(i + 1).padStart(2, '0')}.
            </span>
            <span style={{ color: '#cbd5e1' }}>
              <span className="font-semibold" style={{ color: '#e2e8f0' }}>{n.label}</span>
              {n.description && (
                <span style={{ color: '#94a3b8' }}> — {n.description}</span>
              )}
            </span>
          </li>
        ))}
      </ol>
      {path.narrative && (
        <p className="text-[11px] italic pt-2 border-t"
           style={{ color: '#94a3b8', borderColor: 'rgba(148,163,184,0.15)' }}>
          {path.narrative}
        </p>
      )}
    </div>
  );
}

// ─── Main component ─────────────────────────────────────────────────────

export function AttackPathInvestigator() {
  const [source, setSource] = useState('');
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  // We keep the queries used for the *current* result around so the
  // "We interpreted 'X' as ..." narration matches what the user typed
  // even if they've started editing the inputs again.
  const [lastSource, setLastSource] = useState('');
  const [lastTarget, setLastTarget] = useState('');

  const investigate = useCallback(async (srcOverride?: string, tgtOverride?: string) => {
    const src = (srcOverride ?? source).trim();
    const tgt = (tgtOverride ?? target).trim();
    if (!src && !tgt) {
      setError('Enter a source, a target, or both.');
      return;
    }
    setError(null);
    setLoading(true);
    setResult(null);
    setLastSource(src);
    setLastTarget(tgt);
    try {
      const res = await fetch('/api/argus/investigate-attack-path', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_query: src || null,
          target_query: tgt || null,
          prefer_persisted: true,
        }),
      });
      if (!res.ok) {
        // 400s carry a JSON {error:...}; surface honestly.
        let detail = `HTTP ${res.status}`;
        try {
          const j = await res.json();
          if (j && typeof j.error === 'string') detail = j.error;
        } catch {
          /* non-JSON body — keep the HTTP detail */
        }
        throw new Error(detail);
      }
      const data: InvestigationResult = await res.json();
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'investigation failed');
    } finally {
      setLoading(false);
    }
  }, [source, target]);

  const onSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    if (!loading) investigate();
  }, [investigate, loading]);

  const onExampleClick = useCallback((src: string, tgt: string) => {
    setSource(src);
    setTarget(tgt);
    // Run immediately with the example values (don't wait for state flush).
    investigate(src, tgt);
  }, [investigate]);

  const showEmptyState = !loading && !result && !error;

  // viewProps for the cinematic AttackPathView — single-path mode.
  const viewProps = useMemo(() => {
    if (!result?.found || !result.path) return null;
    const view = toViewPath(result.path);
    return {
      paths: [view],
      summary: {
        total_paths: 1,
        critical_paths: result.path.severity === 'critical' ? 1 : 0,
        max_blast_radius: result.path.severity || 'medium',
      },
    };
  }, [result]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start gap-3">
        <div className="flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center"
             style={{ backgroundColor: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.35)' }}>
          <svg className="w-5 h-5" fill="none" stroke="#a78bfa" strokeWidth={2}
               viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
        </div>
        <div className="min-w-0">
          <h2 className="text-base font-bold" style={{ color: '#f1f5f9' }}>Attack Path Investigator</h2>
          <p className="text-xs mt-0.5" style={{ color: '#94a3b8' }}>
            Ask in plain English. Argus resolves the source and target against your live
            identity and resource catalog, then returns the matching attack path.
          </p>
        </div>
      </div>

      {/* Inputs */}
      <form onSubmit={onSubmit} className="rounded-xl border p-3 space-y-3"
            style={{ borderColor: 'rgba(148,163,184,0.20)', backgroundColor: 'rgba(15,23,42,0.55)' }}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <label className="block">
            <span className="block text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
              Source
            </span>
            <input
              type="text"
              value={source}
              onChange={e => setSource(e.target.value)}
              placeholder="e.g. any AI agent, alexander, identity X"
              disabled={loading}
              className="w-full px-3 py-2 text-sm rounded-lg border outline-none transition-colors focus:border-violet-500 focus:ring-1 focus:ring-violet-500 disabled:opacity-50"
              style={{
                backgroundColor: 'rgba(2,6,23,0.65)',
                color: '#e2e8f0',
                borderColor: 'rgba(148,163,184,0.25)',
              }}
            />
          </label>
          <label className="block">
            <span className="block text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: '#64748b' }}>
              Target
            </span>
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="e.g. subscription, PHI data, Key Vault admin"
              disabled={loading}
              className="w-full px-3 py-2 text-sm rounded-lg border outline-none transition-colors focus:border-violet-500 focus:ring-1 focus:ring-violet-500 disabled:opacity-50"
              style={{
                backgroundColor: 'rgba(2,6,23,0.65)',
                color: '#e2e8f0',
                borderColor: 'rgba(148,163,184,0.25)',
              }}
            />
          </label>
        </div>
        <div className="flex items-center justify-between gap-3">
          <span className="text-[10px]" style={{ color: '#64748b' }}>
            Provide a source, a target, or both. Both fields accept free text.
          </span>
          <button
            type="submit"
            disabled={loading || (!source.trim() && !target.trim())}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg border transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            style={{
              backgroundColor: loading ? 'rgba(139,92,246,0.25)' : '#7c3aed',
              color: '#ffffff',
              borderColor: 'rgba(167,139,250,0.50)',
              boxShadow: loading ? 'none' : '0 0 0 1px rgba(167,139,250,0.30), 0 4px 12px rgba(124,58,237,0.25)',
            }}
          >
            {loading ? (
              <>
                <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.25" />
                  <path d="M22 12a10 10 0 0 1-10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                </svg>
                Investigating
              </>
            ) : (
              <>
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2.5}
                     viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M5 12h14M13 6l6 6-6 6" />
                </svg>
                Investigate
              </>
            )}
          </button>
        </div>
        {error && (
          <div className="text-xs px-3 py-2 rounded-lg border"
               style={{
                 color: '#fca5a5',
                 backgroundColor: 'rgba(239,68,68,0.10)',
                 borderColor: 'rgba(239,68,68,0.35)',
               }}>
            {error}
          </div>
        )}
      </form>

      {/* Empty state — example chips */}
      {showEmptyState && (
        <div className="rounded-xl border p-4"
             style={{ borderColor: 'rgba(148,163,184,0.18)', backgroundColor: 'rgba(15,23,42,0.45)' }}>
          <div className="text-[10px] font-semibold uppercase tracking-wider mb-3" style={{ color: '#64748b' }}>
            Try one of these
          </div>
          <div className="flex flex-wrap gap-2">
            {EXAMPLE_QUERIES.map((ex) => (
              <button
                key={ex.label}
                type="button"
                onClick={() => onExampleClick(ex.source, ex.target)}
                className="text-xs px-3 py-1.5 rounded-full border transition-all hover:scale-[1.02]"
                style={{
                  color: '#c4b5fd',
                  backgroundColor: 'rgba(139,92,246,0.08)',
                  borderColor: 'rgba(139,92,246,0.30)',
                }}
              >
                {ex.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Loading skeleton */}
      {loading && (
        <div className="rounded-xl border p-6 flex items-center gap-3"
             style={{ borderColor: 'rgba(148,163,184,0.18)', backgroundColor: 'rgba(15,23,42,0.55)' }}>
          <div className="w-5 h-5 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-sm" style={{ color: '#cbd5e1' }}>
            Resolving source and target against the live catalog…
          </span>
        </div>
      )}

      {/* Result */}
      {result && !loading && (
        <div className="space-y-3 animate-[fade-in_0.3s_ease-out]">
          {/* Resolution lines */}
          {(lastSource || lastTarget) && (result.source_resolved || result.target_resolved) && (
            <div className="rounded-xl border p-3 space-y-1.5"
                 style={{ borderColor: 'rgba(148,163,184,0.18)', backgroundColor: 'rgba(15,23,42,0.55)' }}>
              {lastSource && (
                <ResolutionLine rawQuery={lastSource} resolved={result.source_resolved} role="source" />
              )}
              {lastTarget && (
                <ResolutionLine rawQuery={lastTarget} resolved={result.target_resolved} role="target" />
              )}
            </div>
          )}

          {/* Fallback banner */}
          {result.fallback_used && (
            <div className="rounded-xl border px-3 py-2 flex items-center gap-2"
                 style={{
                   borderColor: 'rgba(245,158,11,0.40)',
                   backgroundColor: 'rgba(245,158,11,0.10)',
                 }}>
              <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="#fbbf24" strokeWidth={2}
                   viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
              <span className="text-xs" style={{ color: '#fde68a' }}>
                No persisted path matched; computed live.
              </span>
            </div>
          )}

          {/* Not found — gray card with the raw `why` from the backend */}
          {!result.found && <NotFoundCard why={result.why} />}

          {/* Found — header + cinematic chain (or fallback summary) */}
          {result.found && result.path && viewProps && (
            <div className="rounded-xl border p-4 space-y-4"
                 style={{
                   borderColor: 'rgba(139,92,246,0.30)',
                   backgroundColor: 'rgba(15,23,42,0.55)',
                 }}>
              <PathHeader path={result.path} />
              <div className="rounded-lg overflow-hidden"
                   style={{ backgroundColor: 'rgba(255,255,255,0.97)' }}>
                <div className="p-3">
                  <Suspense
                    fallback={
                      <div className="rounded-lg p-4"
                           style={{ backgroundColor: '#ffffff', color: '#0f172a' }}>
                        <PathSummary path={result.path} />
                      </div>
                    }
                  >
                    <AttackPathView paths={viewProps.paths} summary={viewProps.summary} />
                  </Suspense>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default AttackPathInvestigator;
