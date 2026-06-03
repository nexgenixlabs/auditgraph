/**
 * AgentTrustScoreCard — Per-AI-agent Trust Score card (AG-179).
 *
 * Surfaces the 5-dimension Trust grade (Ownership / Secrets / Egress /
 * Telemetry / Oversight) plus a composite 0-100 score. Designed to drop
 * into:
 *   - AIInvestigateDrawer (compact=false, full card)
 *   - AIAgentsStandalone table (compact=true, single-line summary)
 *
 * Endpoint:
 *   GET /api/ai-security/trust-score/<identity_id>
 *
 * Score banding (display constants — see THRESHOLD_NOTE below):
 *   >=90 STRONG (green) · 70-89 GOOD (blue) · 50-69 ELEVATED (amber) · <50 CRITICAL (red)
 */
import React, { useEffect, useState, useRef } from 'react';
import { useConnection } from '../../contexts/ConnectionContext';
import { AgentTrust, TrustDimension, TrustGrade } from '../../types/security_events';

// ─── Display thresholds ────────────────────────────────────────────────
// THRESHOLD_NOTE: 90/70/50 score bands live in this component (not
// settings) on purpose — they are the *display* labels for the composite
// score and map 1:1 to the four-tier industry convention used by the
// Board Scorecard, the standalone table column, the drawer header, and
// PDF auditor packs. Changing them in one place would silently desync
// the rest of the UI, so they are intentional UI constants. The weights
// that *produce* the composite score (per-dimension contributions) DO
// live in backend settings — that's where tuning belongs.
const THRESHOLD_STRONG = 90;
const THRESHOLD_GOOD = 70;
const THRESHOLD_ELEVATED = 50;

const ANIM_DURATION_MS = 800;

// ─── Color helpers ─────────────────────────────────────────────────────

type BandKey = 'strong' | 'good' | 'elevated' | 'critical';

interface BandStyle {
  key: BandKey;
  label: string;
  text: string;     // tailwind text class
  bg: string;       // tailwind bg class (for big-number halo)
  ring: string;     // tailwind ring/border class
  dot: string;      // tailwind solid color for dots
}

function bandFor(score: number): BandStyle {
  if (score >= THRESHOLD_STRONG) {
    return { key: 'strong', label: 'STRONG', text: 'text-emerald-400', bg: 'bg-emerald-500/10', ring: 'ring-emerald-500/40', dot: 'bg-emerald-400' };
  }
  if (score >= THRESHOLD_GOOD) {
    return { key: 'good', label: 'GOOD', text: 'text-blue-400', bg: 'bg-blue-500/10', ring: 'ring-blue-500/40', dot: 'bg-blue-400' };
  }
  if (score >= THRESHOLD_ELEVATED) {
    return { key: 'elevated', label: 'ELEVATED', text: 'text-amber-400', bg: 'bg-amber-500/10', ring: 'ring-amber-500/40', dot: 'bg-amber-400' };
  }
  return { key: 'critical', label: 'CRITICAL', text: 'text-red-400', bg: 'bg-red-500/10', ring: 'ring-red-500/40', dot: 'bg-red-400' };
}

type DimKey = 'ownership' | 'secrets' | 'egress' | 'telemetry' | 'oversight';

interface DimStyle {
  text: string;
  bg: string;
  border: string;
  dot: string;
  isFailing: boolean;
}

/**
 * Per-dimension grade → color. Color semantics:
 *   - ownership/egress/oversight: PASS green · FAIL red
 *   - secrets: NONE green · LOW blue · MEDIUM amber · HIGH orange · CRITICAL red
 *   - telemetry: NONE red · PARTIAL amber · FULL green
 * `isFailing` flags rows that warrant a "Request Exception" link.
 */
function styleForGrade(dim: DimKey, grade: TrustGrade): DimStyle {
  // Defaults
  let text = 'text-slate-400';
  let bg = 'bg-slate-800/60';
  let border = 'border-slate-700/60';
  let dot = 'bg-slate-500';
  let isFailing = false;

  if (dim === 'ownership' || dim === 'egress' || dim === 'oversight') {
    if (grade === 'PASS') {
      text = 'text-emerald-300'; bg = 'bg-emerald-900/30'; border = 'border-emerald-800/40'; dot = 'bg-emerald-400';
    } else if (grade === 'FAIL') {
      text = 'text-red-300'; bg = 'bg-red-900/30'; border = 'border-red-800/40'; dot = 'bg-red-400'; isFailing = true;
    }
  } else if (dim === 'secrets') {
    switch (grade) {
      case 'NONE':
        text = 'text-emerald-300'; bg = 'bg-emerald-900/30'; border = 'border-emerald-800/40'; dot = 'bg-emerald-400'; break;
      case 'LOW':
        text = 'text-blue-300'; bg = 'bg-blue-900/30'; border = 'border-blue-800/40'; dot = 'bg-blue-400'; break;
      case 'MEDIUM':
        text = 'text-amber-300'; bg = 'bg-amber-900/30'; border = 'border-amber-800/40'; dot = 'bg-amber-400'; isFailing = true; break;
      case 'HIGH':
        text = 'text-orange-300'; bg = 'bg-orange-900/30'; border = 'border-orange-800/40'; dot = 'bg-orange-400'; isFailing = true; break;
      case 'CRITICAL':
        text = 'text-red-300'; bg = 'bg-red-900/30'; border = 'border-red-800/40'; dot = 'bg-red-400'; isFailing = true; break;
    }
  } else if (dim === 'telemetry') {
    if (grade === 'NONE') {
      text = 'text-red-300'; bg = 'bg-red-900/30'; border = 'border-red-800/40'; dot = 'bg-red-400'; isFailing = true;
    } else if (grade === 'PARTIAL') {
      text = 'text-amber-300'; bg = 'bg-amber-900/30'; border = 'border-amber-800/40'; dot = 'bg-amber-400';
    } else if (grade === 'FULL') {
      text = 'text-emerald-300'; bg = 'bg-emerald-900/30'; border = 'border-emerald-800/40'; dot = 'bg-emerald-400';
    }
  }

  return { text, bg, border, dot, isFailing };
}

// ─── Dimension metadata ────────────────────────────────────────────────

interface DimMeta {
  key: DimKey;
  label: string;
  icon: string;         // SVG path d=
  tooltip?: string;
}

const DIMENSIONS: DimMeta[] = [
  {
    key: 'ownership',
    label: 'Ownership',
    // user-check icon
    icon: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M16 11l2 2 4-4',
  },
  {
    key: 'secrets',
    label: 'Secrets',
    // key icon
    icon: 'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
  },
  {
    key: 'egress',
    label: 'Egress',
    // globe/network icon
    icon: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M2 12h20 M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z',
  },
  {
    key: 'telemetry',
    label: 'Telemetry',
    // activity icon
    icon: 'M22 12h-4l-3 9L9 3l-3 9H2',
    tooltip: 'Heuristic: last_sign_in OR last_activity within 30d. PARTIAL/FULL split requires diagnostic settings (v1.1)',
  },
  {
    key: 'oversight',
    label: 'Oversight',
    // shield-check icon
    icon: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4',
  },
];

// ─── Animation hook ────────────────────────────────────────────────────

/**
 * Count up from 0 → target over ANIM_DURATION_MS using requestAnimationFrame
 * + cubic-out easing. Pure useEffect + state, no animation library.
 */
function useGaugeSweep(target: number, enabled: boolean): number {
  const [value, setValue] = useState(0);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    if (!enabled) {
      setValue(target);
      return;
    }
    setValue(0);
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / ANIM_DURATION_MS);
      // cubic-out: 1 - (1-t)^3
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(Math.round(eased * target));
      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
  }, [target, enabled]);

  return value;
}

// ─── Component ─────────────────────────────────────────────────────────

interface Props {
  identityId: string;
  compact?: boolean;
}

interface FetchState {
  loading: boolean;
  notAgent: boolean;
  error: string | null;
  data: AgentTrust | null;
  displayName: string | null;
}

export function AgentTrustScoreCard({ identityId, compact = false }: Props) {
  const { withConnection } = useConnection();
  const [state, setState] = useState<FetchState>({
    loading: true,
    notAgent: false,
    error: null,
    data: null,
    displayName: null,
  });

  useEffect(() => {
    let cancelled = false;
    setState({ loading: true, notAgent: false, error: null, data: null, displayName: null });

    fetch(withConnection(`/api/ai-security/trust-score/${encodeURIComponent(identityId)}`))
      .then(async (r) => {
        if (r.status === 404) {
          if (!cancelled) {
            setState({ loading: false, notAgent: true, error: null, data: null, displayName: null });
          }
          return null;
        }
        if (!r.ok) {
          throw new Error(`Failed to load Trust Score (${r.status})`);
        }
        return r.json();
      })
      .then((d) => {
        if (cancelled || !d) return;
        // The endpoint returns AgentTrust fields flat + identity_id + display_name.
        setState({
          loading: false,
          notAgent: false,
          error: null,
          data: d as AgentTrust,
          displayName: (d.display_name as string) ?? null,
        });
      })
      .catch((e: Error) => {
        if (cancelled) return;
        setState({ loading: false, notAgent: false, error: e.message, data: null, displayName: null });
      });

    return () => {
      cancelled = true;
    };
  }, [identityId, withConnection]);

  // ─── Loading ─────────────────────────────────────────────────────────
  if (state.loading) {
    if (compact) {
      return (
        <div className="flex items-center gap-2 text-[11px] text-slate-500">
          <div className="animate-pulse w-8 h-3 bg-slate-700/40 rounded" />
          <span>loading…</span>
        </div>
      );
    }
    return (
      <div className="rounded-lg border p-4 flex items-center justify-center"
        style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <div className="animate-spin h-5 w-5 border-2 border-violet-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  // ─── 404: not an AI agent ────────────────────────────────────────────
  if (state.notAgent) {
    if (compact) {
      return (
        <span className="text-[10px] text-slate-500 italic" title="Not an AI agent — Trust Score does not apply">
          —
        </span>
      );
    }
    return (
      <div className="rounded-lg border border-dashed p-4 text-center"
        style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>
          Not an AI agent — Trust Score does not apply
        </p>
        <p className="text-[11px] leading-snug" style={{ color: 'var(--text-tertiary)' }}>
          This identity is not classified as an AI agent. Trust Score applies only to AI agents.
        </p>
      </div>
    );
  }

  // ─── Error ───────────────────────────────────────────────────────────
  if (state.error || !state.data) {
    if (compact) {
      return <span className="text-[10px] text-red-400" title={state.error ?? 'error'}>err</span>;
    }
    return (
      <div className="rounded-lg border p-3 text-xs text-red-400"
        style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        {state.error ?? 'Failed to load Trust Score'}
      </div>
    );
  }

  const trust = state.data;
  const band = bandFor(trust.trust_score);

  // ─── Compact (single-line for table column) ──────────────────────────
  if (compact) {
    return <CompactRow trust={trust} band={band} />;
  }

  // ─── Full card ───────────────────────────────────────────────────────
  return <FullCard trust={trust} band={band} displayName={state.displayName} />;
}

// ─── Compact subcomponent ──────────────────────────────────────────────

function CompactRow({ trust, band }: { trust: AgentTrust; band: BandStyle }) {
  // No animation in compact form — table re-renders make sweep distracting.
  return (
    <div className="flex items-center gap-2" title={`Trust Score: ${trust.trust_score} (${band.label})`}>
      <span className={`text-sm font-bold tabular-nums ${band.text}`}>{trust.trust_score}</span>
      <div className="flex items-center gap-1">
        {DIMENSIONS.map((dm) => {
          const dim = trust[dm.key] as TrustDimension;
          const st = styleForGrade(dm.key, dim.grade);
          return (
            <span
              key={dm.key}
              className={`inline-block w-2 h-2 rounded-full ${st.dot}`}
              title={`${dm.label}: ${dim.grade} — ${dim.evidence}`}
              aria-label={`${dm.label} ${dim.grade}`}
            />
          );
        })}
      </div>
    </div>
  );
}

// ─── Full card subcomponent ────────────────────────────────────────────

function FullCard({ trust, band, displayName }: { trust: AgentTrust; band: BandStyle; displayName: string | null }) {
  const animatedScore = useGaugeSweep(trust.trust_score, true);

  const hasFailing = DIMENSIONS.some((dm) => {
    const dim = trust[dm.key] as TrustDimension;
    return styleForGrade(dm.key, dim.grade).isFailing;
  });

  return (
    <div className="rounded-lg border overflow-hidden"
      style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
    >
      {/* Header row: big score + band label */}
      <div className={`flex items-center gap-4 px-4 py-3 ${band.bg}`}>
        <div className={`flex items-center justify-center w-20 h-20 rounded-full ring-2 ${band.ring} ${band.bg}`}>
          <span className={`text-4xl font-bold tabular-nums ${band.text}`}>{animatedScore}</span>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[10px] uppercase tracking-wider text-slate-500">Trust Score</p>
          {displayName && (
            <p className="text-xs font-semibold truncate" style={{ color: 'var(--text-primary)' }} title={displayName}>
              {displayName}
            </p>
          )}
          <span className={`inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-bold border ${band.text}`}
            style={{ borderColor: 'currentColor', backgroundColor: 'transparent' }}>
            {band.label}
          </span>
          <p className="text-[9px] mt-1" style={{ color: 'var(--text-tertiary)' }}>
            0–100 composite · {DIMENSIONS.length} dimensions
          </p>
        </div>
      </div>

      {/* 5 dimension rows */}
      <div className="divide-y" style={{ borderColor: 'var(--border-subtle)' }}>
        {DIMENSIONS.map((dm) => {
          const dim = trust[dm.key] as TrustDimension;
          const st = styleForGrade(dm.key, dim.grade);
          return (
            <div key={dm.key}
              className="flex items-start gap-3 px-4 py-2.5"
              style={{ borderColor: 'var(--border-subtle)' }}
              title={dm.tooltip || undefined}
            >
              {/* Icon */}
              <div className={`mt-0.5 w-7 h-7 rounded flex items-center justify-center flex-shrink-0 ${st.bg} border ${st.border}`}>
                <svg className={`w-4 h-4 ${st.text}`} fill="none" stroke="currentColor" strokeWidth={1.8}
                  viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                  <path d={dm.icon} />
                </svg>
              </div>

              {/* Label + evidence */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
                    {dm.label}
                  </span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${st.text} ${st.border} ${st.bg}`}>
                    {dim.grade}
                  </span>
                  {dm.tooltip && (
                    <span className="text-[10px] text-slate-500 cursor-help" title={dm.tooltip}>
                      <svg className="inline w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                        <circle cx="12" cy="12" r="10" /><path d="M12 16v-4 M12 8h.01" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    </span>
                  )}
                </div>
                <p className="text-[11px] mt-0.5 leading-snug" style={{ color: 'var(--text-secondary)' }}>
                  {dim.evidence || '—'}
                </p>
                {(dim.role_name || dim.scope) && (
                  <p className="text-[10px] mt-0.5 font-mono truncate" style={{ color: 'var(--text-tertiary)' }}
                    title={dim.scope || dim.role_name || ''}>
                    {dim.role_name && <span>{dim.role_name}</span>}
                    {dim.role_name && dim.scope && <span className="mx-1">·</span>}
                    {dim.scope && <span>{dim.scope.split('/').slice(-2).join('/') || dim.scope}</span>}
                  </p>
                )}
              </div>

              {/* Per-row "Request Exception" link (only for failing rows). */}
              {st.isFailing && (
                <a
                  href={`#trust-exception?identity=${encodeURIComponent(trust.identity_id)}&dim=${dm.key}`}
                  className="text-[10px] underline whitespace-nowrap flex-shrink-0"
                  style={{ color: 'var(--text-tertiary)' }}
                  title="Request a policy exception for this dimension"
                >
                  Request Exception
                </a>
              )}
            </div>
          );
        })}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 flex items-center justify-between text-[10px] border-t"
        style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-tertiary)' }}>
        <span>
          Computed {trust.computed_at ? new Date(trust.computed_at).toLocaleString() : '—'}
        </span>
        {hasFailing && (
          <span className="italic">Failing rows offer policy exception requests.</span>
        )}
      </div>
    </div>
  );
}

export default AgentTrustScoreCard;
