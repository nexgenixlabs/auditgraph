/**
 * ExplainRiskWaterfall — AG-189 Argus Layer 5 UI.
 *
 * Renders a waterfall decomposition of an identity's composite risk score:
 * the total at the top, then each contributing signal as a horizontal bar
 * ordered highest-weight first. Each bar carries its MITRE technique
 * chips, evidence sentence, and a hover-tooltip with role_name + scope.
 *
 * Endpoint:
 *   GET /api/argus/explain-risk-score/<identity_id>
 *
 * Contract (matches Argus Layer 5 backend):
 *   {
 *     identity_id, display_name, total_score, method, generated_at,
 *     contributions: [
 *       { signal, label, weight, evidence, role_name?, scope?,
 *         mitre_techniques?: string[] }, ...
 *     ]
 *   }
 *
 * Honest "weight=None" path: contributions whose backend weight is null
 * are rendered with a diagonal-stripe pattern and the label
 * "Weight not assigned" — we do NOT fabricate a numeric width.
 */
import React, { useEffect, useState } from 'react';
import { useConnection } from '../../contexts/ConnectionContext';
import { MitreChipStrip } from '../security/MitreChip';

// ─── Types ─────────────────────────────────────────────────────────────

interface RiskContribution {
  signal: string;
  label: string;
  weight: number | null;
  evidence: string;
  role_name?: string | null;
  scope?: string | null;
  mitre_techniques?: string[] | null;
}

interface ExplainRiskResponse {
  identity_id: string;
  display_name: string;
  total_score: number;
  contributions: RiskContribution[];
  method: string;
  generated_at: string;
}

interface Props {
  identityId: string;
}

interface FetchState {
  loading: boolean;
  notFound: boolean;
  error: string | null;
  data: ExplainRiskResponse | null;
}

// ─── Display constants ─────────────────────────────────────────────────

// Cap the number of visible bars to keep the waterfall readable. Anything
// past the cap rolls up into a "+N more" footer line below the bars.
const MAX_BARS = 12;
// Per-bar cascade delay for the optional entrance animation.
const STAGGER_MS = 50;
// Mono truncate length for role_name / scope strings in the hover tooltip.
const MONO_TRUNCATE = 60;

// ─── Color helpers ─────────────────────────────────────────────────────

interface BarTone {
  fill: string;     // tailwind bg class for the filled portion of the bar
  text: string;     // tailwind text class for the weight number
  bandLabel: string;
}

/**
 * Color band for a contribution's weight. Bands match the requirement:
 *   >= 100 red · 50-99 orange · 25-49 amber · < 25 gray.
 * `null` weight is handled separately (striped pattern).
 */
function toneForWeight(weight: number): BarTone {
  if (weight >= 100) {
    return { fill: 'bg-red-500/70', text: 'text-red-300', bandLabel: 'critical' };
  }
  if (weight >= 50) {
    return { fill: 'bg-orange-500/70', text: 'text-orange-300', bandLabel: 'high' };
  }
  if (weight >= 25) {
    return { fill: 'bg-amber-500/70', text: 'text-amber-300', bandLabel: 'medium' };
  }
  return { fill: 'bg-slate-500/60', text: 'text-slate-300', bandLabel: 'low' };
}

// ─── Helpers ───────────────────────────────────────────────────────────

function truncateMono(s: string, max: number = MONO_TRUNCATE): string {
  if (!s) return '';
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function formatGeneratedAt(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

// ─── Component ─────────────────────────────────────────────────────────

export function ExplainRiskWaterfall({ identityId }: Props) {
  const { withConnection } = useConnection();
  const [state, setState] = useState<FetchState>({
    loading: true,
    notFound: false,
    error: null,
    data: null,
  });

  useEffect(() => {
    let cancelled = false;
    setState({ loading: true, notFound: false, error: null, data: null });

    fetch(withConnection(`/api/argus/explain-risk-score/${encodeURIComponent(identityId)}`))
      .then(async (r) => {
        if (r.status === 404) {
          if (!cancelled) {
            setState({ loading: false, notFound: true, error: null, data: null });
          }
          return null;
        }
        if (!r.ok) {
          throw new Error(`Failed to load risk explanation (${r.status})`);
        }
        return r.json() as Promise<ExplainRiskResponse>;
      })
      .then((d) => {
        if (cancelled || !d) return;
        setState({ loading: false, notFound: false, error: null, data: d });
      })
      .catch((e: Error) => {
        if (cancelled) return;
        setState({ loading: false, notFound: false, error: e.message, data: null });
      });

    return () => {
      cancelled = true;
    };
  }, [identityId, withConnection]);

  // ─── Loading ─────────────────────────────────────────────────────────
  if (state.loading) {
    return (
      <div
        className="rounded-lg border p-4 flex items-center justify-center"
        style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
      >
        <div className="animate-spin h-5 w-5 border-2 border-violet-500 border-t-transparent rounded-full" />
        <span className="ml-3 text-xs" style={{ color: 'var(--text-tertiary)' }}>
          Explaining risk score…
        </span>
      </div>
    );
  }

  // ─── 404: no explanation for this identity ───────────────────────────
  if (state.notFound) {
    return (
      <div
        className="rounded-lg border border-dashed p-4 text-center"
        style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
      >
        <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>
          No risk explanation available
        </p>
        <p className="text-[11px] leading-snug" style={{ color: 'var(--text-tertiary)' }}>
          Argus has not yet decomposed this identity's score. Run a discovery to
          populate the contribution signals.
        </p>
      </div>
    );
  }

  // ─── Error ───────────────────────────────────────────────────────────
  if (state.error || !state.data) {
    return (
      <div
        className="rounded-lg border p-3 text-xs text-red-400"
        style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
      >
        {state.error ?? 'Failed to load risk explanation'}
      </div>
    );
  }

  const { total_score, contributions, method, generated_at } = state.data;

  // Sort highest-weight first. Null weights sink to the bottom — they are
  // displayed honestly but should not crowd out the load-bearing signals.
  const sorted = [...(contributions ?? [])].sort((a, b) => {
    const aw = typeof a.weight === 'number' ? a.weight : -Infinity;
    const bw = typeof b.weight === 'number' ? b.weight : -Infinity;
    return bw - aw;
  });
  const visible = sorted.slice(0, MAX_BARS);
  const overflow = Math.max(0, sorted.length - visible.length);

  // Bar widths are proportional to the largest numeric weight in the
  // *visible* slice. Null-weight rows render at a fixed 25% width with
  // the striped pattern so they do not pretend to be quantitative.
  const numericWeights = visible
    .map((c) => c.weight)
    .filter((w): w is number => typeof w === 'number');
  const maxWeight = numericWeights.length > 0 ? Math.max(...numericWeights) : 0;

  return (
    <div
      className="rounded-lg border overflow-hidden"
      style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}
    >
      {/* Stripe pattern definition for "weight not assigned" bars. */}
      <svg width="0" height="0" aria-hidden="true" className="absolute">
        <defs>
          <pattern
            id="agexpl-stripes"
            patternUnits="userSpaceOnUse"
            width="8"
            height="8"
            patternTransform="rotate(45)"
          >
            <rect width="8" height="8" fill="rgba(100,116,139,0.20)" />
            <line x1="0" y1="0" x2="0" y2="8" stroke="rgba(148,163,184,0.55)" strokeWidth="3" />
          </pattern>
        </defs>
      </svg>

      {/* Header: total */}
      <div
        className="px-4 py-3 border-b"
        style={{ borderColor: 'var(--border-subtle)' }}
      >
        <p className="text-[10px] uppercase tracking-wider text-slate-500">
          Argus risk decomposition
        </p>
        <p
          className="text-2xl font-bold tabular-nums"
          style={{ color: 'var(--text-primary)' }}
        >
          Risk Score = {total_score}
        </p>
        <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
          {visible.length} of {sorted.length} contributing signal
          {sorted.length === 1 ? '' : 's'}
          {overflow > 0 ? ` · ${overflow} hidden` : ''}
        </p>
      </div>

      {/* Bars */}
      <div className="px-4 py-3 space-y-2">
        {visible.length === 0 && (
          <p className="text-xs italic" style={{ color: 'var(--text-tertiary)' }}>
            No contributing signals.
          </p>
        )}
        {visible.map((c, idx) => (
          <ContributionBar
            key={`${c.signal}-${idx}`}
            contribution={c}
            maxWeight={maxWeight}
            cascadeDelayMs={idx * STAGGER_MS}
          />
        ))}
        {overflow > 0 && (
          <p className="text-[10px] italic pt-1" style={{ color: 'var(--text-tertiary)' }}>
            +{overflow} more signal{overflow === 1 ? '' : 's'} not shown.
          </p>
        )}
      </div>

      {/* Footer */}
      <div
        className="px-4 py-2 text-[10px] border-t"
        style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-tertiary)' }}
      >
        Sourced from {method || '—'}. Last computed {formatGeneratedAt(generated_at)}.
      </div>
    </div>
  );
}

// ─── ContributionBar ───────────────────────────────────────────────────

interface BarProps {
  contribution: RiskContribution;
  maxWeight: number;
  cascadeDelayMs: number;
}

function ContributionBar({ contribution, maxWeight, cascadeDelayMs }: BarProps) {
  // Cascade-in animation: each bar starts collapsed and fades in.
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const t = window.setTimeout(() => setMounted(true), cascadeDelayMs);
    return () => window.clearTimeout(t);
  }, [cascadeDelayMs]);

  const weight = contribution.weight;
  const hasNumericWeight = typeof weight === 'number';
  const tone = hasNumericWeight ? toneForWeight(weight) : null;

  // Bar width:
  //   - numeric weight  → proportional to maxWeight in visible slice
  //   - null weight     → fixed 25% so the striped slot is still visible
  let targetPct: number;
  if (hasNumericWeight && maxWeight > 0) {
    targetPct = Math.max(2, Math.min(100, (weight / maxWeight) * 100));
  } else if (hasNumericWeight) {
    targetPct = 0;
  } else {
    targetPct = 25;
  }
  const widthPct = mounted ? targetPct : 0;

  const techniques = Array.isArray(contribution.mitre_techniques)
    ? contribution.mitre_techniques.filter((t): t is string => typeof t === 'string' && t.length > 0)
    : [];

  const roleName = contribution.role_name ?? '';
  const scope = contribution.scope ?? '';
  const tooltipParts: string[] = [];
  if (roleName) tooltipParts.push(`role: ${truncateMono(roleName)}`);
  if (scope) tooltipParts.push(`scope: ${truncateMono(scope)}`);
  const tooltip = tooltipParts.length > 0 ? tooltipParts.join('\n') : contribution.evidence || contribution.label;

  return (
    <div
      className="group relative"
      title={tooltip}
    >
      {/* Top row: label + weight badge */}
      <div className="flex items-center justify-between gap-2 mb-1">
        <span
          className="text-xs font-semibold truncate"
          style={{ color: 'var(--text-primary)' }}
          title={contribution.label}
        >
          {contribution.label || contribution.signal}
        </span>
        {hasNumericWeight ? (
          <span
            className={`text-[11px] font-bold tabular-nums flex-shrink-0 ${tone ? tone.text : 'text-slate-300'}`}
          >
            +{weight}
          </span>
        ) : (
          <span
            className="text-[10px] italic flex-shrink-0"
            style={{ color: 'var(--text-tertiary)' }}
          >
            Weight not assigned
          </span>
        )}
      </div>

      {/* The bar itself */}
      <div
        className="relative h-3 w-full rounded overflow-hidden border"
        style={{
          backgroundColor: 'rgba(15,23,42,0.45)',
          borderColor: 'var(--border-subtle)',
        }}
      >
        {hasNumericWeight ? (
          <div
            className={`h-full ${tone ? tone.fill : 'bg-slate-500/60'} transition-all duration-500 ease-out`}
            style={{ width: `${widthPct}%` }}
            aria-label={`Weight ${weight}`}
          />
        ) : (
          // Honest null-weight: diagonal-stripe pattern, fixed slot width.
          <div
            className="h-full transition-all duration-500 ease-out"
            style={{
              width: `${widthPct}%`,
              backgroundImage:
                'repeating-linear-gradient(45deg, rgba(100,116,139,0.25) 0, rgba(100,116,139,0.25) 4px, rgba(148,163,184,0.55) 4px, rgba(148,163,184,0.55) 8px)',
            }}
            aria-label="Weight not assigned"
          />
        )}
      </div>

      {/* Evidence (one-line, hover-title shows full string) */}
      {contribution.evidence && (
        <p
          className="text-[11px] mt-1 truncate"
          style={{ color: 'var(--text-secondary)' }}
          title={contribution.evidence}
        >
          {contribution.evidence}
        </p>
      )}

      {/* MITRE technique chips for this signal */}
      {techniques.length > 0 && (
        <div className="mt-1">
          <MitreChipStrip ids={techniques} size="sm" max={6} />
        </div>
      )}

      {/* Mono role/scope line — small, truncated, full value in tooltip */}
      {(roleName || scope) && (
        <p
          className="text-[10px] mt-1 font-mono truncate"
          style={{ color: 'var(--text-tertiary)' }}
          title={`${roleName ? roleName : ''}${roleName && scope ? ' · ' : ''}${scope ? scope : ''}`}
        >
          {roleName && <span>{truncateMono(roleName)}</span>}
          {roleName && scope && <span className="mx-1">·</span>}
          {scope && <span>{truncateMono(scope)}</span>}
        </p>
      )}
    </div>
  );
}

export default ExplainRiskWaterfall;
