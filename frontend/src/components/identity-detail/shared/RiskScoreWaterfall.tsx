/**
 * Sprint A.3 (2026-06-11) — Risk Score Waterfall
 *
 * Peer-review gap: the existing drawer Risk tab showed each factor as a flat
 * LOW chip ("privileged_admin", "broad_access") with a tiny points number.
 * It didn't answer the executive question — "WHY is this a CVSS 8.7?".
 *
 * This component renders a credit-score-style breakdown:
 *   Baseline 0.0
 *   + Tier-1 privileged role     +3.2   ━━━━━━━━━━░░░░░░░░░░  ░ red
 *   + Unowned identity           +2.5   ━━━━━━━━░░░░░░░░░░░░  ░ orange
 *   + Permanent assignment       +1.8   ━━━━━━░░░░░░░░░░░░░░  ░ yellow
 *   + Broad scope                +1.2   ━━━━░░░░░░░░░░░░░░░░  ░ amber
 *   ─────────────────────────────────
 *   Total CVSS                    8.7
 *
 * Same component used in:
 *   - IdentityDrawer RiskTab (compact mode — no header)
 *   - IdentityDetail OverviewTab (full mode — includes header + total bar)
 *
 * Reads structured `risk_factors` from `/api/identities/<id>`. Falls back to
 * legacy parsed risk_reasons if the structured payload is absent.
 */
import React from 'react';

export interface RiskFactor {
  code?: string;
  description: string;
  points?: number;
  severity?: string;       // 'critical' | 'high' | 'medium' | 'low'
  category?: string;
  evidence?: string;
  cvss?: number;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#10b981',
};

/**
 * Normalize whatever the backend gives us into a uniform factor list with
 * a sensible per-factor weight. We compute weights as `points` if present;
 * otherwise we derive from severity so the visual still works on the legacy
 * `risk_reasons` shape.
 */
function normalizeFactors(rawFactors: RiskFactor[] | undefined, fallbackReasons: string[] | undefined): RiskFactor[] {
  if (rawFactors && rawFactors.length > 0) {
    return rawFactors.map(f => ({
      ...f,
      points: typeof f.points === 'number' && f.points > 0 ? f.points : severityToPoints(f.severity),
      severity: f.severity || 'medium',
    }));
  }
  if (fallbackReasons && fallbackReasons.length > 0) {
    return fallbackReasons.map(r => {
      const m = r.match(/\(\+(\d+)\)\s*$/);
      const points = m ? parseInt(m[1], 10) : 100;
      const description = m ? r.replace(m[0], '').trim() : r;
      const severity = points >= 300 ? 'critical' : points >= 200 ? 'high' : points >= 100 ? 'medium' : 'low';
      return { description, points, severity };
    });
  }
  return [];
}

function severityToPoints(sev?: string): number {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return 300;
    case 'high':     return 200;
    case 'medium':   return 100;
    case 'low':      return 50;
    default:         return 50;
  }
}

interface Props {
  riskFactors?: RiskFactor[];
  riskReasons?: string[];
  totalCvss?: number;
  riskLevel?: string;
  /** "full" shows header + total; "compact" hides header (for drawer use) */
  mode?: 'full' | 'compact';
}

export default function RiskScoreWaterfall({ riskFactors, riskReasons, totalCvss, riskLevel, mode = 'full' }: Props) {
  const factors = normalizeFactors(riskFactors, riskReasons);
  if (factors.length === 0) return null;

  // Sort by points descending — biggest contributor at top.
  const sorted = [...factors].sort((a, b) => (b.points || 0) - (a.points || 0));
  const pointSum = sorted.reduce((s, f) => s + (f.points || 0), 0) || 1;
  const totalScore = typeof totalCvss === 'number' ? totalCvss : Math.min(10, pointSum / 100);

  // Map each factor's points to a 0-10 contribution proportional to its share
  // of the total. This is a *visualization*, not a re-derivation of the score —
  // we don't claim mathematical fidelity to the CVSS rubric, we claim that
  // bigger bars = bigger contributors. The total at the bottom is the real CVSS.
  const contributions = sorted.map(f => ({
    ...f,
    contribution: ((f.points || 0) / pointSum) * totalScore,
    color: SEVERITY_COLOR[(f.severity || 'medium').toLowerCase()] || SEVERITY_COLOR.medium,
  }));

  const maxContribution = Math.max(...contributions.map(c => c.contribution), 0.1);

  const levelColor =
    (riskLevel || '').toLowerCase() === 'critical' ? '#ef4444' :
    (riskLevel || '').toLowerCase() === 'high' ? '#f97316' :
    (riskLevel || '').toLowerCase() === 'medium' ? '#f59e0b' :
    (riskLevel || '').toLowerCase() === 'low' ? '#10b981' : '#94a3b8';

  return (
    <div className={mode === 'full' ? 'bg-white border rounded-2xl p-5' : ''}>
      {mode === 'full' && (
        <div className="flex items-center justify-between mb-3">
          <div>
            <div className="text-sm font-semibold text-gray-900">Risk Score Breakdown</div>
            <div className="text-[11px] text-gray-500 mt-0.5">How {totalScore.toFixed(1)} CVSS was assembled — bigger bar = bigger contributor</div>
          </div>
          {totalCvss !== undefined && (
            <div className="text-right">
              <div className="text-2xl font-bold" style={{ color: levelColor }}>{totalScore.toFixed(1)}</div>
              <div className="text-[10px] uppercase tracking-wider text-gray-500">CVSS · {(riskLevel || '').toUpperCase()}</div>
            </div>
          )}
        </div>
      )}

      <div className="space-y-2">
        {contributions.map((f, i) => {
          const barPct = Math.max(2, (f.contribution / maxContribution) * 100);
          return (
            <div key={i} className="flex items-center gap-3">
              {/* Severity chip */}
              <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase flex-shrink-0 w-16 text-center"
                style={{ background: `${f.color}1a`, color: f.color, border: `1px solid ${f.color}55` }}>
                {f.severity}
              </span>

              {/* Description + bar */}
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline justify-between gap-2 mb-0.5">
                  <span className="text-xs text-gray-800 truncate" title={f.description}>{f.description}</span>
                  <span className="text-[11px] font-mono font-semibold flex-shrink-0" style={{ color: f.color }}>
                    +{f.contribution.toFixed(1)}
                  </span>
                </div>
                <div className="h-1.5 rounded-full bg-gray-100 overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${barPct}%`, background: f.color }} />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {mode === 'full' && (
        <div className="mt-4 pt-3 border-t border-gray-100 flex items-center justify-between">
          <div className="text-[11px] text-gray-500">
            <span className="text-gray-700 font-semibold">{contributions.length}</span> contributing factor{contributions.length === 1 ? '' : 's'} &middot; mapped to CIS / NIST / MITRE ATT&amp;CK
          </div>
          <div className="text-xs">
            <span className="text-gray-500">Total:</span>{' '}
            <span className="font-bold" style={{ color: levelColor }}>{totalScore.toFixed(1)} / 10</span>
          </div>
        </div>
      )}
    </div>
  );
}
