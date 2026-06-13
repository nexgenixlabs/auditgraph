/**
 * Top Improvement Opportunities ranker (2026-06-12)
 *
 * Inverts the Identity Security Score breakdown into actionable remediation
 * opportunities. Each opportunity says: "fix N of X → +Y points." Ranked
 * by projected lift (gap × weight / 100), descending.
 *
 * Per peer review: the Role Mining banner "Removing these 114 toxic combos
 * could lift your score by ~6.8 points" was praised for connecting Problem
 * → Impact → Remediation → Outcome. This util generalizes the same pattern
 * across all 6 score factors and surfaces the top opportunities on the
 * Executive Posture / CISO Dashboard.
 *
 * Math:
 *   gap        = 100 − subScore             (room to grow on this factor)
 *   maxLift    = gap × weight / 100          (overall score points gained)
 *   So closing every bad item maxes out the factor.
 *   Partial fixes scale linearly: items_fixed / items_bad × maxLift.
 */

import { computeIdentityScoreBreakdown, type ScoreBreakdownInput } from './identityScoreBreakdown';

export interface Opportunity {
  key: 'priv' | 'paths' | 'own' | 'sec' | 'aigov' | 'reach';
  title: string;          // imperative — "Close critical attack paths"
  countToFix: number;     // 10
  unit: string;           // "critical attack path" / singular form
  factorLabel: string;    // "Attack Paths"
  weight: number;         // 20
  currentSubScore: number;
  projectedLift: number;  // overall score points if all items fixed (rounded to 0.1)
  drillTo: string;        // "/attack-paths"
  ctaLabel: string;       // "Open attack paths"
  color: string;
}

export function computeImprovementOpportunities(input: ScoreBreakdownInput): Opportunity[] {
  const { factors } = computeIdentityScoreBreakdown(input);

  function liftOf(subScore: number, weight: number): number {
    const lift = ((100 - subScore) * weight) / 100;
    return Math.round(lift * 10) / 10;
  }

  const f = (k: string) => factors.find(x => x.key === k)!;

  const opps: Opportunity[] = [];

  // ── 1. Excessive Privileges (30% weight) — biggest lever ──────────
  const priv = f('priv');
  const privBad = input.criticalIdentities + input.highIdentities;
  if (priv.subScore < 100 && privBad > 0) {
    opps.push({
      key: 'priv', title: 'Reduce excessive privileges (toxic combos + over-permissioned roles)',
      countToFix: privBad, unit: privBad === 1 ? 'identity' : 'identities',
      factorLabel: priv.label, weight: priv.weight, currentSubScore: priv.subScore,
      projectedLift: liftOf(priv.subScore, priv.weight),
      drillTo: '/role-mining', ctaLabel: 'Open Role Mining', color: priv.color,
    });
  }

  // ── 2. Attack Paths (20% weight) ──────────────────────────────────
  const paths = f('paths');
  if (paths.subScore < 100 && input.criticalAttackPaths > 0) {
    opps.push({
      key: 'paths', title: 'Close critical multi-hop attack paths',
      countToFix: input.criticalAttackPaths, unit: input.criticalAttackPaths === 1 ? 'critical attack path' : 'critical attack paths',
      factorLabel: paths.label, weight: paths.weight, currentSubScore: paths.subScore,
      projectedLift: liftOf(paths.subScore, paths.weight),
      drillTo: '/attack-paths', ctaLabel: 'Open Attack Paths', color: paths.color,
    });
  }

  // ── 3. NHI Ownership (15% weight) ─────────────────────────────────
  const own = f('own');
  if (own.subScore < 100 && input.nhiUnowned > 0) {
    opps.push({
      key: 'own', title: 'Assign accountable owners to unowned non-human identities',
      countToFix: input.nhiUnowned, unit: input.nhiUnowned === 1 ? 'unowned NHI' : 'unowned NHIs',
      factorLabel: own.label, weight: own.weight, currentSubScore: own.subScore,
      projectedLift: liftOf(own.subScore, own.weight),
      drillTo: '/ownership', ctaLabel: 'Open Ownership Center', color: own.color,
    });
  }

  // ── 4. Secret Hygiene (15% weight) ────────────────────────────────
  const sec = f('sec');
  if (sec.subScore < 100 && input.expiredOrExpiringCreds > 0) {
    opps.push({
      key: 'sec', title: 'Rotate expired or expiring credentials',
      countToFix: input.expiredOrExpiringCreds, unit: input.expiredOrExpiringCreds === 1 ? 'credential' : 'credentials',
      factorLabel: sec.label, weight: sec.weight, currentSubScore: sec.subScore,
      projectedLift: liftOf(sec.subScore, sec.weight),
      drillTo: '/nhi?tab=secrets', ctaLabel: 'Open Secrets', color: sec.color,
    });
  }

  // ── 5. AI Governance (10% weight) ─────────────────────────────────
  const aigov = f('aigov');
  if (aigov.subScore < 100 && input.aiWithoutTelemetry > 0) {
    opps.push({
      key: 'aigov', title: 'Enable telemetry / activity monitoring on AI agents',
      countToFix: input.aiWithoutTelemetry, unit: input.aiWithoutTelemetry === 1 ? 'AI agent' : 'AI agents',
      factorLabel: aigov.label, weight: aigov.weight, currentSubScore: aigov.subScore,
      projectedLift: liftOf(aigov.subScore, aigov.weight),
      drillTo: '/ai-identity', ctaLabel: 'Open AI Identity', color: aigov.color,
    });
  }

  // ── 6. Exposure Reachability (10% weight) ─────────────────────────
  const reach = f('reach');
  if (reach.subScore < 100 && input.reachableSensitiveCount > 0) {
    opps.push({
      key: 'reach', title: 'Scope-down identities that can reach regulated data',
      countToFix: input.reachableSensitiveCount, unit: input.reachableSensitiveCount === 1 ? 'identity' : 'identities',
      factorLabel: reach.label, weight: reach.weight, currentSubScore: reach.subScore,
      projectedLift: liftOf(reach.subScore, reach.weight),
      drillTo: '/data-reachability', ctaLabel: 'Open Data Reachability', color: reach.color,
    });
  }

  // Rank by projected lift desc; tie-break by item count desc.
  opps.sort((a, b) => b.projectedLift - a.projectedLift || b.countToFix - a.countToFix);
  return opps;
}

/** Sum of the top-N opportunities' projected lifts. Used for the headline. */
export function topNLift(opps: Opportunity[], n = 3): number {
  return Math.round(opps.slice(0, n).reduce((s, o) => s + o.projectedLift, 0) * 10) / 10;
}
