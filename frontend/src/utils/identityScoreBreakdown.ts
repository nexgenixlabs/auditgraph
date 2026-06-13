/**
 * AuditGraph Identity Security Score Methodology v1 (2026-06-11)
 *
 * Decomposes the headline Identity Security Score into 6 weighted factors
 * so a customer can answer "what does 59 mean?" and an auditor can defend
 * the math. Built per peer-review feedback that a black-box score doesn't
 * survive a board review.
 *
 * Each factor is:
 *   - architecturally derived (read-only signals; no telemetry needed)
 *   - weighted by published breach-attribution data (see citations)
 *   - rendered as a 0-100 sub-score; weighted sum ≈ headline score
 *
 * Weights are intentionally rounded to make the methodology memorable:
 *   30 / 20 / 15 / 15 / 10 / 10  →  sum 100
 *
 * SOURCES cited in every factor row of the drawer:
 *   - IBM 2024 Cost of a Data Breach Report (M-Trends, Ponemon)
 *   - Verizon DBIR 2024
 *   - NIST SP 800-53 Rev 5
 *   - NIST AI RMF 1.0
 *   - OWASP API Top 10 (2023)
 */

export interface ScoreFactor {
  key: 'priv' | 'paths' | 'own' | 'sec' | 'aigov' | 'reach';
  label: string;
  weight: number;       // 0-100 (percent of total score this factor can contribute)
  subScore: number;     // 0-100 health of this factor (100 = healthy, 0 = bad)
  contribution: number; // weight * subScore / 100, rounded — the points this adds
  citation: string;     // industry justification for the weight
  signalDetail: string; // plain-English derivation
  // V2.10 (2026-06-12) — board-room concern line. Only set when subScore < 75.
  executiveImpact?: string;
  color: string;        // accent for the row
}

export interface ScoreBreakdownInput {
  totalIdentities: number;
  criticalIdentities: number;        // count flagged as risk_level=critical
  highIdentities: number;            // count flagged as risk_level=high
  totalNhi: number;                  // non-human identities
  nhiUnowned: number;                // NHIs with no owner
  totalAttackPaths: number;
  criticalAttackPaths: number;
  totalCreds: number;                // identity credentials tracked
  expiredOrExpiringCreds: number;    // expired + expiring-within-30d
  totalAi: number;                   // AI agent identities
  aiWithoutTelemetry: number;        // AI with no monitoring/lineage signal
  reachableSensitiveCount: number;   // identities reaching PHI/PCI/PII/AI assets
}

const COLORS = {
  green:  '#34d399',
  yellow: '#fbbf24',
  red:    '#f87171',
};

function pickColor(subScore: number): string {
  if (subScore >= 75) return COLORS.green;
  if (subScore >= 50) return COLORS.yellow;
  return COLORS.red;
}

/**
 * Bound a percentage to 0-100. Treat NaN/Infinity as 100 (healthy) so
 * tenants with zero denominators don't read as red-flagged.
 */
function clamp01(v: number): number {
  if (!Number.isFinite(v)) return 1;
  if (v < 0) return 0;
  if (v > 1) return 1;
  return v;
}

export function computeIdentityScoreBreakdown(input: ScoreBreakdownInput): {
  factors: ScoreFactor[];
  total: number;
} {
  // ── Factor 1: Excessive Privileges (30%) ────────────────────────
  // Weight justified by IBM 2024: privileged access misuse ≈ 26% of
  // breaches; we round to 30 as the heaviest factor.
  const privBad = input.totalIdentities > 0
    ? (input.criticalIdentities + input.highIdentities * 0.5) / input.totalIdentities
    : 0;
  const privScore = Math.round((1 - clamp01(privBad)) * 100);

  // ── Factor 2: Attack Paths (20%) ────────────────────────────────
  // Caps at 10 critical paths = 0 sub-score; below that, linear.
  const pathBad = clamp01(input.criticalAttackPaths / 10);
  const pathScore = Math.round((1 - pathBad) * 100);

  // ── Factor 3: NHI Ownership (15%) ───────────────────────────────
  // Unowned NHI is a NIST AC-2 violation. Score = % owned.
  const ownGood = input.totalNhi > 0
    ? 1 - clamp01(input.nhiUnowned / input.totalNhi)
    : 1;
  const ownScore = Math.round(ownGood * 100);

  // ── Factor 4: Secret Hygiene (15%) ──────────────────────────────
  // Score = % of creds NOT expired/expiring.
  const secGood = input.totalCreds > 0
    ? 1 - clamp01(input.expiredOrExpiringCreds / input.totalCreds)
    : 1;
  const secScore = Math.round(secGood * 100);

  // ── Factor 5: AI Governance (10%) ───────────────────────────────
  // Score = % of AI identities with telemetry / monitoring.
  const aiGood = input.totalAi > 0
    ? 1 - clamp01(input.aiWithoutTelemetry / input.totalAi)
    : 1;
  const aiScore = Math.round(aiGood * 100);

  // ── Factor 6: Exposure Reachability (10%) ───────────────────────
  // Score = % of identities NOT able to reach sensitive data.
  const reachGood = input.totalIdentities > 0
    ? 1 - clamp01(input.reachableSensitiveCount / input.totalIdentities)
    : 1;
  const reachScore = Math.round(reachGood * 100);

  // V2.10 (2026-06-12) — board-room concern lines. Same threshold as the
  // AI drawer: only render impact statements when subScore < 75.
  const HEALTHY = 75;
  const riskFlagged = input.criticalIdentities + input.highIdentities;
  const pathsN = input.criticalAttackPaths;

  const factors: ScoreFactor[] = [
    {
      key: 'priv',
      label: 'Excessive Privileges',
      weight: 30,
      subScore: privScore,
      contribution: Math.round(privScore * 0.30),
      citation: 'IBM 2024 Cost of a Data Breach: ~26% of breaches involve privileged-access misuse — the single largest attributable cause.',
      signalDetail: input.totalIdentities > 0
        ? `${riskFlagged} of ${input.totalIdentities} identities flagged critical or high risk`
        : 'No identities discovered yet',
      executiveImpact: privScore < HEALTHY && riskFlagged > 0
        ? `${riskFlagged} identit${riskFlagged === 1 ? 'y holds' : 'ies hold'} permissions beyond what the role actually requires — every one of them is a candidate for credential theft + lateral movement.`
        : undefined,
      color: pickColor(privScore),
    },
    {
      key: 'paths',
      label: 'Attack Paths',
      weight: 20,
      subScore: pathScore,
      contribution: Math.round(pathScore * 0.20),
      citation: 'Verizon DBIR 2024: multi-hop credential chains are the dominant intra-environment movement pattern in real breaches.',
      signalDetail: pathsN === 0
        ? 'No critical attack paths open'
        : `${pathsN} critical multi-hop attack path${pathsN === 1 ? '' : 's'} active`,
      executiveImpact: pathScore < HEALTHY && pathsN > 0
        ? `${pathsN} chain${pathsN === 1 ? '' : 's'} that an attacker could traverse from a single compromised credential to sensitive data — close any one of them and the chain breaks.`
        : undefined,
      color: pickColor(pathScore),
    },
    {
      key: 'own',
      label: 'NHI Ownership',
      weight: 15,
      subScore: ownScore,
      contribution: Math.round(ownScore * 0.15),
      citation: 'NIST SP 800-53 AC-2: account-ownership assignment is the foundational access-management control — without it, no other control can be enforced.',
      signalDetail: input.totalNhi > 0
        ? `${input.totalNhi - input.nhiUnowned} of ${input.totalNhi} non-human identities have a registered owner`
        : 'No non-human identities discovered yet',
      executiveImpact: ownScore < HEALTHY && input.nhiUnowned > 0
        ? `${input.nhiUnowned} non-human identit${input.nhiUnowned === 1 ? 'y has' : 'ies have'} no accountable owner — auditors cannot establish who authorized the access, and incident response will stall.`
        : undefined,
      color: pickColor(ownScore),
    },
    {
      key: 'sec',
      label: 'Secret Hygiene',
      weight: 15,
      subScore: secScore,
      contribution: Math.round(secScore * 0.15),
      citation: 'OWASP API Top 10 (2023) #2 — Broken Authentication: credential rotation and expiry are the most-violated API security controls.',
      signalDetail: input.totalCreds > 0
        ? `${input.expiredOrExpiringCreds} of ${input.totalCreds} credentials expired or expiring within 30 days`
        : 'No credentials tracked yet',
      executiveImpact: secScore < HEALTHY && input.expiredOrExpiringCreds > 0
        ? `${input.expiredOrExpiringCreds} credential${input.expiredOrExpiringCreds === 1 ? '' : 's'} ${input.expiredOrExpiringCreds === 1 ? 'is' : 'are'} expired or expiring within 30 days — each one becomes a service outage when it lapses or a stolen token if it doesn't get rotated.`
        : undefined,
      color: pickColor(secScore),
    },
    {
      key: 'aigov',
      label: 'AI Governance',
      weight: 10,
      subScore: aiScore,
      contribution: Math.round(aiScore * 0.10),
      citation: 'NIST AI RMF 1.0 Manage 2.1: monitoring and telemetry are the prerequisite to every other AI safeguard.',
      signalDetail: input.totalAi > 0
        ? `${input.totalAi - input.aiWithoutTelemetry} of ${input.totalAi} AI agent identities have telemetry coverage`
        : 'No AI agent identities discovered yet',
      executiveImpact: aiScore < HEALTHY && input.aiWithoutTelemetry > 0
        ? `${input.aiWithoutTelemetry} AI agent${input.aiWithoutTelemetry === 1 ? '' : 's'} operate${input.aiWithoutTelemetry === 1 ? 's' : ''} with limited observability — anomalies, drift, and policy violations will go undetected.`
        : undefined,
      color: pickColor(aiScore),
    },
    {
      key: 'reach',
      label: 'Exposure Reachability',
      weight: 10,
      subScore: reachScore,
      contribution: Math.round(reachScore * 0.10),
      citation: 'IBM 2024 Cost of a Data Breach: the cost-amplifier on every breach is whether the compromised identity could reach regulated data (PHI/PCI/PII).',
      signalDetail: input.totalIdentities > 0
        ? `${input.reachableSensitiveCount} of ${input.totalIdentities} identities can reach a sensitive-data asset`
        : 'No reachability paths computed yet',
      executiveImpact: reachScore < HEALTHY && input.reachableSensitiveCount > 0
        ? `${input.reachableSensitiveCount} identit${input.reachableSensitiveCount === 1 ? 'y is' : 'ies are'} one credential theft away from reading PHI / PCI / PII data — this is the single largest cost amplifier on a breach event.`
        : undefined,
      color: pickColor(reachScore),
    },
  ];

  const total = factors.reduce((sum, f) => sum + f.contribution, 0);
  return { factors, total };
}

/** Tone band for a 0-100 score, matched to existing Veza/Wiz vocabulary. */
export function scoreTone(score: number): { color: string; label: string } {
  if (score >= 80) return { color: '#34d399', label: 'Strong' };
  if (score >= 60) return { color: '#a3e635', label: 'Good' };
  if (score >= 40) return { color: '#fb923c', label: 'Elevated' };
  return            { color: '#f87171', label: 'Critical' };
}
