/**
 * AI Governance Score Methodology v1 (2026-06-11)
 *
 * Decomposes the AI Board Scorecard headline score into 6 weighted factors
 * mapped to NIST AI RMF 1.0 + ISO 42001. Peer review: "How did you get 63?
 * Need score composition." Now they can answer that.
 *
 * Weights chosen to map roughly to the existing 5-card KPI grid plus a
 * Reachability factor (the differentiator):
 *   Ownership            20%  Manage 2.1
 *   Monitoring           20%  Measure 2.1
 *   Network              15%  ISO 42001 4.1.4
 *   Least Privilege      15%  Manage 2.3
 *   Policy Compliance    10%  ISO 42001 4.6.2
 *   Data Reachability    20%  Manage 2.4 — the "can this agent read PHI?" axis
 */

export interface AiScoreFactor {
  key: 'own' | 'mon' | 'net' | 'priv' | 'pol' | 'reach';
  label: string;
  weight: number;
  subScore: number;
  contribution: number;
  citation: string;
  signalDetail: string;
  // V2.10 (2026-06-12) — peer review: surface the executive impact next to
  // the raw count. "10 of 77 agents have telemetry" is a stat; pairing it
  // with "67 agents operate with limited observability" turns the stat
  // into a board-room concern. Only populated when the factor is below
  // the healthy threshold (sub-score < 75) so we don't doomify good news.
  executiveImpact?: string;
  color: string;
}

export interface AiScoreBreakdownInput {
  totalAgents: number;
  agentsWithOwner: number;
  agentsWithTelemetry: number;
  agentsOnPrivateNetwork: number;
  agentsLeastPrivilege: number;
  agentsPolicyCompliant: number;
  agentsReachingSensitive: number;     // agents that CAN reach PHI/PCI/PII (negative signal)
}

function pickColor(s: number): string {
  if (s >= 75) return '#34d399';
  if (s >= 50) return '#fbbf24';
  return '#f87171';
}

function pct(n: number, d: number, invert = false): number {
  if (d <= 0) return invert ? 100 : 100;
  const r = Math.round((n / d) * 100);
  return invert ? Math.max(0, 100 - r) : Math.max(0, Math.min(100, r));
}

export function computeAiScoreBreakdown(input: AiScoreBreakdownInput): {
  factors: AiScoreFactor[];
  total: number;
} {
  const own   = pct(input.agentsWithOwner, input.totalAgents);
  const mon   = pct(input.agentsWithTelemetry, input.totalAgents);
  const net   = pct(input.agentsOnPrivateNetwork, input.totalAgents);
  const priv  = pct(input.agentsLeastPrivilege, input.totalAgents);
  const pol   = pct(input.agentsPolicyCompliant, input.totalAgents);
  const reach = pct(input.agentsReachingSensitive, input.totalAgents, /*invert=*/true);

  // Executive-impact thresholds. Anything below 75 surfaces the
  // inverse-count framing so the board reads it as concern, not stat.
  const HEALTHY = 75;
  const T = input.totalAgents;
  const ownGap   = T - input.agentsWithOwner;
  const monGap   = T - input.agentsWithTelemetry;
  const netGap   = T - input.agentsOnPrivateNetwork;
  const privGap  = T - input.agentsLeastPrivilege;
  const polGap   = T - input.agentsPolicyCompliant;

  const factors: AiScoreFactor[] = [
    {
      key: 'own', label: 'Ownership Coverage', weight: 20, subScore: own,
      contribution: Math.round(own * 0.20),
      citation: 'NIST AI RMF 1.0 Manage 2.1 — ownership is the prerequisite to every other AI safeguard.',
      signalDetail: `${input.agentsWithOwner} of ${T} agents have a registered human owner`,
      executiveImpact: own < HEALTHY && ownGap > 0
        ? `${ownGap} agent${ownGap === 1 ? '' : 's'} ${ownGap === 1 ? 'has' : 'have'} no accountable owner — incident response will stall without an escalation contact.`
        : undefined,
      color: pickColor(own),
    },
    {
      key: 'mon', label: 'Monitoring Coverage', weight: 20, subScore: mon,
      contribution: Math.round(mon * 0.20),
      citation: 'NIST AI RMF 1.0 Measure 2.1 — measurement is required to manage anything.',
      signalDetail: `${input.agentsWithTelemetry} of ${T} agents have activity telemetry`,
      executiveImpact: mon < HEALTHY && monGap > 0
        ? `${monGap} agent${monGap === 1 ? '' : 's'} ${monGap === 1 ? 'operates' : 'operate'} with limited observability — anomalies, drift, and policy violations will go undetected.`
        : undefined,
      color: pickColor(mon),
    },
    {
      key: 'net', label: 'Private Network', weight: 15, subScore: net,
      contribution: Math.round(net * 0.15),
      citation: 'ISO 42001 §4.1.4 — network isolation is the most cost-effective AI compromise containment.',
      signalDetail: `${input.agentsOnPrivateNetwork} of ${T} agents accessible only via private endpoint`,
      executiveImpact: net < HEALTHY && netGap > 0
        ? `${netGap} agent${netGap === 1 ? '' : 's'} ${netGap === 1 ? 'is' : 'are'} reachable from public networks — any future credential leak becomes an external attack surface, not a contained internal one.`
        : undefined,
      color: pickColor(net),
    },
    {
      key: 'priv', label: 'Least Privilege', weight: 15, subScore: priv,
      contribution: Math.round(priv * 0.15),
      citation: 'NIST AI RMF 1.0 Manage 2.3 — over-permissioned agents are the typical lateral-movement vector.',
      signalDetail: `${input.agentsLeastPrivilege} of ${T} agents pass least-privilege check`,
      executiveImpact: priv < HEALTHY && privGap > 0
        ? `${privGap} agent${privGap === 1 ? '' : 's'} ${privGap === 1 ? 'holds' : 'hold'} more permissions than the role requires — any one of them, if compromised, can be used as a lateral-movement pivot.`
        : undefined,
      color: pickColor(priv),
    },
    {
      key: 'pol', label: 'Policy Compliance', weight: 10, subScore: pol,
      contribution: Math.round(pol * 0.10),
      citation: 'ISO 42001 §4.6.2 — internal AI policy attestation is the audit-trail anchor.',
      signalDetail: `${input.agentsPolicyCompliant} of ${T} agents pass internal policy review`,
      executiveImpact: pol < HEALTHY && polGap > 0
        ? `${polGap} agent${polGap === 1 ? '' : 's'} ${polGap === 1 ? 'has' : 'have'} no recorded policy attestation — auditors cannot verify governance was applied at deployment time.`
        : undefined,
      color: pickColor(pol),
    },
    {
      key: 'reach', label: 'Data Reachability', weight: 20, subScore: reach,
      contribution: Math.round(reach * 0.20),
      citation: 'NIST AI RMF 1.0 Manage 2.4 + IBM 2024 — data-class reachability is the cost amplifier on every AI breach.',
      signalDetail: `${input.agentsReachingSensitive} of ${T} agents currently reach PHI / PCI / PII / sensitive data`,
      executiveImpact: reach < HEALTHY && input.agentsReachingSensitive > 0
        ? `${input.agentsReachingSensitive} agent${input.agentsReachingSensitive === 1 ? '' : 's'} can read regulated data without per-query attestation — this is the single largest cost amplifier on an AI breach event (IBM 2024).`
        : undefined,
      color: pickColor(reach),
    },
  ];

  const total = factors.reduce((s, f) => s + f.contribution, 0);
  return { factors, total };
}
