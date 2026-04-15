/**
 * Identity Risk Scoring v2.0 — Pure Computation
 *
 * Maps existing backend identity fields into 5 normalized 0-10 dimensions
 * aligned to CVSS v3.1, MITRE ATT&CK, CIS Controls v8, and NIST CSF 2.0.
 *
 * No side effects, no API calls, no React hooks.
 */

import { DIMENSIONS, getSeverityFromScore } from '../constants/riskScoring';

// ── Output Types ────────────────────────────────────────────

export interface DimensionScore {
  dimension: string;   // dimension key
  name: string;        // display name
  score: number;       // 0-10
  severity: string;    // critical/high/medium/low/info
  color: string;       // dimension color
  icon: string;        // dimension icon
  mitre: string[];     // ATT&CK technique IDs
  cis: string[];       // CIS control IDs
  nist: string[];      // NIST CSF functions
}

export interface IdentityRiskResult {
  dimensions: DimensionScore[];
  overall_severity: string;     // max(all dimension severities)
  overall_score: number;        // max(all dimension scores)
  critical_count: number;       // dimensions >= 9.0
  high_count: number;           // dimensions >= 7.0
}

// ── Severity priority for max() ─────────────────────────────

const SEV_ORDER: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};

/** Clamp a score to 0-10 range. Max possible score is always 10.0. */
export const clamp = (v: number | null | undefined): number => {
  if (v == null || isNaN(Number(v))) return 0;
  return Math.min(10, Math.max(0, Number(v)));
};

/** Normalize a raw score (0-N) to 0-10 by dividing by `divisor`, then clamping. */
export const normalizeScore = (raw: number | null | undefined, divisor: number): number =>
  clamp(raw != null ? raw / divisor : 0);

// ── Helper: extract text from risk_factors ──────────────────

function extractFactorText(identity: Record<string, any>): string {
  const factors = (identity.key_risk_factors || identity.risk_factors || []);
  return factors.map((f: any) => typeof f === 'string' ? f : (f.factor || f.detail || f.description || '')).join(' ').toLowerCase();
}

// ── Helper: normalize privilege_tier to numeric ─────────────

function normalizeTier(raw: any): number {
  if (raw == null) return 3;
  // Numeric already: 0, 1, 2, 3
  if (typeof raw === 'number') return raw;
  // String: 'T0', 'T1', 'T2', 'T3' or '0', '1', '2', '3'
  const s = String(raw).replace(/^T/i, '');
  const n = parseInt(s, 10);
  return isNaN(n) ? 3 : n;
}

// ── Scoring Functions ───────────────────────────────────────

function scoreBlastRadius(identity: Record<string, any>): number {
  const br = identity.blast_radius_score ?? 0;
  if (br >= 80) return 10;
  if (br >= 60) return 8;
  if (br >= 40) return 6;
  if (br >= 20) return 4;
  if (br > 0)   return 2;

  // Fallback: infer from subscription/role counts if blast_radius_score is 0
  const subs = identity.subscription_count ?? 0;
  const roles = identity.total_role_count ?? identity.role_count ?? 0;
  if (subs >= 5 || roles >= 20) return 10;
  if (subs >= 2 || roles >= 10) return 8;
  if (subs >= 1 || roles >= 5)  return 6;
  if (roles > 0) return 2;

  return 0;
}

function scorePrivilegeExposure(identity: Record<string, any>): number {
  const tier = normalizeTier(identity.privilege_tier);
  let score = tier === 0 ? 10 : tier === 1 ? 7 : tier === 2 ? 4 : 0;

  const factorStr = extractFactorText(identity);

  // Fallback FIRST: if tier-based score is 0, infer from risk_factors
  if (score === 0 && factorStr) {
    if (/t0 privilege|global admin/i.test(factorStr)) score = 10;
    else if (/t1 privilege|user access admin|owner/i.test(factorStr)) score = 7;
    else if (/t2 privilege|contributor/i.test(factorStr)) score = 4;
  }

  // Boost +1 if has Owner or Global Admin in risk_factors (applied after fallback)
  if (/owner|global admin|privileged role/i.test(factorStr)) {
    score = Math.min(10, score + 1);
  }

  return score;
}

function scoreDormancyRisk(identity: Record<string, any>): number {
  const status = (identity.activity_status || '').toLowerCase();
  switch (status) {
    case 'never_used': return 10;
    case 'stale':      return 9;
    case 'inactive':   return 6;
    case 'unknown':    return 5;
    case 'recently_created': return 2;
    case 'active':
    case 'likely_active':
      return 0;
    default: break;
  }

  // Fallback: check risk_factors for dormancy signals
  const factorStr = extractFactorText(identity);
  if (/dormant|stale|never.?used/i.test(factorStr)) return 9;
  if (/inactive/i.test(factorStr)) return 6;

  return 3;
}

function scoreGovernanceGaps(identity: Record<string, any>): number {
  const hasOwner = !!identity.owner_display_name;
  const cat = (identity.identity_category || '').toLowerCase();
  const isNHI = cat === 'service_principal' || cat.startsWith('managed_identity');

  let score = 0;
  if (!hasOwner && isNHI)  score = 8;
  else if (!hasOwner)      score = 3;

  // Boost +2 if orphaned risk_factor
  const factorStr = extractFactorText(identity);
  if (/orphan/i.test(factorStr)) {
    score = Math.min(10, score + 2);
  }

  return score;
}

function scoreCredentialRisk(identity: Record<string, any>): number {
  const credRisk = (identity.credential_risk || '').toLowerCase();
  let score = 0;

  if (credRisk === 'expired') score = 10;
  else if (credRisk === 'expiring_soon' || credRisk === 'expiring') score = 7;

  // Also check risk_factors for credential signals
  if (score === 0) {
    const factorStr = extractFactorText(identity);
    if (/expired/i.test(factorStr)) score = 10;
    else if (/expiring|credential/i.test(factorStr)) score = 7;
  }

  // Boost +1 if multi-tenant SPN
  const factorStr = extractFactorText(identity);
  if (/multi.?tenant/i.test(factorStr)) {
    score = Math.min(10, score + 1);
  }

  return score;
}

// ── Score function registry ─────────────────────────────────

const SCORE_FNS: Record<string, (identity: Record<string, any>) => number> = {
  blast_radius: scoreBlastRadius,
  privilege_exposure: scorePrivilegeExposure,
  dormancy_risk: scoreDormancyRisk,
  governance_gaps: scoreGovernanceGaps,
  credential_risk: scoreCredentialRisk,
};

// ── Main computation ────────────────────────────────────────

export function computeIdentityRisk(identity: Record<string, any>): IdentityRiskResult {
  const dimensions: DimensionScore[] = DIMENSIONS.map(dim => {
    const scoreFn = SCORE_FNS[dim.key];
    const raw = scoreFn ? scoreFn(identity) : 0;
    const score = clamp(raw);
    const severity = getSeverityFromScore(score);
    return {
      dimension: dim.key,
      name: dim.name,
      score,
      severity,
      color: dim.color,
      icon: dim.icon,
      mitre: dim.mitre,
      cis: dim.cis,
      nist: dim.nist,
    };
  });

  const maxScore = clamp(Math.max(0, ...dimensions.map(d => d.score)));
  const maxSeverity = dimensions.reduce((best, d) => {
    return (SEV_ORDER[d.severity] ?? 0) > (SEV_ORDER[best] ?? 0) ? d.severity : best;
  }, 'info');

  return {
    dimensions,
    overall_severity: maxSeverity,
    overall_score: maxScore,
    critical_count: dimensions.filter(d => d.score >= 9.0).length,
    high_count: dimensions.filter(d => d.score >= 7.0).length,
  };
}
