/**
 * riskDisplay — single source of truth for rendering a risk score to a user.
 *
 * Per founder directive 2026-05-31: AuditGraph's proprietary additive points
 * (e.g. +400, +900) are NEVER shown to users — only industry-standard
 * NIST/CVSS/CIS/MITRE values are CISO-defensible. This helper enforces that
 * across the codebase.
 *
 * Resolution order:
 *   1. `risk_score_cvss` — CVSS-aligned 0-10 (FIRST.org CVSS 3.1). Render as-is.
 *   2. `risk_score` normalized to 0-10 — legacy fallback for endpoints that
 *      haven't been migrated. Same curve as `points_to_cvss()` server-side.
 *   3. `null` / '—' if neither is present.
 *
 * Returns a one-decimal string ("8.2") for direct render, or null for empty.
 *
 * Usage:
 *   {riskDisplay(identity)} → "8.2"
 *   {riskDisplay(identity) ?? '—'}
 */

interface ScorableItem {
  risk_score_cvss?: number | null;
  risk_score?: number | null;
}

/**
 * Mirrors backend `points_to_cvss()` curve for legacy fallback.
 * 0          → 0.0
 * 1–199      → 0.1–3.9   (low)
 * 200–499    → 4.0–6.9   (medium)
 * 500–899    → 7.0–8.9   (high)
 * ≥ 900      → 9.0–10.0  (critical, capped at 10.0)
 */
function pointsToCvss(points: number): number {
  if (points <= 0) return 0.0;
  if (points >= 900) return 10.0;
  if (points >= 500) return Math.round((7.0 + ((points - 500) / 399.0) * 1.9) * 10) / 10;
  if (points >= 200) return Math.round((4.0 + ((points - 200) / 299.0) * 2.9) * 10) / 10;
  return Math.round((0.1 + ((points - 1) / 198.0) * 3.8) * 10) / 10;
}

/** Returns a formatted CVSS-aligned score string ("8.2") or null if unscored. */
export function riskDisplay(item: ScorableItem | null | undefined): string | null {
  if (!item) return null;
  if (typeof item.risk_score_cvss === 'number' && item.risk_score_cvss > 0) {
    return item.risk_score_cvss.toFixed(1);
  }
  if (typeof item.risk_score === 'number' && item.risk_score > 0) {
    return pointsToCvss(item.risk_score).toFixed(1);
  }
  return null;
}

/** Same as riskDisplay but returns a number (or null). For sort comparisons. */
export function riskValue(item: ScorableItem | null | undefined): number | null {
  if (!item) return null;
  if (typeof item.risk_score_cvss === 'number' && item.risk_score_cvss > 0) return item.risk_score_cvss;
  if (typeof item.risk_score === 'number' && item.risk_score > 0) return pointsToCvss(item.risk_score);
  return null;
}

/** Standard tooltip text explaining what the number means. */
export const CVSS_TOOLTIP =
  'CVSS-aligned 0–10 severity (industry standard, FIRST.org CVSS 3.1). ' +
  'Bands: 9.0+ CRITICAL · 7.0–8.9 HIGH · 4.0–6.9 MEDIUM · 0.1–3.9 LOW.';
