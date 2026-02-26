/**
 * AuditGraph Display Helpers — Zero-Value & Unknown Handling
 *
 * Single source of truth for display logic:
 * - Zero values → always muted (never severity-colored)
 * - Unknown/N/A → plain dash, no colored badge
 * - Score 0.0 → "NO DATA" not "CRITICAL"
 * - Confidence filtering for remediations
 */

// ── Zero-Value Color ───────────────────────────────────────────────

/**
 * Returns the display color for a KPI value.
 * RULE: Zero/null/undefined → always muted, never severity-colored.
 */
export function getValueColor(value: number | null | undefined, hasSeverity?: boolean): string {
  if (value === null || value === undefined || value === 0) return 'var(--text-muted)';
  if (!hasSeverity) return 'var(--text-primary)';
  if (value >= 80) return 'var(--accent-danger, #dc2626)';
  if (value >= 60) return 'var(--accent-warning, #f59e0b)';
  if (value >= 40) return '#ca8a04';
  if (value >= 20) return 'var(--accent-primary, #2563eb)';
  return 'var(--accent-success, #16a34a)';
}

// ── Score Tier ─────────────────────────────────────────────────────

/**
 * Returns tier label for a risk score.
 * RULE: Score 0 → "NO DATA" (grey), not "CRITICAL" (red).
 */
export function getScoreTier(score: number | null | undefined): {
  label: string;
  color: string;
} {
  if (score === null || score === undefined || score === 0) {
    return { label: 'NO DATA', color: 'var(--text-muted)' };
  }
  if (score >= 80) return { label: 'RESILIENT', color: 'var(--accent-success, #16a34a)' };
  if (score >= 60) return { label: 'CONTROLLED', color: '#ca8a04' };
  if (score >= 40) return { label: 'ELEVATED', color: 'var(--accent-warning, #f59e0b)' };
  if (score >= 20) return { label: 'HIGH', color: '#ea580c' };
  return { label: 'CRITICAL', color: 'var(--accent-danger, #dc2626)' };
}

/**
 * Returns severity label for a risk score (inverse of posture).
 * Higher score = worse risk. Score 0 = no data.
 */
export function getRiskSeverity(score: number | null | undefined): {
  label: string;
  color: string;
} {
  if (score === null || score === undefined || score === 0) {
    return { label: 'NO DATA', color: 'var(--text-muted)' };
  }
  if (score < 20) return { label: 'LOW', color: 'var(--accent-success, #16a34a)' };
  if (score < 40) return { label: 'ELEVATED', color: '#ca8a04' };
  if (score < 60) return { label: 'HIGH', color: '#ea580c' };
  if (score < 80) return { label: 'CRITICAL', color: 'var(--accent-danger, #dc2626)' };
  return { label: 'SEVERE', color: 'var(--accent-danger, #dc2626)' };
}

// ── Unknown/N/A Handling ──────────────────────────────────────────

/**
 * Formats unknown, null, or N/A values as a plain dash.
 * RULE: Unknown gets no badge, no color — just "—" in muted text.
 */
export function formatUnknownValue(value: any): { text: string; isMissing: boolean } {
  if (
    value === null ||
    value === undefined ||
    value === '' ||
    value === 'unknown' ||
    value === 'Unknown' ||
    value === 'N/A' ||
    value === 'n/a' ||
    value === 'none' ||
    value === 'None'
  ) {
    return { text: '—', isMissing: true };
  }
  return { text: String(value), isMissing: false };
}

// ── Date Handling ─────────────────────────────────────────────────

/**
 * Formats a date string safely. Returns "No data" for null/invalid dates
 * instead of "Invalid Date".
 */
export function formatDate(dateStr: string | null | undefined, fallback = 'No data'): string {
  if (!dateStr) return fallback;
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return fallback;
  return d.toLocaleString();
}

/**
 * Formats relative time (e.g., "2 hours ago"). Returns fallback for null/invalid.
 */
export function formatRelativeTime(dateStr: string | null | undefined, fallback = 'Never'): string {
  if (!dateStr) return fallback;
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return fallback;

  const now = Date.now();
  const diff = now - d.getTime();
  const mins = Math.floor(diff / 60000);

  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

// ── Remediation Filtering ─────────────────────────────────────────

/**
 * Returns true if a remediation item should be displayed.
 * RULE: Hide items with 0% confidence AND 0 risk reduction.
 */
export function shouldShowRemediation(item: {
  confidence?: number | null;
  riskReduction?: number | null;
  risk_reduction?: number | null;
  gain?: number | null;
  action?: string;
}): boolean {
  const confidence = item.confidence ?? 0;
  const reduction = item.riskReduction ?? item.risk_reduction ?? item.gain ?? 0;

  // Hide items with no meaningful data
  if (confidence === 0 && reduction === 0) return false;
  // Hide webhook-only items with no risk reduction
  if (item.action === 'webhook' && reduction === 0) return false;
  return true;
}

// ── Frequency Handling ────────────────────────────────────────────

/**
 * Formats scan frequency. Returns "Not configured" for null/unknown.
 */
export function formatFrequency(freq: string | null | undefined): string {
  if (!freq || freq === 'unknown' || freq === 'Unknown') return 'Not configured';
  return freq;
}

// ── Completeness Handling ─────────────────────────────────────────

/**
 * Formats completeness percentage with appropriate label for 0%.
 */
export function formatCompleteness(pct: number | null | undefined): {
  text: string;
  color: string;
} {
  if (pct === null || pct === undefined || pct === 0) {
    return { text: 'No scan completed', color: 'var(--text-muted)' };
  }
  if (pct < 30) return { text: `${pct}%`, color: 'var(--accent-warning, #f59e0b)' };
  if (pct < 70) return { text: `${pct}%`, color: '#ca8a04' };
  return { text: `${pct}%`, color: 'var(--accent-success, #16a34a)' };
}
