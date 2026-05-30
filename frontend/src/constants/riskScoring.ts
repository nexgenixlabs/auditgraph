/**
 * Identity Risk Scoring System v2.0 — Constants
 *
 * 5-dimension identity risk model aligned to:
 *   - CVSS v3.1 severity bands
 *   - MITRE ATT&CK for Enterprise
 *   - CIS Controls v8
 *   - NIST CSF 2.0
 *
 * Frontend-only presentation layer — no backend changes.
 */

// ── Severity Bands (CVSS v3.1 aligned) ──────────────────────
//
// CANONICAL severity hex source for the entire app outside the CISO board.
// `design.ts` RISK_COLORS and `components/ui/StatusBadge.tsx` both consume
// from here so "critical red" is the same red everywhere it renders.
// The four hexes below are the Tailwind 500-band and are intentionally
// visually distinct (red / orange / yellow / green) — do not collapse
// medium to amber even if some CSS tint variables don't have a true yellow.
//
// The CISO board (`constants/cisoColors.ts`) intentionally uses a different,
// more-saturated branded palette and is not drift to be unified.

export interface SeverityBand {
  label: string;
  min: number;
  max: number;
  color: string;      // hex for bars/charts
  bgClass: string;    // tailwind-style background
}

export const SEVERITY_BANDS: Record<string, SeverityBand> = {
  critical: { label: 'Critical', min: 9.0, max: 10.0, color: '#ef4444', bgClass: 'bg-red-500' },
  high:     { label: 'High',     min: 7.0, max: 8.9,  color: '#f97316', bgClass: 'bg-orange-500' },
  medium:   { label: 'Medium',   min: 4.0, max: 6.9,  color: '#eab308', bgClass: 'bg-yellow-500' },
  low:      { label: 'Low',      min: 0.1, max: 3.9,  color: '#22c55e', bgClass: 'bg-green-500' },
  info:     { label: 'Info',     min: 0,   max: 0,    color: '#6b7280', bgClass: 'bg-gray-500' },
};

/** Hex-only severity map. Consumed by design.ts RISK_COLORS and StatusBadge
 *  so all three sources resolve to the same color per severity. */
export const SEVERITY_HEX: Record<string, string> = {
  critical: SEVERITY_BANDS.critical.color,
  high:     SEVERITY_BANDS.high.color,
  medium:   SEVERITY_BANDS.medium.color,
  low:      SEVERITY_BANDS.low.color,
  info:     SEVERITY_BANDS.info.color,
};

export function getSeverityFromScore(score: number): string {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0)    return 'low';
  return 'info';
}

export function getSeverityColor(severity: string): string {
  return SEVERITY_BANDS[severity]?.color || SEVERITY_BANDS.info.color;
}

// ── 5 Risk Dimensions ───────────────────────────────────────

export interface DimensionDef {
  key: string;
  name: string;
  description: string;
  color: string;
  icon: string;
  mitre: string[];     // ATT&CK technique IDs
  cis: string[];       // CIS Controls v8
  nist: string[];      // NIST CSF 2.0 functions
}

export const DIMENSIONS: DimensionDef[] = [
  {
    key: 'blast_radius',
    name: 'Blast Radius',
    description: 'Scope of potential compromise if this identity is breached',
    color: '#ef4444',
    icon: '\uD83D\uDCA5', // explosion
    mitre: ['T1078.004', 'T1098'],
    cis: ['5.4', '6.6'],
    nist: ['PR.AC-4', 'DE.CM-3'],
  },
  {
    key: 'privilege_exposure',
    name: 'Privilege Exposure',
    description: 'Standing privilege level and admin role concentration',
    color: '#f97316',
    icon: '\u26A0\uFE0F', // warning
    mitre: ['T1098', 'T1078.004'],
    cis: ['5.4', '6.2'],
    nist: ['PR.AC-4', 'PR.AC-6'],
  },
  {
    key: 'dormancy_risk',
    name: 'Dormancy Risk',
    description: 'Unused or stale account presenting silent attack surface',
    color: '#f59e0b',
    icon: '\u23F0', // alarm clock
    mitre: ['T1078.004', 'T1550'],
    cis: ['5.3', '6.2'],
    nist: ['DE.CM-1', 'DE.CM-3'],
  },
  {
    key: 'governance_gaps',
    name: 'Governance Gaps',
    description: 'Ownership, compliance, and accountability deficiencies',
    color: '#8b5cf6',
    icon: '\u2699\uFE0F', // gear
    mitre: ['T1078.004', 'T1556'],
    cis: ['5.1', '6.6'],
    nist: ['PR.AC-1', 'RS.AN-3'],
  },
  {
    key: 'credential_risk',
    name: 'Credential Risk',
    description: 'Credential hygiene — expired secrets, weak rotation, exposure',
    color: '#eab308',
    icon: '\uD83D\uDD11', // key
    mitre: ['T1528', 'T1556'],
    cis: ['5.3', '6.2'],
    nist: ['PR.AC-1', 'PR.AC-7'],
  },
];

export const DIMENSION_MAP: Record<string, DimensionDef> = Object.fromEntries(
  DIMENSIONS.map(d => [d.key, d]),
);

// ── Collected standards references (for display) ────────────

export const MITRE_TECHNIQUE_LABELS: Record<string, string> = {
  'T1078.004': 'Valid Accounts: Cloud',
  'T1098':     'Account Manipulation',
  'T1528':     'Steal Application Access Token',
  'T1550':     'Use Alternate Authentication Material',
  'T1556':     'Modify Authentication Process',
};

export const CIS_CONTROL_LABELS: Record<string, string> = {
  '5.1': 'Establish and Maintain an Inventory of Accounts',
  '5.3': 'Disable Dormant Accounts',
  '5.4': 'Restrict Administrator Privileges',
  '6.2': 'Establish an Access Revoking Process',
  '6.6': 'Establish and Maintain an Inventory of Authentication and Authorization Systems',
};

export const NIST_FUNCTION_LABELS: Record<string, string> = {
  'PR.AC-1': 'Identities and credentials are issued, managed, verified, revoked, and audited',
  'PR.AC-4': 'Access permissions and authorizations are managed, incorporating least privilege',
  'PR.AC-6': 'Identities are proofed and bound to credentials',
  'PR.AC-7': 'Users, devices, and other assets are authenticated commensurate with risk',
  'DE.CM-1': 'The network is monitored to detect potential cybersecurity events',
  'DE.CM-3': 'Personnel activity is monitored to detect potential cybersecurity events',
  'RS.AN-3': 'Forensics are performed',
};
