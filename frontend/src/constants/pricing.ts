/**
 * DISPLAY-ONLY pricing constants and helpers.
 * All billing calculations are performed server-side in backend/app/pricing.py.
 * These constants are used ONLY for UI display (labels, badges, plan names, rate display).
 * No values from this file are submitted to the backend for billing computation.
 */

// ── Per-Cloud Pricing (Pro Tier) ────────────────────────────────────────────
// Each cloud has its own monthly price. All features included with Pro.
export const CLOUD_PRICING: Record<string, Record<string, number>> = {
  azure: { pro: 899 },
  aws:   { pro: 949 },
  gcp:   { pro: 849 },
};

// ── Paid Add-Ons (Pro tier only) ─────────────────────────────────────────────
export const ADDON_PRICING: Record<string, { label: string; price: number; description: string }> = {
  extended_retention:     { label: 'Extended Retention (365 days)',      price: 149, description: 'Extend data retention from 90 to 365 days' },
  additional_users_5pack: { label: 'Additional Portal Users (5-pack)',  price: 49,  description: '+5 additional portal user seats' },
};

// ── Base Features (included with Pro/Trial — not Free) ───────────────────────
export const BASE_FEATURES: Record<string, { label: string; description: string }> = {
  secret_monitoring:     { label: 'Secret Expiry Monitoring',       description: 'Continuous secret & credential expiry monitoring & notifications' },
  audit_reports:         { label: 'Audit-Ready PDF Reports',        description: 'SOC2, HIPAA, and PCI compliance audit reports' },
  ai_copilot:            { label: 'AI Security Copilot',            description: 'AI-powered security assistant using live AuditGraph data' },
  drift_detection:       { label: 'Drift Detection & Alerts',       description: 'Detect configuration drift and identity changes between snapshots' },
  soar_integration:      { label: 'SOAR Playbooks',                 description: 'Automated response playbooks with condition-based triggers' },
  compliance_frameworks: { label: 'Compliance Frameworks',           description: 'SOC2, HIPAA, PCI, CIS benchmark compliance tracking' },
  identity_governance:   { label: 'Identity Governance',             description: 'Service account attestation and lifecycle management' },
};


// ── Subscription Terms & Progressive Discounts ──────────────────────────────
// Monthly = no discount. Longer commitments get progressive discounts.
export const SUBSCRIPTION_TERMS = [
  { value: 0,  label: 'Monthly',  discount: 0,    shortLabel: 'Monthly' },
  { value: 1,  label: '1 Year',   discount: 0.15, shortLabel: '1yr' },
  { value: 3,  label: '3 Years',  discount: 0.25, shortLabel: '3yr' },
  { value: 5,  label: '5 Years',  discount: 0.35, shortLabel: '5yr' },
] as const;

export type SubscriptionTermValue = 0 | 1 | 3 | 5;

export function getTermDiscount(term: number): number {
  const t = SUBSCRIPTION_TERMS.find(s => s.value === term);
  return t ? t.discount : 0;
}

export function getTermLabel(term: number): string {
  const t = SUBSCRIPTION_TERMS.find(s => s.value === term);
  return t ? t.label : 'Monthly';
}

/** Effective monthly price after term discount */
export function calculateDiscountedMonthly(cfg: CloudConfig, term: number): number {
  const base = calculateMonthlyTotal(cfg);
  return Math.round(base * (1 - getTermDiscount(term)));
}

export const CLOUD_LABELS: Record<string, { label: string; color: string; bg: string; description: string }> = {
  azure: { label: 'Azure', color: 'text-blue-700',   bg: 'bg-blue-100', description: 'Entra ID, SPNs, Managed Identities, Key Vault, Storage' },
  aws:   { label: 'AWS',   color: 'text-orange-700',  bg: 'bg-orange-100', description: 'IAM Roles, Access Keys, Lambda, KMS, S3' },
  gcp:   { label: 'GCP',   color: 'text-red-600',     bg: 'bg-red-100', description: 'Service Accounts, Workload Identity, Secret Manager' },
};

// Per-cloud sub-tiers (within Pro plan)
export const PLAN_TIERS = ['pro'] as const;

// Overall account tiers
export const ACCOUNT_TIERS = ['free', 'trial', 'pro'] as const;

export const ACCOUNT_TIER_LABELS: Record<string, { label: string; color: string; bg: string }> = {
  free:       { label: 'Free',       color: 'text-gray-700',   bg: 'bg-gray-100' },
  trial:      { label: 'Trial',      color: 'text-amber-700',  bg: 'bg-amber-100' },
  pro:        { label: 'Pro',        color: 'text-blue-700',   bg: 'bg-blue-100' },
};

export interface CloudProviderConfig {
  enabled: boolean;
  plan: string | null;
}

export interface CloudConfig {
  cloud_providers: Record<string, CloudProviderConfig>;
  addons: Record<string, boolean>;
}

/** Returns ordered list of enabled cloud keys */
export function getEnabledClouds(cfg: CloudConfig): string[] {
  return ['azure', 'aws', 'gcp'].filter(k => cfg.cloud_providers[k]?.enabled);
}

/** Per-cloud price (Pro tier pricing) */
export function getCloudPrice(_cfg: CloudConfig, cloudKey: string): number {
  return CLOUD_PRICING[cloudKey]?.pro || 0;
}

/** Total monthly cost before term discounts */
export function calculateMonthlyTotal(cfg: CloudConfig): number {
  return calculateCloudBaseTotal(cfg) + calculateAddonTotal(cfg);
}

/** Cloud infrastructure cost only */
export function calculateCloudBaseTotal(cfg: CloudConfig): number {
  let total = 0;
  for (const [key, provider] of Object.entries(cfg.cloud_providers)) {
    if (provider.enabled && CLOUD_PRICING[key]) {
      total += CLOUD_PRICING[key].pro;
    }
  }
  return total;
}

/** Add-on cost only */
export function calculateAddonTotal(cfg: CloudConfig): number {
  let total = 0;
  for (const [addon, enabled] of Object.entries(cfg.addons)) {
    if (enabled && ADDON_PRICING[addon]) {
      total += ADDON_PRICING[addon].price;
    }
  }
  return total;
}

// ── Per-Account Pricing (Subscription-based) ────────────────────────────────
export const ACCOUNT_PRICING = {
  direct: 69,   // $69/month per monitored account (Azure sub / AWS acct / GCP project)
  msp: 40,      // $40/month MSP/CSP partner rate
};

export const PLATFORM_FEE = {
  direct: 500,  // $500/month base platform fee
  msp: 500,     // $500/month MSP platform fee
};

// Phase 78: Tier limits for free/trial enforcement
// Source of truth: backend TIER_LIMITS in handlers.py. These are display-only.
export const TIER_LIMITS: Record<string, { max_identities: number | null; max_subscriptions: number | null; trial_days?: number; blocked_features: string[] }> = {
  free: { max_identities: 500, max_subscriptions: 2, blocked_features: ['soar', 'api_keys', 'advanced_query', 'custom_risk_rules', 'ai_copilot', 'scheduled_reports', 'compliance_export', 'sso'] },
  trial: { max_identities: null, max_subscriptions: null, trial_days: 30, blocked_features: [] },
  pro: { max_identities: null, max_subscriptions: null, blocked_features: [] },
};

// ── Per-Subscription Billing (cents-based) ────────────────────────────────
export const SUB_RATES_CENTS: Record<string, number> = { azure: 6900, aws: 6900, gcp: 6900 };
export const PLATFORM_FEE_CENTS: Record<string, number> = { free: 0, trial: 0, pro: 50000 };

/** Format cents as dollars (e.g. 6900 → "$69") */
export function formatCents(cents: number): string {
  return `$${(cents / 100).toLocaleString()}`;
}

/** Format cents with exact decimals (e.g. 6900 → "$69.00") */
export function formatCentsExact(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}
