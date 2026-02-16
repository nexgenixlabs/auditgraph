// ── Per-Cloud Pricing (Pro Tier) ────────────────────────────────────────────
// Each cloud has its own monthly price. All features included with Pro.
export const CLOUD_PRICING: Record<string, Record<string, number>> = {
  azure: { pro: 899 },
  aws:   { pro: 949 },
  gcp:   { pro: 849 },
};

// ── Enterprise Tier ─────────────────────────────────────────────────────────
// Flat monthly base price — includes all clouds, all add-ons, unlimited users
export const ENTERPRISE_BASE = 2499;

// ── Paid Add-Ons (Pro tier only — Enterprise includes everything) ───────────
export const ADDON_PRICING: Record<string, { label: string; price: number; description: string }> = {
  ai_copilot:            { label: 'AI Security Copilot',                price: 149, description: 'AI-powered security assistant using live AuditGraph data' },
  extended_retention:     { label: 'Extended Retention (365 days)',      price: 249, description: 'Extend data retention from 90 to 365 days' },
  additional_users_5pack: { label: 'Additional Portal Users (5-pack)',  price: 49,  description: '+5 additional portal user seats' },
};

// ── Base Features (included with Pro/Enterprise/Trial — not Free) ───────────
export const BASE_FEATURES: Record<string, { label: string; description: string }> = {
  secret_monitoring:  { label: 'Secret Expiry Monitoring',       description: 'Continuous secret & credential expiry monitoring & notifications' },
  audit_reports:      { label: 'Audit-Ready PDF Reports',        description: 'SOC2, HIPAA, and PCI compliance audit reports' },
};

// ── Coming Soon Features (visible but disabled) ─────────────────────────────
export const COMING_SOON_FEATURES: Record<string, { label: string; description: string }> = {
  terraform_export: { label: 'Terraform/Bicep Export & Bot', description: 'Export infrastructure as Terraform/Bicep with bot integration' },
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

// ── Enterprise Term Bundles ─────────────────────────────────────────────────
// Enterprise gets extra value at longer commitments
export const ENTERPRISE_BUNDLES: Record<number, string[]> = {
  0: [],
  1: ['Extended Retention'],
  3: ['Extended Retention', 'Priority Support'],
  5: ['Extended Retention', 'Priority Support', 'Custom Integration Hours'],
};

export function getTermDiscount(term: number): number {
  const t = SUBSCRIPTION_TERMS.find(s => s.value === term);
  return t ? t.discount : 0;
}

export function getTermLabel(term: number): string {
  const t = SUBSCRIPTION_TERMS.find(s => s.value === term);
  return t ? t.label : 'Monthly';
}

/** Effective monthly price after term discount */
export function calculateDiscountedMonthly(cfg: CloudConfig, term: number, plan: string = 'pro'): number {
  const base = calculateMonthlyTotal(cfg, plan);
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
export const ACCOUNT_TIERS = ['free', 'trial', 'pro', 'enterprise'] as const;

export const ACCOUNT_TIER_LABELS: Record<string, { label: string; color: string; bg: string }> = {
  free:       { label: 'Free',       color: 'text-gray-700',   bg: 'bg-gray-100' },
  trial:      { label: 'Trial',      color: 'text-amber-700',  bg: 'bg-amber-100' },
  pro:        { label: 'Pro',        color: 'text-blue-700',   bg: 'bg-blue-100' },
  enterprise: { label: 'Enterprise', color: 'text-purple-700', bg: 'bg-purple-100' },
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
export function calculateMonthlyTotal(cfg: CloudConfig, plan: string = 'pro'): number {
  if (plan === 'enterprise') return ENTERPRISE_BASE;
  if (plan === 'free' || plan === 'trial') return 0;
  return calculateCloudBaseTotal(cfg) + calculateAddonTotal(cfg);
}

/** Cloud infrastructure cost only */
export function calculateCloudBaseTotal(cfg: CloudConfig, plan?: string): number {
  if (plan === 'enterprise') return ENTERPRISE_BASE;
  let total = 0;
  for (const [key, provider] of Object.entries(cfg.cloud_providers)) {
    if (provider.enabled && CLOUD_PRICING[key]) {
      total += CLOUD_PRICING[key].pro;
    }
  }
  return total;
}

/** Add-on cost only (Pro tier — Enterprise includes all) */
export function calculateAddonTotal(cfg: CloudConfig, plan?: string): number {
  if (plan === 'enterprise') return 0;
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
  direct: 200,  // $200/month base platform fee
  msp: 500,     // $500/month MSP platform fee
};

// Phase 78: Tier limits for free/trial enforcement
export const TIER_LIMITS: Record<string, { max_identities: number | null; trial_days?: number; blocked_features: string[] }> = {
  free: { max_identities: 50, blocked_features: ['soar', 'api_keys', 'advanced_query', 'custom_risk_rules', 'ai_copilot'] },
  trial: { max_identities: 500, trial_days: 14, blocked_features: [] },
  pro: { max_identities: null, blocked_features: [] },
  enterprise: { max_identities: null, blocked_features: [] },
};
