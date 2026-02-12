// ── Cloud Provider Pricing (per-cloud sub-tiers within Pro) ──────────────────
export const CLOUD_PRICING: Record<string, Record<string, number>> = {
  azure: { starter: 199, growth: 799, enterprise: 1499 },
  aws:   { starter: 249, growth: 849, enterprise: 1549 },
  gcp:   { starter: 229, growth: 829, enterprise: 1529 },
};

// ── Paid Add-Ons (only purchasable extras beyond base Pro features) ──────────
export const ADDON_PRICING: Record<string, { label: string; price: number; description: string }> = {
  extended_retention: { label: 'Extended Retention (365 days)', price: 149, description: 'Extend data retention from 90 to 365 days' },
};

// ── Base Features (included with every Pro+ subscription, not billed) ────────
export const BASE_FEATURES: Record<string, { label: string; description: string }> = {
  secret_monitoring:  { label: 'Secret Expiry Monitoring',     description: 'Continuous secret & credential expiry monitoring & notifications' },
  ai_insights:        { label: 'AI Role Recommendation',       description: 'AI-powered role optimization & security recommendations' },
  audit_reports:      { label: 'Audit-Ready PDF Reports',      description: 'SOC2, HIPAA, and PCI compliance audit reports' },
};

// ── Coming Soon Features (visible but disabled) ─────────────────────────────
export const COMING_SOON_FEATURES: Record<string, { label: string; description: string }> = {
  terraform_export: { label: 'Terraform/Bicep Export & Bot', description: 'Export infrastructure as Terraform/Bicep with bot integration' },
};

export const ANNUAL_DISCOUNT = 0.15;

export const CLOUD_LABELS: Record<string, { label: string; color: string; bg: string; description: string }> = {
  azure: { label: 'Azure', color: 'text-blue-700',   bg: 'bg-blue-100', description: 'Entra ID, SPNs, Managed Identities, Key Vault, Storage' },
  aws:   { label: 'AWS',   color: 'text-orange-700',  bg: 'bg-orange-100', description: 'IAM Roles, Access Keys, Lambda, KMS, S3' },
  gcp:   { label: 'GCP',   color: 'text-red-600',     bg: 'bg-red-100', description: 'Service Accounts, Workload Identity, Secret Manager' },
};

// Per-cloud sub-tiers (within Pro plan)
export const PLAN_TIERS = ['starter', 'growth', 'enterprise'] as const;

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

export function calculateMonthlyTotal(cfg: CloudConfig): number {
  let total = 0;
  for (const [provider, pCfg] of Object.entries(cfg.cloud_providers)) {
    if (pCfg.enabled && pCfg.plan && CLOUD_PRICING[provider]) {
      total += CLOUD_PRICING[provider][pCfg.plan] ?? 0;
    }
  }
  for (const [addon, enabled] of Object.entries(cfg.addons)) {
    if (enabled && ADDON_PRICING[addon]) {
      total += ADDON_PRICING[addon].price;
    }
  }
  return total;
}

export function calculateCloudBaseTotal(cfg: CloudConfig): number {
  let total = 0;
  for (const [provider, pCfg] of Object.entries(cfg.cloud_providers)) {
    if (pCfg.enabled && pCfg.plan && CLOUD_PRICING[provider]) {
      total += CLOUD_PRICING[provider][pCfg.plan] ?? 0;
    }
  }
  return total;
}

export function calculateAddonTotal(cfg: CloudConfig): number {
  let total = 0;
  for (const [addon, enabled] of Object.entries(cfg.addons)) {
    if (enabled && ADDON_PRICING[addon]) {
      total += ADDON_PRICING[addon].price;
    }
  }
  return total;
}
