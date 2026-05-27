/**
 * AI Identity Risk Constants — Frontend Mirror
 *
 * Mirrors backend/app/constants/ai_risk.py for UI display.
 * All risk scoring uses CVSS v3.1 severity bands.
 */

// ── Access Level Labels ─────────────────────────────────────

export const ACCESS_LEVEL_LABELS: Record<string, string> = {
  owner: 'Owner',
  contributor: 'Contributor',
  developer: 'Developer',
  user: 'User',
  reader: 'Reader',
  administrator: 'Administrator',
  secrets_officer: 'Secrets Officer',
  secrets_user: 'Secrets User',
  data_reader_writer: 'Read/Write',
  data_reader: 'Read Only',
  full_access: 'Full Access',
  unrestricted: 'Unrestricted',
  restricted: 'Restricted',
  blocked: 'Blocked',
  unknown: 'Unknown',
  none: 'None',
};

export function formatAccessLevel(level: string | null | undefined): string {
  if (!level || level === 'none') return 'Unknown';
  return ACCESS_LEVEL_LABELS[level] || level.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ── Access Category Definitions ─────────────────────────────

export interface AccessCategoryDef {
  key: string;
  label: string;
  description: string;
  icon: string; // SVG path d attribute
  color: string;
}

export const ACCESS_CATEGORIES: AccessCategoryDef[] = [
  {
    key: 'model_access',
    label: 'Model Access',
    description: 'Access to AI/ML models and inference endpoints',
    icon: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z',
    color: '#8b5cf6',
  },
  {
    key: 'key_vault_access',
    label: 'Key Vault',
    description: 'Access to secrets, keys, and certificates',
    icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z',
    color: '#ef4444',
  },
  {
    key: 'data_access',
    label: 'Data Access',
    description: 'Access to storage, databases, and data lakes',
    icon: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4',
    color: '#f97316',
  },
  {
    key: 'telemetry',
    label: 'Telemetry',
    description: 'Access to monitoring, logging, and diagnostics',
    icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
    color: '#22c55e',
  },
  {
    key: 'internet_egress',
    label: 'Internet Egress',
    description: 'Network exposure to public internet',
    icon: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
    color: '#06b6d4',
  },
];

export const ACCESS_CATEGORY_MAP: Record<string, AccessCategoryDef> = Object.fromEntries(
  ACCESS_CATEGORIES.map(c => [c.key, c]),
);

// ── Risk Color Helpers ──────────────────────────────────────

export function accessLevelColor(level: string | null | undefined): string {
  if (!level || level === 'none') return 'text-slate-500';
  const riskMap: Record<string, string> = {
    owner: 'text-red-400',
    administrator: 'text-red-400',
    contributor: 'text-orange-400',
    secrets_officer: 'text-orange-400',
    developer: 'text-yellow-400',
    secrets_user: 'text-yellow-400',
    full_access: 'text-orange-400',
    unrestricted: 'text-red-400',
    user: 'text-blue-400',
    data_reader_writer: 'text-yellow-400',
    data_reader: 'text-green-400',
    reader: 'text-green-400',
    restricted: 'text-green-400',
    blocked: 'text-slate-500',
  };
  return riskMap[level] || 'text-slate-400';
}

export function accessLevelBadge(level: string | null | undefined): string {
  if (!level || level === 'none') return 'bg-slate-800 text-slate-500 border-slate-700';
  const map: Record<string, string> = {
    owner: 'bg-red-900/40 text-red-300 border-red-800/40',
    administrator: 'bg-red-900/40 text-red-300 border-red-800/40',
    contributor: 'bg-orange-900/40 text-orange-300 border-orange-800/40',
    secrets_officer: 'bg-orange-900/40 text-orange-300 border-orange-800/40',
    developer: 'bg-yellow-900/40 text-yellow-300 border-yellow-800/40',
    secrets_user: 'bg-yellow-900/40 text-yellow-300 border-yellow-800/40',
    full_access: 'bg-orange-900/40 text-orange-300 border-orange-800/40',
    unrestricted: 'bg-red-900/40 text-red-300 border-red-800/40',
    user: 'bg-blue-900/30 text-blue-300 border-blue-800/40',
    data_reader: 'bg-green-900/30 text-green-300 border-green-800/40',
    reader: 'bg-green-900/30 text-green-300 border-green-800/40',
    restricted: 'bg-green-900/30 text-green-300 border-green-800/40',
    blocked: 'bg-slate-800 text-slate-400 border-slate-700',
  };
  return map[level] || 'bg-slate-800 text-slate-400 border-slate-700';
}

// ── Platform Labels ─────────────────────────────────────────

export const AI_PLATFORM_LABELS: Record<string, string> = {
  openai: 'OpenAI',
  azure_openai: 'Azure OpenAI',
  azure_ai: 'Azure AI',
  azure_cognitive: 'Azure Cognitive',
  azure_ml: 'Azure ML',
  azure_ai_studio: 'Azure AI Studio',
  anthropic: 'Anthropic',
  copilot_studio: 'Copilot Studio',
  power_virtual_agents: 'Power VA',
  bot_framework: 'Bot Framework',
};

export function formatPlatform(p: string | null | undefined): string {
  if (!p) return '\u2014';
  return AI_PLATFORM_LABELS[p] || p.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ── Confidence Labels ───────────────────────────────────────

export function confidenceLabel(score: number): string {
  if (score >= 0.85) return 'High';
  if (score >= 0.60) return 'Medium';
  if (score >= 0.40) return 'Low';
  return 'Minimal';
}

export function confidenceColor(score: number): string {
  if (score >= 0.85) return 'text-green-400';
  if (score >= 0.60) return 'text-yellow-400';
  if (score >= 0.40) return 'text-orange-400';
  return 'text-red-400';
}
