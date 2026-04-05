/**
 * CISO View Model — Pure Transformation Layer
 *
 * Converts raw `/api/risk/summary/full` + `/api/overview/attack-surface-score`
 * responses into a CISO-friendly view model.
 *
 * SSOT: total_identities is the single source of truth.
 * Every metric derives from it and is expressed as count + percentage.
 *
 * No side effects, no API calls, no React hooks.
 */

import { formatRelativeTime } from './displayHelpers';

// ── Helpers ──────────────────────────────────────────────────

/** Round to 1 decimal: 4.2, 12.0, 0.3 */
function pct(count: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((count / total) * 1000) / 10;
}

/** Format percentage for display: "4.2%" or "<0.1%" */
export function fmtPct(value: number): string {
  if (value <= 0) return '0%';
  if (value < 0.1) return '<0.1%';
  return `${value}%`;
}

// ── Output: What the CISO dashboard renders ──────────────────

export interface CISOViewModel {
  status: 'low' | 'moderate' | 'high' | 'critical' | 'no_data';
  status_label: string;
  status_reason: string;
  trend: 'improving' | 'declining' | 'stable' | null;

  /** SSOT base metric — all percentages derive from this */
  total_identities: number;

  monitored: {
    identities: number;
    subscriptions: number;
  };

  /** (critical + high) / total — headline risk metric */
  risk_exposure: {
    count: number;
    pct: number;
    level: 'low' | 'moderate' | 'high' | 'critical';
    nav: string;
  };

  top_risk_drivers: Array<{
    title: string;
    count: number;
    pct: number;                // count / total_identities
    severity: 'critical' | 'high' | 'medium';
    narrative: string;          // includes count + pct
    nav: string;
  }>;

  blast_radius: {
    level: 'low' | 'medium' | 'high' | 'critical';
    identity_name: string | null;
    identity_id: number | null;
    identity_string_id: string | null;
    summary: string;
    consequences: string[];
  };

  immediate_actions: Array<{
    action: string;
    detail: string;
    nav: string;
  }>;

  business_impact: Array<{
    text: string;
    level: 'red' | 'yellow' | 'green';
  }>;

  system_assessment: string;

  snapshot: {
    risk_distribution: Array<{ level: string; count: number; pct: number; nav: string }>;
    identity_types: Array<{ type: string; count: number; pct: number }>;
  };

  last_updated: string;
  data_confidence: 'high' | 'medium' | 'low';
  confidence_reason: string;
  data_origin: 'tenant_scan' | 'no_data' | 'unknown';

  /** AGIRS composite score for badge display */
  agirs_display: {
    score: number | null;
    tier: string | null;
    nav: string;
  };

  /** Navigation URL for total identities count */
  total_identities_nav: string;

  /** Per-category identity breakdown for metric cards */
  identity_categories: Array<{
    label: string;
    count: number;
    pct: number;
    issues: string[];
    tag: { text: string; variant: string };
    accent: string;
    chart_color: string;
    nav: string;
  }>;

  /** Top dangerous identities for findings table */
  findings: Array<{
    name: string;
    sub: string;
    verdict: string;
    verdict_variant: string;
    blast_pct: number;
    blast_color: string;
    blast_label: string;
    action_label: string;
    nav: string;
    /** Pre-populated metadata for drawer (avoids blank name on load). */
    prefill: { display_name?: string; identity_category?: string; risk_level?: string; risk_score?: number };
  }>;
}

// ── Risk Driver Definitions ──────────────────────────────────

interface RiskDriverDef {
  title: string;
  severity: 'critical' | 'high' | 'medium';
  narrative: (n: number, p: number) => string;     // count, pct
  action: (n: number, p: number) => string;
  action_detail: string;
  nav: string;
}

const RISK_DRIVER_MAP: Record<string, RiskDriverDef> = {
  dormant_privileged: {
    title: 'Dormant Privileged Accounts',
    severity: 'critical',
    narrative: (n, p) => `${n} account${n !== 1 ? 's' : ''} (${fmtPct(p)} of all identities) with admin access ${n !== 1 ? 'have' : 'has'} been inactive for 90+ days — silent attack vectors with standing admin control.`,
    action: (n, p) => `Revoke admin roles from ${n} dormant account${n !== 1 ? 's' : ''} (${fmtPct(p)})`,
    action_detail: 'Eliminate standing privilege on inactive accounts immediately',
    nav: '/identities?metric=dormant&pillar=effective-privilege',
  },
  ghost_accounts: {
    title: 'Ghost Accounts',
    severity: 'critical',
    narrative: (n, p) => `${n} disabled or deleted account${n !== 1 ? 's' : ''} (${fmtPct(p)}) still hold${n === 1 ? 's' : ''} active RBAC roles — invisible backdoors into your environment.`,
    action: (n, p) => `Remove all RBAC from ${n} ghost account${n !== 1 ? 's' : ''} (${fmtPct(p)})`,
    action_detail: 'Strip role assignments from disabled/deleted identities',
    nav: '/identities?metric=ghost',
  },
  orphaned_spns: {
    title: 'Unowned Service Principals',
    severity: 'high',
    narrative: (n, p) => `${n} service principal${n !== 1 ? 's' : ''} (${fmtPct(p)}) operate${n === 1 ? 's' : ''} without an owner — unaccountable access with no human oversight.`,
    action: (n, p) => `Assign owners to ${n} orphaned service principal${n !== 1 ? 's' : ''} (${fmtPct(p)})`,
    action_detail: 'Enforce ownership policy before next compliance review',
    nav: '/identities?metric=unowned_nhi',
  },
  over_privileged: {
    title: 'Excess Privilege',
    severity: 'high',
    narrative: (n, p) => `${n} identit${n !== 1 ? 'ies' : 'y'} (${fmtPct(p)}) hold${n === 1 ? 's' : ''} Owner or Contributor roles not exercised in 90+ days — unnecessary blast radius.`,
    action: (n, p) => `Revoke unused roles from ${n} over-privileged identit${n !== 1 ? 'ies' : 'y'} (${fmtPct(p)})`,
    action_detail: 'Enforce least-privilege — strip roles with no recent activity',
    nav: '/identities?pillar=effective-privilege',
  },
  external_exposure: {
    title: 'External Guest Privilege',
    severity: 'high',
    narrative: (n, p) => `${n} guest${n !== 1 ? 's' : ''} (${fmtPct(p)}) from external organizations hold${n === 1 ? 's' : ''} privileged roles — supply-chain attack surface.`,
    action: (n, p) => `Restrict ${n} external guest account${n !== 1 ? 's' : ''} (${fmtPct(p)}) to time-bound access`,
    action_detail: 'Convert standing roles to PIM-eligible or revoke entirely',
    nav: '/identities?identity_category=guest&hasRoles=true',
  },
};

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2 };

const STATUS_LABELS: Record<string, string> = {
  low: 'LOW RISK',
  moderate: 'MODERATE RISK',
  high: 'HIGH RISK',
  critical: 'CRITICAL RISK',
  no_data: 'NO DATA',
};

// ── Empty View Model ─────────────────────────────────────────

export function buildEmptyCISOViewModel(): CISOViewModel {
  return {
    status: 'no_data',
    status_label: 'NO DATA',
    status_reason: 'No identity data available. Connect your Azure tenant and run discovery.',
    trend: null,
    total_identities: 0,
    monitored: { identities: 0, subscriptions: 0 },
    risk_exposure: { count: 0, pct: 0, level: 'low', nav: '/identities' },
    top_risk_drivers: [],
    blast_radius: {
      level: 'low',
      identity_name: null,
      identity_id: null,
      identity_string_id: null,
      summary: 'No blast radius data available.',
      consequences: [],
    },
    immediate_actions: [],
    business_impact: [],
    system_assessment: '',
    snapshot: { risk_distribution: [], identity_types: [] },
    last_updated: 'Never',
    data_confidence: 'low',
    confidence_reason: '',
    data_origin: 'no_data',
    agirs_display: { score: null, tier: null, nav: '/identities' },
    total_identities_nav: '/identities',
    identity_categories: [],
    findings: [],
  };
}

// ── Finding Helpers ──────────────────────────────────────────

function inferVerdict(identity: Record<string, any>): { verdict: string; variant: string; action: string } {
  const factors = (identity.key_risk_factors || []).join(' ').toLowerCase();
  const cat = identity.identity_category || '';

  if (factors.includes('orphan') || factors.includes('no owner') || factors.includes('unowned'))
    return { verdict: 'ORPHANED', variant: 'red', action: 'REVOKE' };
  if (factors.includes('ghost') || factors.includes('disabled'))
    return cat.includes('managed_identity')
      ? { verdict: 'GHOST_MSI', variant: 'purple', action: 'REVIEW' }
      : { verdict: 'GHOST', variant: 'red', action: 'REVOKE' };
  if (factors.includes('dormant') || factors.includes('stale') || factors.includes('inactive'))
    return { verdict: 'STALE', variant: 'amber', action: 'DISABLE' };
  if (factors.includes('over') || factors.includes('excessive'))
    return { verdict: 'AT_RISK', variant: 'orange', action: 'SCOPE' };
  if (factors.includes('federated') || factors.includes('credential'))
    return { verdict: 'CRED_RISK', variant: 'orange', action: 'FIX' };
  if (cat === 'guest')
    return { verdict: 'NEEDS_REVIEW', variant: 'teal', action: 'REVIEW' };
  return { verdict: 'AT_RISK', variant: 'orange', action: 'REVIEW' };
}

function buildFindingSub(identity: Record<string, any>): string {
  const catMap: Record<string, string> = {
    service_principal: 'SPN', managed_identity_system: 'System MSI',
    managed_identity_user: 'User MSI', human_user: 'Human',
    guest: 'Guest', microsoft_internal: 'Microsoft',
  };
  const cat = catMap[identity.identity_category] || identity.identity_category || 'Unknown';
  const factors = identity.key_risk_factors || [];
  const parts = [cat];
  if (factors.length > 0) parts.push(factors[0]);
  const subs = identity.subscription_count || 0;
  if (subs > 1) parts.push(`${subs} subs`);
  return parts.join(' · ');
}

function inferBlastLabel(identity: Record<string, any>): { label: string; color: string } {
  const subs = identity.subscription_count || 0;
  const rgs = identity.resource_group_count || 0;
  const score = identity.blast_radius_score || 0;
  const color = score >= 70 ? '#e8465a' : score >= 40 ? '#FF7216' : '#f59e0b';
  if (subs > 1) return { label: `Blast: ${subs} subs`, color };
  if (subs === 1) return { label: 'Blast: Sub-wide', color };
  if (rgs > 1) return { label: `Blast: ${rgs} RGs`, color };
  if (rgs === 1) return { label: 'Blast: RG scope', color };
  return { label: 'Blast: Limited', color };
}

function buildIdentityCategories(
  ic: Record<string, any>,
  rc: Record<string, any>,
  total: number,
): CISOViewModel['identity_categories'] {
  const cats: CISOViewModel['identity_categories'] = [];

  const spnCount = ic.service_principal || 0;
  const sysMsi = ic.managed_identity_system || 0;
  const userMsi = ic.managed_identity_user || 0;
  const guestCount = ic.guest || 0;
  // Human = Member users only (exclude guests to prevent double-counting)
  const rawHuman = ic.human || ic.human_user || 0;
  const humanCount = Math.max(0, rawHuman - guestCount);
  // Fallback: if no detailed NHI breakdown, estimate SPNs from nhi total
  const nhiTotal = ic.nhi || 0;
  const spnFinal = spnCount || Math.max(0, nhiTotal - sysMsi - userMsi);

  // Sanity check: segments must be mutually exclusive and sum to total
  const nhiSegment = spnFinal + sysMsi + userMsi;
  const segmentSum = humanCount + nhiSegment + guestCount;
  if (total > 0 && segmentSum !== total) {
    console.warn(
      `[AuditGraph] Donut segments (${segmentSum}) do not equal total (${total}). ` +
      `Check for overlapping identity type filters.`,
      { humanCount, rawHuman, guestCount, spnFinal, sysMsi, userMsi, nhiSegment, total },
    );
  }

  if (humanCount > 0) {
    const issues: string[] = [];
    if (rc.dormant_privileged) issues.push(`${rc.dormant_privileged} dormant privileged`);
    if (rc.ghost_accounts) issues.push(`${rc.ghost_accounts} ghost account${rc.ghost_accounts !== 1 ? 's' : ''}`);
    if (issues.length === 0) issues.push('No critical issues');
    const crit = (rc.dormant_privileged || 0) + (rc.ghost_accounts || 0);
    cats.push({
      label: 'Human Identities', count: humanCount, pct: pct(humanCount, total), issues,
      tag: crit > 0 ? { text: `${crit} critical`, variant: 'red' } : { text: 'Healthy', variant: 'green' },
      accent: '#e8465a', chart_color: '#4f9de8', nav: '/identities?identity_category=human_user',
    });
  }

  if (spnFinal > 0) {
    const issues: string[] = [];
    if (rc.orphaned_spns) issues.push(`${rc.orphaned_spns} orphaned`);
    if (rc.expired_credentials) issues.push(`${rc.expired_credentials} stale secret${rc.expired_credentials !== 1 ? 's' : ''}`);
    if (issues.length === 0) issues.push('No ownership issues');
    cats.push({
      label: 'Non-Human / SPNs', count: spnFinal, pct: pct(spnFinal, total), issues,
      tag: (rc.orphaned_spns || 0) > 0 ? { text: `${rc.orphaned_spns} at-risk`, variant: 'orange' } : { text: 'Healthy', variant: 'green' },
      accent: '#FF7216', chart_color: '#24A2A1', nav: '/workload-identities?type=spn',
    });
  }

  if (sysMsi > 0) {
    cats.push({
      label: 'System MSIs', count: sysMsi, pct: pct(sysMsi, total),
      issues: ['System-assigned identities', `${sysMsi} tracked`],
      tag: { text: `${sysMsi} tracked`, variant: 'teal' },
      accent: '#f59e0b', chart_color: '#FF7216', nav: '/workload-identities?type=managed_identity',
    });
  }

  if (userMsi > 0) {
    cats.push({
      label: 'User-Assigned MSIs', count: userMsi, pct: pct(userMsi, total),
      issues: ['User-assigned identities', `${userMsi} tracked`],
      tag: { text: 'Tracked', variant: 'green' },
      accent: '#22c55e', chart_color: '#f59e0b', nav: '/workload-identities?type=managed_identity',
    });
  }

  if (guestCount > 0) {
    const issues: string[] = [];
    if (rc.external_exposure) issues.push(`${rc.external_exposure} privileged guest${rc.external_exposure !== 1 ? 's' : ''}`);
    if (issues.length === 0) issues.push('No access issues');
    cats.push({
      label: 'Guest Users', count: guestCount, pct: pct(guestCount, total), issues,
      tag: (rc.external_exposure || 0) > 0 ? { text: `${rc.external_exposure} review needed`, variant: 'orange' } : { text: 'Healthy', variant: 'green' },
      accent: '#24A2A1', chart_color: '#a78bfa', nav: '/identities?identity_category=guest',
    });
  }

  return cats;
}

// ── Core Transformation ──────────────────────────────────────

export function buildCISOViewModel(
  riskData: Record<string, any> | null,
  attackData: Record<string, any> | null,
): CISOViewModel {
  if (!riskData && !attackData) return buildEmptyCISOViewModel();

  const vm = buildEmptyCISOViewModel();

  // ── Data origin ──
  const origin = riskData?.data_origin || 'unknown';
  vm.data_origin = origin === 'tenant_scan' ? 'tenant_scan' : origin === 'no_data' ? 'no_data' : 'unknown';

  // ── Last updated ──
  vm.last_updated = formatRelativeTime(attackData?.data_integrity?.last_scan);

  // ── SSOT: total_identities (customer only — excludes microsoft_internal) ──
  const rawIc = riskData?.identity_counts || {};
  // Merge guest count from attack_surface if identity_counts has none (avoids mutating API response)
  const ic: Record<string, any> = {
    ...rawIc,
    guest: rawIc.guest || riskData?.attack_surface?.external || 0,
  };
  const exp = riskData?.exposure || {};
  const total = ic.customer || ic.total || attackData?.total_identities || 0;
  vm.total_identities = total;
  vm.total_identities_nav = '/identities';
  vm.monitored.identities = total;
  vm.monitored.subscriptions = exp.subscriptions || 0;

  // ── Confidence + reasoning ──
  const confidence = attackData?.data_integrity?.confidence;
  vm.data_confidence = confidence === 'High' ? 'high' : confidence === 'Medium' ? 'medium' : 'low';
  vm.confidence_reason = buildConfidenceReason(vm);

  // ── Status (from AGIRS score — score itself is never exposed) ──
  const agirs = riskData?.agirs;
  if (agirs && agirs.score != null) {
    const s = agirs.score;
    if (s >= 80) vm.status = 'low';
    else if (s >= 60) vm.status = 'moderate';
    else if (s >= 40) vm.status = 'high';
    else vm.status = 'critical';
  } else {
    vm.status = total > 0 ? 'moderate' : 'no_data';
  }
  vm.status_label = STATUS_LABELS[vm.status];

  // ── Trend (from AGIRS delta — numeric delta never exposed) ──
  const delta = agirs?.delta;
  if (delta != null && delta !== 0) {
    vm.trend = delta > 0 ? 'improving' : 'declining';
  } else if (delta === 0) {
    vm.trend = 'stable';
  } else {
    vm.trend = null;
  }

  // ── Risk counts → drivers (with SSOT percentages) ──
  const rc = riskData?.risk_counts || {};
  const driverCounts: Record<string, number> = {
    dormant_privileged: rc.dormant_privileged || 0,
    ghost_accounts: rc.ghost_accounts || 0,
    orphaned_spns: rc.orphaned_spns || 0,
    over_privileged: rc.over_privileged || 0,
    external_exposure: rc.external_exposure || 0,
  };

  // Build status_reason from counts — now with percentages
  const criticalSum = (driverCounts.ghost_accounts) + (driverCounts.dormant_privileged);
  const highSum = (driverCounts.orphaned_spns) + (driverCounts.over_privileged) + (driverCounts.external_exposure);
  const criticalCategories = (driverCounts.ghost_accounts > 0 ? 1 : 0) + (driverCounts.dormant_privileged > 0 ? 1 : 0);
  const highCategories = (driverCounts.orphaned_spns > 0 ? 1 : 0) + (driverCounts.over_privileged > 0 ? 1 : 0) + (driverCounts.external_exposure > 0 ? 1 : 0);

  if (criticalCategories > 0 || highCategories > 0) {
    const totalExposed = criticalSum + highSum;
    const exposurePct = pct(totalExposed, total);
    const parts: string[] = [];
    if (criticalCategories > 0) parts.push(`${criticalCategories} critical`);
    if (highCategories > 0) parts.push(`${highCategories} high-risk`);
    vm.status_reason = `${parts.join(' and ')} identity exposure${criticalCategories + highCategories > 1 ? 's' : ''} detected — ${totalExposed} identities (${fmtPct(exposurePct)}) at risk`;
  } else if (total > 0) {
    vm.status_reason = `No significant identity exposures detected across ${total.toLocaleString()} monitored identities`;
  }

  // ── Risk exposure metric: (critical + high) / total ──
  const exposureCount = criticalSum + highSum;
  const exposurePctVal = pct(exposureCount, total);
  vm.risk_exposure = {
    count: exposureCount,
    pct: exposurePctVal,
    level: exposurePctVal >= 20 ? 'critical' : exposurePctVal >= 10 ? 'high' : exposurePctVal >= 5 ? 'moderate' : 'low',
    nav: '/identities?risk=critical,high',
  };

  // ── Top risk drivers (max 5, sorted by severity, with pct) ──
  const drivers: CISOViewModel['top_risk_drivers'] = [];
  for (const [key, count] of Object.entries(driverCounts)) {
    if (count <= 0) continue;
    const def = RISK_DRIVER_MAP[key];
    if (!def) continue;
    const p = pct(count, total);
    drivers.push({
      title: def.title,
      count,
      pct: p,
      severity: def.severity,
      narrative: def.narrative(count, p),
      nav: def.nav,
    });
  }
  drivers.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  vm.top_risk_drivers = drivers.slice(0, 5);

  // ── Immediate actions (max 4, derived 1:1 from drivers, with pct) ──
  vm.immediate_actions = vm.top_risk_drivers.slice(0, 4).map(driver => {
    const key = Object.keys(driverCounts).find(k => RISK_DRIVER_MAP[k]?.title === driver.title);
    const def = key ? RISK_DRIVER_MAP[key] : null;
    return {
      action: def ? def.action(driver.count, driver.pct) : `Address ${driver.count} (${fmtPct(driver.pct)}) ${driver.title.toLowerCase()}`,
      detail: def?.action_detail || '',
      nav: driver.nav,
    };
  });

  // ── Blast radius ──
  const dangerousIdentities = riskData?.dangerous_identities || [];
  const topIdentity = dangerousIdentities[0];

  if (topIdentity) {
    const subs = topIdentity.subscription_count ?? 0;
    const roles = topIdentity.total_role_count ?? 0;

    vm.blast_radius.level = (subs >= 5 || roles >= 20) ? 'critical'
      : (subs >= 2 || roles >= 10) ? 'high'
      : (subs >= 1 || roles >= 5) ? 'medium' : 'low';

    vm.blast_radius.identity_name = topIdentity.display_name || null;
    vm.blast_radius.identity_id = topIdentity.id || null;
    vm.blast_radius.identity_string_id = topIdentity.identity_id || null;

    vm.blast_radius.summary = topIdentity.display_name
      ? `If ${topIdentity.display_name} is compromised, an attacker could:`
      : 'If this identity is compromised, an attacker could:';

    vm.blast_radius.consequences = buildConsequences(topIdentity, exp);
  } else {
    vm.blast_radius.summary = 'No high-risk identities identified.';
  }

  // ── Business impact ──
  vm.business_impact = buildBusinessImpact(vm, exp);
  vm.system_assessment = buildSystemAssessment(vm);

  // ── Snapshot: risk distribution + identity types (with pct) ──
  // POSTURE CONTRACT: Use backend's actual risk_level counts so drawer
  // drill-down (?risk_level=X) returns exactly the displayed count.
  const rld = riskData?.risk_level_distribution || {};
  const snapCritical = rld.critical || 0;
  const snapHigh = rld.high || 0;
  const snapMedium = rld.medium || 0;
  const snapLow = rld.low || 0;

  const dist: CISOViewModel['snapshot']['risk_distribution'] = [];
  if (snapCritical > 0) dist.push({ level: 'critical', count: snapCritical, pct: pct(snapCritical, total), nav: '/identities?risk_level=critical' });
  if (snapHigh > 0) dist.push({ level: 'high', count: snapHigh, pct: pct(snapHigh, total), nav: '/identities?risk_level=high' });
  if (snapMedium > 0) dist.push({ level: 'medium', count: snapMedium, pct: pct(snapMedium, total), nav: '/identities?risk_level=medium' });
  if (snapLow > 0) dist.push({ level: 'low', count: snapLow, pct: pct(snapLow, total), nav: '/identities?risk_level=low' });
  vm.snapshot.risk_distribution = dist;

  const snapGuestCount = ic.guest || 0;
  const snapHumanCount = Math.max(0, (ic.human || 0) - snapGuestCount);
  const snapNhiCount = ic.nhi || 0;

  const types: CISOViewModel['snapshot']['identity_types'] = [];
  if (snapHumanCount > 0) types.push({ type: 'Human', count: snapHumanCount, pct: pct(snapHumanCount, total) });
  if (snapNhiCount > 0) types.push({ type: 'Non-Human', count: snapNhiCount, pct: pct(snapNhiCount, total) });
  if (snapGuestCount > 0) types.push({ type: 'Guest', count: snapGuestCount, pct: pct(snapGuestCount, total) });
  vm.snapshot.identity_types = types;

  // ── AGIRS badge display ──
  vm.agirs_display = {
    score: riskData?.agirs?.score ?? null,
    tier: riskData?.agirs?.tier ?? null,
    nav: '/identities',
  };

  // ── Identity categories (5 metric cards) ──
  vm.identity_categories = buildIdentityCategories(ic, rc, total);

  // ── Findings from dangerous identities ──
  const dangIdents = riskData?.dangerous_identities || [];
  vm.findings = dangIdents.slice(0, 6).map((di: Record<string, any>) => {
    const v = inferVerdict(di);
    const blast = inferBlastLabel(di);
    return {
      name: di.display_name || 'Unknown',
      sub: buildFindingSub(di),
      verdict: v.verdict,
      verdict_variant: v.variant,
      blast_pct: di.blast_radius_score || 0,
      blast_color: blast.color,
      blast_label: blast.label,
      action_label: v.action,
      nav: `/identities/${di.identity_id || di.id}`,
      prefill: {
        display_name: di.display_name || undefined,
        identity_category: di.identity_category || undefined,
        risk_level: di.risk_level || undefined,
        risk_score: di.risk_score ?? undefined,
      },
    };
  });

  return vm;
}

// ── Confidence Reason Builder ────────────────────────────────

function buildConfidenceReason(vm: CISOViewModel): string {
  const total = vm.total_identities;
  const subs = vm.monitored.subscriptions;
  if (total === 0) return 'No identity data ingested — connect a cloud tenant to begin assessment.';

  if (vm.data_confidence === 'high') {
    return `Full scan completed across ${total.toLocaleString()} identities and ${subs} subscription${subs !== 1 ? 's' : ''} — all data sources responded.`;
  }
  if (vm.data_confidence === 'medium') {
    return `Partial scan coverage — some data sources may not have responded. ${total.toLocaleString()} identities assessed.`;
  }
  return `Limited scan data available — results may be incomplete. ${total.toLocaleString()} identities assessed from ${subs} subscription${subs !== 1 ? 's' : ''}.`;
}

// ── Finding → Risk Driver Grouping ──────────────────────────

export interface Finding {
  severity: string;
  rule_type: string;
  [key: string]: unknown;
}

export interface RiskDriverGroup {
  title: string;
  count: number;
  severity: string;
}

const FINDING_SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

const CATEGORY_TITLES: Record<string, string> = {
  high_privilege_identity: 'High Privilege Identity',
  disabled_account_active_role: 'Ghost Account with Active Roles',
  orphaned_spn: 'Orphaned Service Principal',
  dormant_privileged: 'Dormant Privileged Account',
  over_privileged: 'Over-Privileged Identities',
  expired_credential: 'Expired Credential',
  zombie_identity: 'Zombie Persona',
  privilege_escalation: 'Privilege Escalation Risk',
  nhi_security: 'Non-Human Identity Risk',
  dormant_identity: 'Dormant Identity',
  excessive_permissions: 'Excessive Permissions',
  credential_risk: 'Credential Risk',
};

export function groupFindingsIntoDrivers(findings: Finding[]): RiskDriverGroup[] {
  const groups = new Map<string, { count: number; severity: string }>();

  for (const f of findings) {
    const cat = f.rule_type || 'unknown';
    const existing = groups.get(cat);
    if (!existing) {
      groups.set(cat, { count: 1, severity: f.severity || 'low' });
    } else {
      existing.count++;
      const cur = FINDING_SEVERITY_ORDER[existing.severity] ?? 9;
      const next = FINDING_SEVERITY_ORDER[f.severity] ?? 9;
      if (next < cur) existing.severity = f.severity;
    }
  }

  const result: RiskDriverGroup[] = [];
  groups.forEach(({ count, severity }, cat) => {
    result.push({
      title: CATEGORY_TITLES[cat] || cat.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
      count,
      severity,
    });
  });

  result.sort((a, b) => {
    const sevDiff = (FINDING_SEVERITY_ORDER[a.severity] ?? 9) - (FINDING_SEVERITY_ORDER[b.severity] ?? 9);
    return sevDiff !== 0 ? sevDiff : b.count - a.count;
  });

  return result.slice(0, 5);
}

// ── Finding → Action Statements ──────────────────────────────

const ACTION_TEMPLATES: Record<string, (n: number) => string> = {
  dormant_privileged:          (n) => `Review ${n} dormant privileged account${n !== 1 ? 's' : ''}`,
  ghost_accounts:              (n) => `Remove roles from ${n} ghost account${n !== 1 ? 's' : ''}`,
  disabled_account_active_role:(n) => `Remove roles from ${n} disabled account${n !== 1 ? 's' : ''}`,
  orphaned_spn:                (n) => `Assign owners to ${n} orphaned service principal${n !== 1 ? 's' : ''}`,
  over_privileged:             (n) => `Remove unused roles from ${n} identit${n !== 1 ? 'ies' : 'y'}`,
  external_exposure:           (n) => `Review ${n} external guest account${n !== 1 ? 's' : ''}`,
  expired_credential:          (n) => `Rotate ${n} expired credential${n !== 1 ? 's' : ''}`,
  zombie_identity:             (n) => `Investigate ${n} zombie identit${n !== 1 ? 'ies' : 'y'}`,
  privilege_escalation:        (n) => `Mitigate ${n} privilege escalation risk${n !== 1 ? 's' : ''}`,
  nhi_security:                (n) => `Remediate ${n} non-human identity risk${n !== 1 ? 's' : ''}`,
  dormant_identity:            (n) => `Review ${n} dormant identit${n !== 1 ? 'ies' : 'y'}`,
  excessive_permissions:       (n) => `Reduce permissions on ${n} identit${n !== 1 ? 'ies' : 'y'}`,
  credential_risk:             (n) => `Address ${n} credential risk${n !== 1 ? 's' : ''}`,
  high_privilege_identity:     (n) => `Review ${n} high-privilege identit${n !== 1 ? 'ies' : 'y'}`,
};

export function buildActionStatements(findings: Finding[]): string[] {
  const groups = new Map<string, { count: number; severity: string }>();

  for (const f of findings) {
    const cat = f.rule_type || 'unknown';
    const existing = groups.get(cat);
    if (!existing) {
      groups.set(cat, { count: 1, severity: f.severity || 'low' });
    } else {
      existing.count++;
      const cur = FINDING_SEVERITY_ORDER[existing.severity] ?? 9;
      const next = FINDING_SEVERITY_ORDER[f.severity] ?? 9;
      if (next < cur) existing.severity = f.severity;
    }
  }

  const entries: Array<[string, { count: number; severity: string }]> = [];
  groups.forEach((val, key) => entries.push([key, val]));

  entries.sort((a, b) => {
    const sevDiff = (FINDING_SEVERITY_ORDER[a[1].severity] ?? 9) - (FINDING_SEVERITY_ORDER[b[1].severity] ?? 9);
    return sevDiff !== 0 ? sevDiff : b[1].count - a[1].count;
  });

  return entries.slice(0, 5).map(([cat, { count }]) => {
    const template = ACTION_TEMPLATES[cat];
    if (template) return template(count);
    const label = CATEGORY_TITLES[cat] || cat.replace(/_/g, ' ');
    return `Address ${count} ${label.toLowerCase()} finding${count !== 1 ? 's' : ''}`;
  });
}

// ── Blast Radius Summary ─────────────────────────────────────

export interface BlastRadiusInput {
  role_count: number;
  subscription_count: number;
  scope_summary: string[];
}

const HIGH_PRIVILEGE_ROLES = /^(owner|contributor|user access administrator|global administrator|privileged role administrator)$/i;

export function summarizeBlastRadius(input: BlastRadiusInput): string {
  const { role_count, subscription_count, scope_summary } = input;

  if (role_count === 0 && subscription_count === 0) {
    return 'This identity has no significant blast radius.';
  }

  const privileged = (scope_summary || []).filter(r => HIGH_PRIVILEGE_ROLES.test(r));

  const parts: string[] = [];

  if (subscription_count > 0) {
    parts.push(`access ${subscription_count} subscription${subscription_count !== 1 ? 's' : ''}`);
  }

  if (role_count > 0) {
    let rolePart = `${role_count} role${role_count !== 1 ? 's' : ''}`;
    if (privileged.length > 0) {
      rolePart += ` including ${privileged.join(', ')}`;
    }
    parts.push(rolePart);
  }

  return `If compromised, this identity can ${parts.join(' and ')}.`;
}

// ── Consequence Builder ──────────────────────────────────────

function buildConsequences(
  top: Record<string, any>,
  exposure: Record<string, any>,
): string[] {
  const lines: string[] = [];

  const subs = top.subscription_count || 0;
  const totalSubs = exposure.subscriptions || 0;
  if (subs > 0) {
    lines.push(`Control ${subs} of ${totalSubs} Azure subscription${totalSubs !== 1 ? 's' : ''}`);
  }

  const kvs = exposure.key_vaults || 0;
  if (kvs > 0) {
    lines.push(`Access ${kvs} Key Vault${kvs !== 1 ? 's' : ''} (secrets, certificates, keys)`);
  }

  const hasIAM = top.key_risk_factors?.some((f: string) =>
    /owner|user access|privileged role/i.test(f)
  );
  if (hasIAM) {
    lines.push('Modify IAM — grant themselves persistent access');
  }

  const sa = exposure.storage_accounts || 0;
  if (sa > 0) {
    lines.push(`Exfiltrate data from ${sa} storage account${sa !== 1 ? 's' : ''}`);
  }

  const rgs = top.resource_group_count || 0;
  if (rgs > 0 && lines.length < 5) {
    lines.push(`Reach ${rgs} resource group${rgs !== 1 ? 's' : ''}`);
  }

  return lines;
}

// ── System Assessment Builder ────────────────────────────────

function buildSystemAssessment(vm: CISOViewModel): string {
  if (vm.status === 'no_data') return '';

  const parts: string[] = [];
  const driverCount = vm.top_risk_drivers.length;
  const criticals = vm.top_risk_drivers.filter(d => d.severity === 'critical');
  const totalExposed = vm.risk_exposure.count;
  const exposurePct = vm.risk_exposure.pct;

  // Sentence 1: Overall judgment with percentage
  if (vm.status === 'critical') {
    parts.push(`${fmtPct(exposurePct)} of identities (${totalExposed} of ${vm.total_identities.toLocaleString()}) have critical or high-risk exposures across ${driverCount} risk categories — immediate remediation is required.`);
  } else if (vm.status === 'high') {
    parts.push(`${totalExposed} identities (${fmtPct(exposurePct)}) across ${driverCount} risk area${driverCount !== 1 ? 's' : ''} require attention before the next compliance review.`);
  } else if (vm.status === 'moderate') {
    parts.push(`Identity posture is acceptable with ${fmtPct(exposurePct)} exposure rate${driverCount > 0 ? `, but ${driverCount} risk area${driverCount !== 1 ? 's' : ''} remain${driverCount === 1 ? 's' : ''} open` : ''}.`);
  } else {
    parts.push(`Identity security posture is strong — ${fmtPct(exposurePct)} exposure rate across ${vm.total_identities.toLocaleString()} identities.`);
  }

  // Sentence 2: Priority recommendation with percentage
  if (criticals.length > 0) {
    const top = criticals[0];
    parts.push(`Priority: ${top.title.toLowerCase()} — ${top.count} (${fmtPct(top.pct)}) represent the highest-leverage remediation opportunity.`);
  } else if (driverCount > 0) {
    const top = vm.top_risk_drivers[0];
    parts.push(`Start with ${top.title.toLowerCase()} — ${top.count} (${fmtPct(top.pct)}) for the greatest risk reduction.`);
  }

  // Sentence 3: Blast radius context
  if (vm.blast_radius.identity_name && (vm.blast_radius.level === 'critical' || vm.blast_radius.level === 'high')) {
    parts.push(`Worst-case blast radius is ${vm.blast_radius.level}: ${vm.blast_radius.identity_name} can reach ${vm.blast_radius.consequences.length} attack surfaces if compromised.`);
  }

  return parts.join(' ');
}

// ── Business Impact Builder ─────────────────────────────────

function buildBusinessImpact(
  vm: CISOViewModel,
  exposure: Record<string, any>,
): CISOViewModel['business_impact'] {
  const lines: CISOViewModel['business_impact'] = [];
  const total = vm.total_identities;

  // 1. Overall posture with exposure rate
  if (vm.status === 'critical' || vm.status === 'high') {
    lines.push({
      text: `${fmtPct(vm.risk_exposure.pct)} of your identity estate (${vm.risk_exposure.count} of ${total.toLocaleString()}) has critical or high-risk exposures that could be exploited in a breach.`,
      level: 'red',
    });
  } else if (total > 0) {
    lines.push({
      text: `Identity exposure rate is ${fmtPct(vm.risk_exposure.pct)} across ${total.toLocaleString()} monitored identities — ${vm.status === 'low' ? 'well within acceptable thresholds' : 'within acceptable range but monitoring recommended'}.`,
      level: vm.status === 'low' ? 'green' : 'yellow',
    });
  }

  // 2. Most dangerous driver with percentage
  const criticalDrivers = vm.top_risk_drivers.filter(d => d.severity === 'critical');
  if (criticalDrivers.length > 0) {
    const d = criticalDrivers[0];
    lines.push({
      text: `${d.count} identities (${fmtPct(d.pct)}) classified as ${d.title.toLowerCase()} — ${d.severity} severity.`,
      level: 'red',
    });
  }

  // 3. Blast radius as business consequence
  if (vm.blast_radius.identity_name && vm.blast_radius.consequences.length > 0) {
    const subs = exposure.subscriptions || 0;
    const name = vm.blast_radius.identity_name;
    const text = subs > 1
      ? `A single compromised identity (${name}) could provide access across ${subs} Azure subscriptions — enough to disrupt production workloads.`
      : `If ${name} is compromised, an attacker could ${vm.blast_radius.consequences[0].charAt(0).toLowerCase()}${vm.blast_radius.consequences[0].slice(1)}.`;
    lines.push({ text, level: vm.blast_radius.level === 'critical' ? 'red' : 'yellow' });
  }

  // 4. External/guest exposure with percentage
  const guestDriver = vm.top_risk_drivers.find(d => d.title === 'External Guest Privilege');
  if (guestDriver) {
    lines.push({
      text: `${guestDriver.count} external guests (${fmtPct(guestDriver.pct)}) hold privileged access — a supply-chain risk if their accounts are compromised.`,
      level: 'yellow',
    });
  }

  return lines.slice(0, 4);
}
