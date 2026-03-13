import {
  TenantData,
  PillarData,
  RiskDriver,
  Remediation,
  SystemAction,
  ComplianceControl,
  Framework,
  GovMetric,
  PolicyGap,
  getTier,
  getGrade,
  getTimeAgo,
  getMaturityLevel,
  detailToString,
  detailToDrilldown,
  PILLAR_NAMES,
  PILLAR_ORDER,
} from './overview-shared';

export async function fetchJson(url: string) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

export async function fetchTenantData(wc: (u: string) => string = u => u): Promise<TenantData> {
  const [as, stats, comp, trends, posture, remed, idSummary, settings] = await Promise.all([
    fetchJson(wc('/api/overview/attack-surface-score')).catch(() => null),
    fetchJson(wc('/api/stats')).catch(() => null),
    fetchJson(wc('/api/compliance/intelligence')).catch(() => null),
    fetchJson(wc('/api/trends?limit=30')).catch(() => null),
    fetchJson(wc('/api/dashboard/posture')).catch(() => null),
    fetchJson(wc('/api/remediation-summary')).catch(() => null),
    fetchJson(wc('/api/identity-summary')).catch(() => null),
    fetchJson(wc('/api/settings')).catch(() => null),
  ]);

  const lr = stats?.latest_run || {};
  const pr = stats?.previous_run || {};
  const gov = as?.governance || {};
  const di = as?.data_integrity || {};
  const we = as?.workload_exposure || {};
  const ao = as?.attack_opportunities || {};
  const nhi = as?.nhi_breakdown || {};
  const monitored = idSummary?.monitored_resources || {};

  const totalIds = lr.total_identities || as?.total_identities || 0;
  const critCount = lr.critical_count || 0;
  const highCount = lr.high_count || 0;
  const medCount = lr.medium_count || 0;
  const lowCount = Math.max(0, totalIds - critCount - highCount - medCount);

  // Single source of truth: 6-pillar attack surface score (higher = worse risk).
  // Invert to posture (higher = better). If attack-surface API unavailable, derive
  // from posture endpoint. No fabricated scores — show 0 and flag insufficientData.
  const postureScore = (() => {
    if (as?.score != null) return Math.round((100 - as.score) * 10) / 10;
    const fallback = posture?.posture_score;
    if (fallback != null) return fallback;
    return 0; // No data available — insufficientData flag will show "Awaiting Data" state
  })();
  const insufficientData = as?.score == null && posture?.posture_score == null;
  const tier = insufficientData ? 'No Data' : getTier(postureScore);
  const grade = insufficientData ? '—' : getGrade(postureScore);
  const prevPosture: number | null = posture?.previous_posture_score != null
    ? posture.previous_posture_score
    : (stats?.previous_run ? (100 - (stats.previous_run.avg_risk_score || 0)) : null);
  const delta30d = prevPosture != null ? Math.round((postureScore - prevPosture) * 10) / 10 : null;

  const pillars: PillarData[] = PILLAR_ORDER.map(k => {
    const p = as?.pillars?.[k] || { score: 0, weight: 0, detail: {} };
    return {
      name: PILLAR_NAMES[k] || k,
      score: p.score || 0,
      weight: p.weight || 0,
      detail: detailToString(k, p.detail || {}),
      drilldown: detailToDrilldown(k, p.detail || {}),
    };
  });

  // Use API value when available; derive from pillar weights only when API provides weights
  const potentialGain = remed?.potential_gain ?? Math.round(pillars.reduce((s, p) => s + (p.score > 50 && p.weight > 0 ? p.weight * 0.3 : 0), 0) * 10) / 10;

  const history: { day: number; score: number }[] = [];
  if (Array.isArray(trends)) {
    trends.slice(-30).forEach((t: any, i: number) => {
      history.push({ day: i + 1, score: t.posture_score ?? (100 - (t.avg_risk_score || 50)) });
    });
  }
  // No fabricated trend data — history stays empty if no real data exists.
  // The chart component renders an empty state when history.length === 0.

  const topDrivers: RiskDriver[] = [];
  const sortedPillars = [...pillars].sort((a, b) => b.score - a.score);
  for (const p of sortedPillars.slice(0, 5)) {
    if (p.score > 10) {
      const imp: RiskDriver['impact'] = p.score >= 80 ? 'critical' : p.score >= 50 ? 'high' : p.score >= 20 ? 'medium' : 'low';
      topDrivers.push({ label: `${p.detail} — ${p.name} at ${p.score}%`, impact: imp, pillar: p.name });
    }
  }
  if (ao.privileged_nhi_count) topDrivers.push({ label: `${ao.privileged_nhi_count} privileged non-human identities`, impact: 'medium', pillar: 'Privilege' });

  const remedList: Remediation[] = [];
  const remedItems = remed?.items || remed?.remediations || [];
  if (Array.isArray(remedItems) && remedItems.length > 0) {
    remedItems.forEach((r: any, i: number) => {
      const comp = r.complexity || (r.gain > 5 ? 'MEDIUM' : 'LOW');
      const rType = r.type || 'identity-remediation';
      remedList.push({
        rank: i + 1, action: r.action || r.label || `Action ${i + 1}`,
        description: r.description || '', gain: r.gain || r.score_impact || 0,
        complexity: comp, affectedIds: r.affected_ids || r.affectedIds || 0,
        confidence: r.confidence ?? null, estimatedDays: r.estimated_days ?? null,
        automation: r.automation || null,
        blastRadius: r.blast_radius || { identities: r.affected_ids || 0, subscriptions: 0, workloads: 0 },
        rollbackSafety: r.rollback_safety || null,
        impactsProduction: r.impacts_production ?? (r.blast_radius?.workloads > 0),
        type: rType === 'system-action' || rType === 'configuration' ? rType : 'identity-remediation',
      });
    });
  }

  // Derive remediation items from pillar data when API doesn't return items
  if (!remedList.length && as?.pillars) {
    const pillarRemediations: { action: string; description: string; gain: number; complexity: 'LOW' | 'MEDIUM' | 'HIGH'; affectedIds: number; nav: string }[] = [];
    const pils = as.pillars;
    if (pils.effective_privilege?.score > 15) {
      const d = pils.effective_privilege.detail || {};
      const w = pils.effective_privilege.weight || 0;
      pillarRemediations.push({
        action: 'Reduce over-privileged identities',
        description: `${d.t0t1 || 0} identities hold T0/T1 privileges — review and remove unnecessary Global Admin, Owner, and Contributor roles.`,
        gain: w > 0 ? Math.round(pils.effective_privilege.score * 0.3 * w / 10) : 0,
        complexity: pils.effective_privilege.score > 60 ? 'HIGH' : 'MEDIUM',
        affectedIds: d.t0t1 || 0, nav: '/identities?risk_level=critical',
      });
    }
    if (pils.credential_risk?.score > 15) {
      const d = pils.credential_risk.detail || {};
      const w = pils.credential_risk.weight || 0;
      const badCreds = (d.expired || 0) + (d.expiring || 0);
      pillarRemediations.push({
        action: 'Rotate expired & expiring credentials',
        description: `${badCreds} credentials are expired or expiring within 30 days — rotate secrets and certificates immediately.`,
        gain: w > 0 ? Math.round(pils.credential_risk.score * 0.3 * w / 10) : 0,
        complexity: 'LOW',
        affectedIds: badCreds, nav: '/workload-identities',
      });
    }
    if (pils.usage_dormancy?.score > 15) {
      const d = pils.usage_dormancy.detail || {};
      const w = pils.usage_dormancy.weight || 0;
      pillarRemediations.push({
        action: 'Disable dormant identities',
        description: `${d.dormant || 0} identities are stale or never used — disable or remove to reduce attack surface.`,
        gain: w > 0 ? Math.round(pils.usage_dormancy.score * 0.3 * w / 10) : 0,
        complexity: 'LOW',
        affectedIds: d.dormant || 0, nav: '/identities?activity_status=stale',
      });
    }
    if (pils.ownership_governance?.score > 15) {
      const d = pils.ownership_governance.detail || {};
      const w = pils.ownership_governance.weight || 0;
      pillarRemediations.push({
        action: 'Assign owners to unowned service principals',
        description: `${d.unowned_spns || 0} of ${d.total_spns || 0} service principals lack owners — assign accountability for each.`,
        gain: w > 0 ? Math.round(pils.ownership_governance.score * 0.3 * w / 10) : 0,
        complexity: 'LOW',
        affectedIds: d.unowned_spns || 0, nav: '/workload-identities',
      });
    }
    if (pils.trust_federation?.score > 15) {
      const d = pils.trust_federation.detail || {};
      const w = pils.trust_federation.weight || 0;
      pillarRemediations.push({
        action: 'Review guest & external privileged access',
        description: `${d.guest_with_roles || 0} guest identities hold privileged roles — audit and restrict external access.`,
        gain: w > 0 ? Math.round(pils.trust_federation.score * 0.3 * w / 10) : 0,
        complexity: 'MEDIUM',
        affectedIds: d.guest_with_roles || 0, nav: '/identities?identity_category=guest',
      });
    }
    if (pils.external_exposure?.score > 15) {
      const d = pils.external_exposure.detail || {};
      const w = pils.external_exposure.weight || 0;
      pillarRemediations.push({
        action: 'Scope down tenant-wide permissions',
        description: `${d.tenant_scope || 0} identities have tenant-wide scope — apply least-privilege at subscription or resource group level.`,
        gain: w > 0 ? Math.round(pils.external_exposure.score * 0.3 * w / 10) : 0,
        complexity: 'HIGH',
        affectedIds: d.tenant_scope || 0, nav: '/identities',
      });
    }
    // Sort by gain desc and assign ranks
    pillarRemediations.sort((a, b) => b.gain - a.gain);
    pillarRemediations.forEach((pr, i) => {
      remedList.push({
        rank: i + 1, action: pr.action, description: pr.description, gain: pr.gain,
        complexity: pr.complexity, affectedIds: pr.affectedIds,
        estimatedDays: null, automation: null,
        blastRadius: { identities: pr.affectedIds, subscriptions: 0, workloads: 0 },
        rollbackSafety: null,
        impactsProduction: false, type: 'identity-remediation',
      });
    });
  }

  // System actions — always present; "Capture Snapshot" is a system action, never a ranked remediation
  const systemActions: SystemAction[] = [
    { id: 'run-scan', label: 'Capture Snapshot', status: lr.completed_at ? 'completed' : 'pending', description: lr.completed_at ? `Last snapshot: ${getTimeAgo(lr.completed_at)}` : 'No snapshot captured yet' },
  ];

  const compFrameworks: Record<string, Framework[]> = {};
  if (comp?.frameworks) {
    Object.entries(comp.frameworks as Record<string, any>).forEach(([fwKey, fw]) => {
      const cat = fw.category === 'privacy' ? 'Privacy' : fw.tier === 'core' ? 'Core Governance' : fw.tier === 'benchmark' ? 'Benchmark' : 'Industry';
      if (!compFrameworks[cat]) compFrameworks[cat] = [];
      const passCount = fw.pass_count || 0;
      const totalCount = fw.total_controls || 1;
      const controls: ComplianceControl[] = (fw.controls || []).map((c: any) => ({
        controlId: c.control_id || '', name: c.name || '',
        status: c.status || 'pass', severity: c.severity || 'medium',
        metric: c.metric || '', value: c.value ?? 0, passThreshold: c.pass_threshold || '',
        detail: c.detail || '', drilldownUrl: c.drilldown_url || null, weight: c.weight || 5,
        evidenceIdentities: c.evidence_identities || [], evidenceCount: c.evidence_count || 0,
      }));
      compFrameworks[cat].push({
        name: fw.name || fw.short_name || 'Unknown',
        passed: passCount, total: totalCount,
        pct: Math.round((passCount / totalCount) * 100),
        failingIdentities: fw.affected_entities || fw.failing_identities || 0,
        controlMappingSource: fw.scope_label || fw.control_mapping_source || `Mapped to: identity access controls`,
        coverageTrend30d: fw.coverage_trend_30d ?? null,
        controls, key: fwKey, category: cat,
      });
    });
  }
  // No dummy framework — empty state handled by UI components

  const accessReviewsDone = gov.access_reviews_done || 0;
  const accessReviewsConfigured = accessReviewsDone > 0;
  // Access reviews: show privileged_under_review_pct when reviews exist, 0 otherwise
  const accessReviewPct = accessReviewsConfigured
    ? Math.round(gov.privileged_under_review_pct || 0)
    : 0;

  const govMetrics: GovMetric[] = [
    { label: 'Ownership Coverage', value: Math.round(gov.ownership_coverage_pct || 0), target: 80, icon: '\uD83D\uDC64', trend30d: null, configured: gov.ownership_coverage_pct != null && gov.ownership_coverage_pct > 0 },
    { label: 'PIM Coverage', value: Math.round(gov.pim_adoption_pct || 0), target: 90, icon: '\uD83D\uDD10', trend30d: null, configured: gov.pim_adoption_pct != null && gov.pim_adoption_pct > 0 },
    { label: 'Privileged Under Review', value: Math.round(gov.privileged_under_review_pct || 0), target: 100, icon: '\uD83D\uDCCB', trend30d: null, configured: gov.privileged_under_review_pct != null && gov.privileged_under_review_pct > 0 },
    { label: 'Access Reviews Done', value: accessReviewPct, target: 95, icon: '\u2713', trend30d: null, configured: accessReviewsConfigured },
  ];
  const effectivenessConfigured = govMetrics.some(m => m.configured);

  const policyGaps: { preventiveFailures: PolicyGap[]; operationalGaps: PolicyGap[] } = {
    preventiveFailures: [], operationalGaps: [],
  };
  if (gov.pim_adoption_pct != null && gov.pim_adoption_pct < 50) policyGaps.preventiveFailures.push({ label: 'Privilege outside PIM', count: ao.privileged_nhi_count || 0, severity: 'critical' });
  if (gov.ownership_coverage_pct != null && gov.ownership_coverage_pct < 50) policyGaps.operationalGaps.push({ label: `Ownership coverage at ${Math.round(gov.ownership_coverage_pct)}%`, count: we.flags?.orphaned || 0, severity: 'high' });
  if (ao.dormant_privileged_count) policyGaps.operationalGaps.push({ label: 'Dormant privileged accounts active', count: ao.dormant_privileged_count, severity: 'medium' });

  // Effectiveness: only average configured metrics to avoid dilution from unconfigured ones
  const configuredMetrics = govMetrics.filter(m => m.configured);
  const effScore = configuredMetrics.length > 0
    ? Math.round(configuredMetrics.reduce((s, m) => s + m.value, 0) / configuredMetrics.length)
    : 0;

  const lifecycleDist = we.lifecycle_distribution || {};
  const blindCount = lifecycleDist.blind || 0;
  // Source of truth: /api/identity-summary → monitored_resources.azure.subscriptions
  const azureSubs = monitored.azure?.subscriptions || 0;
  const awsAccounts = monitored.aws?.accounts || 0;
  const gcpProjects = monitored.gcp?.projects || 0;
  const subs = azureSubs + awsAccounts + gcpProjects || 0;

  return {
    insufficientData,
    tenant: {
      id: di.organization_id || di.tenant_id || 'unknown', name: di.org_name || di.tenant_name || 'Organization',
      cloud: [azureSubs > 0 && 'Azure', awsAccounts > 0 && 'AWS', gcpProjects > 0 && 'GCP'].filter(Boolean).join(' + ') || 'Azure',
      subscriptions: subs,
      lastScan: di.last_scan || lr.completed_at || new Date().toISOString(),
      scanDuration: di.scan_duration_seconds || 0, scanCompleteness: di.data_completeness_pct || 100,
      scanConfidence: di.confidence || 'Medium',
      sources: [
        ...(azureSubs > 0 ? ['Azure RBAC', 'Entra ID', 'Graph API'] : []),
        ...(awsAccounts > 0 ? ['AWS IAM'] : []),
        ...(gcpProjects > 0 ? ['GCP IAM'] : []),
      ],
      confidenceModelBasis: `Based on ${di.confidence || 'trend'} confidence — ${di.data_completeness_pct || 100}% data completeness`,
      scanCoverage: subs > 0 ? Math.round((di.data_completeness_pct || 100)) : 0,
      dataCompleteness: Math.round(di.data_completeness_pct || 100),
      lastUpdatedAgo: di.last_scan ? getTimeAgo(di.last_scan) : 'unknown',
      isolationGuarantee: 'Isolated dataset \u2022 No cross-tenant visibility',
      organizationName: settings?.settings?.org_name || di.organization_name || di.org_name || 'Organization',
      organizationLogo: di.organization_logo || null,
    },
    scoringMethodology: {
      url: 'https://docs.auditgraph.ai/scoring-methodology',
      label: 'View scoring methodology',
      summary: '6-pillar weighted model: Effective Privilege (30%), Credential Risk (20%), Trust & Federation (20%), Usage Dormancy (10%), Ownership Governance (10%), External Exposure (10%). Each pillar scored 0-100 where higher = more risk.',
    },
    scoringContent: {
      overview: 'AuditGraph computes a composite Identity Attack Surface Score from six weighted security pillars. Each pillar is scored 0\u2013100 where higher values indicate greater risk exposure.',
      scoreDirection: 'Score scale: 0 = no risk \u00B7 100 = maximum risk',
      pillars: [
        { name: 'Effective Privilege', weight: 30, description: 'Measures tier-0/tier-1 role density, standing admin access, and blast radius of privileged identities.' },
        { name: 'Credential Risk', weight: 20, description: 'Tracks expired credentials, soon-to-expire secrets, and rotation compliance across SPNs and app registrations.' },
        { name: 'Trust & Federation', weight: 20, description: 'Evaluates guest identities with privileged roles, external federation configurations, and cross-tenant trust chains.' },
        { name: 'Usage Dormancy', weight: 10, description: 'Identifies identities inactive >30 days that retain active role assignments \u2014 zombie accounts with live access.' },
        { name: 'Ownership Governance', weight: 10, description: 'Measures orphaned SPN coverage, attestation freshness, and ownership assignment completeness.' },
        { name: 'External Exposure', weight: 10, description: 'Detects identities with tenant-wide scope, multi-subscription access at Contributor+, and public-facing service principals.' },
      ],
      compositeFormula: 'Composite = \u03A3(pillar_score \u00D7 pillar_weight) / 100',
      tierThresholds: [
        { tier: 'Resilient', range: '81\u2013100', description: 'Strong posture across all pillars. Minimal attack surface.' },
        { tier: 'Controlled', range: '61\u201380', description: 'Acceptable posture with identified improvement areas.' },
        { tier: 'Elevated', range: '41\u201360', description: 'Significant gaps requiring remediation within 30 days.' },
        { tier: 'Critical', range: '0\u201340', description: 'Immediate action required. High blast radius exposure.' },
      ],
    },
    executiveSummary: {
      riskNarrative: as?.ciso_summary || `Identity posture is ${tier.toLowerCase()} with a score of ${postureScore.toFixed(1)}/100.`,
      businessExposure: { identities: totalIds, subscriptions: subs, productionWorkloads: we.total || 0, totalProductionWorkloads: we.total || 0 },
    },
    identities: {
      total: totalIds, critical: critCount, high: highCount, medium: medCount, low: lowCount,
      byType: {
        users: idSummary?.categories?.human_user?.total ?? nhi.human ?? 0,
        servicePrincipals: idSummary?.categories?.service_principal?.total ?? nhi.service_principal ?? 0,
        managedIdentities: (idSummary?.categories?.managed_identity_system?.total ?? nhi.managed_identity_system ?? 0) + (idSummary?.categories?.managed_identity_user?.total ?? nhi.managed_identity_user ?? 0),
        workloadIdentities: nhi.nhi_total || 0,
        crossTenant: idSummary?.categories?.guest?.total ?? nhi.guest ?? 0,
      },
      movement: { previousTotal: pr.total_identities || 0, newIdentities: lr.new_identities || 0, removedIdentities: lr.removed_identities || 0 },
    },
    riskScore: (() => {
      const remedGain = remedList.filter(r => r.type === 'identity-remediation').reduce((s, r) => s + r.gain, 0);
      const finalGain = remedGain > 0 ? remedGain : potentialGain;
      const hasOpenRemediations = remedList.some(r => r.type === 'identity-remediation') || (critCount + highCount > 0);
      return {
        current: postureScore, grade, tier, previous30d: prevPosture, delta30d,
        industryAvg: as?.industry_avg ?? null,
        target: as?.posture_target ?? (Number(settings?.settings?.posture_target) || Math.min(90, Math.round(postureScore + finalGain))),
        potentialGain: finalGain,
        projectedNoAction: delta30d != null
          ? Math.max(0, postureScore - (delta30d < 0 ? Math.abs(delta30d) : (critCount + highCount > 0 ? 3 : 1)))
          : null,
        projectedRemediated: Math.min(100, postureScore + finalGain),
        history,
      };
    })(),
    pillars,
    topRiskDrivers: topDrivers.slice(0, 5),
    kpis: {
      privilegedNHIs: { count: ao.privileged_nhi_count || 0, description: `${nhi.nhi_pct ? nhi.nhi_pct.toFixed(0) : 0}% of high privilege from machines` },
      dormantPrivileged: { count: ao.dormant_privileged_count || 0, description: 'Unused >90 days with active roles' },
      subscriptionAccess: { count: ao.multi_sub_count || 0, description: 'Contributor+ at subscription scope' },
      rbacModifiers: { count: ao.rbac_modifier_count || 0, description: 'Can alter access policies directly' },
    },
    workloadExposure: {
      avgScore: we.component_averages?.total || 0,
      canEscalate: we.flags?.can_escalate || 0,
      orphaned: we.flags?.orphaned || 0,
      exposureDistribution: we.exposure_distribution || { critical: 0, high: 0, medium: 0, low: 0 },
      componentAverages: [
        { name: 'Privilege', score: we.component_averages?.privilege || 0, max: 40 },
        { name: 'Credential', score: we.component_averages?.credential_risk || 0, max: 25 },
        { name: 'Exposure', score: we.component_averages?.exposure || 0, max: 20 },
        { name: 'Lifecycle', score: we.component_averages?.lifecycle || 0, max: 20 },
        { name: 'Visibility', score: we.component_averages?.visibility || 0, max: 15 },
      ],
      lifecycleState: {
        active: lifecycleDist.active || 0, stale: lifecycleDist.possibly_active || lifecycleDist.stale || 0,
        dormant: (lifecycleDist.likely_dormant || 0) + (lifecycleDist.dormant || 0), blind: blindCount,
      },
      blindTooltip: `${blindCount} identities with no usage telemetry in last 30 days`,
      zombies: we.zombie_count || 0,
      crossSub: we.flags?.cross_subscription || 0,
      tenantScope: we.scope_distribution?.tenant || 0,
      topAffectedWorkloads: [],
    },
    remediations: remedList,
    systemActions,
    compliance: {
      frameworks: compFrameworks,
      controlMaturity: comp?.control_maturity || { preventive: 0, detective: 0, compensating: 0, missing: 0 },
      remediationProgress: Math.round(remed?.completion_pct || comp?.remediation_progress || 0),
      saGovernance: gov.ownership_coverage_pct || 0,
    },
    governance: {
      metrics: govMetrics,
      policyGaps,
      effectivenessScore: effScore,
      effectivenessTooltip: 'Based on ownership, PIM enforcement, review coverage, policy alignment',
      effectivenessConfigured,
      maturityLevel: getMaturityLevel(effScore, effectivenessConfigured),
    },
    trends: {
      movement30d: [
        { label: 'Critical Identities', previous: pr.critical_count || 0, current: critCount, direction: critCount > (pr.critical_count || 0) ? 'up' : critCount < (pr.critical_count || 0) ? 'down' : 'same' },
        { label: 'High-Risk Identities', previous: pr.high_count || 0, current: highCount, direction: highCount > (pr.high_count || 0) ? 'up' : highCount < (pr.high_count || 0) ? 'down' : 'same' },
        { label: 'Total Identities', previous: pr.total_identities || 0, current: totalIds, direction: totalIds > (pr.total_identities || 0) ? 'up' : totalIds < (pr.total_identities || 0) ? 'down' : 'same' },
        { label: 'New Identities', previous: pr.total_identities || 0, current: (pr.total_identities || 0) + (stats?.new_identities_count || 0), direction: (stats?.new_identities_count || 0) > 0 ? 'up' : 'same' },
        { label: 'Removed', previous: pr.total_identities || 0, current: (pr.total_identities || 0) - (stats?.removed_identities_count || 0), direction: (stats?.removed_identities_count || 0) > 0 ? 'down' : 'same' },
      ],
      noActionImpact: [
        ao.privileged_nhi_count ? `${ao.privileged_nhi_count} privileged NHIs remain without review` : null,
        ao.dormant_privileged_count ? `${ao.dormant_privileged_count} dormant privileged accounts retain active roles` : null,
        ao.rbac_modifier_count ? `${ao.rbac_modifier_count} RBAC modifiers continue unreviewed` : null,
        (gov.ownership_coverage_pct != null && gov.ownership_coverage_pct < 100)
          ? `Ownership gap at ${Math.round(100 - gov.ownership_coverage_pct)}% — ${(as?.pillars?.ownership_governance?.detail?.unowned_spns || 0)} SPNs unowned`
          : null,
        (as?.pillars?.usage_dormancy?.detail?.dormant || 0) > 0
          ? `${as.pillars.usage_dormancy.detail.dormant} dormant accounts with active roles unresolved`
          : null,
      ].filter((x): x is string => !!x),
      estimatedBreachImpact: postureScore <= 40 ? 'High' : postureScore <= 60 ? 'Moderate-High' : 'Moderate',
      remediatedBreachImpact: (() => {
        const hasOpen = remedList.some(r => r.type === 'identity-remediation') || (critCount + highCount > 0);
        const proj = Math.min(hasOpen ? 95 : 100, postureScore + potentialGain);
        return proj >= 80 ? 'Low' : proj >= 60 ? 'Moderate' : 'Moderate-High';
      })(),
      remediatedConsequences: (() => {
        // Derive from actual pillar data — state what NEEDS to happen, not false claims
        const items: string[] = [];
        const og = as?.pillars?.ownership_governance?.detail || {};
        const ug = as?.pillars?.usage_dormancy?.detail || {};
        const ep = as?.pillars?.effective_privilege?.detail || {};
        const cr = as?.pillars?.credential_risk?.detail || {};
        const ee = as?.pillars?.external_exposure?.detail || {};
        if (og.unowned_spns > 0) items.push(`Assign owners to ${og.unowned_spns} orphaned SPNs (${Math.round(gov.ownership_coverage_pct || 0)}% → 100%)`);
        if (ug.dormant > 0) items.push(`Review & disable ${ug.dormant} dormant accounts with active roles`);
        if (ep.t0t1 > 0) items.push(`Review ${ep.t0t1} T0/T1 privilege assignments for least-access`);
        if (cr.expired > 0) items.push(`Rotate ${cr.expired} expired credentials`);
        if (ee.tenant_scope > 0) items.push(`Scope down ${ee.tenant_scope} tenant-wide identities`);
        if (!items.length) items.push('No critical remediation actions identified');
        return items;
      })(),
      biggestContributor: {
        label: sortedPillars[0]?.name || 'Unknown',
        delta: `Score ${sortedPillars[0]?.score || 0}/100`,
        pillar: sortedPillars[0]?.name || '',
      },
    },
  };
}
