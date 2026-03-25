/**
 * AuditGraph — Executive Summary
 *
 * Single-viewport (~750px) executive briefing — no scrolling needed.
 * 5 rows: Security Health, Attack Surface + If Compromised, Attack Path + Risk Drivers,
 * Remediation + AGIRS Trend, Data Integrity Footer.
 *
 * All data from snapshot engine (tenant-isolated via RLS). No cross-org leakage.
 * Every numeric value is clickable (DN component) and navigates to the underlying dataset.
 * Compliance frameworks moved to /compliance-posture.
 */
import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import {
  COLORS, getTierColor, getScoreColor,
  getTier, getGrade,
  type TenantData, type ComplianceFramework, type DangerousIdentity,
  type HIRIBreakdown, type NHIRIBreakdown, type GEIBreakdown,
} from '../constants/ciso';
import { formatDate } from '../utils/displayHelpers';
import { FONT, ScoreRing, CISOBadge, Sparkline, CISOCard, DN } from '../components/dashboard/ciso-shared';
import { IdentityDrawerProvider } from '../contexts/IdentityDrawerContext';
import { IdentityContextDrawer } from '../components/dashboard/IdentityContextDrawer';
import { AttackPathWidget } from '../components/dashboard/executive/AttackPathWidget';
import { RemediationPriorities } from '../components/dashboard/executive/RemediationPriorities';
import { AGIRSBreakdownPanel } from '../components/dashboard/executive/AGIRSBreakdownPanel';
import { HumanIdentityRiskTable } from '../components/dashboard/executive/HumanIdentityRiskTable';
import { PhantomExposureTable } from '../components/dashboard/executive/PhantomExposureTable';
import { GovernanceEffectivenessTable } from '../components/dashboard/executive/GovernanceEffectivenessTable';
// useCanonicalMetrics replaced by consolidated /api/risk/summary/full endpoint

// ─── Empty Data (no hardcoded values) ────────────────────────────

// Flatten agirs — eliminate double-nesting (data.agirs.agirs.score → data.agirs.score)
type FlatAGIRS = {
  score: number;
  tier: string;
  delta: number | null;
  hiri: HIRIBreakdown | null;
  nhiri: NHIRIBreakdown | null;
  gei: GEIBreakdown | null;
  dangerous_identities: DangerousIdentity[];
  previous: { agirs: number | null; hiri: number | null; nhiri: number | null; gei: number | null } | null;
};
type CISODataExtended = Omit<TenantData, 'agirs'> & {
  agirs: FlatAGIRS;
  resourceStats: { key_vaults: number; total_resources: number };
  graphAttackPaths: number;
  topRisks: Array<{ id: string; label: string; count: number; severity: string; score_improvement: number }>;
  scoreAnalysis: string;
  potentialScore: number;
  dataCoverage: Array<{ source: string; status: string; detail: string }>;
  dataOrigin: 'tenant_scan' | 'no_data' | 'unknown';
};

function buildEmptyData(): CISODataExtended {
  return {
    tenant: {
      id: '', name: '', organizationName: '', organizationLogo: null,
      cloud: 'Azure', subscriptions: 0, identityCount: 0, customerCount: 0, microsoftCount: 0,
      lastScan: '', scanDuration: 0, scanCompleteness: 0, scanConfidence: 'Low',
      sources: [], isolationGuarantee: 'Isolated dataset \u2022 No cross-tenant visibility',
    },
    riskScore: {
      current: 0, previous: 0, delta: 0,
      tier: 'NO DATA', grade: '\u2014',
      industry: 0, target: 90, potentialGain: 0,
      trend: [],
    },
    projection: {
      noAction: { score: 0, tier: 'NO DATA', consequences: [], breachImpact: 'Unknown' },
      remediated: { score: 0, tier: 'NO DATA', actions: [], breachImpact: 'Unknown' },
    },
    ghostAccounts: {
      total: 0, privileged: 0, nonPrivileged: 0,
      roles: [], complianceImpact: [], lastDetected: '',
    },
    deltaChanges: [],
    identityBreakdown: [],
    pillars: [
      { name: 'Effective Privilege', score: 0, weight: 30, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Credential Risk', score: 0, weight: 20, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Trust & Federation', score: 0, weight: 20, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Usage Dormancy', score: 0, weight: 10, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Ownership Governance', score: 0, weight: 10, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'External Exposure', score: 0, weight: 10, detail: '', identityCount: 0, subMetrics: [] },
    ],
    blastRadius: {
      highRisk: 0, lowRisk: 0, orphaned: 0, productionWorkloads: 0,
      categories: [
        { name: 'Privilege', score: 0, color: COLORS.danger },
        { name: 'Credential', score: 0, color: COLORS.warning },
        { name: 'Exposure', score: 0, color: COLORS.elevated },
        { name: 'Lifecycle', score: 0, color: COLORS.accent },
        { name: 'Visibility', score: 0, color: COLORS.purple },
      ],
    },
    kpis: {
      privilegedRoles: { value: 0, subtitle: '' },
      dormantPrivileged: { value: 0, subtitle: '' },
      ghostAccounts: { value: 0, subtitle: '' },
      subscriptionAccess: { value: 0, subtitle: '' },
      rbacModifiers: { value: 0, subtitle: '' },
    },
    remediations: [],
    governance: {
      effectivenessScore: 0, effectivenessTier: 'NO DATA', maturityLevel: 'Not assessed',
      metrics: [], controlFailures: [],
      setupCompletion: { configured: 0, total: 4 },
    },
    compliance: {
      frameworks: [],
      maturity: { preventive: 0, detective: 0, compensating: 0, missing: 0 },
      progress: { remediation: 0, iaGovernance: 0 },
    },
    riskMovement: {
      trajectory: [], changes: [],
      mostChanged: { name: '', score: 0, category: '' },
      scanMeta: { frequency: '', lastRun: '', sources: '', duration: '', completeness: '' },
    },
    ticketingIntegration: { configured: false, provider: null, projectKey: null, defaultAssignee: null, jira: null },
    agirs: { score: 0, tier: 'F', delta: null, hiri: null, nhiri: null, gei: null, dangerous_identities: [], previous: null },
    resourceStats: { key_vaults: 0, total_resources: 0 },
    graphAttackPaths: 0,
    topRisks: [],
    scoreAnalysis: '',
    potentialScore: 0,
    dataCoverage: [],
    dataOrigin: 'no_data',
  };
}

// ─── Data Hook (2 API calls — consolidated SSOT) ─

function useCISOData(): { data: CISODataExtended; loading: boolean } {
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();
  const [data, setData] = useState<CISODataExtended>(buildEmptyData);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const [summaryRes, attackRes] = await Promise.all([
          fetch(withConnection('/api/risk/summary/full')).catch(() => null),
          fetch(withConnection('/api/overview/attack-surface-score')).catch(() => null),
        ]);

        const riskData = summaryRes?.ok ? await summaryRes.json() : null;
        const attack = attackRes?.ok ? await attackRes.json() : null;

        if (cancelled) return;
        const d = buildEmptyData();

        // ── From consolidated risk summary (SSOT) ──
        if (riskData) {
          // Data origin validation — reject demo data in production
          const origin = riskData.data_origin || 'unknown';
          d.dataOrigin = origin === 'tenant_scan' ? 'tenant_scan' : origin === 'no_data' ? 'no_data' : 'unknown';
          if (origin !== 'tenant_scan' && origin !== 'no_data') {
            console.warn(`[AuditGraph] Unexpected data_origin: "${origin}". Metrics may not reflect real tenant telemetry.`);
          }

          const rc = riskData.risk_counts || {};
          const ic = riskData.identity_counts || {};
          const exp = riskData.exposure || {};

          d.resourceStats.key_vaults = exp.key_vaults || 0;
          d.resourceStats.total_resources = exp.total_resources || 0;

          d.tenant.identityCount = ic.total || d.tenant.identityCount || 0;
          d.tenant.customerCount = ic.customer || 0;
          d.tenant.microsoftCount = ic.microsoft || 0;
          d.tenant.subscriptions = exp.subscriptions || 0;

          // AGIRS data — flat (no double-nesting)
          if (riskData.agirs) {
            d.agirs = {
              score: riskData.agirs.score ?? 0,
              tier: riskData.agirs.tier ?? 'F',
              delta: riskData.agirs.delta ?? null,
              hiri: riskData.hiri || null,
              nhiri: riskData.nhiri || null,
              gei: riskData.gei || null,
              dangerous_identities: riskData.dangerous_identities || [],
              previous: riskData.previous || null,
            };
          }

          // Graph-based attack paths from risk summary
          if (riskData.attack_paths) {
            d.graphAttackPaths = riskData.attack_paths.total || 0;
          }

          // Top risks from backend SSOT
          d.topRisks = riskData.top_risks || [];

          // Score analysis and potential score from backend
          d.scoreAnalysis = riskData.score_analysis || '';
          d.potentialScore = riskData.potential_score ?? 0;
          d.dataCoverage = riskData.data_coverage || [];

          // Ghost accounts from risk counts
          const ghostTotal = rc.ghost_accounts || 0;
          d.ghostAccounts.total = ghostTotal;
          d.ghostAccounts.privileged = Math.min(rc.dormant_privileged || 0, ghostTotal);
          d.ghostAccounts.nonPrivileged = Math.max(0, ghostTotal - d.ghostAccounts.privileged);

          // Identity breakdown from counts
          const humanCount = ic.human || 0;
          const nhiCount = ic.nhi || 0;
          const extCount = rc.external_exposure || 0;
          const total = humanCount + nhiCount + extCount;
          if (total > 0) {
            d.identityBreakdown = [
              { type: 'Human Users', count: humanCount, percentage: Math.round((humanCount / total) * 100), color: 'accent' },
              { type: 'Workload Identities', count: nhiCount, percentage: Math.round((nhiCount / total) * 100), color: 'warning' },
              { type: 'Guest Users', count: extCount, percentage: Math.round((extCount / total) * 100), color: 'textDim' },
            ];
          }
        }

        // ── From attack-surface-score (pillar detail, blast radius, tenant metadata) ──
        if (attack) {
          // Tenant metadata
          if (attack.data_integrity) {
            const di = attack.data_integrity;
            d.tenant.id = String(di.organization_id || di.tenant_id || '');
            d.tenant.name = di.org_name || di.organization_name || '';
            d.tenant.organizationName = di.organization_name || di.org_name || '';
            d.tenant.organizationLogo = di.organization_logo || null;
            d.tenant.lastScan = di.last_scan || '';
            d.tenant.scanDuration = di.scan_duration_seconds || 0;
            d.tenant.scanCompleteness = di.data_completeness_pct || 0;
            d.tenant.scanConfidence = di.confidence || 'Low';
            d.tenant.sources = d.tenant.subscriptions > 0 ? ['Azure RBAC', 'Entra ID', 'Graph API'] : [];
          }
          if (!d.tenant.identityCount) d.tenant.identityCount = attack.total_identities || 0;

          // Risk score (posture = 100 - attack score)
          const posture = Math.round((100 - (attack.score || 0)) * 10) / 10;
          d.riskScore.current = posture;
          d.riskScore.previous = posture;
          d.riskScore.delta = null;
          d.riskScore.tier = getTier(posture);
          const gradeMap: Record<string, string> = { A: 'A', B: 'B', C: 'C', D: 'D', F: 'F' };
          d.riskScore.grade = attack.grade ? (gradeMap[attack.grade as string] || getGrade(posture)) : getGrade(posture);
          d.riskScore.industry = attack.industry_avg != null ? Math.max(0, Math.min(100, attack.industry_avg)) : null;
          d.riskScore.target = attack.posture_target != null ? attack.posture_target : 90;
          d.riskScore.potentialGain = Math.max(0, d.riskScore.target - posture);

          // Trend
          if (attack.trend_data?.length) {
            d.riskScore.trend = attack.trend_data.map((r: { posture_score?: number }) => r.posture_score ?? 0);
          }

          // Pillars — SSOT from riskData.agirs.pillars, enriched with attack-surface-score subMetrics
          if (riskData?.agirs?.pillars) {
            const ap = riskData.agirs.pillars;
            const atkP = attack?.pillars || {};
            const PILLAR_MAP: Record<string, { key: string; name: string; subMetricsFn: () => { name: string; value: number; max: number }[] }> = {
              effective_privilege: { key: 'effective_privilege', name: 'Effective Privilege', subMetricsFn: () => {
                const ep = atkP.effective_privilege?.detail || {};
                return [{ name: 'T0 (Tenant Owner)', value: ep.t0 || 0, max: d.tenant.identityCount || 1 }, { name: 'T0+T1 privileged', value: ep.t0t1 || 0, max: d.tenant.identityCount || 1 }];
              }},
              credential_risk: { key: 'credential_risk', name: 'Credential Risk', subMetricsFn: () => {
                const cr = atkP.credential_risk?.detail || {};
                return [{ name: 'Expired', value: cr.expired || 0, max: cr.with_creds || 1 }, { name: 'Expiring soon', value: cr.expiring || 0, max: cr.with_creds || 1 }];
              }},
              trust_federation: { key: 'trust_federation', name: 'Trust & Federation', subMetricsFn: () => {
                const tf = atkP.trust_federation?.detail || {};
                return [{ name: 'Guests with roles', value: tf.guest_with_roles || 0, max: tf.guests || 1 }];
              }},
              usage_dormancy: { key: 'usage_dormancy', name: 'Usage Dormancy', subMetricsFn: () => {
                const ud = atkP.usage_dormancy?.detail || {};
                return [{ name: 'Dormant', value: ud.dormant || 0, max: ud.total || 1 }];
              }},
              ownership_governance: { key: 'ownership_governance', name: 'Ownership Governance', subMetricsFn: () => {
                const og = atkP.ownership_governance?.detail || {};
                return [{ name: 'Unowned SPNs', value: og.unowned_spns || 0, max: og.total_spns || 1 }];
              }},
              external_exposure: { key: 'external_exposure', name: 'External Exposure', subMetricsFn: () => {
                const ee = atkP.external_exposure?.detail || {};
                return [{ name: 'Tenant-wide scope', value: ee.tenant_scope || 0, max: ee.total || 1 }];
              }},
              attack_path_exposure: { key: 'attack_path_exposure', name: 'Attack Path Exposure', subMetricsFn: () => {
                return [{ name: 'Escalation paths', value: ap.attack_path_exposure?.affected_count || 0, max: d.tenant.identityCount || 1 }];
              }},
            };
            d.pillars = Object.entries(ap).map(([key, pillarData]: [string, any]) => {
              const mapping = PILLAR_MAP[key];
              return {
                name: mapping?.name || pillarData.label || key,
                score: pillarData.risk_pct ?? 0,
                weight: pillarData.weight ?? 0,
                detail: `${pillarData.affected_count ?? 0} of ${d.tenant.identityCount || 0} identities (${(pillarData.risk_pct ?? 0).toFixed(1)}%)`,
                identityCount: pillarData.affected_count ?? 0,
                subMetrics: mapping?.subMetricsFn() || [],
                // Extended pillar data from backend
                _scoreImpact: pillarData.score_impact ?? 0,
                _severity: pillarData.severity ?? 'low',
              };
            });
          } else if (attack?.pillars) {
            // Fallback — old style from attack-surface-score only
            const p = attack.pillars;
            const ep = p.effective_privilege || {};
            const cr = p.credential_risk || {};
            const tf = p.trust_federation || {};
            const ud = p.usage_dormancy || {};
            const og = p.ownership_governance || {};
            const ee = p.external_exposure || {};
            d.pillars = [
              { name: 'Effective Privilege', score: ep.score || 0, weight: ep.weight || 30, detail: `${ep.detail?.t0t1 || 0} IDs at T0/T1`, identityCount: ep.detail?.t0t1 || 0, subMetrics: [] },
              { name: 'Credential Risk', score: cr.score || 0, weight: cr.weight || 20, detail: `${(cr.detail?.expired || 0) + (cr.detail?.expiring || 0)} credential issues`, identityCount: (cr.detail?.expired || 0) + (cr.detail?.expiring || 0), subMetrics: [] },
              { name: 'Trust & Federation', score: tf.score || 0, weight: tf.weight || 10, detail: `${tf.detail?.guest_with_roles || 0} guests with roles`, identityCount: tf.detail?.guest_with_roles || 0, subMetrics: [] },
              { name: 'Usage Dormancy', score: ud.score || 0, weight: ud.weight || 10, detail: `${ud.detail?.dormant || 0} dormant identities`, identityCount: ud.detail?.dormant || 0, subMetrics: [] },
              { name: 'Ownership Governance', score: og.score || 0, weight: og.weight || 10, detail: `${og.detail?.unowned_spns || 0} unowned SPNs`, identityCount: og.detail?.unowned_spns || 0, subMetrics: [] },
              { name: 'External Exposure', score: ee.score || 0, weight: ee.weight || 10, detail: `${ee.detail?.tenant_scope || 0} with tenant-wide scope`, identityCount: ee.detail?.tenant_scope || 0, subMetrics: [] },
            ];
          }

          // KPIs (from attack-surface-score live data)
          const ao = attack.attack_opportunities || {};
          const epDetail = attack.pillars?.effective_privilege?.detail || {};
          d.kpis.privilegedRoles = { value: (epDetail.t0 || 0) + (ao.rbac_modifier_count || 0), subtitle: `${epDetail.t0 || 0} T0 identities` };
          d.kpis.dormantPrivileged = { value: ao.dormant_privileged_count || 0, subtitle: 'Active roles retained' };
          d.kpis.ghostAccounts = { value: d.ghostAccounts.total, subtitle: d.ghostAccounts.total > 0 ? 'Disabled + active RBAC' : 'None detected' };
          d.kpis.subscriptionAccess = { value: d.tenant.subscriptions, subtitle: `${ao.multi_sub_count || 0} cross-sub identities` };
          d.kpis.rbacModifiers = { value: ao.rbac_modifier_count || 0, subtitle: 'Custom role defs' };

          // Blast radius (from attack-surface-score)
          if (attack.workload_exposure) {
            const we = attack.workload_exposure;
            const ed = we.exposure_distribution || {};
            d.blastRadius.highRisk = (ed.critical || 0) + (ed.high || 0);
            d.blastRadius.lowRisk = (ed.medium || 0) + (ed.low || 0);
            d.blastRadius.orphaned = attack.pillars?.ownership_governance?.detail?.unowned_spns || 0;
            d.blastRadius.productionWorkloads = we.total || 0;
            const ca = we.component_averages || {};
            d.blastRadius.categories = [
              { name: 'Privilege', score: ca.privilege || 0, color: COLORS.danger },
              { name: 'Credential', score: ca.credential_risk || 0, color: COLORS.warning },
              { name: 'Exposure', score: ca.exposure || 0, color: COLORS.elevated },
              { name: 'Lifecycle', score: ca.lifecycle || 0, color: COLORS.accent },
              { name: 'Visibility', score: ca.visibility || 0, color: COLORS.purple },
            ];
          }
        }

        // Metric source telemetry
        if (d.dataOrigin === 'tenant_scan') {
          console.info('[AuditGraph] metric_source_verified', {
            data_origin: d.dataOrigin,
            identity_count: d.tenant.identityCount,
            timestamp: new Date().toISOString(),
          });
        }

        setData(d);
      } catch {
        setData(buildEmptyData());
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId, activeOrgId]);

  return { data, loading };
}

// ─── Main Dashboard Component ────────────────────────────────────

export default function CISODashboard() {
  const navigate = useNavigate();
  const { connections, selectedConnectionId, withConnection } = useConnection();
  const { data, loading } = useCISOData();
  const [agirsPanelOpen, setAgirsPanelOpen] = useState(false);
  const [riskDriversOpen, setRiskDriversOpen] = useState(false);

  // Phase 3: AI Agent Risk tile data (independent fetch, gated by feature flag)
  const [agentRisk, setAgentRisk] = useState<{
    total_agents: number; avg_agirs: number; critical_orphans: number;
    highest_risk_agent: { display_name: string | null; risk_score: number };
  } | null>(null);
  useEffect(() => {
    let cancelled = false;
    fetch(withConnection('/api/dashboard/agent-risk-summary'))
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (!cancelled && d) setAgentRisk(d); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [selectedConnectionId]);

  // Connection scope label
  const scopeLabel = selectedConnectionId
    ? connections.find(c => c.id === selectedConnectionId)?.label || `Connection ${selectedConnectionId}`
    : connections.length > 1 ? 'All Connections' : connections[0]?.label || '';

  // AGIRS — flat access (no double-nesting)
  const score = data.agirs?.score ?? 0;
  const TIER_DISPLAY: Record<string, string> = {
    'A': 'RESILIENT', 'B': 'CONTROLLED', 'C': 'ELEVATED', 'D': 'HIGH RISK', 'F': 'CRITICAL',
  };
  const tier = data.agirs?.tier ? (TIER_DISPLAY[data.agirs.tier] || data.agirs.tier) : 'NO DATA';
  const delta = data.agirs?.delta ?? null;

  const workloadCount = useMemo(() =>
    data.identityBreakdown.filter(ib => ib.type !== 'Human Users' && ib.type !== 'Guest Users').reduce((s, ib) => s + ib.count, 0),
    [data.identityBreakdown]
  );
  const guestCount = useMemo(() =>
    data.identityBreakdown.find(ib => ib.type === 'Guest Users')?.count ?? 0,
    [data.identityBreakdown]
  );
  const attackPathCount = data.graphAttackPaths;

  // Risk drivers — from consolidated data (ghost counts stored in ghostAccounts, others in pillars)
  const dormantCount = data.kpis.dormantPrivileged.value;
  const orphanedCount = data.pillars.find(p => p.name === 'Ownership Governance')?.identityCount ?? 0;
  const overPrivCount = data.pillars.find(p => p.name === 'Effective Privilege')?.identityCount ?? 0;
  const extCount = data.pillars.find(p => p.name === 'External Exposure')?.identityCount ?? 0;

  // Blast radius level — scoped to TOP identity's reachable resources
  const blastHigh = data.blastRadius.highRisk;
  const topDangerous = (data.agirs?.dangerous_identities || [])[0];
  const blastSubs = topDangerous?.subscription_count ?? data.tenant.subscriptions ?? 0;
  const blastRoles = topDangerous?.total_role_count ?? data.kpis.privilegedRoles.value;
  const blastLevel = (blastSubs >= 5 || blastRoles >= 20) ? 'CRITICAL'
    : (blastSubs >= 2 || blastRoles >= 10) ? 'HIGH'
    : (blastSubs >= 1 || blastRoles >= 5) ? 'MEDIUM' : 'LOW';
  const blastColor = blastLevel === 'CRITICAL' ? COLORS.danger
    : blastLevel === 'HIGH' ? COLORS.elevated
    : blastLevel === 'MEDIUM' ? COLORS.warning : COLORS.success;

  // Identity risk score (inverted attack surface)
  const identityRiskScore = Math.round(data.riskScore.current);

  // ─── Identity Security Scorecard (reuses existing telemetry) ───
  const scorecardPillars = useMemo(() => {
    const riskToHealth = (riskPct: number) => Math.max(0, Math.min(100, 100 - riskPct));
    const getStatus = (health: number): { label: string; color: string } =>
      health >= 80 ? { label: 'Secure', color: COLORS.success }
        : health >= 60 ? { label: 'Moderate', color: COLORS.warning }
        : health >= 40 ? { label: 'At Risk', color: COLORS.elevated }
        : { label: 'Critical', color: COLORS.danger };

    const ownershipRisk = data.pillars.find(p => p.name === 'Ownership Governance')?.score ?? 0;
    const dormancyRisk = data.pillars.find(p => p.name === 'Usage Dormancy')?.score ?? 0;
    const ghostPenalty = Math.min(30, (data.ghostAccounts.total) * 5);
    const govHealth = riskToHealth(Math.min(100, (ownershipRisk + dormancyRisk) / 2 + ghostPenalty));

    const privRisk = data.pillars.find(p => p.name === 'Effective Privilege')?.score ?? 0;
    const privHealth = riskToHealth(privRisk);

    const credRisk = data.pillars.find(p => p.name === 'Credential Risk')?.score ?? 0;
    const credHealth = riskToHealth(credRisk);

    const attackHealth = attackPathCount === 0 ? 100 : attackPathCount <= 10 ? 70 : attackPathCount <= 100 ? 40 : attackPathCount <= 1000 ? 20 : 5;

    const blastHealth = blastLevel === 'LOW' ? 90 : blastLevel === 'MEDIUM' ? 60 : blastLevel === 'HIGH' ? 30 : 10;

    return [
      { name: 'Identity Governance', health: govHealth, ...getStatus(govHealth),
        tooltip: 'Ownership coverage, ghost account exposure, orphaned identities, and usage dormancy across your identity estate.',
        nav: '/service-accounts' },
      { name: 'Privilege Control', health: privHealth, ...getStatus(privHealth),
        tooltip: 'Over-privileged identities, standing privilege assignments, and effective privilege risk across roles.',
        nav: '/identities?pillar=effective-privilege' },
      { name: 'Credential Security', health: credHealth, ...getStatus(credHealth),
        tooltip: 'Expired credentials, secrets rotation compliance, key vault exposure, and credential abuse risk.',
        nav: '/identities?pillar=credential-risk' },
      { name: 'Attack Path Exposure', health: attackHealth, ...getStatus(attackHealth),
        tooltip: 'Privilege escalation chains and lateral movement paths discovered through graph-based identity analysis.',
        nav: '/graph-findings' },
      { name: 'Blast Radius Risk', health: blastHealth, ...getStatus(blastHealth),
        tooltip: 'Worst-case impact if a high-privilege identity is compromised — subscriptions, resources, and key vaults reachable.',
        nav: '/identities?sort=blast_radius_score&order=desc' },
    ];
  }, [data.pillars, data.ghostAccounts.total, attackPathCount, blastLevel]);

  const overallPosture = useMemo(() => {
    const avg = scorecardPillars.reduce((s, p) => s + p.health, 0) / scorecardPillars.length;
    return avg >= 80 ? { label: 'STRONG', color: COLORS.success }
      : avg >= 60 ? { label: 'MODERATE', color: COLORS.warning }
      : avg >= 40 ? { label: 'ELEVATED RISK', color: COLORS.elevated }
      : { label: 'CRITICAL', color: COLORS.danger };
  }, [scorecardPillars]);

  // Data freshness — color-coded based on scan age
  const scanAgeHours = data.tenant.lastScan
    ? (Date.now() - new Date(data.tenant.lastScan).getTime()) / 3600000
    : Infinity;
  const freshnessColor = scanAgeHours <= 24 ? COLORS.success
    : scanAgeHours <= 72 ? COLORS.warning
    : scanAgeHours < Infinity ? COLORS.danger : COLORS.textDim;
  const freshnessLabel = scanAgeHours <= 24 ? 'FRESH'
    : scanAgeHours <= 72 ? 'AGING' : scanAgeHours < Infinity ? 'STALE' : '';

  if (loading) {
    return (
      <IdentityDrawerProvider>
        <div style={{
          minHeight: 'calc(100vh - 56px)', background: COLORS.bg,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          borderRadius: '12px 0 0 0',
        }}>
          <div style={{ textAlign: 'center' as const }}>
            <div style={{
              width: 40, height: 40, borderRadius: '50%',
              border: `3px solid ${COLORS.border}`, borderTopColor: COLORS.accent,
              animation: 'spin 1s linear infinite', margin: '0 auto 12px',
            }} />
            <div style={{ fontSize: 12, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Loading Executive Summary...</div>
          </div>
          <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
        </div>
        <IdentityContextDrawer />
      </IdentityDrawerProvider>
    );
  }

  return (
    <IdentityDrawerProvider>
      <div style={{ height: 'calc(100vh - 56px)', background: COLORS.bg, fontFamily: FONT.ui, borderRadius: '12px 0 0 0', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>

        {/* ─── Header (36px) ─── */}
        <div style={{
          padding: '6px 20px', borderBottom: `1px solid ${COLORS.border}`,
          background: COLORS.surface, borderRadius: '12px 0 0 0',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          flexShrink: 0, height: 36,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>Executive Summary</span>
            <span style={{ fontSize: 8, color: COLORS.textSecondary, fontFamily: FONT.ui, fontWeight: 400 }}>Identity attack surface posture and risk exposure overview</span>
            {scopeLabel && (
              <span style={{
                fontSize: 8, fontWeight: 600, padding: '1px 6px', borderRadius: 3,
                background: selectedConnectionId ? `${COLORS.accent}18` : `${COLORS.textMuted}15`,
                color: selectedConnectionId ? COLORS.accent : COLORS.textMuted,
                border: `1px solid ${selectedConnectionId ? COLORS.accent : COLORS.textMuted}30`,
                fontFamily: FONT.mono, letterSpacing: '0.06em',
              }}>{scopeLabel}</span>
            )}
            <span style={{
              fontSize: 8, fontWeight: 600, padding: '1px 6px', borderRadius: 3,
              background: `${COLORS.accent}18`, color: COLORS.accent, border: `1px solid ${COLORS.accent}30`,
              fontFamily: FONT.mono, textTransform: 'uppercase', letterSpacing: '0.06em',
            }}>Leadership</span>
            <span style={{
              fontSize: 7, fontWeight: 600, padding: '1px 5px', borderRadius: 3,
              background: `${data.tenant.scanConfidence === 'High' ? COLORS.success : data.tenant.scanConfidence === 'Medium' ? COLORS.warning : COLORS.textDim}15`,
              color: data.tenant.scanConfidence === 'High' ? COLORS.success : data.tenant.scanConfidence === 'Medium' ? COLORS.warning : COLORS.textDim,
              fontFamily: FONT.mono, textTransform: 'uppercase', letterSpacing: '0.06em',
            }}>{data.tenant.scanConfidence} Confidence</span>
            {delta != null && (
              <span style={{
                fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 3,
                fontFamily: FONT.mono,
                background: delta > 0 ? `${COLORS.success}15` : delta < 0 ? `${COLORS.danger}15` : `${COLORS.textDim}15`,
                color: delta > 0 ? COLORS.success : delta < 0 ? COLORS.danger : COLORS.textDim,
              }}>
                {delta > 0 ? '\u2191' : delta < 0 ? '\u2193' : '\u2192'} {delta > 0 ? '+' : ''}{delta.toFixed(1)}
              </span>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 9, fontFamily: FONT.ui }}>
            <span style={{ color: COLORS.textSecondary }}>
              Updated <span style={{ color: freshnessColor, fontWeight: 600 }}>{formatDate(data.tenant.lastScan, 'No snapshot data')}</span>
              {freshnessLabel && (
                <span style={{
                  fontSize: 7, fontWeight: 700, padding: '1px 4px', borderRadius: 3,
                  background: `${freshnessColor}15`, color: freshnessColor,
                  fontFamily: FONT.mono, marginLeft: 4,
                }}>{freshnessLabel}</span>
              )}
            </span>
            <DN navigateTo="/compliance-posture">
              <span style={{ color: COLORS.accent, cursor: 'pointer' }}>Compliance {'\u2192'}</span>
            </DN>
          </div>
        </div>

        {/* ─── Scrollable Content ─── */}
        <div style={{ flex: 1, overflow: 'auto', padding: '10px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>

          {/* ─── Stale Data Warning ─── */}
          {scanAgeHours > 24 && scanAgeHours < Infinity && (
            <div style={{
              background: 'rgba(120,53,15,0.3)', border: '1px solid #D97706',
              borderRadius: 6, padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 8,
              fontSize: 11, color: '#FDE68A',
            }}>
              <span>{'\u26A0\uFE0F'}</span>
              <span style={{ fontFamily: FONT.ui }}>
                Data is <strong>{Math.round(scanAgeHours)}h</strong> old. Risk posture may have changed.
              </span>
              <DN navigateTo="/settings">
                <span style={{
                  color: '#FCD34D', fontWeight: 600, cursor: 'pointer', fontFamily: FONT.ui,
                  marginLeft: 4,
                }}>
                  Run scan now {'\u2192'}
                </span>
              </DN>
            </div>
          )}

          {/* ─── Empty State — no discovery data ─── */}
          {data.dataOrigin === 'no_data' && data.tenant.identityCount === 0 && (
            <div style={{
              background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 10,
              padding: '40px 20px', textAlign: 'center' as const,
            }}>
              <div style={{ fontSize: 28, marginBottom: 10, opacity: 0.5 }}>{'\uD83D\uDD0D'}</div>
              <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui, marginBottom: 6 }}>
                No identities discovered yet
              </div>
              <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.5, maxWidth: 420, margin: '0 auto 14px' }}>
                Connect your Azure tenant and run discovery to analyze your identity environment.
                All metrics on this dashboard are derived from real tenant telemetry only.
              </div>
              <DN navigateTo="/settings">
                <span style={{
                  display: 'inline-block', fontSize: 11, fontWeight: 600, padding: '6px 16px',
                  borderRadius: 6, background: COLORS.accent, color: '#fff', fontFamily: FONT.ui,
                  cursor: 'pointer',
                }}>
                  Configure Connection {'\u2192'}
                </span>
              </DN>
            </div>
          )}

          {/* ─── Identity Security Scorecard ─── */}
          {(data.dataOrigin === 'tenant_scan' || data.tenant.identityCount > 0) && <>
          <div style={{
            background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 8,
            padding: '10px 14px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
              <span style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                Identity Security Scorecard
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{
                  width: 6, height: 6, borderRadius: '50%', background: overallPosture.color,
                  boxShadow: `0 0 6px ${overallPosture.color}60`,
                }} />
                <span style={{ fontSize: 9, fontWeight: 700, color: overallPosture.color, fontFamily: FONT.mono, letterSpacing: '0.06em' }}>
                  {overallPosture.label}
                </span>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8 }}>
              {scorecardPillars.map(pillar => (
                <DN key={pillar.name} navigateTo={pillar.nav}>
                  <div
                    title={pillar.tooltip}
                    style={{
                      padding: '8px 10px', borderRadius: 6,
                      background: `${pillar.color}08`, border: `1px solid ${pillar.color}25`,
                      cursor: 'pointer', transition: 'border-color 0.15s, background 0.15s',
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.borderColor = `${pillar.color}60`;
                      (e.currentTarget as HTMLElement).style.background = `${pillar.color}12`;
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.borderColor = `${pillar.color}25`;
                      (e.currentTarget as HTMLElement).style.background = `${pillar.color}08`;
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 4 }}>
                      <span style={{
                        width: 6, height: 6, borderRadius: '50%', background: pillar.color, flexShrink: 0,
                        boxShadow: `0 0 4px ${pillar.color}50`,
                      }} />
                      <span style={{ fontSize: 8, fontWeight: 600, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.2 }}>
                        {pillar.name}
                      </span>
                    </div>
                    <span style={{
                      fontSize: 10, fontWeight: 700, color: pillar.color, fontFamily: FONT.mono,
                    }}>
                      {pillar.label}
                    </span>
                  </div>
                </DN>
              ))}
            </div>
          </div>

          {/* ─── Row 1: SECURITY HEALTH (4 cards) ─── */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
            {/* AGIRS Score (expandable) */}
            <div
              onClick={() => setAgirsPanelOpen(!agirsPanelOpen)}
              style={{
                background: COLORS.surface, border: `1px solid ${agirsPanelOpen ? COLORS.accent : COLORS.border}`, borderRadius: 8,
                padding: '8px 12px', display: 'flex', alignItems: 'center', gap: 10,
                cursor: 'pointer', transition: 'border-color 0.2s',
              }}
            >
              <ScoreRing score={score} size={48} strokeWidth={4} color={getScoreColor(score)} />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 8, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui }}>
                  AGIRS{' '}
                  <span title="Identity Attack Surface Score — measures exposure across 7 pillars based on your identity configuration. Higher = better posture. Score = 100 minus proportional risk penalties." style={{ cursor: 'help', opacity: 0.6 }}>{'\u24D8'}</span>
                </div>
                <span style={{ fontSize: 16, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text }}>{score.toFixed(1)}</span>
                <span style={{ fontSize: 8, color: COLORS.textSecondary, fontFamily: FONT.ui }}>/100</span>
                <div style={{ marginTop: 2 }}>
                  <CISOBadge label={tier} color={getTierColor(tier)} />
                </div>
                <div style={{ fontSize: 8, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 1 }}>
                  {score >= 80 ? 'Strong Posture' : score >= 60 ? 'Moderate Posture' : score >= 40 ? 'Needs Attention' : 'Weak Posture'}
                </div>
                <div style={{ fontSize: 8, color: COLORS.accent, fontFamily: FONT.ui, marginTop: 3 }}>
                  {agirsPanelOpen ? 'Hide Breakdown' : 'View Posture Breakdown \u2192'}
                </div>
              </div>
            </div>

            {/* Identity Threat Exposure — clickable to toggle drill-down */}
            <div
              onClick={() => setRiskDriversOpen(v => !v)}
              style={{
                background: COLORS.surface, border: `1px solid ${riskDriversOpen ? COLORS.accent : COLORS.border}`, borderRadius: 8,
                padding: '8px 12px', cursor: 'pointer', transition: 'border-color 0.15s',
              }}
            >
              <div style={{ fontSize: 8, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui }}>
                Identity Threat Exposure{' '}
                <span title="Identity Threat Exposure — aggregate threat level across all identities. Measures dangerous identities, credential exposure, and privilege abuse risk. Lower score = higher threat." style={{ cursor: 'help', opacity: 0.6 }}>{'\u24D8'}</span>
              </div>
              <DN navigateTo="/identities?sort=risk_score&order=desc">
                <span style={{ fontSize: 22, fontWeight: 700, fontFamily: FONT.mono, color: getScoreColor(identityRiskScore) }}>{identityRiskScore}</span>
              </DN>
              <span style={{ fontSize: 8, color: COLORS.textSecondary, fontFamily: FONT.ui }}>/100</span>
              <div style={{ fontSize: 8, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 2 }}>
                Grade: <span style={{ fontWeight: 700, color: getScoreColor(identityRiskScore) }}>{data.riskScore.grade}</span>
              </div>
              <div style={{ fontSize: 9, fontWeight: 600, color: getScoreColor(identityRiskScore), fontFamily: FONT.ui, marginTop: 1 }}>
                {identityRiskScore >= 80 ? 'Low Threat' : identityRiskScore >= 60 ? 'Moderate Threat' : identityRiskScore >= 40 ? 'Elevated Threat' : 'Critical Threat'}
              </div>
              <div style={{ fontSize: 8, color: COLORS.accent, fontFamily: FONT.ui, marginTop: 3 }}>
                {riskDriversOpen ? 'Hide Drivers' : 'View Risk Drivers \u2192'}
              </div>
            </div>

            {/* Attack Paths */}
            <div style={{
              background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 8,
              padding: '8px 12px',
            }}>
              <div style={{ fontSize: 8, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui }}>Attack Paths</div>
              <DN navigateTo="/graph-findings">
                <span style={{ fontSize: 22, fontWeight: 700, fontFamily: FONT.mono, color: attackPathCount > 0 ? COLORS.danger : COLORS.textDim }}>{attackPathCount.toLocaleString()}</span>
              </DN>
              <span style={{ fontSize: 8, color: COLORS.textSecondary, fontFamily: FONT.ui }}> escalation paths</span>
              <div style={{ marginTop: 2 }}>
                {(() => {
                  const sev = attackPathCount > 1000 ? 'CRITICAL' : attackPathCount > 100 ? 'HIGH' : attackPathCount > 10 ? 'MEDIUM' : attackPathCount > 0 ? 'LOW' : 'NONE';
                  const sevColor = sev === 'CRITICAL' ? COLORS.danger : sev === 'HIGH' ? COLORS.elevated : sev === 'MEDIUM' ? COLORS.warning : COLORS.success;
                  return (
                    <span style={{
                      fontSize: 7, fontWeight: 700, padding: '1px 5px', borderRadius: 3,
                      background: `${sevColor}15`, color: sevColor, fontFamily: FONT.mono,
                    }}>{sev}</span>
                  );
                })()}
              </div>
            </div>

            {/* High Blast Radius */}
            <div style={{
              background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 8,
              padding: '8px 12px',
            }}>
              <div style={{ fontSize: 8, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui }}>High Blast Radius</div>
              {blastHigh === 0 ? (
                <div style={{ fontSize: 10, color: COLORS.success, fontFamily: FONT.ui, marginTop: 4, fontWeight: 600 }}>
                  No high-risk identities
                </div>
              ) : (
                <>
                  <DN navigateTo="/identities?sort=blast_radius_score&order=desc">
                    <span style={{ fontSize: 22, fontWeight: 700, fontFamily: FONT.mono, color: blastColor }}>{blastHigh}</span>
                  </DN>
                  <span style={{ fontSize: 8, color: COLORS.textSecondary, fontFamily: FONT.ui }}> identities</span>
                  <div style={{ marginTop: 2 }}>
                    <span style={{
                      fontSize: 7, fontWeight: 700, padding: '1px 5px', borderRadius: 3,
                      background: `${blastColor}15`, color: blastColor, fontFamily: FONT.mono,
                    }}>{blastLevel}</span>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* ─── AI Executive Narrative ─── */}
          {data.scoreAnalysis && (
            <div style={{
              background: `${COLORS.accent}08`, border: `1px solid ${COLORS.accent}20`,
              borderRadius: 8, padding: '10px 16px',
              fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.6,
            }}>
              <div style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textMuted, marginBottom: 4 }}>
                AI Posture Analysis
              </div>
              <span style={{ color: COLORS.text }}>{data.scoreAnalysis}</span>
            </div>
          )}

          {/* ─── Identity Threat Exposure Drill-Down ─── */}
          {riskDriversOpen && (
            <CISOCard style={{ padding: '10px 14px' }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui, marginBottom: 8 }}>
                Threat Exposure: {identityRiskScore}/100 &middot; Grade: {data.riskScore.grade} &middot;{' '}
                <span style={{ color: getScoreColor(identityRiskScore) }}>
                  {identityRiskScore >= 80 ? 'Low Threat' : identityRiskScore >= 60 ? 'Moderate Threat' : identityRiskScore >= 40 ? 'Elevated Threat' : 'Critical Threat'}
                </span>
              </div>
              <div style={{ fontSize: 9, fontWeight: 600, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 6 }}>Risk Drivers</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                {[
                  { icon: '\u23F0', label: 'Dormant Privileged', value: dormantCount, nav: '/identities?activity_status=stale' },
                  { icon: '\u2699\uFE0F', label: 'Orphaned SPNs', value: orphanedCount, nav: '/workload-identities?owner=orphaned' },
                  { icon: '\u26A0\uFE0F', label: 'Over-Privileged', value: overPrivCount, nav: '/identities?pillar=effective-privilege' },
                  { icon: '\uD83D\uDC7B', label: 'Ghost Accounts', value: data.ghostAccounts.total, nav: '/identity-exposures?exposure_type=disabled_with_access' },
                  { icon: '\uD83D\uDD11', label: 'Credential Exposure', value: data.pillars.find(p => p.name === 'Credential Risk')?.identityCount ?? 0, nav: '/identities?pillar=credential-risk' },
                ].map(d => (
                  <DN key={d.label} navigateTo={d.nav}>
                    <div style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '5px 8px', borderRadius: 6, background: `${COLORS.accent}08`,
                      border: `1px solid ${COLORS.border}`,
                    }}>
                      <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>{d.icon} {d.label}</span>
                      <span style={{ fontSize: 13, fontWeight: 700, fontFamily: FONT.mono, color: d.value > 0 ? COLORS.warning : COLORS.success }}>{d.value}</span>
                    </div>
                  </DN>
                ))}
              </div>

              {/* Top Risk Identities */}
              {(data.agirs.dangerous_identities || []).length > 0 && (
                <div style={{ marginTop: 10, paddingTop: 8, borderTop: `1px solid ${COLORS.border}` }}>
                  <div style={{ fontSize: 9, fontWeight: 600, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 6 }}>Top Risk Identities</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                    {(data.agirs.dangerous_identities || []).slice(0, 5).map((identity, i, arr) => (
                      <DN key={identity.id} navigateTo={`/identities/${identity.id}`}>
                        <div style={{
                          display: 'flex', alignItems: 'center', gap: 8,
                          padding: '5px 4px', cursor: 'pointer', transition: 'background 0.15s',
                          borderBottom: i < arr.length - 1 ? `1px solid ${COLORS.border}` : 'none',
                        }}
                          onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = `${COLORS.accent}08`; }}
                          onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                        >
                          <span style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.mono, width: 14, textAlign: 'center', flexShrink: 0 }}>{i + 1}</span>
                          <span style={{ fontSize: 10, color: COLORS.text, fontFamily: FONT.ui, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{identity.display_name}</span>
                          <span style={{
                            fontSize: 7, padding: '1px 4px', borderRadius: 3, flexShrink: 0,
                            background: `${COLORS.textMuted}15`, color: COLORS.textMuted, fontFamily: FONT.mono,
                          }}>{identity.identity_category?.replace(/_/g, ' ')}</span>
                          <span style={{
                            fontSize: 11, fontWeight: 700, fontFamily: FONT.mono, minWidth: 24, textAlign: 'right', flexShrink: 0,
                            color: identity.risk_score >= 80 ? COLORS.danger : identity.risk_score >= 60 ? COLORS.elevated : identity.risk_score >= 40 ? COLORS.warning : COLORS.textDim,
                          }}>{identity.risk_score}</span>
                        </div>
                      </DN>
                    ))}
                  </div>
                </div>
              )}
            </CISOCard>
          )}

          {/* ─── Score Relationship Bridge ─── */}
          {(agirsPanelOpen || riskDriversOpen) && score > 0 && identityRiskScore > 0 && Math.abs(score - identityRiskScore) > 15 && (
            <div style={{
              padding: '6px 12px', borderRadius: 6,
              background: `${COLORS.accent}08`, border: `1px solid ${COLORS.accent}20`,
              fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.5,
            }}>
              AGIRS measures your <span style={{ color: COLORS.text, fontWeight: 600 }}>governance posture</span> ({score.toFixed(0)} = {score >= 80 ? 'well-configured' : score >= 65 ? 'needs attention' : 'significant gaps'}).
              Identity Threat Exposure measures <span style={{ color: COLORS.text, fontWeight: 600 }}>individual threat levels</span> ({identityRiskScore} = {identityRiskScore >= 80 ? 'low threat population' : identityRiskScore >= 60 ? 'moderate threat' : 'elevated threat'}).
              {score > identityRiskScore + 20 && ' Strong governance posture with elevated threat exposure indicates configuration is improving but historical identity debt remains.'}
              {identityRiskScore > score + 20 && ' Low threat exposure with weaker governance indicates individual identities are well-managed but structural configuration gaps exist.'}
            </div>
          )}

          {/* ─── AGIRS Expandable Panel ─── */}
          {agirsPanelOpen && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <AGIRSBreakdownPanel
                score={score}
                tier={tier}
                pillars={data.pillars}
                previousScore={data.agirs.previous?.agirs ?? null}
                scoreAnalysis={data.scoreAnalysis}
                potentialScore={data.potentialScore}
                dataCoverage={data.dataCoverage}
              />
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, alignItems: 'start' }}>
                <HumanIdentityRiskTable hiri={data.agirs.hiri} />
                <PhantomExposureTable nhiri={data.agirs.nhiri} />
              </div>
              <GovernanceEffectivenessTable
                gei={data.agirs.gei}
                maturity={data.compliance.maturity}
              />
            </div>
          )}

          {/* ─── Attack Paths Context Banner ─── */}
          {data.graphAttackPaths > 100 && (
            <DN navigateTo="/graph-findings">
              <div style={{
                background: `${COLORS.warning}10`, border: `1px solid ${COLORS.warning}40`,
                borderRadius: 6, padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <span style={{ fontSize: 12 }}>{'\u26A0\uFE0F'}</span>
                <span style={{ fontSize: 10, color: COLORS.warning, fontFamily: FONT.ui }}>
                  <strong>{data.graphAttackPaths.toLocaleString()}</strong> lateral movement paths detected — not yet factored into AGIRS score.
                  <span style={{ color: COLORS.textSecondary }}> Click to review.</span>
                </span>
              </div>
            </DN>
          )}

          {/* ─── Row 2: ATTACK SURFACE + WORST CASE BLAST RADIUS ─── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {/* Left: Attack Surface */}
            <div style={{
              background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 8,
              padding: '8px 12px',
            }}>
              <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 8, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui }}>Attack Surface</span>
                {data.tenant.microsoftCount > 0 && (
                  <span style={{ fontSize: 7, color: COLORS.textDim, fontFamily: FONT.ui }}
                    title={`Total objects: ${data.tenant.identityCount}. Attack Surface shows ${data.tenant.customerCount} customer identities (Microsoft first-party excluded from counts).`}
                  >{data.tenant.customerCount} customer + {data.tenant.microsoftCount} Microsoft system</span>
                )}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 6 }}>
                {[
                  { label: 'Total', value: data.tenant.customerCount || data.tenant.identityCount, color: COLORS.accent, nav: '/identities',
                    tooltip: data.tenant.microsoftCount > 0 ? `${data.tenant.customerCount} customer + ${data.tenant.microsoftCount} Microsoft system (excluded)` : undefined },
                  { label: 'Privileged', value: data.kpis.privilegedRoles.value, color: COLORS.danger, nav: '/identities?pillar=effective-privilege' },
                  { label: 'Machine', value: workloadCount, color: COLORS.purple, nav: '/workload-identities' },
                  { label: 'External', value: guestCount, color: COLORS.elevated, nav: '/identities?identity_category=guest' },
                ].map(pill => (
                  <div key={pill.label} style={{ textAlign: 'center' as const }} title={(pill as any).tooltip}>
                    <DN navigateTo={pill.nav}>
                      <span style={{ fontSize: 16, fontWeight: 700, fontFamily: FONT.mono, color: pill.value > 0 ? pill.color : COLORS.textDim }}>{pill.value}</span>
                    </DN>
                    <div style={{ fontSize: 7, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: 1 }}>{pill.label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: Worst Case Blast Radius */}
            <div style={{
              background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 8,
              padding: '8px 12px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 2 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ fontSize: 8, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.warning, fontFamily: FONT.ui }}>Worst Case Blast Radius</span>
                  <span style={{
                    fontSize: 7, fontWeight: 700, padding: '1px 5px', borderRadius: 3,
                    background: `${blastColor}15`, color: blastColor, fontFamily: FONT.mono,
                  }}>{blastLevel}</span>
                </div>
                {(data.agirs.dangerous_identities || []).length > 0 ? (
                  <DN navigateTo={`/attack-simulator?identity=${data.agirs.dangerous_identities[0].id}`}>
                    <span style={{ fontSize: 8, color: COLORS.accent, fontFamily: FONT.ui, cursor: 'pointer' }}>Simulate Blast Radius {'\u2192'}</span>
                  </DN>
                ) : (
                  <DN navigateTo="/identities?sort=blast_radius_score&order=desc">
                    <span style={{ fontSize: 8, color: COLORS.accent, fontFamily: FONT.ui, cursor: 'pointer' }}>View Details {'\u2192'}</span>
                  </DN>
                )}
              </div>
              <div style={{ fontSize: 8, color: COLORS.textMuted, fontFamily: FONT.ui, marginBottom: 6 }}>
                {(data.agirs.dangerous_identities || []).length > 0
                  ? <>If <DN navigateTo={`/identities/${data.agirs.dangerous_identities[0].id}`}><span style={{ color: '#60A5FA', fontWeight: 600, cursor: 'pointer', textDecoration: 'underline dotted', textUnderlineOffset: 3 }}>{data.agirs.dangerous_identities[0]?.display_name}</span></DN> is compromised, an attacker could reach:</>
                  : 'What an attacker could reach from a privileged identity'}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 6 }}>
                {(() => {
                  const topIdentity = (data.agirs.dangerous_identities || [])[0];
                  const topId = topIdentity?.id;
                  const identityNav = topId ? `/identities/${topId}` : '/identities?sort=blast_radius_score&order=desc';
                  // Use per-identity blast radius data when available, fall back to tenant-wide
                  const idSubs = topIdentity?.subscription_count ?? data.tenant.subscriptions;
                  const idRoles = topIdentity?.total_role_count ?? data.kpis.privilegedRoles.value;
                  const idRGs = topIdentity?.resource_group_count ?? 0;
                  const idEntraRoles = topIdentity?.entra_role_count ?? 0;
                  return [
                    { label: 'Subscriptions', value: idSubs, color: COLORS.accent, nav: identityNav },
                    { label: 'Resource Grps', value: idRGs, color: COLORS.warning, nav: identityNav },
                    { label: 'Entra Roles', value: idEntraRoles, color: COLORS.elevated, nav: identityNav },
                    { label: 'RBAC Roles', value: idRoles, color: COLORS.danger, nav: identityNav },
                  ].map(pill => (
                    <div key={pill.label} style={{ textAlign: 'center' as const }}>
                      <DN navigateTo={pill.nav}>
                        <span style={{ fontSize: 16, fontWeight: 700, fontFamily: FONT.mono, color: pill.value > 0 ? pill.color : COLORS.textDim }}>{pill.value}</span>
                      </DN>
                      <div style={{ fontSize: 7, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: 1 }}>{pill.label}</div>
                    </div>
                  ));
                })()}
              </div>
            </div>
          </div>

          {/* ─── Row 3: ATTACK PATH + IDENTITY THREAT DRIVERS ─── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, minHeight: 0 }}>
            {/* Attack Path Graph (compact) */}
            <AttackPathWidget identities={data.agirs.dangerous_identities || []} attackPathCount={data.graphAttackPaths} compact />

            {/* Identity Threat Drivers */}
            <CISOCard style={{ padding: '10px 14px' }}>
              <div style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8 }}>Identity Threat Drivers</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {[
                  { icon: '\u23F0', label: 'Dormant Privileged', count: dormantCount, color: COLORS.danger, nav: '/identities?activity_status=stale', severity: dormantCount >= 5 ? 'CRIT' : dormantCount >= 2 ? 'HIGH' : dormantCount > 0 ? 'MED' : '' },
                  { icon: '\u2699\uFE0F', label: 'Orphaned SPNs', count: orphanedCount, color: COLORS.elevated, nav: '/workload-identities?owner=orphaned', severity: orphanedCount >= 10 ? 'HIGH' : orphanedCount > 0 ? 'MED' : '' },
                  { icon: '\u26A0\uFE0F', label: 'Over-Privileged', count: overPrivCount, color: COLORS.warning, nav: '/identities?pillar=effective-privilege', severity: overPrivCount >= 5 ? 'CRIT' : overPrivCount >= 2 ? 'HIGH' : overPrivCount > 0 ? 'MED' : '' },
                  { icon: '\uD83C\uDF10', label: 'External Exposure', count: extCount, color: COLORS.purple, nav: '/identities?pillar=external-exposure', severity: extCount >= 5 ? 'HIGH' : extCount > 0 ? 'MED' : '' },
                ].map((d, i, arr) => (
                  <div
                    key={d.label}
                    onClick={() => navigate(d.nav)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '7px 4px', cursor: 'pointer', transition: 'background 0.15s',
                      borderBottom: i < arr.length - 1 ? `1px solid ${COLORS.border}` : 'none',
                    }}
                    onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = `${d.color}08`; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                  >
                    <span style={{ fontSize: 12, width: 18, textAlign: 'center', flexShrink: 0 }}>{d.icon}</span>
                    <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui, flex: 1 }}>{d.label}</span>
                    <DN navigateTo={d.nav}>
                      <span style={{ fontSize: 14, fontWeight: 700, fontFamily: FONT.mono, color: d.count > 0 ? d.color : COLORS.textDim, minWidth: 20, textAlign: 'right' }}>{d.count}</span>
                    </DN>
                    {d.severity && (
                      <span style={{
                        fontSize: 7, fontWeight: 700, padding: '1px 4px', borderRadius: 3, minWidth: 28, textAlign: 'center',
                        background: `${d.color}15`, color: d.color, fontFamily: FONT.mono, flexShrink: 0,
                      }}>{d.severity}</span>
                    )}
                  </div>
                ))}
              </div>
            </CISOCard>
          </div>

          {/* ─── Row 4: REMEDIATION + TREND ─── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, minHeight: 0 }}>
            {/* Top Risks to Fix (compact, max 5 items) */}
            <RemediationPriorities
              pillars={data.pillars}
              kpis={data.kpis}
              ghostAccounts={data.ghostAccounts}
              currentScore={score}
              targetScore={data.riskScore.target}
              topRisks={data.topRisks}
              maxItems={5}
              compact
            />

            {/* AGIRS Trend */}
            <CISOCard style={{ padding: '10px 14px' }}>
              <div style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8 }}>AGIRS Trend</div>
              {data.riskScore.trend.length < 2 ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                  <div style={{ width: 280, height: 80, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
                    <div style={{ textAlign: 'center' as const }}>
                      <div style={{ fontSize: 8, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.06em' }}>Current</div>
                      <div style={{ fontSize: 24, fontWeight: 700, fontFamily: FONT.mono, color: getScoreColor(score) }}>{score.toFixed(1)}</div>
                    </div>
                    <div style={{ fontSize: 16, color: COLORS.textMuted }}>{'\u2192'}</div>
                    <div style={{ textAlign: 'center' as const }}>
                      <div style={{ fontSize: 8, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.06em' }}>Potential</div>
                      <div style={{ fontSize: 24, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.success }}>{data.potentialScore > 0 ? `~${data.potentialScore}` : '\u2014'}</div>
                    </div>
                  </div>
                  <div style={{ flexShrink: 0 }}>
                    <div style={{ fontSize: 8, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.06em' }}>Improvement</div>
                    <div style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.success }}>
                      +{data.potentialScore > 0 ? (data.potentialScore - score).toFixed(1) : '0'}
                    </div>
                    <div style={{ fontSize: 8, color: COLORS.textMuted, marginTop: 2 }}>
                      Target: <span style={{ fontWeight: 600, color: COLORS.text }}>{data.riskScore.target}</span>
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                  <div>
                    <Sparkline data={data.riskScore.trend} width={280} height={80} color={getScoreColor(score)} />
                  </div>
                  <div style={{ flexShrink: 0 }}>
                    <div style={{ fontSize: 8, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Score</div>
                    <DN navigateTo="/compliance-posture">
                      <span style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: getScoreColor(score) }}>{score.toFixed(1)}</span>
                    </DN>
                    <div style={{ fontSize: 8, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 4 }}>
                      Target: <span style={{ fontWeight: 600, color: COLORS.text }}>{data.riskScore.target}</span>
                    </div>
                    {delta != null && (
                      <div style={{ fontSize: 9, fontWeight: 700, fontFamily: FONT.mono, marginTop: 2, color: delta > 0 ? COLORS.success : delta < 0 ? COLORS.danger : COLORS.textDim }}>
                        {delta > 0 ? '\u2191' : delta < 0 ? '\u2193' : '\u2192'} {delta > 0 ? '+' : ''}{delta.toFixed(1)}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </CISOCard>
          </div>

          {/* ─── Phase 3: AI Agent Risk tile (gated) ─── */}
          {agentRisk && agentRisk.total_agents > 0 && (
            <CISOCard style={{ padding: '10px 14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <div style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                  AI Agent Risk
                </div>
                {agentRisk.critical_orphans > 0 && (
                  <span style={{
                    fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
                    background: '#fef2f2', border: '1px solid #fecaca', color: '#dc2626',
                    textTransform: 'uppercase' as const,
                  }}>
                    {agentRisk.critical_orphans} Orphan{agentRisk.critical_orphans !== 1 ? 's' : ''}
                  </span>
                )}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 6 }}>
                <div style={{ textAlign: 'center' as const }}>
                  <div style={{ fontSize: 8, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.06em', fontFamily: FONT.ui }}>Total Agents</div>
                  <DN navigateTo="/identities?identity_category=service_principal&agent_filter=ai_agent">
                    <span style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: '#f59e0b' }}>{agentRisk.total_agents}</span>
                  </DN>
                </div>
                <div style={{ textAlign: 'center' as const }}>
                  <div style={{ fontSize: 8, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.06em', fontFamily: FONT.ui }}>Avg AGIRS</div>
                  <span style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: getScoreColor(agentRisk.avg_agirs) }}>{agentRisk.avg_agirs.toFixed(1)}</span>
                </div>
                <div style={{ textAlign: 'center' as const }}>
                  <div style={{ fontSize: 8, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.06em', fontFamily: FONT.ui }}>Critical Orphans</div>
                  <DN navigateTo="/identities?identity_category=service_principal&agent_filter=ai_agent">
                    <span style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: agentRisk.critical_orphans > 0 ? '#dc2626' : COLORS.success }}>{agentRisk.critical_orphans}</span>
                  </DN>
                </div>
                <div style={{ textAlign: 'center' as const }}>
                  <div style={{ fontSize: 8, color: COLORS.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.06em', fontFamily: FONT.ui }}>Highest Risk</div>
                  <div style={{ fontSize: 11, fontWeight: 600, fontFamily: FONT.ui, color: COLORS.text, marginTop: 2 }} title={agentRisk.highest_risk_agent?.display_name || ''}>
                    {agentRisk.highest_risk_agent?.display_name
                      ? (agentRisk.highest_risk_agent.display_name.length > 12
                        ? agentRisk.highest_risk_agent.display_name.substring(0, 12) + '...'
                        : agentRisk.highest_risk_agent.display_name)
                      : '\u2014'}
                  </div>
                  {agentRisk.highest_risk_agent?.risk_score > 0 && (
                    <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.mono }}>{agentRisk.highest_risk_agent.risk_score} pts</div>
                  )}
                </div>
              </div>
            </CISOCard>
          )}

          </>}

          {/* ─── Footer (28px) ─── */}
          <div style={{
            padding: '6px 12px', borderRadius: 6,
            background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            flexShrink: 0,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 10 }}>{'\uD83D\uDD12'}</span>
              <span style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                {data.tenant.isolationGuarantee}
                {' \u00B7 '}
                <span style={{ color: COLORS.textMuted }}>Identity Attack Surface \u00B7 Attack Path Analysis \u00B7 Blast Radius Simulation \u00B7 Graph-Based Risk</span>
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 8, color: COLORS.textMuted, fontFamily: FONT.ui }}>
                Org: <span style={{ fontWeight: 600, color: COLORS.text }}>{data.tenant.organizationName || data.tenant.name || '\u2014'}</span>
              </span>
              <span style={{ fontSize: 8, color: COLORS.textMuted, fontFamily: FONT.ui }}>
                Confidence: <span style={{ fontWeight: 600, color: data.tenant.scanConfidence === 'High' ? COLORS.success : COLORS.warning }}>{data.tenant.scanConfidence}</span>
              </span>
              <span style={{ fontSize: 8, color: COLORS.textMuted, fontFamily: FONT.ui }}>
                Sources: <span style={{ fontWeight: 600, color: COLORS.textSecondary }}>{data.tenant.sources.join(', ') || 'None'}</span>
              </span>
            </div>
          </div>
        </div>
      </div>
      <IdentityContextDrawer />
    </IdentityDrawerProvider>
  );
}
