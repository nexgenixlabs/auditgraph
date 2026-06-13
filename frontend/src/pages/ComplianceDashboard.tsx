/**
 * AuditGraph — Compliance & Governance Dashboard
 *
 * Dedicated page for compliance frameworks, AGIRS breakdown, governance health,
 * and GEI components. Content moved from CISODashboard collapsible sections
 * to give compliance a full-page treatment.
 *
 * Data source: same useCISOData() hook as Executive Posture — no new API calls.
 */
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
// AG-POLISH-D (2026-06-10)
import { LoadingState } from '../components/LoadingState';
import { useAuth } from '../contexts/AuthContext';
import {
  COLORS, getTierColor, getTier, getGrade,
  type TenantData, type ComplianceFramework,
} from '../constants/ciso';
import { formatDate } from '../utils/displayHelpers';
import { FONT, ScoreRing, CISOBadge, ProgressBar, SectionTitle, CISOCard, DN } from '../components/dashboard/ciso-shared';
import { IdentityDrawerProvider } from '../contexts/IdentityDrawerContext';
import { IdentityContextDrawer } from '../components/dashboard/IdentityContextDrawer';
import { GovernanceEffectivenessTable } from '../components/dashboard/executive/GovernanceEffectivenessTable';
import { ComplianceTab } from '../components/dashboard/compliance/ComplianceTab';

// ─── Empty Data (same as CISODashboard) ────────────────────────────

function buildEmptyData(): TenantData {
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
    agirs: { agirs: null, hiri: null, nhiri: null, gei: null, dangerous_identities: [], previous: null },
  };
}

// ─── Data Hook (same 5 API calls as CISODashboard) ─

function useComplianceData(): { data: TenantData; loading: boolean } {
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();
  const [data, setData] = useState<TenantData>(buildEmptyData);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const [attackRes, compRes, trendsRes, summaryRes, agirstRes] = await Promise.all([
          fetch(withConnection('/api/overview/attack-surface-score')).catch(() => null),
          fetch(withConnection('/api/dashboard/compliance')).catch(() => null),
          fetch(withConnection('/api/trends?limit=30')).catch(() => null),
          fetch(withConnection('/api/identity-summary')).catch(() => null),
          fetch(withConnection('/api/identity-risk-summary')).catch(() => null),
        ]);

        const attack = attackRes?.ok ? await attackRes.json() : null;
        const comp = compRes?.ok ? await compRes.json() : null;
        const trends = trendsRes?.ok ? await trendsRes.json() : null;
        const summary = summaryRes?.ok ? await summaryRes.json() : null;
        const agirstData = agirstRes?.ok ? await agirstRes.json() : null;

        if (cancelled) return;
        const d = buildEmptyData();

        // ── Tenant metadata ──
        const subCount = summary?.monitored_resources?.azure?.subscriptions || 0;
        if (attack?.data_integrity) {
          const di = attack.data_integrity;
          d.tenant.id = String(di.organization_id || di.tenant_id || '');
          d.tenant.name = di.org_name || di.organization_name || '';
          d.tenant.organizationName = di.organization_name || di.org_name || '';
          d.tenant.lastScan = di.last_scan || '';
          d.tenant.scanCompleteness = di.data_completeness_pct || 0;
          d.tenant.scanConfidence = di.confidence || 'Low';
        }
        if (attack) d.tenant.identityCount = attack.total_identities || 0;
        d.tenant.subscriptions = subCount;

        // ── Risk Score ──
        if (attack) {
          const posture = Math.round((100 - (attack.score || 0)) * 10) / 10;
          d.riskScore.current = posture;
          d.riskScore.tier = getTier(posture);
          d.riskScore.grade = attack.grade ? (({ A: 'A', B: 'B', C: 'C', D: 'D', F: 'F' } as Record<string, string>)[attack.grade as string] || getGrade(posture)) : getGrade(posture);
          d.riskScore.target = attack.posture_target != null ? attack.posture_target : 90;
          d.riskScore.potentialGain = Math.max(0, d.riskScore.target - posture);
        }
        if (trends?.runs?.length) {
          d.riskScore.trend = trends.runs.map((r: any) => r.posture_score ?? 0);
        }

        // ── Pillars ──
        if (attack?.pillars) {
          const p = attack.pillars;
          const ep = p.effective_privilege || {};
          const cr = p.credential_risk || {};
          const tf = p.trust_federation || {};
          const ud = p.usage_dormancy || {};
          const og = p.ownership_governance || {};
          const ee = p.external_exposure || {};

          d.pillars = [
            { name: 'Effective Privilege', score: ep.score || 0, weight: ep.weight || 30, detail: `${ep.detail?.t0t1 || 0} IDs at T0/T1`, identityCount: ep.detail?.t0t1 || 0, subMetrics: [{ name: 'T0 (Tenant Owner)', value: ep.detail?.t0 || 0, max: attack.total_identities || 1 }, { name: 'T0+T1 privileged', value: ep.detail?.t0t1 || 0, max: attack.total_identities || 1 }] },
            { name: 'Credential Risk', score: cr.score || 0, weight: cr.weight || 20, detail: `${(cr.detail?.expired || 0) + (cr.detail?.expiring || 0)} credential issues`, identityCount: (cr.detail?.expired || 0) + (cr.detail?.expiring || 0), subMetrics: [{ name: 'Expired', value: cr.detail?.expired || 0, max: cr.detail?.with_creds || 1 }, { name: 'Expiring soon', value: cr.detail?.expiring || 0, max: cr.detail?.with_creds || 1 }] },
            { name: 'Trust & Federation', score: tf.score || 0, weight: tf.weight || 20, detail: `${tf.detail?.guest_with_roles || 0} guests with roles`, identityCount: tf.detail?.guest_with_roles || 0, subMetrics: [{ name: 'Guests with roles', value: tf.detail?.guest_with_roles || 0, max: tf.detail?.guests || 1 }] },
            { name: 'Usage Dormancy', score: ud.score || 0, weight: ud.weight || 10, detail: `${ud.detail?.dormant || 0} dormant identities`, identityCount: ud.detail?.dormant || 0, subMetrics: [{ name: 'Dormant', value: ud.detail?.dormant || 0, max: ud.detail?.total || 1 }] },
            { name: 'Ownership Governance', score: og.score || 0, weight: og.weight || 10, detail: `${og.detail?.unowned_spns || 0} unowned SPNs`, identityCount: og.detail?.unowned_spns || 0, subMetrics: [{ name: 'Unowned SPNs', value: og.detail?.unowned_spns || 0, max: og.detail?.total_spns || 1 }] },
            { name: 'External Exposure', score: ee.score || 0, weight: ee.weight || 10, detail: `${ee.detail?.tenant_scope || 0} with tenant-wide scope`, identityCount: ee.detail?.tenant_scope || 0, subMetrics: [{ name: 'Tenant-wide scope', value: ee.detail?.tenant_scope || 0, max: ee.detail?.total || 1 }] },
          ];
        }

        // ── Ghost Identities ──
        const ghostTotal = attack?.ghost_count || 0;
        d.ghostAccounts.total = ghostTotal;

        // ── Governance ──
        if (attack?.governance) {
          const gov = attack.governance;
          const ownerPct = gov.ownership_coverage_pct || 0;
          const pimPct = gov.pim_adoption_pct || 0;
          const dormantCleanupPct = gov.dormant_cleanup_pct || 0;
          const reviewPct = gov.privileged_under_review_pct || 0;
          const avgPct = (ownerPct + pimPct + dormantCleanupPct + reviewPct) / 4;
          const effScore = Math.round(avgPct / 10);
          d.governance.effectivenessScore = effScore;
          d.governance.effectivenessTier = effScore >= 8 ? 'RESILIENT' : effScore >= 5 ? 'CONTROLLED' : effScore >= 3 ? 'ELEVATED' : 'CRITICAL';
          d.governance.maturityLevel = effScore >= 8 ? 'Optimized' : effScore >= 5 ? 'Managed' : effScore >= 3 ? 'Developing' : effScore >= 1 ? 'Ad-Hoc' : 'Unknown';

          const govStatus = (pct: number) => pct >= 80 ? 'good' : pct >= 40 ? 'warning' : pct > 0 ? 'critical' : 'not-configured';
          d.governance.metrics = [
            { label: 'Ownership Coverage', value: `${Math.round(ownerPct)}%`, target: '80%', status: govStatus(ownerPct), icon: '\uD83D\uDC64' },
            { label: 'PIM Enforcement', value: pimPct > 0 ? `${Math.round(pimPct)}%` : '\u2014', target: '100%', status: govStatus(pimPct), icon: '\uD83D\uDD10' },
            { label: 'Access Reviews', value: gov.access_reviews_done > 0 ? `${gov.access_reviews_done} done` : 'No access reviews configured', target: 'quarterly', status: gov.access_reviews_done > 0 ? 'good' : 'not-configured', icon: '\uD83D\uDCCB' },
            { label: 'Privileged Monitoring', value: reviewPct > 0 ? `${Math.round(reviewPct)}%` : '\u2014', target: 'active', status: govStatus(reviewPct), icon: '\uD83D\uDCE1' },
          ];

          const preventiveItems: { label: string; count: number; color: string }[] = [];
          const operationalItems: { label: string; count: number; color: string }[] = [];
          const privT0 = attack.pillars?.effective_privilege?.detail?.t0 || 0;
          if (privT0 > 0 && pimPct < 100) preventiveItems.push({ label: 'Privilege outside PIM', count: privT0, color: COLORS.danger });
          if (ghostTotal > 0) preventiveItems.push({ label: 'Disabled accounts retain active RBAC roles', count: ghostTotal, color: COLORS.danger });
          const unownedSpns = attack.pillars?.ownership_governance?.detail?.unowned_spns || 0;
          if (unownedSpns > 0) operationalItems.push({ label: `Ownership coverage at ${Math.round(ownerPct)}%`, count: unownedSpns, color: COLORS.warning });
          const dormPriv = attack.attack_opportunities?.dormant_privileged_count || 0;
          if (dormPriv > 0) operationalItems.push({ label: 'Dormant privileged accounts active', count: dormPriv, color: COLORS.warning });

          d.governance.controlFailures = [];
          if (preventiveItems.length > 0) d.governance.controlFailures.push({ type: 'PREVENTIVE FAILURES', items: preventiveItems });
          if (operationalItems.length > 0) d.governance.controlFailures.push({ type: 'OPERATIONAL GAPS', items: operationalItems });

          const configured = [ownerPct > 0, pimPct > 0, gov.access_reviews_done > 0, reviewPct > 0].filter(Boolean).length;
          d.governance.setupCompletion = { configured, total: 4 };
        }

        // ── Compliance ──
        if (comp && typeof comp === 'object') {
          const frameworks: ComplianceFramework[] = [];
          for (const [key, fw] of Object.entries(comp) as [string, any][]) {
            if (!fw || typeof fw !== 'object' || !fw.name) continue;
            frameworks.push({
              id: key, name: fw.short_name || fw.name, type: fw.category || fw.tier || 'Industry',
              score: fw.score || 0, totalControls: fw.total_framework_controls || fw.total_controls || 0,
              failedControls: fw.fail_count || 0,
              status: fw.score >= 80 ? 'Mature' : fw.score >= 50 ? 'Developing' : fw.score > 0 ? 'Initial' : 'Not Assessed',
              trend: 0, identityImpactCount: fw.identity_controls_count || 0,
              controls: (fw.controls || []).map((c: any) => ({
                id: c.id, name: c.name, status: c.status,
                severity: c.status === 'fail' ? 'high' : 'medium',
                evidence: c.detail || '', recommendation: '', identityCount: 0,
                detectedAt: c.detected_at || c.detectedAt || d.tenant.lastScan || '',
                lastEvaluatedAt: c.last_evaluated_at || c.lastEvaluatedAt || d.tenant.lastScan || '',
              })),
            });
          }
          d.compliance.frameworks = frameworks;
          const passTotal = frameworks.reduce((s, f) => s + (f.score >= 80 ? 1 : 0), 0);
          const failTotal = frameworks.reduce((s, f) => s + (f.failedControls || 0), 0);
          d.compliance.maturity = { preventive: passTotal, detective: frameworks.length - passTotal, compensating: 0, missing: failTotal };
          const avgScore = frameworks.length > 0 ? Math.round(frameworks.reduce((s, f) => s + f.score, 0) / frameworks.length) : 0;
          d.compliance.progress = { remediation: avgScore, iaGovernance: (attack?.governance?.ownership_coverage_pct || 0) / 10 };
        }

        // ── AGIRS data ──
        if (agirstData?.agirs) {
          d.agirs = {
            agirs: agirstData.agirs, hiri: agirstData.hiri || null, nhiri: agirstData.nhiri || null,
            gei: agirstData.gei || null, dangerous_identities: agirstData.dangerous_identities || [],
            previous: agirstData.previous || null,
          };
        }
        // AGIRS client-side fallback removed — canonical /api/risk/summary provides all needed counts

        setData(d);
      } catch {
        setData(buildEmptyData());
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [selectedConnectionId, activeOrgId]);

  return { data, loading };
}

// ── Governance Tooltip ──

function GovTooltip({ text, children }: { text: string; children: React.ReactNode }) {
  const [show, setShow] = useState(false);
  return (
    <span style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
      onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)}>
      {children}
      {show && (
        <span style={{
          position: 'absolute', bottom: '100%', left: '50%', transform: 'translateX(-50%)',
          background: '#0f172a', border: `1px solid ${COLORS.border}`, padding: '6px 10px',
          borderRadius: 6, fontSize: 10, color: '#e2e8f0', maxWidth: 260, whiteSpace: 'normal',
          zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.5)', marginBottom: 6, pointerEvents: 'none',
          fontFamily: FONT.ui, lineHeight: 1.4, fontWeight: 400,
        }}>{text}</span>
      )}
    </span>
  );
}

const GOV_METRIC_TOOLTIPS: Record<string, string> = {
  'Ownership Coverage': 'Percentage of service principals with a designated owner.',
  'PIM Enforcement': 'Percentage of privileged roles protected by PIM (just-in-time activation).',
  'Access Reviews': 'Completion of periodic access certifications for privileged identities.',
  'Privileged Monitoring': 'Coverage of privileged identity activity monitoring.',
};

// ─── Main Component ────────────────────────────────────

export default function ComplianceDashboard() {
  const navigate = useNavigate();
  const { data, loading } = useComplianceData();

  if (loading) {
    return (
      <IdentityDrawerProvider>
        <div style={{
          minHeight: 'calc(100vh - 56px)', background: COLORS.bg,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          borderRadius: '12px 0 0 0',
        }}>
          {/* AG-POLISH-D (2026-06-10): drop the hand-rolled spinner */}
          <LoadingState message="Loading compliance data…" detail="Mapping controls to NIST 800-53 / CIS Azure / ISO 27001" />
        </div>
        <IdentityContextDrawer />
      </IdentityDrawerProvider>
    );
  }

  return (
    <IdentityDrawerProvider>
      <div style={{ minHeight: 'calc(100vh - 56px)', background: COLORS.bg, fontFamily: FONT.ui, borderRadius: '12px 0 0 0' }}>
        <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>

        {/* Header */}
        <div style={{
          padding: '12px 24px', borderBottom: `1px solid ${COLORS.border}`,
          background: COLORS.surface, borderRadius: '12px 0 0 0',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 15, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>Compliance & Governance</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, fontSize: 10, fontFamily: FONT.ui }}>
            <DN navigateTo="/">
              <span style={{ color: COLORS.accent, cursor: 'pointer' }}>{'\u2190'} Executive Posture</span>
            </DN>
            <span style={{ color: COLORS.textSecondary }}>Updated {formatDate(data.tenant.lastScan, 'No snapshot data')}</span>
          </div>
        </div>

        {/* Content */}
        <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 18 }}>

          {/* Section 1: Compliance Frameworks */}
          <ComplianceTab d={data} />

          {/* Section 2: Governance Health */}
          <CISOCard>
            <SectionTitle>Governance Health</SectionTitle>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {data.governance.metrics.map((m, i) => {
                  const numVal = parseFloat(String(m.value).replace(/[^0-9.]/g, ''));
                  const tooltip = GOV_METRIC_TOOLTIPS[m.label] || '';
                  const govNav = m.label.toLowerCase().includes('access review') ? '/access-reviews' :
                    m.label.toLowerCase().includes('owner') ? '/service-accounts' :
                    m.label.toLowerCase().includes('pim') ? '/identities?pillar=effective-privilege' :
                    '/service-accounts';
                  return (
                    <div key={i}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>{m.icon} {m.label}</span>
                          {tooltip && (
                            <GovTooltip text={tooltip}>
                              <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
                            </GovTooltip>
                          )}
                        </div>
                        <DN navigateTo={m.status !== 'not-configured' ? govNav : '/settings/governance'}>
                          <span style={{ fontSize: 11, fontWeight: 600, fontFamily: FONT.mono, color: m.status === 'not-configured' ? COLORS.textDim : COLORS.text }}>{m.value}</span>
                        </DN>
                      </div>
                      <ProgressBar value={isNaN(numVal) ? 0 : numVal}
                        color={m.status === 'good' ? COLORS.success : m.status === 'warning' ? COLORS.warning : m.status === 'critical' ? COLORS.danger : COLORS.textDim} />
                    </div>
                  );
                })}
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 14 }}>
                  <ScoreRing
                    score={data.governance.effectivenessScore * 10}
                    size={64} strokeWidth={4}
                    color={getTierColor(data.governance.effectivenessTier)}
                    displayValue={String(data.governance.effectivenessScore)}
                  />
                  <div>
                    <div style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text }}>{data.governance.effectivenessScore}/10</div>
                    <CISOBadge label={data.governance.effectivenessTier} color={getTierColor(data.governance.effectivenessTier)} />
                  </div>
                </div>
                {data.governance.controlFailures.map((group, gi) => (
                  <div key={gi} style={{ marginBottom: 10 }}>
                    <div style={{
                      fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em',
                      color: group.type.includes('PREVENTIVE') ? COLORS.danger : COLORS.warning,
                      marginBottom: 6, fontFamily: FONT.ui,
                    }}>{'\u25B8'} {group.type}</div>
                    {group.items.map((item, ii) => (
                      <div key={ii} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: `1px solid ${COLORS.border}` }}>
                        <span style={{ fontSize: 10, color: COLORS.text, fontFamily: FONT.ui }}>{item.label}</span>
                        <span style={{ fontSize: 10, fontWeight: 600, fontFamily: FONT.mono, color: item.color }}>{item.count}</span>
                      </div>
                    ))}
                  </div>
                ))}
                {data.governance.controlFailures.length === 0 && (
                  <div style={{ fontSize: 11, color: COLORS.success, fontFamily: FONT.ui }}>No control failures detected</div>
                )}
              </div>
            </div>
          </CISOCard>

          {/* Section 3: GEI Components */}
          <GovernanceEffectivenessTable gei={data.agirs.gei} maturity={data.compliance.maturity} />
        </div>
      </div>
      <IdentityContextDrawer />
    </IdentityDrawerProvider>
  );
}
