import React, { useEffect, useState } from 'react';
import { COLORS, RISK_COLORS } from '../constants/design';
import StaleDataBanner from '../components/StaleDataBanner';
import { useConnection } from '../contexts/ConnectionContext';
import {
  ExecutiveRiskHeader,
  AttackSurfaceRadar,
  AttackOpportunitySnapshot,
  RiskReductionPlan,
  RiskMovementPanel,
  GovernanceMaturityIndicators,
  DataIntegrityFooter,
  CompliancePostureSummary,
} from '../components/overview';
import AudienceBadge from '../components/AudienceBadge';

// ── Types ──────────────────────────────────────────────────────────

interface StatsResponse {
  total_discovery_runs: number;
  latest_run: {
    id: number;
    completed_at: string | null;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  } | null;
  previous_run?: {
    id: number;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  } | null;
}

interface InsightsData {
  privilege_tiers?: any;
  action_items?: any;
  risk_reduction_plan?: any[];
}

interface TrendRun {
  run_id: number;
  date: string | null;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface PillarData {
  score: number;
  weight: number;
  detail: Record<string, number>;
}

interface AttackSurfaceData {
  score: number;
  grade: string;
  severity: string;
  pillars: Record<string, PillarData>;
  total_identities: number;
  nhi_breakdown?: any;
  attack_opportunities?: any;
  governance?: any;
  data_integrity?: any;
  ciso_summary?: string;
}

// ── Component ──────────────────────────────────────────────────────

export default function Overview() {
  const { withConnection, selectedConnectionId } = useConnection();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [insights, setInsights] = useState<InsightsData | null>(null);
  const [trends, setTrends] = useState<TrendRun[]>([]);
  const [attackSurface, setAttackSurface] = useState<AttackSurfaceData | null>(null);
  const [compliance, setCompliance] = useState<any>(null);
  const [remediationSummary, setRemediationSummary] = useState<any>(null);
  const [cloudConfig, setCloudConfig] = useState<any>(null);
  const [driftData, setDriftData] = useState<any>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [statsRes, insightsRes] = await Promise.all([
          fetch(withConnection('/api/stats')),
          fetch(withConnection('/api/overview/insights')),
        ]);
        if (!statsRes.ok) throw new Error(`Stats API error: ${statsRes.status}`);
        const statsJson = await statsRes.json();
        const insightsJson = insightsRes.ok ? await insightsRes.json() : null;

        let trendsJson: TrendRun[] = [];
        try { const r = await fetch(withConnection('/api/trends')); if (r.ok) { const d = await r.json(); trendsJson = d.runs || []; } } catch {}

        let asJson: AttackSurfaceData | null = null;
        try { const r = await fetch(withConnection('/api/overview/attack-surface-score')); if (r.ok) asJson = await r.json(); } catch {}

        let complianceJson = null;
        try { const r = await fetch(withConnection('/api/dashboard/compliance')); if (r.ok) complianceJson = await r.json(); } catch {}

        let remSummaryJson = null;
        try { const r = await fetch(withConnection('/api/remediation-summary')); if (r.ok) remSummaryJson = await r.json(); } catch {}

        let cloudConfigJson = null;
        try { const r = await fetch('/api/tenant/config'); if (r.ok) cloudConfigJson = await r.json(); } catch {}

        let driftJson = null;
        try { const r = await fetch(withConnection('/api/drift/latest')); if (r.ok) driftJson = await r.json(); } catch {}

        if (!cancelled) {
          setStats(statsJson);
          setInsights(insightsJson);
          setTrends(trendsJson);
          setAttackSurface(asJson);
          setCompliance(complianceJson);
          setRemediationSummary(remSummaryJson);
          setCloudConfig(cloudConfigJson);
          setDriftData(driftJson);
        }
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load overview');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [selectedConnectionId]);

  const latest = stats?.latest_run;
  const prev = stats?.previous_run;

  // ── Loading ────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8" style={{ fontFamily: "'DM Sans', sans-serif" }}>
        <div className="animate-pulse space-y-5">
          <div className="h-[180px] rounded-2xl" style={{ backgroundColor: '#1E293B' }} />
          <div className="grid grid-cols-2 gap-5">
            <div className="h-[320px] rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />
            <div className="grid grid-cols-2 gap-3">
              {[1, 2, 3, 4, 5, 6].map(i => <div key={i} className="h-28 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />)}
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-28 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />)}
          </div>
          <div className="h-24 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />
          <div className="grid grid-cols-2 gap-5">
            {[1, 2].map(i => <div key={i} className="h-[280px] rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />)}
          </div>
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-20 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />)}
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-24 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />)}
          </div>
          <div className="h-12 rounded-xl" style={{ backgroundColor: COLORS.borderLight }} />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8" style={{ fontFamily: "'DM Sans', sans-serif" }}>
        <div className="rounded-xl p-6" style={{ backgroundColor: RISK_COLORS.critical.bg, border: `1px solid ${COLORS.border}` }}>
          <div className="font-semibold" style={{ color: RISK_COLORS.critical.color }}>Error loading overview</div>
          <div className="text-sm mt-1" style={{ color: COLORS.textSecondary }}>{error}</div>
          <button onClick={() => window.location.reload()} className="mt-3 px-4 py-1.5 text-sm font-medium text-white rounded-lg" style={{ backgroundColor: COLORS.brandLight }}>Retry</button>
        </div>
      </div>
    );
  }

  const improvementPotential = insights?.risk_reduction_plan?.reduce(
    (sum: number, item: any) => sum + (item.estimated_risk_reduction_pct ?? 0), 0
  ) ?? 0;

  const cloudCoverage = cloudConfig ? {
    azure: !!cloudConfig.cloud_providers?.azure?.enabled,
    aws: !!cloudConfig.cloud_providers?.aws?.enabled,
    gcp: !!cloudConfig.cloud_providers?.gcp?.enabled,
  } : undefined;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5" style={{ fontFamily: "'DM Sans', sans-serif" }}>

      {/* Page Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div>
            <h2 className="text-[22px] font-extrabold tracking-tight" style={{ color: COLORS.textPrimary }}>Executive Summary</h2>
            <p className="text-sm" style={{ color: COLORS.textSecondary }}>Strategic identity risk posture — Are we exposed?</p>
          </div>
          <AudienceBadge label="CISO / BOARD" variant="amber" />
        </div>
        <div className="text-xs" style={{ color: COLORS.textMuted }}>
          {latest?.completed_at ? `Updated ${new Date(latest.completed_at).toLocaleString()}` : 'No data yet'}
        </div>
      </div>

      <StaleDataBanner completedAt={latest?.completed_at} />

      {/* Section 1: Executive Risk Header */}
      <ExecutiveRiskHeader
        score={attackSurface?.score ?? null}
        grade={attackSurface?.grade ?? null}
        totalIdentities={latest?.total_identities ?? 0}
        criticalCount={latest?.critical_count ?? 0}
        highCount={latest?.high_count ?? 0}
        previousCritical={prev?.critical_count}
        cisoSummary={attackSurface?.ciso_summary}
        lastScan={attackSurface?.data_integrity?.last_scan}
        pillars={attackSurface?.pillars}
        nhiBreakdown={attackSurface?.nhi_breakdown}
        improvementPotential={improvementPotential}
        cloudCoverage={cloudCoverage}
      />

      {/* Section 2: Attack Surface Radar */}
      {attackSurface && (
        <AttackSurfaceRadar score={attackSurface.score} pillars={attackSurface.pillars} />
      )}

      {/* Section 3: Attack Opportunity Snapshot */}
      <AttackOpportunitySnapshot
        privilegedNhiCount={attackSurface?.attack_opportunities?.privileged_nhi_count}
        dormantPrivilegedCount={attackSurface?.attack_opportunities?.dormant_privileged_count}
        multiSubCount={attackSurface?.attack_opportunities?.multi_sub_count}
        rbacModifierCount={attackSurface?.attack_opportunities?.rbac_modifier_count}
        totalIdentities={latest?.total_identities ?? 0}
      />

      {/* Section 4: Risk Reduction Plan */}
      <RiskReductionPlan plan={insights?.risk_reduction_plan} />

      {/* Section 5: Risk Movement + NHI Dominance */}
      <RiskMovementPanel
        trends={trends}
        nhiBreakdown={attackSurface?.nhi_breakdown}
        previousRun={prev ? { critical: prev.critical_count, high: prev.high_count, total: prev.total_identities } : undefined}
        currentRun={latest ? { critical: latest.critical_count, high: latest.high_count, total: latest.total_identities } : undefined}
        driftCounts={driftData ? { new: driftData.new_identities_count ?? 0, removed: driftData.removed_identities_count ?? 0 } : undefined}
      />

      {/* Section 6: Compliance Posture Summary */}
      <CompliancePostureSummary
        frameworks={compliance?.frameworks}
        remediationPct={remediationSummary?.completion_pct}
        saGovernancePct={attackSurface?.governance?.dormant_cleanup_pct}
      />

      {/* Section 7: Governance Maturity */}
      <GovernanceMaturityIndicators governance={attackSurface?.governance} />

      {/* Section 8: Data Integrity Footer */}
      <DataIntegrityFooter dataIntegrity={attackSurface?.data_integrity} />
    </div>
  );
}
