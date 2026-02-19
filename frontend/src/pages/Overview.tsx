import React, { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';

// ─── Command Center Design Tokens ───────────────────────────────────
const C = {
  bg:           '#060a13',
  surface:      '#0c1220',
  card:         '#0f1729',
  cardElevated: '#131d33',
  border:       '#1a2744',
  borderHover:  '#253a5e',
  accent:       '#FFB938',
  accentGlow:   'rgba(255,185,56,0.08)',
  accentBorder: 'rgba(255,185,56,0.18)',
  critical:     '#FF4D4D',
  high:         '#FF8C42',
  warning:      '#FFB938',
  good:         '#36D986',
  info:         '#4E9FFF',
  purple:       '#A78BFA',
  text:         '#F1F5F9',
  textSec:      '#94A3B8',
  textTer:      '#64748B',
  textDim:      '#475569',
};
const F = {
  display: "'DM Sans', 'Space Grotesk', sans-serif",
  body:    "'DM Sans', 'Outfit', sans-serif",
  mono:    "'JetBrains Mono', 'Fira Code', monospace",
};

// ─── Pillar Config ──────────────────────────────────────────────────
const PILLAR_META: Record<string, { label: string; short: string; color: string; weight: number }> = {
  effective_privilege:    { label: 'Effective Privilege',   short: 'Privilege',  color: C.critical,  weight: 30 },
  credential_risk:       { label: 'Credential Risk',       short: 'Creds',      color: C.high,      weight: 20 },
  trust_federation:      { label: 'Trust & Federation',    short: 'Trust',      color: C.purple,    weight: 20 },
  usage_dormancy:        { label: 'Usage Dormancy',        short: 'Usage',      color: C.info,      weight: 10 },
  ownership_governance:  { label: 'Ownership Governance',  short: 'Ownership',  color: C.warning,   weight: 10 },
  external_exposure:     { label: 'External Exposure',     short: 'Exposure',   color: '#E879F9',   weight: 10 },
};
const PILLAR_KEYS = Object.keys(PILLAR_META);

// ─── Types ──────────────────────────────────────────────────────────
interface PillarData { score: number; weight: number; detail: Record<string, number>; }
interface AttackSurfaceData {
  score: number; grade: string; severity: string;
  pillars: Record<string, PillarData>;
  total_identities: number;
  nhi_breakdown?: any; attack_opportunities?: any;
  governance?: any; data_integrity?: any; ciso_summary?: string;
}
interface StatsRun { id: number; completed_at: string | null; total_identities: number; critical_count: number; high_count: number; medium_count: number; }
interface StatsResponse { total_discovery_runs: number; latest_run: StatsRun | null; previous_run?: StatsRun | null; }

// ─── Helpers ────────────────────────────────────────────────────────
function scoreColor(s: number) { return s <= 30 ? C.good : s <= 60 ? C.warning : C.critical; }
function sevColor(s: string) { return ({ critical: C.critical, high: C.high, medium: C.warning, low: C.good, warning: C.warning } as any)[s] || C.textTer; }
function pct(n: number, d: number) { return d ? Math.round((n / d) * 100) : 0; }

// ─── Main Component ─────────────────────────────────────────────────
export default function Overview() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [mounted, setMounted] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [insights, setInsights] = useState<any>(null);
  const [as, setAs] = useState<AttackSurfaceData | null>(null);
  const [compliance, setCompliance] = useState<any>(null);
  const [remSum, setRemSum] = useState<any>(null);
  const [cloudConfig, setCloudConfig] = useState<any>(null);
  const [identitySummary, setIdentitySummary] = useState<any>(null);
  const [driftData, setDriftData] = useState<any>(null);
  const [prevScore, setPrevScore] = useState<number | null>(null);
  const [expandedPillar, setExpandedPillar] = useState<string | null>(null);

  useEffect(() => { setTimeout(() => setMounted(true), 50); }, []);

  useEffect(() => {
    let c = false;
    (async () => {
      setLoading(true);
      try {
        const [sR, iR] = await Promise.all([
          fetch(withConnection('/api/stats')),
          fetch(withConnection('/api/overview/insights')),
        ]);
        const sJ = sR.ok ? await sR.json() : null;
        const iJ = iR.ok ? await iR.json() : null;
        let asJ: any = null;
        try { const r = await fetch(withConnection('/api/overview/attack-surface-score')); if (r.ok) asJ = await r.json(); } catch {}
        let cJ: any = null;
        try { const r = await fetch(withConnection('/api/dashboard/compliance')); if (r.ok) cJ = await r.json(); } catch {}
        let rJ: any = null;
        try { const r = await fetch(withConnection('/api/remediation-summary')); if (r.ok) rJ = await r.json(); } catch {}
        let ccJ: any = null;
        try { const r = await fetch('/api/tenant/config'); if (r.ok) ccJ = await r.json(); } catch {}
        let isJ: any = null;
        try { const r = await fetch(withConnection('/api/identity-summary')); if (r.ok) isJ = await r.json(); } catch {}
        let dJ: any = null;
        try { const r = await fetch(withConnection('/api/drift/latest')); if (r.ok) dJ = await r.json(); } catch {}
        let trendJ: any = null;
        try { const r = await fetch(withConnection('/api/trends?limit=2')); if (r.ok) trendJ = await r.json(); } catch {}
        // Compute previous score delta from trend data
        let ps: number | null = null;
        if (trendJ?.runs?.length >= 2) {
          const runs = trendJ.runs;
          ps = Math.round(runs[runs.length - 1].avg_risk_score - runs[runs.length - 2].avg_risk_score);
        }
        if (!c) { setStats(sJ); setInsights(iJ); setAs(asJ); setCompliance(cJ); setRemSum(rJ); setCloudConfig(ccJ); setIdentitySummary(isJ); setDriftData(dJ); setPrevScore(ps); }
      } catch {}
      if (!c) setLoading(false);
    })();
    return () => { c = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedConnectionId]);

  const fadeIn = (d: number): React.CSSProperties => ({
    opacity: mounted && !loading ? 1 : 0,
    transform: mounted && !loading ? 'translateY(0)' : 'translateY(12px)',
    transition: `all 0.6s cubic-bezier(0.4,0,0.2,1) ${d}ms`,
  });

  const latest = stats?.latest_run;
  const prev = stats?.previous_run;
  const score = as?.score ?? 0;
  const grade = as?.grade ?? 'F';
  const pillars = as?.pillars ?? {};
  const nhi = as?.nhi_breakdown;
  const atk = as?.attack_opportunities;
  const gov = as?.governance;
  const di = as?.data_integrity;
  const plan = insights?.risk_reduction_plan ?? [];
  const improvPot = plan.reduce((s: number, i: any) => s + (i.estimated_risk_reduction_pct ?? 0), 0);
  const delta30d = prevScore; // null if no history, positive = worsened, negative = improved

  const cloudCov = useMemo(() => {
    if (!cloudConfig) return null;
    const cp = cloudConfig.cloud_providers || {};
    const mr = identitySummary?.monitored_resources;
    const azureSubs = mr?.azure?.subscriptions ?? 0;
    return {
      azure: { connected: !!cp.azure?.enabled, subs: azureSubs, total: azureSubs },
      aws:   { connected: !!cp.aws?.enabled, subs: mr?.aws?.accounts ?? 0 },
      gcp:   { connected: !!cp.gcp?.enabled, subs: mr?.gcp?.projects ?? 0 },
    };
  }, [cloudConfig, identitySummary]);

  // ─── Loading State ──────────────────────────────────────────────
  if (loading) {
    return (
      <div style={{ padding: '36px', maxWidth: 1400, margin: '0 auto', background: C.bg, minHeight: '100vh' }}>
        <div style={{ animation: 'pulse 2s infinite' }}>
          <div style={{ height: 180, borderRadius: 14, background: C.card, marginBottom: 22 }} />
          <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 22, marginBottom: 22 }}>
            <div style={{ height: 320, borderRadius: 14, background: C.card }} />
            <div style={{ height: 320, borderRadius: 14, background: C.card }} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 14, marginBottom: 22 }}>
            {[1,2,3,4].map(i => <div key={i} style={{ height: 140, borderRadius: 14, background: C.card }} />)}
          </div>
        </div>
        <style>{`@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }`}</style>
      </div>
    );
  }

  // ─── Render ─────────────────────────────────────────────────────
  return (
    <div style={{ padding: '28px 36px', maxWidth: 1440, margin: '0 auto', background: C.bg, minHeight: '100vh', color: C.text }}>

      {/* ═══ Section 1: Executive Risk Header ═══ */}
      <div style={{
        ...fadeIn(100),
        background: `linear-gradient(135deg, ${C.cardElevated} 0%, ${C.card} 40%, #0d1525 100%)`,
        border: `1px solid ${C.accentBorder}`, borderRadius: 14, overflow: 'hidden',
        boxShadow: `0 0 40px rgba(255,185,56,0.04)`, position: 'relative',
      }}>
        {/* Top accent line */}
        <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1,
          background: `linear-gradient(90deg, transparent, ${C.accent}30, transparent)` }} />

        <div style={{ padding: '28px 32px', display: 'flex', alignItems: 'center', gap: 32 }}>
          {/* Score Ring */}
          <ScoreRing score={score} grade={grade} size={140} />

          {/* Info */}
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: F.display, letterSpacing: -0.3 }}>
              Identity Attack Surface Score
            </div>
            <div style={{ fontSize: 12, color: C.textSec, marginTop: 4, fontFamily: F.body, maxWidth: 480 }}>
              6-pillar weighted score across privilege, credentials, trust, usage, ownership, and exposure
            </div>
            <div style={{ display: 'flex', gap: 16, marginTop: 12, flexWrap: 'wrap' }}>
              <MetaChip label="vs 30d" value={delta30d !== null ? `${delta30d > 0 ? '+' : ''}${delta30d}` : '—'} color={delta30d !== null ? (delta30d < 0 ? C.good : delta30d > 0 ? C.critical : C.textTer) : C.textTer} />
              <MetaChip label="Industry" value="61" color={C.textSec} />
              <MetaChip label="Target" value="75" color={C.good} />
              <MetaChip label="Potential" value={`+${improvPot}`} color={C.accent} glow />
            </div>
          </div>

          {/* Identity Counts */}
          <div style={{ textAlign: 'right', minWidth: 120 }}>
            <div style={{ fontSize: 10, fontFamily: F.mono, color: C.textTer, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 8 }}>
              Identities
            </div>
            <div style={{ fontSize: 32, fontWeight: 800, fontFamily: F.mono, color: C.text }}>
              {latest?.total_identities ?? 0}
            </div>
            <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end', marginTop: 8 }}>
              <CountChip label="CRIT" value={latest?.critical_count ?? 0} color={C.critical} />
              <CountChip label="HIGH" value={latest?.high_count ?? 0} color={C.high} />
            </div>
          </div>
        </div>

        {/* Coverage Footer */}
        <div style={{
          padding: '10px 32px', borderTop: `1px solid ${C.border}`, background: 'rgba(0,0,0,0.25)',
          display: 'flex', gap: 20, fontSize: 11, fontFamily: F.mono, color: C.textTer,
        }}>
          <CoverageChip label="Azure" connected={cloudCov?.azure?.connected} detail={cloudCov?.azure?.connected ? `${cloudCov.azure.subs} sub${cloudCov.azure.subs !== 1 ? 's' : ''}` : undefined} />
          <CoverageChip label="AWS" connected={cloudCov?.aws?.connected} detail={cloudCov?.aws?.connected && cloudCov.aws.subs ? `${cloudCov.aws.subs} acct${cloudCov.aws.subs !== 1 ? 's' : ''}` : undefined} />
          <CoverageChip label="GCP" connected={cloudCov?.gcp?.connected} detail={cloudCov?.gcp?.connected && cloudCov.gcp.subs ? `${cloudCov.gcp.subs} proj${cloudCov.gcp.subs !== 1 ? 's' : ''}` : undefined} />
          <span style={{ marginLeft: 'auto' }}>
            {di?.last_scan ? new Date(di.last_scan).toLocaleString() : '—'}
          </span>
        </div>
      </div>

      {/* ═══ Section 2: Risk Radar + Pillar Breakdown ═══ */}
      <div style={{ ...fadeIn(200), display: 'grid', gridTemplateColumns: '280px 1fr', gap: 22, marginTop: 22 }}>
        {/* Radar */}
        <Card>
          <SectionLabel>Risk Radar</SectionLabel>
          <div style={{ display: 'flex', justifyContent: 'center', padding: '12px 0' }}>
            <RadarChart pillars={pillars} />
          </div>
        </Card>

        {/* Pillar Breakdown */}
        <Card>
          <SectionLabel right={<span style={{ fontSize: 10, fontFamily: F.mono, color: C.textTer }}>WEIGHTED MODEL</span>}>
            Pillar Breakdown
          </SectionLabel>
          <div style={{ marginTop: 12 }}>
            {PILLAR_KEYS.map(k => {
              const p = pillars[k];
              const meta = PILLAR_META[k];
              if (!p) return null;
              const isOpen = expandedPillar === k;
              return (
                <div key={k}>
                  <button onClick={() => setExpandedPillar(isOpen ? null : k)} style={{
                    display: 'grid', gridTemplateColumns: '110px 40px 1fr 44px auto', alignItems: 'center', gap: 10,
                    width: '100%', padding: '8px 10px', borderRadius: 8, border: 'none', cursor: 'pointer',
                    background: isOpen ? C.accentGlow : 'transparent', textAlign: 'left',
                    transition: 'background 0.2s',
                  }}
                  onMouseEnter={e => { if (!isOpen) (e.currentTarget as any).style.background = `${C.surface}`; }}
                  onMouseLeave={e => { if (!isOpen) (e.currentTarget as any).style.background = 'transparent'; }}>
                    <span style={{ fontSize: 12, color: C.text, fontWeight: 500, fontFamily: F.body }}>{meta.label}</span>
                    <span style={{ fontSize: 14, fontFamily: F.mono, fontWeight: 700, color: scoreColor(p.score) }}>{p.score}</span>
                    <MiniBar value={p.score} color={scoreColor(p.score)} />
                    <span style={{ fontSize: 10, fontFamily: F.mono, color: C.textTer }}>{meta.weight}%</span>
                    <span style={{ fontSize: 10, fontFamily: F.mono, color: C.textSec }}>
                      {Object.entries(p.detail || {}).map(([dk,dv]) => `${dv} ${dk.replace(/_/g,' ')}`).slice(0,1).join('')}
                    </span>
                  </button>
                  {isOpen && (
                    <div style={{
                      margin: '4px 10px 8px', padding: '10px 14px', borderRadius: 8,
                      background: C.accentGlow, border: `1px solid ${C.accentBorder}`,
                    }}>
                      <div style={{ fontSize: 10, fontFamily: F.mono, color: C.accent, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
                        {meta.label} — Risk Drivers
                      </div>
                      {Object.entries(p.detail || {}).map(([dk, dv]) => (
                        <div key={dk} style={{ fontSize: 12, fontFamily: F.body, color: C.textSec, padding: '2px 0' }}>
                          <span style={{ color: C.text, fontFamily: F.mono, fontWeight: 600 }}>{String(dv)}</span>
                          {' '}{dk.replace(/_/g, ' ')}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      </div>

      {/* ═══ Section 3: Attack Opportunity Snapshot ═══ */}
      <div style={{ ...fadeIn(300), display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginTop: 22 }}>
        <AttackCard title="Privileged NHIs" value={atk?.privileged_nhi_count ?? 0}
          subtitle={`${pct(atk?.privileged_nhi_count ?? 0, latest?.total_identities ?? 1)}% of high privilege from machines`}
          severity="critical" />
        <AttackCard title="Dormant Privileged" value={atk?.dormant_privileged_count ?? 0}
          subtitle="Unused >90 days with active roles" severity="high" />
        <AttackCard title="Subscription Access" value={atk?.multi_sub_count ?? 0}
          subtitle="Contributor+ at subscription scope" severity="warning" />
        <AttackCard title="RBAC Modifiers" value={atk?.rbac_modifier_count ?? 0}
          subtitle="Can alter access policies directly" severity="critical" />
      </div>

      {/* ═══ Section 4: Risk Reduction Plan ═══ */}
      <div style={fadeIn(400)}>
        <Card style={{ marginTop: 22 }}>
          <SectionLabel accent right={
            <span style={{ fontSize: 12, fontFamily: F.mono, color: C.accent, fontWeight: 700 }}>
              Potential Gain: <span style={{ textShadow: `0 0 12px ${C.accent}40` }}>+{improvPot} pts</span>
            </span>
          }>
            Highest Impact Remediation
          </SectionLabel>
          <div style={{ marginTop: 14 }}>
            {plan.length === 0 ? (
              <div style={{ fontSize: 12, color: C.textTer, padding: 16, textAlign: 'center', fontFamily: F.body }}>
                No remediation items — run a discovery scan to generate recommendations
              </div>
            ) : plan.slice(0, 5).map((item: any, i: number) => (
              <RemediationRow key={i} rank={i + 1} item={item} />
            ))}
          </div>
        </Card>
      </div>

      {/* ═══ Section 5: Risk Movement + NHI Dominance ═══ */}
      <div style={{ ...fadeIn(500), display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 22, marginTop: 22 }}>
        {/* Risk Movement */}
        <Card>
          <SectionLabel>Risk Movement — 30 Days</SectionLabel>
          <div style={{ marginTop: 12 }}>
            <MovementRow label="Critical Identities" prev={prev?.critical_count} curr={latest?.critical_count} />
            <MovementRow label="High-Risk Identities" prev={prev?.high_count} curr={latest?.high_count} />
            <MovementRow label="Total Identities" prev={prev?.total_identities} curr={latest?.total_identities} />
            {driftData && (
              <>
                <MovementRow label="New Identities" prev={0} curr={driftData.new_identities_count ?? 0} />
                <MovementRow label="Removed" prev={0} curr={driftData.removed_identities_count ?? 0} inverted />
              </>
            )}
          </div>
          {/* Warning block */}
          {(atk?.privileged_nhi_count > 0 || atk?.rbac_modifier_count > 0) && (
            <div style={{
              marginTop: 14, padding: '10px 14px', borderRadius: 8,
              background: `${C.critical}06`, border: `1px solid ${C.critical}12`,
            }}>
              <div style={{ fontSize: 9, fontFamily: F.mono, color: C.critical, textTransform: 'uppercase', letterSpacing: 1.5, marginBottom: 6, fontWeight: 700 }}>
                If No Action Taken
              </div>
              {atk?.privileged_nhi_count > 0 && (
                <div style={{ fontSize: 12, color: C.textSec, fontFamily: F.body, padding: '2px 0' }}>
                  {atk.privileged_nhi_count} privileged NHIs remain without review
                </div>
              )}
              {atk?.rbac_modifier_count > 0 && (
                <div style={{ fontSize: 12, color: C.textSec, fontFamily: F.body, padding: '2px 0' }}>
                  {atk.rbac_modifier_count} RBAC modifiers unreviewed
                </div>
              )}
              <div style={{ fontSize: 12, color: C.textSec, fontFamily: F.body, padding: '2px 0' }}>
                Estimated breach impact: <span style={{ color: C.high, fontWeight: 600 }}>Moderate–High</span>
              </div>
            </div>
          )}
        </Card>

        {/* NHI Dominance */}
        <Card>
          <SectionLabel>NHI Dominance</SectionLabel>
          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 10, fontFamily: F.mono, color: C.textTer, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
              Privilege Distribution
            </div>
            <StackedBar segments={[
              { value: nhi?.nhi_pct ?? 0, color: C.high, label: `Non-Human ${nhi?.nhi_pct ?? 0}%` },
              { value: 100 - (nhi?.nhi_pct ?? 0), color: C.info, label: `Human ${100 - (nhi?.nhi_pct ?? 0)}%` },
            ]} />

            <div style={{ fontSize: 10, fontFamily: F.mono, color: C.textTer, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6, marginTop: 14 }}>
              Ownership Risk
            </div>
            <StackedBar segments={[
              { value: gov?.ownership_coverage_pct != null ? (100 - gov.ownership_coverage_pct) : 100, color: C.critical, label: `NHI Unowned ${gov?.ownership_coverage_pct != null ? (100 - gov.ownership_coverage_pct) : 100}%` },
              { value: gov?.ownership_coverage_pct ?? 0, color: C.good, label: `Owned ${gov?.ownership_coverage_pct ?? 0}%` },
            ]} />

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginTop: 14 }}>
              <StatCell label="Total SPNs" value={nhi?.service_principal ?? 0} color={C.textSec} />
              <StatCell label="Unowned" value={insights?.action_items?.unowned_spn_count ?? 0} color={C.critical} />
              <StatCell label="High Priv" value={atk?.privileged_nhi_count ?? 0} color={C.high} />
              <StatCell label="Used 24h" value={di?.total_scanned ?? '—'} color={C.good} />
              <StatCell label="Expiring" value={insights?.action_items?.expiring_credential_count ?? 0} color={C.warning} />
              <StatCell label="PIM" value={`${gov?.pim_adoption_pct ?? 0}%`} color={C.purple} />
            </div>
          </div>
        </Card>
      </div>

      {/* ═══ Section 6: Compliance Posture ═══ */}
      <div style={fadeIn(600)}>
        <Card style={{ marginTop: 22 }}>
          <SectionLabel right={
            <Badge label="Identity Controls Only" color={C.critical} />
          }>
            Compliance Posture
          </SectionLabel>
          <ComplianceSection compliance={compliance} remPct={remSum?.completion_pct} saGovPct={gov?.dormant_cleanup_pct} />
        </Card>
      </div>

      {/* ═══ Section 7: Governance Maturity ═══ */}
      <div style={{ ...fadeIn(700), display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginTop: 22 }}>
        <GovCard icon={<GovIcon d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z" color={sevColor(govSev(gov?.ownership_coverage_pct ?? 0, 80))} />}
          label="Ownership Coverage" value={`${gov?.ownership_coverage_pct ?? 0}%`}
          target="80%" color={sevColor(govSev(gov?.ownership_coverage_pct ?? 0, 80))} />
        <GovCard icon={<GovIcon d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" color={sevColor(govSev(gov?.pim_adoption_pct ?? 0, 90))} />}
          label="PIM Coverage" value={`${gov?.pim_adoption_pct ?? 0}%`}
          target="90%" color={sevColor(govSev(gov?.pim_adoption_pct ?? 0, 90))} />
        <GovCard icon={<GovIcon d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2M9 5h6M9 14l2 2 4-4" color={sevColor(govSev(gov?.privileged_under_review_pct ?? 0, 100))} />}
          label="Privileged Under Review" value={`${gov?.privileged_under_review_pct ?? 0}%`}
          target="100%" color={sevColor(govSev(gov?.privileged_under_review_pct ?? 0, 100))} />
        <GovCard icon={<GovIcon d="M22 11.08V12a10 10 0 1 1-5.93-9.14M22 4 12 14.01l-3-3" color={sevColor(govSev((gov?.access_reviews_done ?? 0) > 0 ? 62 : 0, 95))} />}
          label="Access Reviews Done" value={`${gov?.access_reviews_done ?? 0}`}
          target="95%" color={sevColor(govSev((gov?.access_reviews_done ?? 0) > 0 ? 62 : 0, 95))} />
      </div>

      {/* ═══ Section 8: Data Integrity Footer ═══ */}
      <div style={{
        ...fadeIn(800), marginTop: 22, padding: '12px 20px', borderRadius: 14,
        background: C.card, border: `1px solid ${C.border}`,
        display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap',
        fontSize: 10, fontFamily: F.mono, color: C.textTer,
      }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <span style={{
            width: 6, height: 6, borderRadius: '50%', background: C.good,
            boxShadow: `0 0 8px ${C.good}60`, display: 'inline-block',
          }} />
          <span>Confidence: <span style={{ color: C.text }}>{di?.confidence || 'High'}</span></span>
        </span>
        <span style={{ color: C.textDim }}>·</span>
        <span>Last Scan: <span style={{ color: C.textSec }}>{di?.last_scan ? new Date(di.last_scan).toUTCString().replace('GMT','UTC') : '—'}</span></span>
        <span style={{ color: C.textDim }}>·</span>
        <span>Sources: <span style={{ color: C.textSec }}>Azure RBAC, Entra ID, Graph API</span></span>
        <span style={{ color: C.textDim }}>·</span>
        <span>Duration: <span style={{ color: C.textSec }}>{di?.scan_duration_seconds ? `${di.scan_duration_seconds}s` : '—'}</span></span>
        <span style={{ color: C.textDim }}>·</span>
        <span>Completeness: <span style={{ color: C.textSec }}>{di?.data_completeness_pct ?? '—'}%</span></span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════════════════

function ScoreRing({ score, grade, size = 140 }: { score: number; grade: string; size?: number }) {
  const [animated, setAnimated] = useState(0);
  useEffect(() => { const t = setTimeout(() => setAnimated(score), 150); return () => clearTimeout(t); }, [score]);
  const r = (size - 12) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - animated / 100);
  const color = scoreColor(score);
  const filterId = 'scoreGlow';
  return (
    <div style={{ position: 'relative', width: size, height: size }}>
      {/* Radial glow */}
      <div style={{
        position: 'absolute', inset: -16, borderRadius: '50%',
        background: `radial-gradient(circle, ${color}08 0%, transparent 70%)`,
      }} />
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <defs>
          <filter id={filterId}>
            <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        {/* Track dashed overlay */}
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={C.border} strokeWidth={6} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={C.border} strokeWidth={1}
          strokeDasharray="4 8" opacity={0.3} />
        {/* Active arc */}
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={6}
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          transform={`rotate(-90 ${size/2} ${size/2})`}
          filter={`url(#${filterId})`}
          style={{ transition: 'stroke-dashoffset 1.5s cubic-bezier(0.4,0,0.2,1)' }} />
        <text x={size/2} y={size/2 - 8} textAnchor="middle" fill={color}
          style={{ fontSize: 38, fontWeight: 800, fontFamily: F.mono }}>{animated}</text>
        <text x={size/2} y={size/2 + 18} textAnchor="middle" fill={C.textTer}
          style={{ fontSize: 11, fontWeight: 600, fontFamily: F.mono, letterSpacing: 2 }}>{grade}</text>
      </svg>
    </div>
  );
}

function RadarChart({ pillars }: { pillars: Record<string, PillarData> }) {
  const size = 260; const cx = size / 2; const cy = size / 2; const maxR = 100;
  const keys = PILLAR_KEYS;
  const n = keys.length;
  const angleStep = (2 * Math.PI) / n;
  const startAngle = -Math.PI / 2;

  function polar(idx: number, r: number): [number, number] {
    const a = startAngle + idx * angleStep;
    return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  }

  const gridRings = [25, 50, 75, 100];
  const dataPoints = keys.map((k, i) => {
    const score = pillars[k]?.score ?? 0;
    const inverted = 100 - score; // lower score = larger polygon = worse
    return polar(i, (inverted / 100) * maxR);
  });
  const polygonStr = dataPoints.map(([x, y]) => `${x},${y}`).join(' ');

  return (
    <svg width={240} height={240} viewBox={`0 0 ${size} ${size}`}>
      {/* Background glow */}
      <defs>
        <radialGradient id="radarGlow"><stop offset="0%" stopColor={C.accent} stopOpacity={0.06} /><stop offset="100%" stopColor="transparent" stopOpacity={0} /></radialGradient>
        <linearGradient id="polyFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.accent} stopOpacity={0.18} /><stop offset="100%" stopColor={C.accent} stopOpacity={0.06} /></linearGradient>
      </defs>
      <circle cx={cx} cy={cy} r={maxR + 10} fill="url(#radarGlow)" />
      {/* Grid rings */}
      {gridRings.map(r => (
        <polygon key={r} points={keys.map((_, i) => polar(i, (r / 100) * maxR).join(',')).join(' ')}
          fill="none" stroke={C.border} strokeWidth={r === 50 ? 0.8 : 0.5} opacity={r === 50 ? 0.5 : 0.3} />
      ))}
      {/* Axis lines */}
      {keys.map((_, i) => {
        const [x, y] = polar(i, maxR);
        return <line key={i} x1={cx} y1={cy} x2={x} y2={y} stroke={C.border} strokeWidth={0.5} opacity={0.25} />;
      })}
      {/* Data polygon */}
      <polygon points={polygonStr} fill="url(#polyFill)" stroke={C.accent} strokeWidth={1.8} />
      {/* Data points */}
      {dataPoints.map(([x, y], i) => (
        <g key={i}>
          <circle cx={x} cy={y} r={6} fill={C.accent} opacity={0.15} />
          <circle cx={x} cy={y} r={3.5} fill={C.accent} stroke={C.bg} strokeWidth={1.5} />
        </g>
      ))}
      {/* Labels */}
      {keys.map((k, i) => {
        const [x, y] = polar(i, maxR + 22);
        const meta = PILLAR_META[k];
        return (
          <text key={k} x={x} y={y} textAnchor="middle" dominantBaseline="central"
            fill={C.textSec} style={{ fontSize: 9.5, fontFamily: F.mono }}>{meta.short}</text>
        );
      })}
    </svg>
  );
}

function Card({ children, glow, style }: { children: React.ReactNode; glow?: boolean; style?: React.CSSProperties }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${glow ? C.accentBorder : C.border}`, borderRadius: 14,
      padding: 24, position: 'relative',
      ...(glow ? { boxShadow: `0 0 40px rgba(255,185,56,0.04)` } : {}),
      ...style,
    }}>
      {glow && (
        <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1,
          background: `linear-gradient(90deg, transparent, ${C.accent}30, transparent)` }} />
      )}
      {children}
    </div>
  );
}

function SectionLabel({ children, right, accent }: { children: string; right?: React.ReactNode; accent?: boolean }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <span style={{
        fontSize: 11, fontFamily: F.mono, fontWeight: 700, textTransform: 'uppercase',
        letterSpacing: 2, color: accent ? C.accent : C.textSec, whiteSpace: 'nowrap',
      }}>{children}</span>
      <div style={{ flex: 1, height: 1, background: `linear-gradient(90deg, ${C.border}, transparent)` }} />
      {right}
    </div>
  );
}

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      fontSize: 9, fontFamily: F.mono, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6,
      padding: '2px 8px', borderRadius: 4, color, background: `${color}15`, border: `1px solid ${color}30`,
    }}>{label}</span>
  );
}

function MiniBar({ value, color }: { value: number; color: string }) {
  return (
    <div style={{ flex: 1, height: 4, background: C.border, borderRadius: 2, minWidth: 50 }}>
      <div style={{
        width: `${Math.min(value, 100)}%`, height: '100%', borderRadius: 2,
        background: color, boxShadow: `0 0 6px ${color}30`,
        transition: 'width 1s ease',
      }} />
    </div>
  );
}

function StackedBar({ segments }: { segments: { value: number; color: string; label: string }[] }) {
  const total = segments.reduce((s, seg) => s + seg.value, 0) || 1;
  return (
    <div style={{ display: 'flex', height: 26, borderRadius: 6, overflow: 'hidden', background: C.card }}>
      {segments.filter(s => s.value > 0).map((s, i) => {
        const w = (s.value / total) * 100;
        return (
          <div key={i} style={{
            width: `${w}%`, background: s.color, display: 'flex', alignItems: 'center', justifyContent: 'center',
            transition: 'width 1s ease',
          }}>
            {w > 18 && <span style={{ fontSize: 9, fontFamily: F.mono, fontWeight: 700, color: '#0a0f1a' }}>{s.label}</span>}
          </div>
        );
      })}
    </div>
  );
}

function StatCell({ label, value, color }: { label: string; value: number | string; color: string }) {
  return (
    <div style={{
      padding: '8px 10px', borderRadius: 8, background: `${color}06`, border: `1px solid ${color}10`, textAlign: 'center',
    }}>
      <div style={{ fontSize: 16, fontFamily: F.mono, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 9, fontFamily: F.mono, color: C.textTer, textTransform: 'uppercase', letterSpacing: 0.5, marginTop: 2 }}>{label}</div>
    </div>
  );
}

function MetaChip({ label, value, color, glow }: { label: string; value: string; color: string; glow?: boolean }) {
  return (
    <span style={{ fontSize: 11, fontFamily: F.mono, color: C.textTer }}>
      {label}{' '}
      <span style={{ color, fontWeight: 700, ...(glow ? { textShadow: `0 0 12px ${color}40` } : {}) }}>{value}</span>
    </span>
  );
}

function CountChip({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <span style={{ fontSize: 11, fontFamily: F.mono }}>
      <span style={{ color: C.textTer }}>{label}</span>{' '}
      <span style={{ color, fontWeight: 700 }}>{value}</span>
    </span>
  );
}

function CoverageChip({ label, connected, detail }: { label: string; connected?: boolean; detail?: string }) {
  return (
    <span>
      <span style={{ color: connected ? C.good : C.textDim }}>●</span>{' '}
      {label}{connected ? (detail ? ` ${detail}` : '') : ': Not Connected'}
    </span>
  );
}

function AttackCard({ title, value, subtitle, severity }: { title: string; value: number; subtitle: string; severity: string }) {
  const color = sevColor(severity);
  return (
    <div style={{
      background: `${color}06`, border: `1px solid ${color}20`, borderLeft: `3px solid ${color}`,
      borderRadius: 14, padding: '20px 20px 16px', position: 'relative', overflow: 'hidden',
      cursor: 'default', transition: 'all 0.25s ease',
    }}
    onMouseEnter={e => { const t = e.currentTarget; t.style.transform = 'translateY(-2px)'; t.style.borderColor = `${color}40`; }}
    onMouseLeave={e => { const t = e.currentTarget; t.style.transform = 'translateY(0)'; t.style.borderColor = `${color}20`; }}>
      {/* Decorative circle */}
      <div style={{
        position: 'absolute', top: -20, right: -20, width: 80, height: 80,
        borderRadius: '50%', background: `${color}05`,
      }} />
      <div style={{ fontSize: 10, fontFamily: F.mono, color: C.textTer, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
        {title}
      </div>
      <div style={{
        fontSize: 40, fontWeight: 900, fontFamily: F.mono, color, letterSpacing: -1,
        textShadow: `0 0 20px ${color}25`,
      }}>{value}</div>
      <div style={{ fontSize: 11, fontFamily: F.body, color: C.textSec, marginTop: 8, lineHeight: 1.4 }}>
        {subtitle}
      </div>
    </div>
  );
}

function RemediationRow({ rank, item }: { rank: number; item: any }) {
  const isFirst = rank === 1;
  const rankColor = isFirst ? C.accent : rank === 2 ? C.high : C.textDim;
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '32px 1fr 60px 60px 60px 90px', alignItems: 'center', gap: 10,
      padding: '10px 12px', borderRadius: 10, marginBottom: 4,
      background: isFirst ? C.accentGlow : 'transparent',
      border: isFirst ? `1px solid ${C.accentBorder}` : '1px solid transparent',
      transition: 'background 0.2s',
    }}
    onMouseEnter={e => { if (!isFirst) (e.currentTarget as any).style.background = C.surface; }}
    onMouseLeave={e => { if (!isFirst) (e.currentTarget as any).style.background = 'transparent'; }}>
      {/* Rank */}
      <div style={{
        width: 28, height: 28, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: `${rankColor}15`, border: `1px solid ${rankColor}30`, fontSize: 12, fontFamily: F.mono, fontWeight: 700, color: rankColor,
        ...(isFirst ? { boxShadow: `0 0 12px ${C.accent}40` } : {}),
      }}>{rank}</div>
      {/* Action */}
      <div>
        <div style={{ fontSize: 13, fontFamily: F.body, color: C.text, fontWeight: 500 }}>{item.action}</div>
        <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
          {(item.compliance_tags || []).slice(0, 4).map((tag: string) => (
            <Badge key={tag} label={tag} color={C.info} />
          ))}
        </div>
      </div>
      {/* Impact */}
      <div style={{
        fontSize: 18, fontFamily: F.mono, fontWeight: 900, color: C.good,
        textShadow: `0 0 10px ${C.good}25`, textAlign: 'center',
      }}>+{item.estimated_risk_reduction_pct ?? 0}</div>
      {/* Effort */}
      <div style={{ textAlign: 'center' }}>
        <Badge label={item.effort || 'Low'} color={item.effort === 'High' ? C.high : item.effort === 'Medium' ? C.warning : C.good} />
      </div>
      {/* Count */}
      <div style={{ fontSize: 11, fontFamily: F.mono, color: C.textSec, textAlign: 'center' }}>
        {item.affected_count ?? '—'} ids
      </div>
      {/* Action button */}
      <Link to={item.route || '/identities'} style={{
        padding: '7px 16px', borderRadius: 8, border: `1px solid ${C.accentBorder}`,
        background: C.accentGlow, color: C.accent, fontSize: 11, fontFamily: F.mono, fontWeight: 600,
        textDecoration: 'none', textAlign: 'center', transition: 'all 0.2s',
      }}
      onMouseEnter={e => { (e.currentTarget as any).style.background = `${C.accent}18`; }}
      onMouseLeave={e => { (e.currentTarget as any).style.background = C.accentGlow; }}>
        Start Fix →
      </Link>
    </div>
  );
}

function MovementRow({ label, prev, curr, inverted }: { label: string; prev?: number; curr?: number; inverted?: boolean }) {
  const p = prev ?? 0;
  const c = curr ?? 0;
  const diff = c - p;
  const improved = inverted ? diff > 0 : diff < 0;
  const worsened = inverted ? diff < 0 : diff > 0;
  const bg = improved ? `${C.good}06` : worsened ? `${C.critical}06` : 'transparent';
  const bdr = improved ? `${C.good}12` : worsened ? `${C.critical}12` : 'transparent';
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px',
      borderRadius: 6, marginBottom: 4, background: bg, border: `1px solid ${bdr}`,
    }}>
      <span style={{ fontSize: 12, fontFamily: F.body, color: C.textSec }}>{label}</span>
      <span style={{ fontFamily: F.mono, fontSize: 12 }}>
        <span style={{ color: C.textTer }}>{p}</span>
        <span style={{ color: C.textDim, margin: '0 6px' }}>→</span>
        <span style={{ color: improved ? C.good : worsened ? C.critical : C.text, fontWeight: 700 }}>{c}</span>
        {diff !== 0 && (
          <span style={{ color: improved ? C.good : C.critical, fontSize: 10, marginLeft: 6 }}>
            {improved ? '↑' : '↓'}
          </span>
        )}
      </span>
    </div>
  );
}

function ComplianceRing({ pct: percent, size = 52 }: { pct: number; size?: number }) {
  const r = (size - 8) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - percent / 100);
  const color = percent >= 80 ? C.good : percent >= 50 ? C.warning : C.critical;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={C.border} strokeWidth={4} />
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={4}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        transform={`rotate(-90 ${size/2} ${size/2})`}
        style={{ filter: `drop-shadow(0 0 3px ${color}40)`, transition: 'stroke-dashoffset 1s ease' }} />
      <text x={size/2} y={size/2 + 4} textAnchor="middle" fill={color}
        style={{ fontSize: 11, fontWeight: 800, fontFamily: F.mono }}>{percent}%</text>
    </svg>
  );
}

// SVG icon helpers for consistent rendering (no emoji)
const TierIcon = ({ d }: { d: string }) => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={C.textSec} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);
const TIER_ICONS: Record<string, React.ReactNode> = {
  core: <TierIcon d="M3 21h18M5 21V7l7-4 7 4v14M9 21v-6h6v6M9 9h.01M15 9h.01" />,
  industry: <TierIcon d="M19 21V5a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v16M3 21h18M9 7h1M9 11h1M9 15h1M14 7h1M14 11h1M14 15h1" />,
  privacy: <TierIcon d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM2 12h20M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10A15 15 0 0 1 12 2z" />,
  benchmark: <TierIcon d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />,
  fallback: <TierIcon d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2M9 5h6" />,
};

const TIER_CONFIG: Record<string, { label: string }> = {
  core: { label: 'CORE GOVERNANCE' },
  industry: { label: 'INDUSTRY' },
  privacy: { label: 'PRIVACY' },
  benchmark: { label: 'BENCHMARK' },
};

function ComplianceSection({ compliance, remPct, saGovPct }: { compliance: any; remPct?: number; saGovPct?: number }) {
  if (!compliance) return <div style={{ fontSize: 12, color: C.textTer, padding: 16, textAlign: 'center' }}>No compliance data</div>;

  const frameworks = Object.values(compliance || {}) as any[];
  const tiers: Record<string, any[]> = {};
  frameworks.forEach((fw: any) => {
    const tier = fw.tier || fw.category || 'core';
    if (!tiers[tier]) tiers[tier] = [];
    tiers[tier].push(fw);
  });

  return (
    <div style={{ marginTop: 14 }}>
      {Object.entries(tiers).map(([tier, fws]) => {
        const tc = TIER_CONFIG[tier] || { label: tier.toUpperCase() };
        const tierIcon = TIER_ICONS[tier] || TIER_ICONS.fallback;
        return (
          <div key={tier} style={{ marginBottom: 16 }}>
            {/* Tier divider */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{ display: 'inline-flex' }}>{tierIcon}</span>
              <span style={{ fontSize: 10, fontFamily: F.mono, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1.5, color: C.textTer }}>{tc.label}</span>
              <div style={{ flex: 1, height: 1, background: `linear-gradient(90deg, ${C.border}, transparent)` }} />
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
              {fws.map((fw: any) => {
                const passPct = fw.total_controls ? Math.round((fw.pass_count / fw.total_controls) * 100) : 0;
                return (
                  <div key={fw.name || fw.short_name} style={{
                    display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px',
                    background: C.surface, border: `1px solid ${C.border}`, borderRadius: 10,
                    minWidth: 180, cursor: 'default', transition: 'border-color 0.2s',
                  }}
                  onMouseEnter={e => { (e.currentTarget as any).style.borderColor = C.borderHover; }}
                  onMouseLeave={e => { (e.currentTarget as any).style.borderColor = C.border; }}>
                    <ComplianceRing pct={passPct} />
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{fw.short_name || fw.name}</div>
                      <div style={{ fontSize: 10, fontFamily: F.mono, color: C.textSec }}>
                        {fw.pass_count ?? 0}/{fw.total_controls ?? 0} controls
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {/* Bottom summary bars */}
      <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 14, marginTop: 8, display: 'flex', gap: 32 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: 11, fontFamily: F.body, color: C.textSec }}>Remediation Progress</span>
            <span style={{ fontSize: 11, fontFamily: F.mono, color: C.text, fontWeight: 600 }}>{remPct ?? 0}%</span>
          </div>
          <MiniBar value={remPct ?? 0} color={C.good} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: 11, fontFamily: F.body, color: C.textSec }}>SA Governance</span>
            <span style={{ fontSize: 11, fontFamily: F.mono, color: C.text, fontWeight: 600 }}>{saGovPct ?? 0}%</span>
          </div>
          <MiniBar value={saGovPct ?? 0} color={C.purple} />
        </div>
      </div>
    </div>
  );
}

function GovIcon({ d, color }: { d: string; color?: string }) {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={color || C.textSec} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d={d} />
    </svg>
  );
}

function GovCard({ icon, label, value, target, color }: { icon: React.ReactNode; label: string; value: string; target: string; color: string }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.border}`, borderRadius: 14,
      padding: 20, textAlign: 'center',
    }}>
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 6 }}>{icon}</div>
      <div style={{ fontSize: 10, fontFamily: F.mono, color: C.textTer, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
        {label}
      </div>
      <div style={{
        fontSize: 32, fontWeight: 900, fontFamily: F.mono, color, letterSpacing: -1,
        textShadow: `0 0 16px ${color}20`,
      }}>{value}</div>
      <div style={{ fontSize: 10, fontFamily: F.body, color: C.textTer, marginTop: 6 }}>
        Target: <span style={{ color: C.good }}>{target}</span>
      </div>
    </div>
  );
}

function govSev(value: number, target: number): string {
  const ratio = value / target;
  if (ratio >= 0.8) return 'low';
  if (ratio >= 0.5) return 'warning';
  return 'critical';
}
