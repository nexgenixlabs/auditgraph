import React, { useState } from 'react';
import {
  TenantData, Nav,
  F, P, KPI_NAV, PILLAR_NAV, WORKLOAD_NAV, LIFECYCLE_NAV,
  getPillarColor,
  Card, SectionTitle, RadarChart, SeverityDot, DrillableNumber,
  MiniProgressBar, TooltipWrap, WorkloadTable,
} from './overview-shared';

export function IdentityRiskTab({ d, nav }: { d: TenantData; nav: Nav }) {
  const [expandedPillar, setExpandedPillar] = useState<number | null>(null);
  const we = d.workloadExposure;
  const expDist = we.exposureDistribution;
  const totalExp = expDist.critical + expDist.high + expDist.medium + expDist.low;
  const lc = we.lifecycleState;
  const totalLc = lc.active + lc.stale + lc.dormant + lc.blind;

  return (
    <div>
      {/* ROW 1: Radar + Pillar Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', gap: 16, marginBottom: 16 }}>
        <Card style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <RadarChart pillars={d.pillars} size={200} onLabelClick={(i) => setExpandedPillar(expandedPillar === i ? null : i)} />
        </Card>
        <Card>
          <SectionTitle right={<span style={{ fontFamily: F.data, fontSize: 9, color: P.textDim }}>Weighted Model</span>}>Pillar Breakdown</SectionTitle>
          <div style={{ fontFamily: F.ui, fontSize: 10, fontStyle: 'italic', color: P.textDim, marginBottom: 10, padding: '4px 10px', background: P.accentIndigoFaint, borderRadius: 4, display: 'inline-block' }}>
            Score scale: 0 = no risk &middot; 100 = maximum risk
          </div>
          {d.pillars.map((p, i) => {
            const pc = getPillarColor(p.score);
            const expanded = expandedPillar === i;
            return (
              <div key={i}>
                <div
                  style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 0', cursor: 'pointer', background: expanded ? P.bgSubtle : 'transparent', borderRadius: 6, paddingLeft: 8, paddingRight: 8 }}
                  onClick={() => setExpandedPillar(expanded ? null : i)}
                >
                  <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, width: 12 }}>{expanded ? '\u25BE' : '\u25B8'}</span>
                  <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textLight, flex: 1 }}>{p.name}</span>
                  <span style={{ fontFamily: F.data, fontSize: 13, fontWeight: 700, color: pc, minWidth: 32, textAlign: 'right' }}><DrillableNumber value={p.score} label={`Drill into ${p.name}`} onClick={() => nav(PILLAR_NAV[p.name] || '/identities')} /></span>
                  <div style={{ width: 80 }}><MiniProgressBar value={p.score} color={pc} height={4} /></div>
                  <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, minWidth: 28 }}>{p.weight}%</span>
                  <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, minWidth: 80 }}>{p.detail}</span>
                </div>
                {expanded && (
                  <div style={{ paddingLeft: 32, paddingBottom: 8, transition: 'max-height 0.3s ease' }}>
                    {p.drilldown.map((dd, j) => (
                      <div key={j} style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6 }}>
                        <SeverityDot severity={dd.impact} />
                        <span style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted }}>{dd.label}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </Card>
      </div>

      {/* ROW 2: KPI Cards (4 columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 16 }}>
        {[
          { title: 'Privileged NHIs', ...d.kpis.privilegedNHIs },
          { title: 'Dormant Privileged', ...d.kpis.dormantPrivileged },
          { title: 'Subscription Access', ...d.kpis.subscriptionAccess },
          { title: 'RBAC Modifiers', ...d.kpis.rbacModifiers },
        ].map((k, i) => (
          <Card key={i}>
            <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, textTransform: 'uppercase', letterSpacing: 1.5, marginBottom: 8 }}>{k.title}</div>
            <div style={{ fontFamily: F.data, fontSize: 36, fontWeight: 800, color: P.textBright }}><DrillableNumber value={k.count} label={`Drill into ${k.title}`} onClick={() => nav(KPI_NAV[k.title] || '/identities')} /></div>
            <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted, marginTop: 4 }}>{k.description}</div>
          </Card>
        ))}
      </div>

      {/* ROW 3: Identity-to-Workload Blast Radius */}
      <Card style={{ marginBottom: 16 }}>
        <SectionTitle right={<span style={{ fontFamily: F.data, fontSize: 10, color: P.accentIndigo, cursor: 'pointer' }}>Deep Dive &rarr;</span>}>
          Identity-to-Workload Blast Radius
        </SectionTitle>

        {/* Exposure Distribution Bar */}
        <div style={{ display: 'flex', height: 20, borderRadius: 4, overflow: 'hidden', marginBottom: 12 }}>
          {totalExp > 0 && [
            { key: 'critical', count: expDist.critical, color: '#ff4444' },
            { key: 'high', count: expDist.high, color: '#ff8c00' },
            { key: 'medium', count: expDist.medium, color: '#eab308' },
            { key: 'low', count: expDist.low, color: '#22c55e' },
          ].map(s => s.count > 0 ? (
            <div key={s.key} title={`${s.key}: ${s.count}`} onClick={() => nav(`/workload-identities?risk_level=${s.key}`)}
              style={{ width: `${(s.count / totalExp) * 100}%`, background: s.color, transition: 'width 0.5s ease', cursor: 'pointer' }} />
          ) : null)}
        </div>
        <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
          {[{ l: 'Avg Score', v: we.avgScore.toFixed(1) }, { l: 'Can Escalate', v: we.canEscalate }, { l: 'Orphaned', v: we.orphaned }].map(s => (
            <div key={s.l}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, textTransform: 'uppercase' }}>{s.l}</div>
              <div style={{ fontFamily: F.data, fontSize: 18, fontWeight: 700, color: P.textLight }}><DrillableNumber value={s.v} label={`Drill into ${s.l}`} onClick={() => nav(WORKLOAD_NAV[s.l] || '/workload-identities')} /></div>
            </div>
          ))}
        </div>

        {/* Component Averages */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 16 }}>
          {we.componentAverages.map((c, i) => {
            const pct = (c.score / c.max) * 100;
            const cc = pct >= 80 ? '#ff4444' : pct >= 50 ? '#ff8c00' : pct >= 20 ? '#eab308' : '#22c55e';
            return (
              <div key={i} style={{ textAlign: 'center' }}>
                <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, marginBottom: 4 }}>{c.name}</div>
                <div style={{ fontFamily: F.data, fontSize: 14, fontWeight: 700, color: cc }}><DrillableNumber value={c.score.toFixed(1)} label={`Drill into ${c.name}`} onClick={() => nav('/workload-identities')} /></div>
                <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint }}>/{c.max}</div>
                <MiniProgressBar value={c.score} max={c.max} color={cc} height={3} />
              </div>
            );
          })}
        </div>

        {/* Lifecycle State Bar */}
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, marginBottom: 4, textTransform: 'uppercase' }}>Lifecycle State</div>
          <div style={{ display: 'flex', height: 16, borderRadius: 4, overflow: 'hidden' }}>
            {totalLc > 0 && [
              { key: 'Active', count: lc.active, color: '#22c55e' },
              { key: 'Stale', count: lc.stale, color: '#eab308' },
              { key: 'Dormant', count: lc.dormant, color: '#ff8c00' },
              { key: 'Blind', count: lc.blind, color: P.textDim },
            ].map(s => s.count > 0 ? (
              <TooltipWrap key={s.key} content={s.key === 'Blind' ? we.blindTooltip : `${s.key}: ${s.count}`}>
                <div onClick={() => nav(LIFECYCLE_NAV[s.key] || '/identities')} style={{ width: `${(s.count / totalLc) * 100}%`, background: s.color, height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
                  <span style={{ fontFamily: F.data, fontSize: 8, color: '#fff', textShadow: '0 1px 2px rgba(0,0,0,0.5)' }}>{s.key} {s.count}</span>
                </div>
              </TooltipWrap>
            ) : null)}
          </div>
        </div>

        {/* Zombies / Cross Sub / Tenant Scope */}
        <div style={{ display: 'flex', gap: 16 }}>
          {[{ l: 'Zombies', v: we.zombies }, { l: 'Cross-Sub', v: we.crossSub }, { l: 'Tenant Scope', v: we.tenantScope }].map(s => (
            <div key={s.l} style={{ padding: '8px 14px', background: P.bgHover, borderRadius: 6 }}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, textTransform: 'uppercase' }}>{s.l}</div>
              <div style={{ fontFamily: F.data, fontSize: 18, fontWeight: 700, color: P.textLight }}><DrillableNumber value={s.v} label={`Drill into ${s.l}`} onClick={() => nav(WORKLOAD_NAV[s.l] || '/identities')} /></div>
            </div>
          ))}
        </div>
      </Card>

      {/* ROW 4: Top Affected Production Workloads */}
      {we.topAffectedWorkloads.length > 0 && (
        <Card>
          <SectionTitle>Top Affected Production Workloads</SectionTitle>
          <WorkloadTable workloads={we.topAffectedWorkloads} />
        </Card>
      )}
    </div>
  );
}
