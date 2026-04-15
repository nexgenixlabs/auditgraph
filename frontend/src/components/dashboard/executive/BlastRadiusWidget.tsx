import React from 'react';
import { COLORS, type DangerousIdentity } from '../../../constants/ciso';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { useIdentityDrawer } from '../../../contexts/IdentityDrawerContext';

interface BlastRadiusWidgetProps {
  identities: DangerousIdentity[];
  blastRadius: {
    highRisk: number;
    lowRisk: number;
    orphaned: number;
    productionWorkloads: number;
    categories: { name: string; score: number; color: string }[];
  };
  subscriptionCount: number;
}

export function BlastRadiusWidget({ identities, blastRadius, subscriptionCount }: BlastRadiusWidgetProps) {
  const drawerCtx = useIdentityDrawer();

  // Sort by blast_radius_score descending, take top 3
  const top3 = [...identities]
    .sort((a, b) => b.blast_radius_score - a.blast_radius_score)
    .slice(0, 3);

  if (top3.length === 0) return null;

  const riskColor = (score: number) =>
    score >= 80 ? COLORS.danger : score >= 60 ? '#FF8C42' : score >= 40 ? COLORS.warning : COLORS.success;

  const tierBadge = (tier: string) => {
    const c = tier === 'T0' ? COLORS.danger : tier === 'T1' ? COLORS.elevated : COLORS.warning;
    return (
      <span style={{
        fontSize: 8, fontWeight: 700, padding: '1px 5px', borderRadius: 3,
        background: `${c}18`, color: c, border: `1px solid ${c}30`,
        fontFamily: FONT.mono,
      }}>
        {tier}
      </span>
    );
  };

  return (
    <CISOCard>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <SectionTitle>Largest Identity Blast Radius</SectionTitle>
        <DN navigateTo="/identities?sort=blast_radius_score&order=desc">
          <span style={{ fontSize: 9, color: COLORS.accent, fontFamily: FONT.ui }}>View All \u2192</span>
        </DN>
      </div>

      {/* Summary stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 14 }}>
        <div style={{ padding: '8px', borderRadius: 6, background: COLORS.surfaceAlt, textAlign: 'center' as const }}>
          <DN navigateTo="/identities?risk_level=critical">
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.danger }}>{blastRadius.highRisk}</div>
          </DN>
          <div style={{ fontSize: 8, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em' }}>High Risk</div>
        </div>
        <div style={{ padding: '8px', borderRadius: 6, background: COLORS.surfaceAlt, textAlign: 'center' as const }}>
          <DN navigateTo="/identities">
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text }}>{blastRadius.productionWorkloads}</div>
          </DN>
          <div style={{ fontSize: 8, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Workloads</div>
        </div>
        <div style={{ padding: '8px', borderRadius: 6, background: COLORS.surfaceAlt, textAlign: 'center' as const }}>
          <DN navigateTo="/workload-identities?owner=orphaned">
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: blastRadius.orphaned > 0 ? COLORS.elevated : COLORS.textDim }}>{blastRadius.orphaned}</div>
          </DN>
          <div style={{ fontSize: 8, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Orphaned</div>
        </div>
        <div style={{ padding: '8px', borderRadius: 6, background: COLORS.surfaceAlt, textAlign: 'center' as const }}>
          <DN navigateTo="/subscriptions">
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.accent }}>{subscriptionCount}</div>
          </DN>
          <div style={{ fontSize: 8, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Subscriptions</div>
        </div>
      </div>

      {/* Blast radius component bar */}
      {blastRadius.categories.some(c => c.score > 0) && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', background: COLORS.border }}>
            {blastRadius.categories.filter(c => c.score > 0).map(c => (
              <div key={c.name} style={{
                flex: c.score, background: c.color, transition: 'flex 0.8s ease',
              }} title={`${c.name}: ${c.score.toFixed(0)}%`} />
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
            {blastRadius.categories.filter(c => c.score > 0).map(c => (
              <span key={c.name} style={{ fontSize: 8, display: 'flex', alignItems: 'center', gap: 3, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                <span style={{ width: 6, height: 6, borderRadius: 2, background: c.color }} />
                {c.name}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Top 3 Identity Cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {top3.map((id, i) => {
          const c = riskColor(id.blast_radius_score);
          const shortName = id.display_name?.split(/[@.]/)[0] || 'Unknown';
          const factors = id.key_risk_factors || [];
          return (
            <div
              key={id.id}
              onClick={() => {
                const resolvedId = id.identity_id || id.id;
                if (resolvedId != null && resolvedId !== undefined) {
                  drawerCtx?.openIdentity(resolvedId, {
                    display_name: id.display_name,
                    identity_category: id.identity_category,
                  });
                }
              }}
              style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '10px', borderRadius: 6, cursor: 'pointer',
                transition: 'background 0.15s',
                borderBottom: i < top3.length - 1 ? `1px solid ${COLORS.border}` : 'none',
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = COLORS.surfaceAlt; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
            >
              {/* Rank */}
              <span style={{ fontSize: 11, fontWeight: 700, color: COLORS.textDim, fontFamily: FONT.mono, width: 18, textAlign: 'center', flexShrink: 0 }}>
                #{i + 1}
              </span>

              {/* Blast radius score ring */}
              <div style={{
                width: 36, height: 36, borderRadius: '50%', flexShrink: 0,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: `${c}15`, border: `2px solid ${c}`,
                fontSize: 11, fontWeight: 700, fontFamily: FONT.mono, color: c,
              }}>
                {id.blast_radius_score}
              </div>

              {/* Identity details */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{
                    fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {shortName}
                  </span>
                  {tierBadge(id.tier)}
                </div>
                <div style={{ display: 'flex', gap: 4, marginTop: 3, flexWrap: 'wrap' }}>
                  {factors.slice(0, 3).map((f, fi) => (
                    <span key={fi} style={{
                      fontSize: 8, fontWeight: 600, padding: '1px 5px', borderRadius: 3,
                      background: `${c}10`, color: COLORS.textSecondary,
                      border: `1px solid ${COLORS.border}`, fontFamily: FONT.ui,
                    }}>
                      {f}
                    </span>
                  ))}
                </div>
              </div>

              {/* Risk score */}
              <div style={{ textAlign: 'right' as const, flexShrink: 0 }}>
                <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui }}>Risk</div>
                <div style={{ fontSize: 13, fontWeight: 700, fontFamily: FONT.mono, color: riskColor(id.risk_score) }}>{id.risk_score}</div>
              </div>
            </div>
          );
        })}
      </div>
    </CISOCard>
  );
}
