import React from 'react';
import { COLORS, type Pillar, type KPIs, type GhostAccounts } from '../../../constants/ciso';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';

interface TopRisk {
  id: string;
  label: string;
  count: number;
  severity: string;
  score_improvement: number;
}

interface RemediationPrioritiesProps {
  pillars: Pillar[];
  kpis: KPIs;
  ghostAccounts: GhostAccounts;
  currentScore: number;
  targetScore: number;
  maxItems?: number;
  compact?: boolean;
  topRisks?: TopRisk[];
}

interface PriorityItem {
  icon: string;
  label: string;
  count: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  agirsDelta: number;
  navigateTo: string;
  description: string;
}

const SEVERITY_CONFIG = {
  critical: { color: '#dc2626', bg: 'rgba(220,38,38,0.08)', border: 'rgba(220,38,38,0.25)', icon: '\u26D4' },
  high:     { color: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.25)', icon: '\u26A0\uFE0F' },
  medium:   { color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.25)', icon: '\u2139\uFE0F' },
  low:      { color: '#10b981', bg: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.25)', icon: '\u2705' },
};

const RISK_META: Record<string, { icon: string; navigateTo: string; description: string }> = {
  dormant_privileged: { icon: '\u23F0', navigateTo: '/identities?activity_status=dormant_strict&privileged=true', description: 'Inactive accounts retaining privileged role assignments' },
  orphaned_spns:      { icon: '\u2699\uFE0F', navigateTo: '/workload-identities?owner=orphaned', description: 'Service principals without designated owners' },
  ghost_accounts:     { icon: '\uD83D\uDC7B', navigateTo: '/identity-exposures?exposure_type=disabled_with_access&status=open', description: 'Disabled accounts with active RBAC role assignments' },
  over_privileged:    { icon: '\u26A0\uFE0F', navigateTo: '/identities?pillar=effective-privilege', description: 'Identities at T0/T1 privilege tier' },
  external_exposure:  { icon: '\uD83C\uDF10', navigateTo: '/identities?pillar=external-exposure', description: 'Identities with tenant-wide scope access' },
  expired_credentials:{ icon: '\uD83D\uDD11', navigateTo: '/identities?pillar=credential-risk', description: 'Identities with expired or expiring credentials' },
};

export function RemediationPriorities({ pillars, kpis, ghostAccounts, currentScore, targetScore, maxItems, compact = false, topRisks }: RemediationPrioritiesProps) {
  // Build priority items from backend-computed top_risks if available
  const items: PriorityItem[] = [];

  if (topRisks && topRisks.length > 0) {
    // Use backend-computed values (SSOT)
    for (const risk of topRisks) {
      const meta = RISK_META[risk.id] || { icon: '\u26A0\uFE0F', navigateTo: '/identities', description: risk.label };
      items.push({
        icon: meta.icon,
        label: risk.label,
        count: risk.count,
        severity: (risk.severity as PriorityItem['severity']) || 'medium',
        agirsDelta: risk.score_improvement,
        navigateTo: meta.navigateTo,
        description: meta.description,
      });
    }
  } else {
    // Fallback: compute from pillars (legacy path)
    const ti = (pillars.reduce((s, p) => s + (p.identityCount || 0), 0)) || 1;

    const dormantPriv = kpis.dormantPrivileged.value;
    if (dormantPriv > 0) {
      const w = pillars.find(p => p.name === 'Usage Dormancy')?.weight || 10;
      items.push({
        icon: '\u23F0', label: 'Dormant Privileged Accounts', count: dormantPriv,
        severity: dormantPriv >= 5 ? 'critical' : dormantPriv >= 2 ? 'high' : 'medium',
        agirsDelta: Math.round(Math.min((dormantPriv / ti) * w, w) * 10) / 10,
        navigateTo: '/identities?activity_status=dormant_strict&privileged=true',
        description: 'Inactive accounts retaining privileged role assignments',
      });
    }

    const orphanedPillar = pillars.find(p => p.name === 'Ownership Governance');
    const orphanedCount = orphanedPillar?.identityCount || 0;
    if (orphanedCount > 0) {
      const w = orphanedPillar?.weight || 10;
      items.push({
        icon: '\u2699\uFE0F', label: 'Orphaned Service Principals', count: orphanedCount,
        severity: orphanedCount >= 10 ? 'high' : 'medium',
        agirsDelta: Math.round(Math.min((orphanedCount / ti) * w, w) * 10) / 10,
        navigateTo: '/workload-identities?owner=orphaned',
        description: 'Service principals without designated owners',
      });
    }

    const ghostCount = ghostAccounts.total;
    if (ghostCount > 0) {
      items.push({
        icon: '\uD83D\uDC7B', label: 'Ghost Accounts', count: ghostCount,
        severity: ghostCount >= 5 ? 'critical' : 'high',
        agirsDelta: Math.round(Math.min((ghostCount / ti) * 10, 10) * 10) / 10,
        navigateTo: '/identity-exposures?exposure_type=disabled_with_access&status=open',
        description: 'Disabled accounts with active RBAC role assignments',
      });
    }

    const epPillar = pillars.find(p => p.name === 'Effective Privilege');
    const overPrivCount = epPillar?.identityCount || 0;
    if (overPrivCount > 0) {
      const w = epPillar?.weight || 30;
      items.push({
        icon: '\u26A0\uFE0F', label: 'Over-Privileged Identities', count: overPrivCount,
        severity: overPrivCount >= 5 ? 'critical' : overPrivCount >= 2 ? 'high' : 'medium',
        agirsDelta: Math.round(Math.min((overPrivCount / ti) * w, w) * 10) / 10,
        navigateTo: '/identities?pillar=effective-privilege',
        description: 'Identities at T0/T1 privilege tier',
      });
    }
  }

  // Sort by agirsDelta descending
  items.sort((a, b) => b.agirsDelta - a.agirsDelta || ({ critical: 0, high: 1, medium: 2, low: 3 }[a.severity] || 3) - ({ critical: 0, high: 1, medium: 2, low: 3 }[b.severity] || 3));

  // Apply maxItems limit if specified
  const displayItems = maxItems ? items.slice(0, maxItems) : items;
  const totalDelta = Math.round(displayItems.reduce((s, i) => s + i.agirsDelta, 0) * 10) / 10;

  if (items.length === 0) {
    return (
      <CISOCard>
        <SectionTitle>Top Risks to Fix Now</SectionTitle>
        <div style={{ padding: '20px 0', textAlign: 'center' as const }}>
          <span style={{ fontSize: 24 }}>{'\u2705'}</span>
          <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.success, fontFamily: FONT.ui, marginTop: 8 }}>
            No critical remediations needed
          </div>
          <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>
            Your identity posture is in good shape.
          </div>
        </div>
      </CISOCard>
    );
  }

  return (
    <CISOCard>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <SectionTitle>Top Risks to Fix Now</SectionTitle>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui }}>
            Total potential improvement:
          </span>
          <DN navigateTo="/remediation">
            <span style={{ fontSize: 13, fontWeight: 700, fontFamily: FONT.mono, color: totalDelta > 0 ? COLORS.success : COLORS.textDim }}>+{totalDelta} pts</span>
          </DN>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {displayItems.map((item, i) => {
          const cfg = SEVERITY_CONFIG[item.severity];
          return (
            <DN key={item.label} navigateTo={item.navigateTo}>
              <div
                style={{
                  display: 'flex', alignItems: 'center', gap: compact ? 6 : 10,
                  padding: compact ? '6px' : '10px', cursor: 'pointer', transition: 'background 0.15s',
                  borderBottom: i < displayItems.length - 1 ? `1px solid ${COLORS.border}` : 'none',
                }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = cfg.bg; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
              >
                {/* Severity icon */}
                <span style={{ fontSize: compact ? 12 : 16, width: compact ? 18 : 24, textAlign: 'center', flexShrink: 0 }}>{item.icon}</span>

                {/* Count badge */}
                <div style={{
                  minWidth: compact ? 24 : 32, height: compact ? 24 : 32, borderRadius: 6, flexShrink: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: cfg.bg, border: `1px solid ${cfg.border}`,
                  fontSize: compact ? 11 : 14, fontWeight: 700, fontFamily: FONT.mono, color: cfg.color,
                }}>
                  {item.count}
                </div>

                {/* Label + description */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: compact ? 11 : 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>
                    {item.label}
                  </div>
                  {!compact && (
                    <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 2 }}>
                      {item.description}
                    </div>
                  )}
                </div>

                {/* Severity badge */}
                <span style={{
                  fontSize: compact ? 7 : 8, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
                  background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}`,
                  fontFamily: FONT.mono, textTransform: 'uppercase', flexShrink: 0,
                }}>
                  {item.severity}
                </span>

                {/* AGIRS improvement */}
                {item.agirsDelta > 0 && (
                  <div style={{ textAlign: 'right' as const, flexShrink: 0 }}>
                    <div style={{ fontSize: compact ? 11 : 13, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.success }}>+{item.agirsDelta} pts</div>
                    <div style={{ fontSize: compact ? 7 : 8, color: COLORS.textMuted, fontFamily: FONT.ui }}>AGIRS</div>
                  </div>
                )}
              </div>
            </DN>
          );
        })}
      </div>
    </CISOCard>
  );
}
