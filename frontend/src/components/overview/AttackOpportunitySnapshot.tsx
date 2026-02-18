import React from 'react';
import { Link } from 'react-router-dom';
import { COLORS, RISK_COLORS } from '../../constants/design';

interface AttackOpportunitySnapshotProps {
  privilegedNhiCount?: number;
  dormantPrivilegedCount?: number;
  multiSubCount?: number;
  rbacModifierCount?: number;
  totalIdentities?: number;
}

interface CardConfig {
  label: string;
  value: number;
  severity: 'critical' | 'high' | 'warning';
  subtitle: string;
  link: string;
}

const SEVERITY_STYLES = {
  critical: { border: RISK_COLORS.critical.color, bg: RISK_COLORS.critical.bg, color: RISK_COLORS.critical.color },
  high: { border: RISK_COLORS.high.color, bg: RISK_COLORS.high.bg, color: RISK_COLORS.high.color },
  warning: { border: '#F59E0B', bg: '#FFFBEB', color: '#D97706' },
};

export default function AttackOpportunitySnapshot({
  privilegedNhiCount = 0,
  dormantPrivilegedCount = 0,
  multiSubCount = 0,
  rbacModifierCount = 0,
  totalIdentities = 0,
}: AttackOpportunitySnapshotProps) {
  const total = Math.max(totalIdentities, 1);

  const cards: CardConfig[] = [
    {
      label: 'Privileged NHIs',
      value: privilegedNhiCount,
      severity: 'critical',
      subtitle: `${totalIdentities > 0 ? Math.round((privilegedNhiCount / total) * 100) : 0}% of total identities`,
      link: '/identities?identity_category=service_principal&privilege_tier=0,1',
    },
    {
      label: 'Dormant Privileged',
      value: dormantPrivilegedCount,
      severity: 'high',
      subtitle: `${totalIdentities > 0 ? Math.round((dormantPrivilegedCount / total) * 100) : 0}% of total identities`,
      link: '/identities?activity_status=stale&privilege_tier=0,1',
    },
    {
      label: 'Multi-Subscription Access',
      value: multiSubCount,
      severity: 'warning',
      subtitle: `${totalIdentities > 0 ? Math.round((multiSubCount / total) * 100) : 0}% of total identities`,
      link: '/identities?multi_subscription=true',
    },
    {
      label: 'RBAC Modifiers',
      value: rbacModifierCount,
      severity: 'critical',
      subtitle: `${totalIdentities > 0 ? Math.round((rbacModifierCount / total) * 100) : 0}% of total identities`,
      link: '/identities?rbac_modifier=true',
    },
  ];

  const hasData = cards.some(c => c.value > 0);
  if (!hasData) return null;

  return (
    <div>
      <h3 className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>Attack Opportunity Snapshot</h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {cards.map(card => {
          const style = SEVERITY_STYLES[card.severity];
          return (
            <Link
              key={card.label}
              to={card.link}
              className="bg-white rounded-xl p-4 transition hover:shadow-md group"
              style={{ border: `1px solid ${COLORS.border}`, borderLeft: `4px solid ${style.border}` }}
            >
              <div className="text-[11px] uppercase tracking-wider mb-2 font-semibold" style={{ color: COLORS.textMuted }}>
                {card.label}
              </div>
              <div className="text-3xl font-extrabold tabular-nums group-hover:opacity-80 transition" style={{ color: style.color, fontFamily: "'DM Mono', monospace" }}>
                {card.value}
              </div>
              <div className="text-[10px] mt-1" style={{ color: COLORS.textSecondary }}>
                {card.subtitle}
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
