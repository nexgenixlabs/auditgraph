import React from 'react';
import { useNavigate } from 'react-router-dom';
import { COLORS } from '../../constants/design';

interface GovernanceData {
  ownership_coverage_pct: number;
  credential_rotation_pct: number;
  pim_adoption_pct: number;
  dormant_cleanup_pct: number;
  avg_remediation_days: number | null;
  privileged_under_review_pct?: number;
  access_reviews_done?: number;
}

interface GovernanceMaturityIndicatorsProps {
  governance?: GovernanceData;
}

interface IndicatorConfig {
  key: keyof GovernanceData;
  label: string;
  unit: string;
  greenThreshold: number;
  amberThreshold: number;
  invertCompare?: boolean;
  target?: string;
}

const INDICATORS: IndicatorConfig[] = [
  { key: 'ownership_coverage_pct', label: 'Ownership Coverage', unit: '%', greenThreshold: 90, amberThreshold: 70, target: '95%' },
  { key: 'pim_adoption_pct', label: 'PIM Coverage', unit: '%', greenThreshold: 50, amberThreshold: 25, target: '90%' },
  { key: 'privileged_under_review_pct', label: 'Privileged Under Review', unit: '%', greenThreshold: 80, amberThreshold: 50, target: '100%' },
  { key: 'access_reviews_done', label: 'Access Reviews Done', unit: '', greenThreshold: 1, amberThreshold: 0 },
];

const INDICATOR_NAV: Record<string, string> = {
  ownership_coverage_pct: '/service-accounts',
  pim_adoption_pct: '/identities',
  privileged_under_review_pct: '/access-reviews',
  access_reviews_done: '/access-reviews',
};

function getTrafficLight(value: number | null, config: IndicatorConfig): string {
  if (value == null) return '#94A3B8'; // gray
  if (config.invertCompare) {
    if (value <= config.greenThreshold) return '#22C55E';
    if (value <= config.amberThreshold) return '#F59E0B';
    return '#EF4444';
  }
  if (value >= config.greenThreshold) return '#22C55E';
  if (value >= config.amberThreshold) return '#F59E0B';
  return '#EF4444';
}

export default function GovernanceMaturityIndicators({ governance }: GovernanceMaturityIndicatorsProps) {
  const navigate = useNavigate();
  if (!governance) return null;

  return (
    <div>
      <h3 className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>Governance Maturity</h3>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {INDICATORS.map(config => {
          const rawValue = governance[config.key];
          const value = rawValue != null ? (typeof rawValue === 'number' ? rawValue : null) : null;
          const color = getTrafficLight(value, config);
          const displayValue = value != null ? (config.unit === 'd' ? value.toFixed(1) : Math.round(value)) : '—';
          const navTarget = INDICATOR_NAV[config.key];

          return (
            <button
              key={config.key}
              onClick={() => navTarget && navigate(navTarget)}
              className="bg-white rounded-xl p-4 text-center cursor-pointer hover:shadow-md transition"
              style={{ border: `1px solid ${COLORS.border}` }}
            >
              {/* Traffic light dot */}
              <div className="flex justify-center mb-2">
                <span className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
              </div>
              {/* Value */}
              <div className="text-2xl font-extrabold" style={{ color }}>
                {displayValue}
                {config.unit && <span className="text-[12px] font-normal" style={{ color: COLORS.textMuted }}>{config.unit}</span>}
              </div>
              {/* Label */}
              <div className="text-[11px] mt-1" style={{ color: COLORS.textSecondary }}>{config.label}</div>
              {/* Target */}
              {config.target && (
                <div className="text-[9px] mt-1 font-medium" style={{ color: COLORS.textMuted }}>Target: {config.target}</div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
