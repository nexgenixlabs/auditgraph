import React from 'react';
import { Link } from 'react-router-dom';
import { COLORS, RISK_COLORS } from '../../constants/design';

interface PlanItem {
  priority: string;
  action: string;
  description: string;
  affected_count: number;
  estimated_risk_reduction_pct: number;
  link: string;
}

interface RiskReductionPlanProps {
  plan?: PlanItem[];
}

const PRIORITY_COLORS: Record<string, { color: string; bg: string }> = {
  critical: { color: RISK_COLORS.critical.color, bg: RISK_COLORS.critical.bg },
  high: { color: RISK_COLORS.high.color, bg: RISK_COLORS.high.bg },
  medium: { color: RISK_COLORS.medium.color, bg: RISK_COLORS.medium.bg },
};

export default function RiskReductionPlan({ plan }: RiskReductionPlanProps) {
  if (!plan || plan.length === 0) return null;

  return (
    <div>
      <h3 className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>Risk Reduction Plan</h3>
      <div className="bg-white rounded-xl overflow-hidden" style={{ border: `1px solid ${COLORS.border}` }}>
        <div className="divide-y" style={{ borderColor: COLORS.borderLight }}>
          {plan.map((item, idx) => {
            const pc = PRIORITY_COLORS[item.priority] ?? PRIORITY_COLORS.medium;
            return (
              <Link
                key={idx}
                to={item.link}
                className="flex items-start gap-4 px-5 py-4 hover:bg-gray-50 transition group"
              >
                {/* Priority badge */}
                <div className="flex-shrink-0 mt-0.5">
                  <span
                    className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase"
                    style={{ color: pc.color, backgroundColor: pc.bg }}
                  >
                    {item.priority}
                  </span>
                </div>

                {/* Description */}
                <div className="flex-1 min-w-0">
                  <div className="text-[13px] font-semibold mb-1 group-hover:text-blue-600 transition" style={{ color: COLORS.textPrimary }}>
                    {item.description}
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="text-[11px]" style={{ color: COLORS.textSecondary }}>
                      {item.affected_count} affected
                    </span>
                    {/* Risk reduction mini bar */}
                    <div className="flex items-center gap-2 flex-1 max-w-[200px]">
                      <div className="h-1.5 rounded-full overflow-hidden flex-1" style={{ backgroundColor: COLORS.borderLight }}>
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${Math.min(item.estimated_risk_reduction_pct * 5, 100)}%`,
                            backgroundColor: RISK_COLORS.low.color,
                          }}
                        />
                      </div>
                      <span className="text-[10px] font-bold" style={{ color: RISK_COLORS.low.color }}>
                        -{item.estimated_risk_reduction_pct}%
                      </span>
                    </div>
                  </div>
                </div>

                {/* Arrow */}
                <div className="flex-shrink-0 mt-1" style={{ color: COLORS.textMuted }}>
                  <span className="text-[12px] font-medium group-hover:text-blue-600 transition">
                    Start Remediation →
                  </span>
                </div>
              </Link>
            );
          })}
        </div>
      </div>
    </div>
  );
}
