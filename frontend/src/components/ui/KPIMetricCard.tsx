import React from 'react';
import { useNavigate } from 'react-router-dom';

interface KPIMetricCardProps {
  label: string;
  value: number | string;
  trend?: 'up' | 'down' | 'flat';
  trendValue?: string;
  /** If true, "up" means worse (e.g. risk count) */
  trendInverted?: boolean;
  /** Click navigates to this route for drill-down */
  to?: string;
  onClick?: () => void;
  /** Accent color for the top border stripe */
  accentColor?: string;
  /** Icon element */
  icon?: React.ReactNode;
  /** Subtitle text below the value */
  subtitle?: string;
  className?: string;
}

/**
 * KPI Metric Card — primary data display component.
 *
 * Spec: 12px border-radius, 20px padding, JetBrains Mono for values.
 * Every number is clickable for drill-down.
 */
export default function KPIMetricCard({
  label,
  value,
  trend,
  trendValue,
  trendInverted,
  to,
  onClick,
  accentColor,
  icon,
  subtitle,
  className = '',
}: KPIMetricCardProps) {
  const navigate = useNavigate();

  const handleClick = () => {
    if (onClick) onClick();
    else if (to) navigate(to);
  };

  const isClickable = !!to || !!onClick;

  const trendColor = (() => {
    if (!trend || trend === 'flat') return 'var(--text-muted)';
    const isGood = trendInverted ? trend === 'up' : trend === 'down';
    return isGood ? 'var(--accent-success)' : 'var(--accent-danger)';
  })();

  const trendArrow = trend === 'up' ? '↑' : trend === 'down' ? '↓' : '→';

  const displayValue = typeof value === 'number' ? value.toLocaleString() : value;

  // Zero-value rule: 0 uses muted color, never severity colors
  const valueColor = value === 0 || value === '0' ? 'var(--text-muted)' : 'var(--text-primary)';

  return (
    <div
      role={isClickable ? 'button' : undefined}
      tabIndex={isClickable ? 0 : undefined}
      onClick={isClickable ? handleClick : undefined}
      onKeyDown={isClickable ? e => { if (e.key === 'Enter') handleClick(); } : undefined}
      className={`kpi-card group ${isClickable ? 'cursor-pointer' : ''} ${className}`}
      style={accentColor ? { borderTopColor: accentColor, borderTopWidth: 2 } : undefined}
    >
      {/* Header: label + icon */}
      <div className="flex items-center justify-between mb-3">
        <span className="kpi-label">{label}</span>
        {icon && <span style={{ color: 'var(--text-tertiary)' }}>{icon}</span>}
      </div>

      {/* Value */}
      <div className="flex items-end gap-3">
        <span
          className="kpi-value"
          style={{
            color: valueColor,
            borderBottom: isClickable ? '1px dashed var(--border-strong)' : 'none',
          }}
        >
          {displayValue}
        </span>

        {/* Trend */}
        {trend && (
          <span className="kpi-trend mb-1" style={{ color: trendColor }}>
            {trendArrow} {trendValue}
          </span>
        )}
      </div>

      {/* Subtitle */}
      {subtitle && (
        <p className="text-xs mt-2" style={{ color: 'var(--text-tertiary)' }}>{subtitle}</p>
      )}
    </div>
  );
}
