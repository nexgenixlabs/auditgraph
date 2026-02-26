import React from 'react';
import { useNavigate } from 'react-router-dom';
import StatusBadge from './StatusBadge';

interface ActionItemCardProps {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Number of affected entities */
  affectedCount?: number;
  /** Risk reduction points */
  riskReduction?: number;
  /** Navigation target for drill-down */
  to?: string;
  onClick?: () => void;
  /** Automation readiness badge */
  automationReady?: boolean;
  className?: string;
}

/**
 * Action Item Card — remediation/action recommendation card.
 *
 * Shows a prioritized action with severity, affected count,
 * and risk reduction potential. Always clickable.
 */
export default function ActionItemCard({
  title,
  description,
  severity,
  affectedCount,
  riskReduction,
  to,
  onClick,
  automationReady,
  className = '',
}: ActionItemCardProps) {
  const navigate = useNavigate();

  const handleClick = () => {
    if (onClick) onClick();
    else if (to) navigate(to);
  };

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={handleClick}
      onKeyDown={e => { if (e.key === 'Enter') handleClick(); }}
      className={`kpi-card cursor-pointer group ${className}`}
      style={{ borderLeftWidth: 3, borderLeftColor: `var(--accent-${severity === 'critical' ? 'danger' : severity === 'high' ? 'warning' : severity === 'medium' ? 'warning' : 'success'})` }}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <h4 className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
          {title}
        </h4>
        <StatusBadge variant={severity}>{severity}</StatusBadge>
      </div>

      <p className="text-xs mb-3" style={{ color: 'var(--text-tertiary)' }}>
        {description}
      </p>

      <div className="flex items-center gap-3 text-xs">
        {affectedCount != null && (
          <span style={{ color: 'var(--text-secondary)' }}>
            <span className="font-mono font-medium" style={{ color: 'var(--text-primary)' }}>
              {affectedCount.toLocaleString()}
            </span>{' '}
            affected
          </span>
        )}
        {riskReduction != null && (
          <span style={{ color: 'var(--accent-success)' }}>
            +{riskReduction} pts risk reduction
          </span>
        )}
        {automationReady && (
          <span
            className="px-1.5 py-0.5 rounded text-[10px] font-medium"
            style={{ backgroundColor: 'var(--tint-blue)', color: '#60a5fa' }}
          >
            AUTO
          </span>
        )}
      </div>
    </div>
  );
}
