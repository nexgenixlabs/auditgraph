import React from 'react';
import { useNavigate } from 'react-router-dom';

interface DrillableNumberProps {
  value?: number | string;
  to: string;
  /** Optional color override (defaults to inherit) */
  color?: string;
  /** Additional className */
  className?: string;
  /** Format number with locale separators (default true) */
  format?: boolean;
  /** Tooltip text */
  title?: string;
  /** Children to render instead of value */
  children?: React.ReactNode;
}

/**
 * Wraps any stat value with click-to-navigate + dashed underline styling.
 * Every number in the platform should be clickable for drill-down.
 */
export default function DrillableNumber({
  value,
  to,
  color,
  className = '',
  format = true,
  title,
  children,
}: DrillableNumberProps) {
  const navigate = useNavigate();

  const displayValue = children ?? (typeof value === 'number' && format
    ? value.toLocaleString()
    : value);

  return (
    <span
      role="link"
      tabIndex={0}
      title={title || `Click to drill down`}
      onClick={(e) => { e.stopPropagation(); navigate(to); }}
      onKeyDown={e => { if (e.key === 'Enter') navigate(to); }}
      className={`cursor-pointer border-b border-dashed border-current hover:opacity-80 transition-opacity ${className}`}
      style={color ? { color } : undefined}
    >
      {displayValue}
    </span>
  );
}
