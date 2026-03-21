import React from 'react';
import { useNavigate } from 'react-router-dom';

interface Props {
  value: number | string;
  route: string;
  label?: string;
  className?: string;
  style?: React.CSSProperties;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  children?: React.ReactNode;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#10b981',
  info: '#8b9dc3',
};

export function ClickableMetric({ value, route, label, className, style, severity, children }: Props) {
  const navigate = useNavigate();
  const display = children ?? (typeof value === 'number' ? value.toLocaleString() : value);
  const color = severity ? SEVERITY_COLOR[severity] : undefined;

  return (
    <span
      onClick={(e) => { e.stopPropagation(); navigate(route); }}
      title={label}
      className={className}
      style={{
        cursor: 'pointer',
        textDecorationLine: 'underline',
        textDecorationStyle: 'dotted',
        textUnderlineOffset: 3,
        color: color || undefined,
        ...style,
      }}
    >
      {display}
    </span>
  );
}
