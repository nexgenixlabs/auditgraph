import React from 'react';
import { FRAMEWORK_COLORS } from '../constants/design';

type Framework = keyof typeof FRAMEWORK_COLORS;

interface ComplianceBadgeProps {
  framework: string;
}

export default function ComplianceBadge({ framework }: ComplianceBadgeProps) {
  const color = FRAMEWORK_COLORS[framework as Framework] || '#64748B';

  return (
    <span
      className="inline-block px-2 py-0.5 rounded text-[10px] font-bold tracking-wide"
      style={{
        color,
        backgroundColor: `${color}1A`, // ~10% opacity
      }}
    >
      {framework}
    </span>
  );
}

interface ComplianceBadgeGroupProps {
  frameworks: string[];
}

export function ComplianceBadgeGroup({ frameworks }: ComplianceBadgeGroupProps) {
  if (!frameworks.length) return null;
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {frameworks.map(f => <ComplianceBadge key={f} framework={f} />)}
    </div>
  );
}
