import React from 'react';

interface AudienceBadgeProps {
  label: string;
  variant: 'amber' | 'blue';
}

const VARIANTS = {
  amber: { bg: 'rgba(245, 158, 11, 0.15)', color: '#D97706', border: 'rgba(245, 158, 11, 0.3)' },
  blue: { bg: 'rgba(59, 130, 246, 0.15)', color: '#2563EB', border: 'rgba(59, 130, 246, 0.3)' },
};

export default function AudienceBadge({ label, variant }: AudienceBadgeProps) {
  const v = VARIANTS[variant];
  return (
    <span
      className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider"
      style={{ backgroundColor: v.bg, color: v.color, border: `1px solid ${v.border}` }}
    >
      {label}
    </span>
  );
}
