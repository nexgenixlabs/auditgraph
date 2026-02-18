import React from 'react';
import { scoreToColor, scoreToGrade } from '../../constants/design';

interface PillarCardProps {
  name: string;
  shortName: string;
  score: number;
  weight: number;
  detail: Record<string, number>;
  expanded: boolean;
  onToggle: () => void;
}

const DETAIL_LABELS: Record<string, string> = {
  t0: 'T0 (Global Admin)',
  t0t1: 'T0+T1 Privileged',
  total: 'Total Identities',
  expired: 'Expired Credentials',
  expiring: 'Expiring (<30d)',
  with_creds: 'With Credentials',
  healthy: 'Healthy Credentials',
  guests: 'Guest Identities',
  guest_with_roles: 'Guests with Roles',
  federated: 'Federated',
  dormant: 'Dormant Identities',
  unowned_spns: 'Unowned SPNs',
  total_spns: 'Total SPNs',
  tenant_scope: 'Tenant-Wide Scope',
};

export default function PillarCard({ name, shortName, score, weight, detail, expanded, onToggle }: PillarCardProps) {
  const color = scoreToColor(score);
  const grade = scoreToGrade(score);

  // Determine top contributing metric
  const topMetric = Object.entries(detail)
    .filter(([k]) => k !== 'total' && k !== 'with_creds' && k !== 'total_spns')
    .sort(([, a], [, b]) => b - a)[0];

  return (
    <div
      className="bg-white rounded-xl p-4 cursor-pointer hover:shadow-md transition-all"
      style={{ border: `1px solid var(--border-default)`, borderLeft: `4px solid ${color}` }}
      onClick={onToggle}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="text-[12px] font-bold" style={{ color: 'var(--text-primary)' }}>{shortName}</div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-medium" style={{ color: 'var(--text-tertiary)' }}>{weight}%</span>
          <span
            className="px-1.5 py-0.5 rounded text-[10px] font-bold"
            style={{ color, backgroundColor: `${color}18` }}
          >
            {grade}
          </span>
        </div>
      </div>

      {/* Score bar */}
      <div className="h-1.5 rounded-full overflow-hidden mb-2" style={{ backgroundColor: 'var(--border-subtle)' }}>
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${Math.min(score, 100)}%`, backgroundColor: color }}
        />
      </div>

      <div className="text-[20px] font-extrabold" style={{ color }}>{Math.round(score)}</div>

      {/* Top contributing metric */}
      {topMetric && (
        <div className="text-[10px] mt-1" style={{ color: 'var(--text-secondary)' }}>
          {DETAIL_LABELS[topMetric[0]] || topMetric[0]}: {topMetric[1]}
        </div>
      )}

      {/* Expanded detail */}
      {expanded && (
        <div className="mt-3 pt-3 space-y-1.5" style={{ borderTop: '1px solid var(--border-subtle)' }}>
          {Object.entries(detail).map(([key, value]) => (
            <div key={key} className="flex items-center justify-between text-[11px]">
              <span style={{ color: 'var(--text-secondary)' }}>{DETAIL_LABELS[key] || key}</span>
              <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>{value}</span>
            </div>
          ))}
        </div>
      )}

      {/* Expand indicator */}
      <div className="flex justify-center mt-1">
        <svg
          className={`w-3 h-3 transition-transform ${expanded ? 'rotate-180' : ''}`}
          style={{ color: 'var(--text-tertiary)' }}
          fill="none" stroke="currentColor" viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>
    </div>
  );
}
