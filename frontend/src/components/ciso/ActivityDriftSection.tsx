import React from 'react';
import type { CISOViewModel, PostureV31Response } from '../../utils/cisoViewModel';
import { DN } from '../dashboard/ciso-shared';

// ── Drift insight (legacy VM) ────────────────────────────────

function driftInsight(vm: CISOViewModel): string {
  const d = vm.drift_summary;
  if (!d.available) return 'Run a second scan to detect drift';
  if (!d.has_drift) return 'No configuration changes since last scan';
  if (d.role_changes > 0 && d.permission_changes > 0) {
    return `${d.role_changes} role and ${d.permission_changes} permission change${d.permission_changes !== 1 ? 's' : ''} detected`;
  }
  if (d.role_changes > 0) return `${d.role_changes} role assignment${d.role_changes !== 1 ? 's' : ''} changed`;
  if (d.permission_changes > 0) return `${d.permission_changes} permission${d.permission_changes !== 1 ? 's' : ''} modified`;
  if (d.credential_changes > 0) return `${d.credential_changes} credential${d.credential_changes !== 1 ? 's' : ''} rotated or added`;
  return `${d.total_changes} change${d.total_changes !== 1 ? 's' : ''} since last scan`;
}

// ── DriftWidget (legacy VM) ──────────────────────────────────

export function DriftWidget({ vm }: { vm: CISOViewModel }) {
  const d = vm.drift_summary;
  const insight = driftInsight(vm);

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 overflow-hidden hover:border-white/10 hover:scale-[1.01] transition flex-shrink-0"
         title={d.available ? (d.has_drift ? `${d.total_changes} changes` : 'No drift') : 'Need second scan'}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Drift</span>
        <DN navigateTo="/drift">
          <span className="text-xs text-[#24A2A1] cursor-pointer">History →</span>
        </DN>
      </div>
      {d.available && !d.has_drift ? (
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0" />
          <span className="text-xs text-emerald-400 font-medium">Stable</span>
        </div>
      ) : d.available && d.has_drift ? (
        <div>
          <div className="flex items-baseline gap-1 mb-0.5">
            <span className="text-lg font-semibold text-gray-100 leading-none font-mono">{d.total_changes}</span>
            <span className="text-xs text-gray-400">changes</span>
          </div>
          <p className="text-xs text-gray-400 line-clamp-2">{insight}</p>
        </div>
      ) : (
        <p className="text-xs text-gray-400 line-clamp-2">{insight}</p>
      )}
    </div>
  );
}

// ── v3.1 Drift Widget ────────────────────────────────────────

const DRIFT_TYPE_LABEL: Record<string, string> = {
  ROLE_ADDED: 'Roles added',
  ROLE_REMOVED: 'Roles removed',
  PRIVILEGE_CHANGE: 'Privilege changes',
  STATE_CHANGE: 'State changes',
  NEW_IDENTITY: 'New identities',
  CREDENTIAL_CHANGE: 'Credential changes',
};

const DRIFT_TYPE_PREFIX: Record<string, { symbol: string; cls: string }> = {
  ROLE_ADDED: { symbol: '+', cls: 'text-red-400' },
  ROLE_REMOVED: { symbol: '\u2212', cls: 'text-emerald-400' },
  PRIVILEGE_CHANGE: { symbol: '\u0394', cls: 'text-amber-400' },
  STATE_CHANGE: { symbol: '\u0394', cls: 'text-amber-400' },
  NEW_IDENTITY: { symbol: '+', cls: 'text-blue-400' },
  CREDENTIAL_CHANGE: { symbol: '\u0394', cls: 'text-amber-400' },
};

export function DriftWidgetV31({ data }: { data: PostureV31Response }) {
  const drift = data.drift;

  // No drift data yet (first scan)
  if (!drift) {
    return (
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 overflow-hidden hover:border-white/10 transition flex-shrink-0">
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Drift</span>
          <DN navigateTo="/drift">
            <span className="text-xs text-[#24A2A1] cursor-pointer">History →</span>
          </DN>
        </div>
        <p className="text-xs text-gray-400">Run a second scan to detect drift</p>
      </div>
    );
  }

  // No changes
  if (!drift.has_drift) {
    return (
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 overflow-hidden hover:border-white/10 transition flex-shrink-0">
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Drift</span>
          <DN navigateTo="/drift">
            <span className="text-xs text-[#24A2A1] cursor-pointer">History →</span>
          </DN>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0" />
          <span className="text-xs text-emerald-400 font-medium">Stable</span>
        </div>
      </div>
    );
  }

  // Compute impact class from change types
  const types = new Set(drift.changes.map(c => c.type));
  const impactClass = types.has('PRIVILEGE_CHANGE') ? 'high'
    : types.has('ROLE_ADDED') ? 'medium'
    : 'low';
  const impactColor = impactClass === 'high' ? '#e8465a'
    : impactClass === 'medium' ? '#f59e0b'
    : '#6b7280';

  // Has changes
  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 overflow-hidden hover:border-white/10 hover:scale-[1.01] transition flex-shrink-0">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Drift</span>
        <DN navigateTo="/drift">
          <span className="text-xs text-[#24A2A1] cursor-pointer">History →</span>
        </DN>
      </div>
      <div className="flex items-baseline gap-1 mb-1">
        <span className="text-lg font-semibold text-gray-100 leading-none font-mono">{drift.total_changes}</span>
        <span className="text-xs text-gray-400">changes detected since last scan <span style={{ color: impactColor }}>({impactClass} impact)</span></span>
      </div>
      <div className="space-y-0.5">
        {drift.changes.slice(0, 3).map(c => {
          const prefix = DRIFT_TYPE_PREFIX[c.type];
          return (
            <div key={c.type} className="flex items-center justify-between text-xs">
              <span className="text-gray-400 flex items-center gap-1">
                {prefix && <span className={`font-mono ${prefix.cls}`}>{prefix.symbol}</span>}
                {DRIFT_TYPE_LABEL[c.type] || c.type}
              </span>
              <span className="font-mono text-gray-300">{c.count}</span>
            </div>
          );
        })}
      </div>
      <p className="text-[10px] mt-1" style={{ color: impactColor }}>
        {impactClass === 'high' ? '\u26A0 Privilege escalation detected \u2014 review required'
         : impactClass === 'medium' ? 'Role assignments modified \u2014 verify intent'
         : '\u2713 No negative drift \u2014 no new privilege exposure since last scan'}
      </p>
    </div>
  );
}

// ── Default export (backwards compat) ────────────────────────

export default function ActivityDriftSection({ vm }: { vm: CISOViewModel }) {
  return <DriftWidget vm={vm} />;
}
