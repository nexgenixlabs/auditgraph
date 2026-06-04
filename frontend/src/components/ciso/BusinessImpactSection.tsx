import React from 'react';
import type { CISOViewModel, PostureV31Response } from '../../utils/cisoViewModel';
import { DN } from '../dashboard/ciso-shared';

const LEVEL_DOT: Record<string, string> = {
  red: 'bg-[#e8465a]',
  orange: 'bg-[#FF7216]',
  yellow: 'bg-[#f59e0b]',
  green: 'bg-[#22c55e]',
};

// ── BusinessImpactWidget (legacy VM) ─────────────────────────

export function BusinessImpactWidget({ vm }: { vm: CISOViewModel }) {
  const items = vm.business_impact.slice(0, 2);

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 overflow-hidden hover:border-white/10 hover:scale-[1.01] transition flex-shrink-0"
         title={items.length > 0 ? 'Business-level risks from identity exposures' : 'No business-impacting exposures detected'}>
      <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Business Impact</span>
      {items.length === 0 ? (
        <div className="flex items-center gap-1 mt-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0" />
          <span className="text-xs text-emerald-400 font-medium">No material business risk detected</span>
        </div>
      ) : (
        <div className="space-y-1 mt-1">
          {items.map((item, i) => (
            <div key={i} className="flex items-start gap-1.5">
              <span className={`w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0 ${LEVEL_DOT[item.level] || LEVEL_DOT.yellow}`} />
              <p className="text-xs text-gray-400 truncate">{item.text}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── v3.1 Business Impact Widget ──────────────────────────────

export function BusinessImpactWidgetV31({ data }: { data: PostureV31Response }) {
  const bi = data.business_impact;
  if (!bi) {
    return (
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 overflow-hidden hover:border-white/10 transition flex-shrink-0">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Business Impact</span>
        <div className="flex items-center gap-1 mt-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0" />
          <span className="text-xs text-emerald-400 font-medium">No material business risk detected</span>
        </div>
      </div>
    );
  }

  const items: Array<{ text: string; level: string; nav: string | null }> = [];

  if (bi.inactive_admin_count > 0) {
    items.push({
      text: `${bi.inactive_admin_count} inactive admin identit${bi.inactive_admin_count !== 1 ? 'ies' : 'y'} increase${bi.inactive_admin_count === 1 ? 's' : ''} the risk of unauthorized access to critical resources`,
      level: 'red',
      nav: '/identities?activity_status=dormant_strict&privileged=true',
    });
  }
  if (bi.disabled_live_rbac_count > 0) {
    items.push({
      text: `${bi.disabled_live_rbac_count} disabled identit${bi.disabled_live_rbac_count !== 1 ? 'ies' : 'y'} still hold${bi.disabled_live_rbac_count === 1 ? 's' : ''} live RBAC roles — access not fully revoked`,
      level: 'orange',
      nav: '/identities?status=Disabled&hasRoles=true',
    });
  }

  if (items.length === 0) {
    items.push({ text: 'No material business risk detected', level: 'green', nav: null });
  }

  // AG-T1.1: dollar exposure band — sourced from breach_cost_factors,
  // computed server-side, never hardcoded. Surfaces when the org has
  // any classified resource so the board sees a $ figure not just counts.
  const exposure = (bi as { estimated_exposure?: {
    low_display: string; mid_display: string; high_display: string;
    classified_resource_count: number; total_records: number;
  } }).estimated_exposure;

  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 overflow-hidden hover:border-white/10 hover:scale-[1.01] transition flex-shrink-0"
         title="Business-level risks from identity exposures">
      <span className="text-xs text-gray-400 uppercase tracking-wider font-medium">Business Impact</span>
      <div className="space-y-1 mt-1">
        {items.slice(0, 2).map((item, i) => {
          const inner = (
            <div key={i} className={`flex items-start gap-1.5${item.nav ? ' cursor-pointer hover:opacity-80 transition' : ''}`}>
              <span className={`w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0 ${LEVEL_DOT[item.level] || LEVEL_DOT.yellow}`} />
              <p className="text-xs text-gray-400 line-clamp-2">{item.text}</p>
            </div>
          );
          return item.nav ? <DN key={i} navigateTo={item.nav}>{inner}</DN> : inner;
        })}
      </div>
      {exposure ? (
        <DN navigateTo="/ai-access/data-reachability">
          <div className="mt-2 pt-2 border-t border-white/5 cursor-pointer hover:opacity-90 transition"
               title={`Estimated breach exposure across ${exposure.classified_resource_count} classified resources (${exposure.total_records.toLocaleString()} records). Range = industry low/high; mid is headline. Source: IBM 2023.`}>
            <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500">
              Estimated breach exposure
            </p>
            <p className="text-base font-bold font-mono text-rose-400 mt-0.5">
              {exposure.mid_display}
            </p>
            <p className="text-[10px] font-mono text-gray-500">
              {exposure.low_display} – {exposure.high_display}
            </p>
          </div>
        </DN>
      ) : null}
    </div>
  );
}

// ── Default export (backwards compat) ────────────────────────

export default function BusinessImpactSection({ vm }: { vm: CISOViewModel }) {
  return <BusinessImpactWidget vm={vm} />;
}
