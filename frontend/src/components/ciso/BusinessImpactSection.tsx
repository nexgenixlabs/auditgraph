import React from 'react';
import type { CISOViewModel, PostureV31Response } from '../../utils/cisoViewModel';
import { DN } from '../dashboard/ciso-shared';
import { BreachCostMethodologyButton } from './BreachCostMethodology';

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

  // AG-T1.1 / AG-T1.5: 3-scope dollar exposure — sourced from
  // breach_cost_factors, computed server-side, never hardcoded.
  // Three scopes (total / ai_reachable / nhi_reachable) so the board
  // sees WHO can touch the data, not just the bare total.
  const bi2 = bi as {
    estimated_exposure?: {
      low_display: string; mid_display: string; high_display: string;
      classified_resource_count?: number; total_records: number;
    } | null;
    exposure_by_scope?: {
      total?:         { low_display: string; mid_display: string; high_display: string; total_records: number } | null;
      ai_reachable?:  { low_display: string; mid_display: string; high_display: string; total_records: number } | null;
      nhi_reachable?: { low_display: string; mid_display: string; high_display: string; total_records: number } | null;
    } | null;
    exposure_status?: 'classification_pending' | string;
    exposure_message?: string;
  };
  const headline = bi2.estimated_exposure;
  const scopes = bi2.exposure_by_scope;
  // AG-PILOT-FIX (2026-06-08): explicit "classification pending" message
  // when fresh scan hasn't tagged data yet — better UX than hiding card
  const exposurePending = bi2.exposure_status === 'classification_pending';

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
      {headline ? (
        <DN navigateTo="/ai-access/data-reachability">
          <div className="mt-2 pt-2 border-t border-white/5 cursor-pointer hover:opacity-90 transition"
               title={`Total classified-data breach exposure across the tenant (${(headline.total_records || 0).toLocaleString()} records). Range = IBM 2023 industry low/high; mid is the headline. Each scope shows how much of this is reachable by AI agents specifically and by any non-human identity (SPN / MI / AI).`}>
            <div className="flex items-center justify-between gap-2">
              <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500">
                Estimated breach exposure · org-wide
              </p>
              {/* AG-CISO-Q (2026-06-06): the CISO's first question is "where
                  does the $ come from?" — this surfaces the methodology one click away */}
              <BreachCostMethodologyButton compact />
            </div>
            <p className="text-base font-bold font-mono text-rose-400 mt-0.5">
              {headline.mid_display}
            </p>
            <p className="text-[10px] font-mono text-gray-500">
              {headline.low_display} – {headline.high_display}
            </p>
            {scopes && (scopes.ai_reachable || scopes.nhi_reachable) ? (
              <div className="mt-2 pt-1.5 border-t border-white/5 space-y-1">
                {scopes.ai_reachable ? (
                  <div className="flex items-center justify-between gap-2"
                       title="Estimated breach exposure for data that AI agents have RBAC reach to. This is the AI-ISPM blast radius under prompt-injection or AI-credential compromise.">
                    <span className="text-[10px] text-violet-300 font-medium">AI-reachable</span>
                    <span className="text-[11px] font-bold font-mono text-violet-300">
                      {scopes.ai_reachable.mid_display}
                    </span>
                  </div>
                ) : null}
                {scopes.nhi_reachable ? (
                  <div className="flex items-center justify-between gap-2"
                       title="Estimated breach exposure for data that any non-human identity (service principal, managed identity, AI agent) can reach via RBAC.">
                    <span className="text-[10px] text-amber-300 font-medium">NHI-reachable</span>
                    <span className="text-[11px] font-bold font-mono text-amber-300">
                      {scopes.nhi_reachable.mid_display}
                    </span>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        </DN>
      ) : exposurePending ? (
        /* AG-PILOT-FIX (2026-06-08): Explicit "classification pending"
           card so the CISO sees what's coming + why no $ figure yet,
           instead of the card silently hiding. */
        <div className="mt-2 pt-2 border-t border-white/5">
          <p className="text-[10px] uppercase tracking-wider font-semibold text-gray-500">
            Estimated breach exposure
          </p>
          <p className="text-xs text-amber-400 mt-1">
            Classification pending
          </p>
          <p className="text-[10px] text-gray-500 mt-1 leading-relaxed">
            {bi2.exposure_message || 'Run a resource scan to populate breach-cost exposure.'}
          </p>
        </div>
      ) : null}
    </div>
  );
}

// ── Default export (backwards compat) ────────────────────────

export default function BusinessImpactSection({ vm }: { vm: CISOViewModel }) {
  return <BusinessImpactWidget vm={vm} />;
}
