/**
 * AG-PHASE1+4 (2026-06-09) — NHI Inventory hero page.
 *
 * The SailPoint-killer numbers screen: a single pane that tells the
 * CISO exactly how many non-human identities exist in their tenant,
 * broken down by type / trust / lifecycle / ownership state.
 *
 * This is the page that should answer the CISO's first question:
 *   "Show me ALL identities that are not human."
 *
 * Composes data from /api/identities (filtered to NHI categories)
 * plus per-bucket counts. Stub today; rich pivots in Phase 4.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
// AG-POLISH-C (2026-06-10): jargon tooltips
import { TermTooltip } from '../components/TermTooltip';

interface NhiStats {
  service_principals: number;
  managed_identity_system: number;
  managed_identity_user: number;
  workloads: number;
  ai_agents: number;
  ci_cd: number;          // GitHub Actions / Azure DevOps / Terraform Cloud
  unowned: number;
  dormant: number;
  critical: number;
  expired_secrets: number;
  federated_only: number;
  total: number;
}

const EMPTY_STATS: NhiStats = {
  service_principals: 0,
  managed_identity_system: 0,
  managed_identity_user: 0,
  workloads: 0,
  ai_agents: 0,
  ci_cd: 0,
  unowned: 0,
  dormant: 0,
  critical: 0,
  expired_secrets: 0,
  federated_only: 0,
  total: 0,
};

function StatCard({
  label, value, sublabel, color, navTo, danger,
}: { label: string; value: number; sublabel?: string; color: string; navTo: string; danger?: boolean }) {
  const navigate = useNavigate();
  return (
    <button
      onClick={() => navigate(navTo)}
      className="text-left bg-[#111827] border border-white/5 rounded-lg p-3 hover:border-white/15 hover:scale-[1.01] transition cursor-pointer"
      style={{ borderLeft: `3px solid ${color}` }}
    >
      <div className="text-[10px] uppercase tracking-wider font-bold text-gray-500">{label}</div>
      <div className={`text-2xl font-bold mt-1 ${danger ? 'text-rose-400' : 'text-gray-100'}`}>
        {value.toLocaleString()}
      </div>
      {sublabel && <div className="text-[10px] text-gray-500 mt-0.5">{sublabel}</div>}
    </button>
  );
}

export default function NHIInventory() {
  const [stats, setStats] = useState<NhiStats>(EMPTY_STATS);
  const [loading, setLoading] = useState(true);
  const [trustScore, setTrustScore] = useState<{ avg: number; critical: number; good: number } | null>(null);

  useEffect(() => {
    // Pull NHI category counts from /api/identities/category-summary
    fetch('/api/identities/category-summary')
      .then(r => r.ok ? r.json() : null)
      .then((d: Record<string, number> | null) => {
        if (!d) return;
        setStats({
          service_principals: d.service_principal || 0,
          managed_identity_system: d.managed_identity_system || 0,
          managed_identity_user: d.managed_identity_user || 0,
          workloads: d.workload || 0,
          ai_agents: d.ai_agent || 0,
          ci_cd: d.ci_cd || 0,
          unowned: d.unowned_nhi || 0,
          dormant: d.dormant_nhi || 0,
          critical: d.critical_nhi || 0,
          expired_secrets: d.expired_secrets_nhi || 0,
          federated_only: d.federated_only_nhi || 0,
          total: (d.service_principal || 0) + (d.managed_identity_system || 0) +
                 (d.managed_identity_user || 0) + (d.workload || 0) + (d.ai_agent || 0),
        });
      })
      .catch(() => {})
      .finally(() => setLoading(false));

    // Trust score rollup (extends Phase 2 NHI Trust)
    fetch('/api/identity-trust/rollup?type=nhi')
      .then(r => r.ok ? r.json() : null)
      .then((d: any) => {
        if (d && typeof d.avg_trust === 'number') {
          setTrustScore({ avg: d.avg_trust, critical: d.critical || 0, good: d.good || 0 });
        }
      })
      .catch(() => {});
  }, []);

  const headlineCount = useMemo(() => stats.total, [stats]);

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-5">
      {/* Hero header — the SailPoint-killer numbers screen */}
      <div>
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span style={{ color: '#f97316' }}>Identity</span>
          <span>·</span>
          <span>Non-Human</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-100 mt-1">Non-Human Identity Inventory</h1>
        <p className="text-sm text-slate-400 max-w-3xl mt-1">
          {/* AG-POLISH-C (2026-06-10): jargon-aware. Every cap term has
              a tooltip the CISO can hover for the precise definition. */}
          Every <TermTooltip term="NHI">non-human identity</TermTooltip> in your tenant —
          {' '}<TermTooltip term="SPN">service principals</TermTooltip>,
          {' '}<TermTooltip term="MI">managed identities</TermTooltip>, workloads,
          CI/CD identities, and AI agents — in one pane. Read-only,
          architecture-derived. AuditGraph never asks for write access.
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="animate-spin h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full" />
        </div>
      ) : (
        <>
          {/* Headline counter */}
          <div className="bg-[#0f172a] rounded-xl border border-white/5 p-5 flex items-center justify-between">
            <div>
              <div className="text-[10px] uppercase tracking-wider font-bold text-gray-500">Total non-human identities</div>
              <div className="text-4xl font-bold text-orange-400 mt-1">{headlineCount.toLocaleString()}</div>
              <div className="text-xs text-slate-400 mt-1">
                {stats.ai_agents > 0 && `${stats.ai_agents} AI agents · `}
                {stats.workloads > 0 && `${stats.workloads} workloads · `}
                {stats.service_principals} SPNs · {stats.managed_identity_system + stats.managed_identity_user} managed identities
              </div>
            </div>
            {trustScore && (
              <div className="text-right">
                <div className="text-[10px] uppercase tracking-wider font-bold text-gray-500">Avg Trust</div>
                <div className={`text-3xl font-bold ${trustScore.avg < 40 ? 'text-rose-400' : trustScore.avg < 70 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {trustScore.avg.toFixed(0)}
                  <span className="text-base text-slate-400">/100</span>
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  {trustScore.critical} critical · {trustScore.good} healthy
                </div>
              </div>
            )}
          </div>

          {/* Type breakdown */}
          <div>
            <div className="text-[10px] uppercase tracking-wider font-bold text-gray-500 mb-2">By type</div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
              <StatCard label="Service Principals" value={stats.service_principals}
                color="#f97316" navTo="/identity-explorer?identity_category=service_principal" />
              <StatCard label="System MIs" value={stats.managed_identity_system}
                color="#f59e0b" navTo="/identity-explorer?identity_category=managed_identity_system" />
              <StatCard label="User MIs" value={stats.managed_identity_user}
                color="#eab308" navTo="/identity-explorer?identity_category=managed_identity_user" />
              <StatCard label="Workloads" value={stats.workloads}
                color="#10b981" navTo="/identity-explorer?identity_category=workload" />
              <StatCard label="AI Agents" value={stats.ai_agents}
                color="#a78bfa" navTo="/ai-inventory" />
            </div>
          </div>

          {/* Risk / hygiene breakdown — the panic-button row */}
          <div>
            <div className="text-[10px] uppercase tracking-wider font-bold text-gray-500 mb-2">Hygiene gaps</div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
              <StatCard label="Unowned" value={stats.unowned} sublabel="No human accountable"
                color="#dc2626" danger navTo="/identity-explorer?owner_status=unowned&identity_category=service_principal" />
              <StatCard label="Dormant" value={stats.dormant} sublabel="No activity in 90d"
                color="#dc2626" danger navTo="/identity-explorer?activity_status=dormant_strict&identity_category=service_principal" />
              <StatCard label="Critical Risk" value={stats.critical}
                color="#dc2626" danger navTo="/identity-explorer?risk_level=critical&identity_category=service_principal" />
              <StatCard label="Expired Secrets" value={stats.expired_secrets}
                color="#f59e0b" navTo="/identity-explorer?credential_status=expired&identity_category=service_principal" />
              <StatCard label="Federated only" value={stats.federated_only} sublabel="OIDC trust, no static secret"
                color="#a78bfa" navTo="/identity-explorer?has_federated=true&identity_category=service_principal" />
            </div>
          </div>

          {/* Drill-down links */}
          <div className="bg-[#0f172a] rounded-xl border border-white/5 p-5">
            <div className="text-xs font-semibold text-slate-300 mb-3">Drill in</div>
            <div className="flex flex-wrap gap-2">
              <Link to="/nhi/trust" className="px-3 py-1.5 rounded-lg text-xs font-medium bg-orange-900/30 text-orange-300 border border-orange-700/40 hover:bg-orange-900/50 transition">
                Trust Score →
              </Link>
              <Link to="/nhi/lifecycle" className="px-3 py-1.5 rounded-lg text-xs font-medium bg-blue-900/30 text-blue-300 border border-blue-700/40 hover:bg-blue-900/50 transition">
                Lifecycle (J/M/L) →
              </Link>
              <Link to="/nhi/secrets" className="px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-900/30 text-amber-300 border border-amber-700/40 hover:bg-amber-900/50 transition">
                Secrets / Credentials →
              </Link>
              <Link to="/nhi/ownership" className="px-3 py-1.5 rounded-lg text-xs font-medium bg-violet-900/30 text-violet-300 border border-violet-700/40 hover:bg-violet-900/50 transition">
                Assign Owners →
              </Link>
              <Link to="/nhi/attack-paths" className="px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-900/30 text-rose-300 border border-rose-700/40 hover:bg-rose-900/50 transition">
                Attack Paths →
              </Link>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
