import React from 'react';
import { Link } from 'react-router-dom';

interface TierIdentity {
  identity_id: string;
  display_name: string;
  risk_level: string;
  category: string;
  cloud?: string;
}

interface DormantIdentity extends TierIdentity {
  tier: number;
  activity_status: string;
}

interface InsightsData {
  tier_distribution: {
    t0: { count: number; identities: TierIdentity[] };
    t1: { count: number; identities: TierIdentity[] };
    t2: { count: number };
    t3: { count: number };
  };
  action_items: {
    dormant_privileged: number;
    expiring_credentials: number;
    unowned_spns: number;
  };
  dormant_privileged: DormantIdentity[];
  unowned_spns: TierIdentity[];
}

interface InsightsPanelProps {
  data: InsightsData | null;
  loading?: boolean;
}

const categoryLabels: Record<string, string> = {
  service_principal: 'SPN',
  managed_identity_system: 'Sys MI',
  managed_identity_user: 'Usr MI',
  human_user: 'Human',
  guest: 'Guest',
  microsoft_internal: 'MSFT',
};

const cloudColors: Record<string, string> = {
  azure: 'bg-blue-100 text-blue-700',
  aws: 'bg-orange-100 text-orange-700',
  gcp: 'bg-red-100 text-red-700',
};

const riskColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
};

function TierBar({ t0, t1, t2, t3 }: { t0: number; t1: number; t2: number; t3: number }) {
  const total = t0 + t1 + t2 + t3 || 1;
  return (
    <div className="w-full h-3 bg-gray-100 rounded-full overflow-hidden flex">
      {t0 > 0 && <div className="bg-red-500 h-full" style={{ width: `${(t0 / total) * 100}%` }} title={`T0: ${t0}`} />}
      {t1 > 0 && <div className="bg-orange-400 h-full" style={{ width: `${(t1 / total) * 100}%` }} title={`T1: ${t1}`} />}
      {t2 > 0 && <div className="bg-yellow-400 h-full" style={{ width: `${(t2 / total) * 100}%` }} title={`T2: ${t2}`} />}
      {t3 > 0 && <div className="bg-gray-300 h-full flex-1" title={`T3: ${t3}`} />}
    </div>
  );
}

export default function InsightsPanel({ data, loading }: InsightsPanelProps) {
  if (loading || !data) {
    return (
      <div className="bg-white border rounded-xl p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-5 bg-gray-200 rounded w-48" />
          <div className="grid grid-cols-4 gap-3">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-20 bg-gray-100 rounded-lg" />)}
          </div>
          <div className="h-40 bg-gray-100 rounded-lg" />
        </div>
      </div>
    );
  }

  const { tier_distribution: td, action_items: ai, dormant_privileged, unowned_spns } = data;
  const totalActions = ai.dormant_privileged + ai.expiring_credentials + ai.unowned_spns;

  return (
    <div className="space-y-4">
      {/* Row 1: Privilege Tier Distribution + Action Items */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Privilege Tier Distribution — spans 2 cols */}
        <div className="lg:col-span-2 bg-white border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-900">Privilege Tier Distribution</h3>
            <Link to="/identities" className="text-xs text-blue-600 hover:underline">View all</Link>
          </div>

          {/* Tier bar */}
          <TierBar t0={td.t0.count} t1={td.t1.count} t2={td.t2.count} t3={td.t3.count} />

          {/* Tier cards */}
          <div className="grid grid-cols-4 gap-3 mt-4">
            {[
              { label: 'T0', sub: 'Control Plane', count: td.t0.count, color: 'border-red-300 bg-red-50', text: 'text-red-800', dot: 'bg-red-500' },
              { label: 'T1', sub: 'Management', count: td.t1.count, color: 'border-orange-300 bg-orange-50', text: 'text-orange-800', dot: 'bg-orange-400' },
              { label: 'T2', sub: 'Data / App', count: td.t2.count, color: 'border-yellow-300 bg-yellow-50', text: 'text-yellow-800', dot: 'bg-yellow-400' },
              { label: 'T3', sub: 'Standard', count: td.t3.count, color: 'border-gray-200 bg-gray-50', text: 'text-gray-600', dot: 'bg-gray-400' },
            ].map(t => (
              <div key={t.label} className={`rounded-lg border p-3 ${t.color}`}>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className={`w-2 h-2 rounded-full ${t.dot}`} />
                  <span className={`text-xs font-bold ${t.text}`}>{t.label}</span>
                </div>
                <div className={`text-2xl font-bold ${t.text}`}>{t.count}</div>
                <div className="text-[10px] text-gray-500">{t.sub}</div>
              </div>
            ))}
          </div>

          {/* T0/T1 identity names */}
          {(td.t0.identities.length > 0 || td.t1.identities.length > 0) && (
            <div className="mt-4 space-y-2">
              {td.t0.identities.map(i => (
                <Link
                  key={i.identity_id}
                  to={`/identities/${encodeURIComponent(i.identity_id)}`}
                  className="flex items-center justify-between py-1.5 px-3 rounded-lg bg-red-50 hover:bg-red-100 transition text-sm"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-200 text-red-800">T0</span>
                    <span className={`px-1 py-0.5 rounded text-[9px] font-semibold uppercase ${cloudColors[i.cloud || 'azure'] || cloudColors.azure}`}>{i.cloud || 'azure'}</span>
                    <span className="font-medium text-gray-900 truncate">{i.display_name}</span>
                    <span className="text-[10px] text-gray-500">{categoryLabels[i.category] || i.category}</span>
                  </div>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase flex-shrink-0 ${riskColors[i.risk_level] || 'bg-gray-100 text-gray-600'}`}>
                    {i.risk_level}
                  </span>
                </Link>
              ))}
              {td.t1.identities.map(i => (
                <Link
                  key={i.identity_id}
                  to={`/identities/${encodeURIComponent(i.identity_id)}`}
                  className="flex items-center justify-between py-1.5 px-3 rounded-lg bg-orange-50 hover:bg-orange-100 transition text-sm"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-orange-200 text-orange-800">T1</span>
                    <span className={`px-1 py-0.5 rounded text-[9px] font-semibold uppercase ${cloudColors[i.cloud || 'azure'] || cloudColors.azure}`}>{i.cloud || 'azure'}</span>
                    <span className="font-medium text-gray-900 truncate">{i.display_name}</span>
                    <span className="text-[10px] text-gray-500">{categoryLabels[i.category] || i.category}</span>
                  </div>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase flex-shrink-0 ${riskColors[i.risk_level] || 'bg-gray-100 text-gray-600'}`}>
                    {i.risk_level}
                  </span>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Action Items */}
        <div className="bg-white border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-900">Action Items</h3>
            {totalActions > 0 && (
              <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-700">
                {totalActions}
              </span>
            )}
          </div>

          <div className="space-y-3">
            <div className={`rounded-lg p-4 ${ai.dormant_privileged > 0 ? 'bg-red-50 border border-red-100' : 'bg-gray-50'}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <svg className={`w-5 h-5 ${ai.dormant_privileged > 0 ? 'text-red-500' : 'text-gray-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span className="text-sm font-medium text-gray-900">Dormant Privileged</span>
                </div>
                <span className={`text-xl font-bold ${ai.dormant_privileged > 0 ? 'text-red-700' : 'text-gray-400'}`}>
                  {ai.dormant_privileged}
                </span>
              </div>
              <div className="text-[10px] text-gray-500 mt-1 ml-7">T0/T1 identities with no recent activity</div>
            </div>

            <div className={`rounded-lg p-4 ${ai.expiring_credentials > 0 ? 'bg-orange-50 border border-orange-100' : 'bg-gray-50'}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <svg className={`w-5 h-5 ${ai.expiring_credentials > 0 ? 'text-orange-500' : 'text-gray-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                  </svg>
                  <span className="text-sm font-medium text-gray-900">Expiring Credentials</span>
                </div>
                <span className={`text-xl font-bold ${ai.expiring_credentials > 0 ? 'text-orange-700' : 'text-gray-400'}`}>
                  {ai.expiring_credentials}
                </span>
              </div>
              <div className="text-[10px] text-gray-500 mt-1 ml-7">Secrets/certs expiring within 30 days</div>
            </div>

            <div className={`rounded-lg p-4 ${ai.unowned_spns > 0 ? 'bg-yellow-50 border border-yellow-100' : 'bg-gray-50'}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <svg className={`w-5 h-5 ${ai.unowned_spns > 0 ? 'text-yellow-600' : 'text-gray-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                  </svg>
                  <span className="text-sm font-medium text-gray-900">Unowned SPNs</span>
                </div>
                <span className={`text-xl font-bold ${ai.unowned_spns > 0 ? 'text-yellow-700' : 'text-gray-400'}`}>
                  {ai.unowned_spns}
                </span>
              </div>
              <div className="text-[10px] text-gray-500 mt-1 ml-7">Risky service principals with no owner</div>
            </div>
          </div>

          {totalActions === 0 && (
            <div className="mt-4 text-center text-sm text-green-600 font-medium">All clear</div>
          )}
        </div>
      </div>

      {/* Row 2: Dormant Privileged + Unowned SPNs lists */}
      {(dormant_privileged.length > 0 || unowned_spns.length > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Dormant Privileged */}
          {dormant_privileged.length > 0 && (
            <div className="bg-white border rounded-xl overflow-hidden">
              <div className="px-5 py-3 border-b bg-red-50 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900">Dormant Privileged Identities</h3>
                <span className="text-xs text-gray-500">{dormant_privileged.length} found</span>
              </div>
              <div className="divide-y">
                {dormant_privileged.map((d, idx) => (
                  <Link
                    key={`${d.identity_id}-${idx}`}
                    to={`/identities/${encodeURIComponent(d.identity_id)}`}
                    className="flex items-center justify-between px-5 py-3 hover:bg-gray-50 transition"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        d.tier === 0 ? 'bg-red-200 text-red-800' : 'bg-orange-200 text-orange-800'
                      }`}>T{d.tier}</span>
                      <span className={`px-1 py-0.5 rounded text-[9px] font-semibold uppercase ${cloudColors[d.cloud || 'azure'] || cloudColors.azure}`}>{d.cloud || 'azure'}</span>
                      <span className="font-medium text-gray-900 text-sm truncate">{d.display_name}</span>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="text-[10px] text-gray-400">{categoryLabels[d.category] || d.category}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${riskColors[d.risk_level] || 'bg-gray-100 text-gray-600'}`}>
                        {d.risk_level}
                      </span>
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Unowned SPNs */}
          {unowned_spns.length > 0 && (
            <div className="bg-white border rounded-xl overflow-hidden">
              <div className="px-5 py-3 border-b bg-yellow-50 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-900">Unowned Service Principals</h3>
                <span className="text-xs text-gray-500">{unowned_spns.length} found</span>
              </div>
              <div className="divide-y">
                {unowned_spns.map((s, idx) => (
                  <Link
                    key={`${s.identity_id}-${idx}`}
                    to={`/identities/${encodeURIComponent(s.identity_id)}`}
                    className="flex items-center justify-between px-5 py-3 hover:bg-gray-50 transition"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`px-1 py-0.5 rounded text-[9px] font-semibold uppercase ${cloudColors[s.cloud || 'azure'] || cloudColors.azure}`}>{s.cloud || 'azure'}</span>
                      <span className="font-medium text-gray-900 text-sm truncate">{s.display_name}</span>
                    </div>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase flex-shrink-0 ${riskColors[s.risk_level] || 'bg-gray-100 text-gray-600'}`}>
                      {s.risk_level}
                    </span>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
