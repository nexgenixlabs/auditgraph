import React, { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import StatsCard from '../components/StatsCard';
import ViewAllButton from '../components/ViewAllButton';
import RiskMethodology from '../components/RiskMethodology';

type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

type IdentityCategory =
  | 'service_principal'
  | 'managed_identity_system'
  | 'managed_identity_user'
  | 'human_user'
  | 'guest'
  | 'microsoft_internal'
  | 'unknown';

interface StatsResponse {
  total_discovery_runs: number;
  latest_run: {
    id: number;
    completed_at: string | null;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  } | null;
}

interface RisksResponse {
  run_id: number;
  count: number;
  risks: Array<{
    identity_id: string;
    display_name: string;
    identity_type?: string;
    identity_category?: IdentityCategory;
    risk_level: RiskLevel;
    risk_reason: string[] | string;
  }>;
}

interface IdentitySummaryResponse {
  run_id: number;
  completed_at: string | null;
  categories: Record<
    string,
    { total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }
  >;
}

function safeLower(v: any) {
  return String(v ?? '').toLowerCase();
}

function riskBadge(level?: string) {
  const v = safeLower(level);
  const base = 'px-2 py-1 rounded-full text-xs font-semibold inline-flex items-center';
  if (v === 'critical') return <span className={`${base} bg-red-100 text-red-700`}>CRITICAL</span>;
  if (v === 'high') return <span className={`${base} bg-orange-100 text-orange-700`}>HIGH</span>;
  if (v === 'medium') return <span className={`${base} bg-yellow-100 text-yellow-700`}>MEDIUM</span>;
  if (v === 'low') return <span className={`${base} bg-green-100 text-green-700`}>LOW</span>;
  if (v === 'info') return <span className={`${base} bg-blue-100 text-blue-700`}>INFO</span>;
  return <span className={`${base} bg-gray-100 text-gray-700`}>UNKNOWN</span>;
}

function categoryLabel(cat: string) {
  switch (cat) {
    case 'service_principal':
      return 'Service Principal';
    case 'managed_identity_system':
      return 'Managed Identity (System)';
    case 'managed_identity_user':
      return 'Managed Identity (User)';
    case 'human_user':
      return 'Human User';
    case 'guest':
      return 'Guest';
    case 'microsoft_internal':
      return 'Microsoft Internal';
    default:
      return 'Unknown';
  }
}

export default function Dashboard() {
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [summary, setSummary] = useState<IdentitySummaryResponse | null>(null);
  const [risks, setRisks] = useState<RisksResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [statsRes, summaryRes, risksRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/identity-summary'),
          fetch('/api/risks'),
        ]);

        if (!statsRes.ok) throw new Error(`Stats API error: ${statsRes.status}`);
        if (!summaryRes.ok) throw new Error(`Summary API error: ${summaryRes.status}`);
        if (!risksRes.ok) throw new Error(`Risks API error: ${risksRes.status}`);

        const [statsJson, summaryJson, risksJson] = await Promise.all([
          statsRes.json(),
          summaryRes.json(),
          risksRes.json(),
        ]);

        if (!cancelled) {
          setStats(statsJson);
          setSummary(summaryJson);
          setRisks(risksJson);
        }
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load dashboard');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const latest = stats?.latest_run;

  const categoryCards = useMemo(() => {
    const categories = summary?.categories || {};
    const ordered: string[] = [
      'service_principal',
      'managed_identity_system',
      'managed_identity_user',
      'human_user',
      'guest',
      'microsoft_internal',
    ];

    return ordered.map((key) => {
      const v = categories[key] || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
      return { key, ...v };
    });
  }, [summary]);

  const openCategory = (cat: string, riskLevel?: string) => {
    let url = `/identities?identity_category=${encodeURIComponent(cat)}`;
    if (riskLevel) {
      url += `&risk_level=${encodeURIComponent(riskLevel)}`;
    }
    navigate(url);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <div className="flex items-start justify-between gap-4 mb-5">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Dashboard</h2>
          <p className="text-sm text-gray-600">
            Posture view from the latest discovery run. Use the category blocks to drill down.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <ViewAllButton />
        </div>
      </div>

      {/* Methodology panel */}
      <RiskMethodology />

      {loading ? (
        <div className="bg-white border rounded-2xl p-6 text-gray-600">Loading…</div>
      ) : error ? (
        <div className="bg-white border rounded-2xl p-6 text-red-600">{error}</div>
      ) : (
        <>
          {/* Top Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
            <StatsCard
              title="Latest Run"
              value={latest?.id ?? '—'}
              icon="🗄️"
              color="gray"
            />
            <StatsCard
              title="Total Identities"
              value={latest?.total_identities ?? 0}
              icon="🧩"
              color="blue"
            />
            <StatsCard
              title="Critical"
              value={latest?.critical_count ?? 0}
              icon="🔴"
              color="red"
            />
            <StatsCard
              title="High"
              value={latest?.high_count ?? 0}
              icon="🟠"
              color="yellow"
            />
          </div>

          {/* Category Blocks */}
          <div className="mb-5">
            <div className="text-sm font-semibold text-gray-900 mb-2">Identity Categories</div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {categoryCards.map((c) => (
                <div
                  key={c.key}
                  className="text-left bg-white border rounded-2xl p-5 hover:shadow-md transition"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-base font-semibold text-gray-900">{categoryLabel(c.key)}</div>
                      <div className="text-xs text-gray-500 mt-1">{c.total} identities</div>
                    </div>
                    <button
                      onClick={() => openCategory(c.key)}
                      className="text-xs font-semibold px-3 py-1 rounded-full bg-gray-100 text-gray-700 hover:bg-gray-200"
                    >
                      View All
                    </button>
                  </div>

                  <div className="flex flex-wrap gap-2 mt-4">
                    {c.critical > 0 && (
                      <button
                        onClick={() => openCategory(c.key, 'critical')}
                        className="text-xs px-2 py-1 rounded-full bg-red-50 text-red-700 hover:bg-red-100 cursor-pointer"
                      >
                        Critical: {c.critical}
                      </button>
                    )}
                    {c.high > 0 && (
                      <button
                        onClick={() => openCategory(c.key, 'high')}
                        className="text-xs px-2 py-1 rounded-full bg-orange-50 text-orange-700 hover:bg-orange-100 cursor-pointer"
                      >
                        High: {c.high}
                      </button>
                    )}
                    {c.medium > 0 && (
                      <button
                        onClick={() => openCategory(c.key, 'medium')}
                        className="text-xs px-2 py-1 rounded-full bg-yellow-50 text-yellow-700 hover:bg-yellow-100 cursor-pointer"
                      >
                        Medium: {c.medium}
                      </button>
                    )}
                    {c.low > 0 && (
                      <button
                        onClick={() => openCategory(c.key, 'low')}
                        className="text-xs px-2 py-1 rounded-full bg-green-50 text-green-700 hover:bg-green-100 cursor-pointer"
                      >
                        Low: {c.low}
                      </button>
                    )}
                    {c.info > 0 && (
                      <button
                        onClick={() => openCategory(c.key, 'info')}
                        className="text-xs px-2 py-1 rounded-full bg-blue-50 text-blue-700 hover:bg-blue-100 cursor-pointer"
                      >
                        Info: {c.info}
                      </button>
                    )}
                    {c.total === 0 && (
                      <span className="text-xs text-gray-400">No identities</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Critical & High Risks */}
          <div className="bg-white border rounded-2xl p-6">
            <div className="flex items-center justify-between mb-3">
              <div className="text-lg font-semibold text-gray-900">Critical & High Risks</div>
              <Link to="/identities?risk_level=critical" className="text-sm text-blue-600 hover:underline">
                View Critical →
              </Link>
            </div>

            {(risks?.risks || []).length === 0 ? (
              <div className="text-sm text-gray-500">No critical/high/medium risks found.</div>
            ) : (
              <div className="space-y-3">
                {risks!.risks.slice(0, 12).map((r, idx) => (
                  <Link
                    key={`${r.identity_id}-${idx}`}
                    to={`/identities/${encodeURIComponent(r.identity_id)}`}
                    className="block border rounded-xl p-4 hover:bg-gray-50 transition"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-semibold text-gray-900">{r.display_name}</div>
                        <div className="text-xs text-gray-500 break-all">{r.identity_id}</div>
                        {r.identity_category ? (
                          <div className="text-xs text-gray-600 mt-1">{categoryLabel(r.identity_category)}</div>
                        ) : null}
                      </div>
                      <div>{riskBadge(r.risk_level)}</div>
                    </div>

                    <div className="text-xs text-gray-700 mt-3">
                      {Array.isArray(r.risk_reason) ? r.risk_reason.join(' • ') : String(r.risk_reason || '')}
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
