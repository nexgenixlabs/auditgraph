import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import StatsCard from '../components/StatsCard';
import ViewAllButton from '../components/ViewAllButton';
import RiskMethodology from '../components/RiskMethodology';
import { RiskHeatMap, QuickActions, RiskDonutChart, PostureScore, CredentialHealth, ComplianceScorecard } from '../components/dashboard';

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

interface IdentitySummaryResponse {
  run_id: number;
  completed_at: string | null;
  categories: Record<
    string,
    { total: number; critical: number; high: number; medium: number; low: number; info: number; unknown: number }
  >;
}

interface PostureResponse {
  current_run: {
    id: number;
    completed_at: string | null;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  };
  previous_run: {
    id: number;
    completed_at: string | null;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  } | null;
  posture_score: number;
  credential_health: {
    expired: number;
    expiring_soon: number;
    healthy: number;
    no_credentials: number;
  };
  dormant_count: number;
  no_owner_count: number;
  expiring_credentials_count: number;
}

export default function Dashboard() {
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [summary, setSummary] = useState<IdentitySummaryResponse | null>(null);
  const [posture, setPosture] = useState<PostureResponse | null>(null);
  const [compliance, setCompliance] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [statsRes, summaryRes, postureRes, complianceRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/identity-summary'),
          fetch('/api/dashboard/posture'),
          fetch('/api/dashboard/compliance'),
        ]);

        if (!statsRes.ok) throw new Error(`Stats API error: ${statsRes.status}`);
        if (!summaryRes.ok) throw new Error(`Summary API error: ${summaryRes.status}`);

        const [statsJson, summaryJson] = await Promise.all([
          statsRes.json(),
          summaryRes.json(),
        ]);

        // Posture endpoint is optional - don't fail if unavailable
        let postureJson: PostureResponse | null = null;
        if (postureRes.ok) {
          postureJson = await postureRes.json();
        }

        const complianceJson = complianceRes.ok ? await complianceRes.json() : null;

        if (!cancelled) {
          setStats(statsJson);
          setSummary(summaryJson);
          setPosture(postureJson);
          setCompliance(complianceJson);
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

  // Calculate overall risk counts for donut chart
  const riskCounts = useMemo(() => {
    const cats = summary?.categories || {};
    let critical = 0, high = 0, medium = 0, low = 0, info = 0, total = 0;

    Object.values(cats).forEach((cat: any) => {
      critical += cat.critical || 0;
      high += cat.high || 0;
      medium += cat.medium || 0;
      low += cat.low || 0;
      info += cat.info || 0;
      total += cat.total || 0;
    });

    return { critical, high, medium, low, info, total };
  }, [summary]);

  const handleSegmentClick = (level: string) => {
    navigate(`/identities?risk_level=${level}`);
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
        <div className="animate-pulse space-y-4">
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-24 bg-gray-100 rounded-xl" />)}
          </div>
          <div className="grid grid-cols-3 gap-4">
            {[1, 2, 3].map(i => <div key={i} className="h-48 bg-gray-100 rounded-xl" />)}
          </div>
        </div>
      ) : error ? (
        <div className="bg-white border rounded-2xl p-6 text-red-600">{error}</div>
      ) : (
        <>
          {/* Top Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
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
            <StatsCard
              title="Discovery Runs"
              value={stats?.total_discovery_runs ?? 0}
              icon="🔄"
              color="gray"
            />
          </div>

          {/* Posture Score + Credential Health + Quick Actions */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 mb-6">
            {posture ? (
              <>
                <PostureScore
                  score={posture.posture_score}
                  currentRun={posture.current_run}
                  previousRun={posture.previous_run}
                />
                <CredentialHealth
                  expired={posture.credential_health.expired}
                  expiringSoon={posture.credential_health.expiring_soon}
                  healthy={posture.credential_health.healthy}
                  noCredentials={posture.credential_health.no_credentials}
                />
              </>
            ) : (
              <>
                <div className="bg-white border rounded-xl p-5 text-sm text-gray-400 col-span-2">
                  Posture data unavailable
                </div>
              </>
            )}
            <QuickActions
              criticalCount={latest?.critical_count ?? 0}
              expiringCount={posture?.expiring_credentials_count ?? 0}
              dormantCount={posture?.dormant_count ?? 0}
            />
          </div>

          {/* Heat Map + Donut Chart Row */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 mb-6">
            <div className="xl:col-span-2">
              <RiskHeatMap categories={categoryCards} />
            </div>
            <div>
              <RiskDonutChart counts={riskCounts} onSegmentClick={handleSegmentClick} />
            </div>
          </div>

          {/* Compliance Scorecard */}
          <ComplianceScorecard data={compliance} loading={loading} />
        </>
      )}
    </div>
  );
}
