// src/pages/Dashboard.tsx
import React, { useEffect, useState } from 'react';
import StatsCard from '../components/StatsCard';
import { getStats, getRisks, getIdentities } from '../services/api';
import { Stats, Identity } from '../types';

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [risks, setRisks] = useState<Identity[]>([]);
  const [recentIdentities, setRecentIdentities] = useState<Identity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch stats first
      const statsData = await getStats();
      setStats({
        total_identities: statsData.latest_run.total_identities,
        actionable_identities: 0, // We'll calculate this
        total_risks: (statsData.latest_run.critical_count || 0) + 
                     (statsData.latest_run.high_count || 0) + 
                     (statsData.latest_run.medium_count || 0),
        critical_risks: statsData.latest_run.critical_count || 0,
        high_risks: statsData.latest_run.high_count || 0,
        medium_risks: statsData.latest_run.medium_count || 0,
        low_risks: 0,
        last_scan: statsData.latest_run.completed_at
      });

      // Fetch risks
      const risksData = await getRisks();
      setRisks(risksData.risks || []);

      // Fetch all identities
      const identitiesData = await getIdentities();
      const allIdentities = identitiesData.identities || [];
      
      // Update actionable count
      setStats(prev => prev ? {
        ...prev,
        actionable_identities: allIdentities.length
      } : null);
      
      setRecentIdentities(allIdentities.slice(0, 5)); // Show top 5

    } catch (err: any) {
      console.error('Error fetching dashboard data:', err);
      setError(err.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-xl text-gray-600">Loading dashboard...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 max-w-md">
          <h2 className="text-red-600 font-bold text-lg mb-2">Error Loading Dashboard</h2>
          <p className="text-red-700">{error}</p>
          <button 
            onClick={fetchDashboardData}
            className="mt-4 bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-4xl font-bold text-gray-800 mb-2">AuditGraph Dashboard</h1>
        <p className="text-gray-600">Identity Security Posture Management</p>
        {stats?.last_scan && (
          <p className="text-sm text-gray-500 mt-1">
            Last scan: {new Date(stats.last_scan).toLocaleString()}
          </p>
        )}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatsCard
          title="Total Identities"
          value={stats?.total_identities || 0}
          icon="👥"
          color="blue"
        />
        <StatsCard
          title="Actionable Identities"
          value={stats?.actionable_identities || 0}
          icon="⚠️"
          color="yellow"
        />
        <StatsCard
          title="Critical Risks"
          value={stats?.critical_risks || 0}
          icon="🔴"
          color="red"
        />
        <StatsCard
          title="High Risks"
          value={stats?.high_risks || 0}
          icon="🟠"
          color="yellow"
        />
      </div>

      {/* Risk Summary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <StatsCard
          title="Medium Risks"
          value={stats?.medium_risks || 0}
          color="yellow"
        />
        <StatsCard
          title="Low Risks"
          value={stats?.low_risks || 0}
          color="green"
        />
        <StatsCard
          title="Total Risks"
          value={stats?.total_risks || 0}
          color="gray"
        />
        <StatsCard
          title="Noise Reduction"
          value="99%"
          color="green"
          icon="✨"
        />
      </div>

      {/* Critical/High Risks Table */}
      <div className="bg-white rounded-lg shadow-md p-6 mb-8">
        <h2 className="text-2xl font-bold text-gray-800 mb-4">
          Critical & High Risks ({risks.length})
        </h2>
        {risks.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Identity
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Risk Level
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Risk Reasons
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Roles
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {risks.map((risk, index) => (
                  <tr key={index} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900">
                        {risk.display_name}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        risk.risk_level === 'critical' 
                          ? 'bg-red-100 text-red-800'
                          : 'bg-orange-100 text-orange-800'
                      }`}>
                        {risk.risk_level?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {risk.risk_reasons || 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {risk.role_count} roles
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-500 text-center py-8">No critical or high risks found! 🎉</p>
        )}
      </div>

      {/* Recent Actionable Identities */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-2xl font-bold text-gray-800 mb-4">
          Recent Identities ({stats?.actionable_identities || 0})
        </h2>
        {recentIdentities.length > 0 ? (
          <div className="space-y-3">
            {recentIdentities.map((identity, index) => (
              <div 
                key={index} 
                className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50"
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <h3 className="font-medium text-gray-900">{identity.display_name}</h3>
                    <p className="text-sm text-gray-500 mt-1">
                      {identity.identity_type} • Risk: {identity.risk_level}
                    </p>
                  </div>
                  <div className="ml-4">
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                      identity.risk_level === 'critical' ? 'bg-red-100 text-red-800' :
                      identity.risk_level === 'high' ? 'bg-orange-100 text-orange-800' :
                      identity.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>
                      {identity.risk_level?.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-500 text-center py-8">No identities found!</p>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
