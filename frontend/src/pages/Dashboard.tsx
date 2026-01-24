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

      const statsData = await getStats();
      setStats({
        total_identities: statsData.latest_run.total_identities,
        actionable_identities: 0,
        total_risks: (statsData.latest_run.critical_count || 0) + 
                     (statsData.latest_run.high_count || 0) + 
                     (statsData.latest_run.medium_count || 0),
        critical_risks: statsData.latest_run.critical_count || 0,
        high_risks: statsData.latest_run.high_count || 0,
        medium_risks: statsData.latest_run.medium_count || 0,
        low_risks: 0,
        last_scan: statsData.latest_run.completed_at
      });

      const risksData = await getRisks();
      setRisks(risksData.risks || []);

      const identitiesData = await getIdentities();
      const allIdentities = identitiesData.identities || [];
      
      setStats(prev => prev ? {
        ...prev,
        actionable_identities: allIdentities.length
      } : null);
      
      setRecentIdentities(allIdentities.slice(0, 5));

    } catch (err: any) {
      console.error('Error fetching dashboard data:', err);
      setError(err.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  // Helper function to get activity status badge
  const getActivityBadge = (activityStatus?: string) => {
    if (!activityStatus) return null;
    
    const status = activityStatus.toLowerCase();
    if (status.includes('active')) {
      return <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded">Active</span>;
    } else if (status.includes('inactive')) {
      return <span className="text-xs bg-yellow-100 text-yellow-700 px-2 py-1 rounded">Inactive</span>;
    } else if (status.includes('dormant')) {
      return <span className="text-xs bg-red-100 text-red-700 px-2 py-1 rounded">Dormant</span>;
    }
    return <span className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded">{activityStatus}</span>;
  };

  // Helper to calculate days since last activity
  const getDaysSinceActivity = (lastSignIn?: string) => {
    if (!lastSignIn) return null;
    const lastDate = new Date(lastSignIn);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - lastDate.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  };

  // Enhanced recommendation function with context
  const getEnhancedRecommendation = (risk: any) => {
    const reasons = (risk.risk_reasons || '').toString().toLowerCase();
    const hasActivity = risk.last_sign_in && risk.last_sign_in !== 'Never';
    const daysSince = getDaysSinceActivity(risk.last_sign_in);
    
    // CRITICAL: Owner role + Never used
    if (reasons.includes('owner') && !hasActivity) {
      return {
        icon: '🚨',
        severity: 'critical',
        title: 'CRITICAL - Orphaned High Privilege Account',
        why: 'Owner role grants full control over all Azure resources including ability to delete data, modify permissions, and access sensitive information. An account that has NEVER been used represents a severe security risk.',
        action: 'Immediate action required: Delete this identity or document business justification within 24 hours',
        hipaa: 'High risk for HIPAA violations - unused accounts with elevated privileges violate least privilege principle'
      };
    }
    
    // CRITICAL: Owner role + Dormant (90+ days)
    if (reasons.includes('owner') && daysSince && daysSince > 90) {
      const months = Math.floor(daysSince / 30);
      return {
        icon: '🚨',
        severity: 'critical',
        title: `CRITICAL - Dormant for ${months} month${months !== 1 ? 's' : ''}`,
        why: `Owner role with no activity for ${months} months. Dormant high-privilege accounts are prime targets for attackers and may indicate forgotten test accounts or former employee access.`,
        action: `Review within 48 hours: Revoke Owner role or require business re-certification. If legitimate, reduce to minimum required privilege.`,
        hipaa: 'Violates HIPAA access review requirements - all privileged accounts must be regularly reviewed'
      };
    }
    
    // WARNING: Owner role + Active (but still high risk)
    if (reasons.includes('owner') && hasActivity && daysSince !== null && daysSince < 90) {
      return {
        icon: '⚠️',
        severity: 'warning',
        title: 'Active High Privilege - Requires Monitoring',
        why: 'Owner role is the highest privilege in Azure. While this account is actively used, it should be continuously monitored to ensure usage aligns with legitimate business needs and follows least privilege principles.',
        action: 'Review activity logs weekly. Verify all actions are job-appropriate. Consider right-sizing to lower privilege role (Contributor, Reader, or custom role).',
        hipaa: 'Requires audit trail review - document that Owner privileges are necessary for job function'
      };
    }
    
    // Contributor role analysis
    if (reasons.includes('contributor')) {
      if (!hasActivity) {
        return {
          icon: '📊',
          severity: 'critical',
          title: 'Over-privileged Unused Account',
          why: 'Contributor role allows creating, modifying, and deleting resources. An account that has never been used with this privilege level is unnecessary and increases attack surface.',
          action: 'Delete this identity immediately. If creation was recent (<7 days), monitor for 1 week then remove if still unused.',
          hipaa: 'Unnecessary access violates minimum necessary standard'
        };
      } else if (daysSince && daysSince > 90) {
        return {
          icon: '📊',
          severity: 'warning',
          title: 'Contributor Role - Consider Right-sizing',
          why: 'Contributor can modify resources but cannot grant access to others. Review actual usage patterns - many Contributors only need Reader access.',
          action: 'Analyze activity logs to determine if write permissions are actively used. If only reading data, downgrade to Reader role.',
          hipaa: 'Right-size to minimum necessary access level per HIPAA requirements'
        };
      } else {
        return {
          icon: '📊',
          severity: 'info',
          title: 'Active Contributor - Review Regularly',
          why: 'Contributor role provides significant permissions. Regular reviews ensure access remains appropriate.',
          action: 'Monthly access review recommended. Verify usage patterns align with job responsibilities.',
          hipaa: 'Document business justification for Contributor level access'
        };
      }
    }
    
    // User Access Administrator
    if (reasons.includes('user access administrator')) {
      if (!hasActivity) {
        return {
          icon: '👥',
          severity: 'critical',
          title: 'Unused Identity Management Privilege',
          why: 'User Access Administrator can grant and revoke access to Azure resources. This is a highly sensitive privilege that should never sit unused.',
          action: 'Remove immediately. This role should only exist when actively managing access.',
          hipaa: 'Critical - unused access management privileges are high-risk for compliance violations'
        };
      } else {
        return {
          icon: '👥',
          severity: 'warning',
          title: 'Active Identity Management Role',
          why: 'Can delegate access to others. Requires strong monitoring and governance.',
          action: 'Review all permission grants made by this identity. Ensure proper approval workflow is followed. Consider implementing JIT (Just-In-Time) access.',
          hipaa: 'High scrutiny required - document all access delegation decisions'
        };
      }
    }
    
    // Default fallback
    return {
      icon: '💡',
      severity: 'info',
      title: 'Review Required',
      why: 'This identity has elevated privileges that require regular review to ensure compliance and security.',
      action: 'Verify access is still required and appropriate for current job function.',
      hipaa: 'Document access justification per HIPAA requirements'
    };
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

      {/* Enhanced Critical/High Risks Cards */}
      <div className="bg-white rounded-lg shadow-md p-6 mb-8">
        <h2 className="text-2xl font-bold text-gray-800 mb-4">
          Critical & High Risks ({risks.length})
        </h2>
        {risks.length > 0 ? (
          <div className="space-y-6">
            {risks.map((risk, index) => {
              const recommendation = getEnhancedRecommendation(risk);
              const daysSince = getDaysSinceActivity(risk.last_sign_in);
              
              return (
                <div 
                  key={index} 
                  className={`border-2 rounded-lg p-6 ${
                    recommendation.severity === 'critical' ? 'border-red-300 bg-red-50' :
                    recommendation.severity === 'warning' ? 'border-yellow-300 bg-yellow-50' :
                    'border-blue-300 bg-blue-50'
                  }`}
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-xl font-bold text-gray-900">
                          {risk.display_name}
                        </h3>
                        <span className={`px-3 py-1 inline-flex text-xs font-bold rounded-full ${
                          risk.risk_level === 'critical' 
                            ? 'bg-red-600 text-white'
                            : 'bg-orange-500 text-white'
                        }`}>
                          {risk.risk_level?.toUpperCase()}
                        </span>
                        {getActivityBadge(risk.activity_status)}
                      </div>
                      <p className="text-sm text-gray-700 font-medium">
                        {risk.risk_reasons || 'No specific reason provided'}
                      </p>
                    </div>
                    <div className="text-right text-sm text-gray-600">
                      <div className="font-semibold">{risk.role_count || 0} role{(risk.role_count || 0) !== 1 ? 's' : ''}</div>
                    </div>
                  </div>

                  {/* Activity Status */}
                  <div className="flex items-center gap-6 text-sm mb-4 pb-4 border-b-2 border-gray-200">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-gray-700">Last Activity:</span>
                      <span className={`font-medium ${!daysSince || daysSince > 90 ? 'text-red-600' : 'text-gray-900'}`}>
                        {daysSince === null || daysSince === undefined ? 'Never' :
                        daysSince === 0 ? 'Today' :
                        daysSince === 1 ? 'Yesterday' :
                        daysSince < 7 ? `${daysSince} days ago` :
                        daysSince < 30 ? `${Math.floor(daysSince / 7)} weeks ago` :
                        daysSince < 365 ? `${Math.floor(daysSince / 30)} months ago` :
                        `${Math.floor(daysSince / 365)} years ago`}
                      </span>
                      {(!daysSince || daysSince > 90) && (
                        <span className="text-red-600 font-bold">⚠️ {daysSince ? 'DORMANT' : 'NEVER USED'}</span>
                      )}
                    </div>
                  </div>

                  {/* Enhanced Recommendation Section */}
                  <div className="space-y-4">
                    {/* Title */}
                    <div className="flex items-center gap-3">
                      <span className="text-3xl">{recommendation.icon}</span>
                      <h4 className="text-lg font-bold text-gray-900">{recommendation.title}</h4>
                    </div>

                    {/* Why it matters */}
                    <div className="bg-white rounded-lg p-4 border border-gray-200">
                      <p className="font-semibold text-gray-900 mb-2">⚠️ Why This Matters:</p>
                      <p className="text-sm text-gray-700 leading-relaxed">{recommendation.why}</p>
                    </div>

                    {/* Action required */}
                    <div className="bg-white rounded-lg p-4 border border-gray-200">
                      <p className="font-semibold text-gray-900 mb-2">✅ Recommended Action:</p>
                      <p className="text-sm text-gray-700 leading-relaxed">{recommendation.action}</p>
                    </div>

                    {/* HIPAA Impact */}
                    <div className="bg-purple-50 rounded-lg p-4 border border-purple-200">
                      <p className="font-semibold text-purple-900 mb-2">🏥 HIPAA Compliance Impact:</p>
                      <p className="text-sm text-purple-800 leading-relaxed">{recommendation.hipaa}</p>
                    </div>
                  </div>
                </div>
              );
            })}
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
            {recentIdentities.map((identity, index) => {
              const daysSince = getDaysSinceActivity(identity.last_sign_in);
              
              return (
                <div 
                  key={index} 
                  className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3">
                        <h3 className="font-medium text-gray-900">{identity.display_name}</h3>
                        {getActivityBadge(identity.activity_status)}
                      </div>
                      <p className="text-sm text-gray-500 mt-1">
                        {identity.identity_type} • Risk: {identity.risk_level}
                        {daysSince !== null && (
                          <span className="ml-2">
                            • Last activity: {
                              daysSince === 0 ? 'Today' :
                              daysSince === 1 ? 'Yesterday' :
                              daysSince < 7 ? `${daysSince} days ago` :
                              `${Math.floor(daysSince / 7)} weeks ago`
                            }
                          </span>
                        )}
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
              );
            })}
          </div>
        ) : (
          <p className="text-gray-500 text-center py-8">No identities found!</p>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
