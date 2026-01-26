// src/pages/IdentityDetail.tsx
import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getIdentity } from '../services/api';
import { Identity } from '../types';

const IdentityDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (id) {
      fetchIdentityDetail(id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const fetchIdentityDetail = async (identityId: string) => {
    try {
      setLoading(true);
      setError(null);
      const data: any = await getIdentity(identityId);
    // API may return { identity: {...} } or just {...}. Handle both.
      setIdentity(data?.identity ?? data);
    } catch (err: any) {
      console.error('Error fetching identity details:', err);
      setError(err.message || 'Failed to load identity details');
    } finally {
      setLoading(false);
    }
  };

  const getRiskBadgeColor = (riskLevel?: string) => {
    const level = (riskLevel ?? 'info').toLowerCase();
    switch (level) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      case 'low':
        return 'bg-green-100 text-green-800 border-green-300';
      case 'info':
        return 'bg-blue-100 text-blue-800 border-blue-300';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-300';
    }
  };

  const formatDate = (dateString?: string | null) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleString();
  };

  const getDaysSince = (dateString?: string | null) => {
    if (!dateString) return null;
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - date.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-xl text-gray-600">Loading identity details...</div>
      </div>
    );
  }

  if (error || !identity) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 max-w-md">
          <h2 className="text-red-600 font-bold text-lg mb-2">Error Loading Identity</h2>
          <p className="text-red-700">{error || 'Identity not found'}</p>
          <button
            onClick={() => navigate('/identities')}
            className="mt-4 bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
          >
            Back to Identities
          </button>
        </div>
      </div>
    );
  }

  const riskLevel = identity.risk_level ?? 'info';
  const daysSinceLastActivity = getDaysSince(identity.last_sign_in);

  const activityStatus = (identity.activity_status ?? 'unknown').toString();
  const activityStatusLower = activityStatus.toLowerCase();

  const roles = identity.roles ?? [];
  const hasOwnerRole =
    roles.length > 0 && roles.some((r: any) => (r?.role_name ?? '').toString().toLowerCase().includes('owner'));

  const riskReasonsRaw: any = (identity as any).risk_reasons;
  const riskReasons: string[] =
    Array.isArray(riskReasonsRaw) ? riskReasonsRaw :
    typeof riskReasonsRaw === 'string' && riskReasonsRaw ? [riskReasonsRaw] :
    [];

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      {/* Back Button */}
      <button
        onClick={() => navigate('/identities')}
        className="mb-6 flex items-center gap-2 text-blue-600 hover:text-blue-800 font-medium"
      >
        ← Back to Identities
      </button>

      {/* Header */}
      <div className="bg-white rounded-lg shadow-md p-6 mb-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              {identity.display_name ?? 'Unknown Identity'}
            </h1>
            <p className="text-gray-600">{identity.identity_type ?? 'unknown'}</p>
          </div>
          <span className={`px-4 py-2 text-sm font-bold rounded-full border-2 ${getRiskBadgeColor(riskLevel)}`}>
            {riskLevel.toUpperCase()}
          </span>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-6">
          <div className="bg-gray-50 rounded-lg p-4">
            <p className="text-sm text-gray-600 mb-1">Status</p>
            <p className={`text-lg font-semibold ${identity.enabled ? 'text-green-600' : 'text-red-600'}`}>
              {identity.enabled ? 'Enabled' : 'Disabled'}
            </p>
          </div>

          <div className="bg-gray-50 rounded-lg p-4">
            <p className="text-sm text-gray-600 mb-1">Role Assignments</p>
            <p className="text-lg font-semibold text-gray-900">
              {roles.length}
            </p>
          </div>

          <div className="bg-gray-50 rounded-lg p-4">
            <p className="text-sm text-gray-600 mb-1">Last Activity</p>
            <p className="text-lg font-semibold text-gray-900">
              {daysSinceLastActivity === null ? 'Never' :
               daysSinceLastActivity === 0 ? 'Today' :
               daysSinceLastActivity === 1 ? 'Yesterday' :
               `${daysSinceLastActivity} days ago`}
            </p>
          </div>

          <div className="bg-gray-50 rounded-lg p-4">
            <p className="text-sm text-gray-600 mb-1">Credentials</p>
            <p className={`text-lg font-semibold ${
              (identity.credential_status ?? 'Unknown') === 'Valid' ? 'text-green-600' : 'text-red-600'
            }`}>
              {identity.credential_status || 'Unknown'}
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Details */}
        <div className="lg:col-span-2 space-y-6">
          {/* Identity Information */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Identity Information</h2>
            <div className="space-y-3">
              <div className="flex justify-between py-2 border-b border-gray-100">
                <span className="text-gray-600 font-medium">Identity ID:</span>
                <span className="text-gray-900 font-mono text-sm">{identity.identity_id ?? 'N/A'}</span>
              </div>

              {identity.app_id && (
                <div className="flex justify-between py-2 border-b border-gray-100">
                  <span className="text-gray-600 font-medium">Application ID:</span>
                  <span className="text-gray-900 font-mono text-sm">{identity.app_id}</span>
                </div>
              )}

              {identity.object_id && (
                <div className="flex justify-between py-2 border-b border-gray-100">
                  <span className="text-gray-600 font-medium">Object ID:</span>
                  <span className="text-gray-900 font-mono text-sm">{identity.object_id}</span>
                </div>
              )}

              <div className="flex justify-between py-2 border-b border-gray-100">
                <span className="text-gray-600 font-medium">Type:</span>
                <span className="text-gray-900">{identity.identity_type ?? 'unknown'}</span>
              </div>

              <div className="flex justify-between py-2 border-b border-gray-100">
                <span className="text-gray-600 font-medium">Created:</span>
                <span className="text-gray-900">{formatDate(identity.created_datetime)}</span>
              </div>
            </div>
          </div>

          {/* Activity Information */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Activity Information</h2>
            <div className="space-y-3">
              <div className="flex justify-between py-2 border-b border-gray-100">
                <span className="text-gray-600 font-medium">Activity Status:</span>
                <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                  activityStatusLower.includes('active') ? 'bg-green-100 text-green-700' :
                  activityStatusLower.includes('dormant') ? 'bg-red-100 text-red-700' :
                  'bg-yellow-100 text-yellow-700'
                }`}>
                  {activityStatus}
                </span>
              </div>

              <div className="flex justify-between py-2 border-b border-gray-100">
                <span className="text-gray-600 font-medium">Last Sign-in:</span>
                <span className="text-gray-900">{formatDate(identity.last_sign_in)}</span>
              </div>

              {daysSinceLastActivity !== null && daysSinceLastActivity > 90 && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-3 mt-3">
                  <p className="text-sm text-red-800">
                    ⚠️ <strong>Warning:</strong> This identity has been inactive for {daysSinceLastActivity} days.
                    Consider reviewing if access is still required.
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Credential Information */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Credential Information</h2>
            <div className="space-y-3">
              <div className="flex justify-between py-2 border-b border-gray-100">
                <span className="text-gray-600 font-medium">Status:</span>
                <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                  (identity.credential_status ?? 'Unknown') === 'Valid' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                }`}>
                  {identity.credential_status || 'Unknown'}
                </span>
              </div>

              {identity.credential_expiration && (
                <div className="flex justify-between py-2 border-b border-gray-100">
                  <span className="text-gray-600 font-medium">Expires:</span>
                  <span className="text-gray-900">{formatDate(identity.credential_expiration)}</span>
                </div>
              )}
            </div>
          </div>

          {/* Role Assignments */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">
              Role Assignments ({roles.length})
            </h2>

            {roles.length > 0 ? (
              <div className="space-y-3">
                {roles.map((role: any, index: number) => (
                  <div key={index} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
                    <div className="flex items-start justify-between mb-2">
                      <h3 className="font-semibold text-gray-900">{role?.role_name ?? 'Unknown Role'}</h3>
                      <span className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded">
                        {role?.scope_type ?? 'scope'}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">
                      <strong>Scope:</strong> {role?.scope ?? 'N/A'}
                    </p>
                    {role?.created_on && (
                      <p className="text-xs text-gray-500">
                        Assigned: {formatDate(role.created_on)}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 text-center py-4">No role assignments found</p>
            )}
          </div>
        </div>

        {/* Right Column - Risk & Actions */}
        <div className="space-y-6">
          {/* Risk Assessment */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Risk Assessment</h2>
            <div className="mb-4">
              <div className="flex justify-between items-center mb-2">
                <span className="text-gray-600 font-medium">Risk Level:</span>
                <span className={`px-3 py-1 rounded-full text-sm font-bold ${getRiskBadgeColor(riskLevel)}`}>
                  {riskLevel.toUpperCase()}
                </span>
              </div>
            </div>

            {riskReasons.length > 0 && (
              <div className="bg-gray-50 rounded-lg p-4 mt-4">
                <p className="text-sm font-semibold text-gray-900 mb-2">Risk Factors:</p>
                <ul className="list-disc pl-5 space-y-1">
                  {riskReasons.map((rr, idx) => (
                    <li key={idx} className="text-sm text-gray-700">{rr}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Recommended Actions */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-4">📋 Recommended Actions</h2>
            <div className="space-y-3">
              {!identity.last_sign_in && (
                <div className="bg-white rounded-lg p-3 border border-red-200">
                  <p className="text-sm font-semibold text-red-900 mb-1">🚨 Never Used</p>
                  <p className="text-xs text-gray-700">Delete this identity immediately or document business justification</p>
                </div>
              )}

              {daysSinceLastActivity !== null && daysSinceLastActivity > 90 && (
                <div className="bg-white rounded-lg p-3 border border-orange-200">
                  <p className="text-sm font-semibold text-orange-900 mb-1">⚠️ Dormant Account</p>
                  <p className="text-xs text-gray-700">Review and revoke access if no longer needed</p>
                </div>
              )}

              {hasOwnerRole && (
                <div className="bg-white rounded-lg p-3 border border-yellow-200">
                  <p className="text-sm font-semibold text-yellow-900 mb-1">🔍 High Privilege</p>
                  <p className="text-xs text-gray-700">Verify Owner role is necessary for job function</p>
                </div>
              )}

              <div className="bg-white rounded-lg p-3 border border-blue-200">
                <p className="text-sm font-semibold text-blue-900 mb-1">📊 Regular Review</p>
                <p className="text-xs text-gray-700">Schedule quarterly access review per HIPAA requirements</p>
              </div>
            </div>
          </div>

          {/* HIPAA Compliance */}
          <div className="bg-purple-50 border border-purple-200 rounded-lg p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-4">🏥 HIPAA Compliance</h2>
            <div className="space-y-2 text-sm text-gray-700">
              <p><strong>§164.308(a)(3):</strong> Workforce access review required</p>
              <p><strong>§164.308(a)(4):</strong> Access authorization must be documented</p>
              <p><strong>§164.312(b):</strong> Audit controls - log all access</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IdentityDetail;
