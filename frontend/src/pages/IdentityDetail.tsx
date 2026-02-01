// frontend/src/pages/IdentityDetail.tsx
import React, { useEffect, useMemo, useState } from 'react';
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
    if (id) fetchIdentityDetail(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const fetchIdentityDetail = async (identityId: string) => {
    try {
      setLoading(true);
      setError(null);
      const data = await getIdentity(identityId);
      setIdentity(data);
    } catch (err: any) {
      console.error('Error fetching identity details:', err);
      setError(err?.message || 'Failed to load identity details');
    } finally {
      setLoading(false);
    }
  };

  // ---------- helpers ----------
  const safeLower = (v: any) => (v ?? '').toString().toLowerCase();

  const getRiskBadgeColor = (riskLevel?: string) => {
    const level = safeLower(riskLevel);
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
    const d = new Date(dateString);
    if (Number.isNaN(d.getTime())) return 'Never';
    return d.toLocaleString();
  };

  const getDaysSince = (dateString?: string | null) => {
    if (!dateString) return null;
    const date = new Date(dateString);
    if (Number.isNaN(date.getTime())) return null;
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - date.getTime());
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  };

  // ---------- HOOKS MUST BE ABOVE RETURNS ----------
  const roles = useMemo(() => {
    const r: any = (identity as any)?.roles;
    return Array.isArray(r) ? r : [];
  }, [identity]);

  const graphPermissions = useMemo(() => {
    const p: any = (identity as any)?.graph_permissions;
    console.log('DEBUG: identity object:', identity);
    console.log('DEBUG: graph_permissions:', p);
    console.log('DEBUG: is array?', Array.isArray(p));
    return Array.isArray(p) ? p : [];
  }, [identity]);

  const hasOwnerRole = useMemo(() => {
    return roles.some((r: any) => safeLower(r?.role_name).includes('owner'));
  }, [roles]);

  const riskReasons = useMemo(() => {
    const rr: any = (identity as any)?.risk_reasons;
    if (Array.isArray(rr)) return rr;
    if (typeof rr === 'string' && rr.trim()) return [rr];
    return [];
  }, [identity]);

  const daysSinceLastActivity = useMemo(() => {
    return getDaysSince(identity?.last_sign_in ?? null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identity?.last_sign_in]);

  const riskLevelText = useMemo(() => {
    return ((identity?.risk_level ?? 'info') as any).toString();
  }, [identity?.risk_level]);

  // ---------- early returns ----------
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

  // ---------- render ----------
  return (
    <div className="min-h-screen bg-gray-50 p-8">
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
              {identity.display_name || 'Unknown Identity'}
            </h1>
            <p className="text-gray-600">{identity.identity_type || 'unknown'}</p>
          </div>

          <span className={`px-4 py-2 text-sm font-bold rounded-full border-2 ${getRiskBadgeColor(identity.risk_level)}`}>
            {riskLevelText.toUpperCase()}
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
            <p className="text-lg font-semibold text-gray-900">{roles.length}</p>
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
              identity.credential_status === 'Valid' ? 'text-green-600' : 'text-red-600'
            }`}>
              {identity.credential_status || 'Unknown'}
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column */}
        <div className="lg:col-span-2 space-y-6">
          {/* Identity Information */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Identity Information</h2>
            <div className="space-y-3">
              <div className="flex justify-between py-2 border-b border-gray-100">
                <span className="text-gray-600 font-medium">Identity ID:</span>
                <span className="text-gray-900 font-mono text-sm">{identity.identity_id || 'N/A'}</span>
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
                <span className="text-gray-900">{identity.identity_type || 'unknown'}</span>
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
                  safeLower(identity.activity_status).includes('active') ? 'bg-green-100 text-green-700' :
                  safeLower(identity.activity_status).includes('dormant') ? 'bg-red-100 text-red-700' :
                  'bg-yellow-100 text-yellow-700'
                }`}>
                  {identity.activity_status || 'Unknown'}
                </span>
              </div>

              <div className="flex justify-between py-2 border-b border-gray-100">
                <span className="text-gray-600 font-medium">Last Sign-in:</span>
                <span className="text-gray-900">{formatDate(identity.last_sign_in)}</span>
              </div>

              {daysSinceLastActivity !== null && daysSinceLastActivity > 90 && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-3 mt-3">
                  <p className="text-sm text-red-800">
                    ⚠️ <strong>Warning:</strong> Inactive for {daysSinceLastActivity} days.
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
                  identity.credential_status === 'Valid' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
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

          {/* Role Assignments - WEEK 6 UPDATE */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">
              Role Assignments ({roles.length})
            </h2>

            {roles.length > 0 ? (
              <div className="space-y-4">
                {roles.map((role: any, index: number) => {
                  const hasIntelligence = role?.risk_level || role?.description;
                  const hasAttackPatterns = role?.attack_patterns && role.attack_patterns.length > 0;
                  const hasHipaaViolations = role?.hipaa_violations && role.hipaa_violations.length > 0;
                  
                  return (
                    <div 
                      key={index} 
                      className={`border rounded-lg p-4 hover:bg-gray-50 transition-colors ${
                        role?.risk_level === 'critical' ? 'border-red-300 bg-red-50' :
                        role?.risk_level === 'high' ? 'border-orange-300 bg-orange-50' :
                        'border-gray-200'
                      }`}
                    >
                      {/* Header: Role Name + Badges */}
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <h3 className="font-semibold text-gray-900 mb-1">
                            {role?.role_name || 'Unknown Role'}
                          </h3>
                          {role?.description && (
                            <p className="text-sm text-gray-600 italic">
                              {role.description}
                            </p>
                          )}
                        </div>
                        <div className="flex gap-2 ml-4 flex-wrap justify-end">
                          {/* Risk Badge */}
                          {role?.risk_level && (
                            <span className={`text-xs font-bold px-3 py-1 rounded-full whitespace-nowrap ${
                              role.risk_level === 'critical' ? 'bg-red-600 text-white' :
                              role.risk_level === 'high' ? 'bg-orange-500 text-white' :
                              role.risk_level === 'medium' ? 'bg-yellow-500 text-white' :
                              'bg-gray-500 text-white'
                            }`}>
                              {role.risk_level.toUpperCase()}
                            </span>
                          )}
                          {/* Type Badge */}
                          <span className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded">
                            {role?.role_type || 'unknown'}
                          </span>
                        </div>
                      </div>

                      {/* Scope Info */}
                      <div className="mb-3">
                        <p className="text-sm text-gray-600">
                          <strong>Scope:</strong> {role?.scope || 'N/A'}
                        </p>
                        {role?.created_on && (
                          <p className="text-xs text-gray-500 mt-1">
                            Assigned: {formatDate(role.created_on)}
                          </p>
                        )}
                      </div>

                      {/* Week 6: Intelligence Section */}
                      {hasIntelligence && (
                        <div className="border-t border-gray-200 pt-3 mt-3 space-y-3">
                          
                          {/* Why Critical */}
                          {role?.why_critical && (
                            <div className="bg-yellow-50 border-l-4 border-yellow-400 p-3 rounded">
                              <p className="text-xs font-semibold text-yellow-800 mb-1">
                                ⚠️ Why This Role Is Dangerous:
                              </p>
                              <p className="text-sm text-yellow-900">
                                {role.why_critical}
                              </p>
                            </div>
                          )}

                          {/* Attack Patterns */}
                          {hasAttackPatterns && (
                            <div className="bg-red-50 border-l-4 border-red-400 p-3 rounded">
                              <p className="text-xs font-semibold text-red-800 mb-2">
                                🔥 Real-World Breaches:
                              </p>
                              {role.attack_patterns.map((pattern: any, idx: number) => (
                                <div key={idx} className="mb-2 last:mb-0">
                                  <p className="text-sm font-medium text-red-900">
                                    {pattern.attack_scenario}
                                  </p>
                                  <p className="text-xs text-red-700 mt-1">
                                    {pattern.company_affected} ({pattern.breach_year}) - 
                                    <span className="font-bold ml-1">
                                      ${(pattern.estimated_cost_usd / 1000000).toFixed(0)}M loss
                                    </span>
                                  </p>
                                  {pattern.real_world_example && (
                                    <p className="text-xs text-red-600 mt-1 italic">
                                      {pattern.real_world_example}
                                    </p>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}

                          {/* HIPAA Violations */}
                          {hasHipaaViolations && (
                            <div className="bg-purple-50 border-l-4 border-purple-400 p-3 rounded">
                              <p className="text-xs font-semibold text-purple-800 mb-2">
                                📋 Compliance Impact (HIPAA):
                              </p>
                              {role.hipaa_violations.map((violation: any, idx: number) => (
                                <div key={idx} className="mb-2 last:mb-0">
                                  <p className="text-sm font-medium text-purple-900">
                                    {violation.hipaa_section}
                                  </p>
                                  <p className="text-xs text-purple-700 mt-1">
                                    {violation.violation_explanation}
                                  </p>
                                  {violation.typical_penalty_min && violation.typical_penalty_max && (
                                    <p className="text-xs text-purple-600 mt-1 font-bold">
                                      Penalty Range: ${(violation.typical_penalty_min / 1000).toFixed(0)}K - 
                                      ${(violation.typical_penalty_max / 1000000).toFixed(1)}M
                                    </p>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Activity Tracking */}
                          {role?.days_since_last_use !== null && role?.days_since_last_use !== undefined && (
                            <div className="bg-gray-50 border-l-4 border-gray-400 p-3 rounded">
                              <p className="text-xs font-semibold text-gray-800 mb-1">
                                📊 Usage Activity:
                              </p>
                              <p className="text-sm text-gray-700">
                                {role.days_since_last_use === 0 ? (
                                  <span className="text-green-600 font-medium">✓ Used today</span>
                                ) : role.days_since_last_use > 90 ? (
                                  <span className="text-red-600 font-medium">
                                    ⚠️ Not used in {role.days_since_last_use} days - Consider removal
                                  </span>
                                ) : (
                                  <span className="text-gray-600">
                                    Last used {role.days_since_last_use} days ago
                                  </span>
                                )}
                              </p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-gray-500 text-center py-4">No role assignments found</p>
            )}
          </div>

          {/* API Permissions - WEEK 9 */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">
              🔐 API Permissions ({graphPermissions.length})
            </h2>

            {graphPermissions.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Permission
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Resource
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Risk
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {graphPermissions.map((perm: any, index: number) => (
                      <tr 
                        key={index}
                        className={`hover:bg-gray-50 ${
                          perm?.risk_level === 'critical' ? 'bg-red-50' :
                          perm?.risk_level === 'high' ? 'bg-orange-50' :
                          ''
                        }`}
                      >
                        <td className="px-4 py-3">
                          <div>
                            <p className="text-sm font-medium text-gray-900">
                              {perm?.permission_name || 'Unknown'}
                            </p>
                            <p className="text-xs text-gray-500">
                              {perm?.permission_description || ''}
                            </p>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-600">
                          {perm?.resource_name || 'Unknown'}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 text-xs font-bold rounded-full ${
                            perm?.risk_level === 'critical' ? 'bg-red-600 text-white' :
                            perm?.risk_level === 'high' ? 'bg-orange-500 text-white' :
                            perm?.risk_level === 'medium' ? 'bg-yellow-500 text-white' :
                            'bg-gray-500 text-white'
                          }`}>
                            {(perm?.risk_level || 'unknown').toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-gray-500 text-center py-4">No API permissions found</p>
            )}
          </div>
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          {/* Risk Assessment */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Risk Assessment</h2>

            <div className="mb-4">
              <div className="flex justify-between items-center mb-2">
                <span className="text-gray-600 font-medium">Risk Level:</span>
                <span className={`px-3 py-1 rounded-full text-sm font-bold ${getRiskBadgeColor(identity.risk_level)}`}>
                  {riskLevelText.toUpperCase()}
                </span>
              </div>
            </div>

            {riskReasons.length > 0 && (
              <div className="bg-gray-50 rounded-lg p-4 mt-4">
                <p className="text-sm font-semibold text-gray-900 mb-2">Risk Factors:</p>
                <ul className="list-disc pl-5 text-sm text-gray-700 space-y-1">
                  {riskReasons.map((r: string, idx: number) => (
                    <li key={idx}>{r}</li>
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
                  <p className="text-xs text-gray-700">Delete immediately or document justification</p>
                </div>
              )}

              {daysSinceLastActivity !== null && daysSinceLastActivity > 90 && (
                <div className="bg-white rounded-lg p-3 border border-orange-200">
                  <p className="text-sm font-semibold text-orange-900 mb-1">⚠️ Dormant Account</p>
                  <p className="text-xs text-gray-700">Review and revoke access if not needed</p>
                </div>
              )}

              {hasOwnerRole && (
                <div className="bg-white rounded-lg p-3 border border-yellow-200">
                  <p className="text-sm font-semibold text-yellow-900 mb-1">🔍 High Privilege</p>
                  <p className="text-xs text-gray-700">Verify Owner is required for job function</p>
                </div>
              )}

              <div className="bg-white rounded-lg p-3 border border-blue-200">
                <p className="text-sm font-semibold text-blue-900 mb-1">📊 Regular Review</p>
                <p className="text-xs text-gray-700">Schedule quarterly access review</p>
              </div>
            </div>
          </div>

          {/* Compliance Impact */}
          <div className="bg-purple-50 border border-purple-200 rounded-lg p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-4">📋 Compliance Impact (HIPAA)</h2>
            <p className="text-sm text-gray-600 mb-4">Additional frameworks (PCI-DSS, SOX, FERPA, ISO 27001) coming in Week 8</p>
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
