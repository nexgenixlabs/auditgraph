import React from 'react';
import { Link, useNavigate } from 'react-router-dom';

interface RecentChangesProps {
  hasData: boolean;
  currentRunId?: number;
  previousRunId?: number;
  newIdentities: number;
  removedIdentities: number;
  permissionChanges: number;
  riskChanges: number;
  credentialChanges: number;
  totalChanges: number;
  createdAt?: string;
}

export default function RecentChanges({
  hasData,
  currentRunId,
  previousRunId,
  newIdentities,
  removedIdentities,
  permissionChanges,
  riskChanges,
  credentialChanges,
  totalChanges,
  createdAt,
}: RecentChangesProps) {
  const navigate = useNavigate();

  if (!hasData) {
    return (
      <div className="bg-white border rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          <div className="text-sm font-semibold text-gray-900">Recent Changes</div>
        </div>
        <div className="text-sm text-gray-400 italic">
          Change tracking available after 2+ snapshots
        </div>
      </div>
    );
  }

  const changeTypes = [
    { label: 'New Identities', count: newIdentities, color: 'text-green-600', bg: 'bg-green-50', icon: '+', link: '/drift' },
    { label: 'Removed', count: removedIdentities, color: 'text-red-600', bg: 'bg-red-50', icon: '-', link: '/drift' },
    { label: 'Permission Changes', count: permissionChanges, color: 'text-orange-600', bg: 'bg-orange-50', icon: '~', link: '/drift' },
    { label: 'Risk Escalations', count: riskChanges, color: 'text-purple-600', bg: 'bg-purple-50', icon: '!', link: '/identities?risk_level=critical' },
    { label: 'Credential Changes', count: credentialChanges, color: 'text-yellow-700', bg: 'bg-yellow-50', icon: '*', link: '/identities?credential_status=expiring_soon' },
  ];

  return (
    <div className="bg-white border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          <div className="text-sm font-semibold text-gray-900">Recent Changes</div>
        </div>
        <span className="text-[10px] text-gray-400">
          Snapshot #{currentRunId} vs #{previousRunId}
        </span>
      </div>

      {totalChanges === 0 ? (
        <div className="flex items-center gap-2 p-3 bg-green-50 rounded-lg">
          <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span className="text-green-700 font-medium text-sm">No changes detected</span>
          <span className="text-xs text-gray-500 ml-auto">Environment is stable</span>
        </div>
      ) : (
        <>
          <div className="text-xs text-gray-500 mb-3">
            {totalChanges} change{totalChanges !== 1 ? 's' : ''} detected
            {createdAt && ` · ${new Date(createdAt).toLocaleString()}`}
          </div>
          <div className="space-y-1.5">
            {changeTypes.filter(ct => ct.count > 0).map(ct => (
              <button key={ct.label} onClick={() => navigate(ct.link)} className={`flex items-center justify-between p-2 rounded-lg ${ct.bg} w-full text-left hover:opacity-80 transition cursor-pointer`}>
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-mono font-bold ${ct.color}`}>{ct.icon}</span>
                  <span className="text-xs text-gray-700">{ct.label}</span>
                </div>
                <span className={`text-sm font-bold ${ct.color}`}>{ct.count}</span>
              </button>
            ))}
          </div>
        </>
      )}

      {/* View History link */}
      <div className="mt-3 pt-3 border-t">
        <Link
          to="/drift"
          className="text-xs text-blue-600 hover:text-blue-800 hover:underline font-medium flex items-center gap-1"
        >
          View History
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
        </Link>
      </div>
    </div>
  );
}
