import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../../contexts/ConnectionContext';

interface CorrelationStats {
  humans_linked: number;
  total_links: number;
  open_findings: number;
  findings_by_severity: Record<string, number>;
}

export default function IdentityCorrelationWidget() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [stats, setStats] = useState<CorrelationStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch(withConnection('/api/dashboard/identity-correlation'))
      .then(r => r.ok ? r.json() : null)
      .then(data => { setStats(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, [selectedConnectionId]);

  if (loading) {
    return (
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex items-center gap-2 mb-4">
          <svg className="w-5 h-5 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
          <h3 className="text-sm font-semibold text-gray-900">Identity Correlation</h3>
        </div>
        <div className="animate-pulse space-y-3">
          {[1, 2].map(i => <div key={i} className="h-8 bg-gray-100 rounded" />)}
        </div>
      </div>
    );
  }

  const critical = stats?.findings_by_severity?.critical ?? 0;
  const high = stats?.findings_by_severity?.high ?? 0;

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <svg className="w-5 h-5 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
          <h3 className="text-sm font-semibold text-gray-900">Identity Correlation</h3>
          {(stats?.open_findings ?? 0) > 0 && (
            <span className="px-1.5 py-0.5 text-[10px] font-bold bg-red-100 text-red-700 rounded-full">
              {stats?.open_findings}
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 mb-3">
        <div className="bg-blue-50 rounded-lg p-2.5">
          <div className="text-lg font-bold text-blue-700">{stats?.humans_linked ?? 0}</div>
          <div className="text-[10px] text-gray-500 font-medium">Linked Pairs</div>
        </div>
        <div className="bg-indigo-50 rounded-lg p-2.5">
          <div className="text-lg font-bold text-indigo-700">{stats?.total_links ?? 0}</div>
          <div className="text-[10px] text-gray-500 font-medium">Total Links</div>
        </div>
        <div className={`${(stats?.open_findings ?? 0) > 0 ? 'bg-orange-50' : 'bg-green-50'} rounded-lg p-2.5`}>
          <div className={`text-lg font-bold ${(stats?.open_findings ?? 0) > 0 ? 'text-orange-700' : 'text-green-700'}`}>
            {stats?.open_findings ?? 0}
          </div>
          <div className="text-[10px] text-gray-500 font-medium">Open Findings</div>
        </div>
        <div className={`${critical > 0 ? 'bg-red-50' : 'bg-green-50'} rounded-lg p-2.5`}>
          <div className={`text-lg font-bold ${critical > 0 ? 'text-red-700' : 'text-green-700'}`}>
            {critical}
          </div>
          <div className="text-[10px] text-gray-500 font-medium">Critical</div>
        </div>
      </div>

      <button
        onClick={() => navigate('/identity-correlation')}
        className="w-full text-center text-xs text-blue-600 hover:text-blue-700 font-medium py-1"
      >
        View All &rarr;
      </button>
    </div>
  );
}
