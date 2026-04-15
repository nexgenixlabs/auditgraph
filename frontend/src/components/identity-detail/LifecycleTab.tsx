import React from 'react';
import {
  type IdentityDetailsResponse,
  formatDate,
  DataSource,
} from './types';

// ─── Props ──────────────────────────────────────────────────────────

interface LifecycleTabProps {
  lifecycleData: any;
  lifecycleLoading: boolean;
  lifecycleFilter: string;
  setLifecycleFilter: React.Dispatch<React.SetStateAction<string>>;
  data: IdentityDetailsResponse;
}

// ─── LifecycleTab ───────────────────────────────────────────────────

export function LifecycleTab({
  lifecycleData,
  lifecycleLoading,
  lifecycleFilter,
  setLifecycleFilter,
  data,
}: LifecycleTabProps) {
  return (
    <div className="space-y-6">
      {lifecycleLoading ? (
        <div className="animate-pulse space-y-4">
          <div className="h-20 bg-gray-100 rounded-xl" />
          {[1, 2, 3, 4].map(i => <div key={i} className="h-16 bg-gray-100 rounded-xl" />)}
        </div>
      ) : !lifecycleData || lifecycleData.total_events === 0 ? (
        <div className="text-center py-12">
          <svg className="w-12 h-12 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="text-sm font-medium text-gray-600">Insufficient snapshot history for lifecycle comparison.</div>
          <div className="text-xs text-gray-400 mt-1">Lifecycle tab requires 2+ snapshots to build a change timeline.</div>
        </div>
      ) : (
        <>
          {/* Summary bar */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <div className="bg-gray-50 rounded-xl p-3 text-center">
              <div className="text-xl font-bold text-gray-900">{lifecycleData.summary.total_runs_observed}</div>
              <div className="text-[10px] text-gray-500 mt-0.5">Snapshots Observed</div>
            </div>
            <div className="bg-gray-50 rounded-xl p-3 text-center">
              <div className="text-xl font-bold text-gray-900">{lifecycleData.total_events}</div>
              <div className="text-[10px] text-gray-500 mt-0.5">Total Events</div>
            </div>
            <div className="bg-red-50 rounded-xl p-3 text-center">
              <div className="text-xl font-bold text-red-700">{lifecycleData.summary.risk_changes}</div>
              <div className="text-[10px] text-red-600 mt-0.5">Risk Changes</div>
            </div>
            <div className="bg-orange-50 rounded-xl p-3 text-center">
              <div className="text-xl font-bold text-orange-700">{lifecycleData.summary.credential_events}</div>
              <div className="text-[10px] text-orange-600 mt-0.5">Credential Events</div>
            </div>
            <div className="bg-blue-50 rounded-xl p-3 text-center">
              <div className="text-xl font-bold text-blue-700">{lifecycleData.summary.access_changes}</div>
              <div className="text-[10px] text-blue-600 mt-0.5">Access Changes</div>
            </div>
            <div className="bg-purple-50 rounded-xl p-3 text-center">
              <div className="text-xl font-bold text-purple-700">{lifecycleData.summary.status_changes}</div>
              <div className="text-[10px] text-purple-600 mt-0.5">Status Changes</div>
            </div>
          </div>

          {/* Date range */}
          <div className="text-xs text-gray-500 flex items-center gap-2">
            <span>First seen: {lifecycleData.summary.first_seen ? new Date(lifecycleData.summary.first_seen).toLocaleDateString() : 'N/A'}</span>
            <span className="text-gray-300">|</span>
            <span>Last seen: {lifecycleData.summary.last_seen ? new Date(lifecycleData.summary.last_seen).toLocaleDateString() : 'N/A'}</span>
          </div>

          {/* Category filter */}
          <div className="flex items-center gap-2 flex-wrap">
            {['all', 'risk', 'credential', 'access', 'lifecycle', 'activity', 'compliance'].map(cat => (
              <button
                key={cat}
                onClick={() => setLifecycleFilter(cat)}
                className={`px-3 py-1 rounded-lg text-xs font-medium border transition ${
                  lifecycleFilter === cat
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-600 border-gray-300 hover:bg-gray-50'
                }`}
              >
                {cat === 'all' ? 'All' : cat.charAt(0).toUpperCase() + cat.slice(1)}
              </button>
            ))}
          </div>

          {/* Timeline */}
          <div className="relative">
            {/* Vertical line */}
            <div className="absolute left-[7px] top-2 bottom-2 w-0.5 bg-gray-200" />

            <div className="space-y-0">
              {(lifecycleData.events as any[])
                .filter((ev: any) => lifecycleFilter === 'all' || ev.category === lifecycleFilter)
                .map((ev: any, idx: number) => {
                  const sevColors: Record<string, string> = {
                    critical: 'bg-red-500',
                    high: 'bg-orange-500',
                    medium: 'bg-yellow-500',
                    info: 'bg-blue-400',
                  };
                  const catBadge: Record<string, string> = {
                    risk: 'bg-red-50 text-red-700',
                    credential: 'bg-orange-50 text-orange-700',
                    access: 'bg-blue-50 text-blue-700',
                    lifecycle: 'bg-purple-50 text-purple-700',
                    activity: 'bg-cyan-50 text-cyan-700',
                    compliance: 'bg-green-50 text-green-700',
                  };
                  return (
                    <div key={idx} className="flex items-start gap-4 py-3 group">
                      {/* Dot */}
                      <div className={`w-3.5 h-3.5 rounded-full flex-shrink-0 mt-0.5 ring-2 ring-white ${sevColors[ev.severity] || 'bg-gray-400'}`} />

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium text-gray-900">{ev.description}</span>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${catBadge[ev.category] || 'bg-gray-100 text-gray-600'}`}>
                            {ev.category}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 mt-0.5 text-[11px] text-gray-400">
                          <span>{ev.timestamp ? new Date(ev.timestamp).toLocaleString() : 'Unknown'}</span>
                          {ev.run_id && <span>Snapshot #{ev.run_id}</span>}
                          {ev.previous_value && ev.current_value && (
                            <span className="font-mono text-gray-500">{ev.previous_value} &rarr; {ev.current_value}</span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              {(lifecycleData.events as any[]).filter((ev: any) => lifecycleFilter === 'all' || ev.category === lifecycleFilter).length === 0 && (
                <div className="text-center py-8 text-sm text-gray-400">No events in this category.</div>
              )}
            </div>
          </div>
        </>
      )}
      <DataSource label="AuditGraph Lifecycle Engine" apiSource="Cross-snapshot identity comparison" collectedAt={data?.evidence?.collected_at} />
    </div>
  );
}
