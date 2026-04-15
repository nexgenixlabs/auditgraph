import React from 'react';

interface RoleTopology {
  workloadType: string;
  confidence: number;
  roleAssignments: Array<{ roleName: string; scope: string }>;
  topResources: string[];
}

const WORKLOAD_BADGE: Record<string, string> = {
  ContainerisedApp: 'bg-cyan-100 text-cyan-700 border-cyan-200',
  ServerlessWorker: 'bg-violet-100 text-violet-700 border-violet-200',
  InfrastructureOrIaC: 'bg-orange-100 text-orange-700 border-orange-200',
  BackendDatabaseService: 'bg-emerald-100 text-emerald-700 border-emerald-200',
  DataPipeline: 'bg-purple-100 text-purple-700 border-purple-200',
  MonitoringAgent: 'bg-blue-100 text-blue-700 border-blue-200',
  Unknown: 'bg-gray-100 text-gray-500 border-gray-200',
};

function ConfidenceRing({ confidence }: { confidence: number }): React.ReactElement {
  const r = 20;
  const circ = 2 * Math.PI * r;
  const offset = circ - (confidence / 100) * circ;
  const color = confidence >= 80 ? '#22c55e' : confidence >= 50 ? '#f59e0b' : '#9ca3af';

  return (
    <svg width="50" height="50" className="shrink-0">
      <circle cx="25" cy="25" r={r} fill="none" stroke="#e5e7eb" strokeWidth="4" />
      <circle cx="25" cy="25" r={r} fill="none" stroke={color}
        strokeWidth="4" strokeDasharray={circ} strokeDashoffset={offset}
        strokeLinecap="round" transform="rotate(-90 25 25)" />
      <text x="25" y="25" textAnchor="middle" dominantBaseline="central"
        className="text-[10px] font-bold fill-gray-700">{confidence}%</text>
    </svg>
  );
}

function scopeLabel(scope: string): string {
  if (!scope) return '';
  const parts = scope.split('/');
  if (parts.length <= 3) return scope;
  // Show last 2 segments
  return '.../' + parts.slice(-2).join('/');
}

export function RoleTopologyPanel({ topology }: { topology: RoleTopology | null }): React.ReactElement {
  return (
    <div className="bg-white border border-gray-200 rounded-lg">
      <div className="px-4 py-3 border-b border-gray-100">
        <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider flex items-center gap-2">
          <svg className="w-4 h-4 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
          </svg>
          Role Topology
        </h3>
      </div>

      <div className="p-4">
        {!topology ? (
          <p className="text-xs text-gray-400 italic py-4 text-center">No role topology inferred yet.</p>
        ) : (
          <div className="space-y-4">
            {/* Workload type badge + confidence ring */}
            <div className="flex items-center gap-4">
              <ConfidenceRing confidence={topology.confidence} />
              <div>
                <span className={`inline-block px-3 py-1 rounded-lg border text-sm font-bold ${WORKLOAD_BADGE[topology.workloadType] || WORKLOAD_BADGE.Unknown}`}>
                  {topology.workloadType}
                </span>
                <p className="text-[10px] text-gray-500 mt-1">Inferred workload classification</p>
              </div>
            </div>

            {/* Top 5 role assignments */}
            {topology.roleAssignments.length > 0 && (
              <div>
                <p className="text-[10px] font-bold text-gray-500 uppercase mb-1.5">Role Assignments</p>
                <div className="space-y-1">
                  {topology.roleAssignments.slice(0, 5).map((ra, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-50 text-blue-700 shrink-0">{ra.roleName}</span>
                      <span className="text-gray-400">on</span>
                      <span className="text-gray-600 truncate font-mono text-[10px]" title={ra.scope}>{scopeLabel(ra.scope)}</span>
                    </div>
                  ))}
                  {topology.roleAssignments.length > 5 && (
                    <p className="text-[10px] text-gray-400 italic">+{topology.roleAssignments.length - 5} more</p>
                  )}
                </div>
              </div>
            )}

            {/* Top resources chips */}
            {topology.topResources.length > 0 && (
              <div>
                <p className="text-[10px] font-bold text-gray-500 uppercase mb-1.5">Top Resources</p>
                <div className="flex flex-wrap gap-1">
                  {topology.topResources.map((r, i) => (
                    <span key={i} className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-gray-100 text-gray-600 truncate max-w-[200px]" title={r}>
                      {r}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default RoleTopologyPanel;
