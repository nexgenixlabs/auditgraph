import React from 'react';

interface ResourceBinding {
  resource_id: string;
  resource_type: string;
  resource_name: string;
  resource_group: string;
  subscription_id: string;
  region: string;
  binding_method: string;
  confidence_score: number;
  binding_evidence: Record<string, unknown>;
  last_verified_at: string | null;
}

const TYPE_ICON: Record<string, string> = {
  // Azure
  AppService: 'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253',
  FunctionApp: 'M13 10V3L4 14h7v7l9-11h-7z',
  AKS: 'M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-7.038 0l-2.387.477a2 2 0 00-1.022.547l-2.386 2.386a2 2 0 00-.147 2.655l.078.098 4.5 4.5a2 2 0 002.828 0l4.5-4.5.078-.098a2 2 0 00-.147-2.655l-2.386-2.386z',
  ContainerApp: 'M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4',
  LogicApp: 'M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zm0 8a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zm12 0a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z',
  AutomationAccount: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z',
  DataFactory: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4',
  // AWS
  AWSTrustPolicy: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
  AWSLambda: 'M13 10V3L4 14h7v7l9-11h-7z',
  AWSECSTask: 'M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4',
  AWSEKSWorkload: 'M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-7.038 0l-2.387.477a2 2 0 00-1.022.547l-2.386 2.386a2 2 0 00-.147 2.655l.078.098 4.5 4.5a2 2 0 002.828 0l4.5-4.5.078-.098a2 2 0 00-.147-2.655l-2.386-2.386z',
  AWSGitHubOIDC: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1',
  S3Bucket: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4',
  KMSKey: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z',
  SQSQueue: 'M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z',
  SNSTopic: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9',
};

function confidenceColor(score: number): string {
  if (score >= 85) return 'bg-green-100 text-green-700';
  if (score >= 60) return 'bg-blue-100 text-blue-700';
  if (score >= 40) return 'bg-yellow-100 text-yellow-700';
  return 'bg-gray-100 text-gray-500';
}

export function WorkloadAssociationsPanel({ bindings }: { bindings: ResourceBinding[] }): React.ReactElement {
  return (
    <div className="bg-white border border-gray-200 rounded-lg">
      <div className="px-4 py-3 border-b border-gray-100">
        <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider flex items-center gap-2">
          <svg className="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
          </svg>
          Workload Associations
          {bindings.length > 0 && (
            <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-blue-100 text-blue-600 font-mono">{bindings.length}</span>
          )}
        </h3>
      </div>

      <div className="p-3">
        {bindings.length === 0 ? (
          <p className="text-xs text-gray-400 italic py-4 text-center">No static workload associations found.</p>
        ) : (
          <div className="space-y-2">
            {bindings.map((b, i) => {
              const icon = TYPE_ICON[b.resource_type] || TYPE_ICON.AppService;
              return (
                <div key={i} className="border border-gray-100 rounded-md p-2.5 hover:bg-gray-50 transition-colors">
                  <div className="flex items-start gap-2">
                    <svg className="w-4 h-4 text-blue-500 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={icon} />
                    </svg>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium text-gray-900 truncate">{b.resource_name || b.resource_id}</span>
                        <span className={`px-1.5 py-0 rounded text-[9px] font-semibold shrink-0 ${
                          b.resource_type.startsWith('AWS') || ['S3Bucket', 'KMSKey', 'SQSQueue', 'SNSTopic'].includes(b.resource_type)
                            ? 'bg-amber-50 text-amber-700'
                            : 'bg-purple-50 text-purple-600'
                        }`}>{b.resource_type}</span>
                      </div>
                      <div className="text-[10px] text-gray-500 mt-0.5 truncate">
                        {b.resource_group && <span>{b.resource_group}</span>}
                        {b.resource_group && b.region && <span> &middot; </span>}
                        {b.region && <span>{b.region}</span>}
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-[10px] text-gray-400">
                          Binding: <span className="font-medium text-gray-600">{b.binding_method}</span>
                        </span>
                        <span className={`px-1.5 py-0 rounded text-[9px] font-bold ${confidenceColor(b.confidence_score)}`}>
                          {b.confidence_score}%
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

export default WorkloadAssociationsPanel;
