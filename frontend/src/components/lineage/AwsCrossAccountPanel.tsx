import React from 'react';

interface CrossAccountBinding {
  resource_id: string;
  resource_type: string;
  resource_name: string;
  binding_method: string;
  confidence_score: number;
  binding_evidence: Record<string, unknown>;
}

function confidenceColor(score: number): string {
  if (score >= 85) return 'bg-green-100 text-green-700';
  if (score >= 60) return 'bg-blue-100 text-blue-700';
  if (score >= 40) return 'bg-yellow-100 text-yellow-700';
  return 'bg-gray-100 text-gray-500';
}

export function AwsCrossAccountPanel({ bindings }: { bindings: CrossAccountBinding[] }): React.ReactElement {
  const crossAccountBindings = bindings.filter(b => {
    const ev = b.binding_evidence || {};
    return !!ev.isCrossAccount || b.resource_id?.includes('/cross-account/') ||
           (ev.trustType === 'CrossAccountAssumeRole');
  });

  if (crossAccountBindings.length === 0) return <></>;

  return (
    <div className="bg-white border border-gray-200 rounded-lg">
      <div className="px-4 py-3 border-b border-gray-100">
        <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider flex items-center gap-2">
          <svg className="w-4 h-4 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
          Cross-Account Trust
          <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-orange-100 text-orange-600 font-mono">
            {crossAccountBindings.length}
          </span>
        </h3>
      </div>

      <div className="p-3 space-y-2">
        {crossAccountBindings.map((b, i) => {
          const ev = b.binding_evidence || {};
          const targetAccount = (ev.targetAccountId as string) || (ev.trustedAccount as string) || '';
          const hasExternalId = !!ev.externalId;

          return (
            <div key={i} className="border border-orange-100 rounded-md p-2.5 hover:bg-orange-50/30 transition-colors">
              <div className="flex items-start gap-2">
                <svg className="w-4 h-4 text-orange-500 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                </svg>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-gray-900 truncate">
                      {b.resource_name || targetAccount || b.resource_id}
                    </span>
                    <span className={`px-1.5 py-0 rounded text-[9px] font-bold ${confidenceColor(b.confidence_score)}`}>
                      {b.confidence_score}%
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 mt-1">
                    {targetAccount && (
                      <span className="px-1.5 py-0 rounded text-[9px] font-semibold bg-gray-100 text-gray-600">
                        Account: {targetAccount}
                      </span>
                    )}
                    {hasExternalId && (
                      <span className="px-1.5 py-0 rounded text-[9px] font-semibold bg-green-50 text-green-600">
                        ExternalId
                      </span>
                    )}
                    {!hasExternalId && (
                      <span className="px-1.5 py-0 rounded text-[9px] font-semibold bg-red-50 text-red-600">
                        No ExternalId
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default AwsCrossAccountPanel;
