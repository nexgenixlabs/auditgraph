import React, { useState } from 'react';

interface AppRegistrationMetadata {
  displayName: string;
  owners: Array<{ displayName: string; id?: string; userPrincipalName?: string }>;
  notes: string;
  description: string;
  inferredHostUrls: string[];
  createdAt: string | null;
}

function CopyField({ label, value }: { label: string; value: string }): React.ReactElement {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="text-gray-500 shrink-0">{label}:</span>
      <span className="text-gray-700 font-mono text-[10px] truncate">{value}</span>
      <button
        onClick={handleCopy}
        className="shrink-0 text-gray-400 hover:text-gray-600 transition-colors"
        title={`Copy ${label}`}
      >
        {copied ? (
          <svg className="w-3.5 h-3.5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        )}
      </button>
    </div>
  );
}

function formatDate(iso: string | null): string {
  if (!iso) return 'Unknown';
  try {
    return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return iso;
  }
}

function azurePortalUrl(url: string): string | null {
  if (url.includes('.azurewebsites.net')) {
    const name = url.replace(/https?:\/\//, '').split('.')[0];
    return `https://portal.azure.com/#view/WebsitesExtension/FunctionMenuBlade/~/Overview/resourceId/%2Fsubscriptions%2F...%2FresourceGroups%2F...%2Fproviders%2FMicrosoft.Web%2Fsites%2F${name}`;
  }
  if (url.includes('.azurecontainerapps.io')) {
    return 'https://portal.azure.com/#view/Microsoft_Azure_ContainerApps';
  }
  return null;
}

export function OwnerGraphPanel({ appReg, objectId, clientId }: { appReg: AppRegistrationMetadata | null; objectId?: string; clientId?: string }): React.ReactElement {
  return (
    <div className="bg-white border border-gray-200 rounded-lg">
      <div className="px-4 py-3 border-b border-gray-100">
        <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider flex items-center gap-2">
          <svg className="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
          </svg>
          Ownership & Registration
        </h3>
      </div>

      <div className="p-4">
        {/* Identity IDs — always shown regardless of appReg */}
        {(objectId || clientId) && (
          <div className="space-y-1.5 mb-3 pb-3 border-b border-gray-100">
            {objectId && <CopyField label="Object ID" value={objectId} />}
            {clientId && <CopyField label="Client ID" value={clientId} />}
          </div>
        )}

        {!appReg ? (
          <p className="text-xs text-gray-400 italic py-4 text-center">No app registration metadata found.</p>
        ) : (
          <div className="space-y-3">
            {/* Created + owners */}
            <div className="flex items-center gap-2 text-xs text-gray-600">
              <svg className="w-3.5 h-3.5 text-gray-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
              Created {formatDate(appReg.createdAt)}
            </div>

            {/* Owners */}
            <div>
              <p className="text-[10px] font-bold text-gray-500 uppercase mb-1.5">Owners</p>
              {appReg.owners.length === 0 ? (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  No owner assigned
                </span>
              ) : (
                <div className="space-y-1">
                  {appReg.owners.map((o, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <div className="w-5 h-5 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-[9px] font-bold shrink-0">
                        {(o.displayName || '?')[0].toUpperCase()}
                      </div>
                      <span className="text-gray-700">{o.displayName}</span>
                      {o.userPrincipalName && (
                        <span className="text-[10px] text-gray-400 font-mono truncate">{o.userPrincipalName}</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Inferred host URLs */}
            {appReg.inferredHostUrls.length > 0 && (
              <div>
                <p className="text-[10px] font-bold text-gray-500 uppercase mb-1.5">Inferred Host URLs</p>
                <div className="space-y-1">
                  {appReg.inferredHostUrls.map((url, i) => {
                    const portalUrl = azurePortalUrl(url);
                    return (
                      <div key={i} className="flex items-center gap-2">
                        <span className="text-xs text-blue-600 font-mono truncate">{url}</span>
                        {portalUrl && (
                          <a
                            href={portalUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[9px] text-blue-500 hover:text-blue-700 shrink-0"
                            onClick={e => e.stopPropagation()}
                          >
                            Portal &rarr;
                          </a>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Notes */}
            {appReg.notes && (
              <div>
                <p className="text-[10px] font-bold text-gray-500 uppercase mb-0.5">Notes</p>
                <p className="text-xs text-gray-600">{appReg.notes}</p>
              </div>
            )}

            {/* Description */}
            {appReg.description && (
              <div>
                <p className="text-[10px] font-bold text-gray-500 uppercase mb-0.5">Description</p>
                <p className="text-xs text-gray-600">{appReg.description}</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default OwnerGraphPanel;
