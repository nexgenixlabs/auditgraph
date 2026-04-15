import React from 'react';
import {
  type IdentityDetailsResponse,
  type Owner,
  DataSource,
} from './types';

interface OwnershipTabProps {
  data: IdentityDetailsResponse;
  identity: IdentityDetailsResponse['identity'];
}

export function OwnershipTab({ data, identity }: OwnershipTabProps) {
  return (
    <div>
      {(data?.owners || []).length === 0 ? (
        <div className="text-center py-8">
          <svg className="w-12 h-12 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
          </svg>
          <div className="text-sm text-gray-500">No owners discovered for this identity.</div>
          <div className="text-xs text-gray-400 mt-1">
            Assigning owners ensures accountability and faster incident response.
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {data!.owners.map((o: Owner, idx: number) => (
            <div key={idx} className="border rounded-xl p-4 flex items-center justify-between">
              <div>
                <div className="font-semibold text-gray-900">
                  {o.owner_display_name || o.owner_upn || o.owner_object_id}
                </div>
                {o.owner_upn && (
                  <div className="text-xs text-gray-500 mt-0.5">{o.owner_upn}</div>
                )}
                <div className="text-xs text-gray-400 mt-0.5">Type: {o.owner_type || 'user'}</div>
              </div>
              {o.is_primary_owner && (
                <span className="px-2 py-1 rounded-full text-xs font-semibold bg-green-100 text-green-700">
                  Primary Owner
                </span>
              )}
            </div>
          ))}
        </div>
      )}
      <DataSource label="Microsoft Graph API" apiSource="/servicePrincipals/{id}/owners" collectedAt={data?.evidence?.collected_at} />
    </div>
  );
}
