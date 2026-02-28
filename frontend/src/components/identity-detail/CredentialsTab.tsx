import React from 'react';
import {
  type IdentityDetailsResponse,
  formatDate,
  credentialCountdown,
  DataSource,
  DATA_EXPLANATIONS,
  safeLower,
} from './types';

interface CredentialsTabProps {
  identity: IdentityDetailsResponse['identity'];
  data: IdentityDetailsResponse;
}

export function CredentialsTab({ identity, data }: CredentialsTabProps) {
  return (
    <div className="space-y-4">
      <DataSource label="Microsoft Graph API" apiSource="/applications/{id}/passwordCredentials + keyCredentials" collectedAt={data?.evidence?.collected_at} />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gray-50 rounded-xl p-4">
          <div className="text-xs text-gray-500 mb-1">Credential Count</div>
          {(identity.identity_category === 'human_user' || identity.identity_category === 'guest') ? (
            <div className="text-sm text-gray-400 italic mt-1" title={DATA_EXPLANATIONS.CREDENTIAL_NA}>N/A — Entra ID auth</div>
          ) : (identity.credential_count ?? 0) > 0 ? (
            <div className="text-2xl font-bold text-gray-900">{identity.credential_count}</div>
          ) : (
            <div>
              <div className="text-2xl font-bold text-gray-900">0</div>
              <div className="text-[10px] text-gray-400">No secrets or certificates registered</div>
            </div>
          )}
        </div>
        <div className="bg-gray-50 rounded-xl p-4">
          <div className="text-xs text-gray-500 mb-1">Status</div>
          <div className="text-sm font-semibold">
            {identity.credential_status ? (
              <span className={
                safeLower(identity.credential_status) === 'valid' ? 'text-green-700' :
                safeLower(identity.credential_status) === 'expired' ? 'text-red-700' :
                safeLower(identity.credential_status) === 'expiring_soon' ? 'text-orange-700' :
                'text-gray-700'
              }>
                {identity.credential_status}
              </span>
            ) : (identity.identity_category === 'human_user' || identity.identity_category === 'guest') ? (
              <span className="text-gray-400 italic">N/A</span>
            ) : (
              <span className="text-gray-400 italic" title="No credentials registered for this identity">No credentials</span>
            )}
          </div>
        </div>
        <div className="bg-gray-50 rounded-xl p-4">
          <div className="text-xs text-gray-500 mb-1">Next Expiration</div>
          <div className="text-sm font-semibold text-gray-900">
            {identity.credential_expiration ? (
              <div>
                <span className={
                  new Date(identity.credential_expiration) < new Date() ? 'text-red-700' :
                  new Date(identity.credential_expiration) < new Date(Date.now() + 30 * 86400000) ? 'text-orange-700' :
                  'text-green-700'
                }>
                  {formatDate(identity.credential_expiration)}
                </span>
                <div className="mt-1">{credentialCountdown(identity.credential_expiration)}</div>
              </div>
            ) : (identity.credential_count ?? 0) > 0 ? (
              <span className="text-yellow-600" title="Credentials exist but have no expiration set">No expiration set</span>
            ) : (
              <span className="text-gray-400 italic">N/A</span>
            )}
          </div>
        </div>
      </div>

      {(identity.identity_category === 'human_user' || identity.identity_category === 'guest') && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 text-sm text-blue-700">
          {DATA_EXPLANATIONS.CREDENTIAL_NA}.
          Secret/certificate tracking applies to service principals and managed identities.
        </div>
      )}
    </div>
  );
}
