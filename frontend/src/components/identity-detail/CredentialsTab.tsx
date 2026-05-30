import React, { useEffect, useState } from 'react';
import {
  type IdentityDetailsResponse,
  formatDate,
  credentialCountdown,
  DataSource,
  DATA_EXPLANATIONS,
  safeLower,
} from './types';
import { TIME_MS } from '../../constants/metrics';

// AG-148: Issuer type display labels
const ISSUER_TYPE_LABELS: Record<string, string> = {
  github_actions: 'GitHub Actions',
  terraform_cloud: 'Terraform Cloud',
  azure_devops: 'Azure DevOps',
  google_workload: 'Google Cloud Workload Identity',
  azure_managed_identity: 'Azure Managed Identity',
  external_oidc: 'External OIDC',
  aks_workload: 'AKS Workload Identity',
};

interface FederatedCredential {
  credential_id: string;
  name: string;
  issuer: string;
  subject: string;
  audiences: string[];
  issuer_type: string;
  description: string;
}

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
                  new Date(identity.credential_expiration) < new Date(Date.now() + 30 * TIME_MS.DAY) ? 'text-orange-700' :
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

      {/* AG-148: Federated Credentials Section */}
      {!!identity.has_federated_credentials && (
        <FederatedCredentialsSection identityId={identity.identity_id} credentialCount={identity.credential_count ?? 0} />
      )}
    </div>
  );
}

export function FederatedCredentialsSection({ identityId, credentialCount }: { identityId: string; credentialCount: number }) {
  const [creds, setCreds] = useState<FederatedCredential[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/identities/${identityId}/lineage`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.federated_credentials) {
          setCreds(data.federated_credentials);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [identityId]);

  if (loading) return <div className="text-sm text-gray-400 py-2">Loading federated credentials...</div>;
  if (!creds.length) return null;

  const hasOnlyFederated = credentialCount === 0;

  return (
    <div className="mt-4">
      <h3 className="text-sm font-semibold text-gray-700 mb-2">Federated Credentials</h3>
      <div className="space-y-2">
        {creds.map((fc, idx) => (
          <div key={fc.credential_id || idx} className="bg-gray-50 border border-gray-200 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-indigo-100 text-indigo-800">
                {ISSUER_TYPE_LABELS[fc.issuer_type] || fc.issuer_type}
              </span>
              {fc.name && <span className="text-sm font-medium text-gray-900">{fc.name}</span>}
            </div>
            <div className="text-xs text-gray-600 mt-1">
              <span className="font-medium">Subject:</span> {fc.subject || '—'}
            </div>
            <div className="text-xs text-gray-500 mt-0.5">
              <span className="font-medium">Issuer:</span> {fc.issuer}
            </div>
            {hasOnlyFederated && (
              <div className="mt-2 flex items-center gap-1 text-xs text-orange-700 bg-orange-50 rounded px-2 py-1">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
                External pipeline dependency — deletion risk HIGH
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
