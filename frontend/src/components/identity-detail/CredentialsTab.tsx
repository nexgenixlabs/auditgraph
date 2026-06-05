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
  external_federation: 'External Federation',
};

interface FederatedCredential {
  credential_id: string;
  name: string;
  issuer: string;
  subject: string;
  audiences: string[];
  issuer_type: string;
  description: string | null;
  risk_level?: string;
  reasons?: string[];
  framework_refs?: { nist?: string[]; cis_azure?: string[]; mitre?: string[] };
}

interface FederatedCredentialsResp {
  identity_id: string;
  credentials: FederatedCredential[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    flag_set: boolean;
    count_field: number;
  };
  last_collected_at: string | null;
}

interface CredentialsTabProps {
  identity: IdentityDetailsResponse['identity'];
  data: IdentityDetailsResponse;
}

export function CredentialsTab({ identity, data }: CredentialsTabProps) {
  const id = identity as IdentityDetailsResponse['identity'] & {
    federated_cred_count?: number;
    is_federated?: boolean;
  };
  const hasFederatedSignal =
    !!id.has_federated_credentials ||
    (id.federated_cred_count ?? 0) > 0 ||
    !!id.is_federated;

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

      {/* AG-148 + AG-150: Federated Credentials Section.
          Render whenever ANY federated signal is present, not just when the
          flag is true — protects against discovery-side flag drift. */}
      {hasFederatedSignal && (
        <FederatedCredentialsSection
          identityId={identity.identity_id}
          credentialCount={identity.credential_count ?? 0}
        />
      )}
    </div>
  );
}

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-300',
  high:     'bg-orange-100 text-orange-800 border-orange-300',
  medium:   'bg-amber-100 text-amber-800 border-amber-300',
  low:      'bg-emerald-100 text-emerald-800 border-emerald-300',
};

export function FederatedCredentialsSection({
  identityId,
  credentialCount,
}: {
  identityId: string;
  credentialCount: number;
}) {
  const [resp, setResp] = useState<FederatedCredentialsResp | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancel = false;
    // AG-150: Use the dedicated endpoint. Lineage endpoint is the fallback for
    // legacy frontends; we don't need its full payload here.
    fetch(`/api/identities/${encodeURIComponent(identityId)}/federated-credentials`)
      .then(r => r.ok ? r.json() : Promise.reject(new Error('fetch_failed')))
      .then((d: FederatedCredentialsResp) => { if (!cancel) setResp(d); })
      .catch(() => { if (!cancel) setError(true); })
      .finally(() => { if (!cancel) setLoading(false); });
    return () => { cancel = true; };
  }, [identityId]);

  if (loading) {
    return (
      <div className="mt-4 border-t border-gray-100 pt-4">
        <div className="text-sm text-gray-400">Loading federated credentials…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="mt-4 border-t border-gray-100 pt-4">
        <div className="rounded-lg bg-red-50 border border-red-200 p-3 text-xs text-red-700">
          Couldn't load federated credentials. The endpoint may be unavailable.
        </div>
      </div>
    );
  }

  if (!resp || resp.credentials.length === 0) {
    // Flag says yes but DB is empty — show a small reconciliation hint
    // instead of silently hiding the section.
    if (resp && (resp.summary.flag_set || resp.summary.count_field > 0)) {
      return (
        <div className="mt-4 border-t border-gray-100 pt-4">
          <div className="rounded-lg bg-amber-50 border border-amber-200 p-3 text-xs text-amber-800">
            Discovery flagged this identity as federated, but no credential records
            are stored. Re-run discovery to refresh, or check whether Microsoft
            Graph returned 403 on /federatedIdentityCredentials.
          </div>
        </div>
      );
    }
    return null;
  }

  const hasOnlyFederated = credentialCount === 0;
  const { summary } = resp;
  const worst =
    summary.critical > 0 ? 'critical' :
    summary.high     > 0 ? 'high'     :
    summary.medium   > 0 ? 'medium'   : 'low';

  return (
    <div className="mt-4 border-t border-gray-100 pt-4">
      <div className="flex items-baseline justify-between mb-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-900">Federated Credentials</h3>
          <p className="text-[11px] text-gray-500 mt-0.5">
            OIDC trust relationships — no secrets, but unpinned subjects let any token from the IdP assume this identity.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-gray-500">Worst:</span>
          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${RISK_BADGE[worst]}`}>
            {worst}
          </span>
          <span className="text-xs text-gray-700 font-medium">{summary.total} total</span>
        </div>
      </div>

      <div className="space-y-2">
        {resp.credentials.map((fc, idx) => {
          const riskLevel = fc.risk_level || 'medium';
          return (
            <div
              key={fc.credential_id || idx}
              className={`rounded-lg p-3 border ${RISK_BADGE[riskLevel] || RISK_BADGE.medium}`}
            >
              <div className="flex items-start gap-2 mb-2">
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-white border border-current">
                  {ISSUER_TYPE_LABELS[fc.issuer_type] || fc.issuer_type || 'External'}
                </span>
                {fc.name && <span className="text-sm font-semibold text-gray-900 flex-1">{fc.name}</span>}
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${RISK_BADGE[riskLevel]}`}>
                  {riskLevel}
                </span>
              </div>

              <div className="grid md:grid-cols-2 gap-2 text-xs">
                <div className="bg-white/60 rounded p-2">
                  <div className="text-[10px] uppercase font-medium text-gray-500 mb-0.5">Subject (token claim)</div>
                  <div className="font-mono text-gray-800 break-all">{fc.subject || '—'}</div>
                </div>
                <div className="bg-white/60 rounded p-2">
                  <div className="text-[10px] uppercase font-medium text-gray-500 mb-0.5">Issuer</div>
                  <div className="font-mono text-gray-800 break-all">{fc.issuer || '—'}</div>
                  {fc.audiences && fc.audiences.length > 0 && (
                    <div className="mt-1 text-[10px] text-gray-600">
                      Audience: <span className="font-mono">{fc.audiences.join(', ')}</span>
                    </div>
                  )}
                </div>
              </div>

              {fc.reasons && fc.reasons.length > 0 && (
                <div className="mt-2">
                  <div className="text-[10px] uppercase font-medium text-gray-500 mb-1">Trust analysis</div>
                  <ul className="space-y-0.5">
                    {fc.reasons.map((r, i) => (
                      <li key={i} className="text-[11px] text-gray-700 flex items-start gap-1">
                        <span className="mt-0.5">•</span>
                        <span>{r}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {fc.framework_refs && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {(fc.framework_refs.mitre || []).map(t => (
                    <span key={t} className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-white/70 text-gray-600 border border-gray-200">
                      MITRE {t}
                    </span>
                  ))}
                  {(fc.framework_refs.cis_azure || []).map(t => (
                    <span key={t} className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-white/70 text-gray-600 border border-gray-200">
                      CIS Azure {t}
                    </span>
                  ))}
                </div>
              )}

              {hasOnlyFederated && (
                <div className="mt-2 flex items-center gap-1 text-[11px] text-orange-800 bg-orange-100 rounded px-2 py-1 border border-orange-200">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                  Sole auth path — deletion would break this external pipeline.
                </div>
              )}
            </div>
          );
        })}
      </div>

      {resp.last_collected_at && (
        <div className="mt-2 text-[10px] text-gray-400">
          Collected {formatDate(resp.last_collected_at)} via Microsoft Graph /federatedIdentityCredentials
        </div>
      )}
    </div>
  );
}
