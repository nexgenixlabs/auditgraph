import React from 'react';

interface FederatedMapping {
  resource_id: string;
  resource_type: string;
  resource_name: string;
  binding_method: string;
  confidence_score: number;
  binding_evidence: Record<string, unknown>;
}

function GitHubIcon(): React.ReactElement {
  return (
    <svg className="w-4 h-4 text-gray-700 shrink-0" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

function KubernetesIcon(): React.ReactElement {
  return (
    <svg className="w-4 h-4 text-blue-600 shrink-0" viewBox="0 0 24 24" fill="currentColor">
      <path d="M10.204 14.35l.007.01-.999 2.413a5.171 5.171 0 01-2.075-2.597l2.578-.437.004.005a.44.44 0 01.485.606zm3.59 0a.44.44 0 01.485-.606l.004-.005 2.578.437a5.171 5.171 0 01-2.075 2.597l-.999-2.413.007-.01zm-1.794-6.5a.44.44 0 01-.78 0l-.003-.006-1.675-2.018a5.17 5.17 0 012.568-.682c.893 0 1.74.232 2.472.642l-1.579 2.058-.003.006z" />
      <path d="M12 0C5.37 0 0 5.37 0 12s5.37 12 12 12 12-5.37 12-12S18.63 0 12 0zm5.755 15.186a.392.392 0 01-.236.333 6.33 6.33 0 01-1.985 1.15 6.35 6.35 0 01-2.292.447.392.392 0 01-.39-.262.392.392 0 01-.004-.123 6.35 6.35 0 01-2.296-.447 6.33 6.33 0 01-1.985-1.15.392.392 0 01-.236-.333.392.392 0 01.108-.35 6.33 6.33 0 011.32-1.752.392.392 0 01.399-.062c.04.018.075.045.102.08a6.35 6.35 0 011.54-1.677.392.392 0 01.442-.003c.594.416 1.11.928 1.539 1.677a.392.392 0 01.102-.077.392.392 0 01.399.062 6.33 6.33 0 011.32 1.752.392.392 0 01.108.35.392.392 0 01.049.135z" />
    </svg>
  );
}

function ShieldIcon(): React.ReactElement {
  return (
    <svg className="w-4 h-4 text-indigo-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  );
}

function parseGitHub(ev: Record<string, unknown>): { org: string; repo: string; branch?: string; environment?: string } {
  const org = (ev.org as string) || '';
  const repo = (ev.repo as string) || '';
  const branch = (ev.branch as string) || undefined;
  const environment = (ev.environment as string) || undefined;
  return { org, repo, branch, environment };
}

function parseAKS(ev: Record<string, unknown>): { namespace: string; serviceAccount: string; cluster?: string } {
  const namespace = (ev.namespace as string) || '';
  const serviceAccount = (ev.serviceAccount as string) || '';
  const cluster = (ev.clusterName as string) || (ev.clusterId as string) || undefined;
  return { namespace, serviceAccount, cluster };
}

function parseAwsGitHubOIDC(ev: Record<string, unknown>): { org: string; repo: string; branch?: string; environment?: string } {
  const org = (ev.org as string) || '';
  const repo = (ev.repo as string) || '';
  const branch = (ev.branch as string) || undefined;
  const environment = (ev.environment as string) || undefined;
  return { org, repo, branch, environment };
}

function parseEKSOIDC(ev: Record<string, unknown>): { clusterArn: string; namespace: string; serviceAccount: string } {
  const clusterArn = (ev.clusterArn as string) || (ev.cluster as string) || '';
  const namespace = (ev.namespace as string) || '';
  const serviceAccount = (ev.serviceAccount as string) || '';
  return { clusterArn, namespace, serviceAccount };
}

function AwsIcon(): React.ReactElement {
  return (
    <svg className="w-4 h-4 text-amber-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
    </svg>
  );
}

export function FederatedMappingsPanel({ mappings }: { mappings: FederatedMapping[] }): React.ReactElement {
  return (
    <div className="bg-white border border-gray-200 rounded-lg">
      <div className="px-4 py-3 border-b border-gray-100">
        <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider flex items-center gap-2">
          <svg className="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
          Federated Credentials
          {mappings.length > 0 && (
            <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-indigo-100 text-indigo-600 font-mono">{mappings.length}</span>
          )}
        </h3>
      </div>

      <div className="p-3">
        {mappings.length === 0 ? (
          <p className="text-xs text-gray-400 italic py-4 text-center">No federated credentials configured.</p>
        ) : (
          <div className="space-y-2">
            {mappings.map((m, i) => {
              const ev = m.binding_evidence || {};

              if (m.resource_type === 'FederatedGitHub') {
                const gh = parseGitHub(ev);
                return (
                  <div key={i} className="border border-gray-100 rounded-md p-2.5 hover:bg-gray-50 transition-colors">
                    <div className="flex items-center gap-2">
                      <GitHubIcon />
                      <div className="min-w-0 flex-1">
                        <span className="text-xs font-medium text-gray-900">
                          {gh.org}/{gh.repo}
                        </span>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          {gh.branch && (
                            <span className="px-1.5 py-0 rounded text-[9px] font-semibold bg-gray-100 text-gray-600">
                              {gh.branch}
                            </span>
                          )}
                          {gh.environment && (
                            <span className="px-1.5 py-0 rounded text-[9px] font-semibold bg-green-50 text-green-600">
                              {gh.environment}
                            </span>
                          )}
                        </div>
                      </div>
                      <span className="text-[9px] font-bold text-green-600">{m.confidence_score}%</span>
                    </div>
                  </div>
                );
              }

              if (m.resource_type === 'FederatedAKS') {
                const aks = parseAKS(ev);
                return (
                  <div key={i} className="border border-gray-100 rounded-md p-2.5 hover:bg-gray-50 transition-colors">
                    <div className="flex items-center gap-2">
                      <KubernetesIcon />
                      <div className="min-w-0 flex-1">
                        <span className="text-xs font-medium text-gray-900">
                          {aks.namespace}/{aks.serviceAccount}
                        </span>
                        {aks.cluster && (
                          <div className="text-[10px] text-gray-500 mt-0.5 truncate">{aks.cluster}</div>
                        )}
                      </div>
                      <span className="text-[9px] font-bold text-blue-600">{m.confidence_score}%</span>
                    </div>
                  </div>
                );
              }

              // AWS GitHub OIDC
              if (m.resource_type === 'AWSGitHubOIDC' || (m.binding_method === 'OIDCFederation' && !!ev.providerType && ev.providerType === 'GitHubActions')) {
                const gh = parseAwsGitHubOIDC(ev);
                return (
                  <div key={i} className="border border-gray-100 rounded-md p-2.5 hover:bg-gray-50 transition-colors">
                    <div className="flex items-center gap-2">
                      <GitHubIcon />
                      <div className="min-w-0 flex-1">
                        <span className="text-xs font-medium text-gray-900">
                          {gh.org}{gh.repo ? `/${gh.repo}` : ''}
                        </span>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          <span className="px-1.5 py-0 rounded text-[9px] font-semibold bg-amber-50 text-amber-700">AWS OIDC</span>
                          {gh.branch && (
                            <span className="px-1.5 py-0 rounded text-[9px] font-semibold bg-gray-100 text-gray-600">{gh.branch}</span>
                          )}
                          {gh.environment && (
                            <span className="px-1.5 py-0 rounded text-[9px] font-semibold bg-green-50 text-green-600">{gh.environment}</span>
                          )}
                        </div>
                      </div>
                      <span className="text-[9px] font-bold text-green-600">{m.confidence_score}%</span>
                    </div>
                  </div>
                );
              }

              // AWS EKS OIDC
              if (m.resource_type === 'AWSEKSOIDC' || (m.binding_method === 'OIDCFederation' && !!ev.providerType && ev.providerType === 'EKSCluster')) {
                const eks = parseEKSOIDC(ev);
                return (
                  <div key={i} className="border border-gray-100 rounded-md p-2.5 hover:bg-gray-50 transition-colors">
                    <div className="flex items-center gap-2">
                      <KubernetesIcon />
                      <div className="min-w-0 flex-1">
                        <span className="text-xs font-medium text-gray-900">
                          {eks.namespace}/{eks.serviceAccount}
                        </span>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          <span className="px-1.5 py-0 rounded text-[9px] font-semibold bg-amber-50 text-amber-700">AWS EKS</span>
                          {eks.clusterArn && (
                            <span className="text-[10px] text-gray-500 truncate">{eks.clusterArn}</span>
                          )}
                        </div>
                      </div>
                      <span className="text-[9px] font-bold text-blue-600">{m.confidence_score}%</span>
                    </div>
                  </div>
                );
              }

              // External IdP
              const issuer = (ev.issuer as string) || m.resource_name || 'External IdP';
              return (
                <div key={i} className="border border-gray-100 rounded-md p-2.5 hover:bg-gray-50 transition-colors">
                  <div className="flex items-center gap-2">
                    <ShieldIcon />
                    <div className="min-w-0 flex-1">
                      <span className="text-xs font-medium text-gray-900 truncate block">{issuer}</span>
                    </div>
                    <span className="text-[9px] font-bold text-indigo-600">{m.confidence_score}%</span>
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

export default FederatedMappingsPanel;
