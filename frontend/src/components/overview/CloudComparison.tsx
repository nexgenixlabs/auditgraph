import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { CLOUD_LABELS, type CloudProviderConfig } from '../../constants/pricing';

interface CloudRiskData {
  cloud: 'azure' | 'aws' | 'gcp';
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface MonitoredResources {
  azure: { subscriptions: number; subscription_ids: string[] };
  aws: { accounts: number; account_ids: string[] };
  gcp: { projects: number; project_ids: string[] };
}

interface ResourceStatsData {
  storage_accounts: number;
  key_vaults: number;
}

interface TenantCloudConfig {
  cloud_providers: Record<string, CloudProviderConfig>;
  addons: Record<string, boolean>;
}

interface CloudComparisonProps {
  data: CloudRiskData[];
  monitoredResources?: MonitoredResources | null;
  resourceStats?: ResourceStatsData | null;
  onCloudClick?: (cloud: string) => void;
  onRiskClick?: (cloud: string, riskLevel: string) => void;
}

const cloudIcons: Record<string, React.ReactNode> = {
  azure: (
    <svg className="w-8 h-8" viewBox="0 0 96 96" fill="none">
      <path d="M33.338 6.544h26.038l-27.03 80.455a4.152 4.152 0 01-3.933 2.824H8.149a4.145 4.145 0 01-3.928-5.47L29.404 9.368a4.152 4.152 0 013.934-2.825z" fill="#0078D4"/>
      <path d="M71.175 60.261H41.293a1.911 1.911 0 00-1.305 3.309l26.532 24.764a4.171 4.171 0 002.846 1.121h23.586L71.175 60.261z" fill="#0078D4"/>
      <path d="M33.338 6.544a4.118 4.118 0 00-3.943 2.879L4.252 84.09a4.142 4.142 0 003.908 5.538h20.787a4.443 4.443 0 003.41-2.9l5.014-14.777 17.91 16.705a4.237 4.237 0 002.666.972h23.628l-10.378-29.37-28.016.001L59.33 6.544H33.338z" fill="#0078D4"/>
      <path d="M66.595 9.364a4.145 4.145 0 00-3.928-2.82H33.648a4.146 4.146 0 013.928 2.82l25.184 75.08a4.146 4.146 0 01-3.928 5.472h29.02a4.146 4.146 0 003.927-5.472L66.595 9.364z" fill="#0078D4" opacity=".8"/>
    </svg>
  ),
  aws: (
    <svg className="w-8 h-8" viewBox="0 0 64 64" fill="none">
      <path d="M18.87 31.27c0 .74.08 1.34.22 1.78.16.44.36.92.64 1.44.1.16.14.32.14.46 0 .2-.12.4-.38.6l-1.26.84c-.18.12-.36.18-.52.18-.2 0-.4-.1-.6-.28-.28-.3-.52-.62-.72-.94-.2-.34-.4-.72-.62-1.18-1.56 1.84-3.52 2.76-5.88 2.76-1.68 0-3.02-.48-4-.44-.98-.96-1.48-2.24-1.48-3.84 0-1.7.6-3.08 1.82-4.12 1.22-1.04 2.84-1.56 4.9-1.56.68 0 1.38.06 2.12.16.74.1 1.5.26 2.3.44v-1.46c0-1.52-.32-2.58-.94-3.2-.64-.62-1.72-.92-3.26-.92-.7 0-1.42.08-2.16.26-.74.18-1.46.4-2.16.7-.32.14-.56.22-.7.24a1.23 1.23 0 01-.32.06c-.28 0-.42-.2-.42-.62v-.98c0-.32.04-.56.14-.7.1-.14.28-.28.56-.42.7-.36 1.54-.66 2.52-.9a11.77 11.77 0 013.12-.38c2.38 0 4.12.54 5.24 1.62 1.1 1.08 1.66 2.72 1.66 4.92v6.48z" fill="#FF9900"/>
      <path d="M56.45 42.76c-6.88 3.82-14.98 5.82-22.6 5.82-10.7 0-20.34-3.96-27.62-10.54-.58-.52-.06-1.22.62-.82 7.86 4.58 17.6 7.34 27.66 7.34 6.78 0 14.24-1.4 21.1-4.32 1.04-.44 1.9.68.84 2.52z" fill="#FF9900"/>
      <path d="M58.88 40.08c-.78-1-5.18-.48-7.16-.24-.6.08-.7-.44-.16-.82 3.5-2.46 9.24-1.76 9.92-.92.66.84-.18 6.68-3.46 9.46-.5.44-1 .2-.76-.36.74-1.86 2.42-6.14 1.62-7.12z" fill="#FF9900"/>
    </svg>
  ),
  gcp: (
    <svg className="w-8 h-8" viewBox="0 0 64 64" fill="none">
      <path d="M40.16 20.42l4.55-4.55.3-1.92A20.75 20.75 0 0012.4 25.06a2.47 2.47 0 011.7-.06l9.1-1.5s.46-.77.7-1.15a11.65 11.65 0 0116.26-1.93z" fill="#EA4335"/>
      <path d="M51.77 25.06a20.86 20.86 0 00-6.3-10.14l-5.3 5.31a11.63 11.63 0 014.26 9.22v1.16a5.82 5.82 0 010 11.64H32.78l-1.16 1.17v6.98l1.16 1.16h11.65a14.92 14.92 0 007.34-27.5z" fill="#4285F4"/>
      <path d="M21.14 51.56h11.64V42.8H21.14a5.8 5.8 0 01-2.4-.52l-1.66.51-4.57 4.55-.41 1.6a14.85 14.85 0 009.04 2.62z" fill="#34A853"/>
      <path d="M21.14 21.73A14.92 14.92 0 0012.1 48.94l6.64-6.64a5.82 5.82 0 113.86-10.94l6.64-6.64a14.9 14.9 0 00-8.1-2.99z" fill="#FBBC05"/>
    </svg>
  ),
};

const cloudBgColors: Record<string, string> = {
  azure: 'bg-blue-50',
  aws: 'bg-orange-50',
  gcp: 'bg-red-50',
};

const cloudBorderColors: Record<string, string> = {
  azure: 'border-blue-200',
  aws: 'border-orange-200',
  gcp: 'border-red-200',
};

const cloudTextColors: Record<string, string> = {
  azure: 'text-blue-700',
  aws: 'text-orange-700',
  gcp: 'text-red-600',
};

const resourceLabel: Record<string, string> = {
  azure: 'Subscriptions',
  aws: 'Accounts',
  gcp: 'Projects',
};

function getResourceCount(cloud: string, res?: MonitoredResources | null): number {
  if (!res) return 0;
  if (cloud === 'azure') return res.azure?.subscriptions ?? 0;
  if (cloud === 'aws') return res.aws?.accounts ?? 0;
  if (cloud === 'gcp') return res.gcp?.projects ?? 0;
  return 0;
}

function SeverityBadge({ level, count, onClick }: { level: string; count: number; onClick?: () => void }) {
  if (count === 0) return <span className="text-gray-300">&mdash;</span>;

  const styles: Record<string, string> = {
    critical: 'bg-red-100 text-red-700 border-red-200 hover:bg-red-200',
    high: 'bg-amber-100 text-amber-700 border-amber-200 hover:bg-amber-200',
    medium: 'bg-indigo-100 text-indigo-700 border-indigo-200 hover:bg-indigo-200',
    low: 'bg-blue-100 text-blue-700 border-blue-200 hover:bg-blue-200',
  };

  return (
    <button
      onClick={(e) => { e.stopPropagation(); onClick?.(); }}
      className={`inline-flex items-center justify-center min-w-[28px] px-2 py-0.5 rounded-full text-xs font-bold border transition ${styles[level] || 'bg-gray-100 text-gray-600 border-gray-200'}`}
    >
      {count}
    </button>
  );
}

export default function CloudComparison({ data, monitoredResources, resourceStats, onCloudClick, onRiskClick }: CloudComparisonProps) {
  const navigate = useNavigate();
  const [cloudConfig, setCloudConfig] = useState<TenantCloudConfig | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);

  useEffect(() => {
    fetch('/api/tenant/config')
      .then(r => { if (!r.ok) throw new Error(); return r.json(); })
      .then(cfg => setCloudConfig({ cloud_providers: cfg.cloud_providers, addons: cfg.addons }))
      .catch(() => {
        setCloudConfig({
          cloud_providers: { azure: { enabled: true, plan: 'starter' }, aws: { enabled: false, plan: null }, gcp: { enabled: false, plan: null } },
          addons: {},
        });
      });
  }, []);

  // Determine which clouds are enabled
  const enabledClouds = cloudConfig
    ? Object.entries(cloudConfig.cloud_providers).filter(([, v]) => v.enabled).map(([k]) => k)
    : ['azure']; // default while loading

  const disabledClouds = cloudConfig
    ? Object.entries(cloudConfig.cloud_providers).filter(([, v]) => !v.enabled).map(([k]) => k)
    : ['aws', 'gcp'];

  // Filter data to only enabled clouds
  const enabledData = enabledClouds.map(cloud => {
    const found = data.find(d => d.cloud === cloud);
    return found || { cloud: cloud as 'azure' | 'aws' | 'gcp', total: 0, critical: 0, high: 0, medium: 0, low: 0 };
  });

  // Summary calculations
  const totalIdentities = enabledData.reduce((s, d) => s + d.total, 0);
  const totalCritical = enabledData.reduce((s, d) => s + d.critical, 0);
  const totalHigh = enabledData.reduce((s, d) => s + d.high, 0);

  return (
    <div className="space-y-5">
      {/* Summary Strip — 4 Metric Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-white border border-gray-200 rounded-xl p-4 flex items-start gap-3">
          <div className="w-1 h-12 rounded-full bg-blue-500 shrink-0" />
          <div>
            <div className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Cloud Providers</div>
            <div className="text-2xl font-extrabold text-gray-900 mt-0.5">{enabledClouds.length}</div>
            <div className="text-[11px] text-gray-400">of 3 enabled</div>
          </div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4 flex items-start gap-3">
          <div className="w-1 h-12 rounded-full bg-purple-500 shrink-0" />
          <div>
            <div className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Total Identities</div>
            <div className="text-2xl font-extrabold text-gray-900 mt-0.5">{totalIdentities.toLocaleString()}</div>
            <div className="text-[11px] text-gray-400">monitored</div>
          </div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4 flex items-start gap-3">
          <div className="w-1 h-12 rounded-full bg-red-500 shrink-0" />
          <div>
            <div className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Critical Risks</div>
            <div className="text-2xl font-extrabold text-red-700 mt-0.5">{totalCritical}</div>
            <div className="text-[11px] text-gray-400">require action</div>
          </div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4 flex items-start gap-3">
          <div className="w-1 h-12 rounded-full bg-amber-500 shrink-0" />
          <div>
            <div className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">High Risks</div>
            <div className="text-2xl font-extrabold text-amber-700 mt-0.5">{totalHigh}</div>
            <div className="text-[11px] text-gray-400">need attention</div>
          </div>
        </div>
      </div>

      {/* Section Header */}
      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-gray-900">Risk by Cloud Provider</h3>
            <p className="text-xs text-gray-500 mt-0.5">Only your enabled cloud platforms are shown</p>
          </div>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 border border-dashed border-blue-300 rounded-lg text-xs font-semibold text-blue-600 hover:bg-blue-50 hover:border-blue-400 transition"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Add Cloud Provider
          </button>
        </div>

        {/* Column Headers */}
        {enabledData.length > 0 && (
          <div className="grid grid-cols-[1fr_100px_100px_80px_80px_80px_80px] px-5 py-2 text-[10px] font-semibold text-gray-400 uppercase tracking-wider border-b border-gray-100">
            <div>Cloud</div>
            <div className="text-center">Monitored</div>
            <div className="text-center">Identities</div>
            <div className="text-center">Critical</div>
            <div className="text-center">High</div>
            <div className="text-center">Medium</div>
            <div className="text-center">Low</div>
          </div>
        )}

        {/* Cloud Provider Rows */}
        {enabledData.length === 0 ? (
          <div className="px-5 py-12 text-center">
            <div className="text-gray-400 mb-2">
              <svg className="w-10 h-10 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 00-9.78 2.096A4.001 4.001 0 003 15z" />
              </svg>
            </div>
            <div className="text-sm font-semibold text-gray-600">No cloud providers configured</div>
            <p className="text-xs text-gray-400 mt-1">Contact your admin or click Add Cloud Provider to get started.</p>
            <button
              onClick={() => setShowAddModal(true)}
              className="mt-3 px-4 py-2 bg-blue-600 text-white text-xs font-semibold rounded-lg hover:bg-blue-700 transition"
            >
              Add Cloud Provider
            </button>
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {enabledData.map((row) => {
              const resCount = getResourceCount(row.cloud, monitoredResources);
              const resType = resourceLabel[row.cloud] || 'Resources';
              const plan = cloudConfig?.cloud_providers[row.cloud]?.plan;
              const showResources = row.cloud === 'azure' && resourceStats && (resourceStats.storage_accounts > 0 || resourceStats.key_vaults > 0);

              return (
                <div key={row.cloud}>
                  {/* Main Row */}
                  <div
                    onClick={() => onCloudClick?.(row.cloud)}
                    className={`grid grid-cols-[1fr_100px_100px_80px_80px_80px_80px] items-center px-5 py-4 cursor-pointer hover:opacity-80 transition ${cloudBgColors[row.cloud]}`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={cloudTextColors[row.cloud]}>{cloudIcons[row.cloud]}</div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className={`font-bold ${cloudTextColors[row.cloud]}`}>{CLOUD_LABELS[row.cloud]?.label || row.cloud}</span>
                          {plan && (
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${cloudBgColors[row.cloud]} ${cloudTextColors[row.cloud]} border ${cloudBorderColors[row.cloud]}`}>
                              {plan}
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-gray-500">{row.total} identities</div>
                      </div>
                    </div>
                    <div className="text-center">
                      <span className="text-lg font-bold text-gray-900">{resCount}</span>
                      <div className="text-[10px] text-gray-400">{resType}</div>
                    </div>
                    <div className="text-center">
                      <span className="text-lg font-bold text-gray-900">{row.total}</span>
                    </div>
                    <div className="text-center">
                      <SeverityBadge level="critical" count={row.critical} onClick={() => onRiskClick?.(row.cloud, 'critical')} />
                    </div>
                    <div className="text-center">
                      <SeverityBadge level="high" count={row.high} onClick={() => onRiskClick?.(row.cloud, 'high')} />
                    </div>
                    <div className="text-center">
                      <SeverityBadge level="medium" count={row.medium} onClick={() => onRiskClick?.(row.cloud, 'medium')} />
                    </div>
                    <div className="text-center">
                      <SeverityBadge level="low" count={row.low} onClick={() => onRiskClick?.(row.cloud, 'low')} />
                    </div>
                  </div>

                  {/* Azure Resources sub-row */}
                  {showResources && (
                    <div className="grid grid-cols-[1fr_100px_100px_80px_80px_80px_80px] items-center px-5 py-2.5 bg-blue-50/60">
                      <div className="pl-11">
                        <div className="text-[11px] font-semibold text-blue-600 uppercase tracking-wide">Resources</div>
                      </div>
                      <div className="col-span-6">
                        <div className="flex items-center gap-6">
                          <a href="/resources?resource_type=storage_account" onClick={e => e.stopPropagation()} className="flex items-center gap-2 hover:opacity-70 transition">
                            <span className="inline-flex items-center justify-center w-6 h-6 rounded bg-sky-100">
                              <svg className="w-3.5 h-3.5 text-sky-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
                              </svg>
                            </span>
                            <div>
                              <span className="text-sm font-bold text-gray-900">{resourceStats!.storage_accounts}</span>
                              <span className="text-[10px] text-gray-500 ml-1">Storage Accounts</span>
                            </div>
                          </a>
                          <a href="/resources?resource_type=key_vault" onClick={e => e.stopPropagation()} className="flex items-center gap-2 hover:opacity-70 transition">
                            <span className="inline-flex items-center justify-center w-6 h-6 rounded bg-purple-100">
                              <svg className="w-3.5 h-3.5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                              </svg>
                            </span>
                            <div>
                              <span className="text-sm font-bold text-gray-900">{resourceStats!.key_vaults}</span>
                              <span className="text-[10px] text-gray-500 ml-1">Key Vaults</span>
                            </div>
                          </a>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Pending scan label for enabled clouds with 0 identities */}
                  {row.total === 0 && (
                    <div className={`px-5 py-2 text-xs text-gray-500 italic ${cloudBgColors[row.cloud]}/50`}>
                      Pending initial scan
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Add Cloud Provider Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={() => setShowAddModal(false)} />
          <div className="relative bg-white rounded-2xl shadow-2xl max-w-lg w-full mx-4 p-6">
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-lg font-bold text-gray-900">Cloud Providers</h3>
              <button onClick={() => setShowAddModal(false)} className="text-gray-400 hover:text-gray-600 text-xl leading-none">&times;</button>
            </div>
            <p className="text-sm text-gray-500 mb-5">Manage your cloud provider connections.</p>

            {disabledClouds.length === 0 ? (
              <div className="text-center py-8">
                <svg className="w-12 h-12 mx-auto text-green-400 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div className="text-sm font-semibold text-gray-700">All cloud providers are enabled!</div>
                <button
                  onClick={() => { setShowAddModal(false); navigate('/settings#cloud-connections'); }}
                  className="mt-3 text-sm text-blue-600 hover:text-blue-800 font-medium"
                >
                  Go to Settings &rarr; Cloud Connections
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                {enabledClouds.length > 0 && (
                  <div className="mb-2">
                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Enabled</div>
                    {enabledClouds.map(cloud => {
                      const meta = CLOUD_LABELS[cloud];
                      return (
                        <div
                          key={cloud}
                          className={`flex items-center gap-3 p-3 border rounded-xl mb-2 ${cloudBgColors[cloud]} ${cloudBorderColors[cloud]}`}
                        >
                          <div className="shrink-0">{cloudIcons[cloud]}</div>
                          <div className="flex-1 min-w-0">
                            <span className={`text-sm font-bold ${cloudTextColors[cloud]}`}>{meta?.label}</span>
                            <span className="flex items-center gap-1 text-[10px] text-green-600 font-medium ml-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                              Enabled
                            </span>
                          </div>
                          <button
                            onClick={() => { setShowAddModal(false); navigate('/settings#cloud-connections'); }}
                            className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                          >
                            Configure
                          </button>
                        </div>
                      );
                    })}
                  </div>
                )}

                <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Not Enabled</div>
                {disabledClouds.map(cloud => {
                  const meta = CLOUD_LABELS[cloud];
                  return (
                    <div
                      key={cloud}
                      className={`flex items-start gap-3 p-4 border-2 border-dashed rounded-xl ${cloudBorderColors[cloud]}`}
                    >
                      <div className="shrink-0 mt-0.5 opacity-50">{cloudIcons[cloud]}</div>
                      <div className="flex-1 min-w-0">
                        <span className={`text-sm font-bold ${cloudTextColors[cloud]}`}>{meta?.label}</span>
                        <p className="text-xs text-gray-500 mt-1">{meta?.description}</p>
                        <p className="text-xs text-gray-400 mt-1.5">Contact your AuditGraph administrator to enable this provider.</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            <div className="mt-5 pt-4 border-t border-gray-100 text-center">
              <button onClick={() => setShowAddModal(false)} className="text-sm text-gray-500 hover:text-gray-700">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
