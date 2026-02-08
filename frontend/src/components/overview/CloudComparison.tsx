import React from 'react';

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

interface CloudComparisonProps {
  data: CloudRiskData[];
  monitoredResources?: MonitoredResources | null;
  onCloudClick?: (cloud: string) => void;
  onRiskClick?: (cloud: string, riskLevel: string) => void;
}

const cloudConfig = {
  azure: {
    label: 'Azure',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200',
    textColor: 'text-blue-700',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 96 96" fill="none">
        <path d="M33.338 6.544h26.038l-27.03 80.455a4.152 4.152 0 01-3.933 2.824H8.149a4.145 4.145 0 01-3.928-5.47L29.404 9.368a4.152 4.152 0 013.934-2.825z" fill="#0078D4"/>
        <path d="M71.175 60.261H41.293a1.911 1.911 0 00-1.305 3.309l26.532 24.764a4.171 4.171 0 002.846 1.121h23.586L71.175 60.261z" fill="#0078D4"/>
        <path d="M33.338 6.544a4.118 4.118 0 00-3.943 2.879L4.252 84.09a4.142 4.142 0 003.908 5.538h20.787a4.443 4.443 0 003.41-2.9l5.014-14.777 17.91 16.705a4.237 4.237 0 002.666.972h23.628l-10.378-29.37-28.016.001L59.33 6.544H33.338z" fill="#0078D4"/>
        <path d="M66.595 9.364a4.145 4.145 0 00-3.928-2.82H33.648a4.146 4.146 0 013.928 2.82l25.184 75.08a4.146 4.146 0 01-3.928 5.472h29.02a4.146 4.146 0 003.927-5.472L66.595 9.364z" fill="#0078D4" opacity=".8"/>
      </svg>
    ),
  },
  aws: {
    label: 'AWS',
    bgColor: 'bg-orange-50',
    borderColor: 'border-orange-200',
    textColor: 'text-orange-700',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 64 64" fill="none">
        <path d="M18.87 31.27c0 .74.08 1.34.22 1.78.16.44.36.92.64 1.44.1.16.14.32.14.46 0 .2-.12.4-.38.6l-1.26.84c-.18.12-.36.18-.52.18-.2 0-.4-.1-.6-.28-.28-.3-.52-.62-.72-.94-.2-.34-.4-.72-.62-1.18-1.56 1.84-3.52 2.76-5.88 2.76-1.68 0-3.02-.48-4-.44-.98-.96-1.48-2.24-1.48-3.84 0-1.7.6-3.08 1.82-4.12 1.22-1.04 2.84-1.56 4.9-1.56.68 0 1.38.06 2.12.16.74.1 1.5.26 2.3.44v-1.46c0-1.52-.32-2.58-.94-3.2-.64-.62-1.72-.92-3.26-.92-.7 0-1.42.08-2.16.26-.74.18-1.46.4-2.16.7-.32.14-.56.22-.7.24a1.23 1.23 0 01-.32.06c-.28 0-.42-.2-.42-.62v-.98c0-.32.04-.56.14-.7.1-.14.28-.28.56-.42.7-.36 1.54-.66 2.52-.9a11.77 11.77 0 013.12-.38c2.38 0 4.12.54 5.24 1.62 1.1 1.08 1.66 2.72 1.66 4.92v6.48z" fill="#FF9900"/>
        <path d="M36.61 35.96c-.44.38-.9.58-1.38.58-.64 0-1.12-.3-1.36-.88l-4.86-16.04c-.12-.36-.18-.6-.18-.74 0-.3.14-.46.44-.46h1.98c.46 0 .78.08.94.24.18.14.3.4.4.78l3.48 13.7 3.22-13.7c.1-.4.22-.64.4-.78.18-.14.52-.24.96-.24h1.62c.46 0 .78.08.96.24.18.14.32.4.4.78l3.26 13.86 3.58-13.86c.12-.4.26-.64.42-.78.18-.14.5-.24.94-.24h1.88c.3 0 .46.14.46.46 0 .1-.02.2-.04.32-.02.12-.06.28-.14.48L48.4 35.68c-.12.4-.24.64-.4.78-.18.14-.5.24-.94.24h-1.74c-.46 0-.78-.08-.96-.26-.18-.16-.32-.42-.4-.8l-3.2-13.34-3.18 13.32c-.1.4-.22.66-.4.82-.18.16-.52.26-.96.26h-1.74l.13-.74z" fill="#FF9900"/>
        <path d="M55.68 36.58c-2.06 0-3.56-.52-4.56-1.54s-1.5-2.46-1.5-4.28c0-1.88.54-3.4 1.6-4.52 1.08-1.14 2.5-1.7 4.28-1.7 1.7 0 3.04.52 4 1.54.96 1.04 1.44 2.42 1.44 4.18v1.04c0 .3-.14.46-.44.46h-8.66c.06 1.3.38 2.28.96 2.92.6.64 1.46.96 2.62.96.56 0 1.08-.06 1.56-.16.48-.12.98-.3 1.5-.54.32-.16.54-.24.66-.26.12-.02.22-.04.3-.04.26 0 .4.18.4.56v.76c0 .28-.04.48-.1.6-.08.12-.24.26-.5.4-.5.28-1.1.5-1.78.66-.7.18-1.44.26-2.22.26h.44z" fill="#FF9900"/>
        <path d="M56.45 42.76c-6.88 3.82-14.98 5.82-22.6 5.82-10.7 0-20.34-3.96-27.62-10.54-.58-.52-.06-1.22.62-.82 7.86 4.58 17.6 7.34 27.66 7.34 6.78 0 14.24-1.4 21.1-4.32 1.04-.44 1.9.68.84 2.52z" fill="#FF9900"/>
        <path d="M58.88 40.08c-.78-1-5.18-.48-7.16-.24-.6.08-.7-.44-.16-.82 3.5-2.46 9.24-1.76 9.92-.92.66.84-.18 6.68-3.46 9.46-.5.44-1 .2-.76-.36.74-1.86 2.42-6.14 1.62-7.12z" fill="#FF9900"/>
      </svg>
    ),
  },
  gcp: {
    label: 'GCP',
    bgColor: 'bg-red-50',
    borderColor: 'border-red-200',
    textColor: 'text-red-600',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 64 64" fill="none">
        <path d="M40.16 20.42l4.55-4.55.3-1.92A20.75 20.75 0 0012.4 25.06a2.47 2.47 0 011.7-.06l9.1-1.5s.46-.77.7-1.15a11.65 11.65 0 0116.26-1.93z" fill="#EA4335"/>
        <path d="M51.77 25.06a20.86 20.86 0 00-6.3-10.14l-5.3 5.31a11.63 11.63 0 014.26 9.22v1.16a5.82 5.82 0 010 11.64H32.78l-1.16 1.17v6.98l1.16 1.16h11.65a14.92 14.92 0 007.34-27.5z" fill="#4285F4"/>
        <path d="M21.14 51.56h11.64V42.8H21.14a5.8 5.8 0 01-2.4-.52l-1.66.51-4.57 4.55-.41 1.6a14.85 14.85 0 009.04 2.62z" fill="#34A853"/>
        <path d="M21.14 21.73A14.92 14.92 0 0012.1 48.94l6.64-6.64a5.82 5.82 0 113.86-10.94l6.64-6.64a14.9 14.9 0 00-8.1-2.99z" fill="#FBBC05"/>
      </svg>
    ),
  },
};

function RiskBadge({ level, count, onClick }: { level: string; count: number; onClick?: () => void }) {
  if (count === 0) return <span className="text-gray-400">-</span>;

  const colors: Record<string, string> = {
    critical: 'bg-red-100 text-red-700 hover:bg-red-200',
    high: 'bg-orange-100 text-orange-700 hover:bg-orange-200',
    medium: 'bg-yellow-100 text-yellow-700 hover:bg-yellow-200',
    low: 'bg-green-100 text-green-700 hover:bg-green-200',
  };

  return (
    <button
      onClick={(e) => { e.stopPropagation(); onClick?.(); }}
      className={`px-2 py-0.5 rounded-full text-xs font-semibold transition ${colors[level] || 'bg-gray-100 text-gray-700'}`}
    >
      {count}
    </button>
  );
}

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

function getResourceIds(cloud: string, res?: MonitoredResources | null): string[] {
  if (!res) return [];
  if (cloud === 'azure') return res.azure?.subscription_ids ?? [];
  if (cloud === 'aws') return res.aws?.account_ids ?? [];
  if (cloud === 'gcp') return res.gcp?.project_ids ?? [];
  return [];
}

export default function CloudComparison({ data, monitoredResources, onCloudClick, onRiskClick }: CloudComparisonProps) {
  // If no data, show placeholder for future clouds
  const displayData: CloudRiskData[] = data.length > 0 ? data : [
    { cloud: 'azure', total: 0, critical: 0, high: 0, medium: 0, low: 0 },
  ];

  return (
    <div className="bg-white border rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b bg-gray-50">
        <h3 className="text-sm font-semibold text-gray-900">Risk by Cloud Provider</h3>
        <p className="text-xs text-gray-500 mt-1">Compare identity risk posture across cloud platforms</p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="text-xs text-gray-500 uppercase">
              <th className="px-5 py-3 text-left font-medium">Cloud</th>
              <th className="px-3 py-3 text-center font-medium">Monitored</th>
              <th className="px-3 py-3 text-center font-medium">Identities</th>
              <th className="px-3 py-3 text-center font-medium">Critical</th>
              <th className="px-3 py-3 text-center font-medium">High</th>
              <th className="px-3 py-3 text-center font-medium">Medium</th>
              <th className="px-3 py-3 text-center font-medium">Low</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {displayData.map((row) => {
              const config = cloudConfig[row.cloud];
              const resCount = getResourceCount(row.cloud, monitoredResources);
              const resIds = getResourceIds(row.cloud, monitoredResources);
              const resType = resourceLabel[row.cloud] || 'Resources';
              return (
                <tr
                  key={row.cloud}
                  onClick={() => onCloudClick?.(row.cloud)}
                  className={`${config.bgColor} hover:opacity-80 cursor-pointer transition`}
                >
                  <td className="px-5 py-4">
                    <div className="flex items-center gap-3">
                      <div className={`${config.textColor}`}>{config.icon}</div>
                      <div>
                        <div className={`font-semibold ${config.textColor}`}>{config.label}</div>
                        <div className="text-xs text-gray-500">{row.total} identities</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-3 py-4 text-center">
                    <div
                      title={resIds.length > 0 ? resIds.map(id => id.substring(0, 8) + '...').join('\n') : `No ${resType.toLowerCase()} detected`}
                    >
                      <span className="text-lg font-bold text-gray-900">{resCount}</span>
                      <div className="text-[10px] text-gray-400 leading-tight">{resType}</div>
                    </div>
                  </td>
                  <td className="px-3 py-4 text-center">
                    <span className="text-lg font-bold text-gray-900">{row.total}</span>
                  </td>
                  <td className="px-3 py-4 text-center">
                    <RiskBadge level="critical" count={row.critical} onClick={() => onRiskClick?.(row.cloud, 'critical')} />
                  </td>
                  <td className="px-3 py-4 text-center">
                    <RiskBadge level="high" count={row.high} onClick={() => onRiskClick?.(row.cloud, 'high')} />
                  </td>
                  <td className="px-3 py-4 text-center">
                    <RiskBadge level="medium" count={row.medium} onClick={() => onRiskClick?.(row.cloud, 'medium')} />
                  </td>
                  <td className="px-3 py-4 text-center">
                    <RiskBadge level="low" count={row.low} onClick={() => onRiskClick?.(row.cloud, 'low')} />
                  </td>
                </tr>
              );
            })}

            {/* Placeholder rows for future clouds */}
            {!data.find(d => d.cloud === 'aws') && (
              <tr className="bg-gray-50 opacity-50">
                <td className="px-5 py-4">
                  <div className="flex items-center gap-3">
                    <div className="text-orange-400">{cloudConfig.aws.icon}</div>
                    <div>
                      <div className="font-semibold text-gray-400">AWS</div>
                      <div className="text-xs text-gray-400">Coming soon</div>
                    </div>
                  </div>
                </td>
                <td className="px-3 py-4 text-center text-gray-400 text-xs">0 Accounts</td>
                <td colSpan={5} className="px-3 py-4 text-center text-gray-400 text-sm">
                  Connect AWS account to enable
                </td>
              </tr>
            )}
            {!data.find(d => d.cloud === 'gcp') && (
              <tr className="bg-gray-50 opacity-50">
                <td className="px-5 py-4">
                  <div className="flex items-center gap-3">
                    <div className="text-red-300">{cloudConfig.gcp.icon}</div>
                    <div>
                      <div className="font-semibold text-gray-400">GCP</div>
                      <div className="text-xs text-gray-400">Coming soon</div>
                    </div>
                  </div>
                </td>
                <td className="px-3 py-4 text-center text-gray-400 text-xs">0 Projects</td>
                <td colSpan={5} className="px-3 py-4 text-center text-gray-400 text-sm">
                  Connect GCP project to enable
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
