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
}

const cloudConfig = {
  azure: {
    label: 'Azure',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200',
    textColor: 'text-blue-700',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="currentColor">
        <path d="M13.05 4.24l-3.25 9.98-5.3-1.88a.75.75 0 00-.88.34l-1.5 2.6a.75.75 0 00.27 1.02l8.5 4.9a.75.75 0 00.74 0l8.5-4.9a.75.75 0 00.27-1.02l-1.5-2.6a.75.75 0 00-.88-.34l-5.3 1.88L9.47 4.24a.75.75 0 00-1.42 0z"/>
      </svg>
    ),
  },
  aws: {
    label: 'AWS',
    bgColor: 'bg-orange-50',
    borderColor: 'border-orange-200',
    textColor: 'text-orange-700',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="currentColor">
        <path d="M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576.04.063.056.127.056.183 0 .08-.048.16-.152.24l-.503.335a.383.383 0 01-.208.072c-.08 0-.16-.04-.239-.112a2.47 2.47 0 01-.287-.375 6.18 6.18 0 01-.248-.471c-.622.734-1.405 1.101-2.347 1.101-.67 0-1.205-.191-1.596-.574-.391-.384-.59-.894-.59-1.533 0-.678.239-1.23.726-1.644.487-.415 1.133-.623 1.955-.623.272 0 .551.024.846.064.296.04.6.104.918.176v-.583c0-.607-.127-1.03-.375-1.277-.255-.248-.686-.367-1.3-.367-.28 0-.567.032-.862.104-.296.064-.583.16-.862.28-.128.056-.224.088-.28.096a.49.49 0 01-.127.024c-.112 0-.168-.08-.168-.247v-.391c0-.128.016-.224.056-.28a.597.597 0 01.224-.167c.279-.144.614-.264 1.005-.36a4.84 4.84 0 011.246-.151c.95 0 1.644.216 2.091.647.439.43.662 1.085.662 1.963v2.586z"/>
      </svg>
    ),
  },
  gcp: {
    label: 'GCP',
    bgColor: 'bg-red-50',
    borderColor: 'border-red-200',
    textColor: 'text-red-600',
    icon: (
      <svg className="w-8 h-8" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 3L4 9v6l8 6 8-6V9l-8-6zm0 2.18l5.45 4.09L12 13.36 6.55 9.27 12 5.18zM6 14.91V10.6l5 3.75v4.31L6 14.91zm7 3.75v-4.31l5-3.75v4.31l-5 3.75z"/>
      </svg>
    ),
  },
};

function RiskBadge({ level, count }: { level: string; count: number }) {
  if (count === 0) return <span className="text-gray-400">-</span>;

  const colors: Record<string, string> = {
    critical: 'bg-red-100 text-red-700',
    high: 'bg-orange-100 text-orange-700',
    medium: 'bg-yellow-100 text-yellow-700',
    low: 'bg-green-100 text-green-700',
  };

  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${colors[level] || 'bg-gray-100 text-gray-700'}`}>
      {count}
    </span>
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

export default function CloudComparison({ data, monitoredResources, onCloudClick }: CloudComparisonProps) {
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
                    <RiskBadge level="critical" count={row.critical} />
                  </td>
                  <td className="px-3 py-4 text-center">
                    <RiskBadge level="high" count={row.high} />
                  </td>
                  <td className="px-3 py-4 text-center">
                    <RiskBadge level="medium" count={row.medium} />
                  </td>
                  <td className="px-3 py-4 text-center">
                    <RiskBadge level="low" count={row.low} />
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
