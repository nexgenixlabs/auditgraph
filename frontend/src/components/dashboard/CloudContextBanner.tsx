import React from 'react';
import { useNavigate } from 'react-router-dom';

interface CloudConnection {
  id: number;
  label: string;
  status: string;
  connection_type: string;
  last_test_status: string | null;
  last_discovery_at: string | null;
  discovered_count: number;
  sub_count: number;
}

interface MonitoredResources {
  azure: { subscriptions: number; subscription_ids: string[]; tenant_count?: number; connected?: boolean; connections?: CloudConnection[] };
  aws: { accounts: number; account_ids: string[]; connected?: boolean; connections?: CloudConnection[] };
  gcp: { projects: number; project_ids: string[]; connected?: boolean; connections?: CloudConnection[] };
}

interface CloudContextBannerProps {
  monitoredResources: MonitoredResources;
}

const cloudConfig = {
  azure: {
    label: 'Azure',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200',
    textColor: 'text-blue-700',
    dotColor: 'bg-blue-500',
    hoverBg: 'hover:bg-blue-100',
    resourceLabel: 'Subscriptions',
    resourceKey: 'subscriptions' as const,
  },
  aws: {
    label: 'AWS',
    bgColor: 'bg-orange-50',
    borderColor: 'border-orange-200',
    textColor: 'text-orange-700',
    dotColor: 'bg-orange-500',
    hoverBg: 'hover:bg-orange-100',
    resourceLabel: 'Accounts',
    resourceKey: 'accounts' as const,
  },
  gcp: {
    label: 'GCP',
    bgColor: 'bg-red-50',
    borderColor: 'border-red-200',
    textColor: 'text-red-600',
    dotColor: 'bg-red-500',
    hoverBg: 'hover:bg-red-100',
    resourceLabel: 'Projects',
    resourceKey: 'projects' as const,
  },
};

type CloudKey = 'azure' | 'aws' | 'gcp';

function getCount(cloud: CloudKey, res: MonitoredResources): number {
  if (cloud === 'azure') return res.azure?.subscriptions ?? 0;
  if (cloud === 'aws') return res.aws?.accounts ?? 0;
  if (cloud === 'gcp') return res.gcp?.projects ?? 0;
  return 0;
}

function isConnected(cloud: CloudKey, res: MonitoredResources): boolean {
  const provider = res[cloud];
  // Check explicit connected flag from backend
  if (provider && 'connected' in provider && provider.connected) return true;
  // Fallback: connected if resource count > 0
  return getCount(cloud, res) > 0;
}

function getSummary(cloud: CloudKey, res: MonitoredResources): string {
  const count = getCount(cloud, res);
  const cfg = cloudConfig[cloud];
  const parts: string[] = [];
  if (count > 0) {
    parts.push(`${count} ${count === 1 ? cfg.resourceLabel.replace(/s$/, '') : cfg.resourceLabel}`);
  }
  if (cloud === 'azure') {
    const tenants = res.azure?.tenant_count ?? 0;
    if (tenants > 1) parts.push(`${tenants} Tenants`);
  }
  if (parts.length === 0) {
    // Connected but no subscriptions yet (e.g. just configured)
    const conns = (res[cloud] as { connections?: CloudConnection[] })?.connections || [];
    if (conns.length > 0) {
      parts.push(`${conns.length} connection${conns.length !== 1 ? 's' : ''}`);
    }
  }
  return parts.join(', ');
}

export default function CloudContextBanner({ monitoredResources }: CloudContextBannerProps) {
  const navigate = useNavigate();
  const allClouds: CloudKey[] = ['azure', 'aws', 'gcp'];

  const connected = allClouds.filter(c => isConnected(c, monitoredResources));
  const available = allClouds.filter(c => !isConnected(c, monitoredResources));

  return (
    <div className="bg-white border rounded-xl px-5 py-4 mb-6">
      <div className="flex items-center gap-2 mb-3">
        <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
        </svg>
        <span className="text-sm font-semibold text-gray-900">Cloud Coverage</span>
      </div>

      <div className="flex items-start gap-6">
        {/* Connected Providers */}
        {connected.length > 0 && (
          <div className="flex-1 min-w-0">
            <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Connected Providers</div>
            <div className="flex flex-wrap gap-2">
              {connected.map(cloud => {
                const cfg = cloudConfig[cloud];
                const summary = getSummary(cloud, monitoredResources);
                return (
                  <button
                    key={cloud}
                    onClick={() => navigate(`/identities?cloud=${cloud}`)}
                    className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border ${cfg.bgColor} ${cfg.borderColor} ${cfg.hoverBg} transition-colors cursor-pointer`}
                  >
                    <div className={`w-2 h-2 rounded-full ${cfg.dotColor}`} />
                    <span className={`text-xs font-semibold ${cfg.textColor}`}>{cfg.label}</span>
                    {summary && (
                      <span className={`text-[10px] ${cfg.textColor} opacity-80`}>({summary})</span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Available Providers */}
        {available.length > 0 && (
          <div className="flex-shrink-0">
            <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Available Providers</div>
            <div className="flex flex-wrap gap-2">
              {available.map(cloud => {
                const cfg = cloudConfig[cloud];
                return (
                  <button
                    key={cloud}
                    onClick={() => navigate('/settings#cloud-connections')}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-dashed border-gray-300 hover:border-gray-400 hover:bg-gray-50 transition-colors cursor-pointer"
                  >
                    <svg className="w-3 h-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                    <span className="text-xs font-medium text-gray-600">Connect {cfg.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
