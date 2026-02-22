import React from 'react';
import { useNavigate } from 'react-router-dom';

interface MonitoredResources {
  azure: { subscriptions: number; subscription_ids: string[] };
  aws: { accounts: number; account_ids: string[] };
  gcp: { projects: number; project_ids: string[] };
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
    resourceLabel: 'Subscriptions',
  },
  aws: {
    label: 'AWS',
    bgColor: 'bg-orange-50',
    borderColor: 'border-orange-200',
    textColor: 'text-orange-700',
    dotColor: 'bg-orange-500',
    resourceLabel: 'Accounts',
  },
  gcp: {
    label: 'GCP',
    bgColor: 'bg-red-50',
    borderColor: 'border-red-200',
    textColor: 'text-red-600',
    dotColor: 'bg-red-500',
    resourceLabel: 'Projects',
  },
};

function getCount(cloud: string, res: MonitoredResources): number {
  if (cloud === 'azure') return res.azure?.subscriptions ?? 0;
  if (cloud === 'aws') return res.aws?.accounts ?? 0;
  if (cloud === 'gcp') return res.gcp?.projects ?? 0;
  return 0;
}

export default function CloudContextBanner({ monitoredResources }: CloudContextBannerProps) {
  const navigate = useNavigate();
  const clouds = (['azure', 'aws', 'gcp'] as const).map(cloud => ({
    cloud,
    count: getCount(cloud, monitoredResources),
    connected: getCount(cloud, monitoredResources) > 0,
    ...cloudConfig[cloud],
  }));

  const connectedCount = clouds.filter(c => c.connected).length;

  return (
    <div className="bg-white border rounded-xl px-5 py-3 mb-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
          </svg>
          <span className="text-sm font-semibold text-gray-900">Cloud Coverage</span>
          <span className="text-xs text-gray-500">
            {connectedCount} provider{connectedCount !== 1 ? 's' : ''} connected
          </span>
        </div>

        <div className="flex items-center gap-4">
          {clouds.map(c => (
            <div key={c.cloud} className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${c.connected ? c.dotColor : 'bg-gray-300'}`} />
              <span className={`text-xs font-medium ${c.connected ? c.textColor : 'text-gray-400'}`}>
                {c.label}
              </span>
              {c.connected ? (
                <button
                  onClick={() => navigate(`/identities?cloud=${c.cloud}`)}
                  className={`text-[10px] px-1.5 py-0.5 rounded-full font-semibold ${c.bgColor} ${c.textColor} border ${c.borderColor} hover:opacity-70 transition cursor-pointer`}
                >
                  {c.count} {c.resourceLabel}
                </button>
              ) : (
                <span className="text-[10px] text-gray-400">Not connected</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
