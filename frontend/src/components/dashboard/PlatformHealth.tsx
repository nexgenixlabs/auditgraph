import React, { useEffect, useState } from 'react';
import { api } from '../../services/apiClient';

interface HealthData {
  status: string;
  checks: {
    database: { status: string; latency_ms?: number };
    scheduler: { status: string };
    system: { uptime_seconds: number };
  };
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export default function PlatformHealth() {
  const [data, setData] = useState<HealthData | null>(null);

  useEffect(() => {
    api.get<HealthData>('/health').then(setData).catch(() => {});
    const iv = setInterval(() => {
      api.get<HealthData>('/health').then(setData).catch(() => {});
    }, 30000);
    return () => clearInterval(iv);
  }, []);

  const statusColor =
    data?.status === 'healthy'
      ? 'bg-green-500'
      : data?.status === 'degraded'
      ? 'bg-yellow-500'
      : 'bg-gray-400';

  const items = [
    {
      label: 'Status',
      value: data?.status || 'Unknown',
      dot: statusColor,
    },
    {
      label: 'Uptime',
      value: data?.checks?.system ? formatUptime(data.checks.system.uptime_seconds) : '--',
    },
    {
      label: 'DB Latency',
      value: data?.checks?.database?.latency_ms != null ? `${data.checks.database.latency_ms}ms` : '--',
    },
    {
      label: 'Scheduler',
      value: data?.checks?.scheduler?.status || '--',
    },
  ];

  return (
    <div className="bg-white border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="text-sm font-semibold text-gray-900">Platform Health</div>
        <span className="text-xs text-gray-400">Live</span>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {items.map(item => (
          <div key={item.label} className="bg-gray-50 rounded-lg p-2.5">
            <div className="text-xs text-gray-500">{item.label}</div>
            <div className="flex items-center gap-1.5 mt-0.5">
              {!!item.dot && <span className={`w-2 h-2 rounded-full ${item.dot}`} />}
              <span className="text-sm font-semibold text-gray-900 capitalize">{item.value}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
