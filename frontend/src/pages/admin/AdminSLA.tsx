import React, { useEffect, useState } from 'react';
import { api } from '../../services/apiClient';

interface SLATarget {
  target: number;
  actual: number;
  unit?: string;
  met: boolean;
}

interface ScanStats {
  avg_sec: number | null;
  max_sec: number | null;
  min_sec: number | null;
  total_runs: number;
  completed_runs: number;
  failed_runs: number;
}

interface SLAData {
  uptime_pct: number;
  total_requests: number;
  error_count: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  scan_stats: ScanStats;
  scan_success_rate: number;
  sla_targets: Record<string, SLATarget>;
}

function StatusDot({ met }: { met: boolean }) {
  return (
    <div className={`w-3 h-3 rounded-full ${met ? 'bg-green-500' : 'bg-red-500'}`} />
  );
}

export default function AdminSLA() {
  const [data, setData] = useState<SLAData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get<SLAData>('/system/sla')
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading SLA metrics...</div>;
  if (!data) return <div className="text-gray-500 text-center py-8">Failed to load SLA data</div>;

  const targets = data.sla_targets || {};
  const allMet = Object.values(targets).every(t => t.met);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">SLA Monitoring</h2>
          <p className="text-sm text-gray-400 mt-0.5">Platform availability, performance, and compliance metrics</p>
        </div>
        <div className={`px-3 py-1.5 rounded-lg text-xs font-bold ${allMet ? 'bg-green-900 text-green-300 border border-green-700' : 'bg-red-900 text-red-300 border border-red-700'}`}>
          {allMet ? 'ALL SLAs MET' : 'SLA BREACH DETECTED'}
        </div>
      </div>

      {/* SLA Target Cards */}
      <div className="grid grid-cols-3 gap-4">
        {Object.entries(targets).map(([key, target]) => (
          <div key={key} className={`rounded-xl border p-5 ${target.met ? 'bg-gray-900 border-green-800' : 'bg-gray-900 border-red-700'}`}>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">
                {key === 'availability' ? 'Availability' : key === 'api_latency_p95' ? 'API Latency (P95)' : 'Scan Success Rate'}
              </span>
              <StatusDot met={target.met} />
            </div>
            <div className="text-3xl font-bold text-white">
              {target.actual.toLocaleString()}{target.unit === 'ms' ? 'ms' : '%'}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              Target: {target.target}{target.unit === 'ms' ? 'ms' : '%'}
            </div>
            {/* Progress bar */}
            <div className="mt-3 h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${target.met ? 'bg-green-500' : 'bg-red-500'}`}
                style={{ width: `${Math.min((target.actual / target.target) * 100, 100)}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Performance Metrics */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">API Performance</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-2xl font-bold text-white">{data.avg_latency_ms.toFixed(0)}ms</div>
              <div className="text-xs text-gray-500">Avg Latency</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{data.p95_latency_ms.toFixed(0)}ms</div>
              <div className="text-xs text-gray-500">P95 Latency</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{data.total_requests.toLocaleString()}</div>
              <div className="text-xs text-gray-500">Total Requests</div>
            </div>
            <div>
              <div className={`text-2xl font-bold ${data.error_count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                {data.error_count.toLocaleString()}
              </div>
              <div className="text-xs text-gray-500">Errors</div>
            </div>
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-700 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Discovery Scans (Last 30 Days)</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-2xl font-bold text-white">{data.scan_stats.total_runs}</div>
              <div className="text-xs text-gray-500">Total Runs</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-green-400">{data.scan_stats.completed_runs}</div>
              <div className="text-xs text-gray-500">Completed</div>
            </div>
            <div>
              <div className={`text-2xl font-bold ${(data.scan_stats.failed_runs || 0) > 0 ? 'text-red-400' : 'text-gray-400'}`}>
                {data.scan_stats.failed_runs || 0}
              </div>
              <div className="text-xs text-gray-500">Failed</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-white">
                {data.scan_stats.avg_sec != null ? `${data.scan_stats.avg_sec}s` : '-'}
              </div>
              <div className="text-xs text-gray-500">Avg Duration</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
