import React, { useMemo, useState, useEffect } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie,
} from 'recharts';

interface RoleUsageChartProps {
  statuses: Record<string, number>;
  byRisk: Record<string, number>;
  total: number;
}

const USAGE_LABELS: Record<string, string> = {
  assumed_active: 'Active',
  possibly_overprivileged: 'Over-Privileged',
  likely_unused: 'Likely Unused',
  definitely_unused: 'Unused',
  orphaned: 'Orphaned',
  unknown: 'Unknown',
};

const USAGE_COLORS: Record<string, string> = {
  assumed_active: '#22c55e',
  possibly_overprivileged: '#eab308',
  likely_unused: '#f97316',
  definitely_unused: '#ef4444',
  orphaned: '#991b1b',
  unknown: '#9ca3af',
};

const USAGE_ORDER = ['assumed_active', 'possibly_overprivileged', 'likely_unused', 'definitely_unused', 'orphaned', 'unknown'];

const RISK_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  unknown: '#9ca3af',
};

const RISK_ORDER = ['critical', 'high', 'medium', 'low', 'unknown'];

function CustomTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const item = payload[0]?.payload;
  return (
    <div className="bg-white border rounded-lg shadow-lg px-3 py-2 text-sm">
      <div className="flex items-center gap-2">
        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item?.fill }} />
        <span className="font-semibold">{item?.label}</span>
      </div>
      <div className="text-gray-600 mt-0.5">
        {item?.value} roles ({item?.pct}%)
      </div>
    </div>
  );
}

function useChartColors() {
  const [colors, setColors] = useState({ grid: '#21262D', tick: '#8B949E' });
  useEffect(() => {
    const style = getComputedStyle(document.documentElement);
    setColors({
      grid: style.getPropertyValue('--chart-grid').trim() || '#21262D',
      tick: style.getPropertyValue('--chart-tick').trim() || '#8B949E',
    });
  }, []);
  return colors;
}

export default function RoleUsageChart({ statuses, byRisk, total }: RoleUsageChartProps) {
  const { grid: cursorFill, tick: tickFill } = useChartColors();

  const barData = useMemo(() => {
    return USAGE_ORDER
      .filter(key => (statuses[key] || 0) > 0)
      .map(key => ({
        key,
        label: USAGE_LABELS[key] || key,
        value: statuses[key] || 0,
        fill: USAGE_COLORS[key] || '#9ca3af',
        pct: total > 0 ? Math.round(((statuses[key] || 0) / total) * 100) : 0,
      }));
  }, [statuses, total]);

  const riskData = useMemo(() => {
    return RISK_ORDER
      .filter(key => (byRisk[key] || 0) > 0)
      .map(key => ({
        key,
        label: key.charAt(0).toUpperCase() + key.slice(1),
        value: byRisk[key] || 0,
        fill: RISK_COLORS[key] || '#9ca3af',
      }));
  }, [byRisk]);

  if (total === 0) {
    return (
      <div className="bg-white border rounded-xl p-5">
        <h3 className="text-sm font-semibold text-gray-900 mb-2">Role Usage Intelligence</h3>
        <div className="text-sm text-gray-400 text-center py-8">No role data available</div>
      </div>
    );
  }

  return (
    <div className="bg-white border rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-gray-900">Role Usage Intelligence</h3>
          <p className="text-xs text-gray-500">Usage status across all role assignments</p>
        </div>
        <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-gray-100 text-gray-600">
          {total} roles
        </span>
      </div>

      {/* Horizontal bar chart */}
      <ResponsiveContainer width="100%" height={barData.length * 36 + 10}>
        <BarChart data={barData} layout="vertical" margin={{ top: 0, right: 10, left: 0, bottom: 0 }}>
          <XAxis type="number" tick={{ fontSize: 10, fill: tickFill }} allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="label"
            tick={{ fontSize: 11, fill: tickFill }}
            width={100}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: cursorFill }} />
          <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20}>
            {barData.map((entry) => (
              <Cell key={entry.key} fill={entry.fill} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* Risk distribution mini pie */}
      {riskData.length > 0 && (
        <div className="mt-4 pt-4 border-t">
          <div className="text-xs font-semibold text-gray-600 mb-2">By Risk Level</div>
          <div className="flex items-center gap-4">
            <div className="w-20 h-20 flex-shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskData}
                    dataKey="value"
                    cx="50%"
                    cy="50%"
                    outerRadius={36}
                    innerRadius={18}
                    strokeWidth={1}
                  >
                    {riskData.map((entry) => (
                      <Cell key={entry.key} fill={entry.fill} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              {riskData.map(d => (
                <div key={d.key} className="flex items-center gap-1.5 text-xs">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.fill }} />
                  <span className="text-gray-600">{d.label}</span>
                  <span className="font-semibold text-gray-900">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
