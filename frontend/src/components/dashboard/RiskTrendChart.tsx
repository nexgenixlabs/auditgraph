import React, { useMemo, useState, useEffect } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

interface TrendPoint {
  date: string | null;
  run_id: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

interface RiskTrendChartProps {
  data: TrendPoint[];
}

const RISK_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

function formatDate(dateStr: string | null): string {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  const point = payload[0]?.payload as TrendPoint | undefined;
  return (
    <div className="bg-white border rounded-lg shadow-lg px-4 py-3 text-sm">
      <div className="font-semibold text-gray-900 mb-1">
        {formatDate(label)}
        {!!point?.run_id && <span className="ml-2 text-xs text-gray-400">Run #{point.run_id}</span>}
      </div>
      <div className="space-y-0.5">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
          <span className="text-gray-600">Critical:</span>
          <span className="font-semibold">{point?.critical ?? 0}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
          <span className="text-gray-600">High:</span>
          <span className="font-semibold">{point?.high ?? 0}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
          <span className="text-gray-600">Medium:</span>
          <span className="font-semibold">{point?.medium ?? 0}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-green-500" />
          <span className="text-gray-600">Low:</span>
          <span className="font-semibold">{point?.low ?? 0}</span>
        </div>
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

export default function RiskTrendChart({ data }: RiskTrendChartProps) {
  const { grid: gridStroke, tick: tickFill } = useChartColors();

  const chartData = useMemo(() =>
    data.map(d => ({
      ...d,
      dateLabel: formatDate(d.date),
    })),
  [data]);

  if (data.length < 2) return null;

  return (
    <div className="bg-white border rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-gray-900">Risk Trend</h3>
          <p className="text-xs text-gray-500">Identity risk levels across discovery runs</p>
        </div>
        <span className="text-xs text-gray-400">{data.length} runs</span>
      </div>
      <ResponsiveContainer width="100%" height={240}>
        <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
          <defs>
            <linearGradient id="gradCritical" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={RISK_COLORS.critical} stopOpacity={0.3} />
              <stop offset="95%" stopColor={RISK_COLORS.critical} stopOpacity={0.05} />
            </linearGradient>
            <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={RISK_COLORS.high} stopOpacity={0.3} />
              <stop offset="95%" stopColor={RISK_COLORS.high} stopOpacity={0.05} />
            </linearGradient>
            <linearGradient id="gradMedium" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={RISK_COLORS.medium} stopOpacity={0.3} />
              <stop offset="95%" stopColor={RISK_COLORS.medium} stopOpacity={0.05} />
            </linearGradient>
            <linearGradient id="gradLow" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={RISK_COLORS.low} stopOpacity={0.3} />
              <stop offset="95%" stopColor={RISK_COLORS.low} stopOpacity={0.05} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
          <XAxis dataKey="date" tickFormatter={formatDate} tick={{ fontSize: 11, fill: tickFill }} />
          <YAxis tick={{ fontSize: 11, fill: tickFill }} allowDecimals={false} />
          <Tooltip content={<CustomTooltip />} />
          <Legend
            iconType="circle"
            iconSize={8}
            wrapperStyle={{ fontSize: 11, paddingTop: 8, color: tickFill }}
          />
          <Area
            type="monotone"
            dataKey="critical"
            name="Critical"
            stroke={RISK_COLORS.critical}
            fill="url(#gradCritical)"
            strokeWidth={2}
          />
          <Area
            type="monotone"
            dataKey="high"
            name="High"
            stroke={RISK_COLORS.high}
            fill="url(#gradHigh)"
            strokeWidth={2}
          />
          <Area
            type="monotone"
            dataKey="medium"
            name="Medium"
            stroke={RISK_COLORS.medium}
            fill="url(#gradMedium)"
            strokeWidth={2}
          />
          <Area
            type="monotone"
            dataKey="low"
            name="Low"
            stroke={RISK_COLORS.low}
            fill="url(#gradLow)"
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
