import React, { useMemo } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, Legend,
} from 'recharts';

interface VelocityTransition {
  run_id: number;
  date: string | null;
  prev_run_id: number;
  inflow:  Record<string, number>;
  outflow: Record<string, number>;
  net:     Record<string, number>;
}

interface RetentionData {
  [level: string]: { retained: number; total: number; rate: number };
}

interface RiskVelocityChartProps {
  transitions: VelocityTransition[];
  retention: RetentionData;
}

const COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
};

function formatDate(d: string | null): string {
  if (!d) return '';
  try {
    return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  } catch {
    return '';
  }
}

export default function RiskVelocityChart({ transitions, retention }: RiskVelocityChartProps) {
  const chartData = useMemo(() => {
    return transitions.map(t => ({
      label: formatDate(t.date),
      run_id: t.run_id,
      critical_in: t.inflow.critical || 0,
      critical_out: -(t.outflow.critical || 0),
      high_in: t.inflow.high || 0,
      high_out: -(t.outflow.high || 0),
      medium_in: t.inflow.medium || 0,
      medium_out: -(t.outflow.medium || 0),
    }));
  }, [transitions]);

  if (chartData.length === 0) return null;

  const hasAnyData = chartData.some(d =>
    d.critical_in || d.critical_out || d.high_in || d.high_out || d.medium_in || d.medium_out
  );

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-gray-900">Risk Velocity</h3>
          <p className="text-[11px] text-gray-500">Identity flow between risk levels per run</p>
        </div>
        {Object.keys(retention).length > 0 && (
          <div className="flex gap-2">
            {Object.entries(retention).map(([level, data]) => (
              <span
                key={level}
                className="text-[10px] px-2 py-1 rounded-full font-medium"
                style={{
                  backgroundColor: level === 'critical' ? '#fef2f2' : '#fff7ed',
                  color: level === 'critical' ? '#991b1b' : '#9a3412',
                }}
              >
                {level} retention: {data.rate}% ({data.retained}/{data.total})
              </span>
            ))}
          </div>
        )}
      </div>

      {!hasAnyData ? (
        <div className="text-center py-6 text-sm text-gray-400">
          No risk level changes between runs
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={chartData} stackOffset="sign" margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
            <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#9ca3af' }} />
            <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} allowDecimals={false} />
            <ReferenceLine y={0} stroke="#d1d5db" />
            <Tooltip
              content={({ active, payload, label }) => {
                if (!active || !payload?.length) return null;
                const d = payload[0]?.payload;
                if (!d) return null;
                return (
                  <div className="bg-white border rounded-lg shadow-lg px-3 py-2 text-xs">
                    <div className="font-semibold mb-1">{label} (Run #{d.run_id})</div>
                    {(['critical', 'high', 'medium'] as const).map(l => {
                      const inKey = `${l}_in` as keyof typeof d;
                      const outKey = `${l}_out` as keyof typeof d;
                      const inVal = (d[inKey] as number) || 0;
                      const outVal = Math.abs((d[outKey] as number) || 0);
                      if (!inVal && !outVal) return null;
                      return (
                        <div key={l} className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[l] }} />
                          <span className="capitalize">{l}:</span>
                          <span className="text-green-600">+{inVal} in</span>
                          <span className="text-red-500">-{outVal} out</span>
                        </div>
                      );
                    })}
                  </div>
                );
              }}
            />
            <Legend
              formatter={(value: string) => {
                const labels: Record<string, string> = {
                  critical_in: 'Critical +', critical_out: 'Critical -',
                  high_in: 'High +', high_out: 'High -',
                  medium_in: 'Medium +', medium_out: 'Medium -',
                };
                return <span className="text-[10px]">{labels[value] || value}</span>;
              }}
              iconSize={8}
              wrapperStyle={{ fontSize: 10 }}
            />
            <Bar dataKey="critical_in" stackId="critical" fill={COLORS.critical} fillOpacity={0.8} />
            <Bar dataKey="critical_out" stackId="critical" fill={COLORS.critical} fillOpacity={0.4} />
            <Bar dataKey="high_in" stackId="high" fill={COLORS.high} fillOpacity={0.8} />
            <Bar dataKey="high_out" stackId="high" fill={COLORS.high} fillOpacity={0.4} />
            <Bar dataKey="medium_in" stackId="medium" fill={COLORS.medium} fillOpacity={0.8} />
            <Bar dataKey="medium_out" stackId="medium" fill={COLORS.medium} fillOpacity={0.4} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
