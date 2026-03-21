import React from 'react';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, ReferenceLine,
} from 'recharts';
import { COLORS } from '../../../constants/ciso';
import { FONT, CISOCard, SectionTitle } from '../ciso-shared';

interface AGIRSTrendChartProps {
  data: Array<{ date: string; score: number }>;
}

export function AGIRSTrendChart({ data }: AGIRSTrendChartProps) {
  if (!data || data.length < 2) return null;

  const formatDate = (d: string) => {
    try {
      const dt = new Date(d);
      return `${dt.getMonth() + 1}/${dt.getDate()}`;
    } catch { return d; }
  };

  return (
    <CISOCard>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <SectionTitle>AGIRS Risk Trend (30 Day)</SectionTitle>
        <span style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui }}>
          Target: 90
        </span>
      </div>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="agirs-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={COLORS.accent} stopOpacity={0.3} />
              <stop offset="95%" stopColor={COLORS.accent} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} />
          <XAxis
            dataKey="date" tickFormatter={formatDate}
            tick={{ fontSize: 9, fill: COLORS.textMuted, fontFamily: FONT.mono }}
            axisLine={{ stroke: COLORS.border }} tickLine={false}
          />
          <YAxis
            domain={[0, 100]}
            tick={{ fontSize: 9, fill: COLORS.textMuted, fontFamily: FONT.mono }}
            axisLine={{ stroke: COLORS.border }} tickLine={false}
          />
          <Tooltip
            contentStyle={{
              background: COLORS.surface, border: `1px solid ${COLORS.border}`,
              borderRadius: 6, fontSize: 11, fontFamily: FONT.ui,
            }}
            labelStyle={{ color: COLORS.textSecondary }}
            itemStyle={{ color: COLORS.accent }}
            labelFormatter={(label: any) => formatDate(String(label))}
            formatter={(v: any) => [Number(v).toFixed(1), 'AGIRS']}
          />
          <ReferenceLine y={90} stroke={COLORS.success} strokeDasharray="4 4" strokeWidth={1} />
          <Area
            type="monotone" dataKey="score"
            stroke={COLORS.accent} strokeWidth={2}
            fill="url(#agirs-fill)" dot={false}
            activeDot={{ r: 3, fill: COLORS.accent, stroke: COLORS.surface, strokeWidth: 2 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </CISOCard>
  );
}
