import React, { useState } from 'react';
import {
  Radar as RRadar,
  RadarChart as RRadarChart,
  PolarGrid as RPolarGrid,
  PolarAngleAxis as RPolarAngleAxis,
  PolarRadiusAxis as RPolarRadiusAxis,
  ResponsiveContainer,
} from 'recharts';
import { COLORS, scoreToColor } from '../../constants/design';
import PillarCard from './PillarCard';

// React 19 type compat — recharts components return ReactNode not ReactElement
const RadarChart = RRadarChart as any;
const PolarGrid = RPolarGrid as any;
const PolarAngleAxis = RPolarAngleAxis as any;
const PolarRadiusAxis = RPolarRadiusAxis as any;
const Radar = RRadar as any;

interface PillarData {
  score: number;
  weight: number;
  detail: Record<string, number>;
}

interface AttackSurfaceRadarProps {
  score: number;
  pillars: Record<string, PillarData>;
}

const PILLAR_META: { key: string; label: string; short: string }[] = [
  { key: 'effective_privilege', label: 'Effective Privilege', short: 'Privilege' },
  { key: 'credential_risk', label: 'Credential Risk', short: 'Credentials' },
  { key: 'trust_federation', label: 'Trust & Federation', short: 'Trust' },
  { key: 'usage_dormancy', label: 'Usage Dormancy', short: 'Usage' },
  { key: 'ownership_governance', label: 'Ownership Governance', short: 'Ownership' },
  { key: 'external_exposure', label: 'External Exposure', short: 'Exposure' },
];

export default function AttackSurfaceRadar({ score, pillars }: AttackSurfaceRadarProps) {
  const [expandedPillar, setExpandedPillar] = useState<string | null>(null);

  const radarData = PILLAR_META.map(p => ({
    pillar: p.short,
    score: Math.round(pillars[p.key]?.score ?? 0),
    fullMark: 100,
  }));

  const fillColor = scoreToColor(score);

  return (
    <div>
      <h3 className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>Attack Surface Breakdown</h3>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Radar Chart */}
        <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
          <ResponsiveContainer width="100%" height={320}>
            <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="75%">
              <PolarGrid stroke="var(--border-subtle)" />
              <PolarAngleAxis
                dataKey="pillar"
                tick={{ fill: 'var(--text-secondary)', fontSize: 11, fontWeight: 600 }}
              />
              <PolarRadiusAxis
                angle={90}
                domain={[0, 100]}
                tick={{ fill: 'var(--text-tertiary)', fontSize: 9 }}
                tickCount={5}
              />
              <Radar
                name="Score"
                dataKey="score"
                stroke={fillColor}
                fill={fillColor}
                fillOpacity={0.25}
                strokeWidth={2}
              />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Pillar Cards Grid */}
        <div className="grid grid-cols-2 gap-3">
          {PILLAR_META.map(p => {
            const pillar = pillars[p.key];
            if (!pillar) return null;
            return (
              <PillarCard
                key={p.key}
                name={p.label}
                shortName={p.short}
                score={pillar.score}
                weight={pillar.weight}
                detail={pillar.detail}
                expanded={expandedPillar === p.key}
                onToggle={() => setExpandedPillar(expandedPillar === p.key ? null : p.key)}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}
