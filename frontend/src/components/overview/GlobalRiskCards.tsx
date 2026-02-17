import React from 'react';
import Sparkline from '../Sparkline';

interface RiskCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

interface GlobalRiskCardsProps {
  counts: RiskCounts;
  onCardClick?: (level: string) => void;
  trends?: { critical: number[]; high: number[]; medium: number[]; low: number[]; info: number[] };
}

const SPARKLINE_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
  info: '#2563eb',
};

export default function GlobalRiskCards({ counts, onCardClick, trends }: GlobalRiskCardsProps) {
  const cards = [
    {
      level: 'critical',
      label: 'Critical',
      count: counts.critical,
      bgColor: 'bg-red-50',
      borderColor: 'border-red-200',
      textColor: 'text-red-700',
      iconBg: 'bg-red-100',
      icon: (
        <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      ),
    },
    {
      level: 'high',
      label: 'High',
      count: counts.high,
      bgColor: 'bg-orange-50',
      borderColor: 'border-orange-200',
      textColor: 'text-orange-700',
      iconBg: 'bg-orange-100',
      icon: (
        <svg className="w-6 h-6 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    {
      level: 'medium',
      label: 'Medium',
      count: counts.medium,
      bgColor: 'bg-yellow-50',
      borderColor: 'border-yellow-200',
      textColor: 'text-yellow-700',
      iconBg: 'bg-yellow-100',
      icon: (
        <svg className="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    {
      level: 'low',
      label: 'Low',
      count: counts.low,
      bgColor: 'bg-green-50',
      borderColor: 'border-green-200',
      textColor: 'text-green-700',
      iconBg: 'bg-green-100',
      icon: (
        <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    {
      level: 'info',
      label: 'Info',
      count: counts.info,
      bgColor: 'bg-blue-50',
      borderColor: 'border-blue-200',
      textColor: 'text-blue-700',
      iconBg: 'bg-blue-100',
      icon: (
        <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
      {cards.map((card) => (
        <button
          key={card.level}
          onClick={() => onCardClick?.(card.level)}
          className={`${card.bgColor} ${card.borderColor} border-2 rounded-xl p-4 text-left hover:shadow-md transition group`}
        >
          <div className="flex items-center justify-between">
            <div>
              <div className={`text-sm font-medium ${card.textColor}`}>{card.label}</div>
              <div className={`text-3xl font-bold ${card.textColor} mt-1`}>{card.count}</div>
            </div>
            <div className={`${card.iconBg} p-3 rounded-full group-hover:scale-110 transition`}>
              {card.icon}
            </div>
          </div>
          <div className={`text-xs text-gray-500 mt-2`}>
            {((card.count / (counts.total || 1)) * 100).toFixed(1)}% of total
          </div>
          {trends && trends[card.level as keyof typeof trends] && trends[card.level as keyof typeof trends].length >= 2 && (
            <div className="mt-2">
              <Sparkline
                data={trends[card.level as keyof typeof trends]}
                color={SPARKLINE_COLORS[card.level] || '#6b7280'}
                width={140}
                height={24}
              />
            </div>
          )}
        </button>
      ))}
    </div>
  );
}
