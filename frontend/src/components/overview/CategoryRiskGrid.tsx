import React from 'react';

interface CategoryData {
  key: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface CategoryRiskGridProps {
  categories: CategoryData[];
  onCategoryClick?: (category: string, riskLevel?: string) => void;
}

const categoryConfig: Record<string, { label: string; description: string; icon: React.ReactNode }> = {
  service_principal: {
    label: 'Service Principals',
    description: 'App registrations & enterprise apps',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
      </svg>
    ),
  },
  managed_identity_system: {
    label: 'System Managed Identity',
    description: 'VM, App Service, Function bindings',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
      </svg>
    ),
  },
  managed_identity_user: {
    label: 'User Managed Identity',
    description: 'Reusable across resources',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
      </svg>
    ),
  },
  human_user: {
    label: 'Human Users',
    description: 'Employees & members',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
      </svg>
    ),
  },
  guest: {
    label: 'Guest Users',
    description: 'External collaborators',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
      </svg>
    ),
  },
  microsoft_internal: {
    label: 'Microsoft Internal',
    description: 'First-party system apps',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
};

function RiskBar({ data }: { data: CategoryData }) {
  const total = data.total || 1;
  const criticalPct = (data.critical / total) * 100;
  const highPct = (data.high / total) * 100;
  const mediumPct = (data.medium / total) * 100;

  return (
    <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden flex">
      {criticalPct > 0 && <div className="bg-red-500 h-full" style={{ width: `${criticalPct}%` }} />}
      {highPct > 0 && <div className="bg-orange-500 h-full" style={{ width: `${highPct}%` }} />}
      {mediumPct > 0 && <div className="bg-yellow-500 h-full" style={{ width: `${mediumPct}%` }} />}
      <div className="bg-green-500 h-full flex-1" />
    </div>
  );
}

export default function CategoryRiskGrid({ categories, onCategoryClick }: CategoryRiskGridProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {categories.map((cat) => {
        const config = categoryConfig[cat.key] || {
          label: cat.key,
          description: '',
          icon: null,
        };

        const hasRisks = cat.critical > 0 || cat.high > 0 || cat.medium > 0;

        return (
          <div
            key={cat.key}
            className="bg-white border rounded-xl p-5 hover:shadow-md transition"
          >
            {/* Header */}
            <div className="flex items-start justify-between gap-3 mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-gray-100 rounded-lg text-gray-600">
                  {config.icon}
                </div>
                <div>
                  <div className="font-semibold text-gray-900">{config.label}</div>
                  <div className="text-xs text-gray-500">{config.description}</div>
                </div>
              </div>
              <button
                onClick={() => onCategoryClick?.(cat.key)}
                className="text-xs font-medium px-3 py-1 rounded-full bg-gray-100 text-gray-700 hover:bg-gray-200 transition"
              >
                View All
              </button>
            </div>

            {/* Stats */}
            <div className="flex items-center justify-between mb-3">
              <span className="text-2xl font-bold text-gray-900">{cat.total}</span>
              <span className="text-xs text-gray-500">identities</span>
            </div>

            {/* Risk Bar */}
            <RiskBar data={cat} />

            {/* Risk Badges */}
            <div className="flex flex-wrap gap-2 mt-4">
              {cat.critical > 0 && (
                <button
                  onClick={() => onCategoryClick?.(cat.key, 'critical')}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-red-50 text-red-700 text-xs font-medium hover:bg-red-100 transition"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                  {cat.critical} Critical
                </button>
              )}
              {cat.high > 0 && (
                <button
                  onClick={() => onCategoryClick?.(cat.key, 'high')}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-orange-50 text-orange-700 text-xs font-medium hover:bg-orange-100 transition"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                  {cat.high} High
                </button>
              )}
              {cat.medium > 0 && (
                <button
                  onClick={() => onCategoryClick?.(cat.key, 'medium')}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-yellow-50 text-yellow-700 text-xs font-medium hover:bg-yellow-100 transition"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-yellow-500" />
                  {cat.medium} Medium
                </button>
              )}
              {!hasRisks && cat.total > 0 && (
                <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-green-50 text-green-700 text-xs font-medium">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                  All Healthy
                </span>
              )}
              {cat.total === 0 && (
                <span className="text-xs text-gray-400">No identities</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
