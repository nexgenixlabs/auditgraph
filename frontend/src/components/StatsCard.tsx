/**
 * StatsCard Component
 *
 * A reusable card component for displaying a single statistic with
 * optional icon, trend indicator, and color theming. Used on the
 * Dashboard to show key metrics like total identities, risk counts, etc.
 *
 * Features:
 *   - Title and value display
 *   - Optional emoji/icon on the right side
 *   - Optional trend indicator (up/down/neutral)
 *   - Color theming (blue, red, yellow, green, gray)
 *
 * Usage:
 *   <StatsCard
 *     title="Critical Risks"
 *     value={5}
 *     icon="🔴"
 *     color="red"
 *     trend="up"
 *   />
 */
import React from 'react';

/**
 * Props for the StatsCard component.
 */
interface StatsCardProps {
  /** Card title/label */
  title: string;
  /** Statistic value (number or formatted string) */
  value: number | string;
  /** Optional emoji or icon to display */
  icon?: string;
  /** Optional trend indicator */
  trend?: 'up' | 'down' | 'neutral';
  /** Color theme for the card */
  color?: 'blue' | 'red' | 'yellow' | 'green' | 'gray';
}

/**
 * Stats card component for displaying metrics.
 *
 * Renders a colored card with title, value, optional icon, and trend indicator.
 */
const StatsCard: React.FC<StatsCardProps> = ({
  title, 
  value, 
  icon, 
  trend,
  color = 'blue' 
}) => {
  const colorClasses = {
    blue: 'bg-blue-50 text-blue-600 border-blue-200',
    red: 'bg-red-50 text-red-600 border-red-200',
    yellow: 'bg-yellow-50 text-yellow-600 border-yellow-200',
    green: 'bg-green-50 text-green-600 border-green-200',
    gray: 'bg-gray-50 text-gray-600 border-gray-200',
  };

  return (
    <div className={`border rounded-lg p-6 ${colorClasses[color]}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium opacity-75">{title}</p>
          <p className="text-3xl font-bold mt-2">{value}</p>
        </div>
        {icon && (
          <div className="text-4xl opacity-50">
            {icon}
          </div>
        )}
      </div>
      {trend && (
        <div className="mt-4 flex items-center text-sm">
          {trend === 'up' && <span className="text-green-600">↑ Trending up</span>}
          {trend === 'down' && <span className="text-red-600">↓ Trending down</span>}
          {trend === 'neutral' && <span className="opacity-50">→ No change</span>}
        </div>
      )}
    </div>
  );
};

export default StatsCard;
