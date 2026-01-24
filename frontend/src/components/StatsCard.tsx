// src/components/StatsCard.tsx
import React from 'react';

interface StatsCardProps {
  title: string;
  value: number | string;
  icon?: string;
  trend?: 'up' | 'down' | 'neutral';
  color?: 'blue' | 'red' | 'yellow' | 'green' | 'gray';
}

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
