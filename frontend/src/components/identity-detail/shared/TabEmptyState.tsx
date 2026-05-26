import React from 'react';

interface TabEmptyStateProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  criteria: string[];
  actionLabel?: string;
  onAction?: () => void;
}

export function TabEmptyState({ icon, title, description, criteria, actionLabel, onAction }: TabEmptyStateProps) {
  return (
    <div className="py-10 px-6">
      <div className="flex flex-col items-center text-center mb-6">
        <div className="mb-3">{icon}</div>
        <h3 className="text-sm font-semibold text-gray-700">{title}</h3>
        <p className="text-xs text-gray-500 mt-1 max-w-md">{description}</p>
      </div>
      <ul className="max-w-lg mx-auto space-y-2">
        {criteria.map((item, idx) => (
          <li key={idx} className="flex items-start gap-2 text-xs text-gray-500">
            <span className="mt-1 w-1 h-1 rounded-full bg-gray-300 flex-shrink-0" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
      {actionLabel && onAction && (
        <div className="flex justify-center mt-6">
          <button
            onClick={onAction}
            className="px-4 py-1.5 rounded-lg text-xs font-medium bg-gray-100 hover:bg-gray-200 text-gray-700 transition"
          >
            {actionLabel}
          </button>
        </div>
      )}
    </div>
  );
}
