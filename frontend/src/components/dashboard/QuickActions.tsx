import React from 'react';
import { useNavigate } from 'react-router-dom';

interface QuickActionsProps {
  criticalCount: number;
  expiringCount?: number;
  dormantCount?: number;
  ghostCount?: number;
}

export default function QuickActions({ criticalCount, expiringCount = 0, dormantCount = 0, ghostCount = 0 }: QuickActionsProps) {
  const navigate = useNavigate();

  const actions = [
    {
      id: 'critical',
      label: 'View Critical Risks',
      description: 'Identities requiring immediate attention',
      count: criticalCount,
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      ),
      color: 'red',
      onClick: () => navigate('/identities?risk_level=critical'),
    },
    {
      id: 'expiring',
      label: 'Expiring Credentials',
      description: 'Secrets/certs expiring within 30 days',
      count: expiringCount,
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
      color: 'orange',
      onClick: () => navigate('/identities?credential_expiry=expiring_soon'),
    },
    {
      id: 'dormant',
      label: 'Dormant Identities',
      description: 'No sign-in activity for 90+ days',
      count: dormantCount,
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
        </svg>
      ),
      color: 'purple',
      onClick: () => navigate('/identities?activity_status=dormant'),
    },
    {
      id: 'ghost_access',
      label: 'Ghost Access',
      description: 'Disabled/deleted with active roles',
      count: ghostCount,
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
        </svg>
      ),
      color: ghostCount > 0 ? 'red' : 'blue',
      onClick: () => navigate('/identities?status=disabled'),
    },
  ];

  const colorClasses: Record<string, { bg: string; hoverBg: string; border: string; text: string; iconBg: string }> = {
    red: { bg: 'bg-red-50', hoverBg: 'hover:bg-red-50', border: 'border-red-200', text: 'text-red-700', iconBg: 'bg-red-100' },
    orange: { bg: 'bg-orange-50', hoverBg: 'hover:bg-orange-50', border: 'border-orange-200', text: 'text-orange-700', iconBg: 'bg-orange-100' },
    purple: { bg: 'bg-purple-50', hoverBg: 'hover:bg-purple-50', border: 'border-purple-200', text: 'text-purple-700', iconBg: 'bg-purple-100' },
    blue: { bg: 'bg-blue-50', hoverBg: 'hover:bg-blue-50', border: 'border-blue-200', text: 'text-blue-700', iconBg: 'bg-blue-100' },
  };

  return (
    <div className="bg-white border rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b bg-gray-50">
        <h3 className="text-sm font-semibold text-gray-900">Quick Actions</h3>
        <p className="text-xs text-gray-500 mt-1">Common security workflows</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 divide-x divide-y lg:divide-y-0">
        {actions.map(action => {
          const colors = colorClasses[action.color];
          return (
            <button
              key={action.id}
              onClick={action.onClick}
              className={`p-4 text-left transition ${colors.hoverBg} group`}
            >
              <div className="flex items-start gap-3">
                <div className={`p-2 rounded-lg ${colors.iconBg} ${colors.text} group-hover:scale-110 transition`}>
                  {action.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-gray-900 text-sm">{action.label}</div>
                  <div className="text-xs text-gray-500 mt-0.5 truncate">{action.description}</div>
                  {action.count !== null && (
                    <div className={`text-lg font-bold ${colors.text} mt-1`}>
                      {action.count}
                    </div>
                  )}
                </div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
