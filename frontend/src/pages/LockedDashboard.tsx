import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

interface DiscoveryStatus {
  has_snapshot: boolean;
  has_connector: boolean;
  active_subscription_count: number;
  discovered_subscription_count: number;
}

export default function LockedDashboard() {
  const navigate = useNavigate();
  const [status, setStatus] = useState<DiscoveryStatus | null>(null);

  useEffect(() => {
    fetch('/api/discovery/status')
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d) setStatus({
          has_snapshot: d.has_snapshot || false,
          has_connector: d.has_connector || false,
          active_subscription_count: d.active_subscription_count || 0,
          discovered_subscription_count: d.discovered_subscription_count || 0,
        });
      })
      .catch(() => {});
  }, []);

  // Determine which onboarding state to show
  const hasConnector = status?.has_connector || false;
  const activeSubs = status?.active_subscription_count || 0;
  const discoveredSubs = status?.discovered_subscription_count || 0;

  let icon: React.ReactNode;
  let title: string;
  let description: string;
  let buttonLabel: string;
  let onButtonClick: () => void;
  let iconBg: string;
  let iconColor: string;
  let stepIndicator: string;

  if (hasConnector && activeSubs === 0 && discoveredSubs > 0) {
    // STATE 2: Connector connected, subscriptions discovered but none activated
    iconBg = 'bg-blue-100';
    iconColor = 'text-blue-600';
    icon = (
      <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    );
    title = 'Activate Your Subscriptions';
    description = `Your Azure connector is connected and ${discoveredSubs} subscription${discoveredSubs !== 1 ? 's were' : ' was'} discovered. Activate the subscriptions you want to monitor to begin scanning.`;
    buttonLabel = 'Activate Subscriptions';
    onButtonClick = () => navigate('/subscriptions');
    stepIndicator = 'Step 2 of 3';
  } else if (hasConnector && activeSubs > 0) {
    // STATE 3: Subs activated, waiting for first snapshot
    iconBg = 'bg-emerald-100';
    iconColor = 'text-emerald-600';
    icon = (
      <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z" />
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 13a3 3 0 11-6 0 3 3 0 016 0z" />
      </svg>
    );
    title = 'Capture Your First Snapshot';
    description = `${activeSubs} subscription${activeSubs !== 1 ? 's are' : ' is'} activated. Capture your first snapshot to discover identities and start monitoring.`;
    buttonLabel = 'Capture Snapshot';
    onButtonClick = () => navigate('/settings/connections');
    stepIndicator = 'Step 3 of 3';
  } else {
    // STATE 1: No connector at all (default)
    iconBg = 'bg-amber-100';
    iconColor = 'text-amber-600';
    icon = (
      <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    );
    title = 'Connect Your Cloud Provider';
    description = 'Connect your Azure, AWS, or GCP credentials to start discovering and monitoring identities across your cloud environment.';
    buttonLabel = 'Add Connection';
    onButtonClick = () => navigate('/settings/connections');
    stepIndicator = 'Step 1 of 3';
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative">
      {/* Blurred placeholder cards */}
      <div className="filter blur-sm pointer-events-none select-none">
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Identity Risk Overview</h2>
        <div className="grid grid-cols-4 gap-4 mb-6">
          {['Total Identities', 'Critical', 'High', 'Snapshots'].map(label => (
            <div key={label} className="bg-white rounded-xl border border-gray-200 p-5">
              <div className="text-xs font-medium text-gray-500 uppercase tracking-wide">{label}</div>
              <div className="text-2xl font-bold text-gray-300 mt-1">&mdash;</div>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-white rounded-xl border border-gray-200 p-6 h-48" />
          <div className="bg-white rounded-xl border border-gray-200 p-6 h-48" />
        </div>
      </div>

      {/* Overlay card */}
      <div className="absolute inset-0 flex items-center justify-center z-10">
        <div className="bg-white rounded-2xl border border-gray-200 shadow-xl p-8 max-w-md text-center">
          <div className={`inline-flex items-center justify-center w-14 h-14 rounded-full ${iconBg} ${iconColor} mb-4`}>
            {icon}
          </div>
          <div className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">{stepIndicator}</div>
          <h3 className="text-lg font-bold text-gray-900 mb-2">{title}</h3>
          <p className="text-sm text-gray-600 mb-5">{description}</p>
          <button
            onClick={onButtonClick}
            className="px-6 py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition"
          >
            {buttonLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
