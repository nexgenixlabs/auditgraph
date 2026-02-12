import React, { useState } from 'react';

interface UpgradeGateProps {
  children: React.ReactNode;
  featureName?: string;
  upgradeRequired?: boolean;
}

export default function UpgradeGate({ children, featureName, upgradeRequired }: UpgradeGateProps) {
  if (!upgradeRequired) return <>{children}</>;

  return (
    <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
      <div className="w-16 h-16 rounded-full bg-amber-100 text-amber-600 flex items-center justify-center text-2xl mb-4">
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h3 className="text-lg font-bold text-gray-900 mb-1">Upgrade Required</h3>
      <p className="text-sm text-gray-600 max-w-md mb-4">
        {featureName ? `${featureName} is not available on your current plan.` : 'This feature requires a plan upgrade.'} Contact your administrator to upgrade.
      </p>
      <span className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg opacity-60 cursor-not-allowed">
        Contact Admin to Upgrade
      </span>
    </div>
  );
}
