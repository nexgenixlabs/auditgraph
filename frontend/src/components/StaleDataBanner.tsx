import React from 'react';

interface StaleDataBannerProps {
  completedAt: string | null | undefined;
}

const StaleDataBanner: React.FC<StaleDataBannerProps> = ({ completedAt }) => {
  if (!completedAt) return null;

  const hoursAgo = Math.floor(
    (Date.now() - new Date(completedAt).getTime()) / (1000 * 60 * 60)
  );

  if (isNaN(hoursAgo) || hoursAgo < 24) return null;

  const displayTime = hoursAgo >= 48
    ? `${Math.floor(hoursAgo / 24)} days`
    : `${hoursAgo} hours`;

  return (
    <div className="bg-yellow-50 border border-yellow-200 rounded-lg px-4 py-3 flex items-center gap-3 mb-4">
      <svg className="w-5 h-5 text-yellow-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
      <div className="text-sm text-yellow-800">
        <span className="font-medium">Stale data:</span>{' '}
        Snapshot data is {displayTime} old. Capture a new snapshot to refresh.
      </div>
    </div>
  );
};

export default StaleDataBanner;
