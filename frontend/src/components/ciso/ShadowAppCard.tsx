import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

/**
 * AG-86: CISO Board tile — Shadow App count.
 * One-glance signal for "how many apps in our tenant are outside the
 * approved registry?" Drills to /shadow-apps for triage.
 */
interface ShadowStats {
  total: number;
  new_30d: number;
  ai_classified: number;
}

export function ShadowAppCard() {
  const [stats, setStats] = useState<ShadowStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancel = false;
    fetch('/api/shadow-apps/stats')
      .then(r => r.ok ? r.json() : null)
      .then((d: ShadowStats | null) => { if (!cancel && d) setStats(d); })
      .catch(() => {})
      .finally(() => { if (!cancel) setLoading(false); });
    return () => { cancel = true; };
  }, []);

  if (loading) {
    return (
      <div className="rounded-xl bg-white border border-gray-200 p-5 animate-pulse">
        <div className="h-3 w-24 bg-gray-100 rounded mb-2" />
        <div className="h-8 w-12 bg-gray-100 rounded mb-3" />
        <div className="h-2 w-40 bg-gray-100 rounded" />
      </div>
    );
  }

  if (!stats) return null;

  const tone =
    stats.total === 0   ? 'border-emerald-200 bg-emerald-50' :
    stats.total < 5     ? 'border-amber-200 bg-amber-50' :
                          'border-red-200 bg-red-50';

  return (
    <Link to="/shadow-apps" className={`block rounded-xl border-2 ${tone} p-5 hover:shadow-md transition`}>
      <div className="flex items-baseline justify-between mb-1">
        <span className="text-[10px] font-bold uppercase tracking-wider text-gray-600">
          Shadow Apps
        </span>
        {stats.new_30d > 0 && (
          <span className="text-[10px] font-semibold text-red-700">
            +{stats.new_30d} new (30d)
          </span>
        )}
      </div>
      <div className="flex items-baseline gap-3">
        <span className={`text-3xl font-bold ${stats.total === 0 ? 'text-emerald-700' : 'text-red-700'}`}>
          {stats.total}
        </span>
        <span className="text-xs text-gray-600">
          {stats.total === 0
            ? 'No unsanctioned apps detected'
            : 'apps outside approved registry'}
        </span>
      </div>
      {stats.ai_classified > 0 && (
        <div className="mt-2 text-[11px] text-gray-700">
          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-semibold bg-violet-100 text-violet-700 mr-1">
            AI
          </span>
          {stats.ai_classified} look like AI / automation tools
        </div>
      )}
      <div className="mt-3 text-[10px] text-gray-500 uppercase tracking-wider">
        Review &amp; approve →
      </div>
    </Link>
  );
}
