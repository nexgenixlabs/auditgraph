import React from 'react';
import { Link } from 'react-router-dom';
import { RISK_BADGE, getCategoryLabel } from '../../constants/metrics';

interface CriticalIdentity {
  identity_id: string;
  display_name: string;
  identity_category?: string;
  risk_level: string;
  risk_score?: number;
  risk_reason?: string[] | string;
}

interface CriticalIdentitiesListProps {
  identities: CriticalIdentity[];
  loading?: boolean;
}

function RiskBadge({ level, score }: { level: string; score?: number }) {
  const colors: Record<string, string> = {
    critical: `${RISK_BADGE.critical} border-red-200`,
    high: `${RISK_BADGE.high} border-orange-200`,
    medium: `${RISK_BADGE.medium} border-yellow-200`,
  };

  return (
    <div className="flex items-center gap-2">
      <span className={`px-2 py-0.5 rounded-full text-xs font-semibold uppercase border ${colors[level] || 'bg-gray-100 text-gray-700'}`}>
        {level}
      </span>
      {score !== undefined && score > 0 && (
        <span className="text-xs text-gray-500 font-mono">({score} pts)</span>
      )}
    </div>
  );
}

export default function CriticalIdentitiesList({ identities, loading }: CriticalIdentitiesListProps) {
  if (loading) {
    return (
      <div className="bg-white border rounded-xl p-6">
        <div className="animate-pulse">
          <div className="h-5 bg-gray-200 rounded w-48 mb-4" />
          <div className="space-y-3">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-16 bg-gray-100 rounded-lg" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  const topIdentities = identities.slice(0, 10);

  return (
    <div className="bg-white border rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b bg-gray-50 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-gray-900">Critical & High Risk Identities</h3>
          <p className="text-xs text-gray-500 mt-1">Identities requiring immediate attention</p>
        </div>
        <Link
          to="/identities?risk_level=critical"
          className="text-xs font-medium text-blue-600 hover:text-blue-700 hover:underline"
        >
          View All Critical →
        </Link>
      </div>

      {topIdentities.length === 0 ? (
        <div className="px-5 py-8 text-center">
          <div className="text-green-600 mb-2">
            <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div className="text-sm font-medium text-gray-900">No Critical Risks Found</div>
          <div className="text-xs text-gray-500 mt-1">Your identity posture looks healthy</div>
        </div>
      ) : (
        <div className="divide-y">
          {topIdentities.map((identity, idx) => {
            const reasons = Array.isArray(identity.risk_reason)
              ? identity.risk_reason
              : identity.risk_reason
                ? [identity.risk_reason]
                : [];

            return (
              <Link
                key={identity.identity_id}
                to={`/identities/${encodeURIComponent(identity.identity_id)}`}
                className="flex items-start gap-4 px-5 py-4 hover:bg-gray-50 transition group"
              >
                {/* Rank */}
                <div className="flex-shrink-0 w-6 h-6 rounded-full bg-gray-100 flex items-center justify-center text-xs font-bold text-gray-500">
                  {idx + 1}
                </div>

                {/* Identity Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-900 truncate group-hover:text-blue-600 transition">
                      {identity.display_name}
                    </span>
                    <span className="flex-shrink-0 px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600">
                      {getCategoryLabel(identity.identity_category)}
                    </span>
                  </div>

                  {reasons.length > 0 && (
                    <div className="text-xs text-gray-500 mt-1 truncate" title={reasons.join(' • ')}>
                      {reasons[0]}
                    </div>
                  )}
                </div>

                {/* Risk Badge */}
                <div className="flex-shrink-0">
                  <RiskBadge level={identity.risk_level} score={identity.risk_score} />
                </div>

                {/* Arrow */}
                <div className="flex-shrink-0 text-gray-400 group-hover:text-blue-600 transition">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
