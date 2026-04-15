import React from 'react';
import type { PostureV31Response } from '../../utils/cisoViewModel';
import { POSTURE_CONFIDENCE_COLOR } from '../../constants/cisoColors';

function formatFreshness(isoString: string | null | undefined): string {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    const diffMs = Date.now() - d.getTime();
    const mins = Math.floor(diffMs / 60_000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  } catch {
    return '—';
  }
}

export function DataIntegrityFooter({ data }: { data: PostureV31Response }) {
  const scanMeta = data?.scan_metadata;
  const coverage = data?.coverage;
  if (!coverage) return null;

  const freshness = formatFreshness(scanMeta?.last_scan_at);
  const confidence = coverage.confidence_level || 'low';
  const confColor = POSTURE_CONFIDENCE_COLOR[confidence] || '#4a6080';
  const activeSources = coverage.active_sources ?? 0;
  const totalSources = coverage.total_sources ?? 0;
  const totalIdentities = data.identity_risk?.total ?? 0;

  return (
    <div className="mx-3 mb-3 px-3 py-2 rounded-md bg-[#111827] border border-white/5 flex items-center justify-between text-xs text-gray-500 flex-shrink-0">
      {/* Left: freshness */}
      <span>Last analyzed: <span className="text-gray-400">{freshness}</span></span>

      {/* Center: scope summary */}
      <div className="flex items-center gap-1.5">
        <span>Scope:</span>
        <span>{(coverage.sub_count ?? 0) === 1 ? '1 subscription' : `${coverage.sub_count ?? 0} subscriptions`}</span>
        <span className="text-gray-600">&middot;</span>
        <span>{totalIdentities === 1 ? '1 identity' : `${totalIdentities.toLocaleString()} identities`}</span>
      </div>

      {/* Right: confidence level */}
      <span className="flex items-center gap-1">
        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: confColor }} />
        <span style={{ color: confColor }} className="capitalize">
          {confidence} ({activeSources}/{totalSources} Sources Active)
        </span>
      </span>
    </div>
  );
}
