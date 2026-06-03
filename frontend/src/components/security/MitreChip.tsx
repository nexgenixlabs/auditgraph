import React from 'react';
import { MITRE_BY_ID, type MitreTechnique } from '../../constants/mitre';

/**
 * AG-177: Canonical MITRE technique chip — used by AttackPathView,
 * AILifecycleTimeline, AgentActivityTimeline, Argus reasoning panes.
 *
 * Props deliberately small: just the technique IDs the backend tagged.
 * All display data resolves from the central MITRE_BY_ID catalog.
 */

const TACTIC_TONE: Record<string, string> = {
  'Initial Access':       'bg-rose-50 text-rose-800 border-rose-200',
  'Privilege Escalation': 'bg-orange-50 text-orange-800 border-orange-200',
  'Credential Access':    'bg-amber-50 text-amber-800 border-amber-200',
  'Persistence':          'bg-violet-50 text-violet-800 border-violet-200',
  'Lateral Movement':     'bg-blue-50 text-blue-800 border-blue-200',
  'Collection':           'bg-sky-50 text-sky-800 border-sky-200',
  'Exfiltration':         'bg-red-50 text-red-800 border-red-200',
  'Defense Evasion':      'bg-purple-50 text-purple-800 border-purple-200',
};

interface MitreChipProps {
  id: string;
  size?: 'sm' | 'md';
  className?: string;
}

export function MitreChip({ id, size = 'sm', className = '' }: MitreChipProps) {
  const tech: MitreTechnique | null = MITRE_BY_ID[id] || null;
  if (!tech) {
    return (
      <span
        className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-gray-100 text-gray-500 border border-gray-200 ${className}`}
        title={`Unknown technique: ${id}`}
      >
        {id}
      </span>
    );
  }
  const tone = TACTIC_TONE[tech.tactic] || 'bg-gray-50 text-gray-700 border-gray-200';
  const px = size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-1 text-xs';
  return (
    <a
      href={tech.url}
      target="_blank"
      rel="noopener noreferrer"
      className={`inline-flex items-center rounded font-mono font-semibold border ${tone} ${px} hover:opacity-80 transition ${className}`}
      title={`${tech.tactic} · ${tech.name}`}
    >
      {tech.id}
    </a>
  );
}

interface MitreChipStripProps {
  ids: string[];
  max?: number;
  size?: 'sm' | 'md';
  className?: string;
}

/** Renders a deduped row of chips. Optionally caps to `max` with "+N more". */
export function MitreChipStrip({ ids, max, size = 'sm', className = '' }: MitreChipStripProps) {
  const dedup: string[] = Array.from(new Set(ids || []));
  if (dedup.length === 0) return null;
  const shown = typeof max === 'number' && dedup.length > max ? dedup.slice(0, max) : dedup;
  const overflow = dedup.length - shown.length;
  return (
    <div className={`flex flex-wrap items-center gap-1 ${className}`}>
      {shown.map(id => <MitreChip key={id} id={id} size={size} />)}
      {overflow > 0 && (
        <span className="text-[10px] font-medium text-gray-500">+{overflow} more</span>
      )}
    </div>
  );
}

/**
 * Tactic-level badge for hero strips ("Credential Access" tactic above the chain).
 * Resolves tactic from the first matching technique.
 */
interface MitreTacticBadgeProps {
  tactic: string;
  className?: string;
}

export function MitreTacticBadge({ tactic, className = '' }: MitreTacticBadgeProps) {
  const tone = TACTIC_TONE[tactic] || 'bg-gray-50 text-gray-700 border-gray-200';
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border ${tone} ${className}`}
    >
      {tactic}
    </span>
  );
}
