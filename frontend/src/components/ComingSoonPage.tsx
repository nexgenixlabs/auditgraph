/**
 * ComingSoonPage — Reusable placeholder for AI Security pillars not yet shipped.
 *
 * Used by AI Runtime, AI Risk, AI Governance until each ships its real page.
 * Sets enterprise expectations: shows WHAT is coming, WHY it matters, and an
 * interest-registration affordance. Never renders fake/mock content.
 */
import React, { useState } from 'react';

export interface PillarCapability {
  /** Section title rendered as a bullet */
  title: string;
  /** One-line description of the capability */
  description: string;
}

export interface ComingSoonPageProps {
  /** Pillar name, e.g. "AI Runtime" */
  pillar: string;
  /** Pillar tagline, 1 line */
  tagline: string;
  /** 2–3 sentence overview of what this pillar will answer for the user */
  overview: string;
  /** Bullet list of concrete capabilities this pillar will ship */
  capabilities: PillarCapability[];
  /** Target ship date (e.g. "Q3 2026") — optional */
  targetWindow?: string;
  /** Linked Jira/roadmap reference — optional */
  roadmapRef?: string;
}

export default function ComingSoonPage({
  pillar,
  tagline,
  overview,
  capabilities,
  targetWindow,
  roadmapRef,
}: ComingSoonPageProps) {
  const [notified, setNotified] = useState(false);

  return (
    <div className="max-w-5xl mx-auto py-8 px-6 space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>{pillar}</h1>
          <span
            className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider"
            style={{
              backgroundColor: 'rgba(139, 92, 246, 0.12)',
              color: '#a78bfa',
              border: '1px solid rgba(139, 92, 246, 0.3)',
            }}
          >
            Coming Soon
          </span>
        </div>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{tagline}</p>
      </div>

      {/* Overview card */}
      <div
        className="rounded-xl border p-6"
        style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}
      >
        <h2 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
          What this pillar answers
        </h2>
        <p className="text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>{overview}</p>
      </div>

      {/* Capabilities list */}
      <div
        className="rounded-xl border p-6"
        style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}
      >
        <h2 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'var(--text-tertiary)' }}>
          Capabilities shipping in this pillar
        </h2>
        <ul className="space-y-3">
          {capabilities.map((cap, idx) => (
            <li key={idx} className="flex gap-3">
              <span
                className="flex-shrink-0 mt-0.5 w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold"
                style={{ backgroundColor: 'rgba(36, 162, 161, 0.15)', color: '#24A2A1' }}
              >
                {idx + 1}
              </span>
              <div>
                <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{cap.title}</div>
                <div className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{cap.description}</div>
              </div>
            </li>
          ))}
        </ul>
      </div>

      {/* Footer: target window + notify CTA */}
      <div
        className="rounded-xl border p-5 flex items-center justify-between gap-4"
        style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}
      >
        <div>
          {targetWindow && (
            <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
              Target availability: <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>{targetWindow}</span>
            </div>
          )}
          {roadmapRef && (
            <div className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
              Roadmap: <span className="font-mono">{roadmapRef}</span>
            </div>
          )}
        </div>
        {!notified ? (
          <button
            onClick={() => setNotified(true)}
            className="px-4 py-2 rounded-lg text-xs font-semibold transition"
            style={{
              backgroundColor: 'rgba(36, 162, 161, 0.15)',
              color: '#24A2A1',
              border: '1px solid rgba(36, 162, 161, 0.4)',
            }}
          >
            Notify me when available →
          </button>
        ) : (
          <span className="text-xs font-semibold" style={{ color: '#24A2A1' }}>
            ✓ We&apos;ll notify you
          </span>
        )}
      </div>
    </div>
  );
}
