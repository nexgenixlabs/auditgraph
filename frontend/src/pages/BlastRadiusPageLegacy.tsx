/**
 * AG-IA-P4 (2026-06-10) — Blast Radius page.
 *
 * Resolves issue #19: prior /blast-radius redirect landed on
 * /identity-explorer with a sort_field=blast_radius_score param. Page
 * title read "Identity Inventory", not "Blast Radius", which made the
 * sidebar nav feel broken.
 *
 * This is a thin wrapper that frames the same Identities table as a
 * Blast Radius surface and pre-sorts by exposure score so the highest-
 * blast identities appear at the top.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import Identities from './Identities';

export default function BlastRadiusPage() {
  return (
    <div className="space-y-4">
      <div className="px-1 pt-2">
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span style={{ color: '#f87171' }}>Exposure Management</span>
          <span>·</span>
          <span>Blast Radius</span>
        </div>
        <h1 className="text-2xl font-bold mt-1" style={{ color: 'var(--text-primary)' }}>Blast Radius</h1>
        <p className="text-sm mt-1 max-w-3xl" style={{ color: 'var(--text-secondary)' }}>
          Identities ranked by what a single credential compromise would unwind — number of
          subscriptions reachable, sensitive data classes touchable, downstream NHIs invokeable.
          The highest-blast identities are the ones to scope down first.
          {' '}
          <Link to="/attack-paths" className="underline" style={{ color: 'var(--accent-primary)' }}>
            See full attack paths →
          </Link>
        </p>
      </div>
      <Identities tabScope="all" />
    </div>
  );
}
