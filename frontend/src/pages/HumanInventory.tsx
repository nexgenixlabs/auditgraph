/**
 * AG-IA-P1 (2026-06-10) — Human Inventory page.
 *
 * Resolves issue #2: when you click the Human bucket → Inventory in the
 * sidebar, you should see ONLY humans, not a tabbed view that also surfaces
 * NHIs and AI Agents. The cross-bucket tabbed view lives at /identity-explorer
 * (All Identities), where it belongs.
 *
 * This page is a thin wrapper that renders <Identities tabScope="humans" />
 * with a Human-only header. Same engine, single-bucket framing.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import Identities from './Identities';

export default function HumanInventory() {
  return (
    <div className="space-y-4">
      <div className="px-1 pt-2">
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span style={{ color: 'var(--accent-primary)' }}>Identity</span>
          <span>·</span>
          <span>Human</span>
          <span>·</span>
          <span>Inventory</span>
        </div>
        <h1 className="text-2xl font-bold mt-1" style={{ color: 'var(--text-primary)' }}>Human Identity Inventory</h1>
        <p className="text-sm mt-1 max-w-3xl" style={{ color: 'var(--text-secondary)' }}>
          Every human in your tenant with direct or PIM-eligible Azure access — employees, contractors, guests.
          {' '}
          <Link to="/identity-explorer" className="underline" style={{ color: 'var(--accent-primary)' }}>
            See all identity types →
          </Link>
        </p>
      </div>
      <Identities tabScope="humans" />
    </div>
  );
}
