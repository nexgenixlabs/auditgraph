/**
 * EnrichmentTierBadge — renders correct label, colour, and tooltip
 * for each of the 4 enrichment tiers, plus null/undefined fallback.
 */

import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import { EnrichmentTierBadge } from '../lineage/EnrichmentTierBadge';

// ── Tests ───────────────────────────────────────────────────────────

describe('EnrichmentTierBadge', () => {
  it('renders STATIC tier with gray badge and correct label', () => {
    const { container } = render(<EnrichmentTierBadge tier="STATIC" />);
    expect(screen.getByText('Static Analysis')).toBeInTheDocument();
    const badge = container.querySelector('span');
    expect(badge?.className).toContain('bg-gray-100');
  });

  it('renders P1_SIGNIN tier with blue badge and correct label', () => {
    const { container } = render(<EnrichmentTierBadge tier="P1_SIGNIN" />);
    expect(screen.getByText('Sign-in Enriched')).toBeInTheDocument();
    const badge = container.querySelector('span');
    expect(badge?.className).toContain('bg-blue-100');
  });

  it('renders P2_AUDIT tier with amber badge and correct label', () => {
    const { container } = render(<EnrichmentTierBadge tier="P2_AUDIT" />);
    expect(screen.getByText('Audit Log Enriched')).toBeInTheDocument();
    const badge = container.querySelector('span');
    expect(badge?.className).toContain('bg-amber-100');
  });

  it('renders FULL tier with green badge and correct label', () => {
    const { container } = render(<EnrichmentTierBadge tier="FULL" />);
    expect(screen.getByText('Full Enrichment')).toBeInTheDocument();
    const badge = container.querySelector('span');
    expect(badge?.className).toContain('bg-green-100');
  });

  it('renders STATIC badge for null input', () => {
    render(<EnrichmentTierBadge tier={null} />);
    expect(screen.getByText('Static Analysis')).toBeInTheDocument();
  });

  it('renders STATIC badge for undefined input', () => {
    render(<EnrichmentTierBadge tier={undefined} />);
    expect(screen.getByText('Static Analysis')).toBeInTheDocument();
  });

  it('renders STATIC badge for unknown tier value', () => {
    render(<EnrichmentTierBadge tier="BANANA" />);
    expect(screen.getByText('Static Analysis')).toBeInTheDocument();
  });

  it('shows tooltip on hover', async () => {
    const { container } = render(<EnrichmentTierBadge tier="FULL" />);
    const wrapper = container.firstElementChild as HTMLElement;

    // Tooltip should not be visible initially
    expect(screen.queryByText(/All enrichment sources active/)).not.toBeInTheDocument();

    // Hover to show tooltip
    await act(async () => {
      fireEvent.mouseEnter(wrapper);
    });
    expect(screen.getByText(/All enrichment sources active/)).toBeInTheDocument();

    // Mouse leave to hide
    await act(async () => {
      fireEvent.mouseLeave(wrapper);
    });
    expect(screen.queryByText(/All enrichment sources active/)).not.toBeInTheDocument();
  });
});
