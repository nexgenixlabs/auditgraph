/**
 * Hardening H3: AgentRiskSection — loading, error, empty, and data states.
 *
 * Tests H3-A through H3-G verifying skeleton, error, retry, empty, and
 * data rendering for the blast radius subsection in IdentityDrawer.
 */

import React from 'react';
import { render, screen, waitFor, act, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';

// ─── react-router-dom is auto-mocked via src/__mocks__/react-router-dom.tsx

// ─── Mock ConnectionContext ──────────────────────────────────────────
jest.mock('../../contexts/ConnectionContext', () => ({
  useConnection: () => ({
    withConnection: (url: string) => url,
    connected: true,
  }),
}));

// ─── Import after mocks ─────────────────────────────────────────────
import IdentityDrawer from '../IdentityDrawer';

// ─── Helpers ─────────────────────────────────────────────────────────

const BASE_AGENT_INFO = {
  detected_platform: 'azure_openai',
  classification_confidence: 0.92,
  days_inactive: 45,
  agirs_score: 78,
  has_orphan_finding: true,
};

const VALID_BLAST_RADIUS = {
  reachable_subscription_count: 2,
  reachable_resource_group_count: 5,
  reachable_resource_count: 12,
  sensitive_resource_count: 3,
  resource_breakdown: { key_vault: 2, storage_account: 4 },
  delegations: [],
};

const EMPTY_BLAST_RADIUS = {
  reachable_subscription_count: 0,
  reachable_resource_group_count: 0,
  reachable_resource_count: 0,
  sensitive_resource_count: 0,
  resource_breakdown: {},
  delegations: [],
};

const IDENTITY_DETAIL = {
  identity: {
    identity_id: 'test-spn-001',
    display_name: 'NightlyBot',
    identity_type: 'service_principal',
    identity_category: 'service_principal',
    risk_level: 'critical',
    risk_score: 78,
    activity_status: 'inactive',
  },
  graph_permissions: [],
  owners: [],
  roles: [],
};

const GRAPH_DATA = {
  trust_relationships: { role_edges: [] },
  secret_exposure: [],
  effective_scope: { scope_hierarchy: [], entra_scopes: [] },
  agent_info: BASE_AGENT_INFO,
};

/**
 * Helper: set up global.fetch to respond to identity detail, graph-data,
 * and blast-radius endpoints. blastHandler controls the blast-radius behavior.
 */
function mockFetchWith(blastHandler: () => Promise<Response>) {
  const fetchMock = jest.fn((url: string) => {
    if (url.includes('/graph-data')) {
      return Promise.resolve(new Response(JSON.stringify(GRAPH_DATA), { status: 200 }));
    }
    if (url.includes('/blast-radius')) {
      return blastHandler();
    }
    // Default: identity detail
    return Promise.resolve(new Response(JSON.stringify(IDENTITY_DETAIL), { status: 200 }));
  });
  global.fetch = fetchMock as any;
  return fetchMock;
}

function renderDrawer() {
  return render(
    <IdentityDrawer identityId="test-spn-001" onClose={jest.fn()} />
  );
}

// ─── Tests ───────────────────────────────────────────────────────────

describe('AgentRiskSection', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  test('H3-A: Loading state renders skeleton during API call', async () => {
    // Blast radius never resolves
    let resolveBlast!: (v: Response) => void;
    mockFetchWith(() => new Promise(resolve => { resolveBlast = resolve; }));

    await act(async () => { renderDrawer(); });

    // Wait for drawer to load identity detail
    await waitFor(() => {
      expect(screen.getByText('NightlyBot')).toBeInTheDocument();
    });

    // Skeleton should be visible while blast radius is in-flight
    expect(screen.getByTestId('blast-radius-skeleton')).toBeInTheDocument();
    // Actual data should NOT be in the DOM
    expect(screen.queryByTestId('blast-radius-data')).not.toBeInTheDocument();
    expect(screen.queryByTestId('blast-radius-error')).not.toBeInTheDocument();

    // Clean up the pending promise
    await act(async () => {
      resolveBlast(new Response(JSON.stringify(VALID_BLAST_RADIUS), { status: 200 }));
    });
  });

  test('H3-B: Data renders after successful API call', async () => {
    mockFetchWith(() =>
      Promise.resolve(new Response(JSON.stringify(VALID_BLAST_RADIUS), { status: 200 }))
    );

    await act(async () => { renderDrawer(); });

    await waitFor(() => {
      expect(screen.getByTestId('blast-radius-data')).toBeInTheDocument();
    });

    // Skeleton should be gone
    expect(screen.queryByTestId('blast-radius-skeleton')).not.toBeInTheDocument();
    // Data should be visible
    expect(screen.getByText(/subscription/i)).toBeInTheDocument();
  });

  test('H3-C: Error state renders on API failure', async () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    mockFetchWith(() => Promise.resolve(new Response('', { status: 500 })));

    await act(async () => { renderDrawer(); });

    await waitFor(() => {
      expect(screen.getByTestId('blast-radius-error')).toBeInTheDocument();
    });

    expect(screen.getByText(/blast radius unavailable/i)).toBeInTheDocument();
    expect(screen.getByTestId('blast-radius-retry')).toBeInTheDocument();
    // No unhandled console errors about the blast radius
    expect(screen.queryByTestId('blast-radius-skeleton')).not.toBeInTheDocument();

    consoleSpy.mockRestore();
  });

  test('H3-D: Retry button re-calls API and shows data on success', async () => {
    let callCount = 0;
    const fetchMock = mockFetchWith(() => {
      callCount++;
      if (callCount === 1) {
        return Promise.resolve(new Response('', { status: 500 }));
      }
      return Promise.resolve(new Response(JSON.stringify(VALID_BLAST_RADIUS), { status: 200 }));
    });

    await act(async () => { renderDrawer(); });

    // Wait for error state
    await waitFor(() => {
      expect(screen.getByTestId('blast-radius-error')).toBeInTheDocument();
    });

    // Click retry
    await act(async () => {
      fireEvent.click(screen.getByTestId('blast-radius-retry'));
    });

    // Should now show data
    await waitFor(() => {
      expect(screen.getByTestId('blast-radius-data')).toBeInTheDocument();
    });

    // Blast radius API should have been called at least twice
    const blastCalls = (fetchMock as jest.Mock).mock.calls.filter(
      ([url]: [string]) => url.includes('/blast-radius')
    );
    expect(blastCalls.length).toBeGreaterThanOrEqual(2);
  });

  test('H3-E: Empty state renders for zero resources', async () => {
    mockFetchWith(() =>
      Promise.resolve(new Response(JSON.stringify(EMPTY_BLAST_RADIUS), { status: 200 }))
    );

    await act(async () => { renderDrawer(); });

    await waitFor(() => {
      expect(screen.getByTestId('blast-radius-empty')).toBeInTheDocument();
    });

    expect(screen.getByText(/no resources in scope/i)).toBeInTheDocument();
    // Should NOT show error or skeleton or data
    expect(screen.queryByTestId('blast-radius-error')).not.toBeInTheDocument();
    expect(screen.queryByTestId('blast-radius-skeleton')).not.toBeInTheDocument();
    expect(screen.queryByTestId('blast-radius-data')).not.toBeInTheDocument();
    // Should NOT show retry button
    expect(screen.queryByTestId('blast-radius-retry')).not.toBeInTheDocument();
  });

  test('H3-F: Skeleton visible during slow API, data visible after resolve', async () => {
    jest.useFakeTimers();
    let resolveBlast!: (v: Response) => void;
    mockFetchWith(() => new Promise(resolve => { resolveBlast = resolve; }));

    await act(async () => { renderDrawer(); });

    // Wait for drawer identity to load
    await waitFor(() => {
      expect(screen.getByText('NightlyBot')).toBeInTheDocument();
    });

    // At t=500ms: skeleton should be visible
    act(() => { jest.advanceTimersByTime(500); });
    expect(screen.getByTestId('blast-radius-skeleton')).toBeInTheDocument();
    expect(screen.queryByTestId('blast-radius-data')).not.toBeInTheDocument();

    // Resolve the blast radius API at ~2s
    await act(async () => {
      resolveBlast(new Response(JSON.stringify(VALID_BLAST_RADIUS), { status: 200 }));
    });

    // Data should now be visible
    await waitFor(() => {
      expect(screen.getByTestId('blast-radius-data')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('blast-radius-skeleton')).not.toBeInTheDocument();

    jest.useRealTimers();
  });

  test('H3-G: Other drawer sections unaffected by blast radius error', async () => {
    mockFetchWith(() => Promise.resolve(new Response('', { status: 500 })));

    await act(async () => { renderDrawer(); });

    // Wait for the drawer to fully load
    await waitFor(() => {
      expect(screen.getByText('NightlyBot')).toBeInTheDocument();
    });

    // Agent risk section shows error state
    await waitFor(() => {
      expect(screen.getByTestId('blast-radius-error')).toBeInTheDocument();
    });

    // Other drawer sections still render correctly
    // Header with identity name
    expect(screen.getByText('NightlyBot')).toBeInTheDocument();
    // Tabs still visible
    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Access')).toBeInTheDocument();
    // Agent info grid (from agentInfo, not blast radius) still renders
    expect(screen.getByText('Platform')).toBeInTheDocument();
    expect(screen.getByText('Risk Level')).toBeInTheDocument();
    // Full Detail link still works
    expect(screen.getByText('Full Detail')).toBeInTheDocument();
    // Close button still present
    expect(screen.getByText('\u00D7')).toBeInTheDocument();
  });
});
