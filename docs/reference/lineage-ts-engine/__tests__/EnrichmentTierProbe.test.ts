/**
 * EnrichmentTierProbe unit tests.
 *
 *   1. No workspaces → STATIC
 *   2. Workspace found + KQL returns data → FULL
 *   3. Workspace found + KQL returns empty → P1_SIGNIN
 *   4. Workspace found + KQL errors → P1_SIGNIN
 *   5. Cached tier returned without probing
 *   6. Cache invalidation
 *   7. Empty subscriptionId → STATIC
 *   8. Cached FULL tier returned
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  detectEnrichmentTier,
  invalidateTierCache,
} from "../EnrichmentTierProbe";

// ── Mock fetch ──────────────────────────────────────────────────────

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// ── Mock DB pool ────────────────────────────────────────────────────

function mockDb(cachedTier: string | null = null) {
  const queryMock = vi.fn().mockImplementation((sql: string) => {
    if (sql.includes("metadata->'enrichment_tier'")) {
      return { rows: cachedTier ? [{ tier: cachedTier }] : [{ tier: null }] };
    }
    if (sql.includes("UPDATE cloud_connections")) {
      return { rows: [] };
    }
    return { rows: [] };
  });
  return { query: queryMock };
}

// ── Mock credential ─────────────────────────────────────────────────

const credential = {
  getToken: vi.fn().mockResolvedValue({ token: "fake-token", expiresOnTimestamp: 0 }),
};

// ── Helper: mock fetch for workspace + query ────────────────────────

function mockWorkspaceFetch(hasWorkspace: boolean, kqlHasData: boolean | null) {
  mockFetch.mockImplementation((url: string) => {
    if (url.includes("Microsoft.OperationalInsights/workspaces")) {
      return Promise.resolve({
        ok: hasWorkspace,
        status: hasWorkspace ? 200 : 404,
        json: () => Promise.resolve(
          hasWorkspace
            ? { value: [{ id: "ws-1", name: "my-workspace", properties: { customerId: "ws-cust-1" } }] }
            : { value: [] }
        ),
      });
    }
    if (url.includes("api.loganalytics.io")) {
      if (kqlHasData === null) {
        return Promise.resolve({ ok: false, status: 500 });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          tables: [{ rows: kqlHasData ? [["some-data"]] : [] }],
        }),
      });
    }
    return Promise.resolve({ ok: false, status: 404 });
  });
}

// ── Tests ───────────────────────────────────────────────────────────

describe("detectEnrichmentTier", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns STATIC when no workspaces exist", async () => {
    const db = mockDb();
    mockWorkspaceFetch(false, null);

    const tier = await detectEnrichmentTier(db as any, "conn-1", "sub-1", credential as any);

    expect(tier).toBe("STATIC");
  });

  it("returns FULL when workspace has sign-in log data", async () => {
    const db = mockDb();
    mockWorkspaceFetch(true, true);

    const tier = await detectEnrichmentTier(db as any, "conn-1", "sub-1", credential as any);

    expect(tier).toBe("FULL");
  });

  it("returns P1_SIGNIN when workspace exists but KQL returns empty", async () => {
    const db = mockDb();
    mockWorkspaceFetch(true, false);

    const tier = await detectEnrichmentTier(db as any, "conn-1", "sub-1", credential as any);

    expect(tier).toBe("P1_SIGNIN");
  });

  it("returns P1_SIGNIN when KQL query errors", async () => {
    const db = mockDb();
    mockWorkspaceFetch(true, null);

    const tier = await detectEnrichmentTier(db as any, "conn-1", "sub-1", credential as any);

    expect(tier).toBe("P1_SIGNIN");
  });

  it("returns cached tier without probing", async () => {
    const db = mockDb("P2_AUDIT");

    const tier = await detectEnrichmentTier(db as any, "conn-1", "sub-1", credential as any);

    expect(tier).toBe("P2_AUDIT");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("caches FULL tier in cloud_connections.metadata", async () => {
    const db = mockDb();
    mockWorkspaceFetch(true, true);

    await detectEnrichmentTier(db as any, "conn-1", "sub-1", credential as any);

    const updateCall = db.query.mock.calls.find(
      (c: string[]) => c[0].includes("UPDATE cloud_connections")
    );
    expect(updateCall).toBeDefined();
    expect(updateCall![1]).toContain("FULL");
  });

  it("returns STATIC when subscriptionId is empty", async () => {
    const db = mockDb();

    const tier = await detectEnrichmentTier(db as any, "conn-1", "", credential as any);

    expect(tier).toBe("STATIC");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("returns cached FULL tier without probing", async () => {
    const db = mockDb("FULL");

    const tier = await detectEnrichmentTier(db as any, "conn-1", "sub-1", credential as any);

    expect(tier).toBe("FULL");
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe("invalidateTierCache", () => {
  it("removes enrichment_tier from metadata", async () => {
    const db = mockDb();

    await invalidateTierCache(db as any, "conn-1");

    const removeCall = db.query.mock.calls.find(
      (c: string[]) => c[0].includes("metadata - 'enrichment_tier'")
    );
    expect(removeCall).toBeDefined();
  });
});
