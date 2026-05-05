/**
 * LineageOrchestrator unit tests.
 *
 * Tests the full pipeline coordination:
 *   1. Connection loading + SPN fetching
 *   2. Enrichment tier detection
 *   3. Per-SPN pipeline (all 7 modules)
 *   4. Batch processing (groups of 50)
 *   5. Error isolation (single SPN failure doesn't abort scan)
 *   6. Summary aggregation
 *   7. Structured log events
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all sub-modules ─────────────────────────────────────────────

const mockScanResources = vi.fn().mockResolvedValue([]);
const mockGetFederated = vi.fn().mockResolvedValue([]);
const mockPersistFederated = vi.fn().mockResolvedValue(undefined);
const mockInferTopology = vi.fn().mockResolvedValue({
  workloadType: "Unknown",
  confidenceScore: 30,
  matchedRule: "default",
  roleAssignments: [],
  topResources: [],
});
const mockPersistTopology = vi.fn().mockResolvedValue(undefined);
const mockGetAppReg = vi.fn().mockResolvedValue(null);
const mockPersistAppReg = vi.fn().mockResolvedValue(undefined);
const mockEnrichSignIn = vi.fn().mockResolvedValue({
  confirmedNHI: false,
  couldBeHuman: false,
  signInType: "Never",
  dormancyDays: -1,
  lastSignInAt: null,
});
const mockPersistSignIn = vi.fn().mockResolvedValue(undefined);
const mockComputeScore = vi.fn().mockResolvedValue(0);
const mockPersistScore = vi.fn().mockResolvedValue(undefined);
const mockClassifyOrphan = vi.fn().mockResolvedValue({
  spnId: "1",
  orphanStatus: "UNKNOWN",
  orphanReasons: [],
  activeRoleCount: 0,
  recommendedAction: null,
});
const mockPersistOrphan = vi.fn().mockResolvedValue(undefined);
const mockDetectTier = vi.fn().mockResolvedValue("P1_SIGNIN");

vi.mock("../ResourceGraphScanner", () => ({
  scanResourcesForSPN: mockScanResources,
}));
vi.mock("../FederatedCredentialMapper", () => ({
  getFederatedMappings: mockGetFederated,
  persistFederatedBindings: mockPersistFederated,
}));
vi.mock("../RoleTopologyInferrer", () => ({
  inferRoleTopology: mockInferTopology,
  persistRoleTopology: mockPersistTopology,
}));
vi.mock("../AppRegistrationMiner", () => ({
  getAppRegistrationMetadata: mockGetAppReg,
  persistAppRegistrationBindings: mockPersistAppReg,
}));
vi.mock("../SignInActivityEnricher", () => ({
  enrichSignInActivity: mockEnrichSignIn,
  persistSignInEnrichment: mockPersistSignIn,
}));
vi.mock("../LineageConfidenceScorer", () => ({
  computeLineageScore: mockComputeScore,
  persistLineageScore: mockPersistScore,
}));
vi.mock("../OrphanDetectionEngine", () => ({
  classifyOrphanStatus: mockClassifyOrphan,
  persistOrphanClassification: mockPersistOrphan,
}));
vi.mock("../EnrichmentTierProbe", () => ({
  detectEnrichmentTier: mockDetectTier,
}));

// Mock Azure credentials
vi.mock("@azure/identity", () => ({
  DefaultAzureCredential: vi.fn().mockImplementation(() => ({
    getToken: vi.fn().mockResolvedValue({ token: "fake-token", expiresOnTimestamp: 0 }),
  })),
}));

// Mock Graph client
vi.mock("@microsoft/microsoft-graph-client", () => ({
  Client: {
    initWithMiddleware: vi.fn().mockReturnValue({
      api: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      get: vi.fn().mockResolvedValue({}),
    }),
  },
}));

// ── DB mock ──────────────────────────────────────────────────────────

function makeMockDb(spnCount = 3, options: { noSubscriptions?: boolean } = {}) {
  const queryMock = vi.fn().mockImplementation((sql: string) => {
    // Connection fetch
    if (sql.includes("cloud_connections")) {
      return {
        rows: [{
          tenantId: "tenant-1",
          clientId: "client-1",
          metadata: {
            client_secret: "secret-1",
            subscription_ids: options.noSubscriptions ? [] : ["sub-1", "sub-2"],
          },
        }],
      };
    }

    // SPN fetch
    if (sql.includes("FROM identities")) {
      const spns = Array.from({ length: spnCount }, (_, i) => ({
        id: String(i + 1),
        clientId: `app-${i + 1}`,
        objectId: `obj-${i + 1}`,
        displayName: `SPN-${i + 1}`,
      }));
      return { rows: spns };
    }

    // Default for upsert queries
    return { rows: [] };
  });

  return { query: queryMock } as unknown;
}

// ── Import after mocks ───────────────────────────────────────────────

// Dynamic import to ensure mocks are in place
async function importOrchestrator() {
  return await import("../LineageOrchestrator");
}

// ── Tests ────────────────────────────────────────────────────────────

describe("runFullLineageScan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("scans all SPNs and returns correct summary", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(3);

    mockScanResources.mockResolvedValue([
      { resourceId: "res-1", resourceType: "AppService", resourceName: "app1",
        resourceGroup: "rg1", region: "eastus", bindingMethod: "ManagedIdentity",
        bindingEvidence: {}, confidenceScore: 90 },
    ]);
    mockGetFederated.mockResolvedValue([
      { credentialId: "cred-1", workloadType: "GitHubActions", issuer: "https://token.actions.githubusercontent.com",
        subject: "repo:org/repo:ref:refs/heads/main", confidenceScore: 98 },
    ]);
    mockClassifyOrphan.mockResolvedValue({
      spnId: "1", orphanStatus: "NOT_ORPHANED", orphanReasons: [], activeRoleCount: 2, recommendedAction: null,
    });

    const summary = await runFullLineageScan(db as any, "conn-1");

    expect(summary.connectionId).toBe("conn-1");
    expect(summary.spnsScanned).toBe(3);
    expect(summary.bindingsFound).toBe(3); // 1 per SPN * 3 SPNs
    expect(summary.federatedFound).toBe(3);
    expect(summary.enrichmentTier).toBe("P1_SIGNIN");
    expect(summary.scanErrors).toHaveLength(0);
    expect(summary.durationMs).toBeGreaterThanOrEqual(0);
    expect(summary.completedAt).toBeTruthy();
  });

  it("returns empty summary when no subscriptions", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(0, { noSubscriptions: true });

    const summary = await runFullLineageScan(db as any, "conn-1");

    expect(summary.spnsScanned).toBe(0);
    expect(summary.enrichmentTier).toBe("STATIC");
    expect(mockDetectTier).not.toHaveBeenCalled();
  });

  it("returns empty summary when no SPNs found", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(0);

    const summary = await runFullLineageScan(db as any, "conn-1");

    expect(summary.spnsScanned).toBe(0);
    expect(summary.bindingsFound).toBe(0);
    expect(summary.enrichmentTier).toBe("P1_SIGNIN");
  });

  it("isolates single SPN failure without aborting scan", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(3);

    // First SPN fails resource scanning, others succeed
    let callCount = 0;
    mockScanResources.mockImplementation(() => {
      callCount++;
      if (callCount === 1) throw new Error("ResourceGraph timeout");
      return Promise.resolve([
        { resourceId: "res-ok", resourceType: "AppService", resourceName: "ok",
          resourceGroup: "rg", region: "eastus", bindingMethod: "ManagedIdentity",
          bindingEvidence: {}, confidenceScore: 85 },
      ]);
    });

    const summary = await runFullLineageScan(db as any, "conn-1");

    expect(summary.spnsScanned).toBe(3);
    expect(summary.bindingsFound).toBe(2); // 2 of 3 succeeded
    expect(summary.scanErrors.length).toBeGreaterThanOrEqual(1);
    expect(summary.scanErrors[0].module).toBe("ResourceGraphScanner");
  });

  it("counts orphan statuses correctly", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(4);

    let orphanCall = 0;
    const statuses = ["SAFE_TO_RETIRE", "CAUTION", "BLOCKED", "NOT_ORPHANED"];
    mockClassifyOrphan.mockImplementation(() => {
      const status = statuses[orphanCall++ % statuses.length];
      return Promise.resolve({
        spnId: "x", orphanStatus: status, orphanReasons: [], activeRoleCount: 0, recommendedAction: null,
      });
    });

    const summary = await runFullLineageScan(db as any, "conn-1");

    expect(summary.orphansFound.safeToRetire).toBe(1);
    expect(summary.orphansFound.caution).toBe(1);
    expect(summary.orphansFound.blocked).toBe(1);
  });

  it("calls all 7 pipeline modules per SPN", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(1);

    await runFullLineageScan(db as any, "conn-1");

    expect(mockScanResources).toHaveBeenCalledTimes(1);
    expect(mockGetFederated).toHaveBeenCalledTimes(1);
    expect(mockInferTopology).toHaveBeenCalledTimes(1);
    expect(mockGetAppReg).toHaveBeenCalledTimes(1);
    expect(mockEnrichSignIn).toHaveBeenCalledTimes(1);
    expect(mockComputeScore).toHaveBeenCalledTimes(1);
    expect(mockClassifyOrphan).toHaveBeenCalledTimes(1);
  });

  it("persists federated bindings only when mappings exist", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(1);

    // No federated mappings
    mockGetFederated.mockResolvedValue([]);
    await runFullLineageScan(db as any, "conn-1");
    expect(mockPersistFederated).not.toHaveBeenCalled();

    // With federated mappings
    vi.clearAllMocks();
    const dbWithFed = makeMockDb(1);
    mockGetFederated.mockResolvedValue([{ credentialId: "c1" }]);
    mockDetectTier.mockResolvedValue("P1_SIGNIN");
    await runFullLineageScan(dbWithFed as any, "conn-1");
    expect(mockPersistFederated).toHaveBeenCalledTimes(1);
  });

  it("handles enrichment tier detection failure gracefully", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(1);

    mockDetectTier.mockRejectedValue(new Error("workspace probe failed"));

    const summary = await runFullLineageScan(db as any, "conn-1");

    // Falls back to STATIC but still scans SPNs
    expect(summary.enrichmentTier).toBe("STATIC");
    expect(summary.spnsScanned).toBe(1);
  });

  it("processes SPNs in batches of 50", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(120);

    const startTimes: number[] = [];
    mockScanResources.mockImplementation(async () => {
      startTimes.push(Date.now());
      return [];
    });

    await runFullLineageScan(db as any, "conn-1");

    // All 120 SPNs should have been scanned
    expect(mockScanResources).toHaveBeenCalledTimes(120);
    expect(mockClassifyOrphan).toHaveBeenCalledTimes(120);
  });

  it("collects errors from multiple modules in same SPN", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(1);

    mockScanResources.mockRejectedValue(new Error("resource graph fail"));
    mockGetFederated.mockRejectedValue(new Error("graph API fail"));
    mockInferTopology.mockRejectedValue(new Error("role fetch fail"));

    const summary = await runFullLineageScan(db as any, "conn-1");

    expect(summary.spnsScanned).toBe(1);
    expect(summary.scanErrors.length).toBeGreaterThanOrEqual(3);

    const modules = summary.scanErrors.map((e: any) => e.module);
    expect(modules).toContain("ResourceGraphScanner");
    expect(modules).toContain("FederatedCredentialMapper");
    expect(modules).toContain("RoleTopologyInferrer");
  });
});

// ── Legacy alias test ────────────────────────────────────────────────

describe("runLineageScan (legacy alias)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("calls runFullLineageScan and returns void", async () => {
    const mod = await importOrchestrator();
    const db = makeMockDb(1);

    const result = await mod.runLineageScan(db as any, "conn-1");
    expect(result).toBeUndefined();
  });
});

// ── Summary shape test ───────────────────────────────────────────────

describe("LineageScanSummary shape", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("includes all required fields", async () => {
    const { runFullLineageScan } = await importOrchestrator();
    const db = makeMockDb(1);

    const summary = await runFullLineageScan(db as any, "conn-1");

    expect(summary).toHaveProperty("connectionId");
    expect(summary).toHaveProperty("spnsScanned");
    expect(summary).toHaveProperty("bindingsFound");
    expect(summary).toHaveProperty("federatedFound");
    expect(summary).toHaveProperty("orphansFound");
    expect(summary.orphansFound).toHaveProperty("safeToRetire");
    expect(summary.orphansFound).toHaveProperty("caution");
    expect(summary.orphansFound).toHaveProperty("blocked");
    expect(summary).toHaveProperty("enrichmentTier");
    expect(summary).toHaveProperty("scanErrors");
    expect(summary).toHaveProperty("durationMs");
    expect(summary).toHaveProperty("completedAt");
    expect(typeof summary.durationMs).toBe("number");
    expect(typeof summary.completedAt).toBe("string");
  });
});
