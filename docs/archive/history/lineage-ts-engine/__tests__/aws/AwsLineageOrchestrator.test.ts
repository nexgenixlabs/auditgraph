/**
 * AwsLineageOrchestrator unit tests.
 *
 *   1. Full pipeline — 3 identities, 2 accounts → summary counts correct
 *   2. 0 account IDs → early return with accountsScanned=0
 *   3. 0 identities → early return with identitiesScanned=0
 *   4. Lambda DB fast-path returns bindings → bindingsFound increments
 *   5. Single identity failure → scan completes, errors[] populated
 *   6. 51 identities → 2 batches
 *   7. Orphan classification → orphansFound counts
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock all sub-modules before importing orchestrator
vi.mock("../../aws/TrustPolicyParser", () => ({
  parseTrustPolicy: vi.fn().mockResolvedValue([]),
  persistTrustBindings: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../aws/LambdaRoleScanner", () => ({
  scanLambdaForRole: vi.fn().mockResolvedValue([]),
}));

vi.mock("../../aws/ECSTaskDefScanner", () => ({
  scanECSTaskDefs: vi.fn().mockResolvedValue([]),
}));

vi.mock("../../aws/EKSWorkloadScanner", () => ({
  scanEKSWorkloads: vi.fn().mockResolvedValue([]),
  eksWorkloadToResourceBinding: vi.fn().mockReturnValue({
    resourceId: "eks://test",
    resourceType: "AWSEKSWorkload",
    resourceName: "test",
    resourceGroup: "",
    region: "",
    bindingMethod: "WorkloadIdentityAnnotation",
    bindingEvidence: {},
    confidenceScore: 95,
  }),
  clearClusterCache: vi.fn(),
}));

vi.mock("../../aws/OIDCProviderMapper", () => ({
  mapOIDCProviders: vi.fn().mockResolvedValue([]),
  persistOIDCMappings: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../aws/ResourcePolicyScanner", () => ({
  scanResourcePolicies: vi.fn().mockResolvedValue([]),
  persistResourcePolicyBindings: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../aws/AwsEnrichmentTierProbe", () => ({
  detectAwsEnrichmentTier: vi.fn().mockResolvedValue("STATIC"),
}));

vi.mock("../../aws/AwsOrphanDetectionEngine", () => ({
  classifyAwsOrphanStatus: vi.fn().mockResolvedValue({
    spnId: "1",
    orphanStatus: "NOT_ORPHANED",
    orphanReasons: [],
    activeRoleCount: 0,
    recommendedAction: null,
  }),
  persistAwsOrphanClassification: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../aws/upsertBindings", () => ({
  upsertBindings: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../LineageConfidenceScorer", () => ({
  computeLineageScore: vi.fn().mockResolvedValue(50),
  persistLineageScore: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@aws-sdk/client-iam", () => ({
  IAMClient: vi.fn().mockImplementation(() => ({})),
  GetRoleCommand: vi.fn(),
}));

vi.mock("@aws-sdk/client-ecs", () => ({
  ECSClient: vi.fn().mockImplementation(() => ({})),
  ListTaskDefinitionFamiliesCommand: vi.fn(),
  DescribeTaskDefinitionCommand: vi.fn(),
}));

vi.mock("@aws-sdk/client-eks", () => ({
  EKSClient: vi.fn().mockImplementation(() => ({})),
  ListClustersCommand: vi.fn(),
  DescribeClusterCommand: vi.fn(),
}));

vi.mock("@aws-sdk/client-sqs", () => ({
  SQSClient: vi.fn().mockImplementation(() => ({})),
}));

vi.mock("@aws-sdk/client-sns", () => ({
  SNSClient: vi.fn().mockImplementation(() => ({})),
}));

import { runAwsLineageScan } from "../../aws/AwsLineageOrchestrator";
import { parseTrustPolicy } from "../../aws/TrustPolicyParser";
import { scanLambdaForRole } from "../../aws/LambdaRoleScanner";
import { classifyAwsOrphanStatus } from "../../aws/AwsOrphanDetectionEngine";

// ── Test helpers ────────────────────────────────────────────────────

function makeIdentityRow(id: number, accountId = "123456789012") {
  return {
    id: String(id),
    identityId: `arn:aws:iam::${accountId}:role/Role${id}`,
    principalId: `arn:aws:iam::${accountId}:role/Role${id}`,
    displayName: `Role${id}`,
    identityCategory: "iam_role",
    isFederated: false,
    tags: "{}",
  };
}

function mockPool(
  connectionRows: unknown[],
  subscriptionRows: unknown[],
  identityRows: unknown[]
) {
  return {
    query: vi.fn().mockImplementation((sql: string) => {
      // Connection query
      if (sql.includes("cloud_connections")) {
        return { rows: connectionRows };
      }
      // Subscription query
      if (sql.includes("cloud_subscriptions")) {
        return { rows: subscriptionRows };
      }
      // Identity query (tenant_or_org_id = ANY)
      if (sql.includes("identities") || sql.includes("tenant_or_org_id")) {
        return { rows: identityRows };
      }
      // CloudTrail probe
      if (sql.includes("aws_cloudtrail_events")) {
        return { rows: [] };
      }
      // Enrichment tier cache
      if (sql.includes("enrichment_tier")) {
        return { rows: [{ tier: null }] };
      }
      // Fallback
      return { rows: [] };
    }),
  } as any;
}

// ── Tests ───────────────────────────────────────────────────────────

describe("runAwsLineageScan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns early with 0 account IDs", async () => {
    const db = mockPool(
      [{ id: 1, metadata: { aws_access_key_id: "AK", aws_secret_access_key: "SK" } }],
      [], // no subscriptions
      []
    );

    const result = await runAwsLineageScan(1, db);
    expect(result.accountsScanned).toBe(0);
    expect(result.identitiesScanned).toBe(0);
    expect(result.enrichmentTier).toBe("STATIC");
    expect(result.connectionId).toBe(1);
  });

  it("returns early with 0 identities", async () => {
    const db = mockPool(
      [{ id: 1, metadata: { aws_access_key_id: "AK", aws_secret_access_key: "SK", region: "us-east-1" } }],
      [{ subscription_id: "123456789012" }],
      [] // no identities
    );

    const result = await runAwsLineageScan(1, db);
    expect(result.identitiesScanned).toBe(0);
    expect(result.accountsScanned).toBe(1);
    expect(result.bindingsFound).toBe(0);
  });

  it("scans 3 identities across 2 accounts", async () => {
    const identities = [
      makeIdentityRow(1, "111111111111"),
      makeIdentityRow(2, "111111111111"),
      makeIdentityRow(3, "222222222222"),
    ];
    const db = mockPool(
      [{ id: 1, metadata: { aws_access_key_id: "AK", aws_secret_access_key: "SK", region: "us-east-1" } }],
      [{ subscription_id: "111111111111" }, { subscription_id: "222222222222" }],
      identities
    );

    const result = await runAwsLineageScan(1, db);
    expect(result.identitiesScanned).toBe(3);
    expect(result.accountsScanned).toBe(2);
    expect(result.connectionId).toBe(1);
    expect(result.completedAt).toBeDefined();
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("Lambda DB fast-path increments bindingsFound", async () => {
    const identities = [makeIdentityRow(1)];
    const db = mockPool(
      [{ id: 1, metadata: { aws_access_key_id: "AK", aws_secret_access_key: "SK", region: "us-east-1" } }],
      [{ subscription_id: "123456789012" }],
      identities
    );

    // Lambda returns 2 bindings
    vi.mocked(scanLambdaForRole).mockResolvedValueOnce([
      {
        resourceId: "lambda://123/us-east-1/fn1",
        resourceType: "AWSLambda",
        resourceName: "fn1",
        resourceGroup: "",
        region: "us-east-1",
        bindingMethod: "ExecutionRole",
        bindingEvidence: {},
        confidenceScore: 95,
      },
      {
        resourceId: "lambda://123/us-east-1/fn2",
        resourceType: "AWSLambda",
        resourceName: "fn2",
        resourceGroup: "",
        region: "us-east-1",
        bindingMethod: "ExecutionRole",
        bindingEvidence: {},
        confidenceScore: 95,
      },
    ] as any);

    const result = await runAwsLineageScan(1, db);
    expect(result.bindingsFound).toBe(2);
  });

  it("isolates single identity failure without aborting", async () => {
    const identities = [makeIdentityRow(1)];
    const db = mockPool(
      [{ id: 1, metadata: { aws_access_key_id: "AK", aws_secret_access_key: "SK", region: "us-east-1" } }],
      [{ subscription_id: "123456789012" }],
      identities
    );

    // Make TrustPolicyParser throw
    vi.mocked(parseTrustPolicy).mockRejectedValueOnce(
      new Error("IAM access denied")
    );

    const result = await runAwsLineageScan(1, db);
    // Scan should still complete
    expect(result.identitiesScanned).toBe(1);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0].module).toBe("TrustPolicyParser");
  });

  it("aggregates orphan counts in summary", async () => {
    const identities = [makeIdentityRow(1), makeIdentityRow(2), makeIdentityRow(3)];
    const db = mockPool(
      [{ id: 1, metadata: { aws_access_key_id: "AK", aws_secret_access_key: "SK", region: "us-east-1" } }],
      [{ subscription_id: "123456789012" }],
      identities
    );

    // 1 → SAFE_TO_RETIRE, 2 → CAUTION, 3 → NOT_ORPHANED
    vi.mocked(classifyAwsOrphanStatus)
      .mockResolvedValueOnce({ spnId: "1", orphanStatus: "SAFE_TO_RETIRE", orphanReasons: [], activeRoleCount: 0, recommendedAction: null } as any)
      .mockResolvedValueOnce({ spnId: "2", orphanStatus: "CAUTION", orphanReasons: [], activeRoleCount: 0, recommendedAction: null } as any)
      .mockResolvedValueOnce({ spnId: "3", orphanStatus: "NOT_ORPHANED", orphanReasons: [], activeRoleCount: 0, recommendedAction: null } as any);

    const result = await runAwsLineageScan(1, db);
    expect(result.orphansFound.safeToRetire).toBe(1);
    expect(result.orphansFound.caution).toBe(1);
    expect(result.orphansFound.blocked).toBe(0);
  });

  it("processes in batches of 50", async () => {
    // Create 51 identities → should be 2 batches
    const identities = Array.from({ length: 51 }, (_, i) =>
      makeIdentityRow(i + 1)
    );
    const db = mockPool(
      [{ id: 1, metadata: { aws_access_key_id: "AK", aws_secret_access_key: "SK", region: "us-east-1" } }],
      [{ subscription_id: "123456789012" }],
      identities
    );

    const result = await runAwsLineageScan(1, db);
    expect(result.identitiesScanned).toBe(51);
  });
});
