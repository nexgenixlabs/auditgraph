/**
 * AwsOrphanDetectionEngine unit tests.
 *
 *   1. No bindings + lastAssumedDays 120 + no CloudTrail → SAFE_TO_RETIRE
 *   2. Lambda binding exists → NOT_ORPHANED
 *   3. No bindings but CloudTrail activity in last 90d → NOT_ORPHANED
 *   4. No bindings + write policies → CAUTION
 *   5. lastAssumedDays 10 → NOT_ORPHANED
 *   6. Role never used (lastAssumedDays -1) + no bindings + no CloudTrail → UNKNOWN
 *   7. crossCloudReferenced → BLOCKED
 *   8. classifyFromSignals pure function tests
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@aws-sdk/client-iam", () => ({
  IAMClient: vi.fn(),
  GetRoleCommand: vi.fn().mockImplementation((input: any) => ({
    constructor: { name: "GetRoleCommand" },
    input,
  })),
}));

import {
  classifyAwsOrphanStatus,
  classifyFromSignals,
  gatherAwsOrphanSignals,
} from "../../aws/AwsOrphanDetectionEngine";

const ROLE_ARN = "arn:aws:iam::123456789012:role/TestRole";
const IDENTITY_ID = "42";

// ── Mock helpers ──────────────────────────────────────────────────

interface MockPoolSetup {
  /** Rows for binding existence checks (returns row or not) */
  bindingTypes: Record<string, boolean>;
  /** CloudTrail count in last 90 days */
  cloudTrailCount: number;
  /** Trust binding evidence for write-policy check */
  trustEvidence?: unknown[];
}

function mockPool(setup: MockPoolSetup) {
  return {
    query: vi.fn().mockImplementation((sql: string, params?: unknown[]) => {
      // Binding existence checks
      if (sql.includes("identity_lineage_bindings") && sql.includes("LIMIT 1")) {
        // Determine which type is being checked
        if (sql.includes("AWSTrustPolicy")) {
          return { rows: setup.bindingTypes["AWSTrustPolicy"] ? [{ x: 1 }] : [] };
        }
        if (sql.includes("AWSLambda")) {
          return { rows: setup.bindingTypes["AWSLambda"] ? [{ x: 1 }] : [] };
        }
        if (sql.includes("AWSECSTask")) {
          return { rows: setup.bindingTypes["AWSECSTask"] ? [{ x: 1 }] : [] };
        }
        if (sql.includes("AWSEKSWorkload")) {
          return { rows: setup.bindingTypes["AWSEKSWorkload"] ? [{ x: 1 }] : [] };
        }
        if (sql.includes("OIDC")) {
          return { rows: setup.bindingTypes["OIDC"] ? [{ x: 1 }] : [] };
        }
        if (sql.includes("S3Bucket") || sql.includes("SQSQueue")) {
          return { rows: setup.bindingTypes["ResourcePolicy"] ? [{ x: 1 }] : [] };
        }
        return { rows: [] };
      }

      // CloudTrail count
      if (sql.includes("aws_cloudtrail_events")) {
        return { rows: [{ cnt: setup.cloudTrailCount }] };
      }

      // Write policy check (trust binding evidence)
      if (sql.includes("identity_lineage_bindings") && sql.includes("LIMIT 5")) {
        return {
          rows: (setup.trustEvidence ?? []).map((e) => ({
            binding_evidence: e,
          })),
        };
      }

      return { rows: [] };
    }),
  } as any;
}

function mockIAMClient(lastUsedDate: Date | null) {
  return {
    send: vi.fn().mockImplementation(() => ({
      Role: {
        RoleLastUsed: lastUsedDate
          ? { LastUsedDate: lastUsedDate }
          : {},
      },
    })),
  } as any;
}

function daysAgo(days: number): Date {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000);
}

// ── classifyFromSignals tests ───────────────────────────────────────

describe("classifyFromSignals", () => {
  it("returns NOT_ORPHANED when any binding exists", () => {
    const result = classifyFromSignals({
      noTrustPolicyBinding: false,
      noLambdaBinding: true,
      noECSBinding: true,
      noEKSBinding: true,
      noOIDCBinding: true,
      noResourcePolicyRef: true,
      lastAssumedDays: 120,
      recentCloudTrailActivity: 0,
      hasWritePolicies: false,
      crossCloudReferenced: false,
    });
    expect(result.status).toBe("NOT_ORPHANED");
  });

  it("returns NOT_ORPHANED when CloudTrail activity exists", () => {
    const result = classifyFromSignals({
      noTrustPolicyBinding: true,
      noLambdaBinding: true,
      noECSBinding: true,
      noEKSBinding: true,
      noOIDCBinding: true,
      noResourcePolicyRef: true,
      lastAssumedDays: 120,
      recentCloudTrailActivity: 5,
      hasWritePolicies: false,
      crossCloudReferenced: false,
    });
    expect(result.status).toBe("NOT_ORPHANED");
  });

  it("returns NOT_ORPHANED when lastAssumedDays < 30", () => {
    const result = classifyFromSignals({
      noTrustPolicyBinding: true,
      noLambdaBinding: true,
      noECSBinding: true,
      noEKSBinding: true,
      noOIDCBinding: true,
      noResourcePolicyRef: true,
      lastAssumedDays: 10,
      recentCloudTrailActivity: 0,
      hasWritePolicies: false,
      crossCloudReferenced: false,
    });
    expect(result.status).toBe("NOT_ORPHANED");
  });

  it("returns SAFE_TO_RETIRE when all bindings missing + dormant 90d+", () => {
    const result = classifyFromSignals({
      noTrustPolicyBinding: true,
      noLambdaBinding: true,
      noECSBinding: true,
      noEKSBinding: true,
      noOIDCBinding: true,
      noResourcePolicyRef: true,
      lastAssumedDays: 120,
      recentCloudTrailActivity: 0,
      hasWritePolicies: false,
      crossCloudReferenced: false,
    });
    expect(result.status).toBe("SAFE_TO_RETIRE");
    expect(result.recommendedAction).toContain("Safe to disable");
  });

  it("returns CAUTION when no bindings + dormant + write policies", () => {
    const result = classifyFromSignals({
      noTrustPolicyBinding: true,
      noLambdaBinding: true,
      noECSBinding: true,
      noEKSBinding: true,
      noOIDCBinding: true,
      noResourcePolicyRef: true,
      lastAssumedDays: 120,
      recentCloudTrailActivity: 0,
      hasWritePolicies: true,
      crossCloudReferenced: false,
    });
    expect(result.status).toBe("CAUTION");
    expect(result.recommendedAction).toContain("write permissions");
  });

  it("returns BLOCKED when crossCloudReferenced", () => {
    const result = classifyFromSignals({
      noTrustPolicyBinding: true,
      noLambdaBinding: true,
      noECSBinding: true,
      noEKSBinding: true,
      noOIDCBinding: true,
      noResourcePolicyRef: true,
      lastAssumedDays: 120,
      recentCloudTrailActivity: 0,
      hasWritePolicies: false,
      crossCloudReferenced: true,
    });
    expect(result.status).toBe("BLOCKED");
  });

  it("returns UNKNOWN when never used + all bindings missing + no CloudTrail", () => {
    const result = classifyFromSignals({
      noTrustPolicyBinding: true,
      noLambdaBinding: true,
      noECSBinding: true,
      noEKSBinding: true,
      noOIDCBinding: true,
      noResourcePolicyRef: true,
      lastAssumedDays: -1,
      recentCloudTrailActivity: 0,
      hasWritePolicies: false,
      crossCloudReferenced: false,
    });
    expect(result.status).toBe("UNKNOWN");
  });
});

// ── classifyAwsOrphanStatus integration tests ────────────────────

describe("classifyAwsOrphanStatus", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("SAFE_TO_RETIRE: no bindings + 120d dormant + no CloudTrail", async () => {
    const db = mockPool({
      bindingTypes: {},
      cloudTrailCount: 0,
    });
    const iam = mockIAMClient(daysAgo(120));

    const result = await classifyAwsOrphanStatus(
      IDENTITY_ID,
      ROLE_ARN,
      db,
      iam
    );

    expect(result.orphanStatus).toBe("SAFE_TO_RETIRE");
    expect(result.spnId).toBe(IDENTITY_ID);
  });

  it("NOT_ORPHANED: Lambda binding exists", async () => {
    const db = mockPool({
      bindingTypes: { AWSLambda: true },
      cloudTrailCount: 0,
    });
    const iam = mockIAMClient(daysAgo(120));

    const result = await classifyAwsOrphanStatus(
      IDENTITY_ID,
      ROLE_ARN,
      db,
      iam
    );

    expect(result.orphanStatus).toBe("NOT_ORPHANED");
  });

  it("NOT_ORPHANED: CloudTrail activity in last 90d", async () => {
    const db = mockPool({
      bindingTypes: {},
      cloudTrailCount: 15,
    });
    const iam = mockIAMClient(daysAgo(120));

    const result = await classifyAwsOrphanStatus(
      IDENTITY_ID,
      ROLE_ARN,
      db,
      iam
    );

    expect(result.orphanStatus).toBe("NOT_ORPHANED");
  });

  it("CAUTION: no bindings + dormant + write policies", async () => {
    const db = mockPool({
      bindingTypes: {},
      cloudTrailCount: 0,
      trustEvidence: [{ trustType: "WildcardTrust" }],
    });
    const iam = mockIAMClient(daysAgo(120));

    const result = await classifyAwsOrphanStatus(
      IDENTITY_ID,
      ROLE_ARN,
      db,
      iam
    );

    expect(result.orphanStatus).toBe("CAUTION");
  });

  it("NOT_ORPHANED: lastAssumedDays = 10", async () => {
    const db = mockPool({
      bindingTypes: {},
      cloudTrailCount: 0,
    });
    const iam = mockIAMClient(daysAgo(10));

    const result = await classifyAwsOrphanStatus(
      IDENTITY_ID,
      ROLE_ARN,
      db,
      iam
    );

    expect(result.orphanStatus).toBe("NOT_ORPHANED");
  });
});
