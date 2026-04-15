/**
 * EKSWorkloadScanner unit tests.
 *
 *   1. SA with matching annotation → binding returned
 *   2. SA without annotation → not returned
 *   3. Cluster 403 → skipped, no error thrown
 *   4. Multiple clusters, one match → only matching cluster returned
 *   5. No clusters → []
 *   6. Cluster without OIDC issuer → skipped
 *   7. Empty roleArn → []
 *   8. eksWorkloadToResourceBinding → correct resource_id format
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock @smithy/signature-v4 before importing the scanner
vi.mock("@smithy/signature-v4", () => ({
  SignatureV4: vi.fn().mockImplementation(() => ({
    presign: vi.fn().mockResolvedValue({
      protocol: "https:",
      hostname: "sts.us-east-1.amazonaws.com",
      path: "/",
      query: { Action: "GetCallerIdentity", "X-Amz-Signature": "fakesig" },
      headers: {},
    }),
  })),
}));

vi.mock("@aws-crypto/sha256-js", () => ({
  Sha256: vi.fn(),
}));

vi.mock("@smithy/protocol-http", () => ({
  HttpRequest: vi.fn().mockImplementation((opts: unknown) => opts),
}));

// Mock node:https — we won't actually use it; tests use injected fetcher
vi.mock("node:https", () => ({
  default: { get: vi.fn() },
}));

import {
  scanEKSWorkloads,
  eksWorkloadToResourceBinding,
  clearClusterCache,
} from "../../aws/EKSWorkloadScanner";
import type { K8sServiceAccountItem } from "../../aws/types";

// ── Helpers ─────────────────────────────────────────────────────────

const ROLE_ARN = "arn:aws:iam::123456789012:role/PodRole";

function mockEKSClient(
  clusterNames: string[],
  clusterDetails: Record<
    string,
    {
      arn: string;
      endpoint?: string;
      caCert?: string;
      oidcIssuer?: string | null;
    }
  >
) {
  return {
    send: vi.fn().mockImplementation((cmd: any) => {
      const cmdName = cmd.constructor?.name ?? cmd._cmdName;

      if (
        cmdName === "ListClustersCommand" ||
        cmd.input === undefined // fallback
      ) {
        if (!cmd.input || !cmd.input.nextToken) {
          return { clusters: clusterNames, nextToken: undefined };
        }
        return { clusters: [], nextToken: undefined };
      }

      // DescribeCluster
      const name = cmd.input?.name;
      const detail = clusterDetails[name];
      if (!detail) {
        const err = new Error("AccessDeniedException");
        (err as any).name = "AccessDeniedException";
        throw err;
      }
      return {
        cluster: {
          arn: detail.arn,
          endpoint: detail.endpoint ?? "https://eks.example.com",
          certificateAuthority: {
            data: detail.caCert ?? Buffer.from("fakeca").toString("base64"),
          },
          identity: detail.oidcIssuer !== undefined
            ? detail.oidcIssuer !== null
              ? { oidc: { issuer: detail.oidcIssuer } }
              : {}
            : { oidc: { issuer: "https://oidc.eks.us-east-1.amazonaws.com/id/ABC" } },
        },
      };
    }),
    config: {
      credentials: vi.fn().mockResolvedValue({
        accessKeyId: "AKIATEST",
        secretAccessKey: "secret",
      }),
    },
  } as any;
}

function makeSA(
  namespace: string,
  name: string,
  roleArn?: string
): K8sServiceAccountItem {
  return {
    metadata: {
      name,
      namespace,
      ...(roleArn
        ? { annotations: { "eks.amazonaws.com/role-arn": roleArn } }
        : {}),
    },
  };
}

// ── Tests ───────────────────────────────────────────────────────────

describe("scanEKSWorkloads", () => {
  beforeEach(() => {
    clearClusterCache();
    vi.clearAllMocks();
  });

  it("returns binding for SA with matching annotation", async () => {
    const client = mockEKSClient(["prod"], {
      prod: {
        arn: "arn:aws:eks:us-east-1:123:cluster/prod",
        oidcIssuer: "https://oidc.eks.us-east-1.amazonaws.com/id/ABC",
      },
    });

    const mockFetcher = vi.fn().mockResolvedValue([
      makeSA("app-ns", "my-sa", ROLE_ARN),
      makeSA("app-ns", "other-sa", "arn:aws:iam::123:role/OtherRole"),
    ]);

    const result = await scanEKSWorkloads(
      ROLE_ARN,
      client,
      "us-east-1",
      mockFetcher
    );

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      clusterName: "prod",
      clusterArn: "arn:aws:eks:us-east-1:123:cluster/prod",
      namespace: "app-ns",
      serviceAccount: "my-sa",
      oidcIssuer: "https://oidc.eks.us-east-1.amazonaws.com/id/ABC",
      roleArn: ROLE_ARN,
      confidenceScore: 95,
    });
  });

  it("does NOT return SA without matching annotation", async () => {
    const client = mockEKSClient(["prod"], {
      prod: {
        arn: "arn:aws:eks:us-east-1:123:cluster/prod",
        oidcIssuer: "https://oidc.eks.us-east-1.amazonaws.com/id/ABC",
      },
    });

    const mockFetcher = vi.fn().mockResolvedValue([
      makeSA("default", "no-annotation"),
      makeSA("kube-system", "annotated", "arn:aws:iam::999:role/Different"),
    ]);

    const result = await scanEKSWorkloads(
      ROLE_ARN,
      client,
      "us-east-1",
      mockFetcher
    );

    expect(result).toHaveLength(0);
  });

  it("skips cluster on 403 without throwing", async () => {
    // "bad-cluster" is not in clusterDetails → mock throws AccessDenied
    const client = mockEKSClient(["good", "bad-cluster"], {
      good: {
        arn: "arn:aws:eks:us-east-1:123:cluster/good",
        oidcIssuer: "https://oidc.eks.us-east-1.amazonaws.com/id/GOOD",
      },
      // "bad-cluster" missing → will throw on DescribeCluster
    });

    const mockFetcher = vi.fn().mockResolvedValue([
      makeSA("ns", "sa", ROLE_ARN),
    ]);

    // Should NOT throw
    const result = await scanEKSWorkloads(
      ROLE_ARN,
      client,
      "us-east-1",
      mockFetcher
    );

    // Only "good" cluster produces results
    expect(result).toHaveLength(1);
    expect(result[0].clusterName).toBe("good");
  });

  it("handles multiple clusters, returns only matching", async () => {
    const client = mockEKSClient(["alpha", "beta"], {
      alpha: {
        arn: "arn:aws:eks:us-east-1:123:cluster/alpha",
        oidcIssuer: "https://oidc.eks.us-east-1.amazonaws.com/id/ALPHA",
      },
      beta: {
        arn: "arn:aws:eks:us-east-1:123:cluster/beta",
        oidcIssuer: "https://oidc.eks.us-east-1.amazonaws.com/id/BETA",
      },
    });

    let callCount = 0;
    const mockFetcher = vi.fn().mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        // alpha cluster: has matching SA
        return [makeSA("ns1", "pod-sa", ROLE_ARN)];
      }
      // beta cluster: no matching SA
      return [makeSA("ns2", "other-sa")];
    });

    const result = await scanEKSWorkloads(
      ROLE_ARN,
      client,
      "us-east-1",
      mockFetcher
    );

    expect(result).toHaveLength(1);
    expect(result[0].clusterName).toBe("alpha");
  });

  it("returns [] when no clusters exist", async () => {
    const client = mockEKSClient([], {});
    const mockFetcher = vi.fn();

    const result = await scanEKSWorkloads(
      ROLE_ARN,
      client,
      "us-east-1",
      mockFetcher
    );

    expect(result).toEqual([]);
    expect(mockFetcher).not.toHaveBeenCalled();
  });

  it("skips cluster without OIDC issuer", async () => {
    const client = mockEKSClient(["no-oidc"], {
      "no-oidc": {
        arn: "arn:aws:eks:us-east-1:123:cluster/no-oidc",
        oidcIssuer: null, // No OIDC configured
      },
    });

    const mockFetcher = vi.fn();

    const result = await scanEKSWorkloads(
      ROLE_ARN,
      client,
      "us-east-1",
      mockFetcher
    );

    expect(result).toEqual([]);
    // K8s API should not be called for clusters without OIDC
    expect(mockFetcher).not.toHaveBeenCalled();
  });

  it("returns [] for empty roleArn", async () => {
    const client = mockEKSClient(["prod"], {});
    const result = await scanEKSWorkloads("", client, "us-east-1");
    expect(result).toEqual([]);
  });
});

// ── Persistence helper tests ────────────────────────────────────────

describe("eksWorkloadToResourceBinding", () => {
  it("produces correct resource_id format", () => {
    const binding = eksWorkloadToResourceBinding({
      clusterName: "prod",
      clusterArn: "arn:aws:eks:us-east-1:123:cluster/prod",
      namespace: "app-ns",
      serviceAccount: "my-sa",
      oidcIssuer: "https://oidc.eks.us-east-1.amazonaws.com/id/ABC",
      roleArn: ROLE_ARN,
      confidenceScore: 95,
    });

    expect(binding).toMatchObject({
      resourceId:
        "eks://arn:aws:eks:us-east-1:123:cluster/prod/app-ns/my-sa",
      resourceType: "AWSEKSWorkload",
      resourceName: "prod/app-ns:my-sa",
      bindingMethod: "WorkloadIdentityAnnotation",
      confidenceScore: 95,
    });
    expect(binding.bindingEvidence).toMatchObject({
      cloud: "aws",
      clusterName: "prod",
      namespace: "app-ns",
      serviceAccount: "my-sa",
    });
  });
});
