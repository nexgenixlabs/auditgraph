/**
 * TrustPolicyParser unit tests.
 *
 *   1. GitHubOIDC trust — full org/repo extraction
 *   2. GitHubOIDC trust — no repo condition (lower confidence)
 *   3. EKSOIDC trust — full namespace/SA extraction
 *   4. EKSOIDC trust — no SA condition (lower confidence)
 *   5. CrossAccountAssumeRole — with ExternalId (higher confidence)
 *   6. CrossAccountAssumeRole — without ExternalId
 *   7. ServicePrincipal — lambda.amazonaws.com
 *   8. ExternalIdPSAML — SAML provider
 *   9. WildcardTrust — with conditions (60) vs without (40)
 *  10. Deny effect → skip
 *  11. IAM user → skip (no trust policy)
 *  12. NoSuchEntity → returns []
 *  13. URL-decode trust document
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  classifyStatement,
  parseTrustPolicy,
} from "../../aws/TrustPolicyParser";
import type { TrustPolicyStatement } from "../../aws/types";

// ── classifyStatement tests ─────────────────────────────────────────

describe("classifyStatement", () => {
  const accountId = "123456789012";

  it("classifies GitHub OIDC with org/repo", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: {
        Federated:
          "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
      },
      Action: "sts:AssumeRoleWithWebIdentity",
      Condition: {
        StringLike: {
          "token.actions.githubusercontent.com:sub":
            "repo:myorg/myrepo:ref:refs/heads/main",
        },
      },
    };

    const bindings = classifyStatement(stmt, accountId);
    expect(bindings).toHaveLength(1);
    expect(bindings[0].trustType).toBe("GitHubOIDC");
    expect(bindings[0].resourceId).toBe(
      "github-oidc://123456789012/myorg/myrepo"
    );
    expect(bindings[0].confidenceScore).toBe(95);
    expect(bindings[0].bindingMethod).toBe("TrustPolicy");
    expect(bindings[0].bindingEvidence).toMatchObject({
      cloud: "aws",
      trustType: "GitHubOIDC",
      org: "myorg",
      repo: "myrepo",
    });
  });

  it("classifies GitHub OIDC without repo condition (lower confidence)", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: {
        Federated:
          "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
      },
      Action: "sts:AssumeRoleWithWebIdentity",
    };

    const bindings = classifyStatement(stmt, accountId);
    expect(bindings).toHaveLength(1);
    expect(bindings[0].trustType).toBe("GitHubOIDC");
    expect(bindings[0].confidenceScore).toBe(75);
    expect(bindings[0].resourceId).toContain("unknown");
  });

  it("classifies EKS OIDC with namespace/SA", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: {
        Federated:
          "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABCDEF123456",
      },
      Action: "sts:AssumeRoleWithWebIdentity",
      Condition: {
        StringEquals: {
          "oidc.eks.us-east-1.amazonaws.com/id/ABCDEF123456:sub":
            "system:serviceaccount:my-ns:my-sa",
        },
      },
    };

    const bindings = classifyStatement(stmt, accountId);
    expect(bindings).toHaveLength(1);
    expect(bindings[0].trustType).toBe("EKSOIDC");
    expect(bindings[0].confidenceScore).toBe(95);
    expect(bindings[0].resourceId).toBe(
      "eks://123456789012/us-east-1/ABCDEF123456/my-ns/my-sa"
    );
    expect(bindings[0].bindingEvidence).toMatchObject({
      clusterId: "ABCDEF123456",
      namespace: "my-ns",
      serviceAccount: "my-sa",
    });
  });

  it("classifies EKS OIDC without SA condition (lower confidence)", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: {
        Federated:
          "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/XYZ789",
      },
      Action: "sts:AssumeRoleWithWebIdentity",
    };

    const bindings = classifyStatement(stmt, accountId);
    expect(bindings).toHaveLength(1);
    expect(bindings[0].trustType).toBe("EKSOIDC");
    expect(bindings[0].confidenceScore).toBe(70);
  });

  it("classifies cross-account trust with ExternalId", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: { AWS: "arn:aws:iam::999999999999:root" },
      Action: "sts:AssumeRole",
      Condition: {
        StringEquals: { "sts:ExternalId": "my-external-id" },
      },
    };

    const bindings = classifyStatement(stmt, accountId);
    expect(bindings).toHaveLength(1);
    expect(bindings[0].trustType).toBe("CrossAccountAssumeRole");
    expect(bindings[0].confidenceScore).toBe(90);
    expect(bindings[0].resourceId).toBe(
      "trust-policy://123456789012/cross-account/999999999999"
    );
  });

  it("classifies cross-account trust without ExternalId", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: { AWS: "arn:aws:iam::888888888888:role/CrossRole" },
      Action: "sts:AssumeRole",
    };

    const bindings = classifyStatement(stmt, accountId);
    expect(bindings).toHaveLength(1);
    expect(bindings[0].trustType).toBe("CrossAccountAssumeRole");
    expect(bindings[0].confidenceScore).toBe(80);
  });

  it("does NOT classify same-account principal as cross-account", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: { AWS: "arn:aws:iam::123456789012:role/SameAccount" },
      Action: "sts:AssumeRole",
    };

    const bindings = classifyStatement(stmt, accountId);
    // Same account — should not produce CrossAccountAssumeRole
    const crossAccount = bindings.filter(
      (b) => b.trustType === "CrossAccountAssumeRole"
    );
    expect(crossAccount).toHaveLength(0);
  });

  it("classifies ServicePrincipal trust", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: { Service: "lambda.amazonaws.com" },
      Action: "sts:AssumeRole",
    };

    const bindings = classifyStatement(stmt, accountId);
    expect(bindings).toHaveLength(1);
    expect(bindings[0].trustType).toBe("ServicePrincipal");
    expect(bindings[0].confidenceScore).toBe(90);
    expect(bindings[0].resourceId).toBe(
      "trust-policy://123456789012/service/lambda"
    );
  });

  it("classifies SAML provider trust", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: {
        Federated: "arn:aws:iam::123456789012:saml-provider/MyIdP",
      },
      Action: "sts:AssumeRoleWithSAML",
    };

    const bindings = classifyStatement(stmt, accountId);
    expect(bindings).toHaveLength(1);
    expect(bindings[0].trustType).toBe("ExternalIdPSAML");
    expect(bindings[0].confidenceScore).toBe(90);
    expect(bindings[0].resourceId).toBe(
      "trust-policy://123456789012/saml/MyIdP"
    );
  });

  it("classifies wildcard trust with conditions (60)", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: "*",
      Action: "sts:AssumeRole",
      Condition: {
        StringEquals: { "aws:PrincipalOrgID": "o-1234" },
      },
    };

    const bindings = classifyStatement(stmt, accountId);
    const wildcard = bindings.find((b) => b.trustType === "WildcardTrust");
    expect(wildcard).toBeDefined();
    expect(wildcard!.confidenceScore).toBe(60);
  });

  it("classifies wildcard trust without conditions (40)", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Allow",
      Principal: "*",
      Action: "sts:AssumeRole",
    };

    const bindings = classifyStatement(stmt, accountId);
    const wildcard = bindings.find((b) => b.trustType === "WildcardTrust");
    expect(wildcard).toBeDefined();
    expect(wildcard!.confidenceScore).toBe(40);
  });

  it("skips Deny statements", () => {
    const stmt: TrustPolicyStatement = {
      Effect: "Deny",
      Principal: "*",
      Action: "sts:AssumeRole",
    };

    const bindings = classifyStatement(stmt, accountId);
    expect(bindings).toHaveLength(0);
  });
});

// ── parseTrustPolicy tests ──────────────────────────────────────────

describe("parseTrustPolicy", () => {
  it("skips IAM users (no trust policy)", async () => {
    const identity = {
      id: "1",
      identityId: "arn:aws:iam::123:user/john",
      principalId: "arn:aws:iam::123:user/john",
      displayName: "john",
      identityCategory: "iam_user",
      isFederated: false,
      tags: {},
    };

    const iamClient = {} as any; // Should not be called
    const result = await parseTrustPolicy(iamClient, identity, "123");
    expect(result).toEqual([]);
  });

  it("handles NoSuchEntityException gracefully", async () => {
    const identity = {
      id: "2",
      identityId: "arn:aws:iam::123:role/Deleted",
      principalId: "arn:aws:iam::123:role/Deleted",
      displayName: "Deleted",
      identityCategory: "iam_role",
      isFederated: false,
      tags: {},
    };

    const error = new Error("NoSuchEntity");
    (error as any).name = "NoSuchEntityException";

    const iamClient = {
      send: vi.fn().mockRejectedValue(error),
    } as any;

    const result = await parseTrustPolicy(iamClient, identity, "123");
    expect(result).toEqual([]);
  });

  it("parses URL-encoded trust document", async () => {
    const trustDoc = {
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Principal: { Service: "ec2.amazonaws.com" },
          Action: "sts:AssumeRole",
        },
      ],
    };

    const identity = {
      id: "3",
      identityId: "arn:aws:iam::123456789012:role/MyRole",
      principalId: "arn:aws:iam::123456789012:role/MyRole",
      displayName: "MyRole",
      identityCategory: "iam_role",
      isFederated: false,
      tags: {},
    };

    const iamClient = {
      send: vi.fn().mockResolvedValue({
        Role: {
          AssumeRolePolicyDocument: encodeURIComponent(
            JSON.stringify(trustDoc)
          ),
        },
      }),
    } as any;

    const result = await parseTrustPolicy(
      iamClient,
      identity,
      "123456789012"
    );
    expect(result).toHaveLength(1);
    expect(result[0].trustType).toBe("ServicePrincipal");
    expect(result[0].bindingEvidence).toMatchObject({
      cloud: "aws",
      servicePrincipal: "ec2.amazonaws.com",
    });
  });

  it("rethrows non-NoSuchEntity errors", async () => {
    const identity = {
      id: "4",
      identityId: "arn:aws:iam::123:role/Broken",
      principalId: "arn:aws:iam::123:role/Broken",
      displayName: "Broken",
      identityCategory: "iam_role",
      isFederated: false,
      tags: {},
    };

    const error = new Error("Access Denied");
    (error as any).name = "AccessDeniedException";

    const iamClient = {
      send: vi.fn().mockRejectedValue(error),
    } as any;

    await expect(
      parseTrustPolicy(iamClient, identity, "123")
    ).rejects.toThrow("Access Denied");
  });
});
