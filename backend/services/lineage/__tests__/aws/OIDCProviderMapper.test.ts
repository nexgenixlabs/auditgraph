/**
 * OIDCProviderMapper unit tests.
 *
 *   1. GitHub OIDC with branch condition → org, repo, branch extracted
 *   2. GitHub OIDC with environment condition → environment extracted
 *   3. EKS OIDC URL → EKSCluster type, confidence 95
 *   4. Unknown URL → ExternalIdP, confidence 70
 *   5. No providers → []
 *   6. No matching providers in trust policy → []
 *   7. Provider not readable (403) → skipped
 *   8. classifyProviderUrl pure function tests
 *   9. Persistence produces correct resource_type / binding_method
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  mapOIDCProviders,
  classifyProviderUrl,
} from "../../aws/OIDCProviderMapper";

// ── Mock IAM client ─────────────────────────────────────────────────

interface MockProviderDetail {
  url: string;
  clientIds?: string[];
  thumbprints?: string[];
}

interface MockSetup {
  providers: Record<string, MockProviderDetail>;
  trustPolicy: {
    Version: string;
    Statement: Array<{
      Effect: string;
      Principal: Record<string, string | string[]> | string;
      Action: string;
      Condition?: Record<string, Record<string, string | string[]>>;
    }>;
  } | null;
}

function mockIAMClient(setup: MockSetup) {
  const providerArns = Object.keys(setup.providers);

  return {
    send: vi.fn().mockImplementation((cmd: any) => {
      const cmdName = cmd.constructor?.name ?? "";

      // ListOpenIDConnectProviders
      if (cmdName === "ListOpenIDConnectProvidersCommand") {
        return {
          OpenIDConnectProviderList: providerArns.map((arn) => ({
            Arn: arn,
          })),
        };
      }

      // GetOpenIDConnectProvider
      if (cmdName === "GetOpenIDConnectProviderCommand") {
        const arn = cmd.input?.OpenIDConnectProviderArn;
        const detail = setup.providers[arn];
        if (!detail) throw new Error("NoSuchEntity");
        return {
          Url: detail.url,
          ClientIDList: detail.clientIds ?? ["sts.amazonaws.com"],
          ThumbprintList: detail.thumbprints ?? ["aabbccdd"],
        };
      }

      // GetRole
      if (cmdName === "GetRoleCommand") {
        if (!setup.trustPolicy) throw new Error("NoSuchEntity");
        return {
          Role: {
            AssumeRolePolicyDocument: encodeURIComponent(
              JSON.stringify(setup.trustPolicy)
            ),
          },
        };
      }

      return {};
    }),
  } as any;
}

const ROLE_ARN = "arn:aws:iam::123456789012:role/MyRole";
const GH_PROVIDER_ARN =
  "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com";
const EKS_PROVIDER_ARN =
  "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/CLUSTER1";
const EXTERNAL_PROVIDER_ARN =
  "arn:aws:iam::123456789012:oidc-provider/login.example.com";

// ── classifyProviderUrl tests ───────────────────────────────────────

describe("classifyProviderUrl", () => {
  it("classifies GitHub OIDC", () => {
    expect(
      classifyProviderUrl("token.actions.githubusercontent.com")
    ).toBe("GitHubActions");
  });

  it("classifies EKS OIDC", () => {
    expect(
      classifyProviderUrl(
        "oidc.eks.us-east-1.amazonaws.com/id/ABCDEF123456"
      )
    ).toBe("EKSCluster");
  });

  it("classifies unknown URL as ExternalIdP", () => {
    expect(classifyProviderUrl("login.example.com")).toBe("ExternalIdP");
  });
});

// ── mapOIDCProviders tests ──────────────────────────────────────────

describe("mapOIDCProviders", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("maps GitHub OIDC with branch condition", async () => {
    const client = mockIAMClient({
      providers: {
        [GH_PROVIDER_ARN]: {
          url: "token.actions.githubusercontent.com",
        },
      },
      trustPolicy: {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: { Federated: GH_PROVIDER_ARN },
            Action: "sts:AssumeRoleWithWebIdentity",
            Condition: {
              StringLike: {
                "token.actions.githubusercontent.com:sub":
                  "repo:myorg/myrepo:ref:refs/heads/main",
              },
            },
          },
        ],
      },
    });

    const result = await mapOIDCProviders(ROLE_ARN, client);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      providerArn: GH_PROVIDER_ARN,
      providerType: "GitHubActions",
      issuerUrl: "token.actions.githubusercontent.com",
      org: "myorg",
      repo: "myrepo",
      branch: "main",
      confidenceScore: 98,
    });
  });

  it("maps GitHub OIDC with environment condition", async () => {
    const client = mockIAMClient({
      providers: {
        [GH_PROVIDER_ARN]: {
          url: "token.actions.githubusercontent.com",
        },
      },
      trustPolicy: {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: { Federated: GH_PROVIDER_ARN },
            Action: "sts:AssumeRoleWithWebIdentity",
            Condition: {
              StringEquals: {
                "token.actions.githubusercontent.com:sub":
                  "repo:acme/deploy:environment:production",
              },
            },
          },
        ],
      },
    });

    const result = await mapOIDCProviders(ROLE_ARN, client);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      providerType: "GitHubActions",
      org: "acme",
      repo: "deploy",
      environment: "production",
      confidenceScore: 98,
    });
  });

  it("maps EKS OIDC URL with confidence 95", async () => {
    const client = mockIAMClient({
      providers: {
        [EKS_PROVIDER_ARN]: {
          url: "oidc.eks.us-east-1.amazonaws.com/id/CLUSTER1",
        },
      },
      trustPolicy: {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: { Federated: EKS_PROVIDER_ARN },
            Action: "sts:AssumeRoleWithWebIdentity",
            Condition: {
              StringEquals: {
                "oidc.eks.us-east-1.amazonaws.com/id/CLUSTER1:sub":
                  "system:serviceaccount:default:my-sa",
              },
            },
          },
        ],
      },
    });

    const result = await mapOIDCProviders(ROLE_ARN, client);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      providerType: "EKSCluster",
      confidenceScore: 95,
      clusterArn:
        "arn:aws:eks:us-east-1:123456789012:cluster/CLUSTER1",
    });
  });

  it("maps unknown OIDC URL as ExternalIdP with confidence 70", async () => {
    const client = mockIAMClient({
      providers: {
        [EXTERNAL_PROVIDER_ARN]: {
          url: "login.example.com",
        },
      },
      trustPolicy: {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: {
              Federated: EXTERNAL_PROVIDER_ARN,
            },
            Action: "sts:AssumeRoleWithWebIdentity",
          },
        ],
      },
    });

    const result = await mapOIDCProviders(ROLE_ARN, client);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      providerType: "ExternalIdP",
      issuerUrl: "login.example.com",
      confidenceScore: 70,
    });
  });

  it("returns [] when no providers exist", async () => {
    const client = mockIAMClient({
      providers: {},
      trustPolicy: {
        Version: "2012-10-17",
        Statement: [],
      },
    });

    const result = await mapOIDCProviders(ROLE_ARN, client);
    expect(result).toEqual([]);
  });

  it("returns [] when no providers match trust policy", async () => {
    const client = mockIAMClient({
      providers: {
        [GH_PROVIDER_ARN]: {
          url: "token.actions.githubusercontent.com",
        },
      },
      trustPolicy: {
        Version: "2012-10-17",
        Statement: [
          {
            // Trust references a DIFFERENT provider
            Effect: "Allow",
            Principal: {
              Federated:
                "arn:aws:iam::123456789012:oidc-provider/something-else.com",
            },
            Action: "sts:AssumeRoleWithWebIdentity",
          },
        ],
      },
    });

    const result = await mapOIDCProviders(ROLE_ARN, client);
    expect(result).toEqual([]);
  });

  it("skips providers that fail to read (403)", async () => {
    // Provider ARN exists but GetOpenIDConnectProvider throws
    const client = {
      send: vi.fn().mockImplementation((cmd: any) => {
        const cmdName = cmd.constructor?.name ?? "";

        if (cmdName === "ListOpenIDConnectProvidersCommand") {
          return {
            OpenIDConnectProviderList: [
              { Arn: GH_PROVIDER_ARN },
              { Arn: "arn:aws:iam::123:oidc-provider/forbidden" },
            ],
          };
        }

        if (cmdName === "GetOpenIDConnectProviderCommand") {
          const arn = cmd.input?.OpenIDConnectProviderArn;
          if (arn === "arn:aws:iam::123:oidc-provider/forbidden") {
            throw new Error("AccessDenied");
          }
          return {
            Url: "token.actions.githubusercontent.com",
            ClientIDList: [],
            ThumbprintList: [],
          };
        }

        if (cmdName === "GetRoleCommand") {
          return {
            Role: {
              AssumeRolePolicyDocument: encodeURIComponent(
                JSON.stringify({
                  Version: "2012-10-17",
                  Statement: [
                    {
                      Effect: "Allow",
                      Principal: { Federated: GH_PROVIDER_ARN },
                      Action: "sts:AssumeRoleWithWebIdentity",
                      Condition: {
                        StringLike: {
                          "token.actions.githubusercontent.com:sub":
                            "repo:org/repo:ref:refs/heads/main",
                        },
                      },
                    },
                  ],
                })
              ),
            },
          };
        }

        return {};
      }),
    } as any;

    const result = await mapOIDCProviders(ROLE_ARN, client);
    // Only the readable provider produces a mapping
    expect(result).toHaveLength(1);
    expect(result[0].providerType).toBe("GitHubActions");
  });

  it("returns [] for empty roleArn", async () => {
    const client = mockIAMClient({ providers: {}, trustPolicy: null });
    const result = await mapOIDCProviders("", client);
    expect(result).toEqual([]);
  });

  it("skips Deny statements when matching providers", async () => {
    const client = mockIAMClient({
      providers: {
        [GH_PROVIDER_ARN]: {
          url: "token.actions.githubusercontent.com",
        },
      },
      trustPolicy: {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Deny",
            Principal: { Federated: GH_PROVIDER_ARN },
            Action: "sts:AssumeRoleWithWebIdentity",
          },
        ],
      },
    });

    const result = await mapOIDCProviders(ROLE_ARN, client);
    expect(result).toEqual([]);
  });

  it("handles provider referenced by URL in trust policy", async () => {
    const client = mockIAMClient({
      providers: {
        [GH_PROVIDER_ARN]: {
          url: "token.actions.githubusercontent.com",
        },
      },
      trustPolicy: {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            // Trust references by URL-based ARN (contains the URL)
            Principal: {
              Federated:
                "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
            },
            Action: "sts:AssumeRoleWithWebIdentity",
            Condition: {
              StringLike: {
                "token.actions.githubusercontent.com:sub":
                  "repo:testorg/testrepo:ref:refs/heads/develop",
              },
            },
          },
        ],
      },
    });

    const result = await mapOIDCProviders(ROLE_ARN, client);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      providerType: "GitHubActions",
      org: "testorg",
      repo: "testrepo",
      branch: "develop",
    });
  });
});
