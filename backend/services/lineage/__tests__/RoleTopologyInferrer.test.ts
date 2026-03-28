/**
 * RoleTopologyInferrer unit tests.
 *
 * Tests the classification engine (classifyRoles) exhaustively, plus
 * the ARM fetch + top-level inferRoleTopology integration path.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  classifyRoles,
  inferRoleTopology,
  type RoleAssignment,
  type RoleTopology,
} from "../RoleTopologyInferrer";

// ── Helpers ─────────────────────────────────────────────────────────

function ra(role: string, scope = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/app-1"): RoleAssignment {
  return { roleDefinitionName: role, scope };
}

function subScope(subId = "sub-1"): string {
  return `/subscriptions/${subId}`;
}

function rgScope(subId = "sub-1", rg = "rg-1"): string {
  return `/subscriptions/${subId}/resourceGroups/${rg}`;
}

// ── classifyRoles tests ─────────────────────────────────────────────

describe("classifyRoles", () => {

  // ── Rule 1: ContainerisedApp ────────────────────────────────────
  describe("Rule 1 — ContainerisedApp", () => {
    it("matches AcrPull + Key Vault Secrets User", () => {
      const result = classifyRoles([
        ra("AcrPull"),
        ra("Key Vault Secrets User"),
      ]);
      expect(result.workloadType).toBe("ContainerisedApp");
      expect(result.confidenceScore).toBe(85);
      expect(result.matchedRule).toBe("Rule1_ContainerisedApp");
    });

    it("matches AcrReader + Storage Blob Data Reader", () => {
      const result = classifyRoles([
        ra("AcrReader"),
        ra("Storage Blob Data Reader"),
      ]);
      expect(result.workloadType).toBe("ContainerisedApp");
      expect(result.confidenceScore).toBe(85);
    });

    it("matches AcrPull + Storage Blob Data Contributor", () => {
      const result = classifyRoles([
        ra("AcrPull"),
        ra("Storage Blob Data Contributor"),
      ]);
      expect(result.workloadType).toBe("ContainerisedApp");
      expect(result.confidenceScore).toBe(85);
    });

    it("does NOT match AcrPull alone (no companion role)", () => {
      const result = classifyRoles([ra("AcrPull")]);
      expect(result.workloadType).not.toBe("ContainerisedApp");
    });
  });

  // ── Rule 2: ServerlessWorker ────────────────────────────────────
  describe("Rule 2 — ServerlessWorker", () => {
    it("matches Storage Queue Data Message Processor", () => {
      const result = classifyRoles([
        ra("Storage Queue Data Message Processor"),
      ]);
      expect(result.workloadType).toBe("ServerlessWorker");
      expect(result.confidenceScore).toBe(80);
      expect(result.matchedRule).toBe("Rule2_ServerlessWorker");
    });

    it("matches Storage Blob Data Owner", () => {
      const result = classifyRoles([ra("Storage Blob Data Owner")]);
      expect(result.workloadType).toBe("ServerlessWorker");
    });

    it("matches Service Bus Data Receiver", () => {
      const result = classifyRoles([ra("Service Bus Data Receiver")]);
      expect(result.workloadType).toBe("ServerlessWorker");
    });
  });

  // ── Rule 3: InfrastructureOrIaC ─────────────────────────────────
  describe("Rule 3 — InfrastructureOrIaC", () => {
    it("matches Contributor at subscription scope, no AcrPull", () => {
      const result = classifyRoles([
        ra("Contributor", subScope()),
      ]);
      expect(result.workloadType).toBe("InfrastructureOrIaC");
      expect(result.confidenceScore).toBe(75);
      expect(result.matchedRule).toBe("Rule3_InfrastructureOrIaC");
    });

    it("matches Owner at resource group scope", () => {
      const result = classifyRoles([
        ra("Owner", rgScope()),
      ]);
      expect(result.workloadType).toBe("InfrastructureOrIaC");
    });

    it("does NOT match Contributor with AcrPull (Rule 1 takes priority if companion present, otherwise Rule 3 blocked)", () => {
      // AcrPull without companion → Rule 1 fails, but Rule 3 checks !hasAcrPull
      const result = classifyRoles([
        ra("Contributor", subScope()),
        ra("AcrPull"),
      ]);
      expect(result.workloadType).not.toBe("InfrastructureOrIaC");
    });

    it("does NOT match Contributor at resource-level scope", () => {
      // resource-level scope is NOT broad
      const result = classifyRoles([
        ra("Contributor", "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1"),
      ]);
      expect(result.workloadType).not.toBe("InfrastructureOrIaC");
    });
  });

  // ── Rule 4: BackendDatabaseService ──────────────────────────────
  describe("Rule 4 — BackendDatabaseService", () => {
    it("matches SQL DB Contributor", () => {
      const result = classifyRoles([ra("SQL DB Contributor")]);
      expect(result.workloadType).toBe("BackendDatabaseService");
      expect(result.confidenceScore).toBe(82);
      expect(result.matchedRule).toBe("Rule4_BackendDatabaseService");
    });

    it("matches Cosmos DB Account Reader Role", () => {
      const result = classifyRoles([ra("Cosmos DB Account Reader Role")]);
      expect(result.workloadType).toBe("BackendDatabaseService");
    });
  });

  // ── Rule 5: DataPipeline ────────────────────────────────────────
  describe("Rule 5 — DataPipeline", () => {
    it("matches Storage Blob Data Contributor + EventHubs Data Sender", () => {
      const result = classifyRoles([
        ra("Storage Blob Data Contributor"),
        ra("Azure Event Hubs Data Sender"),
      ]);
      expect(result.workloadType).toBe("DataPipeline");
      expect(result.confidenceScore).toBe(78);
      expect(result.matchedRule).toBe("Rule5_DataPipeline");
    });

    it("matches Storage Blob Data Contributor + Data Factory Contributor", () => {
      const result = classifyRoles([
        ra("Storage Blob Data Contributor"),
        ra("Data Factory Contributor"),
      ]);
      expect(result.workloadType).toBe("DataPipeline");
    });

    it("does NOT match Storage Blob Data Contributor alone", () => {
      const result = classifyRoles([ra("Storage Blob Data Contributor")]);
      expect(result.workloadType).not.toBe("DataPipeline");
    });
  });

  // ── Rule 6: MonitoringAgent ─────────────────────────────────────
  describe("Rule 6 — MonitoringAgent", () => {
    it("matches when all roles are Reader-level", () => {
      const result = classifyRoles([
        ra("Reader"),
        ra("Monitoring Reader"),
        ra("Log Analytics Reader"),
      ]);
      expect(result.workloadType).toBe("MonitoringAgent");
      expect(result.confidenceScore).toBe(72);
      expect(result.matchedRule).toBe("Rule6_MonitoringAgent");
    });

    it("does NOT match if any non-reader role is present", () => {
      const result = classifyRoles([
        ra("Reader"),
        ra("Contributor", subScope()),
      ]);
      expect(result.workloadType).not.toBe("MonitoringAgent");
    });
  });

  // ── Default: Unknown ────────────────────────────────────────────
  describe("Default — Unknown", () => {
    it("returns Unknown with confidence 30 for unrecognised roles", () => {
      const result = classifyRoles([
        ra("Custom Role XYZ"),
        ra("Another Custom Role"),
      ]);
      expect(result.workloadType).toBe("Unknown");
      expect(result.confidenceScore).toBe(30);
      expect(result.matchedRule).toBe("Default_Unknown");
    });

    it("returns Unknown for empty assignments", () => {
      const result = classifyRoles([]);
      expect(result.workloadType).toBe("Unknown");
      expect(result.confidenceScore).toBe(30);
    });
  });

  // ── Priority: first match wins ──────────────────────────────────
  describe("Rule priority", () => {
    it("Rule 1 beats Rule 2 when both patterns present", () => {
      const result = classifyRoles([
        ra("AcrPull"),
        ra("Key Vault Secrets User"),
        ra("Storage Queue Data Message Processor"),
      ]);
      expect(result.workloadType).toBe("ContainerisedApp");
      expect(result.matchedRule).toBe("Rule1_ContainerisedApp");
    });

    it("Rule 2 beats Rule 4 when both patterns present", () => {
      const result = classifyRoles([
        ra("Storage Blob Data Owner"),
        ra("SQL DB Contributor"),
      ]);
      expect(result.workloadType).toBe("ServerlessWorker");
      expect(result.matchedRule).toBe("Rule2_ServerlessWorker");
    });

    it("Rule 4 beats Rule 5 (DB role present, even with blob+eventhubs)", () => {
      const result = classifyRoles([
        ra("SQL DB Contributor"),
        ra("Storage Blob Data Contributor"),
        ra("Azure Event Hubs Data Sender"),
      ]);
      expect(result.workloadType).toBe("BackendDatabaseService");
    });
  });

  // ── Case insensitivity ──────────────────────────────────────────
  it("matches role names case-insensitively", () => {
    const result = classifyRoles([
      ra("acrpull"),
      ra("KEY VAULT SECRETS USER"),
    ]);
    expect(result.workloadType).toBe("ContainerisedApp");
  });
});

// ── inferRoleTopology tests ─────────────────────────────────────────

// Mock global fetch for ARM API calls
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function armResponse(assignments: Array<{ role: string; scope: string }>): object {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      value: assignments.map((a, i) => ({
        id: `/assignments/${i}`,
        properties: {
          roleDefinitionId: `/providers/Microsoft.Authorization/roleDefinitions/${i}`,
          principalId: "obj-123",
          scope: a.scope,
          expandedProperties: {
            roleDefinition: { displayName: a.role },
          },
        },
      })),
    }),
  };
}

describe("inferRoleTopology", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const credential = {
    getToken: vi.fn().mockResolvedValue({ token: "fake-token", expiresOnTimestamp: 0 }),
  };

  it("fetches assignments from ARM and classifies as ContainerisedApp", async () => {
    mockFetch.mockResolvedValueOnce(
      armResponse([
        { role: "AcrPull", scope: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerRegistry/registries/myacr" },
        { role: "Key Vault Secrets User", scope: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/mykv" },
      ])
    );

    const result = await inferRoleTopology("obj-123", "sub-1", credential as any);

    expect(result.workloadType).toBe("ContainerisedApp");
    expect(result.confidenceScore).toBe(85);
    expect(result.roleAssignments).toHaveLength(2);
    expect(result.topResources).toEqual(["myacr", "mykv"]);
  });

  it("returns Unknown with confidence 0 when objectId is empty", async () => {
    const result = await inferRoleTopology("", "sub-1", credential as any);

    expect(result.workloadType).toBe("Unknown");
    expect(result.confidenceScore).toBe(0);
    expect(result.matchedRule).toBe("NoInput");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("returns Unknown with confidence 0 when subscriptionId is empty", async () => {
    const result = await inferRoleTopology("obj-123", "", credential as any);

    expect(result.workloadType).toBe("Unknown");
    expect(result.confidenceScore).toBe(0);
  });

  it("extracts top 3 unique resource names from scopes", async () => {
    mockFetch.mockResolvedValueOnce(
      armResponse([
        { role: "Reader", scope: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/app-alpha" },
        { role: "Monitoring Reader", scope: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Insights/components/ai-beta" },
        { role: "Log Analytics Reader", scope: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.OperationalInsights/workspaces/log-gamma" },
        { role: "Reader", scope: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa-delta" },
      ])
    );

    const result = await inferRoleTopology("obj-123", "sub-1", credential as any);

    expect(result.workloadType).toBe("MonitoringAgent");
    expect(result.topResources).toHaveLength(3);
    expect(result.topResources).toEqual(["app-alpha", "ai-beta", "log-gamma"]);
  });

  it("deduplicates resource names in topResources", async () => {
    mockFetch.mockResolvedValueOnce(
      armResponse([
        { role: "Reader", scope: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/same-app" },
        { role: "Monitoring Reader", scope: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/same-app" },
      ])
    );

    const result = await inferRoleTopology("obj-123", "sub-1", credential as any);

    expect(result.topResources).toEqual(["same-app"]);
  });

  it("handles ARM API returning empty assignments", async () => {
    mockFetch.mockResolvedValueOnce(armResponse([]));

    const result = await inferRoleTopology("obj-123", "sub-1", credential as any);

    expect(result.workloadType).toBe("Unknown");
    expect(result.confidenceScore).toBe(30);
    expect(result.roleAssignments).toEqual([]);
    expect(result.topResources).toEqual([]);
  });
});

// ── Persistence shape test ──────────────────────────────────────────

describe("persistence contract", () => {
  it("persistRoleTopology is exported and callable", async () => {
    const mod = await import("../RoleTopologyInferrer");
    expect(typeof mod.persistRoleTopology).toBe("function");
  });
});
