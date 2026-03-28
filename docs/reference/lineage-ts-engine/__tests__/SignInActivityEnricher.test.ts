/**
 * SignInActivityEnricher unit tests.
 *
 *   1. NonInteractive only → confirmedNHI: true, signInType: NonInteractive
 *   2. Delegated only → couldBeHuman: true, signInType: Delegated
 *   3. Both set → signInType: Mixed, couldBeHuman: true
 *   4. None set → signInType: Never, dormancyDays: -1
 *   5. dormancyDays computed from most recent timestamp
 *   6. Graph 404 → Never enrichment
 *   7. Empty objectId → Never enrichment
 *   8. ServicePrincipal sign-in without delegated → NonInteractive
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  classifySignInActivity,
  enrichSignInActivity,
  type SignInEnrichment,
} from "../SignInActivityEnricher";

// ── classifySignInActivity tests ────────────────────────────────────

describe("classifySignInActivity", () => {
  const NOW = new Date("2026-03-26T12:00:00Z");

  // ── Rule 1: NonInteractive only ─────────────────────────────────
  it("classifies nonInteractive-only as confirmedNHI + NonInteractive", () => {
    const result = classifySignInActivity(
      null,                          // lastSignIn
      "2026-03-20T10:00:00Z",       // lastNonInteractive
      null,                          // lastDelegated
      null,                          // lastServicePrincipal
      NOW
    );
    expect(result.confirmedNHI).toBe(true);
    expect(result.couldBeHuman).toBe(false);
    expect(result.signInType).toBe("NonInteractive");
    expect(result.dormancyDays).toBe(6);
  });

  // ── Rule 2: Delegated only ──────────────────────────────────────
  it("classifies delegated-only as couldBeHuman + Delegated", () => {
    const result = classifySignInActivity(
      null,
      null,
      "2026-03-25T10:00:00Z",       // lastDelegated
      null,
      NOW
    );
    expect(result.confirmedNHI).toBe(false);
    expect(result.couldBeHuman).toBe(true);
    expect(result.signInType).toBe("Delegated");
    expect(result.dormancyDays).toBe(1);
  });

  // ── Rule 3: Both set → Mixed ───────────────────────────────────
  it("classifies both nonInteractive + delegated as Mixed", () => {
    const result = classifySignInActivity(
      null,
      "2026-03-20T10:00:00Z",
      "2026-03-24T10:00:00Z",
      null,
      NOW
    );
    expect(result.signInType).toBe("Mixed");
    expect(result.couldBeHuman).toBe(true);
    expect(result.confirmedNHI).toBe(false);
    // Most recent is delegated (Mar 24) → 2 days
    expect(result.dormancyDays).toBe(2);
  });

  // ── Rule 4: None set → Never ───────────────────────────────────
  it("classifies all-null as Never with dormancyDays -1", () => {
    const result = classifySignInActivity(null, null, null, null, NOW);
    expect(result.signInType).toBe("Never");
    expect(result.confirmedNHI).toBe(false);
    expect(result.couldBeHuman).toBe(false);
    expect(result.dormancyDays).toBe(-1);
    expect(result.lastSignInAt).toBeNull();
  });

  // ── Rule 5: dormancyDays from most recent ──────────────────────
  it("computes dormancyDays from the most recent of all timestamps", () => {
    const result = classifySignInActivity(
      "2026-03-10T10:00:00Z",       // 16 days ago
      "2026-03-15T10:00:00Z",       // 11 days ago
      null,
      "2026-03-25T10:00:00Z",       // 1 day ago — most recent
      NOW
    );
    expect(result.dormancyDays).toBe(1);
    expect(result.lastSignInAt).toEqual(new Date("2026-03-25T10:00:00Z"));
  });

  it("returns dormancyDays 0 when last sign-in is today", () => {
    const result = classifySignInActivity(
      "2026-03-26T08:00:00Z",
      null,
      null,
      null,
      NOW
    );
    expect(result.dormancyDays).toBe(0);
  });

  // ── Rule 8: SP sign-in without delegated → NonInteractive ──────
  it("classifies servicePrincipal-only sign-in as confirmedNHI + NonInteractive", () => {
    const result = classifySignInActivity(
      null,
      null,
      null,
      "2026-03-22T10:00:00Z",       // lastServicePrincipal
      NOW
    );
    expect(result.confirmedNHI).toBe(true);
    expect(result.couldBeHuman).toBe(false);
    expect(result.signInType).toBe("NonInteractive");
    expect(result.dormancyDays).toBe(4);
  });

  it("includes lastSignIn in dormancy calculation even with no other timestamps", () => {
    const result = classifySignInActivity(
      "2026-03-24T10:00:00Z",       // lastSignIn only
      null,
      null,
      null,
      NOW
    );
    // lastSignIn alone doesn't trigger NonInteractive or Delegated → Never
    // but dormancy uses the timestamp
    expect(result.signInType).toBe("Never");
    expect(result.dormancyDays).toBe(2);
    expect(result.lastSignInAt).toEqual(new Date("2026-03-24T10:00:00Z"));
  });
});

// ── enrichSignInActivity tests (Graph API mock) ─────────────────────

function mockGraphClient(activity: object) {
  return {
    api: vi.fn().mockReturnValue({
      get: vi.fn().mockResolvedValue(activity),
    }),
  };
}

function mockGraphClient404() {
  return {
    api: vi.fn().mockReturnValue({
      get: vi.fn().mockRejectedValue(
        Object.assign(new Error("Not Found"), { statusCode: 404 })
      ),
    }),
  };
}

describe("enrichSignInActivity", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("fetches from Graph and classifies NonInteractive", async () => {
    const client = mockGraphClient({
      id: "obj-1",
      lastSignInActivity: {
        lastSignInDateTime: null,
        lastNonInteractiveSignInDateTime: "2026-03-20T10:00:00Z",
      },
      lastDelegatedSignInDateTime: null,
      lastServicePrincipalSignInDateTime: null,
    });

    const result = await enrichSignInActivity("obj-1", client as any);

    expect(result.confirmedNHI).toBe(true);
    expect(result.signInType).toBe("NonInteractive");
    expect(client.api).toHaveBeenCalledWith(
      "/reports/servicePrincipalSignInActivities/obj-1"
    );
  });

  it("returns Never on Graph 404", async () => {
    const client = mockGraphClient404();
    const result = await enrichSignInActivity("obj-1", client as any);

    expect(result.signInType).toBe("Never");
    expect(result.dormancyDays).toBe(-1);
  });

  it("returns Never when objectId is empty", async () => {
    const client = mockGraphClient({});
    const result = await enrichSignInActivity("", client as any);

    expect(result.signInType).toBe("Never");
    expect(client.api).not.toHaveBeenCalled();
  });

  it("handles Mixed sign-in from Graph response", async () => {
    const client = mockGraphClient({
      id: "obj-2",
      lastSignInActivity: {
        lastSignInDateTime: "2026-03-18T10:00:00Z",
        lastNonInteractiveSignInDateTime: "2026-03-20T10:00:00Z",
      },
      lastDelegatedSignInDateTime: "2026-03-22T10:00:00Z",
      lastServicePrincipalSignInDateTime: null,
    });

    const result = await enrichSignInActivity("obj-2", client as any);

    expect(result.signInType).toBe("Mixed");
    expect(result.couldBeHuman).toBe(true);
  });
});

// ── Persistence tests ───────────────────────────────────────────────

describe("persistSignInEnrichment", () => {
  it("is exported and callable", async () => {
    const mod = await import("../SignInActivityEnricher");
    expect(typeof mod.persistSignInEnrichment).toBe("function");
  });

  it("writes enrichment_tier = 'P1_SIGNIN' to identity_lineage_enrichment", async () => {
    const { persistSignInEnrichment } = await import("../SignInActivityEnricher");
    const queries: Array<{ sql: string; params: unknown[] }> = [];
    const mockPool = {
      query: vi.fn().mockImplementation((sql: string, params: unknown[]) => {
        queries.push({ sql, params });
        return { rows: [] };
      }),
    };

    const enrichment = {
      confirmedNHI: true,
      couldBeHuman: false,
      signInType: "NonInteractive" as const,
      dormancyDays: 5,
      lastSignInAt: new Date("2026-03-21T10:00:00Z"),
    };

    await persistSignInEnrichment(mockPool as any, "42", "conn-1", enrichment);

    // Should have called DELETE + INSERT
    expect(mockPool.query).toHaveBeenCalledTimes(2);

    // The INSERT call should use 'P1_SIGNIN' as enrichment_tier
    const insertCall = queries.find((q) => q.sql.includes("INSERT INTO"));
    expect(insertCall).toBeDefined();
    expect(insertCall!.params).toContain("P1_SIGNIN");
    // Verify it's the last param (enrichment_tier column)
    expect(insertCall!.params[insertCall!.params.length - 1]).toBe("P1_SIGNIN");
  });
});
