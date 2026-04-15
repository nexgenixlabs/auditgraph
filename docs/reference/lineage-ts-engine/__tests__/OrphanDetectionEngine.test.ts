/**
 * OrphanDetectionEngine unit tests.
 *
 * Tests the classification cascade (classify) with all 5 statuses,
 * plus priority ordering and edge cases.
 */

import { describe, it, expect } from "vitest";
import { classify, type OrphanClassification } from "../OrphanDetectionEngine";

// ── Helper ──────────────────────────────────────────────────────────

function signals(overrides: Record<string, unknown> = {}) {
  return {
    secretsExpired: false,
    certsExpired: false,
    dormancyDays: 30,
    hasResourceBindings: false,
    hasFederatedBindings: false,
    activeRoleCount: 0,
    crossCloudReferenced: false,
    ...overrides,
  };
}

// ── BLOCKED ─────────────────────────────────────────────────────────

describe("BLOCKED", () => {
  it("classifies as BLOCKED when crossCloudReferenced is true", () => {
    const result = classify(signals({ crossCloudReferenced: true }));
    expect(result.orphanStatus).toBe("BLOCKED");
    expect(result.recommendedAction).toContain("cross-cloud");
  });

  it("BLOCKED takes priority over all other rules", () => {
    const result = classify(signals({
      crossCloudReferenced: true,
      hasResourceBindings: true,
      dormancyDays: 10,
      secretsExpired: true,
    }));
    expect(result.orphanStatus).toBe("BLOCKED");
  });
});

// ── NOT_ORPHANED ────────────────────────────────────────────────────

describe("NOT_ORPHANED", () => {
  it("classifies as NOT_ORPHANED when resource bindings exist and dormancy < 90", () => {
    const result = classify(signals({
      hasResourceBindings: true,
      dormancyDays: 45,
    }));
    expect(result.orphanStatus).toBe("NOT_ORPHANED");
    expect(result.recommendedAction).toBeNull();
  });

  it("classifies as NOT_ORPHANED when federated bindings exist and dormancy < 90", () => {
    const result = classify(signals({
      hasFederatedBindings: true,
      dormancyDays: 10,
    }));
    expect(result.orphanStatus).toBe("NOT_ORPHANED");
  });

  it("does NOT classify as NOT_ORPHANED when dormancy >= 90 even with bindings", () => {
    const result = classify(signals({
      hasResourceBindings: true,
      dormancyDays: 100,
    }));
    expect(result.orphanStatus).not.toBe("NOT_ORPHANED");
  });
});

// ── CAUTION ─────────────────────────────────────────────────────────

describe("CAUTION", () => {
  it("classifies as CAUTION when creds expired + active roles + dormant >= 90", () => {
    const result = classify(signals({
      secretsExpired: true,
      activeRoleCount: 3,
      dormancyDays: 120,
    }));
    expect(result.orphanStatus).toBe("CAUTION");
    expect(result.recommendedAction).toContain("Review role assignments");
    expect(result.activeRoleCount).toBe(3);
  });

  it("classifies as CAUTION with certsExpired too", () => {
    const result = classify(signals({
      certsExpired: true,
      activeRoleCount: 1,
      dormancyDays: 90,
    }));
    expect(result.orphanStatus).toBe("CAUTION");
  });

  it("does NOT classify as CAUTION when activeRoleCount is 0", () => {
    const result = classify(signals({
      secretsExpired: true,
      activeRoleCount: 0,
      dormancyDays: 120,
    }));
    expect(result.orphanStatus).not.toBe("CAUTION");
  });
});

// ── SAFE_TO_RETIRE ──────────────────────────────────────────────────

describe("SAFE_TO_RETIRE", () => {
  it("classifies as SAFE_TO_RETIRE when expired + no bindings + no roles", () => {
    const result = classify(signals({
      secretsExpired: true,
      hasResourceBindings: false,
      hasFederatedBindings: false,
      activeRoleCount: 0,
    }));
    expect(result.orphanStatus).toBe("SAFE_TO_RETIRE");
    expect(result.recommendedAction).toContain("Safe to disable");
  });

  it("classifies as SAFE_TO_RETIRE when dormant >= 90 + no bindings + no roles", () => {
    const result = classify(signals({
      dormancyDays: 100,
      hasResourceBindings: false,
      hasFederatedBindings: false,
      activeRoleCount: 0,
    }));
    expect(result.orphanStatus).toBe("SAFE_TO_RETIRE");
  });

  it("does NOT classify as SAFE_TO_RETIRE when resource bindings exist", () => {
    const result = classify(signals({
      secretsExpired: true,
      hasResourceBindings: true,
      activeRoleCount: 0,
    }));
    expect(result.orphanStatus).not.toBe("SAFE_TO_RETIRE");
  });

  it("does NOT classify as SAFE_TO_RETIRE when active roles exist", () => {
    const result = classify(signals({
      secretsExpired: true,
      hasResourceBindings: false,
      hasFederatedBindings: false,
      activeRoleCount: 2,
      dormancyDays: 120,
    }));
    // Should be CAUTION (creds expired + active roles + dormant)
    expect(result.orphanStatus).toBe("CAUTION");
  });
});

// ── UNKNOWN ─────────────────────────────────────────────────────────

describe("UNKNOWN", () => {
  it("classifies as UNKNOWN when no conditions match", () => {
    const result = classify(signals({
      dormancyDays: 30,
      hasResourceBindings: false,
      hasFederatedBindings: false,
      activeRoleCount: 0,
    }));
    expect(result.orphanStatus).toBe("UNKNOWN");
    expect(result.recommendedAction).toContain("Gather more lineage data");
  });

  it("classifies as UNKNOWN with default signals", () => {
    const result = classify(signals());
    expect(result.orphanStatus).toBe("UNKNOWN");
  });
});

// ── Reasons tracking ────────────────────────────────────────────────

describe("orphanReasons", () => {
  it("includes all applicable reasons", () => {
    const result = classify(signals({
      secretsExpired: true,
      dormancyDays: 120,
      activeRoleCount: 2,
    }));
    expect(result.orphanReasons).toContain("All client secrets expired");
    expect(result.orphanReasons).toContain("Dormant for 120 days");
    expect(result.orphanReasons).toContain("2 active (non-Reader) role(s)");
    expect(result.orphanReasons).toContain("No resource or federated bindings");
  });

  it("includes binding-present reasons when applicable", () => {
    const result = classify(signals({
      hasResourceBindings: true,
      hasFederatedBindings: true,
      dormancyDays: 10,
    }));
    expect(result.orphanReasons).toContain("Has resource bindings");
    expect(result.orphanReasons).toContain("Has federated credential bindings");
  });
});

// ── Priority cascade ────────────────────────────────────────────────

describe("cascade priority", () => {
  it("NOT_ORPHANED overrides SAFE_TO_RETIRE when bindings exist and dormancy < 90", () => {
    const result = classify(signals({
      secretsExpired: true,
      hasResourceBindings: true,
      dormancyDays: 45,
      activeRoleCount: 0,
    }));
    expect(result.orphanStatus).toBe("NOT_ORPHANED");
  });

  it("CAUTION overrides SAFE_TO_RETIRE when active roles present", () => {
    const result = classify(signals({
      secretsExpired: true,
      dormancyDays: 100,
      activeRoleCount: 1,
    }));
    expect(result.orphanStatus).toBe("CAUTION");
  });
});

// ── Module export test ──────────────────────────────────────────────

describe("module exports", () => {
  it("exports persistOrphanClassification", async () => {
    const mod = await import("../OrphanDetectionEngine");
    expect(typeof mod.persistOrphanClassification).toBe("function");
    expect(typeof mod.classifyOrphanStatus).toBe("function");
    expect(typeof mod.gatherSignals).toBe("function");
  });
});
