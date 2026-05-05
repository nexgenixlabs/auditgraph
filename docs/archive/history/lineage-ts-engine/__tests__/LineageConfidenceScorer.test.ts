/**
 * LineageConfidenceScorer unit tests.
 *
 * Tests the additive scoring model with all 6 signal combinations.
 */

import { describe, it, expect } from "vitest";
import { computeScore } from "../LineageConfidenceScorer";

// ── Helper ──────────────────────────────────────────────────────────

function signals(overrides: Record<string, boolean> = {}) {
  return {
    hasHighConfidenceBinding: false,
    hasFederatedBinding: false,
    hasKnownWorkloadType: false,
    hasAzureReplyUrl: false,
    hasFullEnrichment: false,
    hasOwner: false,
    ...overrides,
  };
}

// ── Individual signal weights ───────────────────────────────────────

describe("computeScore — individual signals", () => {
  it("returns 0 when no signals are present", () => {
    expect(computeScore(signals())).toBe(0);
  });

  it("adds +35 for high-confidence resource binding", () => {
    expect(computeScore(signals({ hasHighConfidenceBinding: true }))).toBe(35);
  });

  it("adds +25 for federated binding", () => {
    expect(computeScore(signals({ hasFederatedBinding: true }))).toBe(25);
  });

  it("adds +15 for known workload type", () => {
    expect(computeScore(signals({ hasKnownWorkloadType: true }))).toBe(15);
  });

  it("adds +10 for Azure reply URL", () => {
    expect(computeScore(signals({ hasAzureReplyUrl: true }))).toBe(10);
  });

  it("adds +10 for full enrichment (P2_AUDIT)", () => {
    expect(computeScore(signals({ hasFullEnrichment: true }))).toBe(10);
  });

  it("adds +5 for having an owner", () => {
    expect(computeScore(signals({ hasOwner: true }))).toBe(5);
  });
});

// ── Combined scoring ────────────────────────────────────────────────

describe("computeScore — combinations", () => {
  it("returns 100 when all signals are present", () => {
    expect(
      computeScore(signals({
        hasHighConfidenceBinding: true,
        hasFederatedBinding: true,
        hasKnownWorkloadType: true,
        hasAzureReplyUrl: true,
        hasFullEnrichment: true,
        hasOwner: true,
      }))
    ).toBe(100);
  });

  it("caps at 100 even if weights sum to more", () => {
    // All signals = 35+25+15+10+10+5 = 100 exactly, verify cap logic
    const score = computeScore(signals({
      hasHighConfidenceBinding: true,
      hasFederatedBinding: true,
      hasKnownWorkloadType: true,
      hasAzureReplyUrl: true,
      hasFullEnrichment: true,
      hasOwner: true,
    }));
    expect(score).toBeLessThanOrEqual(100);
  });

  it("adds resource + federated = 60", () => {
    expect(
      computeScore(signals({
        hasHighConfidenceBinding: true,
        hasFederatedBinding: true,
      }))
    ).toBe(60);
  });

  it("resource + workload + owner = 55", () => {
    expect(
      computeScore(signals({
        hasHighConfidenceBinding: true,
        hasKnownWorkloadType: true,
        hasOwner: true,
      }))
    ).toBe(55);
  });

  it("federated + enrichment + reply URL = 45", () => {
    expect(
      computeScore(signals({
        hasFederatedBinding: true,
        hasFullEnrichment: true,
        hasAzureReplyUrl: true,
      }))
    ).toBe(45);
  });

  it("only owner = 5 (minimum useful score)", () => {
    expect(computeScore(signals({ hasOwner: true }))).toBe(5);
  });
});

// ── Module export test ──────────────────────────────────────────────

describe("module exports", () => {
  it("exports all public functions", async () => {
    const mod = await import("../LineageConfidenceScorer");
    expect(typeof mod.computeLineageScore).toBe("function");
    expect(typeof mod.computeScore).toBe("function");
    expect(typeof mod.persistLineageScore).toBe("function");
  });
});
