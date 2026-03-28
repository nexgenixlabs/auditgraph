/**
 * AppRegistrationMiner unit tests.
 *
 *   1. azurewebsites.net URL → AppService, confidence +20
 *   2. azurecontainerapps.io URL → ContainerApp, confidence +20
 *   3. custom domain → confidence +5
 *   4. localhost URLs are filtered out
 *   5. Full metadata with owners → high confidence
 *   6. No reply URLs → no bindings persisted
 *   7. Graph 404 → null (app not found)
 *   8. Owners fetch failure → gracefully returns empty owners
 */

import { describe, it, expect, vi } from "vitest";
import {
  classifyUrl,
  getAppRegistrationMetadata,
  type AppRegistrationMetadata,
} from "../AppRegistrationMiner";

// ── classifyUrl tests ───────────────────────────────────────────────

describe("classifyUrl", () => {
  it("classifies *.azurewebsites.net as AppService with +20 confidence", () => {
    const result = classifyUrl("https://my-app.azurewebsites.net/auth");
    expect(result.hostType).toBe("AppService");
    expect(result.confidenceBoost).toBe(20);
  });

  it("classifies *.azurecontainerapps.io as ContainerApp with +20 confidence", () => {
    const result = classifyUrl("https://my-ca.azurecontainerapps.io/callback");
    expect(result.hostType).toBe("ContainerApp");
    expect(result.confidenceBoost).toBe(20);
  });

  it("classifies custom domain with +5 confidence", () => {
    const result = classifyUrl("https://api.example.com/oauth2/callback");
    expect(result.hostType).toBe("CustomDomain");
    expect(result.confidenceBoost).toBe(5);
  });

  it("is case-insensitive", () => {
    const result = classifyUrl("https://MY-APP.AZUREWEBSITES.NET/auth");
    expect(result.hostType).toBe("AppService");
  });
});

// ── Mock Graph client ───────────────────────────────────────────────

function mockGraphClient(appResponse: object, ownersResponse?: object) {
  const apiMock = vi.fn().mockImplementation((path: string) => {
    const chain = {
      select: vi.fn().mockReturnThis(),
      get: vi.fn(),
    };
    if (path.includes("/owners")) {
      chain.get.mockResolvedValue(ownersResponse ?? { value: [] });
    } else {
      chain.get.mockResolvedValue(appResponse);
    }
    return chain;
  });
  return { api: apiMock };
}

function mockGraphClient404() {
  return {
    api: vi.fn().mockReturnValue({
      select: vi.fn().mockReturnThis(),
      get: vi.fn().mockRejectedValue(
        Object.assign(new Error("Not Found"), { statusCode: 404 })
      ),
    }),
  };
}

// ── getAppRegistrationMetadata tests ────────────────────────────────

describe("getAppRegistrationMetadata", () => {
  it("extracts full metadata with owners and inferred hosts", async () => {
    const client = mockGraphClient(
      {
        id: "app-obj-1",
        appId: "app-id-1",
        displayName: "My App",
        web: { redirectUris: ["https://my-app.azurewebsites.net/auth"] },
        publicClient: { redirectUris: [] },
        identifierUris: ["https://api.example.com"],
        notes: "Production deployment",
        description: "Main backend API",
        createdDateTime: "2024-01-15T10:00:00Z",
      },
      {
        value: [
          { id: "user-1", displayName: "Alice", userPrincipalName: "alice@example.com" },
        ],
      }
    );

    const result = await getAppRegistrationMetadata("app-obj-1", client as any);

    expect(result).not.toBeNull();
    expect(result!.appId).toBe("app-id-1");
    expect(result!.displayName).toBe("My App");
    expect(result!.replyUrls).toEqual(["https://my-app.azurewebsites.net/auth"]);
    expect(result!.identifierUris).toEqual(["https://api.example.com"]);
    expect(result!.notes).toBe("Production deployment");
    expect(result!.description).toBe("Main backend API");
    expect(result!.owners).toHaveLength(1);
    expect(result!.owners[0].upn).toBe("alice@example.com");
    expect(result!.inferredHostUrls).toHaveLength(2); // azurewebsites + custom domain
    // confidence: base 40 + owners 10 + notes 10 + AppService 20 + custom 5 = 85
    expect(result!.metadataConfidence).toBe(85);
  });

  it("filters out localhost URLs", async () => {
    const client = mockGraphClient({
      id: "app-obj-2",
      appId: "app-id-2",
      displayName: "Dev App",
      web: {
        redirectUris: [
          "http://localhost:3000/callback",
          "https://my-app.azurewebsites.net/auth",
          "http://127.0.0.1:8080/callback",
        ],
      },
      publicClient: { redirectUris: [] },
      identifierUris: [],
      createdDateTime: "2024-01-15T10:00:00Z",
    });

    const result = await getAppRegistrationMetadata("app-obj-2", client as any);

    expect(result).not.toBeNull();
    // Only the azurewebsites URL should survive (localhost filtered)
    expect(result!.inferredHostUrls).toHaveLength(1);
    expect(result!.inferredHostUrls[0].hostType).toBe("AppService");
  });

  it("returns null on Graph 404", async () => {
    const client = mockGraphClient404();
    const result = await getAppRegistrationMetadata("nonexistent", client as any);
    expect(result).toBeNull();
  });

  it("returns empty owners when owner fetch fails", async () => {
    const apiMock = vi.fn().mockImplementation((path: string) => {
      const chain = {
        select: vi.fn().mockReturnThis(),
        get: vi.fn(),
      };
      if (path.includes("/owners")) {
        chain.get.mockRejectedValue(new Error("Forbidden"));
      } else {
        chain.get.mockResolvedValue({
          id: "app-obj-3",
          appId: "app-id-3",
          displayName: "Restricted App",
          web: { redirectUris: [] },
          identifierUris: [],
          createdDateTime: "2024-01-15T10:00:00Z",
        });
      }
      return chain;
    });

    const result = await getAppRegistrationMetadata("app-obj-3", { api: apiMock } as any);

    expect(result).not.toBeNull();
    expect(result!.owners).toEqual([]);
  });

  it("returns null when appObjectId is empty", async () => {
    const client = mockGraphClient({});
    const result = await getAppRegistrationMetadata("", client as any);
    expect(result).toBeNull();
  });

  it("deduplicates URLs across web and identifierUris", async () => {
    const sharedUrl = "https://my-app.azurewebsites.net/auth";
    const client = mockGraphClient({
      id: "app-obj-4",
      appId: "app-id-4",
      displayName: "Dedup App",
      web: { redirectUris: [sharedUrl] },
      identifierUris: [sharedUrl],
      createdDateTime: "2024-01-15T10:00:00Z",
    });

    const result = await getAppRegistrationMetadata("app-obj-4", client as any);

    expect(result).not.toBeNull();
    // Should be deduplicated to 1
    expect(result!.inferredHostUrls).toHaveLength(1);
  });

  it("computes base confidence 40 when no owners, notes, or hosts", async () => {
    const client = mockGraphClient({
      id: "app-obj-5",
      appId: "app-id-5",
      displayName: "Bare App",
      web: { redirectUris: [] },
      identifierUris: [],
      createdDateTime: "2024-01-15T10:00:00Z",
    });

    const result = await getAppRegistrationMetadata("app-obj-5", client as any);

    expect(result).not.toBeNull();
    expect(result!.metadataConfidence).toBe(40);
  });
});
