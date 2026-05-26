/**
 * ECSTaskDefScanner unit tests.
 *
 *   1. Matches taskRoleArn
 *   2. Matches executionRoleArn
 *   3. Matches both taskRoleArn and executionRoleArn (2 bindings)
 *   4. Partial failure: DescribeTaskDefinition failure for one family
 *   5. Empty roleArn returns []
 *   6. No families returns []
 */

import { describe, it, expect, vi } from "vitest";
import { scanECSTaskDefs } from "../../aws/ECSTaskDefScanner";

// ── Mock ECS client ─────────────────────────────────────────────────

function mockECSClient(
  families: string[],
  taskDefs: Record<string, { taskRoleArn?: string; executionRoleArn?: string }>
) {
  return {
    send: vi.fn().mockImplementation((cmd: any) => {
      const cmdName = cmd.constructor.name;

      if (cmdName === "ListTaskDefinitionFamiliesCommand") {
        return { families, nextToken: undefined };
      }

      if (cmdName === "DescribeTaskDefinitionCommand") {
        const family = cmd.input.taskDefinition;
        const def = taskDefs[family];
        if (!def) {
          throw new Error(`Task definition ${family} not found`);
        }
        return {
          taskDefinition: {
            taskDefinitionArn: `arn:aws:ecs:us-east-1:123:task-definition/${family}:1`,
            taskRoleArn: def.taskRoleArn,
            executionRoleArn: def.executionRoleArn,
            revision: 1,
          },
        };
      }

      return {};
    }),
  } as any;
}

describe("scanECSTaskDefs", () => {
  const roleArn = "arn:aws:iam::123456789012:role/MyECSRole";
  const accountId = "123456789012";
  const region = "us-east-1";

  it("matches taskRoleArn", async () => {
    const client = mockECSClient(["my-service"], {
      "my-service": { taskRoleArn: roleArn, executionRoleArn: "other" },
    });

    const result = await scanECSTaskDefs(client, roleArn, accountId, region);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      resourceId: "ecs://123456789012/us-east-1/my-service",
      resourceType: "ECSTaskDefinition",
      resourceName: "my-service",
      bindingMethod: "TaskRole",
      confidenceScore: 95,
    });
  });

  it("matches executionRoleArn", async () => {
    const client = mockECSClient(["my-service"], {
      "my-service": { taskRoleArn: "other", executionRoleArn: roleArn },
    });

    const result = await scanECSTaskDefs(client, roleArn, accountId, region);
    expect(result).toHaveLength(1);
    expect(result[0].bindingMethod).toBe("ExecutionRole");
  });

  it("produces 2 bindings when both match", async () => {
    const client = mockECSClient(["dual-role"], {
      "dual-role": { taskRoleArn: roleArn, executionRoleArn: roleArn },
    });

    const result = await scanECSTaskDefs(client, roleArn, accountId, region);
    expect(result).toHaveLength(2);
    const methods = result.map((b) => b.bindingMethod).sort();
    expect(methods).toEqual(["ExecutionRole", "TaskRole"]);
  });

  it("handles partial failure gracefully", async () => {
    const client = {
      send: vi.fn().mockImplementation((cmd: any) => {
        const cmdName = cmd.constructor.name;
        if (cmdName === "ListTaskDefinitionFamiliesCommand") {
          return { families: ["good", "bad"], nextToken: undefined };
        }
        if (cmdName === "DescribeTaskDefinitionCommand") {
          if (cmd.input.taskDefinition === "bad") {
            throw new Error("AccessDenied");
          }
          return {
            taskDefinition: {
              taskDefinitionArn: "arn:aws:ecs:us-east-1:123:task-definition/good:1",
              taskRoleArn: roleArn,
              executionRoleArn: "other",
              revision: 1,
            },
          };
        }
        return {};
      }),
    } as any;

    const result = await scanECSTaskDefs(client, roleArn, accountId, region);
    // Only "good" should produce a binding, "bad" silently skipped
    expect(result).toHaveLength(1);
    expect(result[0].resourceName).toBe("good");
  });

  it("returns [] for empty roleArn", async () => {
    const client = mockECSClient([], {});
    const result = await scanECSTaskDefs(client, "", accountId, region);
    expect(result).toEqual([]);
  });

  it("returns [] when no families exist", async () => {
    const client = mockECSClient([], {});
    const result = await scanECSTaskDefs(client, roleArn, accountId, region);
    expect(result).toEqual([]);
  });
});
