/**
 * LambdaRoleScanner unit tests.
 *
 *   1. Matches Lambda functions by execution_role_arn
 *   2. Returns correct synthetic resourceId format
 *   3. Includes runtime and memorySize in evidence
 *   4. Empty roleArn returns []
 *   5. No matching functions returns []
 */

import { describe, it, expect, vi } from "vitest";
import { scanLambdaForRole } from "../../aws/LambdaRoleScanner";

function mockPool(rows: unknown[]) {
  return {
    query: vi.fn().mockResolvedValue({ rows }),
  } as any;
}

describe("scanLambdaForRole", () => {
  const roleArn = "arn:aws:iam::123456789012:role/LambdaExecRole";
  const connectionId = "conn-1";

  it("returns bindings for matching Lambda functions", async () => {
    const db = mockPool([
      {
        resource_id: "arn:aws:lambda:us-east-1:123456789012:function:my-func",
        name: "my-func",
        region: "us-east-1",
        aws_account_id: "123456789012",
        runtime: "python3.11",
        memory_size: 256,
      },
    ]);

    const result = await scanLambdaForRole(db, roleArn, connectionId);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      resourceId: "lambda://123456789012/us-east-1/my-func",
      resourceType: "LambdaFunction",
      resourceName: "my-func",
      region: "us-east-1",
      bindingMethod: "ExecutionRole",
      confidenceScore: 95,
    });
    expect(result[0].bindingEvidence).toMatchObject({
      cloud: "aws",
      scanType: "LambdaExecutionRole",
      runtime: "python3.11",
      memorySize: 256,
    });
  });

  it("returns multiple matches", async () => {
    const db = mockPool([
      {
        resource_id: "arn:aws:lambda:us-east-1:123:function:func-a",
        name: "func-a",
        region: "us-east-1",
        aws_account_id: "123",
        runtime: "nodejs18.x",
        memory_size: 128,
      },
      {
        resource_id: "arn:aws:lambda:us-east-1:123:function:func-b",
        name: "func-b",
        region: "us-east-1",
        aws_account_id: "123",
        runtime: "python3.11",
        memory_size: 512,
      },
    ]);

    const result = await scanLambdaForRole(db, roleArn, connectionId);
    expect(result).toHaveLength(2);
    expect(result[0].resourceName).toBe("func-a");
    expect(result[1].resourceName).toBe("func-b");
  });

  it("returns [] for empty roleArn", async () => {
    const db = mockPool([]);
    const result = await scanLambdaForRole(db, "", connectionId);
    expect(result).toEqual([]);
    expect(db.query).not.toHaveBeenCalled();
  });

  it("returns [] when no functions match", async () => {
    const db = mockPool([]);
    const result = await scanLambdaForRole(db, roleArn, connectionId);
    expect(result).toEqual([]);
  });
});
