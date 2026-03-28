/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * EKSWorkloadScanner — discovers EKS workloads bound to an IAM role
 * by querying the Kubernetes API for service accounts annotated with
 * `eks.amazonaws.com/role-arn`.
 *
 * AWS APIs (live — no cached table):
 *   eks:ListClusters → cluster names
 *   eks:DescribeCluster → endpoint, CA cert, OIDC issuer
 *   Kubernetes API (via EKS bearer token):
 *     GET /api/v1/serviceaccounts (all namespaces)
 *     Filter: metadata.annotations["eks.amazonaws.com/role-arn"] == roleArn
 *
 * EKS bearer token: presigned STS GetCallerIdentity URL with
 * x-k8s-aws-id header, base64url-encoded with k8s-aws-v1. prefix.
 *
 * Edge cases:
 *   - EKS cluster not accessible (403) → log warn, skip cluster
 *   - No service accounts with annotation → []
 *   - Cluster with no OIDC issuer configured → skip
 */

import type { EKSClient } from "@aws-sdk/client-eks";
import {
  ListClustersCommand,
  DescribeClusterCommand,
} from "@aws-sdk/client-eks";
import { SignatureV4 } from "@smithy/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";
import { HttpRequest } from "@smithy/protocol-http";
import https from "node:https";

import type {
  EKSWorkloadBinding,
  ResourceBinding,
  K8sServiceAccountItem,
  K8sServiceAccountList,
  K8sServiceAccountFetcher,
} from "./types";

// ── Internal types ──────────────────────────────────────────────────

interface EKSClusterDetail {
  clusterName: string;
  clusterArn: string;
  endpoint: string;
  caCertBase64: string;
  oidcIssuer: string;
}

// ── Module-level cluster cache ──────────────────────────────────────
// Avoids redundant ListClusters+DescribeCluster when scanning many
// identities in the same region during a single orchestrator run.

let _clusterCache: {
  region: string;
  clusters: EKSClusterDetail[];
  ts: number;
} | null = null;

const CLUSTER_CACHE_TTL_MS = 60_000;

/** Clear the cluster cache. Call at scan start. */
export function clearClusterCache(): void {
  _clusterCache = null;
}

// ── EKS bearer token generation ─────────────────────────────────────

/**
 * Generate an EKS-compatible bearer token by presigning an STS
 * GetCallerIdentity request with the x-k8s-aws-id header.
 */
async function generateEKSToken(
  clusterName: string,
  region: string,
  credentials: { accessKeyId: string; secretAccessKey: string; sessionToken?: string }
): Promise<string> {
  const signer = new SignatureV4({
    service: "sts",
    region,
    credentials,
    sha256: Sha256,
  });

  const request = new HttpRequest({
    method: "GET",
    protocol: "https:",
    hostname: `sts.${region}.amazonaws.com`,
    path: "/",
    query: {
      Action: "GetCallerIdentity",
      Version: "2011-06-15",
    },
    headers: {
      host: `sts.${region}.amazonaws.com`,
      "x-k8s-aws-id": clusterName,
    },
  });

  const signed = await signer.presign(request, { expiresIn: 60 });

  // Reconstruct the presigned URL
  const queryParts: string[] = [];
  for (const [key, value] of Object.entries(signed.query ?? {})) {
    const vals = Array.isArray(value) ? value : [value];
    for (const v of vals) {
      queryParts.push(
        `${encodeURIComponent(key)}=${encodeURIComponent(v)}`
      );
    }
  }
  const url = `https://${signed.hostname}${signed.path}?${queryParts.join("&")}`;

  return `k8s-aws-v1.${Buffer.from(url).toString("base64url")}`;
}

// ── Kubernetes API helper ───────────────────────────────────────────

/**
 * Fetch all service accounts from the K8s API across all namespaces.
 * Returns [] on any error (403, timeout, parse failure).
 */
async function defaultFetchK8sServiceAccounts(
  endpoint: string,
  token: string,
  caCertBase64: string
): Promise<K8sServiceAccountItem[]> {
  return new Promise((resolve) => {
    const ca = Buffer.from(caCertBase64, "base64");
    const url = new URL("/api/v1/serviceaccounts", endpoint);

    const req = https.get(
      url,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
        },
        ca,
        rejectUnauthorized: true,
      },
      (res) => {
        if (res.statusCode !== 200) {
          // 403, 401, etc. — non-fatal, skip cluster
          res.resume();
          resolve([]);
          return;
        }
        let data = "";
        res.on("data", (chunk: Buffer) => {
          data += chunk.toString();
        });
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data) as K8sServiceAccountList;
            resolve(parsed.items ?? []);
          } catch {
            resolve([]);
          }
        });
      }
    );

    req.on("error", () => resolve([]));
    req.setTimeout(10_000, () => {
      req.destroy();
      resolve([]);
    });
  });
}

// ── Cluster discovery ───────────────────────────────────────────────

/**
 * Discover all EKS clusters with OIDC issuers in the given region.
 * Uses module-level cache to avoid redundant API calls within a scan.
 */
async function discoverClusters(
  eksClient: EKSClient,
  region: string
): Promise<EKSClusterDetail[]> {
  // Check cache
  if (
    _clusterCache &&
    _clusterCache.region === region &&
    Date.now() - _clusterCache.ts < CLUSTER_CACHE_TTL_MS
  ) {
    return _clusterCache.clusters;
  }

  // List all cluster names (paginated)
  const clusterNames: string[] = [];
  let nextToken: string | undefined;
  do {
    const listResp = await eksClient.send(
      new ListClustersCommand({ nextToken })
    );
    if (listResp.clusters) {
      clusterNames.push(...listResp.clusters);
    }
    nextToken = listResp.nextToken;
  } while (nextToken);

  // Describe each cluster to get endpoint, CA, OIDC issuer
  const clusters: EKSClusterDetail[] = [];
  for (const name of clusterNames) {
    try {
      const descResp = await eksClient.send(
        new DescribeClusterCommand({ name })
      );
      const cluster = descResp.cluster;
      if (!cluster) continue;

      const endpoint = cluster.endpoint;
      const caCert = cluster.certificateAuthority?.data;
      const oidcIssuer = cluster.identity?.oidc?.issuer;
      const clusterArn = cluster.arn ?? "";

      // Skip clusters without OIDC issuer — no IRSA possible
      if (!endpoint || !caCert || !oidcIssuer) continue;

      clusters.push({
        clusterName: name,
        clusterArn,
        endpoint,
        caCertBase64: caCert,
        oidcIssuer,
      });
    } catch {
      // 403, AccessDenied, etc. — skip cluster
    }
  }

  // Cache the result
  _clusterCache = { region, clusters, ts: Date.now() };
  return clusters;
}

// ── Main scanner ────────────────────────────────────────────────────

/**
 * Scan all EKS clusters in the region for service accounts annotated
 * with `eks.amazonaws.com/role-arn` matching the given roleArn.
 *
 * @param roleArn     IAM role ARN to search for in SA annotations
 * @param eksClient   Configured EKS SDK client
 * @param region      AWS region to scan
 * @param fetchSAs    Optional K8s SA fetcher (for testing)
 */
export async function scanEKSWorkloads(
  roleArn: string,
  eksClient: EKSClient,
  region: string,
  fetchSAs: K8sServiceAccountFetcher = defaultFetchK8sServiceAccounts
): Promise<EKSWorkloadBinding[]> {
  if (!roleArn) return [];

  const bindings: EKSWorkloadBinding[] = [];

  // 1. Discover clusters (cached within a scan)
  const clusters = await discoverClusters(eksClient, region);
  if (clusters.length === 0) return [];

  // 2. Resolve credentials for EKS token generation
  const credentials = await eksClient.config.credentials();

  // 3. For each cluster: generate token, query K8s API, filter SAs
  for (const cluster of clusters) {
    try {
      const token = await generateEKSToken(
        cluster.clusterName,
        region,
        credentials
      );

      const serviceAccounts = await fetchSAs(
        cluster.endpoint,
        token,
        cluster.caCertBase64
      );

      for (const sa of serviceAccounts) {
        const annotatedRole =
          sa.metadata?.annotations?.["eks.amazonaws.com/role-arn"];
        if (annotatedRole === roleArn) {
          bindings.push({
            clusterName: cluster.clusterName,
            clusterArn: cluster.clusterArn,
            namespace: sa.metadata.namespace,
            serviceAccount: sa.metadata.name,
            oidcIssuer: cluster.oidcIssuer,
            roleArn,
            confidenceScore: 95,
          });
        }
      }
    } catch {
      // Non-fatal: cluster 403, timeout, token failure — skip
    }
  }

  return bindings;
}

// ── Persistence helpers ─────────────────────────────────────────────

/**
 * Convert an EKSWorkloadBinding to a ResourceBinding for upsert.
 */
export function eksWorkloadToResourceBinding(
  binding: EKSWorkloadBinding
): ResourceBinding {
  return {
    resourceId: `eks://${binding.clusterArn}/${binding.namespace}/${binding.serviceAccount}`,
    resourceType: "AWSEKSWorkload",
    resourceName: `${binding.clusterName}/${binding.namespace}:${binding.serviceAccount}`,
    resourceGroup: "",
    region: "",
    bindingMethod: "WorkloadIdentityAnnotation",
    bindingEvidence: { ...binding, cloud: "aws" },
    confidenceScore: binding.confidenceScore,
  };
}
