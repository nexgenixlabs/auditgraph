/**
 * AuditGraph API Client Service
 *
 * This module provides typed functions for communicating with the Flask backend
 * REST API. All functions return Promises and handle error logging.
 *
 * API Functions:
 *   - getStats(): Fetch dashboard statistics from latest snapshot
 *   - getRisks(): Fetch high-risk identities requiring attention
 *   - getIdentities(): Fetch all identities from latest snapshot
 *   - getIdentity(id): Fetch detailed info for a single identity
 *
 * Configuration:
 *   - Base URL: Set via REACT_APP_API_BASE_URL env var, defaults to localhost:5001/api
 *   - Content-Type: application/json
 *
 * Response Transformation:
 *   The getIdentity function performs response transformation to merge
 *   roles and graph_permissions into the identity object, as the backend
 *   returns these as separate arrays in the response payload.
 *
 * Error Handling:
 *   All functions log errors to console and re-throw for caller handling.
 *   The UI components handle errors by displaying appropriate error states.
 */
import axios from 'axios';
import { Identity } from '../types';

/**
 * Base URL for API requests.
 * Defaults to localhost:5001/api for local development.
 */
const API_BASE =
  process.env.REACT_APP_API_BASE_URL ||
  '/api';

/**
 * Axios instance configured for AuditGraph API requests.
 */
const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const getStats = async () => {
  try {
    const res = await api.get('/stats');
    return res.data;
  } catch (error) {
    console.error('Failed to fetch stats:', error);
    throw error;
  }
};

export const getRisks = async () => {
  try {
    const res = await api.get('/risks');
    return res.data;
  } catch (error) {
    console.error('Failed to fetch risks:', error);
    throw error;
  }
};

export const getIdentities = async () => {
  try {
    const res = await api.get('/identities');
    return res.data;
  } catch (error) {
    console.error('Failed to fetch getIdentities:', error);
    throw error;
  }
};

/**
 * IMPORTANT:
 * Backend returns:
 *  { identity: {...}, roles: [...] }
 * UI expects roles under identity.roles
 * So we merge roles into the identity object here.
 */
export const getIdentity = async (identityId: string): Promise<Identity> => {
  try {
    const res = await api.get(`/identities/${identityId}`);
    const payload = res.data;
    
    // Extract identity, roles, and graph_permissions
    const identity: Identity = payload?.identity ?? payload;
    const roles = identity?.roles ?? payload?.roles ?? [];
    const graph_permissions = identity?.graph_permissions ?? payload?.graph_permissions ?? [];
    
    console.log('API: Full payload:', payload);
    console.log('API: graph_permissions extracted:', graph_permissions);
    
    return {
      ...identity,
      roles,
      graph_permissions,
      role_count:
        typeof identity?.role_count === 'number'
          ? identity.role_count
          : Array.isArray(roles)
            ? roles.length
            : 0,
    };
  } catch (error) {
    console.error('Failed to fetch identity:', error);
    throw error;
  }
};

// Phase 39: Advanced Query Builder

export const queryIdentities = async (
  groups: Array<{ conditions: Array<{ field: string; operator: string; value: any }> }>,
  sortField?: string,
  sortDirection?: string,
  limit?: number,
  offset?: number,
) => {
  try {
    const body: any = { groups };
    if (sortField) body.sort_field = sortField;
    if (sortDirection) body.sort_direction = sortDirection;
    if (limit) body.limit = limit;
    if (offset) body.offset = offset;
    const res = await api.post('/identities/query', body);
    return res.data;
  } catch (error) {
    console.error('Failed to query identities:', error);
    throw error;
  }
};

export const getQueryFields = async () => {
  try {
    const res = await api.get('/identities/query/fields');
    return res.data;
  } catch (error) {
    console.error('Failed to fetch query fields:', error);
    throw error;
  }
};

// ── Snapshot API wrappers (frontend-only terminology layer) ──────
// Backend routes are /api/runs — these wrappers provide snapshot-aligned naming.

/** Fetch all snapshots. Wraps GET /api/runs */
export const getSnapshots = async () => {
  try {
    const res = await api.get('/runs');
    return res.data;
  } catch (error) {
    console.error('Failed to fetch snapshots:', error);
    throw error;
  }
};

/** Trigger a new snapshot capture. Wraps POST /api/runs/trigger */
export const triggerSnapshot = async () => {
  try {
    const res = await api.post('/runs/trigger');
    return res.data;
  } catch (error) {
    console.error('Failed to trigger snapshot:', error);
    throw error;
  }
};

/** Fetch a single snapshot's drift report. Wraps GET /api/runs/:id/drift */
export const getSnapshotById = async (snapshotId: number) => {
  try {
    const res = await api.get(`/runs/${snapshotId}/drift`);
    return res.data;
  } catch (error) {
    console.error('Failed to fetch snapshot:', error);
    throw error;
  }
};

/** @deprecated Use getSnapshots() instead */
export const getRuns = getSnapshots;

export default api;
