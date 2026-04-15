/**
 * AuditGraph Shared API Client
 *
 * Centralizes all HTTP calls through typed helpers.
 * Uses the global fetch (which AuthContext patches with Bearer token).
 *
 * Usage:
 *   import { api } from '../services/apiClient';
 *   const data = await api.get<StatsResponse>('/stats');
 *   await api.post('/runs/trigger', { connection_id: 1 });
 */

const BASE = '/api';

export class ApiError extends Error {
  status: number;
  body: any;
  constructor(status: number, body: any) {
    super(typeof body?.error === 'string' ? body.error : `API error ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

async function request<T = any>(
  method: string,
  path: string,
  body?: any,
  opts?: RequestInit,
): Promise<T> {
  const url = path.startsWith('/api') ? path : `${BASE}${path.startsWith('/') ? '' : '/'}${path}`;
  const init: RequestInit = {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json', ...opts?.headers } : { ...opts?.headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    ...opts,
    // Restore headers after spread so body-based Content-Type isn't overridden
  };
  // Re-apply headers in case opts spread overwrote them
  if (body !== undefined) {
    init.headers = { 'Content-Type': 'application/json', ...opts?.headers };
  }

  const res = await fetch(url, init);

  if (!res.ok) {
    let errBody: any;
    try { errBody = await res.json(); } catch { errBody = { error: res.statusText }; }
    throw new ApiError(res.status, errBody);
  }

  // 204 No Content
  if (res.status === 204) return undefined as unknown as T;

  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return res.json() as Promise<T>;
  }
  return res.text() as unknown as T;
}

export const api = {
  get:    <T = any>(path: string, opts?: RequestInit) => request<T>('GET', path, undefined, opts),
  post:   <T = any>(path: string, body?: any, opts?: RequestInit) => request<T>('POST', path, body, opts),
  put:    <T = any>(path: string, body?: any, opts?: RequestInit) => request<T>('PUT', path, body, opts),
  patch:  <T = any>(path: string, body?: any, opts?: RequestInit) => request<T>('PATCH', path, body, opts),
  del:    <T = any>(path: string, opts?: RequestInit) => request<T>('DELETE', path, undefined, opts),
};

export default api;
