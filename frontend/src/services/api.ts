// frontend/src/services/api.ts
import axios from 'axios';
import { Identity } from '../types';

const API_BASE =
  process.env.REACT_APP_API_BASE_URL ||
  'http://localhost:5001/api';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const getStats = async () => {
  const res = await api.get('/stats');
  return res.data;
};

export const getRisks = async () => {
  const res = await api.get('/risks');
  return res.data;
};

export const getIdentities = async () => {
  const res = await api.get('/identities');
  return res.data;
};

/**
 * IMPORTANT:
 * Backend returns:
 *  { identity: {...}, roles: [...] }
 * UI expects roles under identity.roles
 * So we merge roles into the identity object here.
 */
export const getIdentity = async (identityId: string): Promise<Identity> => {
  const res = await api.get(`/identities/${identityId}`);
  const payload = res.data;

  // Backward/forward compatible:
  // - if backend already embeds roles inside identity, keep it
  // - else merge payload.roles into identity.roles
  const identity: Identity = payload?.identity ?? payload;

  const roles = identity?.roles ?? payload?.roles ?? [];

  return {
    ...identity,
    roles,
    role_count:
      typeof identity?.role_count === 'number'
        ? identity.role_count
        : Array.isArray(roles)
          ? roles.length
          : 0,
  };
};

export default api;
