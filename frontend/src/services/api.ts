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
  } catch (error) {
    console.error('Failed to fetch identity:', error);
    throw error;
  }
};

export default api;
