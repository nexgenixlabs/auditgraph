/**
 * Host-based portal detection utility.
 *
 * Supports multi-level subdomains like dev.admin.auditgraph.ai
 * by checking if any segment of the hostname is 'admin',
 * rather than only checking the first segment.
 */
export function isAdminHost(): boolean {
  const hostname = window.location.hostname;
  if (hostname === 'localhost' || hostname === '127.0.0.1') return false;
  return hostname.split('.').includes('admin');
}
