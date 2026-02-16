/**
 * Masks a credential string, keeping the first portion visible and replacing the last 8 chars.
 * Client secrets are fully masked.
 */
export function maskCredential(value: string, fullyMask = false): string {
  if (!value) return value;
  if (fullyMask || value.length <= 8) return '\u2022'.repeat(16);
  return value.slice(0, value.length - 8) + '\u2022'.repeat(8);
}
