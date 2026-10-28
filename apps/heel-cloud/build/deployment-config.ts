// SPDX-License-Identifier: LicenseRef-Heel-Commercial

const VPC_SERVICE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// WHATWG URL parses a host whose last label looks numeric (decimal or 0x hex) as IPv4.
const NUMERIC_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/;
const LOCAL_ONLY_SUFFIXES = ['localhost', 'local', 'internal'];

/**
 * The one canonical public origin `https://H`, shared by the build and the Worker: lowercase
 * ASCII DNS H with two or more labels, no port, path, query, fragment, userinfo, IP spelling or
 * local-only suffix, spelled exactly as the URL parser serializes it. Syntax only, not ownership.
 */
export function canonicalPublicOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || !value.startsWith('https://')) return null;
  const host = value.slice('https://'.length);
  const labels = host.split('.');
  if (
    host.length > 253
    || labels.length < 2
    || !labels.every((label) => DNS_LABEL.test(label))
    || NUMERIC_LABEL.test(labels[labels.length - 1])
    || LOCAL_ONLY_SUFFIXES.includes(labels[labels.length - 1])
  ) return null;
  try {
    const parsed = new URL(value);
    return parsed.origin === value && parsed.hostname === host ? value : null;
  } catch {
    return null;
  }
}

export function deploymentConfig(env: Record<string, string | undefined>, command: string) {
  const mode = env.HEEL_DEPLOYMENT_MODE?.trim() ?? 'full';
  const service = env.HEEL_CONTROL_PLANE_VPC_SERVICE_ID?.trim();
  const origin = env.HEEL_PUBLIC_ORIGIN;
  if (!['full', 'local_review'].includes(mode)) throw new Error('Unknown Heel deployment mode');
  if (mode === 'local_review' && service) throw new Error('Local review cannot bind a private control plane');
  if (command === 'build') {
    if (mode === 'full' && !VPC_SERVICE_ID.test(service ?? '')) {
      throw new Error('HEEL_CONTROL_PLANE_VPC_SERVICE_ID must be a Cloudflare VPC service UUID for production builds');
    }
    if (canonicalPublicOrigin(origin) === null) {
      throw new Error('HEEL_PUBLIC_ORIGIN must be one canonical HTTPS origin for production builds');
    }
  }
  const vars: Record<string, string> = {};
  if (origin !== undefined) vars.PUBLIC_ORIGIN = origin;
  return {
    vars,
    vpc_services: mode === 'local_review' || service === undefined
      ? [] : [{ binding: 'CONTROL_PLANE', service_id: service }],
  };
}
