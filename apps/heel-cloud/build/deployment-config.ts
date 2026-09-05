// SPDX-License-Identifier: LicenseRef-Heel-Commercial

const VPC_SERVICE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function deploymentConfig(env: Record<string, string | undefined>, command: string) {
  const mode = env.HEEL_DEPLOYMENT_MODE?.trim() ?? 'full';
  const service = env.HEEL_CONTROL_PLANE_VPC_SERVICE_ID?.trim();
  const origin = env.HEEL_PUBLIC_ORIGIN?.trim();
  if (!['full', 'local_review'].includes(mode)) throw new Error('Unknown Heel deployment mode');
  if (mode === 'local_review' && service) throw new Error('Local review cannot bind a private control plane');
  if (command === 'build') {
    if (mode === 'full' && !VPC_SERVICE_ID.test(service ?? '')) {
      throw new Error('HEEL_CONTROL_PLANE_VPC_SERVICE_ID must be a Cloudflare VPC service UUID for production builds');
    }
    let valid = false;
    try {
      const parsed = new URL(origin ?? '');
      valid = parsed.protocol === 'https:' && parsed.origin === origin;
    } catch { /* Invalid origins fail closed below. */ }
    if (!valid) throw new Error('HEEL_PUBLIC_ORIGIN must be one canonical HTTPS origin for production builds');
  }
  const vars: Record<string, string> = {};
  if (origin !== undefined) vars.PUBLIC_ORIGIN = origin;
  return {
    vars,
    vpc_services: mode === 'local_review' || service === undefined
      ? [] : [{ binding: 'CONTROL_PLANE', service_id: service }],
  };
}
