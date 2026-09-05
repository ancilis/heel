// SPDX-License-Identifier: LicenseRef-Heel-Commercial
import { describe, expect, it } from 'vitest';
import { deploymentConfig } from '../build/deployment-config';

const origin = 'https://heel-agent-first-private.hellostella.chatgpt.site';
const service = '00000000-0000-4000-8000-000000000001';
describe('deployment boundaries', () => {
  it('requires the private service for the default production mode', () => {
    expect(() => deploymentConfig({ HEEL_PUBLIC_ORIGIN: origin }, 'build')).toThrow(/VPC service/);
  });
  it('binds only the configured service in full deployment mode', () => {
    expect(deploymentConfig({ HEEL_PUBLIC_ORIGIN: origin, HEEL_CONTROL_PLANE_VPC_SERVICE_ID: service }, 'build'))
      .toEqual({ vars: { PUBLIC_ORIGIN: origin }, vpc_services: [{ binding: 'CONTROL_PLANE', service_id: service }] });
  });
  it('provides no private service capability in explicit local-review mode', () => {
    expect(deploymentConfig({ HEEL_PUBLIC_ORIGIN: origin, HEEL_DEPLOYMENT_MODE: 'local_review' }, 'build'))
      .toEqual({ vars: { PUBLIC_ORIGIN: origin }, vpc_services: [] });
  });
  it('rejects ambiguous local-review configuration', () => {
    expect(() => deploymentConfig({ HEEL_PUBLIC_ORIGIN: origin, HEEL_DEPLOYMENT_MODE: 'local_review', HEEL_CONTROL_PLANE_VPC_SERVICE_ID: service }, 'build')).toThrow(/cannot bind/);
  });
  it('rejects invalid modes and noncanonical origins', () => {
    expect(() => deploymentConfig({ HEEL_DEPLOYMENT_MODE: 'typo' }, 'build')).toThrow(/mode/);
    for (const invalid of ['http://localhost', origin + '/path', origin + '/']) {
      expect(() => deploymentConfig({ HEEL_PUBLIC_ORIGIN: invalid, HEEL_DEPLOYMENT_MODE: 'local_review' }, 'build')).toThrow(/canonical HTTPS/);
    }
  });
});
