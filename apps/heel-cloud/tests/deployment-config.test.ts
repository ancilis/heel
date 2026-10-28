// SPDX-License-Identifier: LicenseRef-Heel-Commercial
import { describe, expect, it } from 'vitest';
import { canonicalPublicOrigin, deploymentConfig } from '../build/deployment-config';

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
  it('rejects a full build whose private service id is not a VPC service UUID', () => {
    for (const invalid of ['', 'not-a-uuid', '00000000-0000-0000-8000-000000000001', `${service}0`]) {
      expect(() => deploymentConfig({ HEEL_PUBLIC_ORIGIN: origin, HEEL_CONTROL_PLANE_VPC_SERVICE_ID: invalid }, 'build')).toThrow(/VPC service/);
    }
  });
});

// Reserved example/test names are syntax fixtures only; acceptance is not evidence of domain ownership.
const accepted = [
  'https://heel.example',
  'https://control-two.heel.test',
  origin,
  'https://xn--bcher-kva.example',
  'https://a1.b2',
  `https://${'a'.repeat(63)}.example`,
  `https://${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`,
];
const refused = [
  '', ' ', 'https://', 'https://heel.example ', ' https://heel.example', 'https://heel.example\n', '\thttps://heel.example',
  'HTTPS://heel.example', 'Https://heel.example', 'https://Heel.example', 'https://HEEL.EXAMPLE',
  'http://heel.example', 'http://localhost', 'http://127.0.0.1:8787', 'wss://heel.example', 'https:heel.example', 'https:/heel.example', 'https:///heel.example',
  'https://heel.example/', 'https://heel.example/path', 'https://heel.example/..', 'https://heel.example?', 'https://heel.example?x=1', 'https://heel.example#', 'https://heel.example#x',
  'https://user@heel.example', 'https://user:pass@heel.example', 'https://@heel.example',
  'https://heel.example:443', 'https://heel.example:8443', 'https://heel.example:',
  'https://127.0.0.1', 'https://1.2.3.4', 'https://127.1', 'https://2130706433', 'https://0x7f000001', 'https://0x7f.0.0.1', 'https://017700000001',
  'https://heel.123', 'https://heel.0x1', 'https://heel.0X1', 'https://[::1]', 'https://[2001:db8::1]', 'https://[::ffff:127.0.0.1]',
  'https://heel', 'https://.example', 'https://heel..example', 'https://heel.example.', 'https://heel.example..',
  `https://${'a'.repeat(64)}.example`, `https://${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}`,
  'https://-heel.example', 'https://heel-.example', 'https://heel.-example', 'https://heel.example-', 'https://heel_ingress.example',
  'https://heel\\example.com', 'https://heel.example\\', 'https://heel%2eexample', 'https://heel.ex%61mple', 'https://h\u00ebel.example', 'https://\uff48eel.example', 'https://heel.\u0435xample',
  'https://localhost', 'https://heel.localhost', 'https://a.b.localhost', 'https://heel.local', 'https://heel.internal', 'https://cp.heel.internal',
  'https://heel-control-plane.internal',
];

describe('canonical public origin', () => {
  it('accepts only the exact lowercase HTTPS DNS origin spelling', () => {
    for (const value of accepted) expect(canonicalPublicOrigin(value), value).toBe(value);
  });
  it('refuses every noncanonical, local-only or numeric spelling, including the legacy private name', () => {
    for (const value of [...refused, undefined, null, 443, {}]) {
      expect(canonicalPublicOrigin(value), JSON.stringify(value)).toBeNull();
    }
  });
  it('emits the configured origin unchanged for a valid full build', () => {
    for (const value of accepted) {
      expect(deploymentConfig({ HEEL_PUBLIC_ORIGIN: value, HEEL_CONTROL_PLANE_VPC_SERVICE_ID: service }, 'build'))
        .toEqual({ vars: { PUBLIC_ORIGIN: value }, vpc_services: [{ binding: 'CONTROL_PLANE', service_id: service }] });
    }
  });
  it('fails every production build mode on a missing or refused origin', () => {
    for (const mode of [{ HEEL_CONTROL_PLANE_VPC_SERVICE_ID: service }, { HEEL_DEPLOYMENT_MODE: 'local_review' }]) {
      expect(() => deploymentConfig(mode, 'build'), 'missing').toThrow(/canonical HTTPS/);
      for (const value of refused) {
        expect(() => deploymentConfig({ ...mode, HEEL_PUBLIC_ORIGIN: value }, 'build'), JSON.stringify(value)).toThrow(/canonical HTTPS/);
      }
    }
  });
});
