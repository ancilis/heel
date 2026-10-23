// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/**
 * The one private control-plane dispatch. Every value arrives as an explicit input and the module
 * holds no ambient authority: it validates the configured binding and public origin itself, frames
 * a POST body to its declared length and refuses upstream redirects.
 */
import { canonicalPublicOrigin } from "../build/deployment-config";

declare const FixedLengthStream: new (expectedLength: number) => TransformStream<Uint8Array, Uint8Array>;

export interface ControlPlaneBinding {
  fetch(upstream: Request): Promise<Response>;
}

export interface ControlPlaneDispatchInput {
  /** The configured private binding exactly as received; its shape is checked here. */
  binding: ControlPlaneBinding | null | undefined;
  /** The configured public origin exactly as received; validated here, never trusted pre-validated. */
  publicOrigin: unknown;
  /** The exact allowlisted route path. */
  upstreamPath: string;
  method: string;
  /** The reconstructed allowlisted headers, including the edge secret. */
  headers: Headers;
  /** The validated declared length. */
  contentLength: number;
  body: ReadableStream<Uint8Array> | null;
}

export type ControlPlaneDispatchOutcome =
  | { kind: "unavailable" }
  | { kind: "invalid" }
  | { kind: "failed" }
  | { kind: "response"; response: Response };

export async function dispatchControlPlane(input: ControlPlaneDispatchInput): Promise<ControlPlaneDispatchOutcome> {
  if (
    input.binding === undefined
    || input.binding === null
    || typeof input.binding.fetch !== "function"
  ) {
    return { kind: "unavailable" };
  }
  // The binding selects the network service; the URL names the one configured public origin,
  // never a caller URL, Host, Origin or forwarding header.
  const origin = canonicalPublicOrigin(input.publicOrigin);
  if (origin === null) return { kind: "unavailable" };
  const url = new URL(input.upstreamPath, origin);
  const init: RequestInit & { duplex?: "half" } = {
    headers: input.headers,
    method: input.method,
    redirect: "manual",
  };
  if (input.method === "POST") {
    if (input.contentLength !== 0 && input.body === null) return { kind: "invalid" };
    try {
      init.body = input.contentLength === 0
        ? new Uint8Array()
        : input.body!.pipeThrough(new FixedLengthStream(input.contentLength));
      init.duplex = "half";
    } catch {
      return { kind: "failed" };
    }
  }
  try {
    const response = await input.binding.fetch(new Request(url, init));
    if (response.status >= 300 && response.status <= 399) return { kind: "failed" };
    return { kind: "response", response };
  } catch {
    return { kind: "failed" };
  }
}
