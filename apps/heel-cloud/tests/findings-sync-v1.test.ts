// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";

import {
  FindingsSyncContractError,
  MAX_FINDINGS_SYNC_BYTES,
  MAX_FINDINGS_SYNC_RECEIPT_BYTES,
  assertFindingsSyncReceiptMatchesV1,
  canonicalFindingsSyncRequestJsonV1,
  findingsSyncRequestDigestV1,
  parseFindingsSyncReceiptJsonV1,
  parseFindingsSyncRequestJsonV1,
  validateFindingsSyncReceiptV1,
  validateFindingsSyncRequestV1,
} from "../lib/findings-sync-v1";


const KEY = Uint8Array.from({ length: 32 }, (_, index) => index);
const REQUEST_ONE_TEXT = readFileSync(
  resolve(process.cwd(), "../../tests/fixtures/findings_sync/request-one-finding.json"),
  "utf8",
);
const REQUEST_PASS_TEXT = readFileSync(
  resolve(process.cwd(), "../../tests/fixtures/findings_sync/request-pass.json"),
  "utf8",
);
const RECEIPT_TEXT = readFileSync(
  resolve(process.cwd(), "../../tests/fixtures/findings_sync/receipt-created.json"),
  "utf8",
);


function compareUnicode(left: string, right: string): number {
  const a = Array.from(left, (character) => character.codePointAt(0)!);
  const b = Array.from(right, (character) => character.codePointAt(0)!);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}


function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") return JSON.stringify(Object.is(value, -0) ? 0 : value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort(compareUnicode).map(
    (key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`,
  ).join(",")}}`;
}


function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}


async function contractFailure(action: () => unknown): Promise<FindingsSyncContractError> {
  try {
    await action();
  } catch (error) {
    expect(error).toBeInstanceOf(FindingsSyncContractError);
    return error as FindingsSyncContractError;
  }
  throw new Error("expected findings sync contract failure");
}


describe("heel.findings-sync.v1", () => {
  test.each([
    ["one finding", REQUEST_ONE_TEXT],
    ["pass", REQUEST_PASS_TEXT],
  ])("accepts the Python %s golden and preserves its exact canonical bytes", async (_label, text) => {
    const request = await parseFindingsSyncRequestJsonV1(text, KEY);
    await expect(canonicalFindingsSyncRequestJsonV1(request, KEY)).resolves.toBe(text.slice(0, -1));
    await expect(findingsSyncRequestDigestV1(request, KEY)).resolves.toBe(sha256(request));
  });

  test("independently verifies the fixture HMAC, projection hash, request digest, and receipt", async () => {
    const request = await parseFindingsSyncRequestJsonV1(REQUEST_ONE_TEXT, KEY);
    const finding = request.findings[0];
    const expectedFinding = createHmac("sha256", KEY).update(canonicalJson([
      "heel.findings-sync.v1", "finding", finding.surface_ref, finding.risk_code,
    ]), "utf8").digest("hex");
    expect(finding.finding_id).toBe(`find1_${expectedFinding}`);
    expect(request.projection_hash).toBe(sha256({
      schema_version: request.schema_version,
      gate_status: request.gate_status,
      summary: request.summary,
      findings: request.findings,
    }));

    const requestDigest = sha256(request);
    const receipt = parseFindingsSyncReceiptJsonV1(RECEIPT_TEXT);
    expect(receipt.request_digest).toBe(requestDigest);
    expect(() => assertFindingsSyncReceiptMatchesV1(receipt, {
      request,
      requestJson: canonicalJson(request),
      requestDigest,
      idempotencyKey: `fs1-${requestDigest}`,
    })).not.toThrow();
  });

  test.each([
    ["unknown request field", (value: Record<string, unknown>) => { value.raw_openapi = "never-cross"; }],
    ["finding identity", (value: Record<string, unknown>) => {
      ((value.findings as Record<string, unknown>[])[0]).finding_id = `find1_${"0".repeat(64)}`;
    }],
    ["projection hash", (value: Record<string, unknown>) => { value.projection_hash = "0".repeat(64); }],
    ["summary count", (value: Record<string, unknown>) => {
      (value.summary as Record<string, unknown>).findings = 2;
    }],
    ["gate", (value: Record<string, unknown>) => { value.gate_status = "pass"; }],
    ["float", (value: Record<string, unknown>) => {
      (value.summary as Record<string, unknown>).findings = 1.5;
    }],
    ["unsafe integer", (value: Record<string, unknown>) => {
      (value.summary as Record<string, unknown>).findings = Number.MAX_SAFE_INTEGER + 1;
    }],
  ])("rejects %s without echoing private values", async (_label, mutate) => {
    const value = JSON.parse(REQUEST_ONE_TEXT) as Record<string, unknown>;
    mutate(value);
    await expect(validateFindingsSyncRequestV1(value, KEY)).rejects.not.toThrow("never-cross");
  });

  test("rejects recursive duplicate keys and malformed namespace keys", async () => {
    const duplicate = REQUEST_ONE_TEXT.replace(
      '"project_ref":"prj_0123456789abcdef0123456789abcdef"',
      '"project_ref":"prj_0123456789abcdef0123456789abcdef","project_ref":"prj_0123456789abcdef0123456789abcdef"',
    );
    await expect(parseFindingsSyncRequestJsonV1(duplicate, KEY)).rejects.toThrow();
    await expect(parseFindingsSyncRequestJsonV1(REQUEST_ONE_TEXT, KEY.slice(0, 31))).rejects.toThrow();
  });

  test("binds receipts to the exact prepared project, digest, and projection", async () => {
    const request = await parseFindingsSyncRequestJsonV1(REQUEST_ONE_TEXT, KEY);
    const requestDigest = await findingsSyncRequestDigestV1(request, KEY);
    const prepared = {
      request,
      requestJson: await canonicalFindingsSyncRequestJsonV1(request, KEY),
      requestDigest,
      idempotencyKey: `fs1-${requestDigest}` as const,
    };
    const receipt = parseFindingsSyncReceiptJsonV1(RECEIPT_TEXT);
    for (const mutate of [
      (value: typeof receipt) => ({
        ...value,
        project_ref: `prj_${"f".repeat(32)}` as typeof receipt.project_ref,
      }),
      (value: typeof receipt) => ({ ...value, request_digest: "0".repeat(64) }),
      (value: typeof receipt) => ({ ...value, projection_hash: "0".repeat(64) }),
    ]) {
      expect(() => assertFindingsSyncReceiptMatchesV1(mutate(receipt), prepared)).toThrow();
    }
  });

  test("bounds raw request and receipt JSON before validation work", async () => {
    const oversizedRequest = `{"padding":"${"x".repeat(MAX_FINDINGS_SYNC_BYTES)}"}`;
    const oversizedReceipt = `{"padding":"${"x".repeat(MAX_FINDINGS_SYNC_RECEIPT_BYTES)}"}`;

    await expect(parseFindingsSyncRequestJsonV1(oversizedRequest, KEY)).rejects.toMatchObject({
      code: "size_limit",
    });
    expect(() => parseFindingsSyncReceiptJsonV1(oversizedReceipt)).toThrow(expect.objectContaining({
      code: "size_limit",
    }));
  });

  test("rejects excessive decoded complexity before exact-field or hashing work", async () => {
    const request = JSON.parse(REQUEST_ONE_TEXT) as Record<string, unknown>;
    const receipt = JSON.parse(RECEIPT_TEXT) as Record<string, unknown>;
    let nested: unknown = "private-leaf-never-echo";
    for (let index = 0; index < 18; index += 1) nested = { nested };
    request.raw_openapi = nested;
    receipt.raw_review = nested;

    await expect(validateFindingsSyncRequestV1(request, KEY)).rejects.toMatchObject({
      code: "complexity_limit",
    });
    expect(() => validateFindingsSyncReceiptV1(receipt)).toThrow(expect.objectContaining({
      code: "complexity_limit",
    }));
  });

  test.each([
    ["malformed", "{not-json"],
    ["duplicate", RECEIPT_TEXT.replace(
      `"receipt_id":"fsr_${"1".repeat(32)}"`,
      `"receipt_id":"fsr_${"1".repeat(32)}","receipt_id":"fsr_${"2".repeat(32)}"`,
    )],
  ])("rejects %s receipt JSON without reflecting its contents", async (_label, source) => {
    const error = await contractFailure(() => parseFindingsSyncReceiptJsonV1(source));
    expect(error.message).not.toContain(source.slice(0, 24));
  });

  test("uses non-echoing errors for private values in decoded requests and receipts", async () => {
    const secret = "private-customer-value-never-echo";
    const request = JSON.parse(REQUEST_ONE_TEXT) as Record<string, unknown>;
    const receipt = JSON.parse(RECEIPT_TEXT) as Record<string, unknown>;
    request.raw_openapi = secret;
    receipt.raw_review = secret;

    const requestError = await contractFailure(() => validateFindingsSyncRequestV1(request, KEY));
    const receiptError = await contractFailure(() => validateFindingsSyncReceiptV1(receipt));
    expect(requestError.message).not.toContain(secret);
    expect(receiptError.message).not.toContain(secret);
  });
});
