// Signed-export verification (export.v1) — round-trip + tamper tests.
//
// The fixture signs exactly the way the platform does
// (packages/sandbox-core/src/exports.ts): canonicalSortKeys(payload),
// sha256 hex of the canonical bytes, Ed25519 over `${canonical}|${keyId}`.

import { describe, expect, it } from "vitest";
import { createHash, sign as nodeSign } from "node:crypto";

import { generateKey, type GeneratedKey } from "./fixtures/builder.js";
import { canonicalSortKeys, base64UrlEncode } from "../src/canonicalJson.js";
import { KeyDirectory } from "../src/keys.js";
import { verifySignedExport, type SignedExport } from "../src/exports.js";

function directoryFor(key: GeneratedKey): KeyDirectory {
  return new KeyDirectory({
    source: "local",
    snapshotId: null,
    issuedAt: null,
    keys: [key.verificationKey],
  });
}

/** Mirror of the platform signer (sandbox-core exports.ts signExport). */
function signExport(
  kind: string,
  orgId: string,
  payload: unknown,
  key: GeneratedKey,
  exportedAt = "2026-07-01T00:00:00.000Z",
): SignedExport {
  const payloadCanonical = canonicalSortKeys(payload);
  const payloadCanonicalHash = createHash("sha256")
    .update(payloadCanonical)
    .digest("hex");
  const signatureBytes = nodeSign(
    null,
    new TextEncoder().encode(`${payloadCanonical}|${key.keyId}`),
    key.signingKey,
  );
  return {
    kind,
    envelopeVersion: "export.v1",
    orgId,
    exportedAt,
    keyId: key.keyId,
    algorithm: "ed25519",
    payload,
    payloadCanonical,
    payloadCanonicalHash,
    signature: base64UrlEncode(new Uint8Array(signatureBytes)),
  };
}

const meteringPayload = {
  schemaVersion: "metering.v1",
  orgId: "org_demo",
  periodStart: "2026-06-01T00:00:00.000Z",
  periodEnd: "2026-07-01T00:00:00.000Z",
  records: [
    {
      idemKey: "a".repeat(64),
      proofReceiptId: "rcpt_demo_0001",
      unitType: "ATTENTION_SECONDS",
      unitCount: "6.500000",
      weight: "1",
      spatialAnchorId: "wsp_northgate",
      spatialPlacementId: null,
      observedAt: "2026-06-14T12:00:00.000Z",
      status: "PROJECTED",
    },
  ],
  totals: { ATTENTION_SECONDS: "6.500000" },
};

describe("verifySignedExport — export.v1", () => {
  it("round-trips: a freshly signed metering export verifies VALID", async () => {
    const key = generateKey();
    const exp = signExport("metering.export.v1", "org_demo", meteringPayload, key);
    const report = await verifySignedExport(exp, directoryFor(key));
    expect(report.status).toBe("VALID");
    expect(report.kind).toBe("metering.export.v1");
    expect(report.steps.every((s) => s.status === "VALID")).toBe(true);
  });

  it("detects a tampered payload (PAYLOAD_CANONICAL_MISMATCH)", async () => {
    const key = generateKey();
    const exp = signExport("metering.export.v1", "org_demo", meteringPayload, key);
    const tampered = {
      ...exp,
      payload: { ...(exp.payload as Record<string, unknown>), orgId: "org_attacker" },
    };
    const report = await verifySignedExport(tampered, directoryFor(key));
    expect(report.status).toBe("INVALID");
    expect(report.steps.some((s) => s.reason === "PAYLOAD_CANONICAL_MISMATCH")).toBe(true);
  });

  it("detects a tampered transparency hash (EXPORT_PAYLOAD_HASH_MISMATCH)", async () => {
    const key = generateKey();
    const exp = signExport("metering.export.v1", "org_demo", meteringPayload, key);
    const tampered = { ...exp, payloadCanonicalHash: "0".repeat(64) };
    const report = await verifySignedExport(tampered, directoryFor(key));
    expect(report.status).toBe("INVALID");
    expect(report.steps.some((s) => s.reason === "EXPORT_PAYLOAD_HASH_MISMATCH")).toBe(true);
  });

  it("rejects a signature from a different key (SIGNATURE_INVALID)", async () => {
    const key = generateKey();
    const otherKey = generateKey("fixture_other");
    const exp = signExport("settlement.export.v1", "org_demo", meteringPayload, otherKey);
    // Present it as if signed by `key` — directory resolves key, signature is other's.
    const forged = { ...exp, keyId: key.keyId };
    // Re-sign the canonical under otherKey but claim key.keyId — signature can't
    // verify because keyId is bound into the signed bytes AND the key differs.
    const report = await verifySignedExport(forged, directoryFor(key));
    expect(report.status).toBe("INVALID");
    expect(report.steps.some((s) => s.reason === "SIGNATURE_INVALID")).toBe(true);
  });

  it("reports an unknown keyId as a key_lookup failure", async () => {
    const key = generateKey();
    const stranger = generateKey("fixture_stranger");
    const exp = signExport("metering.export.v1", "org_demo", meteringPayload, stranger);
    const report = await verifySignedExport(exp, directoryFor(key));
    expect(report.status).toBe("INVALID");
    expect(
      report.steps.some((s) => s.kind === "key_lookup" && s.reason === "UNKNOWN_KEY_ID"),
    ).toBe(true);
  });

  it("rejects an unsupported envelope version", async () => {
    const key = generateKey();
    const exp = { ...signExport("metering.export.v1", "org_demo", meteringPayload, key), envelopeVersion: "export.v9" };
    const report = await verifySignedExport(exp, directoryFor(key));
    expect(report.status).toBe("INVALID");
    expect(report.steps.some((s) => s.reason === "UNSUPPORTED_ENVELOPE_VERSION")).toBe(true);
  });
});
