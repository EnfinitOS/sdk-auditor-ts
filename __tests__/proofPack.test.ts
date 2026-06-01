import { describe, expect, it } from "vitest";

import { KeyDirectory } from "../src/keys.js";
import {
  NodeCryptoEd25519Verifier,
  parseSignedProofPack,
  verifyProofRecord,
} from "../src/proofPack.js";

import { buildValidPack, generateKey } from "./fixtures/builder.js";

describe("parseSignedProofPack", () => {
  it("accepts a well-formed pack", () => {
    const { pack } = buildValidPack();
    // Round-trip through JSON to simulate disk read.
    const parsed = parseSignedProofPack(JSON.parse(JSON.stringify(pack)));
    expect(parsed.envelopeVersion).toBe("envelope.v1");
    expect(parsed.records).toHaveLength(1);
    expect(parsed.records[0]!.payload.receiptId).toBe("rec_001");
  });

  it("rejects non-object input", () => {
    expect(() => parseSignedProofPack("nope")).toThrow(/must be a JSON object/);
  });

  it("rejects unsupported envelopeVersion", () => {
    const { pack } = buildValidPack();
    const broken = { ...pack, envelopeVersion: "envelope.v99" };
    expect(() => parseSignedProofPack(broken)).toThrow(/unsupported envelopeVersion/);
  });

  it("rejects missing payload.version", () => {
    const { pack } = buildValidPack();
    const broken = JSON.parse(JSON.stringify(pack));
    delete broken.records[0].payload.version;
    expect(() => parseSignedProofPack(broken)).toThrow(/payload\.version/);
  });

  it("rejects unknown algorithm", () => {
    const { pack } = buildValidPack();
    const broken = JSON.parse(JSON.stringify(pack));
    broken.records[0].algorithm = "rsa";
    expect(() => parseSignedProofPack(broken)).toThrow(/algorithm/);
  });
});

describe("verifyProofRecord", () => {
  const verifier = new NodeCryptoEd25519Verifier();

  it("returns all VALID steps for an honest record", async () => {
    const { pack, key } = buildValidPack();
    const dir = new KeyDirectory({
      source: "local",
      snapshotId: null,
      issuedAt: null,
      keys: [key.verificationKey],
    });
    const steps = await verifyProofRecord(pack.records[0]!, 0, dir, verifier);
    for (const s of steps) {
      expect(s.status, JSON.stringify(s)).toBe("VALID");
    }
  });

  it("flags PAYLOAD_CANONICAL_MISMATCH when payloadCanonical is wrong", async () => {
    const { pack, key } = buildValidPack();
    const tampered = { ...pack.records[0]!, payloadCanonical: "{}" };
    const dir = new KeyDirectory({
      source: "local",
      snapshotId: null,
      issuedAt: null,
      keys: [key.verificationKey],
    });
    const steps = await verifyProofRecord(tampered, 0, dir, verifier);
    const fail = steps.find((s) => s.reason === "PAYLOAD_CANONICAL_MISMATCH");
    expect(fail).toBeDefined();
  });

  it("flags AFTER_HASH_MISMATCH when afterHash is wrong", async () => {
    const { pack, key } = buildValidPack();
    const tampered = { ...pack.records[0]!, afterHash: "deadbeef" };
    const dir = new KeyDirectory({
      source: "local",
      snapshotId: null,
      issuedAt: null,
      keys: [key.verificationKey],
    });
    const steps = await verifyProofRecord(tampered, 0, dir, verifier);
    const fail = steps.find((s) => s.reason === "AFTER_HASH_MISMATCH");
    expect(fail).toBeDefined();
  });

  it("flags UNKNOWN_KEY_ID when the directory lacks the key", async () => {
    const { pack } = buildValidPack();
    const otherKey = generateKey("other_key");
    const dir = new KeyDirectory({
      source: "local",
      snapshotId: null,
      issuedAt: null,
      keys: [otherKey.verificationKey],
    });
    const steps = await verifyProofRecord(pack.records[0]!, 0, dir, verifier);
    const fail = steps.find((s) => s.reason === "UNKNOWN_KEY_ID");
    expect(fail).toBeDefined();
  });

  it("flags SIGNATURE_INVALID when the payload is tampered (keeping signature)", async () => {
    const { pack, key } = buildValidPack();
    const tamperedRec = {
      ...pack.records[0]!,
      payload: { ...pack.records[0]!.payload, dwellMs: 999999 },
    };
    // After-hash + canonical will also break — but the signature step
    // is reached only if those pass. So we have to also recompute
    // payloadCanonical + afterHash for the tampered payload to
    // exercise the signature-fail path specifically.
    const { canonicaliseProofPayload } = await import("../src/canonicalJson.js");
    const { sha256Hex } = await import("../src/hashing.js");
    const newCanonical = canonicaliseProofPayload(tamperedRec.payload);
    const fixedTamper = {
      ...tamperedRec,
      payloadCanonical: newCanonical,
      afterHash: sha256Hex(newCanonical),
    };
    const dir = new KeyDirectory({
      source: "local",
      snapshotId: null,
      issuedAt: null,
      keys: [key.verificationKey],
    });
    const steps = await verifyProofRecord(fixedTamper, 0, dir, verifier);
    const sig = steps.find((s) => s.kind === "signature");
    expect(sig?.status).toBe("INVALID");
    expect(sig?.reason).toBe("SIGNATURE_INVALID");
  });
});
