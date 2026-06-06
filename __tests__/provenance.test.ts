import { describe, expect, it } from "vitest";

import { KeyDirectory } from "../src/keys.js";
import {
  canonicaliseProvenanceSigningInput,
  PROVENANCE_SIGNING_VERSION,
  verifyProvenanceChain,
  verifyProvenanceRecord,
} from "../src/provenance.js";
import { NodeCryptoEd25519Verifier } from "../src/proofPack.js";

import {
  buildLegacyProvenanceRecord,
  generateKey,
  signProvenanceRecord,
} from "./fixtures/builder.js";

const verifier = new NodeCryptoEd25519Verifier();

function directoryFor(key: ReturnType<typeof generateKey>) {
  return new KeyDirectory({
    source: "local",
    snapshotId: null,
    issuedAt: null,
    keys: [key.verificationKey],
  });
}

/** A representative RIGHT_ISSUED signing-fields shape. */
function issuedFields(orgId = "org_test") {
  return {
    orgId,
    eventType: "RIGHT_ISSUED",
    rightId: "rgh_001",
    basisId: "bas_001",
    offerId: null,
    beforeHash: null,
    afterHash: "sha256:" + "1".repeat(64),
  };
}

describe("canonicaliseProvenanceSigningInput", () => {
  it("produces the platform's pipe-delimited rightProvenance.v1 form", () => {
    const out = canonicaliseProvenanceSigningInput(issuedFields(), "key-1");
    expect(out).toBe(
      `${PROVENANCE_SIGNING_VERSION}|org_test|RIGHT_ISSUED|rgh_001|bas_001|-|-|sha256:${"1".repeat(64)}|key-1`,
    );
  });

  it("encodes null AND empty-string fields identically as '-' (no collision surface)", () => {
    const withNull = canonicaliseProvenanceSigningInput(
      { ...issuedFields(), offerId: null },
      "key-1",
    );
    const withEmpty = canonicaliseProvenanceSigningInput(
      { ...issuedFields(), offerId: "" },
      "key-1",
    );
    expect(withNull).toBe(withEmpty);
  });

  it("includes the keyId so a signature cannot be re-attributed to a different key", () => {
    const a = canonicaliseProvenanceSigningInput(issuedFields(), "key-a");
    const b = canonicaliseProvenanceSigningInput(issuedFields(), "key-b");
    expect(a).not.toBe(b);
  });
});

describe("verifyProvenanceRecord — write-time signed records", () => {
  it("returns all VALID steps for an honest record", async () => {
    const key = generateKey("prov_key_1");
    const record = signProvenanceRecord(issuedFields(), key);
    const steps = await verifyProvenanceRecord(record, 0, directoryFor(key), verifier);
    expect(steps.length).toBeGreaterThan(0);
    for (const s of steps) {
      expect(s.status, JSON.stringify(s)).toBe("VALID");
    }
  });

  it("flags PROVENANCE_CANONICAL_MISMATCH when a raw field is edited after signing", async () => {
    const key = generateKey();
    const record = signProvenanceRecord(issuedFields(), key);
    // Move the right to a different id without re-signing — the
    // classic post-write tamper the write-time signature exists for.
    const tampered = { ...record, rightId: "rgh_evil" };
    const steps = await verifyProvenanceRecord(tampered, 0, directoryFor(key), verifier);
    const fail = steps.find((s) => s.reason === "PROVENANCE_CANONICAL_MISMATCH");
    expect(fail).toBeDefined();
    expect(fail!.status).toBe("INVALID");
  });

  it("flags PROVENANCE_CANONICAL_MISMATCH when payloadCanonical is missing on an ed25519 record", async () => {
    const key = generateKey();
    const record = signProvenanceRecord(issuedFields(), key);
    const partial = { ...record, payloadCanonical: null };
    const steps = await verifyProvenanceRecord(partial, 0, directoryFor(key), verifier);
    expect(steps.find((s) => s.reason === "PROVENANCE_CANONICAL_MISMATCH")).toBeDefined();
  });

  it("flags PROVENANCE_SIGNATURE_INVALID when the signature bytes are swapped", async () => {
    const key = generateKey();
    const recordA = signProvenanceRecord(issuedFields(), key);
    const recordB = signProvenanceRecord(
      { ...issuedFields(), eventType: "RIGHT_SUSPENDED", beforeHash: "sha256:" + "1".repeat(64), afterHash: "sha256:" + "2".repeat(64) },
      key,
    );
    // A's claims with B's signature — both internally well-formed.
    const spliced = { ...recordA, signature: recordB.signature };
    const steps = await verifyProvenanceRecord(spliced, 0, directoryFor(key), verifier);
    const fail = steps.find((s) => s.reason === "PROVENANCE_SIGNATURE_INVALID");
    expect(fail).toBeDefined();
    expect(fail!.status).toBe("INVALID");
  });

  it("flags PROVENANCE_SIGNATURE_MALFORMED for a signature that is not base64url / 64 bytes", async () => {
    const key = generateKey();
    const record = signProvenanceRecord(issuedFields(), key);

    const badAlphabet = { ...record, payloadCanonical: record.payloadCanonical, signature: "not+base64url/safe==" };
    let steps = await verifyProvenanceRecord(badAlphabet, 0, directoryFor(key), verifier);
    expect(steps.find((s) => s.reason === "PROVENANCE_SIGNATURE_MALFORMED")).toBeDefined();

    const truncated = { ...record, signature: record.signature.slice(0, 16) };
    // The truncated signature still canonical-matches (claims intact),
    // so the failure has to come from the byte-length gate.
    steps = await verifyProvenanceRecord(truncated, 0, directoryFor(key), verifier);
    expect(steps.find((s) => s.reason === "PROVENANCE_SIGNATURE_MALFORMED")).toBeDefined();
  });

  it("flags UNKNOWN_KEY_ID when the directory lacks the signing key", async () => {
    const key = generateKey("prov_key_signing");
    const other = generateKey("prov_key_other");
    const record = signProvenanceRecord(issuedFields(), key);
    const steps = await verifyProvenanceRecord(record, 0, directoryFor(other), verifier);
    const fail = steps.find((s) => s.reason === "UNKNOWN_KEY_ID");
    expect(fail).toBeDefined();
    expect(fail!.kind).toBe("key_lookup");
  });

  it("flags KEY_REVOKED_BEFORE_ISSUANCE when the record post-dates the key's revocation", async () => {
    const key = generateKey("prov_key_revoked");
    const revokedKey = {
      ...key,
      verificationKey: {
        ...key.verificationKey,
        revokedAt: "2026-01-01T00:00:00.000Z",
      },
    };
    const record = signProvenanceRecord(
      { ...issuedFields(), occurredAt: "2026-06-01T00:00:00.000Z" },
      key,
    );
    const steps = await verifyProvenanceRecord(
      record,
      0,
      directoryFor(revokedKey),
      verifier,
    );
    expect(
      steps.find((s) => s.reason === "KEY_REVOKED_BEFORE_ISSUANCE"),
    ).toBeDefined();
  });
});

describe("verifyProvenanceRecord — legacy (pre-Wave-14) records", () => {
  it("reports an informational SKIPPED PROVENANCE_UNSIGNED_RECORD, never INVALID", async () => {
    const key = generateKey();
    const legacy = buildLegacyProvenanceRecord();
    const steps = await verifyProvenanceRecord(legacy, 0, directoryFor(key), verifier);
    expect(steps).toHaveLength(1);
    expect(steps[0]).toMatchObject({
      status: "SKIPPED",
      reason: "PROVENANCE_UNSIGNED_RECORD",
      kind: "provenance_signature",
    });
  });
});

describe("verifyProvenanceChain", () => {
  it("returns VALID for a clean signed lifecycle (issue → suspend → resume)", async () => {
    const key = generateKey();
    const records = [
      signProvenanceRecord(issuedFields(), key),
      signProvenanceRecord(
        {
          orgId: "org_test",
          eventType: "RIGHT_SUSPENDED",
          rightId: "rgh_001",
          basisId: null,
          offerId: null,
          beforeHash: "sha256:" + "1".repeat(64),
          afterHash: "sha256:" + "2".repeat(64),
        },
        key,
      ),
      signProvenanceRecord(
        {
          orgId: "org_test",
          eventType: "RIGHT_REACTIVATED",
          rightId: "rgh_001",
          basisId: null,
          offerId: null,
          beforeHash: "sha256:" + "2".repeat(64),
          afterHash: "sha256:" + "3".repeat(64),
        },
        key,
      ),
    ];

    const report = await verifyProvenanceChain(records, [key.verificationKey]);
    expect(report.status).toBe("VALID");
    expect(report.recordCount).toBe(3);
    expect(report.signedRecordCount).toBe(3);
    expect(report.unsignedRecordCount).toBe(0);
    expect(report.steps.every((s) => s.status === "VALID")).toBe(true);
  });

  it("returns INVALID and points at the tampered record's index", async () => {
    const key = generateKey();
    const records = [
      signProvenanceRecord(issuedFields(), key),
      signProvenanceRecord(
        {
          orgId: "org_test",
          eventType: "RIGHT_REVOKED",
          rightId: "rgh_001",
          basisId: null,
          offerId: null,
          beforeHash: "sha256:" + "1".repeat(64),
          afterHash: "sha256:" + "9".repeat(64),
        },
        key,
      ),
    ];
    // Flip the revocation into a reactivation without re-signing.
    records[1] = { ...records[1]!, provenanceEventType: "RIGHT_REACTIVATED" };

    const report = await verifyProvenanceChain(records, [key.verificationKey]);
    expect(report.status).toBe("INVALID");
    const fail = report.steps.find(
      (s) => s.status === "INVALID" && s.reason === "PROVENANCE_CANONICAL_MISMATCH",
    );
    expect(fail).toBeDefined();
    expect(fail!.target).toContain("provenance[1]");
  });

  it("mixed signed + legacy sets verify VALID with informational unsigned findings (0.0.1 back-compat)", async () => {
    const key = generateKey();
    const records = [
      buildLegacyProvenanceRecord({ orgId: "org_test" }),
      signProvenanceRecord(issuedFields(), key),
    ];

    const report = await verifyProvenanceChain(records, [key.verificationKey]);
    expect(report.status).toBe("VALID");
    expect(report.signedRecordCount).toBe(1);
    expect(report.unsignedRecordCount).toBe(1);
    const informational = report.steps.filter(
      (s) => s.reason === "PROVENANCE_UNSIGNED_RECORD",
    );
    expect(informational).toHaveLength(1);
    expect(informational[0]!.status).toBe("SKIPPED");
  });

  it("an all-legacy set reports SKIPPED — nothing was verifiable, nothing failed", async () => {
    const key = generateKey();
    const records = [
      buildLegacyProvenanceRecord(),
      buildLegacyProvenanceRecord({ provenanceEventType: "RIGHT_SUSPENDED" }),
    ];
    const report = await verifyProvenanceChain(records, [key.verificationKey]);
    expect(report.status).toBe("SKIPPED");
    expect(report.signedRecordCount).toBe(0);
    expect(report.unsignedRecordCount).toBe(2);
    expect(report.steps.every((s) => s.status === "SKIPPED")).toBe(true);
  });

  it("flags PROVENANCE_ORG_MISMATCH on a tenant-spliced record set when expectedOrgId is pinned", async () => {
    const key = generateKey();
    const records = [
      signProvenanceRecord(issuedFields("org_test"), key),
      signProvenanceRecord(issuedFields("org_other"), key),
    ];
    const report = await verifyProvenanceChain(records, [key.verificationKey], {
      expectedOrgId: "org_test",
    });
    expect(report.status).toBe("INVALID");
    const fail = report.steps.find((s) => s.reason === "PROVENANCE_ORG_MISMATCH");
    expect(fail).toBeDefined();
    expect(fail!.target).toBe("provenance[1].orgId");
  });

  it("rejects an empty record set as INVALID", async () => {
    const key = generateKey();
    const report = await verifyProvenanceChain([], [key.verificationKey]);
    expect(report.status).toBe("INVALID");
    expect(report.steps[0]!.reason).toBe("MALFORMED_PACK");
  });

  it("accepts a pre-built KeyDirectory in place of a raw key array", async () => {
    const key = generateKey();
    const record = signProvenanceRecord(issuedFields(), key);
    const report = await verifyProvenanceChain([record], directoryFor(key));
    expect(report.status).toBe("VALID");
  });
});
