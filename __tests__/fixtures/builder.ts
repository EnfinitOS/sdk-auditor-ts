// Fixture builder — generates SignedProofPacks under a freshly-minted
// Ed25519 keypair so the tests verify against the same primitive
// shape the platform emits.
//
// The static JSON fixtures in this directory are LANDMARK records
// (human-readable shape; placeholder signatures). The DYNAMIC
// fixtures here are the ones the tests run against — the test
// suite builds a pack, signs it, and then audits it, asserting
// VALID. Then it tampers a byte and asserts INVALID.

import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";

import {
  base64UrlEncode,
  canonicaliseProofPayload,
  canonicaliseProofSigningInput,
} from "../../src/canonicalJson.js";
import {
  meterIdemKey,
  settlementIdemKey,
  sha256Hex,
} from "../../src/hashing.js";
import {
  canonicaliseProvenanceSigningInput,
  type ProvenanceSigningFields,
} from "../../src/provenance.js";
import type {
  MeteringSummary,
  ProofReceiptPayload,
  ProofRecord,
  ProvenanceRecord,
  SettlementSummary,
  SignedProofPack,
  VerificationKey,
} from "../../src/types.js";

export type GeneratedKey = {
  keyId: string;
  /** Base64url 32-byte public key, ready for VerificationKey shape. */
  publicKeyB64: string;
  /** The Node KeyObject — used for signing in fixtures. */
  signingKey: import("node:crypto").KeyObject;
  verificationKey: VerificationKey;
};

/**
 * generateKey — fresh Ed25519 keypair, plus a VerificationKey
 * shape consumable by the auditor.
 */
export function generateKey(
  keyId: string = "fixture_key_" + Math.random().toString(36).slice(2, 8),
): GeneratedKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  // Extract raw 32-byte public key from SPKI DER.
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = spki.subarray(spki.length - 32);
  const publicKeyB64 = base64UrlEncode(new Uint8Array(rawPub));

  const verificationKey: VerificationKey = {
    keyId,
    algorithm: "ed25519",
    publicKey: publicKeyB64,
    notBefore: "2020-01-01T00:00:00.000Z",
    notAfter: null,
    revokedAt: null,
    purpose: "test_fixture",
  };

  return {
    keyId,
    publicKeyB64,
    signingKey: privateKey,
    verificationKey,
  };
}

/**
 * signRecord — produce a fully-formed ProofRecord from a payload
 * and a generated key. Mirrors the platform's
 * SpatialProofService.issueProof signing path byte-for-byte.
 */
export function signRecord(
  payload: ProofReceiptPayload,
  key: GeneratedKey,
  beforeHash: string | null = null,
): ProofRecord {
  const payloadCanonical = canonicaliseProofPayload(payload);
  const signingInput = canonicaliseProofSigningInput(payload, key.keyId);
  const signatureBytes = nodeSign(
    null,
    new TextEncoder().encode(signingInput),
    key.signingKey,
  );
  const signature = base64UrlEncode(new Uint8Array(signatureBytes));
  const afterHash = createHash("sha256").update(payloadCanonical).digest("hex");
  return {
    payload,
    keyId: key.keyId,
    algorithm: "ed25519",
    signature,
    payloadCanonical,
    beforeHash,
    afterHash,
  };
}

/**
 * buildValidPack — single-record VALID pack.
 */
export function buildValidPack(opts?: {
  key?: GeneratedKey;
  orgId?: string;
  packId?: string;
  payloadOverrides?: Partial<ProofReceiptPayload>;
}): { pack: SignedProofPack; key: GeneratedKey } {
  const key = opts?.key ?? generateKey();
  const orgId = opts?.orgId ?? "org_test";
  const payload: ProofReceiptPayload = {
    version: "1",
    receiptId: "rec_001",
    correlationId: null,
    spatialAnchorId: "anchor_A",
    spatialPlacementId: "place_A",
    issuedAt: "2026-04-01T12:00:00.000Z",
    renderedAt: "2026-04-01T11:59:59.000Z",
    dwellMs: 3500,
    nonce: "n0001",
    witness: null,
    ...opts?.payloadOverrides,
  };
  const record = signRecord(payload, key);
  const pack: SignedProofPack = {
    envelopeVersion: "envelope.v1",
    issuedAt: "2026-04-01T12:00:00.500Z",
    orgId,
    packId: opts?.packId ?? "pack_001",
    records: [record],
  };
  return { pack, key };
}

/**
 * buildMultiRecordChain — produces N records, properly chained.
 */
export function buildMultiRecordChain(
  count: number,
  key: GeneratedKey,
): SignedProofPack {
  const records: ProofRecord[] = [];
  for (let i = 0; i < count; i++) {
    const payload: ProofReceiptPayload = {
      version: "1",
      receiptId: `rec_${String(i).padStart(3, "0")}`,
      correlationId: null,
      spatialAnchorId: `anchor_${i % 3}`,
      spatialPlacementId: null,
      issuedAt: new Date(Date.UTC(2026, 3, 1, 12, i, 0)).toISOString(),
      renderedAt: new Date(Date.UTC(2026, 3, 1, 11, 59, i)).toISOString(),
      dwellMs: 1000 + i * 250,
      nonce: `nonce_${i}`,
      witness: null,
    };
    const before = i === 0 ? null : records[i - 1]!.afterHash;
    records.push(signRecord(payload, key, before));
  }
  return {
    envelopeVersion: "envelope.v1",
    issuedAt: "2026-04-01T13:00:00.000Z",
    orgId: "org_test",
    packId: "pack_multi",
    records,
  };
}

/**
 * buildMeteringSummary — project a pack into metering using the
 * same formula the auditor uses (DWELL_SECONDS = dwellMs/1000).
 */
export function buildMeteringSummary(
  pack: SignedProofPack,
): MeteringSummary {
  const records = pack.records.map((r) => {
    const unitCountScaled = (BigInt(r.payload.dwellMs) * 10n ** 6n) / 1000n;
    const unitCount = formatDecimal(unitCountScaled, 6);
    return {
      idemKey: meterIdemKey(r.payload.receiptId, "DWELL_SECONDS"),
      proofReceiptId: r.payload.receiptId,
      unitType: "DWELL_SECONDS" as const,
      unitCount,
      weight: "1.000000",
      spatialAnchorId: r.payload.spatialAnchorId,
      spatialPlacementId: r.payload.spatialPlacementId,
      observedAt: r.payload.renderedAt,
      status: "PROJECTED" as const,
    };
  });
  const totalScaled = pack.records.reduce(
    (acc, r) => acc + (BigInt(r.payload.dwellMs) * 10n ** 6n) / 1000n,
    0n,
  );
  return {
    schemaVersion: "metering.v1",
    orgId: pack.orgId,
    periodStart: pack.records[0]?.payload.issuedAt ?? "2026-04-01T00:00:00.000Z",
    periodEnd: pack.records[pack.records.length - 1]?.payload.issuedAt ?? "2026-04-02T00:00:00.000Z",
    records,
    totals: {
      DWELL_SECONDS: formatDecimal(totalScaled, 6),
      IMPRESSION_IN_PLACE: "0.000000",
      ATTENTION_SECONDS: "0.000000",
      OCCUPANCY_WEIGHTED_EXPOSURE: "0.000000",
      COMPLIANT_DELIVERY_MINUTE: "0.000000",
      CUSTOM: "0.000000",
    },
  };
}

/**
 * buildSettlementSummary — single-line TENANT-100% projection at
 * 100 cents / DWELL_SECOND.
 */
export function buildSettlementSummary(
  metering: MeteringSummary,
): SettlementSummary {
  const PRICE_PER_SECOND_CENTS = 100;
  const meterGross: Record<string, number> = {};
  const lines = metering.records.map((m) => {
    const seconds = Number(parseDecimal(m.unitCount, 6) / 10n ** 6n);
    const gross = seconds * PRICE_PER_SECOND_CENTS;
    meterGross[m.idemKey] = gross;
    return {
      idemKey: settlementIdemKey(m.idemKey, "TENANT"),
      meterRecordIdemKey: m.idemKey,
      partyRole: "TENANT" as const,
      share: "1.000000",
      ledgerAccountCode: "SPATIAL_REVENUE_GROSS",
      amountCents: gross,
      currency: "USD",
      status: "PROJECTED" as const,
    };
  });
  const totalGross = lines.reduce((a, l) => a + l.amountCents, 0);
  return {
    schemaVersion: "settlement.v1",
    orgId: metering.orgId,
    periodStart: metering.periodStart,
    periodEnd: metering.periodEnd,
    currency: "USD",
    meterGross,
    lines,
    totals: {
      grossCents: totalGross,
      netToTenantCents: totalGross,
      platformFeeCents: 0,
    },
  };
}

/**
 * signProvenanceRecord — produce a write-time-signed rights-provenance
 * record from its signing fields and a generated key. Mirrors the
 * platform's apps/api/src/modules/rights/provenanceSigner.ts
 * `signProvenance` path byte-for-byte: canonical pipe-delimited
 * signing input, raw 64-byte Ed25519 signature, base64url unpadded.
 */
export function signProvenanceRecord(
  fields: ProvenanceSigningFields & {
    proofId?: string;
    occurredAt?: string;
  },
  key: GeneratedKey,
): ProvenanceRecord {
  const payloadCanonical = canonicaliseProvenanceSigningInput(fields, key.keyId);
  const signatureBytes = nodeSign(
    null,
    new TextEncoder().encode(payloadCanonical),
    key.signingKey,
  );
  return {
    proofId: fields.proofId ?? `rp_${Math.random().toString(36).slice(2, 10)}`,
    orgId: fields.orgId,
    provenanceEventType: fields.eventType,
    occurredAt: fields.occurredAt ?? "2026-05-29T12:00:00.000Z",
    rightId: fields.rightId,
    basisId: fields.basisId,
    offerId: fields.offerId,
    provenanceBeforeHash: fields.beforeHash,
    provenanceAfterHash: fields.afterHash,
    signatureAlgorithm: "ed25519",
    signature: base64UrlEncode(new Uint8Array(signatureBytes)),
    signerKeyId: key.keyId,
    payloadCanonical,
  };
}

/**
 * buildLegacyProvenanceRecord — a pre-Wave-14 record carrying only
 * the platform's read-time transport HMAC. Not independently
 * verifiable; the verifier reports it as an informational
 * PROVENANCE_UNSIGNED_RECORD finding.
 */
export function buildLegacyProvenanceRecord(
  overrides: Partial<ProvenanceRecord> = {},
): ProvenanceRecord {
  return {
    proofId: `rp_legacy_${Math.random().toString(36).slice(2, 10)}`,
    orgId: "org_test",
    provenanceEventType: "RIGHT_ISSUED",
    occurredAt: "2026-03-01T12:00:00.000Z",
    rightId: "rgh_legacy",
    basisId: null,
    offerId: null,
    provenanceBeforeHash: null,
    provenanceAfterHash: "sha256:" + "a".repeat(64),
    signatureAlgorithm: "hmac-sha256",
    signature: "c0ffee".repeat(10) + "abcd",
    signerKeyId: "ledger.v1.org_test",
    payloadCanonical: null,
    ...overrides,
  };
}

function parseDecimal(s: string, places: number): bigint {
  const [intPart, fracPart = ""] = s.split(".");
  const padded = (fracPart + "0".repeat(places)).slice(0, places);
  return BigInt(`${intPart}${padded}`);
}

function formatDecimal(n: bigint, places: number): string {
  const s = n.toString().padStart(places + 1, "0");
  return `${s.slice(0, s.length - places)}.${s.slice(s.length - places)}`;
}

// Note: this fixture uses node:crypto's raw ed25519 signing which
// requires the KeyObject — see signRecord above. We avoid pulling in
// @noble/ed25519 at fixture-build time precisely because the auditor
// SDK must verify what the platform signs, and the platform signs
// via node:crypto in production. (See
// apps/api/src/services/spatialChain/envSigner.ts for the in-process
// signing backend.)

// Suppress unused-import warning when sha256Hex is not used directly.
void sha256Hex;
