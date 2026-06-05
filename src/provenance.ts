// @enfinitos/sdk-auditor — rights-provenance write-time signature
// verification.
//
// Wave 14 Phase 2. Independently verifies the per-record Ed25519
// signatures the platform computes at write time on every rights-
// provenance row (apps/api/src/modules/rights/provenanceSigner.ts):
// basis assert/verify/reject, right issue/suspend/resume/revoke/
// expire, offer propose/accept/counter/reject/withdraw/expire, and
// challenge open/resolve/withdraw.
//
// The signing input is a flat pipe-delimited string — NOT canonical
// JSON — so TS / Rust / Python verifiers reconstruct the exact bytes
// without sharing a canonical-JSON library:
//
//   "rightProvenance.v1|<orgId>|<eventType>|<rightId|->|<basisId|->|
//    <offerId|->|<beforeHash|->|<afterHash|->|<keyId>"
//
// where "-" encodes absence (null or empty string — the platform
// deliberately collapses the two so an absent rightId cannot collide
// with a literal empty-string rightId).
//
// Verification path per record
// ────────────────────────────
//   ed25519 records (write-time signed):
//     1. Re-derive the canonical signing input from the record's raw
//        fields + signerKeyId, and assert byte-equality against the
//        record's `payloadCanonical` transparency field
//        (PROVENANCE_CANONICAL_MISMATCH on divergence).
//     2. Look the signerKeyId up in the KeyDirectory; reject if
//        missing / outside validity window / revoked
//        (UNKNOWN_KEY_ID / KEY_OUTSIDE_VALIDITY_WINDOW /
//        KEY_REVOKED_BEFORE_ISSUANCE — same codes as receipts).
//     3. Decode the base64url signature + public key
//        (PROVENANCE_SIGNATURE_MALFORMED if not 64/32 bytes).
//     4. Ed25519-verify the signature over the canonical bytes
//        (PROVENANCE_SIGNATURE_INVALID on failure).
//
//   hmac-sha256 records (legacy, pre-Wave-14):
//     The platform synthesised a read-time transport HMAC; there is
//     nothing write-signed for an independent party to verify. The
//     verifier reports a single SKIPPED step per record carrying the
//     informational reason PROVENANCE_UNSIGNED_RECORD — NEVER an
//     INVALID. This is the honest-history posture the platform chose
//     at Wave 14 (no retroactive back-signing): published 0.0.1-era
//     exports keep verifying, with the unsigned records clearly
//     labelled.
//
// Relationship to the other chain verifiers
// ─────────────────────────────────────────
// This module verifies WHO wrote each row (non-repudiation). It is
// deliberately orthogonal to:
//   - tenantChain.ts — verifies the rows' POSITION in the tenant's
//     append-only history (insertion/rewrite detection). Run both
//     for the full provenance posture.
//   - proofChain.ts — the spatial-chain receipt walker; receipts are
//     a different artefact with a different canonical encoding.

import type {
  AuditReasonCode,
  AuditStep,
  ProvenanceAuditReport,
  ProvenanceRecord,
  VerificationKey,
} from "./types";
import { SDK_VERSION } from "./types";
import { base64UrlDecode } from "./canonicalJson";
import { KeyDirectory } from "./keys";
import {
  defaultSignatureVerifier,
  type SignatureVerifier,
} from "./proofPack";

/** Stable canonical signing-input version tag. */
export const PROVENANCE_SIGNING_VERSION = "rightProvenance.v1" as const;

/**
 * The subset of ProvenanceRecord fields that participate in the
 * canonical signing input. Kept as its own type so callers building
 * conformance fixtures don't have to fabricate the envelope fields.
 */
export interface ProvenanceSigningFields {
  orgId: string;
  /** The platform's raw lifecycle event tag (e.g. RIGHT_ISSUED). */
  eventType: string;
  rightId: string | null;
  basisId: string | null;
  offerId: string | null;
  beforeHash: string | null;
  afterHash: string | null;
}

/**
 * Reconstruct the exact canonical string the platform signed at write
 * time. Pure; byte-for-byte parity with
 * apps/api/src/modules/rights/provenanceSigner.ts
 * `canonicaliseProvenanceSigningInput`. Absence (null or empty
 * string) encodes as "-".
 */
export function canonicaliseProvenanceSigningInput(
  fields: ProvenanceSigningFields,
  keyId: string,
): string {
  const f = (v: string | null) => (v == null || v === "" ? "-" : v);
  return [
    PROVENANCE_SIGNING_VERSION,
    f(fields.orgId),
    f(fields.eventType),
    f(fields.rightId),
    f(fields.basisId),
    f(fields.offerId),
    f(fields.beforeHash),
    f(fields.afterHash),
    f(keyId),
  ].join("|");
}

// ─────────────────────────────────────────────────────────────────────
// Per-record verification
// ─────────────────────────────────────────────────────────────────────

/**
 * verifyProvenanceRecord — verify one rights-provenance record's
 * write-time signature. Returns an array of AuditSteps mirroring the
 * receipt-side `verifyProofRecord` shape:
 *
 *   - legacy (hmac-sha256) record → one SKIPPED step with the
 *     informational reason PROVENANCE_UNSIGNED_RECORD.
 *   - ed25519 record → canonicalisation step, key-lookup step,
 *     signature step; each VALID or INVALID with a structured reason.
 */
export async function verifyProvenanceRecord(
  record: ProvenanceRecord,
  recordIndex: number,
  keys: KeyDirectory,
  verifier: SignatureVerifier = defaultSignatureVerifier,
): Promise<AuditStep[]> {
  const steps: AuditStep[] = [];
  const target = (suffix: string) => `provenance[${recordIndex}].${suffix}`;

  // Legacy partition — informational, never a failure. There is no
  // write-time signature to verify; the platform's honest-history
  // decision at Wave 14 was to tag rather than back-sign.
  if (record.signatureAlgorithm !== "ed25519") {
    steps.push({
      target: target("signature"),
      kind: "provenance_signature",
      status: "SKIPPED",
      reason: "PROVENANCE_UNSIGNED_RECORD" as AuditReasonCode,
      message:
        "record pre-dates write-time provenance signing (read-time HMAC only) — not independently verifiable; informational, not a failure",
      detail: {
        signatureAlgorithm: record.signatureAlgorithm,
        provenanceEventType: record.provenanceEventType,
      },
    });
    return steps;
  }

  // 1. Canonical-input parity. The record ships `payloadCanonical` as
  // a transparency aid; we re-derive from the raw fields and compare
  // byte-for-byte. A divergence means the raw fields were edited
  // after signing, or the platform's canonicaliser version skewed.
  const reconstructed = canonicaliseProvenanceSigningInput(
    {
      orgId: record.orgId,
      eventType: record.provenanceEventType,
      rightId: record.rightId,
      basisId: record.basisId,
      offerId: record.offerId,
      beforeHash: record.provenanceBeforeHash,
      afterHash: record.provenanceAfterHash,
    },
    record.signerKeyId,
  );
  if (record.payloadCanonical == null) {
    steps.push({
      target: target("payloadCanonical"),
      kind: "provenance_signature",
      status: "INVALID",
      reason: "PROVENANCE_CANONICAL_MISMATCH" as AuditReasonCode,
      message:
        "ed25519 record carries no payloadCanonical — the signed bytes cannot be attested; partial-fill violates the write-time signing contract",
    });
    return steps;
  }
  if (reconstructed !== record.payloadCanonical) {
    steps.push({
      target: target("payloadCanonical"),
      kind: "provenance_signature",
      status: "INVALID",
      reason: "PROVENANCE_CANONICAL_MISMATCH" as AuditReasonCode,
      message:
        "the canonical signing input the SDK reconstructed from the record's raw fields does not match the bytes the record ships — field tampering or canonicaliser version skew",
      detail: {
        expected: record.payloadCanonical.slice(0, 256),
        actual: reconstructed.slice(0, 256),
      },
    });
    // Continue: the signature step over the SHIPPED canonical bytes
    // still tells the auditor whether the signature is at least
    // internally consistent — useful forensics either way.
  } else {
    steps.push({
      target: target("payloadCanonical"),
      kind: "provenance_signature",
      status: "VALID",
      message: "canonical signing input reconstructs from the raw fields",
    });
  }

  // 2. Key lookup — same directory + validity-window semantics as the
  // receipt verifier; `occurredAt` plays the role of issuedAt.
  const lookup = keys.lookup(record.signerKeyId, record.occurredAt);
  if (lookup.kind === "miss") {
    steps.push({
      target: target("signerKeyId"),
      kind: "key_lookup",
      status: "INVALID",
      reason: lookup.reason,
      message: `provenance signing key '${record.signerKeyId}' rejected: ${lookup.reason}`,
      detail: {
        signerKeyId: record.signerKeyId,
        occurredAt: record.occurredAt,
      },
    });
    return steps;
  }
  steps.push({
    target: target("signerKeyId"),
    kind: "key_lookup",
    status: "VALID",
    message: `key '${record.signerKeyId}' resolved and valid for occurredAt`,
  });

  // 3. Decode signature + public key — strict base64url (unpadded).
  let sigBytes: Uint8Array;
  let pubBytes: Uint8Array;
  try {
    sigBytes = base64UrlDecode(record.signature);
    pubBytes = base64UrlDecode(lookup.key.publicKey);
  } catch (e) {
    steps.push({
      target: target("signature"),
      kind: "provenance_signature",
      status: "INVALID",
      reason: "PROVENANCE_SIGNATURE_MALFORMED" as AuditReasonCode,
      message:
        e instanceof Error
          ? `signature/public-key decoding failed: ${e.message}`
          : "signature/public-key decoding failed",
    });
    return steps;
  }
  if (sigBytes.length !== 64 || pubBytes.length !== 32) {
    steps.push({
      target: target("signature"),
      kind: "provenance_signature",
      status: "INVALID",
      reason: "PROVENANCE_SIGNATURE_MALFORMED" as AuditReasonCode,
      message: `expected 64-byte signature / 32-byte public key, got ${sigBytes.length} / ${pubBytes.length}`,
    });
    return steps;
  }

  // 4. Ed25519 verify — over the SHIPPED canonical bytes (the exact
  // bytes the platform claims it signed). If step 1 already flagged a
  // canonical mismatch, a VALID result here means "internally
  // consistent signature over tampered claims" — the report is
  // already INVALID from step 1, so no failure is masked.
  const message = new TextEncoder().encode(record.payloadCanonical);
  let ok = false;
  try {
    ok = await verifier.verifyEd25519(pubBytes, message, sigBytes);
  } catch (e) {
    steps.push({
      target: target("signature"),
      kind: "provenance_signature",
      status: "INVALID",
      reason: "PROVENANCE_SIGNATURE_INVALID" as AuditReasonCode,
      message:
        e instanceof Error
          ? `signature verify threw: ${e.message}`
          : "signature verify threw",
    });
    return steps;
  }
  steps.push({
    target: target("signature"),
    kind: "provenance_signature",
    status: ok ? "VALID" : "INVALID",
    ...(ok ? {} : { reason: "PROVENANCE_SIGNATURE_INVALID" as AuditReasonCode }),
    message: ok
      ? "Ed25519 write-time signature verifies against the declared key"
      : "Ed25519 write-time signature did NOT verify — the record was tampered with after signing, or the signerKeyId points to a different key than the one that signed it",
  });

  return steps;
}

// ─────────────────────────────────────────────────────────────────────
// Chain-level verification
// ─────────────────────────────────────────────────────────────────────

export interface VerifyProvenanceChainOptions {
  /**
   * When supplied, every record's orgId must match — a mixed-tenant
   * record set is reported as PROVENANCE_ORG_MISMATCH (a spliced
   * export). Omit for multi-tenant forensic walks.
   */
  expectedOrgId?: string;
  /** Pluggable Ed25519 backend; defaults to the SDK's Noble verifier. */
  verifier?: SignatureVerifier;
}

/**
 * verifyProvenanceChain — verify the write-time signatures across a
 * rights-provenance record set (e.g. the records array of a
 * `/proof/export` archive, or a `/proof/:id/chain` walk).
 *
 * Per record this runs `verifyProvenanceRecord`; legacy
 * (hmac-sha256) records surface as informational SKIPPED steps with
 * the PROVENANCE_UNSIGNED_RECORD reason and never fail the report.
 *
 * Report status:
 *   - INVALID if any step is INVALID;
 *   - VALID if at least one record verified and none failed;
 *   - SKIPPED if every record was legacy (nothing was verifiable) —
 *     conservative: a fully-unsigned set must not be promoted to
 *     VALID just because nothing contradicted it.
 *
 * Backwards compatibility: exports produced before the platform
 * shipped write-time provenance signing verify as SKIPPED with
 * informational findings only — never INVALID.
 *
 * NOTE: this primitive proves WHO signed each record. To prove the
 * records' POSITION in the tenant's append-only history (insertion /
 * rewrite detection), additionally run `verifyTenantChain` over the
 * same records' tenant-chain fields.
 */
export async function verifyProvenanceChain(
  records: ReadonlyArray<ProvenanceRecord>,
  keys: ReadonlyArray<VerificationKey> | KeyDirectory,
  options: VerifyProvenanceChainOptions = {},
): Promise<ProvenanceAuditReport> {
  const verifiedAt = new Date().toISOString();
  const verifier = options.verifier ?? defaultSignatureVerifier;
  const directory =
    keys instanceof KeyDirectory
      ? keys
      : new KeyDirectory({
          source: "local",
          snapshotId: null,
          issuedAt: null,
          keys: [...keys],
        });

  const steps: AuditStep[] = [];
  let signedRecordCount = 0;
  let unsignedRecordCount = 0;

  if (records.length === 0) {
    return {
      status: "INVALID",
      verifiedAt,
      sdkVersion: SDK_VERSION,
      recordCount: 0,
      signedRecordCount: 0,
      unsignedRecordCount: 0,
      steps: [
        {
          target: "records",
          kind: "provenance_signature",
          status: "INVALID",
          reason: "MALFORMED_PACK" as AuditReasonCode,
          message:
            "provenance signature audit received an empty record set — nothing to verify",
        },
      ],
    };
  }

  for (let i = 0; i < records.length; i++) {
    const record = records[i]!;

    // Org consistency — a spliced multi-tenant export is rejected
    // before the signature even runs (the signature would verify;
    // the splice is at the SET level, not the record level).
    if (options.expectedOrgId && record.orgId !== options.expectedOrgId) {
      steps.push({
        target: `provenance[${i}].orgId`,
        kind: "provenance_signature",
        status: "INVALID",
        reason: "PROVENANCE_ORG_MISMATCH" as AuditReasonCode,
        message: `record orgId '${record.orgId}' does not match the expected orgId '${options.expectedOrgId}' — record set spliced across tenants`,
        detail: { expected: options.expectedOrgId, actual: record.orgId },
      });
    }

    if (record.signatureAlgorithm === "ed25519") {
      signedRecordCount += 1;
    } else {
      unsignedRecordCount += 1;
    }

    steps.push(...(await verifyProvenanceRecord(record, i, directory, verifier)));
  }

  const anyInvalid = steps.some((s) => s.status === "INVALID");
  const anyValid = steps.some((s) => s.status === "VALID");
  const status: ProvenanceAuditReport["status"] = anyInvalid
    ? "INVALID"
    : anyValid
      ? "VALID"
      : "SKIPPED";

  return {
    status,
    verifiedAt,
    sdkVersion: SDK_VERSION,
    recordCount: records.length,
    signedRecordCount,
    unsignedRecordCount,
    steps,
  };
}
