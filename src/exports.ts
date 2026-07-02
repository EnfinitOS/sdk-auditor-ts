// @enfinitos/sdk-auditor — signed-export verification (export.v1).
//
// The platform signs its metering + settlement summaries on demand
// (`GET /v1/metering?export=true`, `GET /v1/settlement?export=true`) into a
// `SignedExport` envelope so a third party can hold a portable, offline-
// verifiable copy of the money-plane numbers — the same "verify us without
// trusting us" guarantee the proof packs carry. This module is the verifier
// side; the signer is `packages/sandbox-core/src/exports.ts` and the two are
// byte-parity mirrors:
//
//   payloadCanonical      = canonicalSortKeys(payload)   (recursive lexicographic
//                           key sort, array order preserved)
//   payloadCanonicalHash  = sha256 hex (bare, no prefix) of payloadCanonical
//   signature             = base64url( Ed25519( utf8(`${payloadCanonical}|${keyId}`) ) )
//
// The keyId is bound into the signed bytes, so a signature cannot be lifted
// onto a different key. NOTE (documented signer behaviour): the envelope
// metadata OUTSIDE `payload` — `kind`, `envelopeVersion`, `orgId`,
// `exportedAt` — is NOT covered by the signature. Treat the signed payload as
// the evidence; treat the envelope metadata as convenience labelling. The
// payload itself carries `orgId` and period bounds, so the load-bearing facts
// are all inside the signed bytes.
//
// Verification never throws on bad input — every failure is an AuditStep with
// a stable reason code, mirroring the rest of the SDK.

import { canonicalSortKeys, base64UrlDecode } from "./canonicalJson.js";
import { sha256Hex } from "./hashing.js";
import { KeyDirectory } from "./keys.js";
import {
  NobleEd25519Verifier,
  type SignatureVerifier,
} from "./proofPack.js";
import { SDK_VERSION, type AuditStep, type AuditStepStatus } from "./types.js";

/**
 * SignedExport — wire-compatible mirror of the platform envelope
 * (packages/sandbox-core/src/exports.ts `SignedExport<T>`).
 */
export type SignedExport<T = unknown> = {
  /** "metering.export.v1" | "settlement.export.v1" (open for future kinds). */
  kind: string;
  /** Envelope version — this verifier supports "export.v1". */
  envelopeVersion: string;
  orgId: string;
  /** ISO-8601. Also the instant the signing key is validity-checked against. */
  exportedAt: string;
  keyId: string;
  algorithm: string;
  /** The summary as issued (MeteringSummary / SettlementSummary / …). */
  payload: T;
  /** Transparency copy of the exact bytes that were hashed + signed. */
  payloadCanonical: string;
  /** sha256 hex of payloadCanonical. */
  payloadCanonicalHash: string;
  /** base64url Ed25519 signature over `${payloadCanonical}|${keyId}`. */
  signature: string;
};

export type SignedExportAuditReport = {
  status: AuditStepStatus;
  /** Envelope `kind` as declared (unsigned metadata — see module note). */
  kind: string;
  orgId: string;
  keyId: string;
  exportedAt: string;
  /** ISO-8601 — when the audit ran. */
  verifiedAt: string;
  sdkVersion: string;
  steps: AuditStep[];
};

export type VerifySignedExportOptions = {
  /** Pluggable Ed25519 backend. Defaults to the Noble verifier. */
  verifier?: SignatureVerifier;
};

const TEXT_ENCODER = new TextEncoder();

/**
 * Verify a signed export offline against a key directory.
 *
 * Steps (each an AuditStep; overall status is INVALID if any step is):
 *   1. envelope        — envelopeVersion is "export.v1", algorithm "ed25519".
 *   2. key_lookup      — keyId resolves in the directory and is inside its
 *                        validity window (checked at `exportedAt`), not revoked.
 *   3. canonicalisation— re-canonicalising `payload` reproduces
 *                        `payloadCanonical` byte-for-byte, and its sha256
 *                        matches `payloadCanonicalHash`.
 *   4. signature       — Ed25519 over `${payloadCanonical}|${keyId}` verifies
 *                        under the directory key.
 *
 * The deeper content checks (does the metering re-project? does the settlement
 * reconcile?) remain the job of `verifyMeteringProjection` /
 * `verifySettlementReconciliation` — pass them `export.payload` after this
 * signature gate passes.
 */
export async function verifySignedExport(
  exp: SignedExport,
  keys: KeyDirectory,
  options: VerifySignedExportOptions = {},
): Promise<SignedExportAuditReport> {
  const steps: AuditStep[] = [];
  const verifier = options.verifier ?? new NobleEd25519Verifier();

  // ── 1. Envelope ──────────────────────────────────────────────────
  if (exp.envelopeVersion !== "export.v1") {
    steps.push({
      target: "export.envelopeVersion",
      kind: "envelope",
      status: "INVALID",
      reason: "UNSUPPORTED_ENVELOPE_VERSION",
      message: `unsupported export envelope version "${exp.envelopeVersion}" (verifier supports "export.v1")`,
    });
  } else {
    steps.push({
      target: "export.envelopeVersion",
      kind: "envelope",
      status: "VALID",
      message: "envelope version export.v1",
    });
  }
  if (exp.algorithm !== "ed25519") {
    steps.push({
      target: "export.algorithm",
      kind: "envelope",
      status: "INVALID",
      reason: "UNSUPPORTED_ALGORITHM",
      message: `unsupported signature algorithm "${exp.algorithm}"`,
    });
  } else {
    steps.push({
      target: "export.algorithm",
      kind: "envelope",
      status: "VALID",
      message: "algorithm ed25519",
    });
  }

  // ── 2. Key lookup (validity window anchored at exportedAt) ────────
  const lookup = keys.lookup(exp.keyId, exp.exportedAt);
  if (lookup.kind === "miss") {
    steps.push({
      target: "export.keyId",
      kind: "key_lookup",
      status: "INVALID",
      reason: lookup.reason,
      message: `signing key "${exp.keyId}" not usable at ${exp.exportedAt}: ${lookup.reason}`,
    });
    return finish(exp, steps);
  }
  steps.push({
    target: "export.keyId",
    kind: "key_lookup",
    status: "VALID",
    message: `key "${exp.keyId}" resolved and inside its validity window`,
  });

  // ── 3. Canonicalisation + hash transparency ───────────────────────
  const recomputedCanonical = canonicalSortKeys(exp.payload);
  if (recomputedCanonical !== exp.payloadCanonical) {
    steps.push({
      target: "export.payloadCanonical",
      kind: "canonicalisation",
      status: "INVALID",
      reason: "PAYLOAD_CANONICAL_MISMATCH",
      message:
        "re-canonicalising the payload does not reproduce payloadCanonical — the payload was modified after signing",
    });
    return finish(exp, steps);
  }
  steps.push({
    target: "export.payloadCanonical",
    kind: "canonicalisation",
    status: "VALID",
    message: "payload re-canonicalises byte-for-byte",
  });

  const recomputedHash = sha256Hex(recomputedCanonical);
  if (recomputedHash !== exp.payloadCanonicalHash) {
    steps.push({
      target: "export.payloadCanonicalHash",
      kind: "canonicalisation",
      status: "INVALID",
      reason: "EXPORT_PAYLOAD_HASH_MISMATCH",
      message: "sha256(payloadCanonical) does not equal payloadCanonicalHash",
      detail: { expected: recomputedHash, actual: exp.payloadCanonicalHash },
    });
    return finish(exp, steps);
  }
  steps.push({
    target: "export.payloadCanonicalHash",
    kind: "canonicalisation",
    status: "VALID",
    message: "payload hash matches",
  });

  // ── 4. Signature over `${payloadCanonical}|${keyId}` ──────────────
  let publicKeyBytes: Uint8Array;
  let signatureBytes: Uint8Array;
  try {
    publicKeyBytes = base64UrlDecode(lookup.key.publicKey);
    signatureBytes = base64UrlDecode(exp.signature);
  } catch {
    steps.push({
      target: "export.signature",
      kind: "signature",
      status: "INVALID",
      reason: "SIGNATURE_MALFORMED",
      message: "signature or public key is not valid base64url",
    });
    return finish(exp, steps);
  }
  const message = TEXT_ENCODER.encode(`${exp.payloadCanonical}|${exp.keyId}`);
  const ok = await verifier.verifyEd25519(publicKeyBytes, message, signatureBytes);
  steps.push(
    ok
      ? {
          target: "export.signature",
          kind: "signature",
          status: "VALID",
          message: "Ed25519 signature verifies under the directory key",
        }
      : {
          target: "export.signature",
          kind: "signature",
          status: "INVALID",
          reason: "SIGNATURE_INVALID",
          message: "Ed25519 signature does not verify — the export is not authentic",
        },
  );
  return finish(exp, steps);
}

function finish(exp: SignedExport, steps: AuditStep[]): SignedExportAuditReport {
  const status: AuditStepStatus = steps.some((s) => s.status === "INVALID")
    ? "INVALID"
    : "VALID";
  return {
    status,
    kind: exp.kind,
    orgId: exp.orgId,
    keyId: exp.keyId,
    exportedAt: exp.exportedAt,
    verifiedAt: new Date().toISOString(),
    sdkVersion: SDK_VERSION,
    steps,
  };
}
