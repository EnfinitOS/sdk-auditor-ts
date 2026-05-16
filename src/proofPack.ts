// @enfinitos/sdk-auditor — proof pack parsing + signature verification.
//
// This module takes the raw JSON the platform emitted, validates it
// against the SignedProofPack shape, and verifies every record's
// Ed25519 signature against the KeyDirectory.
//
// It does NOT walk the chain — that's proofChain.ts. It does NOT
// re-project metering or settlement. Each module is a separate
// verification primitive so an auditor can run them in isolation
// (e.g. "I just want to verify signatures; the metering is being
// audited by a different team").
//
// Signature verification path
// ───────────────────────────
// 1. Decode the base64url signature → 64 raw bytes.
// 2. Re-canonicalise the payload locally, and assert byte-equality
//    against the record's `payloadCanonical` — a divergence means
//    the platform's encoder is on a different version than ours.
// 3. Build the signing input: `<payloadCanonical>|<keyId>`.
// 4. Recompute `afterHash = sha256(payloadCanonical)` (no prefix).
//    Assert it matches `record.afterHash`.
// 5. Look up the public key in the KeyDirectory; reject if missing,
//    outside validity window, or revoked.
// 6. Call the underlying Ed25519 verify primitive.
//
// We import `@noble/ed25519` statically — it's a real dependency,
// audited, browser+node+deno+workers safe, no native bindings. The
// previous version dynamic-imported it and fell back to `node:crypto`
// when the import failed, which let the SDK keep working in
// stripped-down Node builds but made it unusable in browsers (because
// `node:crypto` doesn't exist there and the dynamic-import-then-
// fallback path leaked a `Buffer` reference on every verify).
//
// A NodeCryptoEd25519Verifier remains exported below for callers who
// explicitly want the Node-only path (FIPS-validated builds, etc.),
// but it's opt-in. The default verifier is Noble + Web crypto.

import * as ed from "@noble/ed25519";
import { sha512 as nobleSha512 } from "@noble/hashes/sha512";

// Configure @noble/ed25519 v2's required SHA-512 hook once at module
// load. Noble v2 deliberately doesn't bundle a SHA-512 impl; the
// recommended path is to inject @noble/hashes here.
ed.etc.sha512Sync = (...m: Uint8Array[]) =>
  nobleSha512(ed.etc.concatBytes(...m));

import {
  base64UrlDecode,
  canonicaliseProofPayload,
  canonicaliseProofSigningInput,
} from "./canonicalJson";
import { AuditorError } from "./errors";
import { constantTimeHexEqual, sha256Hex } from "./hashing";
import { KeyDirectory } from "./keys";
import {
  SUPPORTED_ENVELOPE_VERSIONS,
  SUPPORTED_SIGNATURE_ALGORITHMS,
  type AuditReasonCode,
  type AuditStep,
  type EnvelopeVersion,
  type ProofRecord,
  type SignedProofPack,
  type VerificationKey,
} from "./types";

// ─────────────────────────────────────────────────────────────────────
// Parsing
// ─────────────────────────────────────────────────────────────────────

/**
 * Parse + structurally validate raw JSON into a SignedProofPack.
 *
 * **Does not verify signatures.** Verification is the caller's next
 * step — this just confirms the shape is well-formed enough that
 * verification can run.
 *
 * Throws AuditorError(INVALID_INPUT) on malformed input. Returns a
 * SignedProofPack with field types narrowed.
 */
export function parseSignedProofPack(input: unknown): SignedProofPack {
  if (typeof input !== "object" || input === null) {
    throw new AuditorError({
      code: "INVALID_INPUT",
      message: "proof pack must be a JSON object",
    });
  }
  const o = input as Record<string, unknown>;
  const reqStr = (k: string): string => {
    const v = o[k];
    if (typeof v !== "string") {
      throw new AuditorError({
        code: "INVALID_INPUT",
        message: `proof pack: '${k}' must be a string`,
      });
    }
    return v;
  };
  const envelopeVersion = reqStr("envelopeVersion");
  if (!isSupportedEnvelopeVersion(envelopeVersion)) {
    // We do NOT throw here — an unsupported envelope is an audit
    // failure (reportable as an INVALID step) not an operational one.
    // But proceeding through parsing makes no sense if we can't
    // interpret the shape. We throw with reason=UNSUPPORTED_ENVELOPE_VERSION
    // so the caller can demote to an INVALID step at the top level.
    throw new AuditorError({
      code: "INVALID_INPUT",
      message: `unsupported envelopeVersion '${envelopeVersion}'`,
      reason: "UNSUPPORTED_ENVELOPE_VERSION",
      detail: { supported: SUPPORTED_ENVELOPE_VERSIONS },
    });
  }
  const records = o["records"];
  if (!Array.isArray(records)) {
    throw new AuditorError({
      code: "INVALID_INPUT",
      message: "proof pack: 'records' must be an array",
    });
  }
  const parsedRecords = records.map((r, i) => parseProofRecord(r, i));

  const pack: SignedProofPack = {
    envelopeVersion,
    issuedAt: reqStr("issuedAt"),
    orgId: reqStr("orgId"),
    packId: reqStr("packId"),
    records: parsedRecords,
  };
  if (typeof o["label"] === "string") {
    pack.label = o["label"];
  }
  if (o["metering"] !== undefined) {
    pack.metering = o["metering"] as NonNullable<SignedProofPack["metering"]>;
  }
  if (o["settlement"] !== undefined) {
    pack.settlement = o["settlement"] as NonNullable<SignedProofPack["settlement"]>;
  }
  return pack;
}

function isSupportedEnvelopeVersion(s: string): s is EnvelopeVersion {
  return (SUPPORTED_ENVELOPE_VERSIONS as readonly string[]).includes(s);
}

function parseProofRecord(input: unknown, index: number): ProofRecord {
  if (typeof input !== "object" || input === null) {
    throw new AuditorError({
      code: "INVALID_INPUT",
      message: `records[${index}] must be an object`,
    });
  }
  const r = input as Record<string, unknown>;
  const payload = r["payload"];
  if (typeof payload !== "object" || payload === null) {
    throw new AuditorError({
      code: "INVALID_INPUT",
      message: `records[${index}].payload must be an object`,
    });
  }
  const p = payload as Record<string, unknown>;
  for (const k of [
    "version",
    "receiptId",
    "spatialAnchorId",
    "issuedAt",
    "renderedAt",
    "nonce",
  ] as const) {
    if (typeof p[k] !== "string") {
      throw new AuditorError({
        code: "INVALID_INPUT",
        message: `records[${index}].payload.${k} must be a string`,
      });
    }
  }
  if (p["version"] !== "1") {
    throw new AuditorError({
      code: "INVALID_INPUT",
      message: `records[${index}].payload.version must be "1"`,
      detail: { got: p["version"] },
    });
  }
  if (typeof p["dwellMs"] !== "number" || !Number.isFinite(p["dwellMs"])) {
    throw new AuditorError({
      code: "INVALID_INPUT",
      message: `records[${index}].payload.dwellMs must be a finite number`,
    });
  }
  const algorithm = r["algorithm"];
  if (
    typeof algorithm !== "string" ||
    !(SUPPORTED_SIGNATURE_ALGORITHMS as readonly string[]).includes(algorithm)
  ) {
    throw new AuditorError({
      code: "INVALID_INPUT",
      message: `records[${index}].algorithm '${String(algorithm)}' unsupported`,
      reason: "UNSUPPORTED_ALGORITHM",
      detail: { supported: SUPPORTED_SIGNATURE_ALGORITHMS },
    });
  }
  for (const k of ["keyId", "signature", "payloadCanonical", "afterHash"] as const) {
    if (typeof r[k] !== "string") {
      throw new AuditorError({
        code: "INVALID_INPUT",
        message: `records[${index}].${k} must be a string`,
      });
    }
  }
  if (r["beforeHash"] !== null && typeof r["beforeHash"] !== "string") {
    throw new AuditorError({
      code: "INVALID_INPUT",
      message: `records[${index}].beforeHash must be a string or null`,
    });
  }
  // Construct with explicit field projection — protects against
  // accidental prototype-pollution or unknown-key smuggling.
  return {
    payload: {
      version: "1",
      receiptId: p["receiptId"] as string,
      correlationId:
        p["correlationId"] === null ? null : (p["correlationId"] as string | null),
      spatialAnchorId: p["spatialAnchorId"] as string,
      spatialPlacementId:
        p["spatialPlacementId"] === null
          ? null
          : (p["spatialPlacementId"] as string | null),
      issuedAt: p["issuedAt"] as string,
      renderedAt: p["renderedAt"] as string,
      dwellMs: p["dwellMs"] as number,
      nonce: p["nonce"] as string,
      witness: p["witness"] === null ? null : (p["witness"] as string | null),
    },
    keyId: r["keyId"] as string,
    algorithm: algorithm as ProofRecord["algorithm"],
    signature: r["signature"] as string,
    payloadCanonical: r["payloadCanonical"] as string,
    beforeHash: r["beforeHash"] as string | null,
    afterHash: r["afterHash"] as string,
  };
}

// ─────────────────────────────────────────────────────────────────────
// Signature verification
// ─────────────────────────────────────────────────────────────────────

/**
 * SignatureVerifier — pluggable Ed25519 verify backend.
 *
 * Default backend: dynamic-import @noble/ed25519 (the canonical
 * choice — small, audited, no native deps). Fallback backend: Node's
 * built-in `crypto.verify` with an Ed25519 public key.
 *
 * The pluggable shape exists so a future build can ship
 * `@noble/ed25519` or `tweetnacl` or a WebCrypto-only path without
 * touching the rest of the SDK.
 */
export interface SignatureVerifier {
  verifyEd25519(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean>;
}

/**
 * NobleEd25519Verifier — uses @noble/ed25519 directly (no dynamic
 * import). Runs in every supported runtime: Node 16+, browsers,
 * Cloudflare Workers, Deno, Bun. This is the SDK's default verifier.
 *
 * The previous version of this class dynamic-imported @noble/ed25519
 * and fell back to `node:crypto` — which made the SDK unusable in
 * browsers because the fallback path always loaded, even when noble
 * had already been bundled. Pinning noble statically removes the
 * fallback's existence as a constraint and lets the bundle ship
 * cleanly to the edge.
 */
export class NobleEd25519Verifier implements SignatureVerifier {
  async verifyEd25519(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    if (publicKey.length !== 32 || signature.length !== 64) return false;
    try {
      return ed.verify(signature, message, publicKey);
    } catch {
      // Any malformed input — non-canonical signature, invalid curve
      // point, etc. — fails closed. Auditors expect a boolean, not
      // a thrown exception path.
      return false;
    }
  }
}

/**
 * NodeCryptoEd25519Verifier — uses Node's built-in `node:crypto`
 * Ed25519 implementation. Opt-in for callers that explicitly want
 * the Node-only path (e.g. FIPS-validated builds, security policies
 * that disallow non-stdlib crypto). NOT usable in browsers or
 * Cloudflare Workers — those should keep the default Noble path.
 *
 * The verifier dynamic-imports `node:crypto` so that bundlers
 * targeting non-Node runtimes don't choke on the import when this
 * class is never instantiated. Instantiating it on a non-Node
 * runtime returns `false` from `verifyEd25519`.
 */
export class NodeCryptoEd25519Verifier implements SignatureVerifier {
  async verifyEd25519(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    if (publicKey.length !== 32 || signature.length !== 64) return false;
    try {
      // Dynamic-import so non-Node bundles tree-shake this away.
      const nodeCrypto = await import("node:crypto");
      // Wrap the raw 32-byte Ed25519 public key in its fixed SPKI
      // DER prefix so Node's `createPublicKey` can ingest it without
      // requiring callers to hand-roll the DER themselves.
      const SPKI_PREFIX = Buffer.from(
        "302a300506032b6570032100",
        "hex",
      );
      const spkiDer = Buffer.concat([SPKI_PREFIX, Buffer.from(publicKey)]);
      const keyObj = nodeCrypto.createPublicKey({
        key: spkiDer,
        format: "der",
        type: "spki",
      });
      return nodeCrypto.verify(
        null,
        Buffer.from(message),
        keyObj,
        Buffer.from(signature),
      );
    } catch {
      // Any malformed input or non-Node runtime fails closed.
      return false;
    }
  }
}

/**
 * Default verifier — exported as the SDK's preferred backend.
 *
 * Callers can override by passing a custom `SignatureVerifier` to
 * `verifyProofPack` / `verifyAll`, e.g. to wire in a FIPS-validated
 * native Ed25519 implementation in regulated environments.
 */
export const defaultSignatureVerifier: SignatureVerifier = new NobleEd25519Verifier();

// ─────────────────────────────────────────────────────────────────────
// Per-record verification
// ─────────────────────────────────────────────────────────────────────

/**
 * verifyProofRecord — re-canonicalises + re-hashes + verifies the
 * signature on one ProofRecord. Returns an array of audit steps:
 * canonicalisation, after-hash, key-lookup, signature. Each step is
 * either VALID or INVALID with a structured reason.
 *
 * Designed to be called per-record by `verifyProofPack` so a tampered
 * record reports specifically WHICH check failed.
 */
export async function verifyProofRecord(
  record: ProofRecord,
  recordIndex: number,
  keys: KeyDirectory,
  verifier: SignatureVerifier,
): Promise<AuditStep[]> {
  const steps: AuditStep[] = [];

  // 1. Canonicalisation parity.
  let localCanonical: string;
  try {
    localCanonical = canonicaliseProofPayload(record.payload);
  } catch (e) {
    steps.push({
      target: `record[${recordIndex}].payloadCanonical`,
      kind: "canonicalisation",
      status: "INVALID",
      reason: "PAYLOAD_CANONICAL_MISMATCH",
      message:
        e instanceof Error
          ? `canonicalisation threw: ${e.message}`
          : "canonicalisation threw",
    });
    // If canonicalisation itself failed, downstream checks are
    // meaningless — short-circuit.
    return steps;
  }
  if (localCanonical !== record.payloadCanonical) {
    steps.push({
      target: `record[${recordIndex}].payloadCanonical`,
      kind: "canonicalisation",
      status: "INVALID",
      reason: "PAYLOAD_CANONICAL_MISMATCH",
      message:
        "the canonical payload the SDK computed does not match the bytes the pack ships — encoder version skew or tampering",
      detail: {
        expected: record.payloadCanonical.slice(0, 256),
        actual: localCanonical.slice(0, 256),
      },
    });
  } else {
    steps.push({
      target: `record[${recordIndex}].payloadCanonical`,
      kind: "canonicalisation",
      status: "VALID",
      message: "canonical payload bytes match",
    });
  }

  // 2. afterHash parity.
  const expectedAfterHash = sha256Hex(localCanonical);
  if (!constantTimeHexEqual(expectedAfterHash, record.afterHash)) {
    steps.push({
      target: `record[${recordIndex}].afterHash`,
      kind: "canonicalisation",
      status: "INVALID",
      reason: "AFTER_HASH_MISMATCH",
      message: "record afterHash does not equal sha256(payloadCanonical)",
      detail: { expected: expectedAfterHash, actual: record.afterHash },
    });
  } else {
    steps.push({
      target: `record[${recordIndex}].afterHash`,
      kind: "canonicalisation",
      status: "VALID",
      message: "afterHash equals sha256(payloadCanonical)",
    });
  }

  // 3. Key lookup.
  const lookup = keys.lookup(record.keyId, record.payload.issuedAt);
  if (lookup.kind === "miss") {
    steps.push({
      target: `record[${recordIndex}].keyId`,
      kind: "key_lookup",
      status: "INVALID",
      reason: lookup.reason,
      message: keyMissMessage(lookup.reason, record.keyId),
      detail: { keyId: record.keyId, issuedAt: record.payload.issuedAt },
    });
    // Can't verify the signature without a key — but we still ran
    // canonicalisation, so don't short-circuit overall.
    return steps;
  }
  steps.push({
    target: `record[${recordIndex}].keyId`,
    kind: "key_lookup",
    status: "VALID",
    message: `key '${record.keyId}' resolved and valid for issuedAt`,
  });

  // 4. Signature verification.
  let sigBytes: Uint8Array;
  let pubBytes: Uint8Array;
  try {
    sigBytes = base64UrlDecode(record.signature);
    pubBytes = base64UrlDecode(lookup.key.publicKey);
  } catch (e) {
    steps.push({
      target: `record[${recordIndex}].signature`,
      kind: "signature",
      status: "INVALID",
      reason: "SIGNATURE_MALFORMED",
      message:
        e instanceof Error
          ? `signature/public-key decoding failed: ${e.message}`
          : "signature/public-key decoding failed",
    });
    return steps;
  }
  if (sigBytes.length !== 64 || pubBytes.length !== 32) {
    steps.push({
      target: `record[${recordIndex}].signature`,
      kind: "signature",
      status: "INVALID",
      reason: "SIGNATURE_MALFORMED",
      message: `expected 64-byte signature / 32-byte public key, got ${sigBytes.length} / ${pubBytes.length}`,
    });
    return steps;
  }
  const signingInput = canonicaliseProofSigningInput(
    record.payload,
    record.keyId,
  );
  const message = new TextEncoder().encode(signingInput);
  let ok = false;
  try {
    ok = await verifier.verifyEd25519(pubBytes, message, sigBytes);
  } catch (e) {
    steps.push({
      target: `record[${recordIndex}].signature`,
      kind: "signature",
      status: "INVALID",
      reason: "SIGNATURE_INVALID",
      message:
        e instanceof Error
          ? `signature verify threw: ${e.message}`
          : "signature verify threw",
    });
    return steps;
  }
  steps.push({
    target: `record[${recordIndex}].signature`,
    kind: "signature",
    status: ok ? "VALID" : "INVALID",
    ...(ok ? {} : { reason: "SIGNATURE_INVALID" as AuditReasonCode }),
    message: ok
      ? "Ed25519 signature verifies against the declared key"
      : "Ed25519 signature did NOT verify — the record has been tampered with, or the keyId points to a different key than the one that actually signed it",
  });

  return steps;
}

function keyMissMessage(
  reason:
    | "UNKNOWN_KEY_ID"
    | "KEY_OUTSIDE_VALIDITY_WINDOW"
    | "KEY_REVOKED_BEFORE_ISSUANCE",
  keyId: string,
): string {
  switch (reason) {
    case "UNKNOWN_KEY_ID":
      return `keyId '${keyId}' is not in the verification key directory`;
    case "KEY_OUTSIDE_VALIDITY_WINDOW":
      return `keyId '${keyId}' is outside its declared validity window for the record's issuedAt`;
    case "KEY_REVOKED_BEFORE_ISSUANCE":
      return `keyId '${keyId}' was revoked before the record's issuedAt — the record cannot be trusted`;
  }
}

// ─────────────────────────────────────────────────────────────────────
// Convenience: re-export the structural shape of VerificationKey for
// callers building local key sets at test time.
// ─────────────────────────────────────────────────────────────────────

export type { VerificationKey };
