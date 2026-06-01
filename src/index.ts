// @enfinitos/sdk-auditor — public surface.

import { EnfinitOSAuditor, type EnfinitOSAuditorOptions } from "./auditor";
import type { AuditBundle, FullAuditReport } from "./types";

export { EnfinitOSAuditor } from "./auditor";
export type { EnfinitOSAuditorOptions } from "./auditor";

/**
 * Convenience top-level wrapper around `EnfinitOSAuditor.verifyAll`.
 *
 * The class form (`new EnfinitOSAuditor(opts).verifyAll(bundle)`) is
 * the right entry point when the caller is auditing many packs in
 * sequence — the auditor instance caches the verification-key
 * directory so a thousand packs reuse the same fetched / parsed
 * key set.
 *
 * For one-shot regulator + sandbox conformance scenarios where a
 * single pack is being verified, this function is friendlier: it
 * constructs a transient auditor, runs the full pipeline, and
 * returns the FullAuditReport.
 *
 *   import { verifyAll } from "@enfinitos/sdk-auditor";
 *
 *   const report = await verifyAll(
 *     { pack, verificationKeys: [key] },
 *     { verificationKeySource: "local" },
 *   );
 *   if (report.status !== "VALID") {  ...  }
 *
 * The EnfinitOSAuditor constructor requires `localKeys` when source
 * is `"local"` (and fails fast otherwise). For the common conformance
 * pattern where the bundle ships its own `verificationKeys`, this
 * wrapper pre-seeds those into the constructor so the source-check
 * passes; the class-side `verifyAll` then performs its per-bundle
 * override later in the pipeline. When no `verificationKeys` are on
 * the bundle and the caller passes no options, defaults to
 * `verificationKeySource: "platform"` (the auditor fetches the
 * published key directory at runtime).
 */
export async function verifyAll(
  bundle: AuditBundle,
  options?: EnfinitOSAuditorOptions,
): Promise<FullAuditReport> {
  let resolved: EnfinitOSAuditorOptions;
  if (options) {
    // Honour the caller's source choice. If they said "local" but
    // didn't supply localKeys, pull them from the bundle so the
    // constructor's guard doesn't trip.
    if (
      options.verificationKeySource === "local" &&
      !options.localKeys &&
      bundle.verificationKeys
    ) {
      resolved = { ...options, localKeys: bundle.verificationKeys };
    } else {
      resolved = options;
    }
  } else if (bundle.verificationKeys) {
    // No options + bundle has keys → local source with bundle keys.
    resolved = {
      verificationKeySource: "local",
      localKeys: bundle.verificationKeys,
    };
  } else {
    // No options + no bundle keys → fetch from the platform's
    // published verification-key directory at runtime.
    resolved = { verificationKeySource: "platform" };
  }
  const auditor = new EnfinitOSAuditor(resolved);
  return auditor.verifyAll(bundle);
}

export {
  parseSignedProofPack,
  verifyProofRecord,
  defaultSignatureVerifier,
  NobleEd25519Verifier,
  NodeCryptoEd25519Verifier,
  type SignatureVerifier,
} from "./proofPack";

export { verifyProofChain } from "./proofChain";

export {
  verifyTenantChain,
  canonicaliseTenantChainLink,
  genesisChainTip,
  TENANT_CHAIN_VERSION,
  type TenantChainedRecord,
} from "./tenantChain";

// ─────────────────────────────────────────────────────────────────────
// Independent single-receipt verification — Wave 27 / Phase 4.
//
// Convenience wrapper around `verifyProofRecord` for the common case
// where a buyer wants to verify a single receipt offline against a
// pinned key snapshot. Returns a `{ valid: boolean; reasons: ... }`
// shape rather than the raw `AuditStep[]` — the auditor's full report
// is the source of truth for forensic walks; this is the ergonomic
// path for buyer integrations.
// ─────────────────────────────────────────────────────────────────────

import { verifyProofRecord as _verifyProofRecord, defaultSignatureVerifier as _defaultVerifier } from "./proofPack";
import { KeyDirectory as _KeyDirectory } from "./keys";
import type { ProofRecord, VerificationKey, AuditStep } from "./types";

export interface VerifyReceiptResult {
  valid: boolean;
  /**
   * The complete list of audit steps from the verifier. Empty when
   * `valid === true` AND the caller only wants the boolean; populated
   * with INVALID step entries when `valid === false`.
   */
  steps: AuditStep[];
  /**
   * The high-level reason string for the failure, or `null` on success.
   * Picked from the first INVALID step so a buyer-side integration can
   * surface a single string without parsing the step list.
   */
  reason: string | null;
}

/**
 * Verify a single ProofRecord against a pinned set of verification
 * keys, end-to-end (canonicalisation parity, afterHash parity, key
 * lookup, Ed25519 signature). Designed for buyer integrations:
 * given a receipt and the published key snapshot, "is this real?"
 *
 * Pure function in the cryptographic sense — no network calls; the
 * caller pre-fetched and pinned the keys. Suitable for embedding in
 * a buyer's own audit pipeline or in their CI as a contract test.
 */
export async function verifyReceiptIndependently(
  record: ProofRecord,
  keys: ReadonlyArray<VerificationKey>,
): Promise<VerifyReceiptResult> {
  const directory = new _KeyDirectory([...keys]);
  const steps = await _verifyProofRecord(record, 0, directory, _defaultVerifier);
  const invalid = steps.find((s) => s.status === "INVALID");
  return {
    valid: invalid === undefined,
    steps,
    reason: invalid?.reason ?? null,
  };
}

export { verifyMeteringProjection } from "./meteringAudit";

export { verifySettlementReconciliation } from "./settlementAudit";

export {
  loadKeyDirectory,
  KeyDirectory,
  type FetchLike,
  type KeyDirectoryOptions,
  type KeyDirectorySnapshot,
  type KeyLookupResult,
  type VerificationKeySourceKind,
} from "./keys";

export {
  canonicaliseProofPayload,
  canonicaliseProofSigningInput,
  canonicalSortKeys,
  base64UrlDecode,
  base64UrlEncode,
  sha256Prefixed,
} from "./canonicalJson";

export {
  sha256Hex,
  sha256HexPrefixed,
  meterIdemKey,
  settlementIdemKey,
  constantTimeEqual,
  constantTimeHexEqual,
} from "./hashing";

export { AuditorError, asAuditorError } from "./errors";
export type { AuditorErrorCode } from "./errors";

export {
  SDK_VERSION,
  SUPPORTED_ENVELOPE_VERSIONS,
  SUPPORTED_SIGNATURE_ALGORITHMS,
  type AuditBundle,
  type AuditReasonCode,
  type AuditReport,
  type AuditStep,
  type AuditStepKind,
  type AuditStepStatus,
  type ChainAuditReport,
  type EnvelopeVersion,
  type FullAuditReport,
  type MeterRecord,
  type MeterUnitType,
  type MeteringSummary,
  type ProjectionAuditReport,
  type ProofPack,
  type ProofReceiptPayload,
  type ProofRecord,
  type RuntimeKeysResponse,
  type SettlementAuditReport,
  type SettlementLine,
  type SettlementPartyRole,
  type SettlementSummary,
  type SignatureAlgorithm,
  type SignedProofPack,
  type VerificationKey,
} from "./types";
