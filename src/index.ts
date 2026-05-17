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
