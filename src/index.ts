// @enfinitos/sdk-auditor — public surface.

export { EnfinitOSAuditor } from "./auditor.js";
export type { EnfinitOSAuditorOptions } from "./auditor.js";

export {
  parseSignedProofPack,
  verifyProofRecord,
  defaultSignatureVerifier,
  NobleEd25519Verifier,
  NodeCryptoEd25519Verifier,
  type SignatureVerifier,
} from "./proofPack.js";

export { verifyProofChain } from "./proofChain.js";

export { verifyMeteringProjection } from "./meteringAudit.js";

export { verifySettlementReconciliation } from "./settlementAudit.js";

export {
  loadKeyDirectory,
  KeyDirectory,
  type FetchLike,
  type KeyDirectoryOptions,
  type KeyDirectorySnapshot,
  type KeyLookupResult,
  type VerificationKeySourceKind,
} from "./keys.js";

export {
  canonicaliseProofPayload,
  canonicaliseProofSigningInput,
  canonicalSortKeys,
  base64UrlDecode,
  base64UrlEncode,
  sha256Prefixed,
} from "./canonicalJson.js";

export {
  sha256Hex,
  sha256HexPrefixed,
  meterIdemKey,
  settlementIdemKey,
  constantTimeEqual,
  constantTimeHexEqual,
} from "./hashing.js";

export { AuditorError, asAuditorError } from "./errors.js";
export type { AuditorErrorCode } from "./errors.js";

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
} from "./types.js";
