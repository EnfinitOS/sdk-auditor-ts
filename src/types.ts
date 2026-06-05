// @enfinitos/sdk-auditor — wire + domain types.
//
// Why this file exists
// ────────────────────
// The auditor SDK consumes JSON documents that EnfinitOS issues as
// part of a "trust package" — a self-contained, cryptographically
// signed bundle that a regulator, auditor, court, or third party can
// independently re-verify without re-trusting EnfinitOS.
//
// The types here mirror — verbatim, field-for-field — the shapes the
// platform actually emits, in particular:
//
//   apps/api/src/services/spatialChain/proofService.ts
//       → SignedProofPack.records[].payload (the canonical
//         ProofReceiptPayload shape, version "1")
//   apps/api/src/services/spatialChain/canonicalise.ts
//       → canonical JSON encoding rules (see canonicalJson.ts here)
//   apps/api/src/modules/rights/service.ts
//       → hashRight / hashBasis / hashOffer projections + the
//         beforeHash/afterHash chain shape (see proofChain.ts)
//   apps/api/src/services/spatialChain/meterService.ts
//       → MeterRecord projection rules (see meteringAudit.ts)
//   apps/api/src/services/spatialChain/settlementService.ts
//       → Settlement projection split rules (see settlementAudit.ts)
//
// We re-state the types here rather than importing from the API
// workspace for two reasons:
//
//   1. **Independence.** The whole point of the auditor SDK is that
//      it works as a standalone artefact. An auditor running it five
//      years from now must not need access to the EnfinitOS
//      monorepo — only this SDK and a JSON proof pack.
//
//   2. **Versioning.** Wire formats version forward; the auditor SDK
//      pins the shapes it understands ("envelope.v1") and rejects
//      anything else. The platform's internal types may evolve.
//
// All types here are zero-runtime (pure type declarations); the
// parsing + validation layer lives in proofPack.ts.

// ─────────────────────────────────────────────────────────────────────
// Protocol constants
// ─────────────────────────────────────────────────────────────────────

/**
 * Envelope versions the SDK can verify.
 *
 * Bumped on **any** semantic break in the SignedProofPack shape — a
 * new envelope version is the platform's signal to auditors that the
 * old SDK can no longer be trusted to interpret this pack.
 *
 *   "envelope.v1": initial release. ProofReceiptPayload "1",
 *                  beforeHash/afterHash provenance chain, single
 *                  Ed25519 signature per record, metering "v1",
 *                  settlement "v1".
 */
export const SUPPORTED_ENVELOPE_VERSIONS = ["envelope.v1"] as const;
export type EnvelopeVersion = (typeof SUPPORTED_ENVELOPE_VERSIONS)[number];

/**
 * Current SDK version. Recorded on every AuditReport so an auditor
 * can pin "I verified this pack with SDK X.Y.Z" — important if a
 * later SDK release fixes a verification bug.
 */
export const SDK_VERSION = "0.0.2" as const;

/**
 * Algorithm identifiers the SDK understands. We only ship Ed25519
 * today; SignedProofPack always carries `algorithm` so an upgrade to
 * P-256 or post-quantum hybrid in v2 doesn't silently break v1
 * verifiers.
 */
export const SUPPORTED_SIGNATURE_ALGORITHMS = ["ed25519"] as const;
export type SignatureAlgorithm =
  (typeof SUPPORTED_SIGNATURE_ALGORITHMS)[number];

// ─────────────────────────────────────────────────────────────────────
// Verification keys
// ─────────────────────────────────────────────────────────────────────

/**
 * VerificationKey — one of N public keys the platform may have used
 * to sign records in a proof pack. The auditor SDK fetches these
 * from `/v1/runtime-keys` (or accepts them locally for offline
 * audit) and matches a record's `keyId` to one entry here.
 *
 * `publicKey` is base64url-encoded 32 raw bytes (Ed25519 public key).
 * `notBefore` / `notAfter` bound the key's validity window; a
 * signature whose record's issuedAt lies outside the window is
 * rejected as `KEY_OUTSIDE_VALIDITY_WINDOW`.
 *
 * Key rotation: the platform may rotate its signing key at any time.
 * Old keys remain published with a `revokedAt` so historical proofs
 * remain verifiable; the SDK refuses to use a `revokedAt`-bearing
 * key for any record issued **after** that timestamp.
 */
export type VerificationKey = {
  /** Stable identifier — what `keyId` on a record matches against. */
  keyId: string;
  /** "ed25519" — present so v2 keys can coexist with v1. */
  algorithm: SignatureAlgorithm;
  /**
   * Base64url-encoded 32-byte Ed25519 public key (no padding).
   * Matches the encoding used by the platform's signer in
   * apps/api/src/services/spatialChain/managedKeyProofSigner.ts.
   */
  publicKey: string;
  /** ISO-8601 — key issued at or after this instant is valid. */
  notBefore: string;
  /**
   * ISO-8601 — key issued before this instant is valid. May be null
   * for keys without an a-priori expiry (rare; usually set).
   */
  notAfter: string | null;
  /**
   * ISO-8601 timestamp at which the platform revoked this key. If
   * non-null, the key is rejected for any record whose `issuedAt`
   * exceeds this value, even within `[notBefore, notAfter]`.
   */
  revokedAt: string | null;
  /**
   * Optional free-form purpose label — "proof_receipt_signing",
   * "metering_summary_signing", etc. The SDK does not gate on it
   * (the same key may sign multiple artefact types) but auditors
   * use it for human review.
   */
  purpose?: string;
};

/**
 * Optional signature over the verification-key-directory body, per
 * ADR-0011 (envelope.v2). When the platform publishes signed
 * directories, the auditor SDK verifies this signature against a
 * pinned root public key before trusting any of the contained
 * verification keys. Closes pen-test 2026-05-25 finding MC-1.
 *
 * When absent (e.g. against a v1 platform endpoint), the SDK falls
 * back to TLS-only trust on the key directory — acceptable for
 * pre-AWS-deployment but not for production.
 */
export type DirectorySignature = {
  /** Identifier of the root key that produced this signature. */
  rootKeyId: string;
  /** Always "Ed25519" for v2. */
  algorithm: SignatureAlgorithm;
  /**
   * Ed25519 signature, base64url-encoded (unpadded), over the
   * canonical serialisation of the `data` block plus the rootKeyId
   * separator. Verification reproduces the input as:
   *   canonical(data) + "|" + rootKeyId
   */
  signature: string;
  /** When the directory was signed (may pre-date issuance by minutes). */
  issuedAt: string;
};

/**
 * Response envelope from `/v1/runtime-keys` (the public verification
 * key directory endpoint).
 */
export type RuntimeKeysResponse = {
  ok: true;
  contractVersion: string;
  data: {
    /** Active + historical signing keys. Auditor must consume all. */
    keys: VerificationKey[];
    /** Platform-issued snapshot timestamp. */
    issuedAt: string;
    /**
     * Optional snapshot ID for "I fetched the keys at this point in
     * time and pinned them" workflows. Recorded into the
     * AuditReport so a re-run weeks later can prove it used the
     * same set.
     */
    snapshotId?: string;
  };
  /**
   * Per ADR-0011: signature over the `data` block by a pinned root
   * key. The auditor SDK validates this signature when constructed
   * with a `rootPublicKey`; otherwise the field is informational.
   * Optional during the v1→v2 migration; required once the platform
   * defaults to v2 emission.
   */
  directorySignature?: DirectorySignature;
};

// ─────────────────────────────────────────────────────────────────────
// Proof pack — the signed artefact under audit
// ─────────────────────────────────────────────────────────────────────

/**
 * ProofReceiptPayload — exactly the shape the platform emits in
 * apps/api/src/services/spatialChain/proofService.ts, version "1".
 *
 * The auditor SDK MUST not mutate this object before re-canonicalising
 * — even a key-reorder will produce a different signature input.
 */
export type ProofReceiptPayload = {
  version: "1";
  receiptId: string;
  correlationId: string | null;
  spatialAnchorId: string;
  spatialPlacementId: string | null;
  issuedAt: string;
  renderedAt: string;
  dwellMs: number;
  nonce: string;
  witness: string | null;
};

/**
 * ProofRecord — a single signed receipt, plus the provenance-chain
 * fields that link this record to its predecessor and successor.
 *
 * The chain shape mirrors the basis/right/offer provenance trail in
 * apps/api/src/modules/rights/service.ts — every record carries a
 * `beforeHash` (the predecessor's afterHash, or `null` for genesis)
 * and an `afterHash` (sha256 of this record's canonical payload).
 *
 * The platform reuses the same primitive across the proof, basis,
 * right, and offer chains so a single auditor walk can verify any
 * of them; this SDK targets the proof shape and reuses the same
 * walking algorithm for rights/basis/offers in proofChain.ts.
 */
export type ProofRecord = {
  payload: ProofReceiptPayload;
  /** Identifier of the signing key — matches a VerificationKey.keyId. */
  keyId: string;
  /** Algorithm — repeated per record so a v2 record can coexist. */
  algorithm: SignatureAlgorithm;
  /** Base64url-encoded raw 64-byte Ed25519 signature. */
  signature: string;
  /**
   * Canonical payload string the signature is over. The SDK still
   * re-canonicalises and compares — this field is a transparency aid
   * for auditors who want to inspect what was signed without running
   * any code.
   */
  payloadCanonical: string;
  /**
   * The predecessor record's `afterHash`. Null for the genesis
   * record. The chain is verified by walking the records in order
   * and asserting `records[i].beforeHash === records[i-1].afterHash`.
   */
  beforeHash: string | null;
  /**
   * Sha256 (hex) of `payloadCanonical`. The SDK recomputes this and
   * compares — a divergence means the canonical-encoder version
   * disagrees with the platform.
   */
  afterHash: string;
};

/**
 * SignedProofPack — the top-level envelope. Carries N ProofRecords
 * in the order they were issued, plus the metering + settlement
 * summaries the platform projected from them. The auditor SDK's
 * full-bundle verification re-projects the proof into metering and
 * re-derives settlement to confirm the platform's published
 * numbers reconcile from first principles.
 */
export type SignedProofPack = {
  envelopeVersion: EnvelopeVersion;
  /** ISO-8601 — when the platform sealed the pack. */
  issuedAt: string;
  /**
   * Org the pack belongs to. The auditor walks records and rejects
   * the pack if any record's downstream attribution mismatches this.
   */
  orgId: string;
  /**
   * Free-form pack identifier — usually a UUID. Carried into the
   * AuditReport so multi-pack audits can group results.
   */
  packId: string;
  /**
   * Optional human label — e.g. "Q4-2025-spatial-chain-audit-pack".
   */
  label?: string;
  /** The proof records, in issuance order. */
  records: ProofRecord[];
  /** Optional metering summary if available. */
  metering?: MeteringSummary;
  /** Optional settlement summary if available. */
  settlement?: SettlementSummary;
};

/**
 * ProofPack — same shape as SignedProofPack but without signatures.
 * The auditor uses this to call verifyMeteringProjection alone (the
 * caller has already verified signatures) or to feed re-projection
 * helpers in test rigs.
 */
export type ProofPack = {
  envelopeVersion: EnvelopeVersion;
  issuedAt: string;
  orgId: string;
  packId: string;
  records: Array<Pick<ProofRecord, "payload">>;
};

// ─────────────────────────────────────────────────────────────────────
// Rights-provenance records — Wave 14 write-time signing contract
// ─────────────────────────────────────────────────────────────────────

/**
 * ProvenanceRecord — one rights-provenance ledger entry as the
 * platform's proof read surface emits it
 * (apps/api/src/modules/proof/decoder.ts → ProofRecord, proof.v1).
 *
 * This is a DIFFERENT artefact from the spatial-chain ProofRecord
 * above: that one wraps a ProofReceiptPayload signed over a
 * canonical-JSON encoding; this one is a rights lifecycle event
 * (basis assert/verify/reject, right issue/suspend/resume/revoke/
 * expire, offer propose/accept/counter/reject/withdraw/expire,
 * challenge open/resolve/withdraw) signed over a flat pipe-delimited
 * canonical string:
 *
 *   "rightProvenance.v1|<orgId>|<eventType>|<rightId|->|<basisId|->|
 *    <offerId|->|<beforeHash|->|<afterHash|->|<keyId>"
 *
 * where "-" encodes an absent field. The hand-rolled form is what
 * lets TS / Rust / Python verifiers reconstruct the signed bytes
 * without sharing a canonical-JSON library.
 *
 * Signature presence is per-record:
 *   - `signatureAlgorithm: "ed25519"` → the record was signed at
 *     write time. `signature` is the base64url (unpadded) 64-byte
 *     Ed25519 signature; `signerKeyId` matches a VerificationKey.
 *     `payloadCanonical` carries the exact signed string as a
 *     transparency aid — the SDK re-derives it from the raw fields
 *     and asserts byte-equality before verifying.
 *   - `signatureAlgorithm: "hmac-sha256"` → legacy (pre-Wave-14)
 *     record. The signature is a platform-side read-time transport
 *     HMAC the SDK cannot independently verify; the verifier reports
 *     PROVENANCE_UNSIGNED_RECORD as an informational SKIPPED step,
 *     never INVALID — published 0.0.1-era exports must keep
 *     verifying.
 */
export type ProvenanceRecord = {
  /** Stable record id (the RightProvenance row id). */
  proofId: string;
  /** Tenant the record belongs to. Part of the signing input. */
  orgId: string;
  /**
   * The platform's raw lifecycle event tag (e.g. RIGHT_ISSUED,
   * OFFER_ACCEPTED, RIGHT_CHALLENGE_RESOLVED). Part of the signing
   * input. NOTE: this is NOT the proof surface's collapsed 10-value
   * `type` taxonomy — the wire field is `provenanceEventType`.
   */
  provenanceEventType: string;
  /** ISO-8601 — when the event was recorded. Drives key-validity checks. */
  occurredAt: string;
  /** Entity pointers — each part of the signing input; null when absent. */
  rightId: string | null;
  basisId: string | null;
  offerId: string | null;
  /**
   * Raw entity-chain hashes exactly as persisted (typically
   * `sha256:<hex>`-prefixed; null on auxiliary birth rows such as
   * OFFER_PROPOSED). Part of the signing input. Wire fields are
   * `provenanceBeforeHash` / `provenanceAfterHash`.
   */
  provenanceBeforeHash: string | null;
  provenanceAfterHash: string | null;
  /** "ed25519" (write-time signed) or "hmac-sha256" (legacy). */
  signatureAlgorithm: "ed25519" | "hmac-sha256";
  /**
   * For ed25519 records: base64url (unpadded) 64-byte Ed25519
   * signature over the canonical signing input. For hmac-sha256
   * records: the platform's transport HMAC (hex) — opaque to the SDK.
   */
  signature: string;
  /**
   * For ed25519 records: the signing key id, resolvable in the
   * published verification-key directory. For hmac-sha256 records:
   * the synthetic `ledger.v1.<orgId>` tag.
   */
  signerKeyId: string;
  /**
   * For ed25519 records: the exact canonical string that was signed.
   * Null on legacy records.
   */
  payloadCanonical: string | null;
};

/**
 * ProvenanceAuditReport — verifyProvenanceChain output. Same shape
 * family as ChainAuditReport, with the signed/unsigned partition
 * surfaced so a regulator can quote "N of M records carry write-time
 * signatures" directly.
 */
export type ProvenanceAuditReport = {
  status: AuditStepStatus;
  verifiedAt: string;
  sdkVersion: string;
  recordCount: number;
  /** Records carrying a write-time Ed25519 signature. */
  signedRecordCount: number;
  /** Legacy records (read-time HMAC only) — informational, not failures. */
  unsignedRecordCount: number;
  steps: AuditStep[];
};

// ─────────────────────────────────────────────────────────────────────
// Metering
// ─────────────────────────────────────────────────────────────────────

/**
 * MeterRecord — one billable unit projection of one ProofReceipt.
 *
 * Mirrors apps/api/src/services/spatialChain/meterService.ts. The
 * auditor recomputes `unitCount` from `proofReceiptId`'s dwellMs
 * (looked up in the pack's records) using the same policy formula
 * and asserts equality. Mismatches are reported as
 * `METER_UNIT_COUNT_MISMATCH` reason codes.
 */
export type MeterUnitType =
  | "DWELL_SECONDS"
  | "IMPRESSION_IN_PLACE"
  | "ATTENTION_SECONDS"
  | "OCCUPANCY_WEIGHTED_EXPOSURE"
  | "COMPLIANT_DELIVERY_MINUTE"
  | "CUSTOM";

export type MeterRecord = {
  /** Stable per-orgId, equal to `sha256(proofReceiptId|unitType)`. */
  idemKey: string;
  proofReceiptId: string;
  unitType: MeterUnitType;
  /**
   * Decimal as string so the auditor sees byte-exact precision
   * (round-tripping through Number loses precision beyond 2^53).
   */
  unitCount: string;
  /** Multiplier applied during projection. Default "1". */
  weight: string;
  spatialAnchorId: string;
  spatialPlacementId: string | null;
  observedAt: string;
  status: "PROJECTED" | "ACCEPTED" | "SETTLED" | "VOID";
};

export type MeteringSummary = {
  /** "metering.v1" — bumped on shape break. */
  schemaVersion: "metering.v1";
  orgId: string;
  /** ISO-8601 inclusive. */
  periodStart: string;
  /** ISO-8601 exclusive. */
  periodEnd: string;
  records: MeterRecord[];
  /**
   * Optional convenience aggregate — the auditor recomputes from
   * `records` and asserts equality. Carries (unitType → sum-as-string)
   * to preserve decimal precision.
   *
   * `Partial` because a pack may emit metering for only a subset of
   * unit types (e.g. a DOOH render-only pack has DWELL_SECONDS but
   * no MESSAGE_DELIVERED). The auditor's projection asserts equality
   * only over keys present in the recomputed totals — missing keys
   * mean "no records of that unit type", which is distinguishable
   * from "zero recorded value" but both are accepted as VALID.
   */
  totals?: Partial<Record<MeterUnitType, string>>;
};

// ─────────────────────────────────────────────────────────────────────
// Settlement
// ─────────────────────────────────────────────────────────────────────

/**
 * SettlementLine — one row of the post-meter settlement projection.
 *
 * Mirrors apps/api/src/services/spatialChain/settlementService.ts.
 * Splits a meter record's gross amount across party roles using a
 * `share` (0..1) and a `ledgerAccountCode`. The auditor recomputes
 * `amountCents` from `meterRecordIdemKey`'s `unitCount` and the
 * pricing policy, then asserts equality.
 */
export type SettlementPartyRole =
  | "TENANT"
  | "VENUE"
  | "CUSTOMER"
  | "PLATFORM"
  // The enterprise settlement rebuild (May 2026) widened the
  // platform's role union — counterparty-addressed splits can pay
  // agencies, affiliates, resellers, and tax authorities. The
  // auditor's settlement checks are role-agnostic (idemKey
  // reconstruction + per-meter share sums + amount recomputation),
  // so verification semantics are unchanged; this keeps the wire
  // contract in field-for-field parity with sandbox-core
  // (enforced by sandbox-core's conformance test).
  | "AGENCY"
  | "AFFILIATE"
  | "RESELLER"
  | "TAX_AUTHORITY";

export type SettlementLine = {
  /** sha256(meterRecordIdemKey|partyRole). */
  idemKey: string;
  meterRecordIdemKey: string;
  partyRole: SettlementPartyRole;
  /** 0..1 fraction; lines for a given meter must sum to 1. */
  share: string;
  ledgerAccountCode: string;
  /** Minor currency units (cents/pence). */
  amountCents: number;
  currency: string;
  status: "PROJECTED" | "ACCEPTED" | "POSTED" | "VOID";
};

export type SettlementSummary = {
  schemaVersion: "settlement.v1";
  orgId: string;
  periodStart: string;
  periodEnd: string;
  currency: string;
  /** Gross amount in cents per meterRecordIdemKey — pricing input. */
  meterGross: Record<string, number>;
  lines: SettlementLine[];
  totals?: {
    grossCents: number;
    netToTenantCents: number;
    platformFeeCents: number;
  };
};

// ─────────────────────────────────────────────────────────────────────
// Audit bundle
// ─────────────────────────────────────────────────────────────────────

/**
 * AuditBundle — the input to `verifyAll`. The pack is the signed
 * artefact; the optional metering + settlement summaries are platform
 * outputs the auditor reconciles against the pack's records.
 *
 * In practice an auditor receives the bundle as a single ZIP from
 * the platform's regulator-export endpoint, unpacks it, and feeds it
 * into `verifyAll` in a single call.
 */
export type AuditBundle = {
  pack: SignedProofPack;
  metering?: MeteringSummary;
  settlement?: SettlementSummary;
  /**
   * Optional explicit set of verification keys to use. If absent,
   * the auditor fetches from `verificationKeySource` (default
   * "platform"). Audit reports always record which keys were used.
   */
  verificationKeys?: VerificationKey[];
  /**
   * Optional anchor for cross-pack chain continuity. When a tenant
   * issues multiple packs serially (the normal case — every
   * pre-sealed batch becomes one pack), each pack's first record
   * carries the previous pack's last `afterHash` as its
   * `beforeHash`. The auditor's "genesis" invariant (records[0]
   * .beforeHash === null) holds for the FIRST pack only; for every
   * subsequent pack the caller passes the prior pack's tail
   * `afterHash` here so the chain-walk verifies cross-pack
   * continuity instead of falsely tripping
   * GENESIS_BEFORE_HASH_NOT_NULL.
   *
   * Omit this field when verifying a standalone pack (the auditor
   * defaults to the genesis check, matching pre-2026.05 behaviour).
   */
  priorAfterHash?: string | null;
};

// ─────────────────────────────────────────────────────────────────────
// Audit reports
// ─────────────────────────────────────────────────────────────────────

/**
 * AuditStepStatus — verdict of one verification step.
 *
 *   - VALID:    step passed. Numbers reconcile, signatures verify.
 *   - INVALID:  step failed. The pack must NOT be trusted; the
 *               `reason` field carries the structured error code.
 *   - SKIPPED:  step did not run (e.g. settlement was not included
 *               in the bundle so settlementAudit was skipped). The
 *               rolled-up report status is conservative: SKIPPED
 *               steps do not promote to VALID.
 */
export type AuditStepStatus = "VALID" | "INVALID" | "SKIPPED";

/**
 * Reason codes are deliberately enumerable + stable across SDK
 * releases — regulators and auditors cite them in formal reports.
 * **Adding** codes is forward-compatible; **renaming** them is a
 * breaking change requiring an envelope-version bump.
 */
export type AuditReasonCode =
  // Envelope / pack-level
  | "UNSUPPORTED_ENVELOPE_VERSION"
  | "MALFORMED_PACK"
  | "EMPTY_PACK"
  | "PACK_ORG_MISMATCH"
  | "UNSUPPORTED_ALGORITHM"
  // Signature
  | "SIGNATURE_INVALID"
  | "SIGNATURE_MALFORMED"
  | "UNKNOWN_KEY_ID"
  | "KEY_OUTSIDE_VALIDITY_WINDOW"
  | "KEY_REVOKED_BEFORE_ISSUANCE"
  // Canonicalisation
  | "PAYLOAD_CANONICAL_MISMATCH"
  | "AFTER_HASH_MISMATCH"
  // Chain
  | "GENESIS_BEFORE_HASH_NOT_NULL"
  | "CHAIN_LINK_MISMATCH"
  | "CHAIN_OUT_OF_ORDER"
  // Metering re-projection
  | "METER_RECORD_FOR_UNKNOWN_PROOF"
  | "METER_UNIT_COUNT_MISMATCH"
  | "METER_IDEM_KEY_MISMATCH"
  | "METER_TOTAL_MISMATCH"
  | "METER_ORG_MISMATCH"
  // Settlement reconciliation
  | "SETTLEMENT_LINE_FOR_UNKNOWN_METER"
  | "SETTLEMENT_SHARE_SUM_NOT_ONE"
  | "SETTLEMENT_AMOUNT_MISMATCH"
  | "SETTLEMENT_IDEM_KEY_MISMATCH"
  | "SETTLEMENT_TOTAL_MISMATCH"
  | "SETTLEMENT_ORG_MISMATCH"
  // Rights-provenance write-time signing (Wave 14 Phase 2). Additive —
  // packs/exports produced before the platform shipped write-time
  // provenance signing never trip these.
  | "PROVENANCE_SIGNATURE_INVALID"
  | "PROVENANCE_SIGNATURE_MALFORMED"
  | "PROVENANCE_CANONICAL_MISMATCH"
  | "PROVENANCE_UNSIGNED_RECORD"
  | "PROVENANCE_ORG_MISMATCH"
  // Keys
  | "KEYS_FETCH_FAILED"
  | "KEYS_RESPONSE_MALFORMED";

/**
 * AuditStep — one row in a multi-step report. Each step is a single
 * verification primitive (verify one signature, verify one chain
 * link, verify one meter projection, etc.).
 */
export type AuditStep = {
  /** Identifier of what was being verified — e.g. "record[2].signature". */
  target: string;
  /** What kind of step this is — see AuditStepKind. */
  kind: AuditStepKind;
  status: AuditStepStatus;
  /**
   * Set on INVALID; absent on VALID. SKIPPED steps normally carry no
   * reason, with one citable exception: informational provenance
   * findings (PROVENANCE_UNSIGNED_RECORD) set the reason on a SKIPPED
   * step so a regulator can quote the code without the step counting
   * as a failure.
   */
  reason?: AuditReasonCode;
  /** Human-readable note. Always safe to surface in regulator UIs. */
  message: string;
  /** Optional structured detail for advanced audit tools. */
  detail?: Record<string, unknown>;
};

export type AuditStepKind =
  | "envelope"
  | "signature"
  | "canonicalisation"
  | "chain_link"
  | "meter_projection"
  | "meter_total"
  | "settlement_line"
  | "settlement_total"
  | "key_lookup"
  // Wave 14 Phase 2 — rights-provenance write-time signature checks.
  | "provenance_signature";

/**
 * AuditReport — the result of `verifyProofPack`. Reports the
 * envelope-level checks plus per-record signature + canonicalisation
 * + chain-link results. Settlement / metering reports are separate.
 */
export type AuditReport = {
  status: AuditStepStatus;
  packId: string;
  orgId: string;
  /** ISO-8601 — when the audit ran. */
  verifiedAt: string;
  /** SDK version that produced this report. */
  sdkVersion: string;
  /** EnvelopeVersion the pack declared. */
  envelopeVersion: EnvelopeVersion | "unknown";
  /** Keys snapshot the auditor used. */
  keysSnapshot: {
    source: "platform" | "local";
    snapshotId: string | null;
    keyCount: number;
    keyIds: string[];
  };
  steps: AuditStep[];
};

/**
 * ChainAuditReport — verifyProofChain output. Walks records in
 * issuance order and reports per-link status.
 */
export type ChainAuditReport = {
  status: AuditStepStatus;
  verifiedAt: string;
  sdkVersion: string;
  recordCount: number;
  steps: AuditStep[];
};

/**
 * ProjectionAuditReport — verifyMeteringProjection output.
 */
export type ProjectionAuditReport = {
  status: AuditStepStatus;
  verifiedAt: string;
  sdkVersion: string;
  proofRecordCount: number;
  meterRecordCount: number;
  steps: AuditStep[];
};

/**
 * SettlementAuditReport — verifySettlementReconciliation output.
 */
export type SettlementAuditReport = {
  status: AuditStepStatus;
  verifiedAt: string;
  sdkVersion: string;
  meterRecordCount: number;
  settlementLineCount: number;
  steps: AuditStep[];
};

/**
 * FullAuditReport — verifyAll output. Combines the four sub-reports
 * plus a rolled-up status. **Status promotion rule:** the rolled-up
 * status is VALID only if **every** sub-report is VALID; any
 * INVALID demotes the whole report to INVALID; otherwise the report
 * is SKIPPED.
 */
export type FullAuditReport = {
  status: AuditStepStatus;
  packId: string;
  orgId: string;
  verifiedAt: string;
  sdkVersion: string;
  keysSnapshot: AuditReport["keysSnapshot"];
  pack: AuditReport;
  chain: ChainAuditReport;
  metering: ProjectionAuditReport;
  settlement: SettlementAuditReport;
};
