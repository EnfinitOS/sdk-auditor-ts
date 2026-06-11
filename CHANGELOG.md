# Changelog — @enfinitos/sdk-auditor

All notable changes to the TypeScript auditor SDK. The TS SDK is the
reference implementation; the Python (`enfinitos-sdk-auditor` on
PyPI) and Rust (`enfinitos-sdk-auditor` on crates.io) ports track it
release-for-release with identical wire shapes, reason codes, and
verdicts.

## 0.0.3 — 2026-06-10

### Changed (BREAKING — settlement.v2)

- **Settlement idemKey is now 3-field and content-hash based** (CRYPTO-01).
  `settlementIdemKey(meterRecordIdemKey, partyRole, ledgerAccountCode)` =
  `sha256(meterRecordIdemKey|partyRole|ledgerAccountCode)`, matching the
  production settlement engine (`apps/api/.../spatialChain/settlementService.ts`).
  Previously `sha256(meterRecordIdemKey|partyRole)`, which could not be
  reconstructed for a (meter, partyRole) pair split across multiple ledger
  accounts — and which production never actually emitted (it keyed on the
  internal DB id, which no external auditor can reconstruct). This is what makes
  production settlement independently recomputable.
- `SettlementSummary.schemaVersion` now accepts `"settlement.v2"`.
- Amounts remain a floor-of-(gross×share) split with the remainder reabsorbed
  into the largest-share line; the production engine now produces this exactly
  (deterministic residual). Tightening the auditor's ±group-size tolerance to
  exact-cent equality is the planned follow-up (CRYPTO-04).

## 0.0.2 — 2026-06-05

### Added

- **Rights-provenance write-time signature verification** (Wave 14
  Phase 2). New `provenance.ts` module, exported from the package
  root:
  - `verifyProvenanceChain(records, keys, options?)` — verifies the
    per-record Ed25519 signatures the platform computes at write time
    on every rights-provenance row (basis assert/verify/reject, right
    issue/suspend/resume/revoke/expire, offer propose/accept/counter/
    reject/withdraw/expire, challenge open/resolve/withdraw). Returns
    a `ProvenanceAuditReport` with the signed/unsigned record
    partition surfaced.
  - `verifyProvenanceRecord(record, index, keys, verifier?)` — the
    per-record primitive.
  - `canonicaliseProvenanceSigningInput(fields, keyId)` +
    `PROVENANCE_SIGNING_VERSION` — byte-for-byte reconstruction of
    the platform's flat pipe-delimited signing input
    (`rightProvenance.v1|org|eventType|rightId|basisId|offerId|`
    `beforeHash|afterHash|keyId`, `-` for absent fields).
  - New types: `ProvenanceRecord`, `ProvenanceAuditReport`,
    `ProvenanceSigningFields`, `VerifyProvenanceChainOptions`.
  - Five new stable reason codes (additive):
    `PROVENANCE_SIGNATURE_INVALID`, `PROVENANCE_SIGNATURE_MALFORMED`,
    `PROVENANCE_CANONICAL_MISMATCH`, `PROVENANCE_UNSIGNED_RECORD`,
    `PROVENANCE_ORG_MISMATCH`; new step kind `provenance_signature`.
- **Legacy posture**: records written before write-time provenance
  signing (`signatureAlgorithm: "hmac-sha256"`) report as
  informational SKIPPED steps with reason
  `PROVENANCE_UNSIGNED_RECORD` — never INVALID. Exports produced
  under 0.0.1 keep verifying unchanged; an all-legacy set reports
  SKIPPED (nothing verifiable, nothing failed).

### Changed

- `SettlementPartyRole` widened from 4 to 8 roles — added `AGENCY`,
  `AFFILIATE`, `RESELLER`, `TAX_AUTHORITY` to match the platform's
  May-2026 enterprise settlement rebuild (counterparty-addressed
  splits). All settlement checks were already role-agnostic, so
  verification semantics are unchanged; the TS type union was
  non-enforcing at runtime, so 0.0.1 TS callers were not affected at
  parse time (unlike Rust — see the Rust CHANGELOG).
- `SDK_VERSION` constant (stamped onto every audit report) bumped to
  `"0.0.2"`.

### Notes

- No breaking changes. The provenance verifier is a new, parallel
  primitive; the receipt/chain/metering/settlement pipeline is
  untouched.
- Pair `verifyProvenanceChain` (WHO signed each record) with
  `verifyTenantChain` (each record's POSITION in the tenant's
  append-only history) for the full provenance posture.

## 0.0.1 — 2026-06-03

Initial public release on npm.

- `EnfinitOSAuditor` + `verifyAll` — full-bundle verification:
  envelope checks, per-record Ed25519 signature + canonicalisation +
  afterHash parity, proof-chain walk, metering re-projection,
  settlement reconciliation.
- `verifyTenantChain` — tenant append-only history verification.
- Offline / pinned-key audit via `verificationKeySource: "local"`.
- Stable, enumerable `AuditReasonCode` set for regulator citation.
