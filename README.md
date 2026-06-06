# @enfinitos/sdk-auditor

EnfinitOS **Auditor / Verifier SDK** — the cryptographic verification
library that regulators, auditors, courts, and third-party compliance
tools use to verify signed proof packs issued by EnfinitOS, **without
having to trust EnfinitOS as a vendor**.

This is the reference implementation. Companion ports with identical
wire shapes, reason codes, and verdicts:
[Python](https://github.com/EnfinitOS/sdk-auditor-py) ·
[Rust](https://github.com/EnfinitOS/sdk-auditor-rs).

## What's new in 0.0.2

**Rights-provenance write-time signature verification.** The platform
now Ed25519-signs every rights-provenance ledger row at write time
(basis, right, offer, and challenge lifecycle events); 0.0.2 ships
the independent verifier:

```typescript
import { verifyProvenanceChain } from "@enfinitos/sdk-auditor";

const report = await verifyProvenanceChain(
  exportArchive.records,      // ProvenanceRecord[] from /proof/export
  pinnedKeys,                 // VerificationKey[] or a KeyDirectory
  { expectedOrgId: "org_abc" },
);
report.status;                // "VALID" | "INVALID" | "SKIPPED"
report.signedRecordCount;     // write-time-signed records
report.unsignedRecordCount;   // legacy (pre-write-time) records
```

Legacy records (pre-write-time signing, `signatureAlgorithm:
"hmac-sha256"`) surface as informational SKIPPED findings — never
INVALID — so 0.0.1-era exports keep verifying. Also in 0.0.2:
`SettlementPartyRole` widened to the platform's full 8-role union
(`AGENCY`, `AFFILIATE`, `RESELLER`, `TAX_AUTHORITY` added). See
[CHANGELOG.md](https://github.com/EnfinitOS/sdk-auditor-ts/blob/main/CHANGELOG.md)
for the full release notes, including the Rust-specific upgrade note.

## The trust model

EnfinitOS issues signed evidence as part of every spatial-chain run:
a proof receipt for every render, a metering summary projecting
those proofs into billable units, and a settlement summary
reconciling those units into invoiced amounts.

The trust model is **"don't trust us — verify"**:

1. **We sign every record with our private key.** The corresponding
   public key is published at `/v1/runtime-keys`, a deliberately
   public, unauthenticated endpoint. The same endpoint is also
   archived in a regulator-pinnable JSON snapshot, so an auditor can
   verify a months-old proof pack using exactly the key set we
   published at the time it was issued.

2. **Every proof receipt is chained.** Each record carries a
   `beforeHash` (the previous record's `afterHash`) and an
   `afterHash` (sha256 of its own canonical payload). The chain
   makes a single record's tampering detectable by any party walking
   the chain in order.

3. **Metering is a pure projection of proof.** No platform-side
   alchemy: every meter record is `dwellMs / 1000` (or one of a few
   other deterministic policies). The auditor SDK ships the same
   projection formulae and re-derives them, asserting equality with
   the platform's published numbers.

4. **Settlement is a pure projection of metering.** Same logic — a
   share table, a gross price per unit, banker's rounding. The
   auditor SDK ships the same formulae and reconciles.

5. **The auditor has the full canonical-JSON encoder.** Whatever we
   signed, the auditor recomputes from the wire payload, byte-exact.
   A 1-bit divergence between our encoder and theirs would make
   every verification fail — that's a feature: it surfaces immediately.

What this means in practice: an auditor running this SDK on a
proof pack we issued does **not** need access to our infrastructure
(beyond the public key directory), does **not** need credentials,
and does **not** need to take our word for anything. They get back
a structured `AuditReport` that says VALID, INVALID, or SKIPPED per
step, with stable reason codes.

## Installation

```bash
pnpm add @enfinitos/sdk-auditor
```

or, in a regulator's air-gapped environment:

```bash
npm install @enfinitos/sdk-auditor --offline --no-fund
```

The SDK has one runtime dependency: [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519)
— a small, well-audited, zero-native-dep Ed25519 implementation. The
SDK falls back to Node's built-in `crypto.verify` when the noble
package isn't resolvable.

## Architecture

```
                  ┌─────────────────────────────────────────┐
                  │           SignedProofPack JSON          │
                  │     (envelope.v1, signed by EnfinitOS)  │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │   parseSignedProofPack (proofPack.ts)   │
                  └────────────────────┬────────────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  │                                         │
                  ▼                                         ▼
   ┌────────────────────────────┐         ┌─────────────────────────┐
   │   verifyProofRecord ×N     │         │   verifyProofChain      │
   │   (proofPack.ts)           │         │   (proofChain.ts)       │
   │                            │         │                         │
   │   • canonicalise payload   │         │   • beforeHash links    │
   │   • check afterHash        │         │   • genesis null check  │
   │   • lookup keyId in dir    │         │   • issuedAt ordering   │
   │   • Ed25519 verify         │         └─────────────────────────┘
   └────────────────────────────┘
                  │
                  ▼
   ┌────────────────────────────┐
   │  verifyMeteringProjection  │
   │     (meteringAudit.ts)     │
   │                            │
   │   • idemKey reconstruct    │
   │   • unitCount re-project   │
   │   • totals reconcile       │
   └─────────────┬──────────────┘
                 │
                 ▼
   ┌────────────────────────────┐
   │  verifySettlementReconcil. │
   │   (settlementAudit.ts)     │
   │                            │
   │   • idemKey reconstruct    │
   │   • share-sum == 1         │
   │   • amountCents recompute  │
   │   • totals reconcile       │
   └─────────────┬──────────────┘
                 │
                 ▼
   ┌────────────────────────────┐
   │       FullAuditReport      │
   │                            │
   │   status: VALID / INVALID  │
   │   + steps[] per primitive  │
   │   + reason codes (stable)  │
   └────────────────────────────┘
```

## Five-minute getting started

```typescript
import { readFileSync } from "node:fs";
import { EnfinitOSAuditor } from "@enfinitos/sdk-auditor";

const pack = JSON.parse(readFileSync("./pack.json", "utf8"));

const auditor = new EnfinitOSAuditor({
  // "platform" fetches from https://api.enfinitos.com/v1/runtime-keys.
  // "local" reads from opts.localKeys (offline audit).
  verificationKeySource: "platform",
});

const report = await auditor.verifyAll({ pack });
console.log(report.status); // "VALID" | "INVALID" | "SKIPPED"

if (report.status !== "VALID") {
  for (const sub of [report.pack, report.chain, report.metering, report.settlement]) {
    for (const step of sub.steps) {
      if (step.status === "INVALID") {
        console.error(`[${step.reason}] ${step.target}: ${step.message}`);
      }
    }
  }
}
```

## Modules

### `EnfinitOSAuditor` (auditor.ts)

The class. Holds the verification key cache; reusable across many
packs.

```typescript
class EnfinitOSAuditor {
  constructor(opts: {
    verificationKeySource?: "platform" | "local";  // default "platform"
    platformKeysUrl?: string;                      // default https://api.enfinitos.com/v1/runtime-keys
    localKeys?: VerificationKey[];                 // required if source=local
    httpFetch?: typeof globalThis.fetch;           // inject custom fetch
    signatureVerifier?: SignatureVerifier;         // inject custom ed25519 backend
  });

  verifyProofPack(pack: SignedProofPack | unknown): Promise<AuditReport>;
  verifyProofChain(records: ProofRecord[]): Promise<ChainAuditReport>;
  verifyMeteringProjection(proof: ProofPack, metering: MeteringSummary): Promise<ProjectionAuditReport>;
  verifySettlementReconciliation(metering: MeteringSummary, settlement: SettlementSummary): Promise<SettlementAuditReport>;
  verifyAll(bundle: AuditBundle): Promise<FullAuditReport>;
}
```

### `parseSignedProofPack` (proofPack.ts)

Pure parsing + structural validation. Use when you've already
verified signatures and now just want the typed shape.

### `verifyProofChain` (proofChain.ts)

Walks `records[]` in order, asserts genesis-null, link continuity,
and issuedAt ordering.

### `verifyMeteringProjection` (meteringAudit.ts)

Re-projects proof receipts into meter records using the same
deterministic formula the platform uses. Reports
`METER_UNIT_COUNT_MISMATCH` on any divergence.

### `verifySettlementReconciliation` (settlementAudit.ts)

Re-derives settlement lines from metering using the share table.
Reports `SETTLEMENT_AMOUNT_MISMATCH` / `SETTLEMENT_SHARE_SUM_NOT_ONE` /
`SETTLEMENT_TOTAL_MISMATCH` on any divergence.

### `verifyProvenanceChain` + `verifyProvenanceRecord` (provenance.ts)

Independently verifies the **write-time Ed25519 signatures on
rights-provenance records** — the lifecycle ledger behind every
basis, right, offer, and challenge (assert/verify/reject, issue/
suspend/resume/revoke/expire, propose/accept/counter/reject/
withdraw/expire, open/resolve/withdraw).

Unlike proof receipts (canonical-JSON payloads), each provenance
record is signed over a flat pipe-delimited canonical string that
every verifier language reconstructs without a canonical-JSON
library:

```
rightProvenance.v1|<orgId>|<eventType>|<rightId|->|<basisId|->|<offerId|->|<beforeHash|->|<afterHash|->|<keyId>
```

(`-` encodes an absent field). Per record the SDK: re-derives that
string from the record's raw fields and asserts byte-equality with
the shipped `payloadCanonical`; resolves `signerKeyId` in the key
directory (same validity-window + revocation semantics as
receipts); then Ed25519-verifies the signature.

```typescript
import { verifyProvenanceChain } from "@enfinitos/sdk-auditor";

const report = await verifyProvenanceChain(
  exportArchive.records,   // ProvenanceRecord[] from /proof/export
  pinnedKeys,              // VerificationKey[] or a KeyDirectory
  { expectedOrgId: "org_abc" },
);
report.status;             // "VALID" | "INVALID" | "SKIPPED"
report.signedRecordCount;  // write-time-signed records
report.unsignedRecordCount; // legacy (pre-write-time) records
```

**Backwards compatibility — legacy records.** Records written before
the platform shipped write-time provenance signing carry
`signatureAlgorithm: "hmac-sha256"` (a read-time transport HMAC the
SDK cannot independently verify). The verifier reports each as an
**informational SKIPPED step** with reason
`PROVENANCE_UNSIGNED_RECORD` — never INVALID — so exports produced
under SDK 0.0.1 keep verifying. A set that mixes signed and legacy
records is VALID if every signed record verifies; an all-legacy set
is SKIPPED (nothing verifiable, nothing failed).

**Pair with `verifyTenantChain`.** `verifyProvenanceChain` proves
WHO wrote each record (non-repudiation); `verifyTenantChain` proves
each record's POSITION in the tenant's append-only history
(insertion/rewrite detection). Run both for the full provenance
posture.

### `loadKeyDirectory` (keys.ts)

Fetches verification keys from `/v1/runtime-keys` or accepts a local
set. Validates key shape; caches in-process.

### `canonicaliseProofPayload` + `canonicalSortKeys` (canonicalJson.ts)

The two canonical-JSON encoders. The first matches
`apps/api/src/services/spatialChain/canonicalise.ts` byte-for-byte;
the second matches `rights/service.ts`'s recursive sort-key encoder.

## Error model

Two failure classes:

1. **Audit failures** — pack contents fail verification. Returned
   inside `AuditReport.steps[]` with a stable `reason` code (see
   `AuditReasonCode` in types.ts). Never thrown.

2. **Operational errors** — the SDK can't run (network failure,
   malformed JSON, unsupported envelope version). Thrown as
   `AuditorError` with a stable `code` (`INVALID_INPUT`,
   `KEYS_UNAVAILABLE`, `KEYS_MALFORMED`, `PLATFORM_RESPONSE`,
   `INTERNAL`).

The stable reason codes:

| Code | Where | What it means |
|---|---|---|
| `UNSUPPORTED_ENVELOPE_VERSION` | pack | We can't interpret this envelope version. |
| `MALFORMED_PACK` | pack | Shape is structurally broken. |
| `EMPTY_PACK` | pack | Zero records. |
| `PACK_ORG_MISMATCH` | pack | Records' orgs disagree with envelope orgId. |
| `UNSUPPORTED_ALGORITHM` | pack | Signature algorithm we don't speak. |
| `PAYLOAD_CANONICAL_MISMATCH` | record | Encoder version skew or tampering. |
| `AFTER_HASH_MISMATCH` | record | sha256(canonical) != record.afterHash. |
| `SIGNATURE_INVALID` | record | Ed25519 verify failed. |
| `SIGNATURE_MALFORMED` | record | Signature/key bytes not 64/32. |
| `UNKNOWN_KEY_ID` | keys | keyId not in directory. |
| `KEY_OUTSIDE_VALIDITY_WINDOW` | keys | issuedAt outside notBefore/notAfter. |
| `KEY_REVOKED_BEFORE_ISSUANCE` | keys | Record's issuedAt > key.revokedAt. |
| `GENESIS_BEFORE_HASH_NOT_NULL` | chain | First record has non-null beforeHash. |
| `CHAIN_LINK_MISMATCH` | chain | beforeHash != predecessor.afterHash. |
| `CHAIN_OUT_OF_ORDER` | chain | issuedAt sequence goes backward. |
| `METER_RECORD_FOR_UNKNOWN_PROOF` | meter | proofReceiptId not in pack. |
| `METER_UNIT_COUNT_MISMATCH` | meter | unitCount doesn't re-project. |
| `METER_IDEM_KEY_MISMATCH` | meter | idemKey != sha256(proofReceiptId\|unitType). |
| `METER_TOTAL_MISMATCH` | meter | totals don't sum from records. |
| `METER_ORG_MISMATCH` | meter | summary.orgId != pack.orgId. |
| `SETTLEMENT_LINE_FOR_UNKNOWN_METER` | settlement | meterRecordIdemKey not in metering. |
| `SETTLEMENT_SHARE_SUM_NOT_ONE` | settlement | Per-meter shares don't sum to 1. |
| `SETTLEMENT_AMOUNT_MISMATCH` | settlement | amountCents doesn't recompute. |
| `SETTLEMENT_IDEM_KEY_MISMATCH` | settlement | idemKey != sha256(meterIdemKey\|partyRole). |
| `SETTLEMENT_TOTAL_MISMATCH` | settlement | totals don't sum from lines. |
| `SETTLEMENT_ORG_MISMATCH` | settlement | settlement.orgId != metering.orgId. |
| `PROVENANCE_SIGNATURE_INVALID` | provenance | Ed25519 verify failed on a rights-provenance record. |
| `PROVENANCE_SIGNATURE_MALFORMED` | provenance | Signature/key bytes not valid base64url / 64/32 bytes. |
| `PROVENANCE_CANONICAL_MISMATCH` | provenance | Raw fields don't reconstruct payloadCanonical — post-write tampering. |
| `PROVENANCE_UNSIGNED_RECORD` | provenance | Informational (SKIPPED, never INVALID): pre-write-time-signing record. |
| `PROVENANCE_ORG_MISMATCH` | provenance | Record orgId != pinned expectedOrgId — tenant-spliced set. |

## Offline / pinned-key audit

A regulator auditing a proof pack issued months ago wants to use
**the same key set that was published at the time of issuance** —
not the current set (which may have been rotated).

The platform exposes a key directory snapshot per issuance day. A
regulator pins it at the start of audit:

```typescript
import { readFileSync } from "node:fs";
import { EnfinitOSAuditor, type VerificationKey } from "@enfinitos/sdk-auditor";

const localKeys: VerificationKey[] = JSON.parse(
  readFileSync("./pinned-keys-2026-q1.json", "utf8"),
);

const auditor = new EnfinitOSAuditor({
  verificationKeySource: "local",
  localKeys,
});

const report = await auditor.verifyAll({ pack: readPack() });
console.log(report.keysSnapshot);
// { source: "local", snapshotId: null, keyCount: 3, keyIds: [...] }
```

The audit run is **reproducible**: months later, anyone with the same
pack + the same pinned key set will get exactly the same
`FullAuditReport`. The SDK records the SDK version and key snapshot
ID into every report so the audit is byte-traceable.

## Verification

```bash
pnpm typecheck    # tsc --noEmit
pnpm test         # vitest run
```

Cross-references to the platform-side counterpart:
- canonicalise.ts: `apps/api/src/services/spatialChain/canonicalise.ts`
- proof signing: `apps/api/src/services/spatialChain/proofService.ts`
- metering projection: `apps/api/src/services/spatialChain/meterService.ts`
- settlement projection: `apps/api/src/services/spatialChain/settlementService.ts`
- right/basis/offer hashes: `apps/api/src/modules/rights/service.ts`
- provenance write-time signing: `apps/api/src/modules/rights/provenanceSigner.ts`
  (canonical input) + `apps/api/src/modules/proof/decoder.ts` (wire shape)
