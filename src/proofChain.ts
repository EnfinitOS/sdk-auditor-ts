// @enfinitos/sdk-auditor — proof-chain walking + continuity verification.
//
// The platform's proof receipts form a content-addressable chain:
// every record carries `beforeHash` (the predecessor's afterHash, or
// null for the first record) and `afterHash` (sha256 of its own
// canonical payload). The same primitive is used for the
// rights/basis/offer chain in apps/api/src/modules/rights/service.ts.
//
// Auditor's job
// ─────────────
// Walk the records in issuance order and verify three invariants:
//
//   1. **Genesis.**       records[0].beforeHash MUST be null.
//   2. **Continuity.**    For i ≥ 1, records[i].beforeHash MUST equal
//                         records[i-1].afterHash.
//   3. **Ordering.**      issuedAt MUST be non-decreasing along the
//                         chain (the platform issues serially per
//                         (orgId, anchor); concurrent issuance is
//                         resolved via DB serialisation before the
//                         record is emitted).
//
// We DON'T re-hash the payloads here — that's proofPack.ts. We
// assume the caller has already run that step. The chain walk
// trusts the `afterHash` values; if it can't, the pack is already
// invalid at the canonicalisation layer.
//
// Why "issuedAt non-decreasing" is a chain invariant
// ──────────────────────────────────────────────────
// A reordering attack would otherwise be possible: a hostile party
// could re-arrange records to put a SUSPENDED-then-resumed sequence
// in a misleading order. The platform's database guarantees serial
// issuance per chain head; the auditor SDK enforces that the bundle
// they receive preserves that order.

import type {
  AuditStep,
  ChainAuditReport,
  ProofRecord,
} from "./types.js";
import { SDK_VERSION } from "./types.js";

/**
 * verifyProofChain — walk records in array order, verify the three
 * invariants, and return a ChainAuditReport.
 *
 * The report's overall status is INVALID if any step is INVALID,
 * VALID otherwise. An empty input set is reported as INVALID with
 * a single EMPTY_PACK-style step — an audit of zero records is
 * meaningless.
 */
export function verifyProofChain(records: ProofRecord[]): ChainAuditReport {
  const verifiedAt = new Date().toISOString();
  const steps: AuditStep[] = [];

  if (records.length === 0) {
    return {
      status: "INVALID",
      verifiedAt,
      sdkVersion: SDK_VERSION,
      recordCount: 0,
      steps: [
        {
          target: "records",
          kind: "chain_link",
          status: "INVALID",
          reason: "MALFORMED_PACK",
          message: "proof chain is empty — cannot audit a zero-record pack",
        } as AuditStep,
      ],
    };
  }

  // 1. Genesis check.
  const first = records[0]!;
  if (first.beforeHash !== null) {
    steps.push({
      target: "records[0].beforeHash",
      kind: "chain_link",
      status: "INVALID",
      reason: "GENESIS_BEFORE_HASH_NOT_NULL",
      message:
        "first record carries a non-null beforeHash — the chain is rooted at a record the auditor has not been given. The pack is incomplete.",
      detail: { beforeHash: first.beforeHash },
    });
  } else {
    steps.push({
      target: "records[0].beforeHash",
      kind: "chain_link",
      status: "VALID",
      message: "genesis record has null beforeHash, as expected",
    });
  }

  // 2. Continuity + 3. ordering, walking forward.
  let prevIssuedAtMs: number | null = parseIsoOrNull(first.payload.issuedAt);
  for (let i = 1; i < records.length; i++) {
    const curr = records[i]!;
    const prev = records[i - 1]!;
    if (curr.beforeHash === null) {
      steps.push({
        target: `records[${i}].beforeHash`,
        kind: "chain_link",
        status: "INVALID",
        reason: "GENESIS_BEFORE_HASH_NOT_NULL",
        message: `non-genesis record at index ${i} carries a null beforeHash — chain broken`,
      });
      continue;
    }
    if (curr.beforeHash !== prev.afterHash) {
      steps.push({
        target: `records[${i}].beforeHash`,
        kind: "chain_link",
        status: "INVALID",
        reason: "CHAIN_LINK_MISMATCH",
        message: `record[${i}].beforeHash does not equal record[${i - 1}].afterHash — chain link broken`,
        detail: {
          expected: prev.afterHash,
          actual: curr.beforeHash,
        },
      });
    } else {
      steps.push({
        target: `records[${i}].beforeHash`,
        kind: "chain_link",
        status: "VALID",
        message: `record[${i}] correctly chains off record[${i - 1}]`,
      });
    }
    const currIssuedAtMs = parseIsoOrNull(curr.payload.issuedAt);
    if (
      currIssuedAtMs !== null &&
      prevIssuedAtMs !== null &&
      currIssuedAtMs < prevIssuedAtMs
    ) {
      steps.push({
        target: `records[${i}].payload.issuedAt`,
        kind: "chain_link",
        status: "INVALID",
        reason: "CHAIN_OUT_OF_ORDER",
        message: `record[${i}].issuedAt (${curr.payload.issuedAt}) is earlier than record[${i - 1}].issuedAt (${prev.payload.issuedAt}) — chain reordered`,
      });
    }
    prevIssuedAtMs = currIssuedAtMs;
  }

  const anyInvalid = steps.some((s) => s.status === "INVALID");
  return {
    status: anyInvalid ? "INVALID" : "VALID",
    verifiedAt,
    sdkVersion: SDK_VERSION,
    recordCount: records.length,
    steps,
  };
}

function parseIsoOrNull(iso: string): number | null {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}
