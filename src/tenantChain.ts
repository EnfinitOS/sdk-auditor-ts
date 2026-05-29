// @enfinitos/sdk-auditor — tenant-level chain verification.
//
// Wave 27 / pre-pilot punch #1 Phase 4. Independently verifies the
// tenant-level chain that links every rights-provenance row a tenant
// has ever written (Wave 25 / Phase 2). The link shape is:
//
//   tenantChainNext_n = sha256(
//     "tenantChain.v1|<prev>|<rowAfterHash>|<sequence>"
//   )
//
// where `<prev>` is the previous row's `tenantChainNext` (or
// `provenance.tenantChain.v1.<orgId>` for the genesis row), encoded
// as `-` if null. Same pipe-delimited hand-rolled form as the
// provenance signing input — reconstructable in TS / Rust / Python
// without a canonical-JSON library.
//
// What this catches that the entity chain does not
// ────────────────────────────────────────────────
// An attacker with current-key signing access could fabricate a
// rights-provenance row, sign it with the current Ed25519 key, and
// slot it into history. The entity chain (basis/right/offer chain
// via beforeHash/afterHash) still validates because the row is the
// only one in its position. The tenant chain catches this: the
// fabricated row's tenantChainPrev cannot match the existing tip
// without rewriting every subsequent row, which would invalidate
// their signatures and their tenant-chain links.
//
// This module is independent from proofChain.ts (the receipt chain
// walker). The receipt chain links proof receipts within a single
// SignedProofPack; the tenant chain links rights-provenance rows
// across the whole tenant's history.

import { createHash } from "node:crypto";
import type {
  AuditStep,
  ChainAuditReport,
  AuditReasonCode,
} from "./types";
import { SDK_VERSION } from "./types";

// ─────────────────────────────────────────────────────────────────────
// Public types — describe one tenant-chained record. Decoupled from
// the on-platform ProofRecord shape so this verifier doesn't pull
// the entire receipt-side type system into the tenant-chain audit.
// ─────────────────────────────────────────────────────────────────────

export interface TenantChainedRecord {
  /** The row's content-addressable afterHash (entity chain). */
  rowAfterHash: string;
  /** The tenant-chain predecessor link, or null for the genesis row. */
  tenantChainPrev: string | null;
  /** This row's tenant-chain link — what the next row will read as prev. */
  tenantChainNext: string;
  /**
   * Monotonic position within the tenant. Stringified so JSON can
   * carry the BigInt without precision loss.
   */
  tenantChainSequence: string;
}

/** Stable canonical chain-link version. */
export const TENANT_CHAIN_VERSION = "tenantChain.v1" as const;

/**
 * Compute the canonical chain-link bytes that the platform hashed at
 * write time. Pure; hand-rolled pipe-delimited form so cross-language
 * verifiers reconstruct without a canonical-JSON library.
 */
export function canonicaliseTenantChainLink(input: {
  prev: string | null;
  rowAfterHash: string;
  sequence: string;
}): string {
  const prev = input.prev == null || input.prev === "" ? "-" : input.prev;
  return [TENANT_CHAIN_VERSION, prev, input.rowAfterHash, input.sequence].join("|");
}

/**
 * Genesis seed value for a tenant. The first row's tenantChainPrev
 * is this string (length differs from any sha256 hex output, so the
 * seed cannot collide with a real link hash).
 */
export function genesisChainTip(orgId: string): string {
  return `provenance.${TENANT_CHAIN_VERSION}.${orgId}`;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

// ─────────────────────────────────────────────────────────────────────
// verifyTenantChain — walks the array, verifies link integrity.
// ─────────────────────────────────────────────────────────────────────

/**
 * Verify the tenant-level chain across an array of rows.
 *
 * Invariants checked, in order:
 *   1. **Sequence monotonicity.** records[i].tenantChainSequence
 *      MUST equal records[i-1].tenantChainSequence + 1. Gaps or
 *      duplicates indicate inserted/dropped rows.
 *   2. **Prev linkage.** For i ≥ 1, records[i].tenantChainPrev MUST
 *      equal records[i-1].tenantChainNext. For i = 0 (genesis),
 *      tenantChainPrev MUST equal the supplied `expectedGenesis` or
 *      `genesisChainTip(orgId)` (caller pre-computes which).
 *   3. **Next recomputation.** records[i].tenantChainNext MUST equal
 *      sha256(canonicaliseTenantChainLink(prev, rowAfterHash, sequence)).
 *      Catches a tampered link that still chains correctly to the
 *      neighbours but was forged.
 *
 * Returns a ChainAuditReport — same shape as `verifyProofChain` so
 * callers can render the two reports side-by-side in dashboards.
 */
export function verifyTenantChain(
  records: ReadonlyArray<TenantChainedRecord>,
  expectedGenesis: string,
): ChainAuditReport {
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
          reason: "MALFORMED_PACK" as AuditReasonCode,
          message:
            "tenant chain audit received an empty record set — nothing to verify",
        } as AuditStep,
      ],
    };
  }

  // 1. Genesis link.
  const first = records[0]!;
  if (first.tenantChainPrev !== expectedGenesis) {
    steps.push({
      target: "records[0].tenantChainPrev",
      kind: "chain_link",
      status: "INVALID",
      reason: "CHAIN_LINK_MISMATCH" as AuditReasonCode,
      message:
        "first record's tenantChainPrev does not equal the expected genesis seed — chain is rooted at an unknown prior tip",
      detail: {
        expected: expectedGenesis,
        actual: first.tenantChainPrev,
      },
    });
  } else {
    steps.push({
      target: "records[0].tenantChainPrev",
      kind: "chain_link",
      status: "VALID",
      message: "genesis prev seed matches the expected tenant seed",
    });
  }

  // 2. Walk: monotonicity, prev linkage, next recomputation.
  let prevSequence: bigint | null = null;
  for (let i = 0; i < records.length; i++) {
    const curr = records[i]!;
    const prev = i > 0 ? records[i - 1]! : null;

    // Sequence monotonicity.
    let currSequence: bigint;
    try {
      currSequence = BigInt(curr.tenantChainSequence);
    } catch {
      steps.push({
        target: `records[${i}].tenantChainSequence`,
        kind: "chain_link",
        status: "INVALID",
        reason: "MALFORMED_PACK" as AuditReasonCode,
        message: `tenantChainSequence at index ${i} is not a valid bigint string`,
        detail: { value: curr.tenantChainSequence },
      });
      continue;
    }
    if (prevSequence !== null && currSequence !== prevSequence + 1n) {
      steps.push({
        target: `records[${i}].tenantChainSequence`,
        kind: "chain_link",
        status: "INVALID",
        reason: "CHAIN_OUT_OF_ORDER" as AuditReasonCode,
        message: `tenantChainSequence at index ${i} is ${currSequence}, expected ${
          prevSequence + 1n
        } (gaps or duplicates indicate inserted/dropped rows)`,
        detail: {
          expected: (prevSequence + 1n).toString(),
          actual: currSequence.toString(),
        },
      });
    }
    prevSequence = currSequence;

    // Prev linkage (skip for genesis — covered above).
    if (i > 0 && prev && curr.tenantChainPrev !== prev.tenantChainNext) {
      steps.push({
        target: `records[${i}].tenantChainPrev`,
        kind: "chain_link",
        status: "INVALID",
        reason: "CHAIN_LINK_MISMATCH" as AuditReasonCode,
        message: `record[${i}].tenantChainPrev does not equal record[${
          i - 1
        }].tenantChainNext — chain link broken`,
        detail: {
          expected: prev.tenantChainNext,
          actual: curr.tenantChainPrev,
        },
      });
    } else if (i > 0) {
      steps.push({
        target: `records[${i}].tenantChainPrev`,
        kind: "chain_link",
        status: "VALID",
        message: `record[${i}] correctly chains off record[${i - 1}]`,
      });
    }

    // Next recomputation.
    const expectedNext = sha256Hex(
      canonicaliseTenantChainLink({
        prev: curr.tenantChainPrev,
        rowAfterHash: curr.rowAfterHash,
        sequence: currSequence.toString(),
      }),
    );
    if (expectedNext !== curr.tenantChainNext) {
      steps.push({
        target: `records[${i}].tenantChainNext`,
        kind: "chain_link",
        status: "INVALID",
        reason: "CHAIN_LINK_MISMATCH" as AuditReasonCode,
        message: `record[${i}].tenantChainNext does not equal the recomputed link — value was tampered with after write`,
        detail: { expected: expectedNext, actual: curr.tenantChainNext },
      });
    } else {
      steps.push({
        target: `records[${i}].tenantChainNext`,
        kind: "chain_link",
        status: "VALID",
        message: `record[${i}].tenantChainNext matches the recomputed link`,
      });
    }
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
