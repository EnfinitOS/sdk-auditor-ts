import { describe, expect, it } from "vitest";

import { verifyProofChain } from "../src/proofChain.js";

import { buildMultiRecordChain, generateKey } from "./fixtures/builder.js";

describe("verifyProofChain", () => {
  it("walks a valid 5-record chain", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(5, key);
    const report = verifyProofChain(pack.records);
    expect(report.status).toBe("VALID");
    expect(report.recordCount).toBe(5);
  });

  it("flags an empty chain", () => {
    const report = verifyProofChain([]);
    expect(report.status).toBe("INVALID");
  });

  it("flags GENESIS_BEFORE_HASH_NOT_NULL when first record has beforeHash", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(3, key);
    const broken = pack.records.map((r, i) =>
      i === 0 ? { ...r, beforeHash: "deadbeef" } : r,
    );
    const report = verifyProofChain(broken);
    expect(report.status).toBe("INVALID");
    expect(
      report.steps.some((s) => s.reason === "GENESIS_BEFORE_HASH_NOT_NULL"),
    ).toBe(true);
  });

  it("flags CHAIN_LINK_MISMATCH for a broken link", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(3, key);
    const broken = pack.records.map((r, i) =>
      i === 1 ? { ...r, beforeHash: "deadbeef" } : r,
    );
    const report = verifyProofChain(broken);
    expect(report.status).toBe("INVALID");
    expect(
      report.steps.some((s) => s.reason === "CHAIN_LINK_MISMATCH"),
    ).toBe(true);
  });

  it("flags CHAIN_OUT_OF_ORDER for swapped issuance timestamps", () => {
    const key = generateKey();
    const pack = buildMultiRecordChain(3, key);
    // Rewrite record[1].issuedAt to be earlier than record[0]
    // — but keep the chain hashes intact (the chain-walk doesn't
    // recompute hashes; it trusts them).
    const broken = pack.records.map((r, i) => {
      if (i === 1) {
        return {
          ...r,
          payload: { ...r.payload, issuedAt: "2020-01-01T00:00:00.000Z" },
        };
      }
      return r;
    });
    const report = verifyProofChain(broken);
    expect(
      report.steps.some((s) => s.reason === "CHAIN_OUT_OF_ORDER"),
    ).toBe(true);
  });
});
