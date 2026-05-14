import { describe, expect, it } from "vitest";

import {
  EnfinitOSAuditor,
  NodeCryptoEd25519Verifier,
} from "../src/index.js";

import {
  buildMeteringSummary,
  buildMultiRecordChain,
  buildSettlementSummary,
  buildValidPack,
} from "./fixtures/builder.js";

describe("EnfinitOSAuditor.verifyProofPack", () => {
  it("returns VALID for an honest pack with the right local keys", async () => {
    const { pack, key } = buildValidPack();
    const auditor = new EnfinitOSAuditor({
      verificationKeySource: "local",
      localKeys: [key.verificationKey],
      signatureVerifier: new NodeCryptoEd25519Verifier(),
    });
    const report = await auditor.verifyProofPack(pack);
    expect(report.status).toBe("VALID");
    expect(report.packId).toBe(pack.packId);
    expect(report.keysSnapshot.source).toBe("local");
    expect(report.keysSnapshot.keyIds).toEqual([key.keyId]);
  });

  it("returns INVALID for a tampered payload", async () => {
    const { pack, key } = buildValidPack();
    const tampered = JSON.parse(JSON.stringify(pack));
    tampered.records[0].payload.dwellMs = 99999;
    const auditor = new EnfinitOSAuditor({
      verificationKeySource: "local",
      localKeys: [key.verificationKey],
      signatureVerifier: new NodeCryptoEd25519Verifier(),
    });
    const report = await auditor.verifyProofPack(tampered);
    expect(report.status).toBe("INVALID");
  });

  it("returns a single-step INVALID report on unparseable input", async () => {
    const auditor = new EnfinitOSAuditor({
      verificationKeySource: "local",
      localKeys: [],
    });
    const report = await auditor.verifyProofPack("not a pack" as never);
    expect(report.status).toBe("INVALID");
    expect(report.envelopeVersion).toBe("unknown");
  });

  it("verifyAll runs the full pipeline and reconciles", async () => {
    const key = (await import("./fixtures/builder.js")).generateKey();
    const pack = buildMultiRecordChain(3, key);
    const metering = buildMeteringSummary(pack);
    const settlement = buildSettlementSummary(metering);
    const auditor = new EnfinitOSAuditor({
      verificationKeySource: "local",
      localKeys: [key.verificationKey],
      signatureVerifier: new NodeCryptoEd25519Verifier(),
    });
    const full = await auditor.verifyAll({ pack, metering, settlement });
    expect(full.status).toBe("VALID");
    expect(full.pack.status).toBe("VALID");
    expect(full.chain.status).toBe("VALID");
    expect(full.metering.status).toBe("VALID");
    expect(full.settlement.status).toBe("VALID");
  });

  it("verifyAll skips metering/settlement when not in bundle", async () => {
    const { pack, key } = buildValidPack();
    const auditor = new EnfinitOSAuditor({
      verificationKeySource: "local",
      localKeys: [key.verificationKey],
      signatureVerifier: new NodeCryptoEd25519Verifier(),
    });
    const full = await auditor.verifyAll({ pack });
    expect(full.metering.status).toBe("SKIPPED");
    expect(full.settlement.status).toBe("SKIPPED");
    // overall status is VALID — every non-skipped step passed
    expect(full.status).toBe("VALID");
  });

  it("verifyAll demotes to INVALID if any sub-step fails", async () => {
    const key = (await import("./fixtures/builder.js")).generateKey();
    const pack = buildMultiRecordChain(2, key);
    const metering = buildMeteringSummary(pack);
    const settlement = buildSettlementSummary(metering);
    settlement.lines[0]!.amountCents += 999;
    const auditor = new EnfinitOSAuditor({
      verificationKeySource: "local",
      localKeys: [key.verificationKey],
      signatureVerifier: new NodeCryptoEd25519Verifier(),
    });
    const full = await auditor.verifyAll({ pack, metering, settlement });
    expect(full.status).toBe("INVALID");
    expect(full.settlement.status).toBe("INVALID");
  });

  it("rejects construction with local source but no localKeys", () => {
    expect(
      () =>
        new EnfinitOSAuditor({
          verificationKeySource: "local",
        }),
    ).toThrow(/requires opts.localKeys/);
  });
});
