import { describe, expect, it } from "vitest";

import {
  base64UrlDecode,
  base64UrlEncode,
  canonicalSortKeys,
  canonicaliseProofPayload,
  canonicaliseProofSigningInput,
  sha256Prefixed,
} from "../src/canonicalJson.js";
import type { ProofReceiptPayload } from "../src/types.js";

const FIXTURE: ProofReceiptPayload = {
  version: "1",
  receiptId: "rec_001",
  correlationId: null,
  spatialAnchorId: "anchor_A",
  spatialPlacementId: "place_A",
  issuedAt: "2026-04-01T12:00:00.000Z",
  renderedAt: "2026-04-01T11:59:59.000Z",
  dwellMs: 3500,
  nonce: "n0001",
  witness: null,
};

describe("canonicaliseProofPayload", () => {
  it("emits fields in the declared order", () => {
    const out = canonicaliseProofPayload(FIXTURE);
    // Key order: version, receiptId, correlationId, spatialAnchorId,
    // spatialPlacementId, issuedAt, renderedAt, dwellMs, nonce, witness
    expect(out).toBe(
      `{"version":"1","receiptId":"rec_001","correlationId":null,"spatialAnchorId":"anchor_A","spatialPlacementId":"place_A","issuedAt":"2026-04-01T12:00:00.000Z","renderedAt":"2026-04-01T11:59:59.000Z","dwellMs":3500,"nonce":"n0001","witness":null}`,
    );
  });

  it("is independent of JS key-insertion order", () => {
    const shuffled = {
      witness: null,
      nonce: "n0001",
      dwellMs: 3500,
      renderedAt: "2026-04-01T11:59:59.000Z",
      issuedAt: "2026-04-01T12:00:00.000Z",
      spatialPlacementId: "place_A",
      spatialAnchorId: "anchor_A",
      correlationId: null,
      receiptId: "rec_001",
      version: "1",
    } as ProofReceiptPayload;
    expect(canonicaliseProofPayload(shuffled)).toBe(
      canonicaliseProofPayload(FIXTURE),
    );
  });

  it("throws on non-finite dwellMs", () => {
    const bad = { ...FIXTURE, dwellMs: Number.NaN };
    expect(() => canonicaliseProofPayload(bad)).toThrow(/non-finite/);
  });
});

describe("canonicaliseProofSigningInput", () => {
  it("appends |<keyId> with no extra whitespace", () => {
    const out = canonicaliseProofSigningInput(FIXTURE, "key_001");
    expect(out.endsWith("|key_001")).toBe(true);
    expect(out).not.toContain(" ");
  });
});

describe("canonicalSortKeys", () => {
  it("sorts object keys lexicographically", () => {
    const out = canonicalSortKeys({ b: 2, a: 1, c: 3 });
    expect(out).toBe(`{"a":1,"b":2,"c":3}`);
  });

  it("preserves array order", () => {
    const out = canonicalSortKeys([3, 1, 2]);
    expect(out).toBe("[3,1,2]");
  });

  it("recurses into nested objects but not arrays", () => {
    const out = canonicalSortKeys({
      arr: [{ z: 1, a: 2 }, { y: 1 }],
      nested: { b: 1, a: 2 },
    });
    expect(out).toBe(`{"arr":[{"a":2,"z":1},{"y":1}],"nested":{"a":2,"b":1}}`);
  });

  it("handles null + primitives without modification", () => {
    expect(canonicalSortKeys(null)).toBe("null");
    expect(canonicalSortKeys(42)).toBe("42");
    expect(canonicalSortKeys("hello")).toBe(`"hello"`);
    expect(canonicalSortKeys(true)).toBe("true");
  });
});

describe("base64url", () => {
  it("round-trips arbitrary bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const enc = base64UrlEncode(bytes);
    expect(enc).not.toContain("+");
    expect(enc).not.toContain("/");
    expect(enc).not.toContain("=");
    const back = base64UrlDecode(enc);
    expect(Array.from(back)).toEqual(Array.from(bytes));
  });

  it("decodes padded input as well as unpadded", () => {
    const padded = "AQIDBA==";
    const unpadded = "AQIDBA";
    expect(Array.from(base64UrlDecode(padded))).toEqual(
      Array.from(base64UrlDecode(unpadded)),
    );
  });
});

describe("sha256Prefixed", () => {
  it("produces the platform's sha256:<hex> form", () => {
    const out = sha256Prefixed("abc");
    expect(out).toBe(
      "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});
