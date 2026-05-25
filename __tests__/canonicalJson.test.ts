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

  it("decodes valid unpadded base64url", () => {
    // 4 bytes → 6 base64url characters (no padding).
    const unpadded = "AQIDBA";
    expect(Array.from(base64UrlDecode(unpadded))).toEqual([1, 2, 3, 4]);
  });

  // ── Strict-mode rejection cases (MC-3 / pentest 2026-05-25) ────────
  //
  // The decoder enforces RFC 4648 §5 strictly. Wire-malleability is the
  // attack we're closing: a verifier that accepts two different spellings
  // of the same logical signature cannot byte-compare two signatures and
  // trust the result. Below: each rejection case + a positive control.

  it("rejects padding (= character)", () => {
    expect(() => base64UrlDecode("AQIDBA==")).toThrow(/padding/);
    expect(() => base64UrlDecode("A=")).toThrow(/padding/);
    expect(() => base64UrlDecode("=")).toThrow(/padding/);
  });

  it("rejects whitespace anywhere in the input", () => {
    expect(() => base64UrlDecode("AQ IDBA")).toThrow(/whitespace/);
    expect(() => base64UrlDecode(" AQIDBA")).toThrow(/whitespace/);
    expect(() => base64UrlDecode("AQIDBA ")).toThrow(/whitespace/);
    expect(() => base64UrlDecode("AQIDBA\n")).toThrow(/whitespace/);
    expect(() => base64UrlDecode("AQ\tIDBA")).toThrow(/whitespace/);
  });

  it("rejects standard-base64 characters (+ and /)", () => {
    expect(() => base64UrlDecode("AQ+DBA")).toThrow(/invalid.+character/i);
    expect(() => base64UrlDecode("AQ/DBA")).toThrow(/invalid.+character/i);
  });

  it("rejects other non-alphabet characters", () => {
    expect(() => base64UrlDecode("AQ!DBA")).toThrow(/invalid.+character/i);
    expect(() => base64UrlDecode("AQ.DBA")).toThrow(/invalid.+character/i);
    expect(() => base64UrlDecode("hello world")).toThrow(/whitespace|invalid/);
  });

  it("rejects impossible length (mod 4 === 1)", () => {
    // A 5-char input cannot represent any valid byte sequence under
    // base64url. The decoder rejects rather than silently producing
    // garbage.
    expect(() => base64UrlDecode("AQIDB")).toThrow(/length/);
  });

  it("rejects non-string input", () => {
    // Defensive — pen test scope is JS users; type-coerce attacks here
    // are theoretical but we close them anyway.
    expect(() => base64UrlDecode(null as unknown as string)).toThrow(/string/);
    expect(() => base64UrlDecode(undefined as unknown as string)).toThrow(
      /string/,
    );
    expect(() => base64UrlDecode(123 as unknown as string)).toThrow(/string/);
  });

  it("accepts the canonical unpadded forms produced by base64UrlEncode", () => {
    // Round-trip property: anything our encoder emits must decode.
    for (const len of [0, 1, 2, 3, 4, 5, 16, 32, 64, 65]) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = (i * 31) & 0xff;
      const enc = base64UrlEncode(bytes);
      expect(enc).not.toContain("=");
      expect(() => base64UrlDecode(enc)).not.toThrow();
      expect(Array.from(base64UrlDecode(enc))).toEqual(Array.from(bytes));
    }
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
