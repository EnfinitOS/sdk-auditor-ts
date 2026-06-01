import { describe, expect, it } from "vitest";

import { AuditorError } from "../src/errors.js";
import { KeyDirectory, loadKeyDirectory } from "../src/keys.js";
import type { VerificationKey } from "../src/types.js";

const K: VerificationKey = {
  keyId: "k1",
  algorithm: "ed25519",
  publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  notBefore: "2025-01-01T00:00:00.000Z",
  notAfter: "2027-01-01T00:00:00.000Z",
  revokedAt: null,
};

describe("KeyDirectory.lookup", () => {
  const dir = new KeyDirectory({
    source: "local",
    snapshotId: null,
    issuedAt: null,
    keys: [K],
  });

  it("returns hit for a key in its window", () => {
    const r = dir.lookup("k1", "2026-04-01T12:00:00.000Z");
    expect(r.kind).toBe("hit");
  });

  it("returns miss UNKNOWN_KEY_ID for missing keyId", () => {
    const r = dir.lookup("nope", "2026-04-01T12:00:00.000Z");
    expect(r.kind).toBe("miss");
    if (r.kind === "miss") expect(r.reason).toBe("UNKNOWN_KEY_ID");
  });

  it("returns miss KEY_OUTSIDE_VALIDITY_WINDOW before notBefore", () => {
    const r = dir.lookup("k1", "2024-04-01T12:00:00.000Z");
    expect(r.kind).toBe("miss");
    if (r.kind === "miss") expect(r.reason).toBe("KEY_OUTSIDE_VALIDITY_WINDOW");
  });

  it("returns miss KEY_OUTSIDE_VALIDITY_WINDOW after notAfter", () => {
    const r = dir.lookup("k1", "2028-04-01T12:00:00.000Z");
    expect(r.kind).toBe("miss");
    if (r.kind === "miss") expect(r.reason).toBe("KEY_OUTSIDE_VALIDITY_WINDOW");
  });

  it("returns miss KEY_REVOKED_BEFORE_ISSUANCE for issuance after revocation", () => {
    const dir2 = new KeyDirectory({
      source: "local",
      snapshotId: null,
      issuedAt: null,
      keys: [{ ...K, revokedAt: "2026-01-01T00:00:00.000Z" }],
    });
    const r = dir2.lookup("k1", "2026-04-01T12:00:00.000Z");
    expect(r.kind).toBe("miss");
    if (r.kind === "miss") expect(r.reason).toBe("KEY_REVOKED_BEFORE_ISSUANCE");
  });

  it("accepts issuance before revocation", () => {
    const dir2 = new KeyDirectory({
      source: "local",
      snapshotId: null,
      issuedAt: null,
      keys: [{ ...K, revokedAt: "2026-06-01T00:00:00.000Z" }],
    });
    const r = dir2.lookup("k1", "2026-04-01T12:00:00.000Z");
    expect(r.kind).toBe("hit");
  });

  it("rejects duplicate keyIds at construction", () => {
    expect(
      () =>
        new KeyDirectory({
          source: "local",
          snapshotId: null,
          issuedAt: null,
          keys: [K, K],
        }),
    ).toThrow(AuditorError);
  });
});

describe("loadKeyDirectory(local)", () => {
  it("validates each key shape", async () => {
    await expect(
      loadKeyDirectory({
        source: "local",
        localKeys: [{ ...K, algorithm: "rsa" as never }],
      }),
    ).rejects.toThrow(/not supported/);
  });

  it("requires localKeys when source=local", async () => {
    await expect(loadKeyDirectory({ source: "local" })).rejects.toThrow(
      /requires localKeys/,
    );
  });

  it("returns a KeyDirectory containing the supplied keys", async () => {
    const dir = await loadKeyDirectory({ source: "local", localKeys: [K] });
    expect(dir.size()).toBe(1);
    expect(dir.keyIds()).toEqual(["k1"]);
    expect(dir.snapshot.source).toBe("local");
  });
});

describe("loadKeyDirectory(platform)", () => {
  it("propagates KEYS_UNAVAILABLE on fetch failure", async () => {
    await expect(
      loadKeyDirectory({
        source: "platform",
        httpFetch: async () => {
          throw new Error("ECONNREFUSED");
        },
      }),
    ).rejects.toThrow(/ECONNREFUSED|failed to fetch/);
  });

  it("propagates PLATFORM_RESPONSE on non-2xx", async () => {
    await expect(
      loadKeyDirectory({
        source: "platform",
        httpFetch: async () => ({
          ok: false,
          status: 503,
          json: async () => ({}),
          text: async () => "service unavailable",
        }),
      }),
    ).rejects.toThrow(/HTTP 503/);
  });

  it("parses a well-formed runtime_keys.v1 envelope", async () => {
    const dir = await loadKeyDirectory({
      source: "platform",
      httpFetch: async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          ok: true,
          contractVersion: "runtime_keys.v1",
          data: {
            keys: [K],
            issuedAt: "2026-04-01T00:00:00.000Z",
            snapshotId: "snap_1",
          },
        }),
        text: async () => "",
      }),
    });
    expect(dir.size()).toBe(1);
    expect(dir.snapshot.snapshotId).toBe("snap_1");
  });

  it("rejects malformed envelope", async () => {
    await expect(
      loadKeyDirectory({
        source: "platform",
        httpFetch: async () => ({
          ok: true,
          status: 200,
          json: async () => ({ not: "an envelope" }),
          text: async () => "",
        }),
      }),
    ).rejects.toThrow(/runtime_keys.v1 envelope/);
  });
});
