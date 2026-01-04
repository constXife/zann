import { describe, it, expect } from "vitest";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import {
  SecurityError,
  TimeSyncError,
  canonicalMessage,
  deriveServerId,
  verifyIdentitySpec,
  verifyTimeSkew,
} from "../identity";

const sha256 = (data: Uint8Array): Uint8Array => {
  return createHash("sha256").update(data).digest();
};

const signMessage = (
  message: string,
  privateKey: CryptoKey | ReturnType<typeof generateKeyPairSync>["privateKey"],
) => sign(null, Buffer.from(message), privateKey);

const verifySignature = (
  message: string,
  signature: Uint8Array,
  publicKey: CryptoKey | ReturnType<typeof generateKeyPairSync>["publicKey"],
) => verify(null, Buffer.from(message), publicKey, signature);

describe("identity verification (spec)", () => {
  it("derives server_id from public key hash (base32, lowercase, no padding)", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const pubBytes = publicKey.export({ type: "spki", format: "der" });
    const serverId = deriveServerId(pubBytes, sha256);

    expect(serverId).toBe(serverId.toLowerCase());
    expect(serverId).not.toContain("=");
    expect(serverId.length).toBeGreaterThan(10);
  });

  it("validates proof-of-possession with a signature", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pubBytes = publicKey.export({ type: "spki", format: "der" });
    const serverId = deriveServerId(pubBytes, sha256);
    const timestamp = 1_704_400_000;
    const msg = canonicalMessage(serverId, timestamp);

    const signature = signMessage(msg, privateKey);

    expect(verifySignature(msg, signature, publicKey)).toBe(true);
  });

  it("rejects mismatched server_id", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const pubBytes = publicKey.export({ type: "spki", format: "der" });
    const serverId = deriveServerId(pubBytes, sha256);

    const tampered = new Uint8Array(pubBytes);
    tampered[0] ^= 0b0001_0000;
    const otherId = deriveServerId(tampered, sha256);

    expect(otherId).not.toBe(serverId);
  });

  it("accepts timestamps within the allowed skew window", () => {
    const clientTime = 1_704_400_600;
    const serverTime = 1_704_400_450;
    const maxSkew = 300;

    expect(verifyTimeSkew(serverTime, clientTime, maxSkew)).toBe(true);
  });

  it("rejects timestamps outside the allowed skew window", () => {
    const clientTime = 1_704_401_000;
    const serverTime = 1_704_400_000;
    const maxSkew = 300;

    expect(verifyTimeSkew(serverTime, clientTime, maxSkew)).toBe(false);
  });

  it("treats hash mismatches as security errors", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const pubBytes = publicKey.export({ type: "spki", format: "der" });
    const serverId = "wrong-id";

    expect(() =>
      verifyIdentitySpec({
        serverId,
        publicKey: pubBytes,
        signature: new Uint8Array([1, 2, 3]),
        timestamp: 1_704_400_000,
        clientTime: 1_704_400_100,
        maxSkew: 300,
        hashFn: sha256,
        verifySignature: () => true,
      }),
    ).toThrow(SecurityError);
  });

  it("treats invalid signatures as security errors", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const pubBytes = publicKey.export({ type: "spki", format: "der" });
    const serverId = deriveServerId(pubBytes, sha256);

    expect(() =>
      verifyIdentitySpec({
        serverId,
        publicKey: pubBytes,
        signature: new Uint8Array([9, 9, 9]),
        timestamp: 1_704_400_000,
        clientTime: 1_704_400_100,
        maxSkew: 300,
        hashFn: sha256,
        verifySignature: () => false,
      }),
    ).toThrow(SecurityError);
  });

  it("treats clock skew as a time sync error", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const pubBytes = publicKey.export({ type: "spki", format: "der" });
    const serverId = deriveServerId(pubBytes, sha256);

    expect(() =>
      verifyIdentitySpec({
        serverId,
        publicKey: pubBytes,
        signature: new Uint8Array([7, 7, 7]),
        timestamp: 1_704_400_000,
        clientTime: 1_704_500_000,
        maxSkew: 300,
        hashFn: sha256,
        verifySignature: () => true,
      }),
    ).toThrow(TimeSyncError);
  });
});
