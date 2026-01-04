export const ID_SIGNATURE_PREFIX = "zann-id:v1";

export class SecurityError extends Error {}
export class TimeSyncError extends Error {}

export const base32Encode = (input: Uint8Array): string => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      const index = (value >> (bits - 5)) & 31;
      output += alphabet[index];
      bits -= 5;
    }
  }
  if (bits > 0) {
    const index = (value << (5 - bits)) & 31;
    output += alphabet[index];
  }
  return output;
};

export const deriveServerId = (
  publicKey: Uint8Array,
  hashFn: (data: Uint8Array) => Uint8Array,
): string => base32Encode(hashFn(publicKey));

export const canonicalMessage = (serverId: string, timestamp: number) =>
  `${ID_SIGNATURE_PREFIX}:${serverId}:${timestamp}`;

export const verifyTimeSkew = (
  serverTimestamp: number,
  clientTimestamp: number,
  maxSkew: number,
) => {
  const skew = Math.abs(clientTimestamp - serverTimestamp);
  return skew <= maxSkew;
};

export const verifyIdentitySpec = (options: {
  serverId: string;
  publicKey: Uint8Array;
  signature: Uint8Array;
  timestamp: number;
  clientTime: number;
  maxSkew: number;
  hashFn: (data: Uint8Array) => Uint8Array;
  verifySignature: (
    message: string,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ) => boolean;
}) => {
  const calculatedId = deriveServerId(options.publicKey, options.hashFn);
  if (calculatedId !== options.serverId) {
    throw new SecurityError("SERVER INTEGRITY FAILED");
  }

  const message = canonicalMessage(options.serverId, options.timestamp);
  if (
    !options.verifySignature(message, options.signature, options.publicKey)
  ) {
    throw new SecurityError("SPOOFING DETECTED");
  }

  if (
    !verifyTimeSkew(options.timestamp, options.clientTime, options.maxSkew)
  ) {
    throw new TimeSyncError("CLOCK SKEW");
  }
};
