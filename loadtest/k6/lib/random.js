export function randomHex(len) {
  let out = "";
  for (let i = 0; i < len; i += 1) {
    out += Math.floor(Math.random() * 16).toString(16);
  }
  return out;
}

export function randomUuidV4() {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0"));
  return [
    hex.slice(0, 4).join(""),
    hex.slice(4, 6).join(""),
    hex.slice(6, 8).join(""),
    hex.slice(8, 10).join(""),
    hex.slice(10, 16).join(""),
  ].join("-");
}

export function randomId(prefix) {
  const rand = Math.random().toString(16).slice(2);
  return prefix ? `${prefix}-${rand}` : rand;
}

export function pickWeighted(rng, choices) {
  const roll = rng();
  let acc = 0;
  for (const choice of choices) {
    acc += choice.weight;
    if (roll <= acc) {
      return choice;
    }
  }
  return choices[choices.length - 1];
}

export function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export function randomAscii(size) {
  let out = "";
  for (let i = 0; i < size; i += 1) {
    out += String.fromCharCode(97 + Math.floor(Math.random() * 26));
  }
  return out;
}

export function randomEmail(domain) {
  const host = domain || "loadtest.local";
  return `${randomId("k6")}-${randomAscii(6)}@${host}`;
}
