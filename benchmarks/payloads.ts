/**
 * Deterministic inputs, so every run (and every machine) benchmarks the same bytes.
 */
export const ONE_KIB = 1024;
export const ONE_MIB = 1024 * 1024;

export const PASSWORD = "correct horse battery staple";

/** mulberry32: a small seeded PRNG. Not for cryptography, only for repeatable inputs. */
function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Pseudo-random, incompressible bytes. */
export function randomBytes(length: number, seed = 42): number[] {
  const next = seededRandom(seed);
  const bytes = new Array<number>(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = Math.floor(next() * 256);
  }
  return bytes;
}

/** Text-like bytes that compress roughly like a log or JSON file. */
export function compressible(length: number, seed = 42): number[] {
  const words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", '{"id":', '"name":', "},"];
  const next = seededRandom(seed);
  let text = "";
  while (text.length < length) {
    text += `${words[Math.floor(next() * words.length)]} ${Math.floor(next() * 1000)}\n`;
  }
  return Array.from(Buffer.from(text.slice(0, length), "utf8"));
}

/** Human-readable byte size for parameter labels, e.g. 1 KiB, 1 MiB. */
export function formatSize(bytes: number): string {
  if (bytes >= ONE_MIB && bytes % ONE_MIB === 0) {
    return `${bytes / ONE_MIB} MiB`;
  }
  if (bytes >= ONE_KIB && bytes % ONE_KIB === 0) {
    return `${bytes / ONE_KIB} KiB`;
  }
  return `${bytes} B`;
}
