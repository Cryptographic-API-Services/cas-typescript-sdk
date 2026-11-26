// Downloads the NIST CAVP archives used by tests/nist-*.spec.ts and
// tests/aes-fips.spec.ts into tests/data/nist/ (git-ignored).
//
// The archives are static files on csrc.nist.gov, so each one is pinned by
// SHA-256. Only HTTPS is followed, including redirects. #183.
//
// Usage: node scripts/fetch-nist.mjs [--force]

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { inflateRawSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const MAX_REDIRECTS = 5;

const ARCHIVES = [
  {
    name: "gcm",
    url: "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip",
    sha256: "f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023",
    members: [
      "gcmEncryptExtIV128.rsp",
      "gcmEncryptExtIV256.rsp",
      "gcmDecrypt128.rsp",
      "gcmDecrypt256.rsp",
    ],
  },
  {
    name: "kw",
    url: "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/kwtestvectors.zip",
    sha256: "04a4a82e4de65bca505125295003f9c75a5a815afda046dc83661b8b580dfdf3",
    members: [
      "kwtestvectors/KW_AE_128.txt",
      "kwtestvectors/KW_AE_256.txt",
      "kwtestvectors/KW_AD_128.txt",
      "kwtestvectors/KW_AD_256.txt",
      "kwtestvectors/KWP_AE_128.txt",
      "kwtestvectors/KWP_AE_256.txt",
      "kwtestvectors/KWP_AD_128.txt",
      "kwtestvectors/KWP_AD_256.txt",
    ],
  },
  {
    name: "hmac",
    url: "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip",
    sha256: "418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd",
    members: ["HMAC.rsp"],
  },
];

const force = process.argv.includes("--force");
const outDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "tests", "data", "nist");
const markerPath = path.join(outDir, ".nist-ref");
const marker = ARCHIVES.map((archive) => `${archive.name} ${archive.sha256}`).join("\n");

function wantedNames() {
  return ARCHIVES.flatMap((archive) => archive.members.map((member) => path.basename(member)));
}

// GNU tar on Linux does not read zip files. Windows bsdtar does, which is why
// a local extract is not a check. Read the central directory and inflate here.
function unzipMembers(zip, wanted) {
  const eocd = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0) {
    throw new Error("download is not a zip archive");
  }
  const count = zip.readUInt16LE(eocd + 10);
  let cursor = zip.readUInt32LE(eocd + 16);
  const found = new Map();
  for (let i = 0; i < count; i++) {
    if (zip.readUInt32LE(cursor) !== 0x02014b50) {
      throw new Error("zip central directory is truncated");
    }
    const method = zip.readUInt16LE(cursor + 10);
    const compressedSize = zip.readUInt32LE(cursor + 20);
    const nameLength = zip.readUInt16LE(cursor + 28);
    const extraLength = zip.readUInt16LE(cursor + 30);
    const commentLength = zip.readUInt16LE(cursor + 32);
    const localOffset = zip.readUInt32LE(cursor + 42);
    const name = zip.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8").replaceAll("\\", "/");
    cursor += 46 + nameLength + extraLength + commentLength;
    if (!wanted.has(name)) {
      continue;
    }
    const dataStart = localOffset + 30 + zip.readUInt16LE(localOffset + 26) + zip.readUInt16LE(localOffset + 28);
    const compressed = zip.subarray(dataStart, dataStart + compressedSize);
    if (method === 0) {
      found.set(name, Buffer.from(compressed));
    } else if (method === 8) {
      found.set(name, inflateRawSync(compressed));
    } else {
      throw new Error(`${name} uses unsupported zip method ${method}`);
    }
  }
  return found;
}

async function httpsGet(url) {
  for (let redirects = 0; ; redirects++) {
    if (new URL(url).protocol !== "https:") {
      throw new Error(`Refusing to fetch non-HTTPS URL ${url}`);
    }
    const response = await fetch(url, { redirect: "manual" });
    const location = response.headers.get("location");
    if (response.status >= 300 && response.status < 400 && location) {
      await response.body?.cancel();
      if (redirects >= MAX_REDIRECTS) {
        throw new Error(`Too many redirects fetching ${url}`);
      }
      url = new URL(location, url).href;
      continue;
    }
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} for ${url}`);
    }
    return Buffer.from(await response.arrayBuffer());
  }
}

if (
  !force &&
  fs.existsSync(markerPath) &&
  fs.readFileSync(markerPath, "utf8").trim() === marker &&
  wantedNames().every((name) => fs.existsSync(path.join(outDir, name)))
) {
  console.log("NIST CAVP vectors already match the pinned archives");
} else {
  fs.mkdirSync(outDir, { recursive: true });
  for (const archive of ARCHIVES) {
    process.stdout.write(`Fetching ${archive.name}... `);
    const bytes = await httpsGet(archive.url);
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== archive.sha256) {
      throw new Error(`${archive.name} SHA-256 is ${actual}, expected ${archive.sha256}`);
    }
    const extracted = unzipMembers(bytes, new Set(archive.members));
    for (const member of archive.members) {
      const data = extracted.get(member);
      if (!data) {
        throw new Error(`${archive.name} has no ${member}`);
      }
      fs.writeFileSync(path.join(outDir, path.basename(member)), data);
    }
    console.log(`ok (${archive.members.length} files, sha256 ${actual})`);
  }
  fs.writeFileSync(markerPath, `${marker}\n`);
}
