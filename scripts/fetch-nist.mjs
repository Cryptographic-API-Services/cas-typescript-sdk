// Downloads the NIST CAVP archives used by tests/nist-*.spec.ts and
// tests/aes-fips.spec.ts into tests/data/nist/ (git-ignored).
//
// The archives are static files on csrc.nist.gov, so each one is pinned by
// SHA-256. Only HTTPS is followed, including redirects. #183.
//
// Usage: node scripts/fetch-nist.mjs [--force]

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nist-cavp-"));
  try {
    for (const archive of ARCHIVES) {
      process.stdout.write(`Fetching ${archive.name}... `);
      const bytes = await httpsGet(archive.url);
      const actual = createHash("sha256").update(bytes).digest("hex");
      if (actual !== archive.sha256) {
        throw new Error(`${archive.name} SHA-256 is ${actual}, expected ${archive.sha256}`);
      }
      const zipPath = path.join(tmp, `${archive.name}.zip`);
      fs.writeFileSync(zipPath, bytes);
      execFileSync("tar", ["-xf", zipPath, "-C", tmp, ...archive.members], { stdio: "inherit" });
      for (const member of archive.members) {
        const from = path.join(tmp, member);
        const to = path.join(outDir, path.basename(member));
        fs.copyFileSync(from, to);
      }
      console.log(`ok (${archive.members.length} files, sha256 ${actual})`);
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  fs.writeFileSync(markerPath, `${marker}\n`);
}
