// Downloads the Wycheproof test vectors used by tests/wycheproof-*.spec.ts from
// C2SP/wycheproof into tests/data/wycheproof/ (git-ignored).
//
// Every run tests against the latest upstream vectors: the ref (default
// "main", override with WYCHEPROOF_REF) is resolved to a commit SHA, which is
// logged for reproducibility and used to skip re-downloading unchanged files.
//
// Usage: node scripts/fetch-wycheproof.mjs [--force]

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = "C2SP/wycheproof";
const VECTOR_DIR = "testvectors_v1";

const FILES = [
  "aes_gcm_test.json",
  "aes_gcm_siv_test.json",
  "chacha20_poly1305_test.json",
  "ed25519_test.json",
  "hmac_sha256_test.json",
  "hmac_sha512_test.json",
  "mldsa_65_sign_seed_test.json",
  "mldsa_65_verify_test.json",
  "mlkem_1024_semi_expanded_decaps_test.json",
  "x25519_test.json",
];

const requestedRef = process.env.WYCHEPROOF_REF || "main";
const force = process.argv.includes("--force");

function resolveRef(name) {
  if (/^[0-9a-f]{40}$/i.test(name)) {
    return name;
  }
  try {
    const output = execFileSync(
      "git",
      ["ls-remote", `https://github.com/${REPO}`, name],
      { encoding: "utf8" },
    );
    const sha = output.split(/\s/)[0];
    if (/^[0-9a-f]{40}$/i.test(sha)) {
      return sha;
    }
  } catch {
    // Fall through and fetch by name; the files just won't be cached.
  }
  return name;
}

const ref = resolveRef(requestedRef);
const isCommitSha = /^[0-9a-f]{40}$/i.test(ref);

const outDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "tests", "data", "wycheproof");
const markerPath = path.join(outDir, ".wycheproof-ref");

function upToDate() {
  // Branches and tags can move, so only a commit SHA is safe to cache.
  if (force || !isCommitSha || !fs.existsSync(markerPath)) {
    return false;
  }
  if (fs.readFileSync(markerPath, "utf8").trim() !== ref) {
    return false;
  }
  return FILES.every((file) => fs.existsSync(path.join(outDir, file)));
}

async function download(file, attempts = 3) {
  const url = `https://raw.githubusercontent.com/${REPO}/${ref}/${VECTOR_DIR}/${file}`;
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} for ${url}`);
      }
      const body = await response.text();
      // Fail here rather than with a confusing error inside a spec.
      const parsed = JSON.parse(body);
      if (!Array.isArray(parsed.testGroups)) {
        throw new Error(`${url} is not a Wycheproof vector file`);
      }
      const target = path.join(outDir, file);
      fs.writeFileSync(`${target}.tmp`, body);
      fs.renameSync(`${target}.tmp`, target);
      return parsed.numberOfTests;
    } catch (error) {
      if (attempt >= attempts || /HTTP 404/.test(String(error))) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
    }
  }
}

if (upToDate()) {
  console.log(`Wycheproof vectors already at ${ref}`);
} else {
  fs.mkdirSync(outDir, { recursive: true });
  console.log(`Fetching ${FILES.length} Wycheproof vector files from ${REPO}@${ref} (${requestedRef})`);
  const counts = await Promise.all(FILES.map((file) => download(file)));
  FILES.forEach((file, i) => console.log(`  ${file} (${counts[i]} tests)`));
  fs.writeFileSync(markerPath, `${ref}\n`);
}
