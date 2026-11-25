// Downloads the Wycheproof test vectors used by tests/wycheproof-*.spec.ts from
// C2SP/wycheproof into tests/data/wycheproof/ (git-ignored).
//
// Every run tests against the latest upstream vectors: the ref (default
// "main", override with WYCHEPROOF_REF) is resolved to a commit SHA, which is
// logged for reproducibility and used to skip re-downloading unchanged files.
// Each downloaded file must match the git blob SHA-1 recorded for it in that
// commit's tree (read from the GitHub API), and only HTTPS URLs are followed,
// including redirects. Set GITHUB_TOKEN to raise the API rate limit.
//
// Usage: node scripts/fetch-wycheproof.mjs [--force]

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = "C2SP/wycheproof";
const VECTOR_DIR = "testvectors_v1";
const MAX_REDIRECTS = 5;

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
const isCommitSha = (value) => /^[0-9a-f]{40}$/i.test(value);

class IntegrityError extends Error {}

async function httpsFetch(url, options = {}) {
  for (let redirects = 0; ; redirects++) {
    if (new URL(url).protocol !== "https:") {
      throw new Error(`Refusing to fetch non-HTTPS URL ${url}`);
    }
    const response = await fetch(url, { ...options, redirect: "manual" });
    const location = response.headers.get("location");
    if (response.status < 300 || response.status >= 400 || !location) {
      return response;
    }
    await response.body?.cancel();
    if (redirects >= MAX_REDIRECTS) {
      throw new Error(`Too many redirects fetching ${url}`);
    }
    url = new URL(location, url).href;
  }
}

async function githubApi(endpoint, accept = "application/vnd.github+json") {
  const url = `https://api.github.com/repos/${REPO}/${endpoint}`;
  const headers = { Accept: accept, "User-Agent": "cas-typescript-sdk-wycheproof-fetch" };
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const response = await httpsFetch(url, { headers });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} for ${url}: ${await response.text()}`);
  }
  return accept === "application/vnd.github.sha" ? response.text() : response.json();
}

async function resolveRef(name) {
  if (isCommitSha(name)) {
    return name.toLowerCase();
  }
  try {
    // Pin git to HTTPS, including for redirects it follows.
    const output = execFileSync(
      "git",
      ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "ls-remote", `https://github.com/${REPO}`, name],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );
    const sha = output.split(/\s/)[0];
    if (isCommitSha(sha)) {
      return sha.toLowerCase();
    }
  } catch {
    // git missing or failed; ask the GitHub API instead.
  }
  const sha = (await githubApi(`commits/${encodeURIComponent(name)}`, "application/vnd.github.sha")).trim();
  if (!isCommitSha(sha)) {
    throw new Error(`Could not resolve ${REPO}@${name} to a commit SHA`);
  }
  return sha.toLowerCase();
}

// Maps each vector file name to its git blob SHA-1 in the given commit.
async function expectedBlobShas(commitSha) {
  const root = await githubApi(`git/trees/${commitSha}`);
  const dir = root.tree.find((entry) => entry.path === VECTOR_DIR && entry.type === "tree");
  if (!dir) {
    throw new Error(`${REPO}@${commitSha} has no ${VECTOR_DIR}/ directory`);
  }
  const vectors = await githubApi(`git/trees/${dir.sha}`);
  if (vectors.truncated) {
    throw new Error(`GitHub truncated the ${VECTOR_DIR}/ tree listing for ${REPO}@${commitSha}`);
  }
  return new Map(vectors.tree.filter((entry) => entry.type === "blob").map((entry) => [entry.path, entry.sha.toLowerCase()]));
}

function gitBlobSha(bytes) {
  return createHash("sha1").update(`blob ${bytes.byteLength}\0`).update(bytes).digest("hex");
}

const ref = await resolveRef(requestedRef);

const outDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "tests", "data", "wycheproof");
const markerPath = path.join(outDir, ".wycheproof-ref");

function upToDate() {
  if (force || !fs.existsSync(markerPath)) {
    return false;
  }
  if (fs.readFileSync(markerPath, "utf8").trim() !== ref) {
    return false;
  }
  return FILES.every((file) => fs.existsSync(path.join(outDir, file)));
}

async function download(file, expectedSha, attempts = 3) {
  const url = `https://raw.githubusercontent.com/${REPO}/${ref}/${VECTOR_DIR}/${file}`;
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await httpsFetch(url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} for ${url}`);
      }
      const bytes = Buffer.from(await response.arrayBuffer());
      const actualSha = gitBlobSha(bytes);
      if (actualSha !== expectedSha) {
        throw new IntegrityError(
          `Integrity check failed for ${url}: git blob SHA-1 is ${actualSha}, but ${REPO}@${ref} records ${expectedSha}`,
        );
      }
      // Fail here rather than with a confusing error inside a spec.
      const parsed = JSON.parse(bytes.toString("utf8"));
      if (!Array.isArray(parsed.testGroups)) {
        throw new Error(`${url} is not a Wycheproof vector file`);
      }
      const target = path.join(outDir, file);
      fs.writeFileSync(`${target}.tmp`, bytes);
      fs.renameSync(`${target}.tmp`, target);
      return parsed.numberOfTests;
    } catch (error) {
      if (attempt >= attempts || error instanceof IntegrityError || /HTTP 404|non-HTTPS/.test(String(error))) {
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
  const expected = await expectedBlobShas(ref);
  const missing = FILES.filter((file) => !expected.has(file));
  if (missing.length > 0) {
    throw new Error(`${REPO}@${ref} has no ${missing.map((file) => `${VECTOR_DIR}/${file}`).join(", ")}`);
  }
  const counts = await Promise.all(FILES.map((file) => download(file, expected.get(file))));
  FILES.forEach((file, i) => console.log(`  ${file} (${counts[i]} tests, git blob ${expected.get(file)} verified)`));
  fs.writeFileSync(markerPath, `${ref}\n`);
}
