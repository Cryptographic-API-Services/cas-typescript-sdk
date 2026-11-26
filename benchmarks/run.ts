/**
 * Benchmark runner for the SDK's public API (issue #182). See benchmarks/README.md.
 *
 *   npm run bench -- --filter '*Hasher*' --job short
 *   npm run bench -- --category PostQuantum
 *   npm run bench -- --list
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
import { Bench, type BenchOptions, type Task } from "tinybench";
import { Categories, type Category, type Suite } from "./registry";
import { suites } from "./suites";

interface Job {
  description: string;
  options: BenchOptions;
}

/**
 * How long each benchmark runs, from quickest to most accurate (named after
 * BenchmarkDotNet's jobs). tinybench keeps sampling until both `time` (ms) and
 * `iterations` are reached, so slow operations such as password hashing still
 * get a few samples without running for minutes.
 */
const JOBS: Record<string, Job> = {
  dry: {
    description: "each benchmark runs once with no warmup, to check the suite works; timings are meaningless",
    options: { warmup: false, iterations: 1, time: 0 },
  },
  short: {
    description: "100 ms warmup, then at least 500 ms and 5 iterations",
    options: { warmupTime: 100, warmupIterations: 2, time: 500, iterations: 5 },
  },
  medium: {
    description: "250 ms warmup, then at least 2 s and 10 iterations",
    options: { warmupTime: 250, warmupIterations: 5, time: 2_000, iterations: 10 },
  },
  long: {
    description: "1 s warmup, then at least 5 s and 20 iterations",
    options: { warmupTime: 1_000, warmupIterations: 10, time: 5_000, iterations: 20 },
  },
};

const DEFAULT_OUT_DIR = path.resolve(__dirname, "..", "results");

const USAGE = `Usage: npm run bench -- [options]

Options:
  -f, --filter <glob>      Run benchmarks whose name (<Suite>.<Benchmark>) matches the glob,
                           case-insensitive; * matches anything. Repeatable. Default: *
  -c, --category <name>    Run benchmarks in any of these categories. Repeatable.
                           One of: ${Object.values(Categories).join(", ")}
  -j, --job <name>         ${Object.entries(JOBS)
    .map(([name, job]) => `${name}: ${job.description}`)
    .join("\n                           ")}
                           Default: short
  -o, --out <dir>          Where to write results.json and results.md. Default: benchmarks/results
  -l, --list               List the selected benchmarks and exit
  -h, --help               Show this help

The SDK must be built first (npm run build:rust; npm run bench builds the TypeScript).`;

interface Selection {
  suite: Suite;
  benchmarks: Suite["benchmarks"];
}

interface Statistics {
  mean: number;
  p50: number;
  p75: number;
  p99: number;
  min: number;
  max: number;
  sd: number;
}

interface BenchmarkResult {
  id: string;
  suite: string;
  benchmark: string;
  param?: { name: string; value: string };
  categories: Category[];
  state: "completed" | "failed";
  error?: string;
  /** Milliseconds per call. */
  latencyMs?: Statistics;
  /** Relative margin of error of the mean latency, in percent. */
  rmePercent?: number;
  /** Calls per second. */
  throughputOpsPerSec?: Statistics;
  samples?: number;
}

function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

function select(filters: string[], categories: string[]): Selection[] {
  const patterns = filters.map(globToRegExp);
  const wanted = new Set(categories.map((c) => c.toLowerCase()));
  return suites
    .map((suite) => ({
      suite,
      benchmarks: suite.benchmarks.filter(
        (b) =>
          patterns.some((p) => p.test(`${suite.name}.${b.name}`)) &&
          (wanted.size === 0 || b.categories.some((c) => wanted.has(c.toLowerCase()))),
      ),
    }))
    .filter((s) => s.benchmarks.length > 0);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function toStatistics(stats: Statistics): Statistics {
  const { mean, p50, p75, p99, min, max, sd } = stats;
  return { mean, p50, p75, p99, min, max, sd };
}

function toResult(
  suite: Suite,
  benchmark: Suite["benchmarks"][number],
  param: Suite["paramValues"][number],
  task: Task | undefined,
  setupError?: unknown,
): BenchmarkResult {
  const base = {
    id: `${suite.name}.${benchmark.name}${param.label ? ` [${suite.paramName}=${param.label}]` : ""}`,
    suite: suite.name,
    benchmark: benchmark.name,
    param: suite.paramName && param.label ? { name: suite.paramName, value: param.label } : undefined,
    categories: benchmark.categories,
  };
  if (setupError !== undefined) {
    return { ...base, state: "failed", error: `setup failed: ${errorMessage(setupError)}` };
  }
  const result = task?.result;
  if (!result || result.state !== "completed") {
    const error = result?.state === "errored" ? errorMessage(result.error) : `task ${result?.state ?? "missing"}`;
    return { ...base, state: "failed", error };
  }
  return {
    ...base,
    state: "completed",
    latencyMs: toStatistics(result.latency),
    rmePercent: result.latency.rme,
    throughputOpsPerSec: toStatistics(result.throughput),
    samples: result.latency.samplesCount,
  };
}

function formatTime(ms: number): string {
  if (ms >= 1_000) return `${(ms / 1_000).toFixed(2)} s`;
  if (ms >= 1) return `${ms.toFixed(2)} ms`;
  if (ms >= 0.001) return `${(ms * 1_000).toFixed(2)} µs`;
  return `${(ms * 1_000_000).toFixed(0)} ns`;
}

function formatOps(ops: number): string {
  return ops >= 100 ? Math.round(ops).toLocaleString("en-US") : ops.toFixed(2);
}

const COLUMNS = ["Benchmark", "Mean", "p50", "p99", "±", "ops/s", "Samples"] as const;

function row(result: BenchmarkResult): string[] {
  if (result.state === "failed" || !result.latencyMs || !result.throughputOpsPerSec) {
    return [result.benchmark, "FAILED", "", "", "", "", ""];
  }
  return [
    result.benchmark,
    formatTime(result.latencyMs.mean),
    formatTime(result.latencyMs.p50),
    formatTime(result.latencyMs.p99),
    `${(result.rmePercent ?? 0).toFixed(2)}%`,
    formatOps(result.throughputOpsPerSec.mean),
    String(result.samples ?? 0),
  ];
}

function printTable(results: BenchmarkResult[]): void {
  const rows = [Array.from(COLUMNS), ...results.map(row)];
  const widths = COLUMNS.map((_, i) => Math.max(...rows.map((r) => r[i].length)));
  const line = (cells: string[]) =>
    cells.map((cell, i) => (i === 0 ? cell.padEnd(widths[i]) : cell.padStart(widths[i]))).join("  ");
  console.log(line(rows[0]));
  console.log(widths.map((w) => "-".repeat(w)).join("  "));
  for (const r of rows.slice(1)) console.log(line(r));
  for (const r of results.filter((r) => r.state === "failed")) {
    console.log(`  ✗ ${r.benchmark}: ${r.error}`);
  }
  console.log();
}

function environment(jobName: string) {
  const packageJson = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "..", "package.json"), "utf8"));
  const cpus = os.cpus();
  return {
    sdkVersion: packageJson.version as string,
    commit: process.env.GITHUB_SHA,
    node: process.version,
    v8: process.versions.v8,
    platform: `${os.type()} ${os.release()} (${process.platform}-${process.arch})`,
    cpu: `${cpus[0]?.model?.trim() ?? "unknown"} × ${os.availableParallelism()}`,
    job: jobName,
    jobDescription: JOBS[jobName].description,
    date: new Date().toISOString(),
  };
}

function markdownReport(env: ReturnType<typeof environment>, results: BenchmarkResult[]): string {
  // Escape backslash first, then the pipe. Replacing "|" with "\|" alone leaves a
  // backslash in the cell able to swallow the escape (js/incomplete-sanitization).
  const escapeCell = (text: string) => text.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
  const lines: string[] = [];
  if (env.job === "dry") {
    lines.push("> Dry run: every benchmark ran once to check it works. These timings are not meaningful.", "");
  }
  lines.push(
    "| Environment | |",
    "| --- | --- |",
    `| SDK | cas-typescript-sdk ${env.sdkVersion}${env.commit ? ` (${env.commit.slice(0, 7)})` : ""} |`,
    `| Node.js | ${env.node} (V8 ${env.v8}) |`,
    `| OS | ${env.platform} |`,
    `| CPU | ${escapeCell(env.cpu)} |`,
    `| Job | \`${env.job}\`: ${env.jobDescription} |`,
    `| Date | ${env.date} |`,
    "",
  );
  const bySuite = new Map<string, BenchmarkResult[]>();
  for (const r of results) {
    bySuite.set(r.suite, [...(bySuite.get(r.suite) ?? []), r]);
  }
  for (const [suite, suiteResults] of bySuite) {
    const paramName = suiteResults.find((r) => r.param)?.param?.name;
    const header = paramName ? ["Benchmark", paramName, ...COLUMNS.slice(1)] : Array.from(COLUMNS);
    lines.push(`### ${suite}`, "", `| ${header.join(" | ")} |`, `| ${header.map((_, i) => (i < (paramName ? 2 : 1) ? "---" : "---:")).join(" | ")} |`);
    for (const r of suiteResults) {
      const cells = row(r);
      if (paramName) cells.splice(1, 0, r.param?.value ?? "");
      lines.push(`| ${cells.map(escapeCell).join(" | ")} |`);
    }
    lines.push("");
  }
  const failures = results.filter((r) => r.state === "failed");
  if (failures.length > 0) {
    lines.push("### Failures", "");
    for (const r of failures) lines.push(`- \`${r.id}\`: ${escapeCell(r.error ?? "unknown error")}`);
    lines.push("");
  }
  return lines.join("\n");
}

function main(): number {
  let args;
  try {
    args = parseArgs({
      options: {
        filter: { type: "string", short: "f", multiple: true },
        category: { type: "string", short: "c", multiple: true },
        job: { type: "string", short: "j", default: "short" },
        out: { type: "string", short: "o" },
        list: { type: "boolean", short: "l", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
      strict: true,
      allowPositionals: false,
    }).values;
  } catch (error) {
    console.error(`${errorMessage(error)}\n\n${USAGE}`);
    return 2;
  }
  if (args.help) {
    console.log(USAGE);
    return 0;
  }

  const jobName = args.job ?? "short";
  const job = JOBS[jobName];
  if (!job) {
    console.error(`Unknown job "${jobName}". Use one of: ${Object.keys(JOBS).join(", ")}`);
    return 2;
  }
  const knownCategories = new Set(Object.values(Categories).map((c) => c.toLowerCase()));
  const unknownCategory = (args.category ?? []).find((c) => !knownCategories.has(c.toLowerCase()));
  if (unknownCategory) {
    console.error(`Unknown category "${unknownCategory}". Use one of: ${Object.values(Categories).join(", ")}`);
    return 2;
  }

  const selection = select(args.filter ?? ["*"], args.category ?? []);
  if (selection.length === 0) {
    console.error("No benchmarks match the given --filter / --category.");
    return 1;
  }

  if (args.list) {
    for (const { suite, benchmarks } of selection) {
      const params = suite.paramName ? ` (${suite.paramName}: ${suite.paramValues.map((p) => p.label).join(", ")})` : "";
      console.log(`${suite.name}${params}`);
      for (const b of benchmarks) console.log(`  ${suite.name}.${b.name}  [${b.categories.join(", ")}]`);
    }
    return 0;
  }

  const env = environment(jobName);
  console.log(`cas-typescript-sdk ${env.sdkVersion} benchmarks | Node.js ${env.node} | ${env.platform} | ${env.cpu}`);
  console.log(`Job: ${jobName} (${job.description})\n`);

  const results: BenchmarkResult[] = [];
  for (const { suite, benchmarks } of selection) {
    for (const param of suite.paramValues) {
      console.log(`## ${suite.name}${param.label ? ` [${suite.paramName}=${param.label}]` : ""}`);
      let context: unknown;
      let setupError: unknown;
      try {
        context = suite.setup(param.value);
      } catch (error) {
        setupError = error ?? new Error("setup threw");
      }

      let tasks: Task[] = [];
      if (setupError === undefined) {
        const bench = new Bench({ ...job.options, name: suite.name });
        for (const b of benchmarks) {
          bench.add(b.name, () => {
            b.fn(context);
          });
        }
        tasks = bench.runSync();
      }
      const suiteResults = benchmarks.map((b) =>
        toResult(suite, b, param, tasks.find((t) => t.name === b.name), setupError),
      );
      results.push(...suiteResults);
      printTable(suiteResults);
    }
  }

  const outDir = args.out ? path.resolve(args.out) : DEFAULT_OUT_DIR;
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "results.json"), `${JSON.stringify({ environment: env, results }, null, 2)}\n`);
  fs.writeFileSync(path.join(outDir, "results.md"), markdownReport(env, results));
  console.log(`Results written to ${path.join(outDir, "results.json")} and results.md`);

  const failures = results.filter((r) => r.state === "failed");
  if (failures.length > 0) {
    console.error(`\n${failures.length} benchmark(s) failed:`);
    for (const r of failures) console.error(`  ✗ ${r.id}: ${r.error}`);
    return 1;
  }
  return 0;
}

process.exitCode = main();
