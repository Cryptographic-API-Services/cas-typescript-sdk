/**
 * Category names for `--category`. A suite's categories apply to all of its
 * benchmarks; a benchmark can add more (e.g. KeyGeneration).
 */
export const Categories = {
  Hashing: "Hashing",
  Symmetric: "Symmetric",
  Asymmetric: "Asymmetric",
  PostQuantum: "PostQuantum",
  PasswordHashing: "PasswordHashing",
  Compression: "Compression",
  KeyGeneration: "KeyGeneration",
} as const;

export type Category = (typeof Categories)[keyof typeof Categories];

export interface BenchmarkDef<C> {
  name: string;
  categories?: Category[];
  /** One call of the operation being measured. Inputs come from the suite's setup. */
  fn: (context: C) => unknown;
}

export interface SuiteDef<P, C> {
  /** Suite name, e.g. "HasherBenchmarks". Benchmarks are named `<suite>.<benchmark>`. */
  name: string;
  categories: Category[];
  /**
   * Optional parameter: the suite runs once per value, with setup called again
   * for each value (like a BenchmarkDotNet [Params] property).
   */
  params?: { name: string; values: readonly P[]; format?: (value: P) => string };
  /**
   * Builds the inputs (keys, ciphertexts, signatures...) outside the timed code.
   * Only called when at least one of the suite's benchmarks is selected.
   */
  setup: (param: P) => C;
  benchmarks: BenchmarkDef<C>[];
}

/** A suite with its parameter and context types erased, so suites can share one list. */
export interface Suite {
  name: string;
  categories: Category[];
  paramName?: string;
  paramValues: { label?: string; value: unknown }[];
  setup: (param: unknown) => unknown;
  benchmarks: { name: string; categories: Category[]; fn: (context: unknown) => unknown }[];
}

export function defineSuite<C, P = undefined>(def: SuiteDef<P, C>): Suite {
  const params = def.params;
  return {
    name: def.name,
    categories: def.categories,
    paramName: params?.name,
    paramValues: params
      ? params.values.map((value) => ({ label: params.format ? params.format(value) : String(value), value }))
      : [{ value: undefined }],
    setup: (param) => def.setup(param as P),
    benchmarks: def.benchmarks.map((b) => ({
      name: b.name,
      categories: [...def.categories, ...(b.categories ?? [])],
      fn: (context) => b.fn(context as C),
    })),
  };
}

/**
 * Throws unless a verify-style call returned true, so a benchmark can't end up
 * timing the rejection path (e.g. after a change to argument order).
 */
export function expectTrue(value: boolean, what: string): boolean {
  if (value !== true) {
    throw new Error(`${what} returned ${String(value)}, expected true`);
  }
  return value;
}
