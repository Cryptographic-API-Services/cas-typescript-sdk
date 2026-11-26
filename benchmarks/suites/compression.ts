import { ZTSDWrapper } from "cas-typescript-sdk";
import { compressible, ONE_MIB } from "../payloads";
import { Categories, defineSuite } from "../registry";

const zstd = new ZTSDWrapper();

export const zstdBenchmarks = defineSuite({
  name: "ZstdBenchmarks",
  categories: [Categories.Compression],
  params: { name: "level", values: [1, 3, 19] },
  setup: (level: number) => {
    const data = compressible(ONE_MIB);
    return { data, level, compressed: zstd.compress(data, level) };
  },
  benchmarks: [
    { name: "Compress", fn: (c) => zstd.compress(c.data, c.level) },
    { name: "Decompress", fn: (c) => zstd.decompress(c.compressed) },
  ],
});
