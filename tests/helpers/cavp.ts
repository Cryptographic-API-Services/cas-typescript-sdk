// Parser for the NIST CAVP response format (.rsp / .txt): # comments,
// [Section = value] headers, and Count/COUNT records separated by blank lines.
// A record that contains a bare FAIL line (decrypt / unwrap rejection) has fail: true.

export type CavpRecord = {
  fail: boolean;
  fields: Record<string, string>;
  section: Record<string, string>;
};

export function hexToBytes(hex: string): number[] {
  if (!hex) {
    return [];
  }
  return Array.from(Buffer.from(hex, "hex"));
}

export function bytesToHex(bytes: ArrayLike<number>): string {
  return Buffer.from(bytes).toString("hex");
}

export function parseCavp(contents: string): CavpRecord[] {
  const records: CavpRecord[] = [];
  let section: Record<string, string> = {};
  let fields: Record<string, string> | null = null;
  let fail = false;

  const flush = () => {
    if (fields && Object.keys(fields).length > 0) {
      records.push({ fail, fields, section });
    }
    fields = null;
    fail = false;
  };

  for (const line of contents.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      flush();
      continue;
    }
    if (trimmed.startsWith("#")) {
      continue;
    }

    const header = trimmed.match(/^\[(.+)\]$/);
    if (header) {
      flush();
      const [name, value] = header[1].split("=").map((part) => part.trim());
      if (value !== undefined) {
        section = { ...section, [name]: value };
      }
      continue;
    }

    if (/^count\s*=/i.test(trimmed)) {
      flush();
      fields = {};
      continue;
    }

    if (trimmed === "FAIL") {
      fail = true;
      continue;
    }

    const assignment = trimmed.match(/^([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)$/);
    if (!assignment) {
      continue;
    }
    fields ??= {};
    fields[assignment[1]] = assignment[2].trim();
  }
  flush();
  return records;
}
