import { describe, expect, test } from "vitest";
import { z } from "zod";

describe("CVE-2025-54404: oversized constrained array validation", () => {
  test("fails fast on an oversized array instead of accumulating one issue per element", () => {
    const schema = z.array(z.number()).max(10);
    // 20,000 elements, half invalid: a vulnerable zod collects one issue per
    // failing element (10,000 issues); zod >= 4.6.6 rejects via the size cap
    // with a single issue.
    const oversized = Array.from(
      { length: 20000 },
      (_, i) => (i % 2 === 0 ? i : "not-a-number"),
    );

    const result = schema.safeParse(oversized);

    if (result.success) {
      throw new Error("expected validation of an oversized array to fail");
    }
    expect(result.error.issues.length).toBeLessThanOrEqual(10);
  });
});
