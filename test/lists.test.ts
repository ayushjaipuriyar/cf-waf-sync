import { describe, it, expect } from "vitest";
import { resolveMaxListSize } from "../src/cloudflare/lists";

describe("resolveMaxListSize", () => {
  it("subtracts other lists from cap", () => {
    const all = [
      { id: "a", name: "x", kind: "ip", num_items: 1000 },
      { id: "b", name: "y", kind: "ip", num_items: 2000 },
      { id: "own", name: "sefinek_cf_waf", kind: "ip", num_items: 500 },
    ] as any;
    expect(resolveMaxListSize(all, "own", 10000)).toBe(7000);
  });

  it("ignores hostname/as n lists", () => {
    const all = [
      { id: "h", kind: "hostname", num_items: 5000 },
      { id: "a", kind: "asn", num_items: 3000 },
      { id: "own", kind: "ip", num_items: 0 },
    ] as any;
    expect(resolveMaxListSize(all, "own", 10000)).toBe(10000);
  });

  it("never negative", () => {
    const all = [{ id: "x", kind: "ip", num_items: 20000 }] as any;
    expect(resolveMaxListSize(all, null, 10000)).toBe(0);
  });
});
