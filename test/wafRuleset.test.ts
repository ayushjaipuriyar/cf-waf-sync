import { describe, it, expect } from "vitest";
import { buildZoneExpression, getRuleCap, isManagedDescription, passthroughRule, MAX_EXPRESSION_LENGTH } from "../src/parsers/wafRuleset";

describe("wafRuleset", () => {
  it("getRuleCap respects plan", () => {
    expect(getRuleCap({ plan: { legacy_id: "free" } } as any)).toBe(5);
    expect(getRuleCap({ plan: { legacy_id: "pro" } } as any)).toBe(20);
    expect(getRuleCap({} as any)).toBe(5);
  });

  it("isManagedDescription matches Part", () => {
    expect(isManagedDescription("🔥 Part 1 - Suspicious")).toBe(true);
    expect(isManagedDescription("my custom rule")).toBe(false);
  });

  it("buildZoneExpression filters by zone", () => {
    const entries = [
      { expression: 'http.host eq "a.com"', zone: null, exclude: false },
      { expression: 'http.host eq "b.com"', zone: "b.com", exclude: false },
      { expression: 'http.host eq "c.com"', zone: "c.com", exclude: true },
    ];
    // a.com matches always-true + excluded-from-c.com (so c included for a)
    expect(buildZoneExpression(entries, { name: "a.com" } as any)).toBe('(http.host eq "a.com") or (http.host eq "c.com")');
    expect(buildZoneExpression(entries, { name: "b.com" } as any)).toBe('(http.host eq "a.com") or (http.host eq "b.com") or (http.host eq "c.com")');
    // c.com is excluded from c, so only a remains (b is zone-specific to b)
    expect(buildZoneExpression(entries, { name: "c.com" } as any)).toBe('http.host eq "a.com"');
  });

  it("passthroughRule preserves id and fields", () => {
    const r = passthroughRule({ id: "123", action: "block", expression: "true", description: "x", enabled: true, action_parameters: { foo: 1 } });
    expect(r.id).toBe("123");
    expect(r.action_parameters).toEqual({ foo: 1 });
  });

  it("MAX_EXPRESSION_LENGTH is 4096", () => {
    expect(MAX_EXPRESSION_LENGTH).toBe(4096);
  });
});
