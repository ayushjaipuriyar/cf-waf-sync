import { describe, it, expect } from "vitest";
import { resolveConfig } from "../src/config";

describe("resolveConfig", () => {
  it("validates CF_ACCOUNT_ID hex", () => {
    expect(() => resolveConfig({ CF_API_TOKEN: "tok", CF_ACCOUNT_ID: "bad" } as any)).toThrow(/CF_ACCOUNT_ID/);
    expect(() => resolveConfig({ CF_API_TOKEN: "tok", CF_ACCOUNT_ID: "a".repeat(32) } as any)).not.toThrow();
  });

  it("bounds confidence and limits", () => {
    expect(() => resolveConfig({ CF_API_TOKEN: "tok", CF_ACCOUNT_ID: "a".repeat(32), SNIFFCAT_CONFIDENCE_MIN: "200" } as any)).toThrow();
    expect(() => resolveConfig({ CF_API_TOKEN: "tok", CF_ACCOUNT_ID: "a".repeat(32), ABUSEIPDB_LIMIT: "0" } as any)).toThrow();
  });

  it("validates zoneIds must be hex", () => {
    expect(() => resolveConfig({ CF_API_TOKEN: "tok", CF_ACCOUNT_ID: "a".repeat(32), CF_ZONE_IDS: "not-hex" } as any)).toThrow();
  });

  it("parses csv and defaults", () => {
    const cfg = resolveConfig({ CF_API_TOKEN: "tok", CF_ACCOUNT_ID: "a".repeat(32), CF_ZONE_IDS: "a".repeat(32) + "," + "b".repeat(32), ALLOWLIST: 'http.host eq "x.com"' } as any);
    expect(cfg.zoneIds).toHaveLength(2);
    expect(cfg.allowlist).toContain("x.com");
    expect(cfg.listName).toBe("sefinek_cf_waf");
  });

  it("empty listName disables list", () => {
    const cfg = resolveConfig({ CF_API_TOKEN: "tok", CF_ACCOUNT_ID: "a".repeat(32), CF_IP_BLOCKLIST_NAME: "" } as any);
    expect(cfg.listName).toBe("");
  });
});
