import { describe, it, expect } from "vitest";
import { parseExpressionsText } from "../src/parsers/expressions";
import type { ResolvedConfig } from "../src/config";

function cfg(over: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    cfApiToken: "test",
    cfAccountId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    listName: "sefinek_cf_waf",
    phpSupport: false,
    wordpressSupport: false,
    sniffcatConfidenceMin: 80,
    sniffcatLimit: 2000,
    abuseIpdbConfidenceMin: 75,
    abuseIpdbLimit: 8000,
    excludedZones: [],
    zoneIds: [],
    zoneNames: [],
    allowlist: "",
    ...over,
  };
}

const SAMPLE = `## 🔥 Part 1 - Suspicious paths
> **Action:** Block
\`\`\`
(http.request.uri.path contains "evil") or
(http.request.uri.path wildcard "*.php*" and not cf.client.bot)
\`\`\`

## 🤖 Part 3 - Unwanted bots
> **Action:** Block
\`\`\`
(http.user_agent wildcard "*scrapy*")
\`\`\`

<div>Last update: 10.09.2026</div>
`;

describe("parseExpressionsText", () => {
  it("parses basic blocks and extracts version", () => {
    const res = parseExpressionsText(SAMPLE, cfg());
    expect(res).not.toBeNull();
    expect(res![1].name).toContain("Part 1");
    expect(res![1].action).toBe("block");
    expect(res!._meta.version).toBe("10.09.2026");
    expect(res!._meta.blocks).toBe(2);
  });

  it("replaces list placeholder", () => {
    const withList = SAMPLE + `\n## 🦕 Part 4 - IP\n> **Action:** Block\n\`\`\`\n(ip.src in $foo)\n\`\`\`\n`;
    const res = parseExpressionsText(withList, cfg({ listName: "my_list" }));
    expect(res![3].expressions).toContain("ip.src in $my_list");
  });

  it("strips list clause when listName empty (cfut)", () => {
    const withList = `## Part 4\n> **Action:** Block\n\`\`\`\n(http.user_agent wildcard "*a*") or (ip.src in $sefinek_cf_waf)\n\`\`\`\n`;
    const res = parseExpressionsText(withList, cfg({ listName: "" }));
    expect(res![1].expressions).not.toContain("ip.src in $");
    expect(res![1].expressions).not.toContain("or  or");
  });

  it("drops empty block after PHP stripping instead of (true) block-all", () => {
    const phpOnly = `## 🔥 Part 1\n> **Action:** Block\n\`\`\`\n(http.request.uri.path wildcard "*.php*" and not cf.client.bot)\n\`\`\`\n`;
    const res = parseExpressionsText(phpOnly, cfg({ phpSupport: true }));
    // should be dropped, not emitted as "(true)"
    expect(res![1]).toBeUndefined();
    expect(res!._meta.blocks).toBe(1); // raw blocks 1 but dropped
  });

  it("keeps block when PHP disabled", () => {
    const phpOnly = `## 🔥 Part 1\n> **Action:** Block\n\`\`\`\n(http.request.uri.path wildcard "*.php*" and not cf.client.bot)\n\`\`\`\n`;
    const res = parseExpressionsText(phpOnly, cfg({ phpSupport: false }));
    expect(res![1].expressions).toContain("*.php*");
  });

  it("drops WP block after wordpress filter", () => {
    const wp = `## Part 5\n> **Action:** Managed Challenge\n\`\`\`\n(http.request.uri.path wildcard "*/wp-content*" and not cf.client.bot)\n\`\`\`\n`;
    const res = parseExpressionsText(wp, cfg({ wordpressSupport: true, phpSupport: true }));
    expect(res![1]).toBeUndefined();
  });
});
