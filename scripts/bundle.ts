#!/usr/bin/env tsx
// Bundles upstream sefinek/Cloudflare-WAF-Expressions assets into src/assets/bundled.ts
// Usage: npm run bundle
// Fetches: rules/expressions.md + rules/ip-blocklist.txt + my-lists/ip-blocklist.txt fallback

const EXPRESSIONS_URL = "https://raw.githubusercontent.com/sefinek/Cloudflare-WAF-Expressions/main/rules/expressions.md";
const IP_BLOCKLIST_URL = "https://raw.githubusercontent.com/sefinek/Cloudflare-WAF-Expressions/main/rules/ip-blocklist.txt";
const OUT = "src/assets/bundled.ts";

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch ${url} ${res.status} ${await res.text().catch(() => "")}`);
  return res.text();
}

async function main() {
  console.log(`Fetching ${EXPRESSIONS_URL} ...`);
  const expressions = await fetchText(EXPRESSIONS_URL);
  console.log(`Fetched expressions ${expressions.length} chars`);

  console.log(`Fetching ${IP_BLOCKLIST_URL} ...`);
  let ipBlocklist: string;
  try {
    ipBlocklist = await fetchText(IP_BLOCKLIST_URL);
  } catch (err: any) {
    console.warn(`ip-blocklist fetch failed: ${err.message}, using empty`);
    ipBlocklist = "# empty fallback\n";
  }
  console.log(`Fetched ip-blocklist ${ipBlocklist.split("\n").length} lines`);

  const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\${/g, "\\${");

  const out = `export const BUNDLED_EXPRESSIONS = \`${esc(expressions)}\`;\nexport const BUNDLED_IP_BLOCKLIST = \`${esc(ipBlocklist)}\`;\n`;

  const { writeFileSync } = await import("node:fs");
  writeFileSync(OUT, out);
  console.log(`Wrote ${OUT} (${out.length} chars)`);
  const versionMatch = expressions.match(/Last update:\s*([\d.]+)/i);
  if (versionMatch) console.log(`Upstream version: ${versionMatch[1]}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
