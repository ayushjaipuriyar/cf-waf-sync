import type { ResolvedConfig } from "../config";

export async function fetchSniffCatIPs(cfg: ResolvedConfig): Promise<string[]> {
  if (!cfg.sniffcatToken) return [];
  try {
    const url = new URL("https://api.sniffcat.com/api/v1/blacklist");
    url.searchParams.set("type", "txt");
    url.searchParams.set("confidenceMin", String(cfg.sniffcatConfidenceMin));
    url.searchParams.set("limit", String(cfg.sniffcatLimit));
    const res = await fetch(url.toString(), {
      headers: { "X-Secret-Token": cfg.sniffcatToken, "User-Agent": "cf-waf-sync/1.0" },
    });
    if (!res.ok) throw new Error(`SniffCat ${res.status}`);
    const text = await res.text();
    return text
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
  } catch (err: any) {
    console.warn(`SniffCat fetch failed: ${err.message}`);
    return [];
  }
}
