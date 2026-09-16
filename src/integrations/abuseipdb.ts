import type { ResolvedConfig } from "../config";

export async function fetchAbuseIPDBIPs(cfg: ResolvedConfig): Promise<string[]> {
  if (!cfg.abuseIpdbKey) return [];
  try {
    const url = new URL("https://api.abuseipdb.com/api/v2/blacklist");
    url.searchParams.set("confidenceMinimum", String(cfg.abuseIpdbConfidenceMin));
    url.searchParams.set("limit", String(cfg.abuseIpdbLimit));
    const res = await fetch(url.toString(), {
      headers: { Key: cfg.abuseIpdbKey, Accept: "application/json" },
    });
    if (!res.ok) throw new Error(`AbuseIPDB ${res.status} ${await res.text()}`);
    const data: any = await res.json();
    return (data.data || []).map((e: any) => e.ipAddress).filter(Boolean);
  } catch (err: any) {
    console.warn(`AbuseIPDB fetch failed: ${err.message}`);
    return [];
  }
}
