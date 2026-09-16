import type { ResolvedConfig } from "../config"

async function fetchWithRetry(
  url: string,
  init: RequestInit,
  retries = 2,
  timeoutMs = 10000,
): Promise<Response> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const ctrl = new AbortController()
    const t = setTimeout(() => ctrl.abort(), timeoutMs)
    try {
      const res = await fetch(url, { ...init, signal: ctrl.signal })
      clearTimeout(t)
      if ((res.status === 429 || res.status >= 500) && attempt < retries) {
        const retryMs = 500 * 2 ** attempt * (0.5 + Math.random())
        await new Promise((r) => setTimeout(r, retryMs))
        continue
      }
      return res
    } catch (err: any) {
      clearTimeout(t)
      if (attempt < retries) {
        const retryMs = 500 * 2 ** attempt * (0.5 + Math.random())
        await new Promise((r) => setTimeout(r, retryMs))
        continue
      }
      throw err
    }
  }
  throw new Error("fetchWithRetry exhausted")
}

export async function fetchAbuseIPDBIPs(
  cfg: ResolvedConfig,
): Promise<string[]> {
  if (!cfg.abuseIpdbKey) return []
  try {
    const url = new URL("https://api.abuseipdb.com/api/v2/blacklist")
    url.searchParams.set(
      "confidenceMinimum",
      String(cfg.abuseIpdbConfidenceMin),
    )
    url.searchParams.set("limit", String(cfg.abuseIpdbLimit))
    const res = await fetchWithRetry(url.toString(), {
      headers: {
        Key: cfg.abuseIpdbKey,
        Accept: "application/json",
        "User-Agent": "cf-waf-sync/1.0",
      },
    })
    if (!res.ok) throw new Error(`AbuseIPDB ${res.status} ${await res.text()}`)
    const data: any = await res.json()
    return (data.data || []).map((e: any) => e.ipAddress).filter(Boolean)
  } catch (err: any) {
    console.warn(
      JSON.stringify({
        level: "warn",
        msg: "AbuseIPDB fetch failed",
        error: err.message,
      }),
    )
    return []
  }
}
