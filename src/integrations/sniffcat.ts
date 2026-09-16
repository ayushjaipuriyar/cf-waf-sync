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

export async function fetchSniffCatIPs(cfg: ResolvedConfig): Promise<string[]> {
  if (!cfg.sniffcatToken) return []
  try {
    const url = new URL("https://api.sniffcat.com/api/v1/blacklist")
    url.searchParams.set("type", "txt")
    url.searchParams.set("confidenceMin", String(cfg.sniffcatConfidenceMin))
    url.searchParams.set("limit", String(cfg.sniffcatLimit))
    const res = await fetchWithRetry(url.toString(), {
      headers: {
        "X-Secret-Token": cfg.sniffcatToken,
        "User-Agent": "cf-waf-sync/1.0",
      },
    })
    if (!res.ok)
      throw new Error(
        `SniffCat ${res.status} ${await res.text().catch(() => "")}`,
      )
    const text = await res.text()
    return text
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
  } catch (err: any) {
    console.warn(
      JSON.stringify({
        level: "warn",
        msg: "SniffCat fetch failed",
        error: err.message,
      }),
    )
    return []
  }
}
