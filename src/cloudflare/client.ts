import type { ResolvedConfig } from "../config"

export interface CFResponse<T> {
  success: boolean
  result: T
  errors: Array<{ code: number; message: string }>
  messages: Array<{ code: number; message: string }>
  result_info?: { total_pages?: number; cursors?: { after?: string | null } }
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms))
}

function jitter(ms: number) {
  return ms * (0.5 + Math.random())
}

function isRetryable(status: number) {
  return (
    status === 429 ||
    status === 500 ||
    status === 502 ||
    status === 503 ||
    status === 504
  )
}

function parseRetryAfter(res: Response): number | null {
  const h = res.headers.get("Retry-After")
  if (!h) return null
  const secs = parseInt(h, 10)
  if (!Number.isNaN(secs)) return secs * 1000
  const date = Date.parse(h)
  if (!Number.isNaN(date)) return Math.max(0, date - Date.now())
  return null
}

export async function cfFetch<T>(
  cfg: ResolvedConfig,
  path: string,
  init: RequestInit & {
    params?: Record<string, string | number | undefined>
  } = {},
  opts: { retries?: number; timeoutMs?: number } = {},
): Promise<CFResponse<T>> {
  const retries = opts.retries ?? 3
  const timeoutMs = opts.timeoutMs ?? 15000
  const url = new URL(`https://api.cloudflare.com/client/v4${path}`)
  if (init.params) {
    for (const [k, v] of Object.entries(init.params))
      if (v !== undefined) url.searchParams.set(k, String(v))
  }

  let lastErr: any
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController()
    const t = setTimeout(() => controller.abort(), timeoutMs)
    try {
      const res = await fetch(url.toString(), {
        ...init,
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${cfg.cfApiToken}`,
          "Content-Type": "application/json",
          ...(init.headers as any),
        },
      })
      clearTimeout(t)

      // handle 429 / 5xx with retry
      if (isRetryable(res.status) && attempt < retries) {
        const retryMs = parseRetryAfter(res) ?? jitter(1000 * 2 ** attempt)
        // eslint-disable-next-line no-console
        console.warn(
          `cfFetch ${path} ${res.status} retry ${attempt + 1}/${retries} after ${Math.round(retryMs)}ms`,
        )
        await sleep(retryMs)
        continue
      }

      const json = (await res.json()) as CFResponse<T>
      if (!res.ok || !json.success) {
        const msg =
          json.errors?.map((e) => e.message).join("; ") || res.statusText
        const err: any = new Error(
          `${init.method || "GET"} ${path} failed: ${msg}`,
        )
        err.status = res.status
        err.cfErrors = json.errors
        err.response = { status: res.status, data: json }
        // retry on 5xx errors surfaced as json.success=false
        if (isRetryable(res.status) && attempt < retries) {
          lastErr = err
          const retryMs = jitter(1000 * 2 ** attempt)
          await sleep(retryMs)
          continue
        }
        throw err
      }
      return json
    } catch (err: any) {
      clearTimeout(t)
      lastErr = err
      const isAbort = err.name === "AbortError"
      const isNetwork = !err.status
      if (
        (isAbort || isNetwork || (err.status && isRetryable(err.status))) &&
        attempt < retries
      ) {
        const retryMs = jitter(1000 * 2 ** attempt)
        console.warn(
          `cfFetch ${path} ${err.message} retry ${attempt + 1}/${retries} after ${Math.round(retryMs)}ms`,
        )
        await sleep(retryMs)
        continue
      }
      throw err
    }
  }
  throw lastErr
}

export async function cfFetchRaw(
  path: string,
  token: string,
  init: RequestInit = {},
): Promise<Response> {
  const url = `https://api.cloudflare.com/client/v4${path}`
  return fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(init.headers as any),
    },
  })
}
