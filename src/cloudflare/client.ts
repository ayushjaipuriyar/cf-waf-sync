import type { ResolvedConfig } from "../config";

export interface CFResponse<T> {
  success: boolean;
  result: T;
  errors: Array<{ code: number; message: string }>;
  messages: Array<{ code: number; message: string }>;
  result_info?: { total_pages?: number; cursors?: { after?: string | null } };
}

export async function cfFetch<T>(
  cfg: ResolvedConfig,
  path: string,
  init: RequestInit & { params?: Record<string, string | number | undefined> } = {}
): Promise<CFResponse<T>> {
  const url = new URL(`https://api.cloudflare.com/client/v4${path}`);
  if (init.params) {
    for (const [k, v] of Object.entries(init.params)) if (v !== undefined) url.searchParams.set(k, String(v));
  }
  const res = await fetch(url.toString(), {
    ...init,
    headers: {
      Authorization: `Bearer ${cfg.cfApiToken}`,
      "Content-Type": "application/json",
      ...(init.headers as any),
    },
  });
  const json = (await res.json()) as CFResponse<T>;
  if (!res.ok || !json.success) {
    const msg = json.errors?.map((e) => e.message).join("; ") || res.statusText;
    const err: any = new Error(`${init.method || "GET"} ${path} failed: ${msg}`);
    err.status = res.status;
    err.cfErrors = json.errors;
    err.response = { status: res.status, data: json };
    throw err;
  }
  return json;
}

export async function cfFetchRaw(
  path: string,
  token: string,
  init: RequestInit = {}
): Promise<Response> {
  const url = `https://api.cloudflare.com/client/v4${path}`;
  return fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(init.headers as any),
    },
  });
}
