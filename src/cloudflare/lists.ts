import type { ResolvedConfig } from "../config";
import { cfFetch } from "./client";

export interface CFList {
  id: string;
  name: string;
  kind: string; // ip
  description?: string;
  num_items?: number;
}

export interface CFListItem {
  id: string;
  ip: string;
}

const DEFAULT_ITEM_CAP = 10000;
const ENTERPRISE_ITEM_CAP = 500000;

export async function getAllLists(cfg: ResolvedConfig): Promise<CFList[]> {
  const data = await cfFetch<CFList[]>(cfg, `/accounts/${cfg.cfAccountId}/rules/lists`);
  return data.result;
}

export async function isEnterpriseAccount(cfg: ResolvedConfig): Promise<boolean> {
  try {
    const data = await cfFetch<any[]>(cfg, `/accounts/${cfg.cfAccountId}/subscriptions`);
    return (data.result || []).some((sub: any) => sub.rate_plan?.id === "enterprise" || sub.rate_plan?.is_contract === true);
  } catch {
    return false;
  }
}

export function resolveMaxListSize(allLists: CFList[], ownListId: string | null, itemCap: number): number {
  const usedByOthers = allLists
    .filter((l) => l.id !== ownListId && l.kind !== "hostname" && l.kind !== "asn")
    .reduce((sum, l) => sum + (l.num_items || 0), 0);
  return Math.max(0, itemCap - usedByOthers);
}

export async function getOrCreateList(cfg: ResolvedConfig): Promise<{ listId: string; allLists: CFList[]; itemCap: number }> {
  if (!cfg.listName) throw new Error("listName empty");
  const [allLists, enterprise] = await Promise.all([getAllLists(cfg), isEnterpriseAccount(cfg)]);
  const itemCap = enterprise ? ENTERPRISE_ITEM_CAP : DEFAULT_ITEM_CAP;

  const version = "1.0.0";
  const listSources = ["ip-blocklist.txt", ...(cfg.sniffcatToken ? ["SniffCat"] : []), ...(cfg.abuseIpdbKey ? ["AbuseIPDB"] : [])];
  const description = `Managed by cf-waf-sync v${version} (port of sefinek/Cloudflare-WAF-Expressions). Sources: ${listSources.join(", ")}. Do not edit manually.`;

  let list = allLists.find((l) => l.name === cfg.listName);
  if (list) {
    if (list.description !== description) {
      await cfFetch(cfg, `/accounts/${cfg.cfAccountId}/rules/lists/${list.id}`, {
        method: "PUT",
        body: JSON.stringify({ description }),
      });
    }
    return { listId: list.id, allLists, itemCap };
  }

  // create
  const existingIPLists = allLists.filter((l) => l.kind === "ip");
  let created: any;
  try {
    const res = await cfFetch<any>(cfg, `/accounts/${cfg.cfAccountId}/rules/lists`, {
      method: "POST",
      body: JSON.stringify({ name: cfg.listName, kind: "ip", description }),
    });
    created = res.result;
  } catch (err: any) {
    const code = err.cfErrors?.[0]?.code;
    if (code === 10019) {
      const url = `https://dash.cloudflare.com/${cfg.cfAccountId}/configurations/lists`;
      const hint = existingIPLists.length
        ? `Set CF_IP_BLOCKLIST_NAME=${existingIPLists[0].name} to reuse existing list or delete at ${url}`
        : `Delete a list at ${url}`;
      throw new Error(`List limit reached. ${hint}`);
    }
    throw err;
  }
  return { listId: created.id, allLists, itemCap };
}

async function waitForBulk(cfg: ResolvedConfig, operationId: string) {
  for (let attempt = 0; attempt < 30; attempt++) {
    const data = await cfFetch<{ status: string; error?: string }>(cfg, `/accounts/${cfg.cfAccountId}/rules/lists/bulk_operations/${operationId}`);
    const status = (data.result as any).status;
    const error = (data.result as any).error;
    if (status === "completed") return;
    if (status === "failed") throw new Error(`Bulk operation failed: ${error || "unknown"}`);
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`Bulk operation ${operationId} did not complete in 60s`);
}

export async function getAllListItems(cfg: ResolvedConfig, listId: string): Promise<CFListItem[]> {
  const items: CFListItem[] = [];
  let cursor: string | null | undefined = undefined;
  do {
    const params: Record<string, string | number | undefined> = { per_page: 500 };
    if (cursor) params.cursor = cursor;
    const data = await cfFetch<CFListItem[]>(cfg, `/accounts/${cfg.cfAccountId}/rules/lists/${listId}/items`, { params });
    items.push(...data.result);
    cursor = (data.result_info as any)?.cursors?.after ?? null;
    if (!cursor) break;
  } while (cursor);
  return items;
}

export async function syncListItems(cfg: ResolvedConfig, listId: string, desiredIPs: Set<string>) {
  const currentItems = await getAllListItems(cfg, listId);
  const currentMap = new Map(currentItems.map((i) => [i.ip, i.id]));
  const toAdd = [...desiredIPs].filter((ip) => !currentMap.has(ip));
  const toDelete = currentItems.filter((it) => !desiredIPs.has(it.ip)).map((it) => ({ id: it.id }));

  if (toDelete.length) {
    const data = await cfFetch<{ operation_id: string }>(cfg, `/accounts/${cfg.cfAccountId}/rules/lists/${listId}/items`, {
      method: "DELETE",
      body: JSON.stringify({ items: toDelete }),
    });
    await waitForBulk(cfg, (data.result as any).operation_id);
  }
  if (toAdd.length) {
    // Cloudflare bulk create supports max 1000 per request chunk
    for (let i = 0; i < toAdd.length; i += 1000) {
      const chunk = toAdd.slice(i, i + 1000).map((ip) => ({ ip }));
      const data = await cfFetch<{ operation_id: string }>(cfg, `/accounts/${cfg.cfAccountId}/rules/lists/${listId}/items`, {
        method: "POST",
        body: JSON.stringify(chunk),
      });
      await waitForBulk(cfg, (data.result as any).operation_id);
    }
  }
  return { toAdd: toAdd.length, toDelete: toDelete.length, current: currentItems.length };
}
