import { resolveConfig, validateConfig, type Env } from "./config";
/// <reference types="@cloudflare/workers-types" />
import { loadExpressions } from "./parsers/expressions";
import { parseZoneScopedListText } from "./parsers/zoneLists";
import {
  BLOCKLIST_DESCRIPTION,
  MAX_EXPRESSION_LENGTH,
  buildZoneExpression,
  getRuleCap,
  isManagedDescription,
  isPartDescription,
  passthroughRule,
} from "./parsers/wafRuleset";
import { BUNDLED_EXPRESSIONS, BUNDLED_IP_BLOCKLIST } from "./assets/bundled";
import { getZones } from "./cloudflare/zones";
import { getEntrypoint, normalize, putEntrypoint } from "./cloudflare/rulesets";
import { getAllLists, getAllListItems, getOrCreateList, isEnterpriseAccount, resolveMaxListSize, syncListItems } from "./cloudflare/lists";
import { fetchSniffCatIPs } from "./integrations/sniffcat";
import { fetchAbuseIPDBIPs } from "./integrations/abuseipdb";

export interface SyncResult {
  zones: Array<{ name: string; status: string; details: string }>;
  ipList?: { added: number; removed: number; total: number };
  warnings: string[];
}

function parseIPList(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
}

async function buildDesiredIPs(bundled: string, cfg: ReturnType<typeof resolveConfig>): Promise<Set<string>> {
  const builtin = parseIPList(bundled);
  const [sniffcat, abuse] = await Promise.all([fetchSniffCatIPs(cfg), fetchAbuseIPDBIPs(cfg)]);

  // need budget calculation requires list info; we do that in syncIpListWithBudget
  // For now just merge priority + abuse with deduplication
  // Actual truncation happens after we know maxListSize
  // Return raw sets via separate function
  return new Set([...builtin, ...sniffcat, ...abuse]);
}

async function syncIPList(cfg: ReturnType<typeof resolveConfig>): Promise<{ added: number; removed: number; total: number } | null> {
  if (!cfg.listName) {
    console.log("CF_IP_BLOCKLIST_NAME empty — skipping IP list sync");
    return null;
  }
  if (!cfg.cfAccountId) {
    console.log("CF_ACCOUNT_ID missing — skipping IP list sync");
    return null;
  }

  console.log(`Syncing IP list '${cfg.listName}'...`);
  const builtinIPs = parseIPList(BUNDLED_IP_BLOCKLIST);
  const [sniffcatIPs, abuseIPDBIPs] = await Promise.all([fetchSniffCatIPs(cfg), fetchAbuseIPDBIPs(cfg)]);

  const { listId, allLists, itemCap } = await getOrCreateList(cfg);
  const maxListSize = resolveMaxListSize(allLists, listId, itemCap);

  // priority: builtin + sniffcat (kept fully), abuse trimmed
  const priorityIPs = [...new Set([...builtinIPs, ...sniffcatIPs])];
  const prioritySet = new Set(priorityIPs);
  const newAbuse = abuseIPDBIPs.filter((ip) => !prioritySet.has(ip));
  const budget = Math.max(0, maxListSize - priorityIPs.length);
  const truncatedCount = Math.max(0, newAbuse.length - budget);
  const usedAbuse = truncatedCount > 0 ? newAbuse.slice(0, budget) : newAbuse;
  const merged = [...new Set([...priorityIPs, ...usedAbuse])].sort();

  if (truncatedCount > 0) {
    console.warn(
      `List cap exceeded: ${priorityIPs.length + newAbuse.length} unique IPs but only ${maxListSize} available — dropped ${truncatedCount} lowest-confidence AbuseIPDB IPs. Lower ABUSEIPDB_LIMIT/CONFIDENCE.`
    );
  }

  console.log(`Desired list: ${merged.length} unique IPs (${builtinIPs.length} builtin + ${sniffcatIPs.length} SniffCat + ${abuseIPDBIPs.length} AbuseIPDB) — budget ${maxListSize}`);

  const desiredSet = new Set(merged);
  const { toAdd, toDelete } = await syncListItems(cfg, listId, desiredSet);
  console.log(`IP list sync done: +${toAdd} / -${toDelete}`);
  return { added: toAdd, removed: toDelete, total: merged.length };
}

function pickBlocklistHostIndex(expressions: any): number | null {
  let best: number | null = null;
  let bestLen = Infinity;
  for (const [k, block] of Object.entries(expressions as Record<string, { action: string; length: number }>)) {
    const idx = parseInt(k);
    if (isNaN(idx) || (block as any).action !== "block") continue;
    if ((block as any).length < bestLen) {
      bestLen = (block as any).length;
      best = idx;
    }
  }
  return best;
}

export async function runSync(env: Env, dryRun = false, triggerCron?: string): Promise<SyncResult> {
  const start = Date.now();
  const cfg = resolveConfig(env);
  const warnings = validateConfig(cfg);
  for (const w of warnings) console.warn(w);

  const expressions = await loadExpressions(cfg, BUNDLED_EXPRESSIONS);
  if (!expressions || !Object.keys(expressions).filter((k) => k !== "_meta").length) throw new Error("No expressions found");

  const blocklistHostIndex = pickBlocklistHostIndex(expressions);

  // allowlist for CDN public hosts — default exempts media-cdn1.seabuddy.co, override via ALLOWLIST var
  const allowlistEntries = parseZoneScopedListText((cfg as any).allowlist || "");
  const blocklistEntries: ReturnType<typeof parseZoneScopedListText> = [];

  let ipResult: { added: number; removed: number; total: number } | null = null;
  if (!dryRun) {
    try {
      ipResult = await syncIPList(cfg);
    } catch (err: any) {
      const msg = err.cfErrors?.[0]?.message || err.message;
      // Zone-scoped cfut tokens can't do Account lists (needs cfat) — don't fail whole sync, just warn and continue WAF
      if (msg?.includes("Authentication error") || err.status === 403) {
        console.warn(`IP list sync skipped (token lacks Account Filter Lists:Edit — use cfat_... or set CF_IP_BLOCKLIST_NAME="" to silence): ${msg}`);
        ipResult = null;
      } else {
        throw err;
      }
    }
  } else {
    console.log("[dryRun] skipping IP list sync");
  }

  const zones = await getZones(cfg);
  const filtered = cfg.excludedZones.length ? zones.filter((z) => !cfg.excludedZones.includes(z.name)) : zones;
  console.log(`Found ${zones.length} zones, ${filtered.length} active after excluded filter`);

  const results: SyncResult["zones"] = [];

  for (const zone of filtered) {
    const allowlistExpr = buildZoneExpression(allowlistEntries as any, zone);
    const wrap = (expr: string) => (allowlistExpr ? `not (${allowlistExpr}) and (${expr})` : expr);

    // build blocklist expression (user blocklist.txt) — currently empty
    const blocklistExpr = buildZoneExpression(blocklistEntries as any, zone);

    let current: any[] = [];
    let userRules: any[] = [];
    let existingManaged: any[] = [];
    try {
      const entrypoint = await getEntrypoint(cfg, zone.id);
      current = entrypoint?.rules ?? [];
      userRules = current.filter((r) => !isManagedDescription(r.description || ""));
      existingManaged = current.filter((r) => isManagedDescription(r.description || ""));

      const partRules: any[] = [];
      for (const [idxStr, block] of Object.entries(expressions as any)) {
        if (idxStr === "_meta") continue;
        const idx = parseInt(idxStr);
        if (isNaN(idx)) continue;
        const { name, action, expressions: part } = block as any;
        const expression = wrap(part as string);
        if (expression.length > MAX_EXPRESSION_LENGTH) {
          throw new Error(`"${name}" for ${zone.name} is ${expression.length} chars, exceeds ${MAX_EXPRESSION_LENGTH}. Trim expressions.md`);
        }
        const match = existingManaged.find((r) => isPartDescription(r.description, idx));
        partRules.push({
          ...(match?.id ? { id: match.id } : {}),
          action,
          expression,
          description: name,
          enabled: true,
        });
      }

      let blocklistStatus = "None";
      if (blocklistExpr) {
        const ruleCap = getRuleCap(zone);
        const hasSpare = partRules.length + userRules.length < ruleCap;
        if (hasSpare) {
          const expr = wrap(blocklistExpr);
          if (expr.length > MAX_EXPRESSION_LENGTH) {
            blocklistStatus = `Skipped (${expr.length}/${MAX_EXPRESSION_LENGTH})`;
          } else {
            const match = existingManaged.find((r) => r.description === BLOCKLIST_DESCRIPTION);
            partRules.push({
              ...(match?.id ? { id: match.id } : {}),
              action: "block",
              expression: expr,
              description: BLOCKLIST_DESCRIPTION,
              enabled: true,
            });
            blocklistStatus = `own rule (${expr.length})`;
          }
        } else {
          const host = blocklistHostIndex !== null ? partRules.find((r) => isPartDescription(r.description, blocklistHostIndex)) : null;
          if (!host) {
            blocklistStatus = "Skipped (no block host)";
          } else {
            const rawPart = (expressions as any)[blocklistHostIndex!].expressions;
            const merged = wrap(`${rawPart} or (${blocklistExpr})`);
            if (merged.length > MAX_EXPRESSION_LENGTH) {
              blocklistStatus = `Skipped merged ${merged.length}/${MAX_EXPRESSION_LENGTH}`;
            } else {
              host.expression = merged;
              blocklistStatus = `merged into ${host.description}`;
            }
          }
        }
      }

      const desired = [...userRules.map(passthroughRule), ...partRules];

      if (normalize(current) === normalize(desired)) {
        results.push({ name: zone.name, status: "Up to date", details: "-" });
        console.log(`${zone.name}: Up to date`);
        continue;
      }

      if (dryRun) {
        results.push({ name: zone.name, status: "Would update", details: `${partRules.length} managed, ${userRules.length} preserved, blocklist: ${blocklistStatus}` });
        console.log(`[dryRun] ${zone.name}: would update (${partRules.length} managed)`);
        continue;
      }

      await putEntrypoint(cfg, zone.id, desired);
      results.push({ name: zone.name, status: "Updated", details: `${partRules.length} managed, ${userRules.length} preserved` });
      console.log(`${zone.name}: Updated`);

      if (cfg.discordWebhookUrl) {
        // fire-and-forget
        try {
          await fetch(cfg.discordWebhookUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content: `✅ WAF updated: ${zone.name}` }),
          });
        } catch {}
      }
    } catch (err: any) {
      const msg = err.cfErrors?.map((e: any) => e.message).join("; ") || err.message;
      // If WAF references unknown list (cfut without Account lists perms + CF_IP_BLOCKLIST_NAME still set), retry without list clause
      if (msg.includes("is unknown") && msg.includes("list") && cfg.listName) {
        console.warn(`${zone.name}: list ${cfg.listName} unknown with this token (needs cfat_...), retrying WAF without IP list clause`);
        try {
          const strippedCfg = { ...cfg, listName: "" } as typeof cfg;
          const strippedExpr = await loadExpressions(strippedCfg, BUNDLED_EXPRESSIONS);
          if (!strippedExpr) throw err;
          // rebuild partRules without list reference
          const retryPartRules: any[] = [];
          for (const [idxStr, block] of Object.entries(strippedExpr as any)) {
            if (idxStr === "_meta") continue;
            const idx = parseInt(idxStr);
            if (isNaN(idx)) continue;
            const { name, action, expressions: part } = block as any;
            const expression = wrap(part as string);
            const match = existingManaged.find((r: any) => isPartDescription(r.description, idx));
            retryPartRules.push({ ...(match?.id ? { id: match.id } : {}), action, expression, description: name, enabled: true });
          }
          const retryDesired = [...userRules.map(passthroughRule), ...retryPartRules];
          if (normalize(current) === normalize(retryDesired)) {
            results.push({ name: zone.name, status: "Up to date (without IP list)", details: "list unavailable with cfut" });
            continue;
          }
          if (dryRun) {
            results.push({ name: zone.name, status: "Would update (without IP list)", details: `${retryPartRules.length} managed` });
            continue;
          }
          await putEntrypoint(cfg, zone.id, retryDesired);
          results.push({ name: zone.name, status: "Updated (without IP list)", details: `${retryPartRules.length} managed — provide cfat_... to enable ${cfg.listName}` });
          continue;
        } catch (retryErr: any) {
          const rmsg = retryErr.cfErrors?.map((e: any) => e.message).join("; ") || retryErr.message;
          results.push({ name: zone.name, status: "Error", details: `${msg} | retry without list also failed: ${rmsg}` });
          console.error(`${zone.name}: Error ${msg} | retry failed ${rmsg}`);
          continue;
        }
      }
      results.push({ name: zone.name, status: "Error", details: msg });
      console.error(`${zone.name}: Error ${msg}`);
    }
  }

  console.log(`Done in ${Date.now() - start}ms — cron: ${triggerCron ?? "manual"}`);
  return { zones: results, ipList: ipResult ? { added: ipResult.added, removed: ipResult.removed, total: ipResult.total } : undefined, warnings };
}

export default {
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    // do not throw — log only, so cron shows success/failure correctly
    try {
      console.log(`scheduled cron: ${controller.cron} at ${new Date(controller.scheduledTime).toISOString()}`);
      await runSync(env, false, controller.cron);
    } catch (err: any) {
      console.error(`scheduled failed: ${err.message}`, err.stack);
      throw err;
    }
  },

  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ ok: true, service: "cf-waf-sync" }), { headers: { "Content-Type": "application/json" } });
    }
    if (url.pathname === "/sync" || url.pathname === "/") {
      const dryRun = url.searchParams.get("dryRun") === "1" || url.searchParams.get("dry_run") === "1" || env.DRY_RUN === "true";
      // simple auth: require Authorization Bearer == CF_API_TOKEN or no auth if dryRun
      const auth = request.headers.get("Authorization");
      if (!dryRun && auth !== `Bearer ${env.CF_API_TOKEN}` && request.method !== "GET") {
        // allow GET dryRun without auth for quick check
        if (!(dryRun && request.method === "GET")) {
          return new Response(JSON.stringify({ error: "Unauthorized — send Authorization: Bearer $CF_API_TOKEN" }), { status: 401 });
        }
      }
      try {
        const result = await runSync(env, dryRun);
        return new Response(JSON.stringify({ success: true, dryRun, result }, null, 2), {
          headers: { "Content-Type": "application/json" },
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ success: false, error: err.message, stack: err.stack }, null, 2), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        });
      }
    }
    return new Response("Not found. Use GET /health or GET /sync?dryRun=1", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
