/// <reference types="@cloudflare/workers-types" />

import pLimit from "p-limit"
import { BUNDLED_EXPRESSIONS, BUNDLED_IP_BLOCKLIST } from "./assets/bundled"
import {
  getOrCreateList,
  resolveMaxListSize,
  syncListItems,
} from "./cloudflare/lists"
import { getEntrypoint, normalize, putEntrypoint } from "./cloudflare/rulesets"
import { getZones } from "./cloudflare/zones"
import { type Env, resolveConfig, validateConfig } from "./config"
import { fetchAbuseIPDBIPs } from "./integrations/abuseipdb"
import { fetchSniffCatIPs } from "./integrations/sniffcat"
import { loadExpressions } from "./parsers/expressions"
import {
  BLOCKLIST_DESCRIPTION,
  buildZoneExpression,
  getRuleCap,
  isManagedDescription,
  isPartDescription,
  MAX_EXPRESSION_LENGTH,
  passthroughRule,
} from "./parsers/wafRuleset"
import { parseZoneScopedListText } from "./parsers/zoneLists"

export interface SyncResult {
  zones: Array<{
    name: string
    status: string
    details: string
    diff?: { before: number; after: number; changes: string[] }
  }>
  ipList?: { added: number; removed: number; total: number }
  warnings: string[]
  meta?: { version: string | null; durationMs: number; cron?: string }
}

// ---------- structured logger ----------
function jlog(
  level: "info" | "warn" | "error",
  msg: string,
  extra: Record<string, unknown> = {},
) {
  console.log(
    JSON.stringify({ level, msg, ts: new Date().toISOString(), ...extra }),
  )
}

// ---------- secure compare (timing-safe) ----------
function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  // Use crypto.timingSafeEqual if available (Node/Workers), else constant-time loop
  try {
    const enc = new TextEncoder()
    const ab = enc.encode(a)
    const bb = enc.encode(b)
    if ((crypto as any).timingSafeEqual)
      return (crypto as any).timingSafeEqual(ab, bb)
  } catch {}
  let out = 0
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return out === 0
}

// ---------- rate limit (in-memory per isolate, 60s window) ----------
const rateLimitStore = new Map<string, { count: number; resetAt: number }>()
function checkRateLimit(key: string, limit = 10, windowMs = 60_000): boolean {
  const now = Date.now()
  const entry = rateLimitStore.get(key)
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + windowMs })
    return true
  }
  if (entry.count >= limit) return false
  entry.count++
  return true
}

function parseIPList(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
}

async function syncIPList(
  cfg: ReturnType<typeof resolveConfig>,
): Promise<{ added: number; removed: number; total: number } | null> {
  if (!cfg.listName) {
    jlog("info", "CF_IP_BLOCKLIST_NAME empty — skipping IP list sync")
    return null
  }
  if (!cfg.cfAccountId) {
    jlog("info", "CF_ACCOUNT_ID missing — skipping IP list sync")
    return null
  }

  jlog("info", `Syncing IP list '${cfg.listName}'...`)
  // Lazy: getOrCreateList first (validates token has Filter Lists:Edit), then fetch intel — saves quota on cfut tokens
  const { listId, allLists, itemCap } = await getOrCreateList(cfg)
  const maxListSize = resolveMaxListSize(allLists, listId, itemCap)

  const builtinIPs = parseIPList(BUNDLED_IP_BLOCKLIST)
  const [sniffcatIPs, abuseIPDBIPs] = await Promise.all([
    fetchSniffCatIPs(cfg),
    fetchAbuseIPDBIPs(cfg),
  ])

  // priority: builtin + sniffcat (kept fully), abuse trimmed
  const priorityIPs = [...new Set([...builtinIPs, ...sniffcatIPs])]
  const prioritySet = new Set(priorityIPs)
  const newAbuse = abuseIPDBIPs.filter((ip) => !prioritySet.has(ip))
  const budget = Math.max(0, maxListSize - priorityIPs.length)
  const truncatedCount = Math.max(0, newAbuse.length - budget)
  const usedAbuse = truncatedCount > 0 ? newAbuse.slice(0, budget) : newAbuse
  const merged = [...new Set([...priorityIPs, ...usedAbuse])].sort()

  if (truncatedCount > 0) {
    jlog(
      "warn",
      `List cap exceeded: ${priorityIPs.length + newAbuse.length} unique but only ${maxListSize} — dropped ${truncatedCount}`,
      {
        truncatedCount,
        priority: priorityIPs.length,
        maxListSize,
      },
    )
  }

  jlog("info", `Desired list: ${merged.length} unique IPs`, {
    builtin: builtinIPs.length,
    sniffcat: sniffcatIPs.length,
    abuse: abuseIPDBIPs.length,
    budget: maxListSize,
  })

  const desiredSet = new Set(merged)
  const { toAdd, toDelete } = await syncListItems(cfg, listId, desiredSet)
  jlog("info", `IP list sync done`, { toAdd, toDelete })
  return { added: toAdd, removed: toDelete, total: merged.length }
}

function pickBlocklistHostIndex(expressions: any): number | null {
  let best: number | null = null
  let bestLen = Infinity
  for (const [k, block] of Object.entries(
    expressions as Record<string, { action: string; length: number }>,
  )) {
    const idx = parseInt(k, 10)
    if (Number.isNaN(idx) || (block as any).action !== "block") continue
    if ((block as any).length < bestLen) {
      bestLen = (block as any).length
      best = idx
    }
  }
  return best
}

function buildDiff(current: any[], desired: any[]): string[] {
  const curSet = new Set(current.map((r) => r.description))
  const desSet = new Set(desired.map((r) => r.description))
  const changes: string[] = []
  for (const d of desSet) if (!curSet.has(d)) changes.push(`+ ${d}`)
  for (const c of curSet) if (!desSet.has(c)) changes.push(`- ${c}`)
  // detect modified expressions (same desc, different expr)
  const curMap = new Map(current.map((r) => [r.description, r.expression]))
  for (const r of desired)
    if (curMap.has(r.description) && curMap.get(r.description) !== r.expression)
      changes.push(`~ ${r.description} (expression changed)`)
  return changes
}

async function syncOneZone(
  zone: { id: string; name: string; plan?: any },
  cfg: ReturnType<typeof resolveConfig>,
  expressions: any,
  blocklistHostIndex: number | null,
  allowlistEntries: ReturnType<typeof parseZoneScopedListText>,
  blocklistEntries: ReturnType<typeof parseZoneScopedListText>,
  dryRun: boolean,
  _existingManagedCache?: any[],
): Promise<{
  name: string
  status: string
  details: string
  diff?: { before: number; after: number; changes: string[] }
}> {
  const allowlistExpr = buildZoneExpression(
    allowlistEntries as any,
    zone as any,
  )
  const wrap = (expr: string) =>
    allowlistExpr ? `not (${allowlistExpr}) and (${expr})` : expr
  const blocklistExpr = buildZoneExpression(
    blocklistEntries as any,
    zone as any,
  )

  let current: any[] = []
  let userRules: any[] = []
  let existingManaged: any[] = []
  try {
    const entrypoint = await getEntrypoint(cfg, zone.id)
    current = entrypoint?.rules ?? []
    userRules = current.filter(
      (r) => !isManagedDescription(r.description || ""),
    )
    existingManaged = current.filter((r) =>
      isManagedDescription(r.description || ""),
    )

    const partRules: any[] = []
    for (const [idxStr, block] of Object.entries(expressions as any)) {
      if (idxStr === "_meta") continue
      const idx = parseInt(idxStr, 10)
      if (Number.isNaN(idx)) continue
      const { name, action, expressions: part } = block as any
      if (!part || part.trim() === "" || part === "(true)") {
        jlog("warn", `Skipping empty block ${idx} "${name}" for ${zone.name}`)
        continue
      }
      const expression = wrap(part as string)
      if (expression.length > MAX_EXPRESSION_LENGTH) {
        throw new Error(
          `"${name}" for ${zone.name} is ${expression.length} chars, exceeds ${MAX_EXPRESSION_LENGTH}. Trim expressions.md`,
        )
      }
      const match = existingManaged.find((r) =>
        isPartDescription(r.description, idx),
      )
      partRules.push({
        ...(match?.id ? { id: match.id } : {}),
        action,
        expression,
        description: name,
        enabled: true,
      })
    }

    let blocklistStatus = "None"
    if (blocklistExpr) {
      const ruleCap = getRuleCap(zone as any)
      const hasSpare = partRules.length + userRules.length < ruleCap
      if (hasSpare) {
        const expr = wrap(blocklistExpr)
        if (expr.length > MAX_EXPRESSION_LENGTH) {
          blocklistStatus = `Skipped (${expr.length}/${MAX_EXPRESSION_LENGTH})`
        } else {
          const match = existingManaged.find(
            (r) => r.description === BLOCKLIST_DESCRIPTION,
          )
          partRules.push({
            ...(match?.id ? { id: match.id } : {}),
            action: "block",
            expression: expr,
            description: BLOCKLIST_DESCRIPTION,
            enabled: true,
          })
          blocklistStatus = `own rule (${expr.length})`
        }
      } else {
        const host =
          blocklistHostIndex !== null
            ? partRules.find((r) =>
                isPartDescription(r.description, blocklistHostIndex),
              )
            : null
        if (!host) {
          blocklistStatus = "Skipped (no block host)"
        } else {
          const rawPart = (expressions as any)[blocklistHostIndex!].expressions
          const merged = wrap(`${rawPart} or (${blocklistExpr})`)
          if (merged.length > MAX_EXPRESSION_LENGTH) {
            blocklistStatus = `Skipped merged ${merged.length}/${MAX_EXPRESSION_LENGTH}`
          } else {
            host.expression = merged
            blocklistStatus = `merged into ${host.description}`
          }
        }
      }
    }

    const desired = [...userRules.map(passthroughRule), ...partRules]
    const diffChanges = buildDiff(current, desired)
    const normalizedEqual = normalize(current) === normalize(desired)
    const diff = {
      before: current.length,
      after: desired.length,
      changes: diffChanges,
    }

    if (normalizedEqual) {
      jlog("info", `${zone.name}: Up to date`, {
        before: current.length,
        after: desired.length,
      })
      return { name: zone.name, status: "Up to date", details: "-", diff }
    }

    if (dryRun) {
      jlog("info", `[dryRun] ${zone.name}: would update`, {
        managed: partRules.length,
        preserved: userRules.length,
      })
      return {
        name: zone.name,
        status: "Would update",
        details: `${partRules.length} managed, ${userRules.length} preserved, blocklist: ${blocklistStatus}`,
        diff,
      }
    }

    await putEntrypoint(cfg, zone.id, desired)
    jlog("info", `${zone.name}: Updated`, {
      managed: partRules.length,
      preserved: userRules.length,
    })

    if (cfg.discordWebhookUrl) {
      try {
        await fetch(cfg.discordWebhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            content: `✅ WAF updated: ${zone.name} (${partRules.length} managed, ${userRules.length} preserved)`,
          }),
        })
      } catch {}
    }
    return {
      name: zone.name,
      status: "Updated",
      details: `${partRules.length} managed, ${userRules.length} preserved`,
      diff,
    }
  } catch (err: any) {
    const msg =
      err.cfErrors?.map((e: any) => e.message).join("; ") || err.message
    // If WAF references unknown list (cfut without Account lists perms + CF_IP_BLOCKLIST_NAME still set), retry without list clause
    if (msg.includes("is unknown") && msg.includes("list") && cfg.listName) {
      jlog(
        "warn",
        `${zone.name}: list ${cfg.listName} unknown with this token (needs cfat_...), retrying without IP list`,
        { msg },
      )
      try {
        const strippedCfg = { ...cfg, listName: "" } as typeof cfg
        const strippedExpr = await loadExpressions(
          strippedCfg,
          BUNDLED_EXPRESSIONS,
        )
        if (!strippedExpr) throw err
        const retryPartRules: any[] = []
        const allowlistExpr2 = buildZoneExpression(
          allowlistEntries as any,
          zone as any,
        )
        const wrap2 = (expr: string) =>
          allowlistExpr2 ? `not (${allowlistExpr2}) and (${expr})` : expr
        for (const [idxStr, block] of Object.entries(strippedExpr as any)) {
          if (idxStr === "_meta") continue
          const idx = parseInt(idxStr, 10)
          if (Number.isNaN(idx)) continue
          const { name, action, expressions: part } = block as any
          if (!part || part.trim() === "") continue
          const expression = wrap2(part as string)
          const match = existingManaged.find((r: any) =>
            isPartDescription(r.description, idx),
          )
          retryPartRules.push({
            ...(match?.id ? { id: match.id } : {}),
            action,
            expression,
            description: name,
            enabled: true,
          })
        }
        const retryDesired = [
          ...userRules.map(passthroughRule),
          ...retryPartRules,
        ]
        const diffChanges = buildDiff(current, retryDesired)
        if (normalize(current) === normalize(retryDesired)) {
          return {
            name: zone.name,
            status: "Up to date (without IP list)",
            details: "list unavailable with cfut",
            diff: {
              before: current.length,
              after: retryDesired.length,
              changes: diffChanges,
            },
          }
        }
        if (dryRun) {
          return {
            name: zone.name,
            status: "Would update (without IP list)",
            details: `${retryPartRules.length} managed`,
            diff: {
              before: current.length,
              after: retryDesired.length,
              changes: diffChanges,
            },
          }
        }
        await putEntrypoint(cfg, zone.id, retryDesired)
        return {
          name: zone.name,
          status: "Updated (without IP list)",
          details: `${retryPartRules.length} managed — provide cfat_... to enable ${cfg.listName}`,
          diff: {
            before: current.length,
            after: retryDesired.length,
            changes: diffChanges,
          },
        }
      } catch (retryErr: any) {
        const rmsg =
          retryErr.cfErrors?.map((e: any) => e.message).join("; ") ||
          retryErr.message
        jlog("error", `${zone.name}: retry without list failed`, { msg, rmsg })
        return {
          name: zone.name,
          status: "Error",
          details: `${msg} | retry without list also failed: ${rmsg}`,
        }
      }
    }
    jlog("error", `${zone.name}: Error`, { msg })
    return { name: zone.name, status: "Error", details: msg }
  }
}

export async function runSync(
  env: Env,
  dryRun = false,
  triggerCron?: string,
): Promise<SyncResult> {
  const start = Date.now()
  const cfg = resolveConfig(env)
  const warnings = validateConfig(cfg)
  for (const w of warnings) jlog("warn", w)

  const expressions = await loadExpressions(cfg, BUNDLED_EXPRESSIONS)
  if (
    !expressions ||
    !Object.keys(expressions).filter((k) => k !== "_meta").length
  )
    throw new Error("No expressions found — check RULES_SOURCE_URL/bundled")

  const metaVersion = (expressions as any)._meta?.version ?? null
  const blocklistHostIndex = pickBlocklistHostIndex(expressions)

  const allowlistEntries = parseZoneScopedListText((cfg as any).allowlist || "")
  const blocklistEntries: ReturnType<typeof parseZoneScopedListText> = []

  let ipResult: { added: number; removed: number; total: number } | null = null
  if (!dryRun) {
    try {
      ipResult = await syncIPList(cfg)
    } catch (err: any) {
      const msg = err.cfErrors?.[0]?.message || err.message
      if (msg?.includes("Authentication error") || err.status === 403) {
        jlog(
          "warn",
          `IP list sync skipped (token lacks Account Filter Lists:Edit — use cfat_... or set CF_IP_BLOCKLIST_NAME="" to silence)`,
          { msg },
        )
        ipResult = null
      } else {
        throw err
      }
    }
  } else {
    jlog("info", "[dryRun] skipping IP list sync")
  }

  const zones = await getZones(cfg)
  const filtered = cfg.excludedZones.length
    ? zones.filter((z) => !cfg.excludedZones.includes(z.name))
    : zones
  jlog(
    "info",
    `Found ${zones.length} zones, ${filtered.length} active after excluded filter`,
  )

  // Concurrent zones with limit 5
  const limit = pLimit(5)
  const zoneTasks = filtered.map((zone) =>
    limit(() =>
      syncOneZone(
        zone,
        cfg,
        expressions,
        blocklistHostIndex,
        allowlistEntries,
        blocklistEntries,
        dryRun,
      ),
    ),
  )
  const results = await Promise.all(zoneTasks)

  const durationMs = Date.now() - start
  jlog("info", `Done in ${durationMs}ms`, {
    cron: triggerCron ?? "manual",
    zones: results.length,
    ipList: ipResult?.total,
  })

  // KV audit — best effort
  if ((env as any).SYNC_KV) {
    try {
      const kv = (env as any).SYNC_KV as KVNamespace
      await kv.put(
        "lastSync",
        JSON.stringify({
          at: new Date().toISOString(),
          durationMs,
          cron: triggerCron,
          result: { zones: results, ipList: ipResult, warnings },
        }),
        { expirationTtl: 60 * 60 * 24 * 7 },
      )
      await kv.put(
        "lastSync:raw",
        JSON.stringify({
          meta: { version: metaVersion, durationMs, cron: triggerCron },
          zones: results,
          ipList: ipResult,
        }),
        { expirationTtl: 60 * 60 * 24 * 7 },
      )
    } catch (err: any) {
      jlog("warn", "KV audit write failed", { error: err.message })
    }
  }

  return {
    zones: results,
    ipList: ipResult
      ? {
          added: ipResult.added,
          removed: ipResult.removed,
          total: ipResult.total,
        }
      : undefined,
    warnings,
    meta: { version: metaVersion, durationMs, cron: triggerCron },
  }
}

export default {
  async scheduled(
    controller: ScheduledController,
    env: Env,
    _ctx: ExecutionContext,
  ) {
    try {
      jlog(
        "info",
        `scheduled cron: ${controller.cron} at ${new Date(controller.scheduledTime).toISOString()}`,
      )
      await runSync(env, false, controller.cron)
    } catch (err: any) {
      jlog("error", `scheduled failed`, {
        error: err.message,
        stack: err.stack,
      })
      throw err
    }
  },

  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url)
    const ip =
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("x-forwarded-for") ||
      "unknown"

    if (url.pathname === "/health") {
      let lastSync: any = null
      if ((env as any).SYNC_KV) {
        try {
          const raw = await (env as any).SYNC_KV.get("lastSync", "json")
          lastSync = raw
        } catch {}
      }
      return new Response(
        JSON.stringify(
          {
            ok: true,
            service: "cf-waf-sync",
            version: "1.0.0",
            lastSync,
            now: new Date().toISOString(),
          },
          null,
          2,
        ),
        { headers: { "Content-Type": "application/json" } },
      )
    }

    if (url.pathname === "/sync" || url.pathname === "/") {
      const dryRun =
        url.searchParams.get("dryRun") === "1" ||
        url.searchParams.get("dry_run") === "1" ||
        url.searchParams.get("diff") === "1" ||
        env.DRY_RUN === "true"
      const wantDiff =
        url.searchParams.get("diff") === "1" ||
        url.searchParams.get("dryRun") === "diff"

      // Rate limit: 10 req / min per IP for /sync
      const rlKey = `rl:${ip}:${url.pathname}`
      if (!checkRateLimit(rlKey, 10, 60_000)) {
        return new Response(
          JSON.stringify({
            error: "Too many requests — rate limited (10/min)",
          }),
          {
            status: 429,
            headers: {
              "Content-Type": "application/json",
              "Retry-After": "60",
            },
          },
        )
      }

      // Auth: require timing-safe Bearer compare; dryRun GET still requires auth unless ALLOW_UNAUTH_DRYRUN (not set)
      const auth = request.headers.get("Authorization") || ""
      const expected = `Bearer ${env.CF_API_TOKEN}`
      const isAuthed =
        auth.length === expected.length && secureCompare(auth, expected)
      // For GET dryRun/diff, allow unauthenticated but rate-limited — supports quick curl checks
      const allowUnauthDryRun = request.method === "GET" && dryRun
      if (!isAuthed && !allowUnauthDryRun) {
        if (request.method !== "GET" || !dryRun) {
          return new Response(
            JSON.stringify({
              error: "Unauthorized — send Authorization: Bearer $CF_API_TOKEN",
            }),
            {
              status: 401,
              headers: {
                "Content-Type": "application/json",
                "WWW-Authenticate": 'Bearer realm="cf-waf-sync"',
              },
            },
          )
        }
      }

      try {
        const result = await runSync(env, dryRun)
        // For diff=1, emphasize diff payload
        if (wantDiff) {
          return new Response(
            JSON.stringify(
              {
                success: true,
                dryRun,
                diff: result.zones.map((z) => ({
                  name: z.name,
                  status: z.status,
                  diff: z.diff,
                  details: z.details,
                })),
                result,
              },
              null,
              2,
            ),
            {
              headers: { "Content-Type": "application/json" },
            },
          )
        }
        return new Response(
          JSON.stringify({ success: true, dryRun, result }, null, 2),
          {
            headers: { "Content-Type": "application/json" },
          },
        )
      } catch (err: any) {
        jlog("error", "sync failed", { error: err.message })
        return new Response(
          JSON.stringify(
            { success: false, error: err.message, stack: err.stack },
            null,
            2,
          ),
          {
            status: 500,
            headers: { "Content-Type": "application/json" },
          },
        )
      }
    }
    return new Response(
      "Not found. Use GET /health or GET /sync?dryRun=1 or GET /sync?diff=1",
      { status: 404 },
    )
  },
} satisfies ExportedHandler<Env>
