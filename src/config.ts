/// <reference types="@cloudflare/workers-types" />
import { z } from "zod"

export interface Env {
  // required
  CF_API_TOKEN: string
  CF_ACCOUNT_ID: string
  // vars with defaults
  CF_IP_BLOCKLIST_NAME?: string
  PHP_SUPPORT?: string
  WORDPRESS_SUPPORT?: string
  SNIFFCAT_API_TOKEN?: string
  SNIFFCAT_CONFIDENCE_MIN?: string
  SNIFFCAT_LIMIT?: string
  ABUSEIPDB_API_KEY?: string
  ABUSEIPDB_CONFIDENCE_MIN?: string
  ABUSEIPDB_LIMIT?: string
  EXCLUDED_ZONES?: string
  CF_ZONE_IDS?: string
  CF_ZONE_NAMES?: string
  DISCORD_WEBHOOK_URL?: string
  RULES_SOURCE_URL?: string
  DRY_RUN?: string
  ALLOWLIST?: string
  // bindings
  SYNC_KV?: KVNamespace
}

export interface ResolvedConfig {
  cfApiToken: string
  cfAccountId: string
  listName: string
  phpSupport: boolean
  wordpressSupport: boolean
  sniffcatToken?: string
  sniffcatConfidenceMin: number
  sniffcatLimit: number
  abuseIpdbKey?: string
  abuseIpdbConfidenceMin: number
  abuseIpdbLimit: number
  excludedZones: string[]
  zoneIds: string[]
  zoneNames: string[]
  discordWebhookUrl?: string
  rulesSourceUrl?: string
  allowlist: string
}

const envSchema = z.object({
  CF_API_TOKEN: z
    .string()
    .min(1, "Missing CF_API_TOKEN (wrangler secret put CF_API_TOKEN)"),
  CF_ACCOUNT_ID: z
    .string()
    .min(1, "Missing CF_ACCOUNT_ID (wrangler secret put CF_ACCOUNT_ID)")
    .regex(
      /^[a-f0-9]{32}$/i,
      "CF_ACCOUNT_ID must be 32-char hex (dash.cloudflare.com/<id>/)",
    ),
  CF_IP_BLOCKLIST_NAME: z.string().optional(),
  PHP_SUPPORT: z.string().optional(),
  WORDPRESS_SUPPORT: z.string().optional(),
  SNIFFCAT_API_TOKEN: z.string().optional(),
  SNIFFCAT_CONFIDENCE_MIN: z.string().optional(),
  SNIFFCAT_LIMIT: z.string().optional(),
  ABUSEIPDB_API_KEY: z.string().optional(),
  ABUSEIPDB_CONFIDENCE_MIN: z.string().optional(),
  ABUSEIPDB_LIMIT: z.string().optional(),
  EXCLUDED_ZONES: z.string().optional(),
  CF_ZONE_IDS: z.string().optional(),
  CF_ZONE_NAMES: z.string().optional(),
  DISCORD_WEBHOOK_URL: z.string().url().optional().or(z.literal("")),
  RULES_SOURCE_URL: z.string().url().optional().or(z.literal("")),
  DRY_RUN: z.string().optional(),
  ALLOWLIST: z.string().optional(),
})

function parseBool(v: string | undefined, def = false): boolean {
  if (v === undefined) return def
  return v.toLowerCase() === "true"
}

function parseIntBound(
  raw: string | undefined,
  fallback: number,
  min: number,
  max: number,
  field: string,
): number {
  if (!raw) return fallback
  const n = parseInt(raw, 10)
  if (Number.isNaN(n)) throw new Error(`${field} must be integer, got "${raw}"`)
  if (n < min || n > max)
    throw new Error(`${field} must be ${min}-${max}, got ${n}`)
  return n
}

function splitCsv(v: string | undefined): string[] {
  return (v || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
}

export function resolveConfig(env: Env): ResolvedConfig {
  const parsed = envSchema.parse(env)

  const php = parseBool(parsed.PHP_SUPPORT, false)
  const wp = parseBool(parsed.WORDPRESS_SUPPORT, false)

  const sniffcatConfidenceMin = parseIntBound(
    parsed.SNIFFCAT_CONFIDENCE_MIN,
    80,
    0,
    100,
    "SNIFFCAT_CONFIDENCE_MIN",
  )
  const sniffcatLimit = parseIntBound(
    parsed.SNIFFCAT_LIMIT,
    2000,
    1,
    10000,
    "SNIFFCAT_LIMIT",
  )
  const abuseIpdbConfidenceMin = parseIntBound(
    parsed.ABUSEIPDB_CONFIDENCE_MIN,
    75,
    0,
    100,
    "ABUSEIPDB_CONFIDENCE_MIN",
  )
  const abuseIpdbLimit = parseIntBound(
    parsed.ABUSEIPDB_LIMIT,
    8000,
    1,
    10000,
    "ABUSEIPDB_LIMIT",
  )

  const zoneIds = splitCsv(parsed.CF_ZONE_IDS)
  const zoneNames = splitCsv(parsed.CF_ZONE_NAMES)
  if (
    zoneIds.length &&
    zoneNames.length &&
    zoneIds.length !== zoneNames.length &&
    zoneNames.length !== 1
  ) {
    throw new Error(
      `CF_ZONE_IDS (${zoneIds.length}) and CF_ZONE_NAMES (${zoneNames.length}) length mismatch — provide 1 name or N names matching N ids`,
    )
  }
  // validate zone ids are 32 hex or known alias like seabuddy id
  for (const id of zoneIds) {
    if (!/^[a-f0-9]{32}$/i.test(id))
      throw new Error(`CF_ZONE_IDS entry "${id}" must be 32-char hex`)
  }
  if (sniffcatLimit + abuseIpdbLimit > 10000) {
    // not fatal — caller budgets, but warn via validateConfig
  }

  return {
    cfApiToken: parsed.CF_API_TOKEN,
    cfAccountId: parsed.CF_ACCOUNT_ID,
    listName:
      parsed.CF_IP_BLOCKLIST_NAME === ""
        ? ""
        : parsed.CF_IP_BLOCKLIST_NAME || "sefinek_cf_waf",
    phpSupport: php,
    wordpressSupport: wp,
    sniffcatToken: parsed.SNIFFCAT_API_TOKEN || undefined,
    sniffcatConfidenceMin,
    sniffcatLimit,
    abuseIpdbKey: parsed.ABUSEIPDB_API_KEY || undefined,
    abuseIpdbConfidenceMin,
    abuseIpdbLimit,
    excludedZones: splitCsv(parsed.EXCLUDED_ZONES),
    zoneIds,
    zoneNames,
    discordWebhookUrl: parsed.DISCORD_WEBHOOK_URL || undefined,
    rulesSourceUrl: parsed.RULES_SOURCE_URL || undefined,
    allowlist: parsed.ALLOWLIST || "",
  }
}

export function validateConfig(cfg: ResolvedConfig): string[] {
  const warnings: string[] = []
  if (cfg.wordpressSupport && !cfg.phpSupport) {
    warnings.push(
      "WORDPRESS_SUPPORT=true but PHP_SUPPORT=false — WordPress needs PHP; consider PHP_SUPPORT=true",
    )
  }
  if (!cfg.sniffcatToken && !cfg.abuseIpdbKey) {
    warnings.push(
      "Neither SNIFFCAT_API_TOKEN nor ABUSEIPDB_API_KEY set — only static ip-blocklist.txt will be used",
    )
  }
  if (cfg.sniffcatLimit + cfg.abuseIpdbLimit > 10000) {
    warnings.push(
      `SNIFFCAT_LIMIT (${cfg.sniffcatLimit}) + ABUSEIPDB_LIMIT (${cfg.abuseIpdbLimit}) > 10000 Free cap — budget will trim AbuseIPDB tail`,
    )
  }
  if (cfg.allowlist && cfg.allowlist.length > 2048) {
    warnings.push(
      `ALLOWLIST ${cfg.allowlist.length} chars may push expressions over MAX 4096`,
    )
  }
  return warnings
}
