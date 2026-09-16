export interface Env {
  // required
  CF_API_TOKEN: string;
  CF_ACCOUNT_ID: string;
  // vars with defaults
  CF_IP_BLOCKLIST_NAME?: string;
  PHP_SUPPORT?: string;
  WORDPRESS_SUPPORT?: string;
  SNIFFCAT_API_TOKEN?: string;
  SNIFFCAT_CONFIDENCE_MIN?: string;
  SNIFFCAT_LIMIT?: string;
  ABUSEIPDB_API_KEY?: string;
  ABUSEIPDB_CONFIDENCE_MIN?: string;
  ABUSEIPDB_LIMIT?: string;
  EXCLUDED_ZONES?: string;
  CF_ZONE_IDS?: string;
  CF_ZONE_NAMES?: string;
  DISCORD_WEBHOOK_URL?: string;
  RULES_SOURCE_URL?: string;
  DRY_RUN?: string;
  ALLOWLIST?: string;
}

export interface ResolvedConfig {
  cfApiToken: string;
  cfAccountId: string;
  listName: string;
  phpSupport: boolean;
  wordpressSupport: boolean;
  sniffcatToken?: string;
  sniffcatConfidenceMin: number;
  sniffcatLimit: number;
  abuseIpdbKey?: string;
  abuseIpdbConfidenceMin: number;
  abuseIpdbLimit: number;
  excludedZones: string[];
  zoneIds: string[];
  zoneNames: string[];
  discordWebhookUrl?: string;
  rulesSourceUrl?: string;
  allowlist: string;
}

export function resolveConfig(env: Env): ResolvedConfig {
  if (!env.CF_API_TOKEN) throw new Error("Missing CF_API_TOKEN (wrangler secret put CF_API_TOKEN)");
  if (!env.CF_ACCOUNT_ID) throw new Error("Missing CF_ACCOUNT_ID (wrangler secret put CF_ACCOUNT_ID)");

  const php = (env.PHP_SUPPORT ?? "false").toLowerCase() === "true";
  const wp = (env.WORDPRESS_SUPPORT ?? "false").toLowerCase() === "true";

  return {
    cfApiToken: env.CF_API_TOKEN,
    cfAccountId: env.CF_ACCOUNT_ID,
    // CF_IP_BLOCKLIST_NAME="" disables IP list sync (for zone-scoped cfut tokens without Account Filter Lists perms)
    listName: env.CF_IP_BLOCKLIST_NAME === "" ? "" : env.CF_IP_BLOCKLIST_NAME || "sefinek_cf_waf",
    phpSupport: php,
    wordpressSupport: wp,
    sniffcatToken: env.SNIFFCAT_API_TOKEN || undefined,
    sniffcatConfidenceMin: parseInt(env.SNIFFCAT_CONFIDENCE_MIN || "80", 10),
    sniffcatLimit: parseInt(env.SNIFFCAT_LIMIT || "2000", 10),
    abuseIpdbKey: env.ABUSEIPDB_API_KEY || undefined,
    abuseIpdbConfidenceMin: parseInt(env.ABUSEIPDB_CONFIDENCE_MIN || "75", 10),
    abuseIpdbLimit: parseInt(env.ABUSEIPDB_LIMIT || "8000", 10),
    excludedZones: (env.EXCLUDED_ZONES || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    zoneIds: (env.CF_ZONE_IDS || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    zoneNames: (env.CF_ZONE_NAMES || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    discordWebhookUrl: env.DISCORD_WEBHOOK_URL || undefined,
    rulesSourceUrl: env.RULES_SOURCE_URL || undefined,
    allowlist: env.ALLOWLIST || "",
  };
}

export function validateConfig(cfg: ResolvedConfig): string[] {
  const warnings: string[] = [];
  if (cfg.wordpressSupport && !cfg.phpSupport) {
    warnings.push("WORDPRESS_SUPPORT=true but PHP_SUPPORT=false — WordPress needs PHP; consider PHP_SUPPORT=true");
  }
  if (!cfg.sniffcatToken && !cfg.abuseIpdbKey) {
    warnings.push("Neither SNIFFCAT_API_TOKEN nor ABUSEIPDB_API_KEY set — only static ip-blocklist.txt will be used");
  }
  return warnings;
}
