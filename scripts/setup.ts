#!/usr/bin/env tsx
/**
 * One-shot setup for cf-waf-sync
 *
 * 1. Cloudflare API — create least-privilege Account Token (cfat_...) via POST /accounts/{account_id}/tokens
 *    API: https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/create/
 *    Scans permission_groups to resolve ids for:
 *      Account: Filter Lists:Edit, Account:Read
 *      Zone: WAF:Edit, Zone:Read
 *    Resources: com.cloudflare.api.account.{id} + com.cloudflare.api.zone.{id} (or * for all zones)
 *
 * 2. KV namespace SYNC_KV via POST /accounts/{id}/storage/kv/namespaces
 *
 * 3. GitHub branch protection via REST https://docs.github.com/en/rest/branches/branch-protection
 *
 * Usage:
 *   CF_ACCOUNT_ID=0115c... CF_PARENT_TOKEN=xxxx CF_ZONE_IDS=0115c... \
 *   GH_REPO=ayushjaipuriyar/cf-waf-sync \
 *   pnpm exec tsx scripts/setup.ts
 *
 * Or interactive: pnpm run setup
 */

const CF_API_BASE = "https://api.cloudflare.com/client/v4";

type PermissionGroup = { id: string; name: string };

async function cfFetch(path: string, token: string, init: RequestInit = {}) {
  const res = await fetch(`${CF_API_BASE}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(init.headers as any),
    },
  });
  const json: any = await res.json();
  if (!res.ok || !json.success) {
    const msg = json.errors?.map((e: any) => e.message).join("; ") || res.statusText;
    throw new Error(`${init.method || "GET"} ${path} ${res.status}: ${msg}`);
  }
  return json;
}

async function getPermissionGroups(accountId: string, token: string): Promise<PermissionGroup[]> {
  const json = await cfFetch(`/accounts/${accountId}/tokens/permission_groups`, token);
  return json.result as PermissionGroup[];
}

function findGroupId(groups: PermissionGroup[], needle: string): string {
  // name match is case-insensitive, fallback to id prefix search
  const lower = needle.toLowerCase();
  const found = groups.find((g) => g.name.toLowerCase().includes(lower));
  if (!found) throw new Error(`Permission group "${needle}" not found — ${groups.map((g) => g.name).join(", ")}`);
  return found.id;
}

async function createToken(opts: {
  accountId: string;
  parentToken: string;
  tokenName: string;
  zoneIds: string[]; // empty => all zones "*"
}) {
  const groups = await getPermissionGroups(opts.accountId, opts.parentToken);
  console.log(`Found ${groups.length} permission groups`);

  const filterListsEdit = findGroupId(groups, "Filter Lists") || findGroupId(groups, "List Edit");
  const accountRead = findGroupId(groups, "Account Resources Read") || findGroupId(groups, "Account Read");
  const wafEdit = findGroupId(groups, "WAF") || findGroupId(groups, "Firewall");
  const zoneRead = findGroupId(groups, "Zone Read") || findGroupId(groups, "Zone");

  console.log(`Resolved: FilterListsEdit=${filterListsEdit.slice(0, 8)}... AccountRead=${accountRead.slice(0, 8)}... WAF=${wafEdit.slice(0, 8)}... ZoneRead=${zoneRead.slice(0, 8)}...`);

  // Resources shape: Cloudflare expects { "com.cloudflare.api.account.{id}": "*", "com.cloudflare.api.zone.*": "*" }
  const accountResource = `com.cloudflare.api.account.${opts.accountId}`;
  const zoneResources: Record<string, string> =
    opts.zoneIds.length === 0 ? { "com.cloudflare.api.zone.*": "*" } : Object.fromEntries(opts.zoneIds.map((z) => [`com.cloudflare.api.zone.${z}`, "*"] as const));

  const policies = [
    {
      effect: "allow" as const,
      permission_groups: [{ id: filterListsEdit }, { id: accountRead }],
      resources: { [accountResource]: "*" },
    },
    {
      effect: "allow" as const,
      permission_groups: [{ id: wafEdit }, { id: zoneRead }],
      resources: zoneResources,
    },
  ];

  console.log(`Creating token "${opts.tokenName}" with policies:`);
  console.log(JSON.stringify(policies, null, 2));

  const json = await cfFetch(`/accounts/${opts.accountId}/tokens`, opts.parentToken, {
    method: "POST",
    body: JSON.stringify({
      name: opts.tokenName,
      policies,
    }),
  });
  const result = json.result as { id: string; value: string; status: string };
  console.log(`Created token ${result.id} status=${result.status}`);
  console.log(`\n=== SAVE THIS VALUE (shown once) ===\n${result.value}\n=== cfat_... ===\n`);
  console.log(`Set via: pnpm exec wrangler secret put CF_API_TOKEN\nSet via: gh secret set CF_API_TOKEN --body="${result.value}" --repos ${process.env.GH_REPO || "ayushjaipuriyar/cf-waf-sync"}`);
  return result;
}

async function createKV(accountId: string, token: string, title = "cf-waf-sync-SYNC_KV") {
  const json = await cfFetch(`/accounts/${accountId}/storage/kv/namespaces`, token, {
    method: "POST",
    body: JSON.stringify({ title }),
  });
  const ns = json.result as { id: string; title: string };
  console.log(`KV ${ns.title} id=${ns.id}`);
  console.log(`Add to wrangler.toml:\n[[kv_namespaces]]\nbinding = "SYNC_KV"\nid = "${ns.id}"\npreview_id = "${ns.id}"`);
  return ns;
}

async function setupBranchProtection(repo: string, branch = "main") {
  // Uses gh CLI if available, else fetch with GITHUB_TOKEN
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (!token) {
    console.warn("GITHUB_TOKEN not set — skipping branch protection (run: gh auth login; pnpm run setup:branch)");
    return;
  }
  const api = `https://api.github.com/repos/${repo}/branches/${branch}/protection`;
  const body = {
    required_status_checks: {
      strict: true,
      contexts: ["ci"], // matches job name in ci.yml
      checks: [{ context: "ci" }],
    },
    enforce_admins: false,
    required_pull_request_reviews: {
      dismiss_stale_reviews: false,
      require_code_owner_reviews: false,
      required_approving_review_count: 0,
    },
    required_conversation_resolution: true,
    restrictions: null,
    allow_force_pushes: false,
    allow_deletions: false,
    required_linear_history: false,
  };
  const res = await fetch(api, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Branch protection ${res.status}: ${t}`);
  }
  console.log(`Branch protection set for ${repo}@${branch} — require ci + conversation resolution`);
}

async function main() {
  const accountId = process.env.CF_ACCOUNT_ID || process.env.CF_ZONE_IDS?.split(",")[0];
  const parentToken = process.env.CF_API_TOKEN || process.env.CF_PARENT_TOKEN || process.env.CLOUDFLARE_API_TOKEN;
  const zoneIds = (process.env.CF_ZONE_IDS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const repo = process.env.GH_REPO || "ayushjaipuriyar/cf-waf-sync";
  const doToken = process.argv.includes("--token") || !process.argv.includes("--skip-token");
  const doKV = process.argv.includes("--kv");
  const doBranch = process.argv.includes("--branch") || !process.argv.includes("--skip-branch");

  console.log(`cf-waf-sync setup — account=${accountId || "(missing CF_ACCOUNT_ID)"} zones=${zoneIds.join(",") || "*"}`);

  if (!accountId || !parentToken) {
    console.error("Missing CF_ACCOUNT_ID or CF_API_TOKEN/CF_PARENT_TOKEN — set env before running");
    console.log("Example:\n  CF_ACCOUNT_ID=abc... CF_API_TOKEN=xxxx pnpm run setup -- --token --kv --branch");
    console.log("Get CF_ACCOUNT_ID: dash.cloudflare.com/<id>/ or pnpm exec wrangler whoami");
    console.log("Create parent token at: https://dash.cloudflare.com/profile/api-tokens -> Create Custom Token with Account API Tokens Write");
    if (!doBranch) process.exit(1);
  } else if (doToken) {
    try {
      await createToken({ accountId, parentToken, tokenName: `cf-waf-sync-${Date.now()}`, zoneIds });
      if (doKV) await createKV(accountId, parentToken);
    } catch (e: any) {
      console.error(`Token/KV setup failed: ${e.message}`);
      console.error("Fallback: create manually at https://dash.cloudflare.com/<account>/config/api/tokens -> Custom Token -> Account Filter Lists:Edit + Account:Read, Zone WAF:Edit + Zone:Read");
    }
  }

  if (doBranch) {
    try {
      await setupBranchProtection(repo);
    } catch (e: any) {
      console.error(`Branch protection failed: ${e.message}`);
      console.log(`Fallback: gh api repos/${repo}/branches/main/protection -f required_status_checks='{\"strict\":true,\"contexts\":[\"ci\"]}'`);
    }
  }

  console.log("\nSetup done. Next:");
  console.log("- pnpm install");
  console.log("- pnpm run check && pnpm test && pnpm exec biome check --write ./src");
  console.log("- pnpm exec wrangler deploy --dry-run");
  console.log("- git push");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

export { createToken, createKV, setupBranchProtection };
