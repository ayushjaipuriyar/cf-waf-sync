// Ported from data/services/cloudflare/wafRuleset.js
export const PHASE = "http_request_firewall_custom" as const;
export const PART_REGEX = /Part \d+/i;
export const MAX_EXPRESSION_LENGTH = 4096;

export const BLOCKLIST_PATH = "rules/my-lists/blocklist.txt";
export const BLOCKLIST_DESCRIPTION = `🚫 Custom Blocklist (${BLOCKLIST_PATH})`;

export const isManagedDescription = (desc: string) => PART_REGEX.test(desc) || desc === BLOCKLIST_DESCRIPTION;
export const isPartDescription = (desc: string, index: number) => new RegExp(`Part ${index}\\b`).test(desc || "");

export const RULE_CAPS: Record<string, number> = { free: 5, lite: 5, pro: 20, business: 100, enterprise: 1000 };

export interface Zone {
  id: string;
  name: string;
  status: string;
  paused?: boolean;
  type?: string;
  development_mode?: number;
  account?: { id: string };
  plan?: { name?: string; legacy_id?: string };
}

export function getRuleCap(zone: Zone): number {
  const legacy = zone.plan?.legacy_id;
  if (legacy && legacy in RULE_CAPS) return RULE_CAPS[legacy as string];
  return RULE_CAPS.free;
}

export function passthroughRule(rule: any) {
  const out: any = {
    action: rule.action,
    expression: rule.expression,
    description: rule.description,
    enabled: rule.enabled !== false,
  };
  if (rule.id) out.id = rule.id;
  if (rule.action_parameters) out.action_parameters = rule.action_parameters;
  if (rule.ref) out.ref = rule.ref;
  if (rule.logging) out.logging = rule.logging;
  return out;
}

export interface ZoneScopedEntry {
  expression: string;
  zone: string | null;
  exclude: boolean;
}

export function buildZoneExpression(entries: ZoneScopedEntry[], zone: Zone): string | null {
  const applicable = entries.filter((e) => {
    if (!e.zone) return true;
    const matches = e.zone === zone.name || e.zone === zone.id;
    return e.exclude ? !matches : matches;
  });
  if (!applicable.length) return null;
  return applicable.length === 1 ? applicable[0].expression : applicable.map((e) => `(${e.expression})`).join(" or ");
}
