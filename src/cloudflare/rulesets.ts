import type { ResolvedConfig } from "../config";
import { cfFetch } from "./client";
import { PHASE } from "../parsers/wafRuleset";

export interface Ruleset {
  id: string;
  name: string;
  kind: string;
  phase: string;
  rules: Array<{
    id?: string;
    ref?: string;
    action: string;
    expression: string;
    description: string;
    enabled?: boolean;
    action_parameters?: any;
    logging?: any;
  }>;
}

export async function getEntrypoint(cfg: ResolvedConfig, zoneId: string): Promise<Ruleset | null> {
  try {
    const data = await cfFetch<Ruleset>(cfg, `/zones/${zoneId}/rulesets/phases/${PHASE}/entrypoint`);
    return data.result;
  } catch (err: any) {
    if (err.status === 404) return null;
    throw err;
  }
}

export async function putEntrypoint(cfg: ResolvedConfig, zoneId: string, rules: any[]): Promise<Ruleset> {
  const data = await cfFetch<Ruleset>(cfg, `/zones/${zoneId}/rulesets/phases/${PHASE}/entrypoint`, {
    method: "PUT",
    body: JSON.stringify({ rules }),
  });
  return data.result;
}

export function normalize(rules: Array<{ action: string; expression: string; description: string; enabled?: boolean }>): string {
  return JSON.stringify(
    rules.map((r) => ({
      action: r.action,
      expression: r.expression,
      description: r.description,
      enabled: r.enabled !== false,
    }))
  );
}
