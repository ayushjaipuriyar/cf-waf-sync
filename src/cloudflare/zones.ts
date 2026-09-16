import type { ResolvedConfig } from "../config";
import { cfFetch } from "./client";
import type { Zone } from "../parsers/wafRuleset";

export async function getZones(cfg: ResolvedConfig): Promise<Zone[]> {
  // If explicit zone IDs/names provided (for zone-scoped cfut tokens that can't list zones), return stubbed zones without API call.
  // This avoids GET /zones which fails for tokens with only Zone WAF:Edit on specific zones.
  if (cfg.zoneIds.length || cfg.zoneNames.length) {
    const stubs: Zone[] = [];
    // Prefer IDs; if both provided, pair by index; if only names, synthesize IDs as names (will be resolved via rulesets if needed)
    if (cfg.zoneIds.length) {
      for (let i = 0; i < cfg.zoneIds.length; i++) {
        const id = cfg.zoneIds[i]!;
        const name = cfg.zoneNames[i] || cfg.zoneNames[0] || (id === "0115c6fc4aab62dff1c8c1730b17cea9" ? "seabuddy.co" : id);
        // seabuddy.co is known Pro (20 rules), otherwise default free (5)
        const legacy = name === "seabuddy.co" ? "pro" : "free";
        stubs.push({ id, name, status: "active", plan: { legacy_id: legacy, name: legacy } } as Zone);
      }
    } else {
      for (const name of cfg.zoneNames) {
        // Without ID we can't call rulesets; try to resolve via known map
        const id = name === "seabuddy.co" ? "0115c6fc4aab62dff1c8c1730b17cea9" : name;
        const legacy = name === "seabuddy.co" ? "pro" : "free";
        stubs.push({ id, name, status: "active", plan: { legacy_id: legacy, name: legacy } } as Zone);
      }
    }
    return stubs;
  }

  const zones: Zone[] = [];
  let page = 1;
  while (true) {
    const data = await cfFetch<Zone[]>(cfg, "/zones", { params: { page, per_page: 1000 } });
    zones.push(...data.result);
    const totalPages = data.result_info?.total_pages ?? 1;
    if (page >= totalPages) break;
    page++;
  }
  return zones;
}
