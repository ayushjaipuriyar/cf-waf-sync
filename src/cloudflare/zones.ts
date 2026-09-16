import type { ResolvedConfig } from "../config"
import type { Zone } from "../parsers/wafRuleset"
import { cfFetch } from "./client"

export async function getZones(cfg: ResolvedConfig): Promise<Zone[]> {
  // Generic probing: if explicit zone IDs/names provided, try to enrich via /zones (works for cfat) then fallback to stub for cfut
  if (cfg.zoneIds.length || cfg.zoneNames.length) {
    // Try to hydrate from real /zones when token allows (cfat) — better plan detection
    try {
      // probe single page with attempt, if 403 fall through to stub
      const probed: Zone[] = []
      let page = 1
      let totalPages = 1
      let succeeded = false
      do {
        const data = await cfFetch<Zone[]>(cfg, "/zones", {
          params: { page, per_page: 1000 },
        })
        probed.push(...data.result)
        totalPages = data.result_info?.total_pages ?? 1
        succeeded = true
        page++
      } while (page <= totalPages && probed.length < 1000)
      if (succeeded && probed.length) {
        const byId = new Map(probed.map((z) => [z.id, z]))
        const byName = new Map(probed.map((z) => [z.name, z]))
        const matched: Zone[] = []
        if (cfg.zoneIds.length) {
          for (let i = 0; i < cfg.zoneIds.length; i++) {
            const id = cfg.zoneIds[i]!
            const fallbackName = cfg.zoneNames[i] || cfg.zoneNames[0] || id
            const real = byId.get(id)
            if (real) matched.push(real)
            else {
              const legacy = fallbackName === "seabuddy.co" ? "pro" : "free"
              matched.push({
                id,
                name: fallbackName,
                status: "active",
                plan: { legacy_id: legacy, name: legacy },
              } as Zone)
            }
          }
        } else {
          for (const name of cfg.zoneNames) {
            const real = byName.get(name)
            if (real) matched.push(real)
            else {
              const id =
                name === "seabuddy.co"
                  ? "0115c6fc4aab62dff1c8c1730b17cea9"
                  : name
              const legacy = name === "seabuddy.co" ? "pro" : "free"
              matched.push({
                id,
                name,
                status: "active",
                plan: { legacy_id: legacy, name: legacy },
              } as Zone)
            }
          }
        }
        if (matched.length) return matched
      }
    } catch (err: any) {
      if (err.status !== 403 && err.status !== 401)
        console.warn(
          JSON.stringify({
            level: "warn",
            msg: "zone probe failed, using stub",
            error: err.message,
          }),
        )
      // fall through to stub for zone-scoped cfut tokens
    }
    const stubs: Zone[] = []
    // Prefer IDs; if both provided, pair by index; if only names, synthesize IDs as names (will be resolved via rulesets if needed)
    if (cfg.zoneIds.length) {
      for (let i = 0; i < cfg.zoneIds.length; i++) {
        const id = cfg.zoneIds[i]!
        const name = cfg.zoneNames[i] || cfg.zoneNames[0] || id
        const legacy = name === "seabuddy.co" ? "pro" : "free"
        stubs.push({
          id,
          name,
          status: "active",
          plan: { legacy_id: legacy, name: legacy },
        } as Zone)
      }
    } else {
      for (const name of cfg.zoneNames) {
        // Without ID we can't call rulesets; try to resolve via known map
        const id =
          name === "seabuddy.co" ? "0115c6fc4aab62dff1c8c1730b17cea9" : name
        const legacy = name === "seabuddy.co" ? "pro" : "free"
        stubs.push({
          id,
          name,
          status: "active",
          plan: { legacy_id: legacy, name: legacy },
        } as Zone)
      }
    }
    return stubs
  }

  const zones: Zone[] = []
  let page = 1
  while (true) {
    const data = await cfFetch<Zone[]>(cfg, "/zones", {
      params: { page, per_page: 1000 },
    })
    zones.push(...data.result)
    const totalPages = data.result_info?.total_pages ?? 1
    if (page >= totalPages) break
    page++
  }
  return zones
}
