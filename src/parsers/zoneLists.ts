import type { ZoneScopedEntry } from "./wafRuleset"

const ZONE_PREFIX = /^\[(!?)([^\]]+)]\s*/

export function parseZoneScopedListText(text: string): ZoneScopedEntry[] {
  const entries: ZoneScopedEntry[] = []
  for (const raw of text.split("\n")) {
    const line = raw.trim()
    if (!line || line.startsWith("#")) continue
    const match = line.match(ZONE_PREFIX)
    if (match) {
      const expression = line.slice(match[0].length).trim()
      if (!expression) continue
      entries.push({
        expression,
        zone: match[2].trim(),
        exclude: match[1] === "!",
      })
    } else {
      entries.push({ expression: line, zone: null, exclude: false })
    }
  }
  return entries
}

// For Worker: allowlist/blocklist are optional assets; return empty if not bundled
export function parseAllowlist(text?: string): ZoneScopedEntry[] {
  if (!text) return []
  return parseZoneScopedListText(text)
}
