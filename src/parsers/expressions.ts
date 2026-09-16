import type { ResolvedConfig } from "../config";

export interface ExpressionBlock {
  name: string;
  length: number;
  action: string;
  expressions: string;
}

export type ExpressionsMap = Record<number, ExpressionBlock> & { _meta: { version: string | null; totalLength: number; blocks: number } };

const PATTERN = /##\s*([^<\n]*)[^\n]*\n> \*\*Action:\*\* ([^\n]*)\n+```([\s\S]*?)```/gi;

export function parseExpressionsText(raw: string, cfg: ResolvedConfig): ExpressionsMap | null {
  // replace list name placeholder, or strip list clause if IP list disabled (zone-scoped cfut without Account perms)
  let text = raw;
  if (!cfg.listName) {
    // remove the (ip.src in $...) clause including surrounding "or" — keeps WAF valid even without list
    text = text.replace(/\s*or\s*\(ip\.src in \$\w+\)/g, "");
    text = text.replace(/\(ip\.src in \$\w+\)\s*or\s*/g, "");
    text = text.replace(/\(ip\.src in \$\w+\)/g, "(false)");
  } else {
    text = text.replace(/ip\.src in \$\w+/g, `ip.src in $${cfg.listName}`);
  }

  const blocks = [...text.matchAll(PATTERN)].map(([, name, action, rawExpressions]) => {
    const quotedParts: Array<{ key: string; value: string }> = [];
    let idx = 0;
    let restored = (rawExpressions as string)
      .replace(/"((?:[^"\\]|\\.)*)"/g, (_, quote: string) => {
        const key = `__QUOTE_PLACEHOLDER_${idx++}__`;
        quotedParts.push({ key, value: quote });
        return key;
      })
      .replace(/[\n\r]+/g, " ")
      .replace(/\s+/g, " ")
      .replace(/\{\s+/g, "{")
      .replace(/\s+}/g, "}")
      .trim();

    for (const { key, value } of quotedParts) restored = restored.replace(key, `"${value}"`);

    let cleaned = restored.trim();

    if (cfg.phpSupport) {
      cleaned = cleaned.replace(
        /\s*\(\s*http\.request\.uri\.path\s+(?:wildcard|contains|eq)\s+"[^"]*\.php[^"]*"(?:\s+and\s+[^)]+)?\s*\)\s*(?:or|$)/gi,
        ""
      );
    }
    if (cfg.wordpressSupport) {
      cleaned = cleaned.replace(
        /\s*\(\s*http\.request\.uri\.path\s+wildcard\s+"[^"]*\/wp-(?:content|includes)[^"]*"(?:\s+and\s+[^)]+)?\s*\)\s*(?:or|$)/gi,
        ""
      );
    }
    if (cfg.phpSupport || cfg.wordpressSupport) {
      cleaned = cleaned.replace(/^\s*(?:or|and)\s+/i, "");
      cleaned = cleaned.replace(/\s+(?:or|and)\s*$/i, "");
      cleaned = cleaned.replace(/\s+(?:or|and)\s+(?:or|and)\s+/gi, " or ");
      cleaned = cleaned.trim();
      if (!cleaned || cleaned === "or" || cleaned === "and") cleaned = "(true)";
    }

    return {
      name: (name as string).trim(),
      length: cleaned.length,
      action: (action as string).trim().toLowerCase().replace(/\s+/g, "_"),
      expressions: cleaned,
    };
  });

  if (!blocks.length) return null;

  const acc: any = {};
  blocks.forEach((block, i) => {
    if (!block.expressions) return;
    acc[i + 1] = block;
  });

  const versionMatch = text.match(/Last update:\s*([\d.]+)/i);
  acc._meta = {
    version: versionMatch ? versionMatch[1] : null,
    totalLength: blocks.reduce((s, b) => s + b.length, 0),
    blocks: blocks.length,
  };
  return acc as ExpressionsMap;
}

export async function loadExpressions(cfg: ResolvedConfig, bundledText: string): Promise<ExpressionsMap | null> {
  let text = bundledText;
  if (cfg.rulesSourceUrl) {
    const res = await fetch(cfg.rulesSourceUrl);
    if (!res.ok) throw new Error(`Failed to fetch RULES_SOURCE_URL ${cfg.rulesSourceUrl}: ${res.status}`);
    text = await res.text();
  }
  return parseExpressionsText(text, cfg);
}
