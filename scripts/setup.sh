#!/usr/bin/env bash
set -euo pipefail

# One-shot setup — Cloudflare API token via POST /accounts/{id}/tokens + intel + open rules
# Uses CLOUDFLARE_API_TOKEN alias for Authorization: Bearer (creates CF_API_TOKEN for Worker)
# API: https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/create/
# Wrangler adds env via `wrangler secret put` (encrypted, not in wrangler.toml)
#
# Env (required): CF_ACCOUNT_ID (32 hex, from dash.cloudflare.com/<id>/)
# Env (one of): CLOUDFLARE_API_TOKEN | CF_PARENT_TOKEN | CF_API_TOKEN (parent with Account API Tokens Write)
# Env (optional, both can be missing): SNIFFCAT_API_TOKEN / ABUSEIPDB_API_KEY (external intel)
#
# Usage:
#   CF_ACCOUNT_ID=... CLOUDFLARE_API_TOKEN=... bash scripts/setup.sh
#   CF_ACCOUNT_ID=... CLOUDFLARE_API_TOKEN=... bash scripts/setup.sh --create --kv --open
#   # interactive prompt for SNIFFCAT/ABUSE if missing: bash scripts/setup.sh --prompt

ACCOUNT_ID="${CF_ACCOUNT_ID:-}"
PARENT_TOKEN="${CLOUDFLARE_API_TOKEN:-${CF_PARENT_TOKEN:-${CF_API_TOKEN:-}}}"
ZONE_IDS="${CF_ZONE_IDS:-}"
ZONE_NAMES="${CF_ZONE_NAMES:-}"
DO_CREATE=0
DO_KV=0
DO_OPEN=1
DO_PROMPT=0

for arg in "$@"; do
  case "$arg" in
    --create) DO_CREATE=1 ;;
    --kv) DO_KV=1 ;;
    --open) DO_OPEN=1 ;;
    --no-open) DO_OPEN=0 ;;
    --prompt) DO_PROMPT=1 ;;
    --skip-external) DO_PROMPT=0 ;;
  esac
done

if [[ -z "${ACCOUNT_ID}" ]]; then
  echo "Missing CF_ACCOUNT_ID (32-char hex from https://dash.cloudflare.com/<id>/) — export CF_ACCOUNT_ID=..."
  echo "Hint: pnpm exec wrangler whoami  # shows account id"
  exit 1
fi
if ! [[ "${ACCOUNT_ID}" =~ ^[a-f0-9]{32}$ ]]; then
  echo "CF_ACCOUNT_ID must be 32-char hex, got '${ACCOUNT_ID}'"
  exit 1
fi
if [[ -z "${PARENT_TOKEN}" ]]; then
  echo "Missing CLOUDFLARE_API_TOKEN (alias) — export CLOUDFLARE_API_TOKEN=\$CF_API_TOKEN or CF_PARENT_TOKEN"
  echo "Create parent at https://dash.cloudflare.com/profile/api-tokens -> Create Custom Token with Account API Tokens Write"
  exit 1
fi

API="https://api.cloudflare.com/client/v4"

need_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found — install via: brew install jq / apt-get install jq"
    exit 1
  fi
}

verify_token() {
  echo "Verifying token scopes via GET /accounts/${ACCOUNT_ID}/tokens/verify ..."
  curl -s -H "Authorization: Bearer ${PARENT_TOKEN}" "${API}/accounts/${ACCOUNT_ID}/tokens/verify" | jq .
}

get_permission_groups() {
  curl -s -H "Authorization: Bearer ${PARENT_TOKEN}" "${API}/accounts/${ACCOUNT_ID}/tokens/permission_groups"
}

create_token() {
  need_jq
  echo "Resolving permission groups ..."
  local groups
  groups=$(get_permission_groups)
  echo "${groups}" | jq -r '.result[] | "\(.name) \(.id)"' | head -20

  local filterListsEdit accountRead wafEdit zoneRead
  filterListsEdit=$(echo "${groups}" | jq -r '.result[] | select(.name | test("Filter Lists"; "i")) | .id' | head -1)
  accountRead=$(echo "${groups}" | jq -r '.result[] | select(.name | test("Account.*Read"; "i")) | .id' | head -1)
  wafEdit=$(echo "${groups}" | jq -r '.result[] | select(.name | test("WAF"; "i")) | .id' | head -1)
  zoneRead=$(echo "${groups}" | jq -r '.result[] | select(.name | test("Zone Read"; "i")) | .id' | head -1)

  if [[ -z "${filterListsEdit}" || -z "${wafEdit}" ]]; then
    echo "Failed to resolve permission groups — check parent token has Account API Tokens Write"
    echo "${groups}" | jq '.result | map(.name)'
    exit 1
  fi

  local zoneResources
  if [[ -z "${ZONE_IDS}" ]]; then
    zoneResources='{"com.cloudflare.api.zone.*":"*"}'
  else
    # Build {"com.cloudflare.api.zone.<id>":"*"} map
    zoneResources=$(echo "${ZONE_IDS}" | tr ',' '\n' | jq -R 'select(length>0)' | jq -s 'map({"key":"com.cloudflare.api.zone." + ., "value":"*"}) | from_entries')
  fi

  local name="cf-waf-sync-$(date +%s)"
  local body
  body=$(jq -n \
    --arg name "${name}" \
    --arg fid "${filterListsEdit}" \
    --arg arid "${accountRead}" \
    --arg wid "${wafEdit}" \
    --arg zid "${zoneRead}" \
    --argjson zr "${zoneResources}" \
    --arg acct "com.cloudflare.api.account.${ACCOUNT_ID}" \
    '{
      name: $name,
      policies: [
        {effect:"allow", permission_groups:[{id:$fid},{id:$arid}], resources: {($acct): "*"}},
        {effect:"allow", permission_groups:[{id:$wid},{id:$zid}], resources: $zr}
      ]
    }')

  echo "Creating token ${name} ..."
  echo "${body}" | jq .

  local resp
  resp=$(curl -s -X POST -H "Authorization: Bearer ${PARENT_TOKEN}" -H "Content-Type: application/json" -d "${body}" "${API}/accounts/${ACCOUNT_ID}/tokens")
  echo "${resp}" | jq .
  local value
  value=$(echo "${resp}" | jq -r '.result.value // empty')
  local id
  id=$(echo "${resp}" | jq -r '.result.id // empty')
  if [[ -z "${value}" ]]; then
    echo "Token creation failed — check errors above. Fallback: https://dash.cloudflare.com/${ACCOUNT_ID}/config/api/tokens"
    return 1
  fi
  echo ""
  echo "=== SAVE ONCE (cfat_...) ==="
  echo "${value}"
  echo "=== id ${id} ==="
  echo ""
  echo "Storing via wrangler (encrypted) ..."
  printf "%s" "${value}" | pnpm exec wrangler secret put CF_API_TOKEN
  printf "%s" "${ACCOUNT_ID}" | pnpm exec wrangler secret put CF_ACCOUNT_ID
  echo "Also for CI: gh secret set CF_API_TOKEN --body \"${value}\" --repos \${GH_REPO:-ayushjaipuriyar/cf-waf-sync}"
  echo "          gh secret set CF_ACCOUNT_ID --body \"${ACCOUNT_ID}\""
}

setup_intel() {
  local sniff="${SNIFFCAT_API_TOKEN:-}"
  local abuse="${ABUSEIPDB_API_KEY:-}"
  if [[ "${DO_PROMPT}" -eq 1 ]]; then
    if [[ -z "${sniff}" ]]; then
      read -r -p "SNIFFCAT_API_TOKEN (optional, enter to skip): " sniff || true
    fi
    if [[ -z "${abuse}" ]]; then
      read -r -p "ABUSEIPDB_API_KEY (optional, enter to skip): " abuse || true
    fi
  fi
  if [[ -n "${sniff}" ]]; then
    echo "Storing SNIFFCAT_API_TOKEN via wrangler secret ..."
    printf "%s" "${sniff}" | pnpm exec wrangler secret put SNIFFCAT_API_TOKEN
  else
    echo "SNIFFCAT_API_TOKEN not set — using static ip-blocklist.txt only (optional, skip OK)"
  fi
  if [[ -n "${abuse}" ]]; then
    echo "Storing ABUSEIPDB_API_KEY via wrangler secret ..."
    printf "%s" "${abuse}" | pnpm exec wrangler secret put ABUSEIPDB_API_KEY
  else
    echo "ABUSEIPDB_API_KEY not set — using static ip-blocklist.txt only (optional, skip OK)"
  fi
}

create_kv() {
  echo "Creating KV SYNC_KV ..."
  local resp
  resp=$(curl -s -X POST -H "Authorization: Bearer ${PARENT_TOKEN}" -H "Content-Type: application/json" -d '{"title":"cf-waf-sync-SYNC_KV"}' "${API}/accounts/${ACCOUNT_ID}/storage/kv/namespaces")
  echo "${resp}" | jq .
  local id
  id=$(echo "${resp}" | jq -r '.result.id // empty')
  if [[ -n "${id}" ]]; then
    echo "KV id=${id}"
    echo "Add to wrangler.toml:"
    echo "[[kv_namespaces]]"
    echo "binding = \"SYNC_KV\""
    echo "id = \"${id}\""
    echo "preview_id = \"${id}\""
  fi
}

open_dashboard() {
  if [[ "${DO_OPEN}" -eq 0 ]]; then return 0; fi
  local zoneId
  zoneId=$(echo "${ZONE_IDS}" | cut -d',' -f1 | tr -d ' ')
  if [[ -z "${zoneId}" ]]; then
    # Try to fetch first zone via API if not provided
    zoneId=$(curl -s -H "Authorization: Bearer ${PARENT_TOKEN}" "${API}/zones?per_page=1" | jq -r '.result[0].id // empty' 2>/dev/null || true)
  fi
  local url
  if [[ -n "${zoneId}" ]]; then
    url="https://dash.cloudflare.com/${ACCOUNT_ID}/${zoneId}/firewall/custom-rules"
  else
    url="https://dash.cloudflare.com/${ACCOUNT_ID}/firewall/custom-rules"
  fi
  echo "Opening ${url} ..."
  if command -v open >/dev/null 2>&1; then
    open "${url}" || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${url}" || true
  else
    echo "${url}"
  fi
  # Also open tokens page for verification
  local tokensUrl="https://dash.cloudflare.com/${ACCOUNT_ID}/config/api/tokens"
  echo "Tokens: ${tokensUrl}"
  if command -v open >/dev/null 2>&1; then
    sleep 1; open "${tokensUrl}" || true
  fi
}

main() {
  echo "cf-waf-sync bash setup — CLOUDFLARE_API_TOKEN alias for Bearer, both intel optional"
  echo "Account: ${ACCOUNT_ID} Zones: ${ZONE_IDS:-*}"
  verify_token || echo "Verify failed — parent may lack verify, continuing"

  if [[ "${DO_CREATE}" -eq 1 ]]; then
    create_token
  else
    echo "Skipping token create (pass --create to POST /accounts/{id}/tokens). Verifying existing CF_API_TOKEN scopes ..."
  fi

  setup_intel

  if [[ "${DO_KV}" -eq 1 ]]; then
    create_kv
  fi

  open_dashboard

  echo ""
  echo "Done. Next: pnpm run check && pnpm test && pnpm exec wrangler deploy --dry-run"
}

main "$@"
