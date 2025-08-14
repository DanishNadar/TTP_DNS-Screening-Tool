#!/usr/bin/env bash
set -euo pipefail

# Usage: ./TTP_GoogleDoH.bash domain1 [domain2 ...]
if [[ $# -lt 1 ]]; then
  echo "Usage: $(basename "$0") <domain1> [domain2 ...]" >&2
  exit 2
fi

# DKIM selectors
SELECTORS=(
  selector1 selector2 default google s1 s2 k1 k2
  fm1 fm2 fm3 pm pm-bounces mandrill mandrill1 mandrill2
  amazonses mail scph scph1 scph2 hs1 hs2 zoho zohomail krs kl
)

PY="$(dirname "$0")/TTP_GoogleDoH.py"

for DOMAIN in "$@"; do
  echo -e "\n\t\t${DOMAIN}\t\t"
  python3 "$PY" "$DOMAIN" --selectors "${SELECTORS[@]}"
  echo
done
