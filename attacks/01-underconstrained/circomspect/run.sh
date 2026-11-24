#!/usr/bin/env bash
# Runs circomspect (Trail of Bits) on the lab 01 circuits and saves the reports
# here. Requires: cargo install circomspect   (reports below made with v0.9.0)
#   npm run lab:01:circomspect
set -euo pipefail
cd "$(dirname "$0")/../../.."
OUT=attacks/01-underconstrained/circomspect
L=attacks/01-underconstrained
declare -A FILES=(
  [01a_vulnerable]=$L/vulnerable/credential_01a.circom
  [01a_fixed]=circuits/credential.circom
  [01b_vulnerable]=$L/vulnerable/credential_01b.circom
  [01b_fixed]=$L/fixed/credential_01b_fixed.circom
  [probe_p1_01a_laundered]=$L/vulnerable/probes/p1_01a_laundered.circom
  [probe_p2_01b_ternary]=$L/vulnerable/probes/p2_01b_ternary.circom
  [probe_p3_01b_boolean]=$L/vulnerable/probes/p3_01b_boolean.circom
)
for name in "${!FILES[@]}"; do
  src=${FILES[$name]}
  {
    echo "# circomspect $(cargo install --list 2>/dev/null | awk '/^circomspect /{print $2}' | tr -d :) -L node_modules -l INFO $src"
    # circomspect exits non-zero when it finds issues; keep going.
    NO_COLOR=1 circomspect -L node_modules -l INFO "$src" 2>&1 || true
  } | sed -e 's/\x1b\[[0-9;]*m//g' -e "s#$PWD/##g" > "$OUT/$name.txt"
  echo "$OUT/$name.txt: $(grep -c '^warning' "$OUT/$name.txt") warnings, $(grep -c '^note' "$OUT/$name.txt") notes"
done
