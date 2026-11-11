#!/usr/bin/env sh
# Runs the three root-cause reproducers against BOTH the vulnerable (19.2.8) and
# patched (19.2.9) react-server-dom-webpack, side by side. Hermetic: installs its
# own pinned copies. Intended to run inside evidence/Dockerfile, but also works on
# any host with Node >= 18 and network access to npm.
set -eu

VULN_VER="${VULN_VER:-19.2.8}"
FIXED_VER="${FIXED_VER:-19.2.9}"
WORK="${WORK:-/work}"

setup() {
  dir="$1"; ver="$2"
  mkdir -p "$dir"
  if [ ! -d "$dir/node_modules/react-server-dom-webpack" ]; then
    (cd "$dir" && npm init -y >/dev/null 2>&1 && \
       npm install --no-audit --no-fund --save-exact \
         "react@$ver" "react-dom@$ver" "react-server-dom-webpack@$ver" >/dev/null 2>&1)
  fi
  cp "$(dirname "$0")"/0*.cjs "$dir/"
}

run_one() {
  dir="$1"; label="$2"; script="$3"; shift 3
  echo "------ [$label] $script $* ------"
  (cd "$dir" && NODE_ENV="${NODE_ENV:-production}" node --conditions react-server "$script" "$@") || true
  echo
}

echo "#############################################################"
echo "# GHSA-673q-mjm6-r5xr root-cause evidence"
echo "#   vulnerable: react-server-dom-webpack@$VULN_VER"
echo "#   patched   : react-server-dom-webpack@$FIXED_VER"
echo "#############################################################"
echo

echo ">>> installing pinned transports (first run only) ..."
setup "$WORK/vuln" "$VULN_VER"
setup "$WORK/fixed" "$FIXED_VER"
echo

echo "============================================================"
echo "STEP 0 — ArrayBuffer detach primitive (no dependencies)"
echo "============================================================"
echo "------ [host node] 00-arraybuffer-detach.mjs ------"
node "$(dirname "$0")/00-arraybuffer-detach.mjs" || true
echo

echo "============================================================"
echo "STEP 1 — Encoder desync (header declares N bytes, writes 0)"
echo "============================================================"
run_one "$WORK/vuln"  "VULN  $VULN_VER"  01-encoder-desync.cjs
run_one "$WORK/fixed" "FIXED $FIXED_VER" 01-encoder-desync.cjs

echo "============================================================"
echo "STEP 2 — Type-confusion sink (thenable .then = server ref)"
echo "============================================================"
run_one "$WORK/vuln"  "VULN  $VULN_VER"  02-type-confusion-sink.cjs
run_one "$WORK/fixed" "FIXED $FIXED_VER" 02-type-confusion-sink.cjs

echo "============================================================"
echo "STEP 3 — Full chain: desync -> injection -> RCE (runs 'id')"
echo "============================================================"
run_one "$WORK/vuln"  "VULN  $VULN_VER"  03-full-chain-rce.cjs
run_one "$WORK/fixed" "FIXED $FIXED_VER" 03-full-chain-rce.cjs

echo "Done. Vulnerable rows should show a swallowed typed array and an executed"
echo "command; patched rows should show both arrays intact and no execution."
