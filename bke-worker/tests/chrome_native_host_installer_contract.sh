#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SCRIPT="$ROOT/scripts/prepare-chrome-native-host.sh"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
chmod 700 "$tmp"
sandbox="$tmp/sandbox"; mkdir -m 700 "$sandbox"
export HOME="$tmp/home"; mkdir -m 700 "$HOME"
real_node="$(node -p 'require("node:fs").realpathSync(process.execPath)')"
safe_node_dir="$tmp/safe-node"; mkdir -m 700 "$safe_node_dir"
safe_node="$safe_node_dir/node"; cp -- "$real_node" "$safe_node"; chmod 700 "$safe_node"
unsafe_node="$tmp/unsafe-node"; cp -- "$real_node" "$unsafe_node"; chmod 777 "$unsafe_node"
origin="chrome-extension://$(printf 'a%.0s' {1..32})/"
BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" inspect </dev/null
test ! -e "$sandbox/chrome"
if BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$unsafe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" inspect </dev/null 2>/dev/null; then exit 1; fi
if BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" unknown </dev/null 2>/dev/null; then exit 1; fi
if BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN='https://example.invalid/' bash "$SCRIPT" inspect </dev/null 2>/dev/null; then exit 1; fi
if BKE_NATIVE_HOST_TEST_ROOT="$tmp/not-created" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" inspect </dev/null 2>/dev/null; then exit 1; fi
test ! -e "$tmp/not-created"
! grep -Eq 'nativeMessaging' "$ROOT/browser-extension/manifest.json"
! grep -Eq 'wrangler deploy|gh workflow run|cloudflare|PREPRODUCTION' "$SCRIPT"
bash -n "$SCRIPT"
echo "BKE Chrome native host installer contract: PASS"
