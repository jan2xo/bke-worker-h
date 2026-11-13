#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SRC_SCRIPT="$ROOT/scripts/prepare-chrome-native-host.sh"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
chmod 700 "$tmp"

fake_repo="$tmp/repo"
sandbox="$tmp/sandbox"; mkdir -m 700 "$sandbox"
export HOME="$tmp/home"; mkdir -m 700 "$HOME"

# Build a disposable Git repository at fixture root so canonical tracked path
# and provenance checks run faithfully even when parent repo nests bke-worker/.
mkdir -m 700 -p "$fake_repo" "$fake_repo/scripts" "$fake_repo/browser-extension" "$fake_repo/browser-extension/native-host"
cp -- "$SRC_SCRIPT" "$fake_repo/scripts/prepare-chrome-native-host.sh"
cp -- "$ROOT/browser-extension/manifest.json" "$fake_repo/browser-extension/manifest.json"
for mod in entry.mjs host.mjs framing.mjs; do
  cp -- "$ROOT/browser-extension/native-host/$mod" "$fake_repo/browser-extension/native-host/$mod"
  chmod 600 "$fake_repo/browser-extension/native-host/$mod"
done
chmod 600 "$fake_repo/browser-extension/manifest.json"
chmod 700 "$fake_repo/scripts/prepare-chrome-native-host.sh"

git init -q -b main "$fake_repo"
git -C "$fake_repo" config user.email "test@example.invalid"
git -C "$fake_repo" config user.name "Installer Test"
git -C "$fake_repo" add .
git -C "$fake_repo" commit -qm "test fixture"

SCRIPT="$fake_repo/scripts/prepare-chrome-native-host.sh"

real_node="$(node -p 'require("node:fs").realpathSync(process.execPath)')"
safe_node_dir="$tmp/safe-node"; mkdir -m 700 "$safe_node_dir"
safe_node="$safe_node_dir/node"; cp -- "$real_node" "$safe_node"; chmod 700 "$safe_node"
unsafe_node="$tmp/unsafe-node"; cp -- "$real_node" "$unsafe_node"; chmod 777 "$unsafe_node"
node_link="$tmp/node-link"; ln -s "$real_node" "$node_link"
sandbox_link="$tmp/sandbox-link"; ln -s "$sandbox" "$sandbox_link"

origin="chrome-extension://$(printf 'a%.0s' {1..32})/"

# 1. Valid privately owned fixture and safe Node executable succeed (inspect & dry-run)
BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" inspect </dev/null
BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" dry-run </dev/null

# 2. World-writable Node executable fails
if BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$unsafe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" inspect </dev/null 2>/dev/null; then exit 1; fi

# 3. Symlink and unsafe path attempts fail
ln -s prepare-chrome-native-host.sh "$fake_repo/scripts/alternate-entry.sh"
if BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$fake_repo/scripts/alternate-entry.sh" inspect </dev/null 2>/dev/null; then exit 1; fi
rm -f -- "$fake_repo/scripts/alternate-entry.sh"
if BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$node_link" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" inspect </dev/null 2>/dev/null; then exit 1; fi
if BKE_NATIVE_HOST_TEST_ROOT="$sandbox_link" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" inspect </dev/null 2>/dev/null; then exit 1; fi
if BKE_NATIVE_HOST_TEST_ROOT="$tmp/not-created" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" inspect </dev/null 2>/dev/null; then exit 1; fi
test ! -e "$tmp/not-created"

# 4. Invalid origins and arguments fail
if BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN="$origin" bash "$SCRIPT" unknown </dev/null 2>/dev/null; then exit 1; fi
if BKE_NATIVE_HOST_TEST_ROOT="$sandbox" BKE_NATIVE_HOST_TEST_NODE_PATH="$safe_node" BKE_NATIVE_HOST_EXTENSION_ORIGIN='https://example.invalid/' bash "$SCRIPT" inspect </dev/null 2>/dev/null; then exit 1; fi

# 5. No Chrome registration, browser profile, credentials, or production resources modified
test ! -e "$sandbox/chrome"
test ! -e "$sandbox/xdg"
test ! -e "$HOME/.config"
test ! -e "$HOME/.local"
node -e '
  const m = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
  if (!Array.isArray(m.permissions) || m.permissions.includes("nativeMessaging")) process.exit(1);
' "$ROOT/browser-extension/manifest.json"
if grep -Eq 'wrangler deploy|gh workflow run|cloudflare|PREPRODUCTION' "$SRC_SCRIPT"; then exit 1; fi
bash -n "$SRC_SCRIPT"
echo "BKE Chrome native host installer contract: PASS"
