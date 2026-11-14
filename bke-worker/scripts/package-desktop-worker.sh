#!/usr/bin/env bash
# Deterministically packages, verifies, and safely uninstalls ONLY package-owned
# BKE Desktop Worker artifacts (browser-extension + native-host + controller CLI + templates).
#
# Safety guarantees:
# - Never writes secrets, tokens, or live send enablements (live_send_locked_false=true).
# - Rejects symlinks and non-owner-private directories.
# - `clean-uninstall` only removes files tracked & hash-verified in package-manifest.json
#   and NEVER touches Chrome profiles, cookies, localStorage, .git, or SSH/GitHub credentials.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"

usage() {
  cat <<'EOF'
Usage: bash scripts/package-desktop-worker.sh <package|verify|clean-uninstall> [--out <dir>]

Subcommands:
  package          Build and write deterministic non-secret bundle + SHA-256 package-manifest.json
  verify           Verify bundle integrity, regular-file status, and SHA-256 checksums against manifest
  clean-uninstall  Remove ONLY manifest-verified package artifacts (never touches browser profiles)
EOF
}

fail() {
  printf 'FAIL-CLOSED: %s\n' "$1" >&2
  exit 2
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || $# -eq 0 ]]; then
  usage
  exit 0
fi

SUBCOMMAND="$1"
shift
OUT_DIR="$ROOT_DIR/artifacts/desktop-worker-package"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ $# -ge 2 && -n "${2:-}" ]] || fail "--out requires a directory path"
      OUT_DIR="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

case "$SUBCOMMAND" in
  package|verify|clean-uninstall) ;;
  *) fail "unsupported subcommand: $SUBCOMMAND" ;;
esac

assert_no_symlink_in_existing_ancestors() {
  local target="$1"
  local walk="$target"
  while [[ "$walk" != "/" && "$walk" != "." ]]; do
    if [[ -L "$walk" ]]; then
      fail "symlinked path component forbidden: $walk"
    fi
    walk="$(dirname -- "$walk")"
  done
}

verify_bundle() {
  local bundle_dir="$1"
  [[ -d "$bundle_dir" && ! -L "$bundle_dir" ]] || fail "bundle directory missing or symlink: $bundle_dir"
  assert_no_symlink_in_existing_ancestors "$bundle_dir"
  local manifest_file="$bundle_dir/package-manifest.json"
  [[ -f "$manifest_file" && ! -L "$manifest_file" ]] || fail "package-manifest.json missing or symlink"

  node - "$bundle_dir" "$manifest_file" <<'NODE' || fail "bundle verification failed"
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const [bundleDir, manifestPath] = process.argv.slice(2);
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

if (
  !manifest ||
  typeof manifest !== 'object' ||
  manifest.version !== 1 ||
  manifest.package_name !== 'bke-worker-desktop' ||
  manifest.live_send_locked_false !== true ||
  manifest.execution_envelope_default_disabled !== true ||
  !manifest.files ||
  typeof manifest.files !== 'object' ||
  Array.isArray(manifest.files)
) {
  console.error('MANIFEST_SCHEMA_INVALID');
  process.exit(1);
}

const actualFiles = [];
function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    const st = lstatSync(full);
    if (st.isSymbolicLink()) {
      console.error('SYMLINK_FORBIDDEN:' + full);
      process.exit(1);
    }
    if (st.isDirectory()) {
      walk(full);
    } else if (st.isFile()) {
      const rel = relative(bundleDir, full).split(sep).join('/');
      if (rel !== 'package-manifest.json') {
        actualFiles.push(rel);
      }
    } else {
      console.error('NON_REGULAR_FILE:' + full);
      process.exit(1);
    }
  }
}
walk(bundleDir);
actualFiles.sort();

const expectedFiles = Object.keys(manifest.files).sort();
if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
  console.error('FILE_INVENTORY_MISMATCH');
  process.exit(1);
}

for (const rel of expectedFiles) {
  const expectedSha = manifest.files[rel];
  if (typeof expectedSha !== 'string' || !/^[a-f0-9]{64}$/.test(expectedSha)) {
    console.error('INVALID_SHA_FORMAT:' + rel);
    process.exit(1);
  }
  const actualSha = createHash('sha256').update(readFileSync(join(bundleDir, rel))).digest('hex');
  if (actualSha !== expectedSha) {
    console.error('SHA256_MISMATCH:' + rel);
    process.exit(1);
  }
}
NODE
  printf 'PASS: Verified %s (%s)\n' "$bundle_dir" "$SUBCOMMAND"
}

package_bundle() {
  local ext_dir="$ROOT_DIR/browser-extension"
  [[ -d "$ext_dir" && ! -L "$ext_dir" ]] || fail "browser-extension directory missing"

  # Build extension + claim/controller TypeScript targets & validate MV3 manifest
  npm --prefix "$ext_dir" run build >/dev/null
  npm --prefix "$ext_dir" run validate >/dev/null
  npm --prefix "$ext_dir" run controller:build >/dev/null

  # Verify source-level live-send locks and feature-gated defaults remain hard false
  grep -q 'export const FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const;' "$ext_dir/src/first-message-actuator.ts" \
    || fail "FIRST_MESSAGE_LIVE_SEND_ENABLED must remain locked false"
  grep -q 'export const CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const;' "$ext_dir/src/continuation-runtime.ts" \
    || fail "CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED must remain locked false"
  grep -q '^BKE_HUMAN_LIVE_SEND_AUTHORIZED=false$' "$ROOT_DIR/deploy/desktop-controller.env.example" \
    || fail "BKE_HUMAN_LIVE_SEND_AUTHORIZED must default false in deploy template"
  grep -q '^BKE_EXECUTION_ENVELOPE_ENABLED=false$' "$ROOT_DIR/deploy/desktop-controller.env.example" \
    || fail "BKE_EXECUTION_ENVELOPE_ENABLED must default false in deploy template"

  local out_parent
  out_parent="$(dirname -- "$OUT_DIR")"
  assert_no_symlink_in_existing_ancestors "$out_parent"
  mkdir -p -- "$out_parent"
  chmod 700 "$out_parent" || true

  local stage_dir
  stage_dir="$(mktemp -d "${out_parent}/.bke-pkg-stage.XXXXXX")"
  cleanup_stage() {
    if [[ -n "${stage_dir:-}" && -d "$stage_dir" ]]; then
      rm -rf -- "$stage_dir"
    fi
  }
  trap cleanup_stage EXIT

  mkdir -p \
    "$stage_dir/extension/dist" \
    "$stage_dir/native-host/claim/dist" \
    "$stage_dir/deploy" \
    "$stage_dir/scripts"

  # Copy unpacked extension runtime assets only (no node_modules or test fixtures)
  cp -- "$ext_dir/manifest.json" "$stage_dir/extension/manifest.json"
  cp -- "$ext_dir/popup.html" "$stage_dir/extension/popup.html"
  cp -R -- "$ext_dir/dist/." "$stage_dir/extension/dist/"

  # Copy native-host Node modules and compiled claim/daemon JS
  for f in entry.mjs host.mjs framing.mjs controller-host.mjs controller-protocol.mjs installation-witness.mjs linux-parent-provenance.mjs private-peer-attestor.mjs; do
    cp -- "$ext_dir/native-host/$f" "$stage_dir/native-host/$f"
  done
  cp -- "$ext_dir/native-host/claim/package.json" "$stage_dir/native-host/claim/package.json"
  cp -R -- "$ext_dir/native-host/claim/dist/." "$stage_dir/native-host/claim/dist/"

  # Copy deploy templates and operator scripts
  cp -- "$ROOT_DIR/deploy/desktop-controller.env.example" "$stage_dir/deploy/desktop-controller.env.example"
  cp -- "$ROOT_DIR/deploy/owner-native-policy.template.json" "$stage_dir/deploy/owner-native-policy.template.json"
  cp -- "$ROOT_DIR/scripts/prepare-chrome-native-host.sh" "$stage_dir/scripts/prepare-chrome-native-host.sh"
  cp -- "$ROOT_DIR/scripts/forge-f1-desktop-readiness.sh" "$stage_dir/scripts/forge-f1-desktop-readiness.sh"

  # Enforce restrictive permissions inside staged bundle
  find "$stage_dir" -type d -exec chmod 700 {} +
  find "$stage_dir" -type f -exec chmod 600 {} +
  chmod 700 "$stage_dir/scripts/prepare-chrome-native-host.sh" "$stage_dir/scripts/forge-f1-desktop-readiness.sh"

  # Generate deterministic SHA-256 manifest
  node - "$stage_dir" <<'NODE'
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const stageDir = process.argv[2];
const files = {};
const relPaths = [];

function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
    } else if (entry.isFile()) {
      relPaths.push(relative(stageDir, full).split(sep).join('/'));
    }
  }
}
walk(stageDir);
relPaths.sort();

for (const rel of relPaths) {
  files[rel] = createHash('sha256').update(readFileSync(join(stageDir, rel))).digest('hex');
}

const manifest = {
  version: 1,
  package_name: 'bke-worker-desktop',
  live_send_locked_false: true,
  execution_envelope_default_disabled: true,
  extension_manifest_version: 3,
  file_count: relPaths.length,
  files,
};
writeFileSync(join(stageDir, 'package-manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
NODE

  if [[ -L "$OUT_DIR" ]]; then
    fail "refusing symlinked destination: $OUT_DIR"
  fi
  rm -rf -- "$OUT_DIR"
  mv -- "$stage_dir" "$OUT_DIR"
  stage_dir=""
  trap - EXIT
  verify_bundle "$OUT_DIR"
}

clean_uninstall_bundle() {
  if [[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]]; then
    printf 'INFO: package directory absent (%s); nothing to uninstall.\n' "$OUT_DIR"
    return 0
  fi
  verify_bundle "$OUT_DIR"
  node - "$OUT_DIR" <<'NODE' || fail "clean-uninstall aborted"
import { readFileSync, rmSync, rmdirSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const outDir = resolve(process.argv[2]);
const manifest = JSON.parse(readFileSync(join(outDir, 'package-manifest.json'), 'utf8'));
for (const rel of Object.keys(manifest.files)) {
  rmSync(join(outDir, rel), { force: false });
}
rmSync(join(outDir, 'package-manifest.json'), { force: false });

function removeEmptyDirs(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      removeEmptyDirs(join(dir, entry.name));
    }
  }
  if (readdirSync(dir).length === 0) {
    rmdirSync(dir);
  }
}
removeEmptyDirs(outDir);
NODE
  printf 'PASS: Removed only verified package-owned artifacts from %s (Chrome profiles and user state untouched).\n' "$OUT_DIR"
}

case "$SUBCOMMAND" in
  package) package_bundle ;;
  verify) verify_bundle "$OUT_DIR" ;;
  clean-uninstall) clean_uninstall_bundle ;;
esac
