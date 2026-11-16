# HYDROGEN BKE WORKER — F5 PR-1 CANONICAL PROMOTION PREPARATION HANDOFF

**FROM:** Gemini Hydrogen — Lead Implementing Engineer  
**TO:** Owner / GPT-6 — Independent Security Reviewer and BKE Systems Architect  
**SOURCE (SANDBOX):** `jan2xo/bke-worker-h` @ `8547acd4a879b8d13c75fa3468797a0b1be94232`  
**SOURCE VERIFIED CI:** `https://github.com/jan2xo/bke-worker-h/actions/runs/43790885047`  
**DESTINATION (CANONICAL):** `jan2xo/bke-worker` (`main`)  
**CANONICAL BASELINE SHA:** `a7713c8a5278d6dcb90465b7c5ca8c63ad013e07` (`docs(mvp): adopt owner-directed self review (#167)`)  
**CANONICAL MUTATION STATUS:** **`READ_ONLY_LOCAL_PREFLIGHT_ONLY`** *(Zero branches pushed, zero issues/PRs opened, zero merges or canonical edits performed on `jan2xo/bke-worker`.)*

---

## 1. Executive Summary & Reconciliation Result

Reconciling the verified F1–F4.3.1 sandbox source (`jan2xo/bke-worker-h@8547acd4a879b8d13c75fa3468797a0b1be94232`) against canonical `jan2xo/bke-worker@a7713c8a5278d6dcb90465b7c5ca8c63ad013e07` and `.github/workflows/pr-guard.yml` yields an independently buildable, self-contained **PR-1 (`F1 Foundation & Build-Isolation Preparation`)** candidate:

- **Changed Files:** `5` files (`3` modified config/manifest build files, `2` added static boundary lint files)
- **Changed-Line Budget:** **`130` total lines** (`+130` additions / `-0` deletions) — **26.0%** of `mvp-scope-gate`'s `500`-line hard limit (requiring **no** `bke:oversize-ok` label)
- **Frozen / Restricted Surfaces Touched:** `0` (`cloudflare-relay/`, `android-gecko/`, `src/`, `deploy/`, `BKE.Worker.sln`, `Directory.Build.props`, `.github/`, and added `.md` files are all `0`)
- **Unmerged Future Dependencies:** `0` (`PR-1` compiles and passes every canonical CI check directly on top of `a7713c8`)

> **Governance Note:** This handoff file (`bke-worker/docs/HYDROGEN_BKE_WORKER_F5_PR1_PROMOTION_HANDOFF.md`) is a sandbox engineering deliverable and is intentionally **not** part of the canonical PR-1 patch so PR-1 adds zero `.md` files.

---

## 2. Exact PR-1 Patch Inventory & Changed-Line Budget

### 2.1 File-Level `git diff --numstat` Against Canonical `a7713c8`

| Repo-Relative Path (`jan2xo/bke-worker`) | Change Type | Additions | Deletions | Total Delta | Purpose in F1 Foundation Wave |
|---|---|---:|---:|---:|---|
| `browser-extension/package.json` | Modified | `2` | `0` | `2` | Pins `@types/node: "22.20.5"` alongside `typescript: "5.8.3"` and adds `"controller:build": "tsc -p native-host/claim/tsconfig.json"`. |
| `browser-extension/tsconfig.json` | Modified | `1` | `0` | `1` | Adds `"types": []` so installing `@types/node` never leaks Node globals (`process`, `Buffer`, `node:*`) into the Chrome MV3 extension compilation target (`src/**/*.ts`). |
| `browser-extension/native-host/claim/tsconfig.json` | Modified | `2` | `0` | `2` | Adds `"types": ["node"]` and `"noImplicitOverride": true`, scoping Node typings exclusively to `native-host/claim/` while keeping `"include": ["send-once-claim-adapter.ts"]` valid on `main`. |
| `scripts/input-only-lint.mjs` | Added | `79` | `0` | `79` | Standalone static regression detector checking `browser-extension/src` and `android-gecko/.../worker-extension` for forbidden assistant-reply DOM reads (`innerText`, `textContent`, `innerHTML`, `outerHTML`) or reply/message-list selectors. |
| `scripts/input-only-lint.test.mjs` | Added | `46` | `0` | `46` | Unit test suite (`4` tests via `node:test`) covering positive input-composer allowances, negative DOM-text/reply-selector blocks, and directory/symlink filtering. |
| **TOTAL PR-1 DIFF** | **5 files** | **130** | **0** | **130** | **Well below `500`-line `mvp-scope-gate` ceiling (`130 <= 500`).** |

### 2.2 Exact Unified Diff (Ready to Apply on `a7713c8`)

```diff
diff --git a/browser-extension/native-host/claim/tsconfig.json b/browser-extension/native-host/claim/tsconfig.json
index dab54fa..333b965 100644
--- a/browser-extension/native-host/claim/tsconfig.json
+++ b/browser-extension/native-host/claim/tsconfig.json
@@ -9,7 +9,9 @@
     ],
     "rootDir": "../..",
     "outDir": "dist",
+    "types": ["node"],
     "strict": true,
+    "noImplicitOverride": true,
     "noUncheckedIndexedAccess": true,
     "noEmitOnError": true,
     "skipLibCheck": true
diff --git a/browser-extension/package.json b/browser-extension/package.json
index 22e5272..e35e8e5 100644
--- a/browser-extension/package.json
+++ b/browser-extension/package.json
@@ -7,6 +7,7 @@
     "node": ">=22"
   },
   "devDependencies": {
+    "@types/node": "22.20.5",
     "typescript": "5.8.3"
   },
   "scripts": {
@@ -16,6 +17,7 @@
     "check": "npm run build && npm run validate && npm test && npm run test:native && npm run test:host-claim",
     "test:native": "node --test native-host/tests/*.test.mjs",
     "smoke:native": "npm run build && node scripts/run-desktop-native-smoke.mjs",
+    "controller:build": "tsc -p native-host/claim/tsconfig.json",
     "test:host-claim": "tsc -p native-host/claim/tsconfig.json && node --test native-host/claim/tests/*.test.mjs"
   }
 }
diff --git a/browser-extension/tsconfig.json b/browser-extension/tsconfig.json
index b18e962..20cc0e0 100644
--- a/browser-extension/tsconfig.json
+++ b/browser-extension/tsconfig.json
@@ -6,6 +6,7 @@
     "lib": ["ES2022", "DOM"],
     "rootDir": "src",
     "outDir": "dist",
+    "types": [],
     "strict": true,
     "noImplicitOverride": true,
     "noUncheckedIndexedAccess": true,
```
*(Plus verbatim creation of `scripts/input-only-lint.mjs` [79 lines] and `scripts/input-only-lint.test.mjs` [46 lines] matching sandbox commit `8547acd4a879b8d13c75fa3468797a0b1be94232`.)*

---

## 3. Dependency & Reconciliation Analysis

1. **Why this exact 5-file boundary is the minimum independent PR-1:**
   - Every Node-based controller/ledger module (`ipc-client.ts`, `github-f1-ledger.ts`, `desktop-controller.ts`, `controller-daemon.ts`, `github-app-harness.ts`, `runtime-broker-factory.ts`) requires `@types/node` (`node:crypto`, `node:fs/promises`, `node:http`, `node:net`, `node:path`) under `native-host/claim/tsconfig.json`.
   - Installing `@types/node` inside `browser-extension/package.json` without setting `"types": []` in `browser-extension/tsconfig.json` would allow `@types/node` globals to silently leak into the Chrome MV3 `src/**/*.ts` compiler target.
   - Pairing both TypeScript isolation fixes with `scripts/input-only-lint.{mjs,test.mjs}` puts the static input-only DOM boundary regression detector in place *before* any F1 browser DOM actuation or runtime bridge PRs land.
2. **Intentionally deferred to later canonical PRs (avoiding broken imports or missing files on `a7713c8`):**
   - `controller:cli` and `controller:doctor` scripts in `browser-extension/package.json` (depend on `controller-daemon.ts`, deferred to the daemon wave `PR-8`).
   - Extra `include` entries in `native-host/claim/tsconfig.json` (added alongside each module's own PR so `tsc -p native-host/claim/tsconfig.json` stays green on every commit).
   - Pure protocol foundation contracts (`dispatch-fence.ts`, `ticket-contract.ts`) and runtime/installer changes (`prepare-chrome-native-host.sh`, `controller-host.mjs`, `controller-transport.ts`, `github-f1-ledger.ts`, `desktop-controller.ts`), each cleanly staged after `PR-1`.
3. **Note on `pr-guard.yml` on canonical `main` vs `hydrogen-sandbox-ci.yml`:**
   - Verified `diff -u` between `canonical/.github/workflows/pr-guard.yml` and sandbox `bke-worker/.github/workflows/pr-guard.yml` is empty (0 diff).
   - Canonical `pr-guard.yml` triggers `guard`, `bke-intent`, `webextension-device-identity` (because `browser-extension/` is modified), and `mvp-scope-gate` (`<= 500` lines, open `bke:mvp` issue via `MVP-Task: #<issue>`, zero frozen paths, zero `.github/` touches, zero added `.md` files).

---

## 4. Isolated Preflight Verification Results (Clean Canonical Checkout `a7713c8` + PR-1)

All checks below ran in a disposable clean clone of `jan2xo/bke-worker` pinned at `a7713c8a5278d6dcb90465b7c5ca8c63ad013e07` with the exact 5-file PR-1 patch applied and `node_modules/` deleted prior to installation:

| Check / Gate | Command Executed | Result | Exact Measured Output |
|---|---|---|---|
| Clean `npm install` + `npm run check` (`browser-extension/`) | `rm -rf node_modules dist native-host/claim/dist && npm install --ignore-scripts --no-audit --no-fund --package-lock=false && npm run check` | **PASS** | `tsc -p tsconfig.json` + `validate-manifest.mjs` + **142/142** extension unit tests + **36/36** native-host tests + **25/25** host-claim tests (**203/203 total**) |
| New `controller:build` script | `npm run controller:build` | **PASS** | Clean `tsc -p native-host/claim/tsconfig.json` (`0` errors) |
| MV3 vs Node Type Isolation Probes | Temporary `tsc --noEmit` probe importing `process` in `src/` vs `node:fs` in `claim/` (probes deleted after check) | **PASS** | MV3 rejects `process` with **`TS2591`** (`"types": []`); `native-host/claim/` resolves `node:fs` + `process` under `"types": ["node"]` |
| Native Smoke & Syntax | `npm run smoke:native -- --report /tmp/pr1-smoke-report.json && bash -n scripts/smoke-desktop-native-integration.sh` | **PASS** | `BKE_DESKTOP_NATIVE_SMOKE=PASS` (`9/9` assertions, `BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN`) |
| Input-Only Boundary Lint & Unit Tests | `node scripts/input-only-lint.mjs && node --test scripts/input-only-lint.test.mjs` | **PASS** | `Input-only source lint: no listed patterns (NOT runtime proof)` + **4/4** lint unit tests |
| `pr-guard.yml` `guard` Contracts (All 19 Checks) | Active workflow check (`[certify.yml, pr-guard.yml, serial-dispatcher.yml]`), 5 serial-dispatcher contracts, `android_preproduction_signing_contract.py`, `operator_entrypoint_contract.py`, `chrome_native_host_installer_contract.{py,sh}`, `forge_f1_desktop_readiness_contract.py`, `forge_f1_chrome_readiness_test.py`, `android_continuation_operator_contract.py`, `admin_preproduction_operator_contract.py`, `admin_preproduction_activation.test.mjs`, `bash -n` operator scripts | **PASS** | **37 + 12 + 10 + 12 + 27** dispatcher contract tests + **10/10** activation tests + all Python/Bash contracts **PASS** |
| Diff Hygiene & Simulated `mvp-scope-gate` | `git diff --cached --check` + exact `pr-guard.yml:338-375` rule check | **PASS** | Clean whitespace; `5` files, `130` changed lines (`<= 500`), `0` frozen paths, `0` `.github/`, `0` added `.md` files |

### Applicable Security Guarantees Preserved
- `manifest.json` untouched (`permissions: ["storage", "webNavigation"]`, `optional_permissions: ["nativeMessaging"]`, zero forbidden permissions).
- MV3 browser extension compilation strictly isolated from `@types/node` (`"types": []` verified via `TS2591` negative probe).
- Input-only browser boundary static linter passes with `0` findings across `browser-extension/src/` and `android-gecko/app/src/main/assets/worker-extension/`.
- Live ChatGPT sends remain disabled/absent (`BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN`); zero broker activation, zero Cloudflare deployment, zero production secrets, and zero frozen canonical edits.

---

## 5. Draft GitHub `bke:mvp` Issue (Exact Title & Body)

- **Target Repository:** `jan2xo/bke-worker`
- **Required Label:** `bke:mvp`
- **Issue Title:**
  ```text
  [F1 PR-1] Build isolation for Node claim adapter and input-only DOM boundary lint
  ```
- **Issue Body:**
  ```markdown
  ## Objective
  Prepare the foundational desktop F1 build-isolation and static safety-rail baseline in `jan2xo/bke-worker` before subsequent incremental F1 desktop controller and native-IPC PRs.

  ## Exact Scope (PR-1)
  - Pin `@types/node` (`22.20.5`) alongside `typescript` (`5.8.3`) in `browser-extension/package.json` and expose `"controller:build"`.
  - Isolate browser MV3 compilation (`browser-extension/tsconfig.json` with `"types": []`) from Node claim-adapter compilation (`browser-extension/native-host/claim/tsconfig.json` with `"types": ["node"]` and `"noImplicitOverride": true`).
  - Add conservative static regression detector `scripts/input-only-lint.mjs` and its `node:test` suite `scripts/input-only-lint.test.mjs` covering `browser-extension/src` and `android-gecko/app/src/main/assets/worker-extension` without modifying frozen paths.

  ## Governance & Security Bounds
  - Total change budget: 130 lines across 5 files (`<= 500` `mvp-scope-gate` cap; zero `bke:oversize-ok` exception needed).
  - No frozen canonical surfaces modified (`cloudflare-relay/`, `android-gecko/`, `src/`, `deploy/`, `BKE.Worker.sln`, `Directory.Build.props`, `.github/`).
  - No added Markdown files, no live-send enablement, no credentials, and no broker/Cloudflare activation.
  ```

---

## 6. Draft Canonical Pull Request (Conforming to `.github/pull_request_template.md`)

- **PR Title:**
  ```text
  build(f1): isolate MV3 vs Node TypeScript targets and add input-only lint
  ```
- **PR Body (replace `<issue>` with the open `bke:mvp` issue number):**
  ```markdown
  MVP-Task: #<issue>

  ## Description
  This PR establishes the first independent F1 foundation and build-preparation slice on `main` without altering runtime behavior or touching frozen surfaces:

  1. Pins `@types/node` (`22.20.5`) in `browser-extension/package.json` and adds `"controller:build": "tsc -p native-host/claim/tsconfig.json"` so future Node-targeted claim/controller modules have explicit pinned typings.
  2. Sets `"types": []` in `browser-extension/tsconfig.json` so Node ambient types never leak into the Chrome MV3 extension bundle (`src/**/*.ts`), while configuring `"types": ["node"]` and `"noImplicitOverride": true` in `browser-extension/native-host/claim/tsconfig.json`.
  3. Adds `scripts/input-only-lint.mjs` and `scripts/input-only-lint.test.mjs` as a standalone zero-dependency static regression detector verifying `browser-extension/src/` and `android-gecko/app/src/main/assets/worker-extension/` contain no DOM reply-text reads or reply/message-list selectors.

  Fixes #<issue>

  ---

  ## Type of change
  - [ ] Bug fix (non-breaking change which fixes an issue)
  - [x] New feature (non-breaking change which adds functionality)
  - [ ] Breaking change (fix or feature that changes an existing contract or behavior)
  - [ ] Documentation update
  - [ ] Performance improvement
  - [ ] Code refactoring
  - [x] Tests
  - [ ] CI / certification
  - [ ] Packaging / release infrastructure
  - [x] Security / trust-boundary change

  ---

  ## Worker Delegation
  - **Assigned worker ID:** `UNASSIGNED`
  - **Required PR label:** `UNASSIGNED (human/owner-gated promotion PR)`
  - **Expected ChatGPT target:** `N/A`

  ---

  ## How Has This Been Tested?
  ### Tested Scenarios
  - [x] Clean install in `browser-extension/` (`npm install --ignore-scripts --no-audit --no-fund --package-lock=false`), `npm run check` (`tsc` build, manifest audit, 142/142 extension unit tests, 36/36 native-host tests, 25/25 host-claim tests), `npm run controller:build`, and `npm run smoke:native` (9/9 PASS; `BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN`).
  - [x] TypeScript isolation verified negatively (`TS2591` blocks `process` under `browser-extension/tsconfig.json`) and positively (`node:fs` + `process` resolve under `native-host/claim/tsconfig.json`).
  - [x] `node scripts/input-only-lint.mjs` (0 findings) and `node --test scripts/input-only-lint.test.mjs` (4/4 PASS).
  - [x] Full `pr-guard.yml` `guard` contract suites (serial dispatcher, operator entrypoints, Chrome native-host installer `.py`/`.sh`, desktop readiness, Android contracts, admin activation 10/10 PASS).

  ### Certification
  - **Exact head:** `<PR_HEAD_SHA_AFTER_PUSH>`
  - **Required certification:** `PR Guard (guard, bke-intent, webextension-device-identity, mvp-scope-gate)`
  - **Result:** `PENDING (awaiting owner branch push and GitHub Actions run)`

  ---

  ## Architecture / Security
  - **Ownership boundaries affected:**
    - BKE Launcher: Browser extension TypeScript build config only (`types: []` isolation)
    - Licensing Agent: None
    - Digital Solutions: None
    - GitHub / release authority: None
  - **Authentication / authorization impact:** None (live sends remain absent/OFF; `manifest.json` unchanged).
  - **Persistence / migration impact:** None.
  - **Packaging / signing / provenance impact:** Pins `@types/node: "22.20.5"` devDependency in `browser-extension/package.json`; no runtime binaries or manifest changes.
  - **Fail-closed behavior:** MV3 extension compiler target explicitly sets `"types": []` to fail compilation (`TS2591`) on accidental Node global usage; `input-only-lint.mjs` exits nonzero if forbidden DOM text properties or reply selectors appear.
  - **Cross-repository dependencies:** None (sourced and preflighted from verified `jan2xo/bke-worker-h@8547acd4a879b8d13c75fa3468797a0b1be94232` onto `jan2xo/bke-worker@a7713c8a5278d6dcb90465b7c5ca8c63ad013e07`).

  ---

  ## Operator Action
  - **Required:** `NO`
  - **Entrypoint:** `N/A`
  - **Human-only inputs:** `NONE`
  - **Post-action verification:** `N/A`

  ---

  ## Checklist
  - [x] My code follows the conventions and ownership boundaries of this project
  - [x] I have performed a self-review of my changes
  - [ ] I have added screenshots for meaningful UI changes where practical
  - [x] I have updated documentation where needed
  - [x] My changes introduce no new unexplained warnings
  - [x] I have added or updated tests/certification that prove the changed behavior
  - [x] Required cross-repository dependencies are pinned to immutable SHAs/releases where applicable
  - [x] The minimum complete certification graph is declared
  - [ ] Required certification passed on the exact current head before merge
  - [x] Production/security locks remain respected unless explicitly authorized
  - [x] Any required operator action is exposed as one repo-tracked entrypoint that prompts internally only when human input is genuinely required
  - [x] This PR contains one coherent engineering intent; the next independent wave will use a fresh PR from current `main`

  ---

  ## Additional context
  ### Expected Rollback Notes
  Zero schema, state, credential, manifest, or workflow changes exist in this PR. Reverting is a clean single-commit `git revert <merge_sha>` removing the two new `scripts/input-only-lint*` files and three TypeScript/devDependency config lines.

  ### Test Plan for Reviewer
  ```bash
  cd browser-extension
  npm install --ignore-scripts --no-audit --no-fund --package-lock=false
  npm run check
  npm run controller:build
  npm run smoke:native
  cd ..
  node scripts/input-only-lint.mjs
  node --test scripts/input-only-lint.test.mjs
  ```

  ---

  ## Certification Notes
  **Required:**
  - `PR Guard` (`guard`, `bke-intent`, `webextension-device-identity`, `mvp-scope-gate`)

  **Not required:**
  - Android APK/signing builds, Cloudflare relay deploy, live Chrome Level 7 acceptance

  **Reason:**
  Zero changes to `android-gecko/`, `cloudflare-relay/`, `src/`, `.github/`, `deploy/`, or runtime message sending.

  **Environment:**
  `DEVELOPMENT`
  ```

---

## 7. Explicit Remaining Owner Action & Smallest Safe Next Step

### Remaining Owner Actions
1. Create the open tracking issue in `jan2xo/bke-worker` with label `bke:mvp` using the Section 5 title/body and note its issue number `#<issue>`.
2. On a fresh branch created from `jan2xo/bke-worker` `main` (`a7713c8a5278d6dcb90465b7c5ca8c63ad013e07`), apply the 5-file PR-1 diff from Section 2.2, push the branch, and open the single PR using the Section 6 title/body with `MVP-Task: #<issue>`.
3. Verify `PR Guard` (`guard`, `bke-intent`, `webextension-device-identity`, `mvp-scope-gate`) passes on the exact PR head SHA before merging.

### Smallest Safe Next Step
Open the `bke:mvp` issue and push/stage **only PR-1 (`130` lines, `5` files)** against `jan2xo/bke-worker@a7713c8` to establish verified CI build isolation before preparing PR-2 (`F1` pure protocol contracts / native IPC wave).

---

## 8. Machine-Readable Evidence Capsule

```json
{
  "schema_version": "bke.hydrogen.f5.pr1_promotion_candidate.v1",
  "disposition": "READY_FOR_OWNER_BRANCH_AND_PR",
  "canonical_mutated": false,
  "source_repository": "jan2xo/bke-worker-h",
  "source_verified_sha": "8547acd4a879b8d13c75fa3468797a0b1be94232",
  "source_verified_ci": "https://github.com/jan2xo/bke-worker-h/actions/runs/43790885047",
  "destination_repository": "jan2xo/bke-worker",
  "canonical_baseline_sha": "a7713c8a5278d6dcb90465b7c5ca8c63ad013e07",
  "pr_budget": {
    "max_allowed_lines": 500,
    "measured_changed_lines": 130,
    "additions": 130,
    "deletions": 0,
    "files_changed": 5,
    "oversize_label_required": false,
    "frozen_surfaces_touched": [],
    "github_workflows_touched": false,
    "added_markdown_files_in_pr": []
  },
  "files": [
    { "path": "browser-extension/package.json", "status": "modified", "additions": 2, "deletions": 0 },
    { "path": "browser-extension/tsconfig.json", "status": "modified", "additions": 1, "deletions": 0 },
    { "path": "browser-extension/native-host/claim/tsconfig.json", "status": "modified", "additions": 2, "deletions": 0 },
    { "path": "scripts/input-only-lint.mjs", "status": "added", "additions": 79, "deletions": 0 },
    { "path": "scripts/input-only-lint.test.mjs", "status": "added", "additions": 46, "deletions": 0 }
  ],
  "isolated_preflight_checks": {
    "status": "PASS",
    "browser_extension_clean_install": "PASS",
    "browser_extension_npm_run_check": "PASS (203/203: 142 extension + 36 native + 25 claim)",
    "browser_extension_controller_build": "PASS",
    "mv3_node_type_isolation_negative_probe": "PASS (TS2591)",
    "claim_node_typings_positive_probe": "PASS",
    "browser_extension_smoke_native": "PASS (9/9; BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN)",
    "input_only_lint_repo_scan": "PASS (0 findings)",
    "input_only_lint_unit_tests": "PASS (4/4)",
    "pr_guard_workflow_policy_check": "PASS",
    "pr_guard_contracts_and_shell_checks": "PASS (all 19 contract/syntax commands green)",
    "git_diff_check": "PASS",
    "mvp_scope_gate_simulation": "PASS"
  },
  "expected_ci_gates": [
    "guard (Intent + CI policy)",
    "bke-intent (BKE pinned intent consumer proof)",
    "webextension-device-identity (Exact-head WebExtension identity contract)",
    "mvp-scope-gate (MVP scope gate)"
  ],
  "security_locks": {
    "live_send_features_default_off": true,
    "real_browser_messages_sent": false,
    "broker_activated": false,
    "cloudflare_deployments": false,
    "production_credentials_present": false,
    "android_worker_activated": false
  }
}
```
