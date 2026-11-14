# Canonical Promotion Plan (`jan2xo/bke-worker-h` -> `jan2xo/bke-worker`)

This document reconciles the completed **F1 + F2** BKE Desktop Worker implementation in `jan2xo/bke-worker-h` against the canonical governance gates enforced by `jan2xo/bke-worker/.github/workflows/pr-guard.yml` (Issue `#149`).

> **Governance Reminder:** Do **NOT** open, merge, or reuse any oversized omnibus PR against `jan2xo/bke-worker` during sandbox engineering. Each canonical promotion PR requires an open `bke:mvp`-labeled GitHub issue referenced via `MVP-Task: #<issue>` in the PR body.

---

## 1. Exact `pr-guard.yml` Rules Reconciled Against Measured F1+F2 Source

Inspecting canonical `bke-worker/.github/workflows/pr-guard.yml` (lines 250–376) establishes five hard gates:

1. **500-Line Total PR Budget (ALL Files Included — Code + Tests + Docs):**
   - `pr-guard.yml:341-345` computes `files.reduce((n, f) => n + f.additions + f.deletions, 0)` across **every file in the PR**, *including test and documentation files*, unless the owner explicitly adds label `bke:oversize-ok`.
   - Therefore, splitting tests into separate PRs only helps if each PR's combined `(code + test + doc)` diff stays `<= 500` lines, OR an oversize module/test is decomposed into helper modules before canonical PR creation, OR the owner explicitly pre-authorizes `bke:oversize-ok`.
2. **Frozen Surface Allowlist Rule (`deploy/` Is Frozen Too!):**
   - `pr-guard.yml:348-356` blocks any change touching:
     `cloudflare-relay/`, `android-gecko/`, `src/`, **`deploy/`**, `BKE.Worker.sln`, `Directory.Build.props`
     unless the linked `MVP-Task: #<issue>` body/title literally contains the matching path prefix.
   - `cloudflare-relay/`, `android-gecko/`, `src/`, `BKE.Worker.sln`, and `Directory.Build.props` remain **100% untouched** in F1+F2.
   - Only `deploy/desktop-controller.env.example` (52 lines) and `deploy/owner-native-policy.template.json` (13 lines) touch `deploy/`, so that specific PR's `#<issue>` must explicitly name `deploy/`.
3. **CI / Workflow Protection Rule:**
   - Any file under `.github/` requires owner label `bke:gate-change` (`pr-guard.yml:360-362`).
   - `.github/workflows/hydrogen-sandbox-ci.yml` lives at the sandbox root (`jan2xo/bke-worker-h`) and is **excluded** from canonical `jan2xo/bke-worker` promotion; `bke-worker/.github/workflows/pr-guard.yml` itself is untouched.
4. **Added Markdown Filename Rule:**
   - Every newly added `.md` file causes `mvp-scope-gate` failure unless its **exact repo-relative filename** appears in the linked `#<issue>` body/title (`pr-guard.yml:365-369`).
5. **Exact-Head WebExtension Identity Contract:**
   - Any PR touching `browser-extension/`, `scripts/prepare-chrome-native-host.sh`, or `tests/chrome_native_host_installer_contract.py` triggers `pr-guard.yml` lines 251–297 on the exact PR head SHA: clean `npm install --ignore-scripts --no-audit --no-fund --package-lock=false`, `npm run check`, `npm run smoke:native`, `bash -n scripts/smoke-desktop-native-integration.sh`, and `git diff --check`.
   - Consequently, **no canonical PR may depend on an unmerged future PR to pass `npm run check`**; every PR in the wave must compile, pass manifest validation, and pass all existing + added tests on its own exact head SHA.

---

## 2. Measured Diff & File Sizes Requiring Decomposition Before Sub-500-Line PR Submission

### 2.1 Existing Modified Canonical Files (`bke-worker` tracked deltas)
These canonical edits total **+891 / -39** lines combined and fit easily inside `<= 500`-line PR slices:
- Build/runtime core: `browser-extension/tsconfig.json` (+1), `browser-extension/package.json` (+4), `browser-extension/native-host/claim/tsconfig.json` (+11/-1), `browser-extension/native-host/entry.mjs` (+14), `browser-extension/src/protocol.ts` (+53/-1).
- Extension gates & DOM actuator: `browser-extension/src/bootstrap-fence.ts` (+86/-3), `browser-extension/src/fresh-attempt-gate.ts` (+97/-1), `browser-extension/src/content-script.ts` (+273/-8), `browser-extension/src/service-worker.ts` (+187), `browser-extension/src/popup.ts` (+38), `browser-extension/popup.html` (+4/-1).
- Scripts & contracts: `scripts/forge-f1-desktop-readiness.sh` (+16/-12), `scripts/prepare-chrome-native-host.sh` (+3/-3), `tests/chrome_native_host_installer_contract.py` (+8/-3), `tests/chrome_native_host_installer_contract.sh` (+64/-9), `browser-extension/tests/forge-f1-readiness-policy.test.mjs` (+23).

### 2.2 Oversized New F1+F2 Modules (`> 500` lines each in `jan2xo/bke-worker-h`)
The following sandbox files currently exceed 500 lines individually and therefore **either require file-splitting into `<= 450`-line modules before opening canonical PRs OR owner label `bke:oversize-ok`**:

| File (`bke-worker/browser-extension/...`) | Current Lines | Recommended Sub-500-Line Split (or `bke:oversize-ok`) |
|---|---:|---|
| `src/controller-transport.ts` | 860 | Split P-256 handshake session (`controller-handshake.ts`, ~350) + command router/replay guard (`controller-transport.ts`, ~450). |
| `native-host/claim/github-f1-ledger.ts` | 1,106 | Split REST ref/commit CAS helpers (`github-ledger-cas.ts`, ~420), ticket/authority inspection (~400), and receipt builders (~280). |
| `native-host/claim/desktop-controller.ts` | 975 | Split `FileExecutionJournal` + POSIX lock (`file-execution-journal.ts`, ~390) from `DesktopController` orchestration (~480). |
| `native-host/claim/controller-daemon.ts` | 1,091 | Split HTTP route handler (`daemon-http-routes.ts`, ~380) + CLI/doctor (`daemon-cli.ts`, ~360) + core `DesktopControllerDaemon` (~350). |
| `native-host/claim/github-authority-provider.ts` | 539 | Extract pagination + permission-map validators (`github-authority-validators.ts`, ~180) so core provider is ~360 lines. |
| `native-host/claim/tests/controller-daemon.test.mjs` | 594 | Split into `controller-daemon-http.test.mjs` (~300) and `controller-daemon-cli-halt.test.mjs` (~295). |
| `native-host/claim/tests/reliability-adversarial.test.mjs` | 986 | Split Groups 1–3 (~440), Groups 4–5 (~300), and F2 Groups 6–7 (~320) across three focused test PRs. |
| `native-host/claim/tests/e2e-two-turn-acceptance.test.mjs` | 1,111 | Keep F1 webhook 2-turn E2E (~480), adversarial crash/drift (~180), and F2 signed-envelope E2E (~450) in separate files. |

*(Existing untouched-or-slightly-edited F1 protocol files `src/first-message-runtime.ts` [1,041], `src/continuation-runtime.ts` [894], `src/continuation-gate.ts` [774], and `src/bootstrap-fence.ts` [679] are measured only at baseline/delta; `bootstrap-fence.ts` delta is only +86/-3.)*

---

## 3. Dependency-Ordered F1 + F2 Canonical Promotion Wave

Every PR below must keep `FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const`, `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const`, `humanLiveSendAuthorized = false` default, and `executionEnvelopeEnabled = false` default.

| Wave | Proposed Canonical PR Scope | Included Files / Split Targets | Budget Strategy (`pr-guard.yml`) | Depends On | Exact-Head Verification |
|---|---|---|---|---|---|
| **PR-1** | **F1 Build Isolation, Protocol & Gate Prep** | `browser-extension/package.json`, `tsconfig.json`, `native-host/claim/tsconfig.json`, `entry.mjs`, `src/protocol.ts`, `src/bootstrap-fence.ts`, `src/fresh-attempt-gate.ts`, `tests/forge-f1-readiness-policy.test.mjs` | `~325` changed lines (`<= 500`, zero overrides) | Canonical `main` | `npm run check`, `npm run smoke:native` |
| **PR-2** | **Native Controller Bridge & Socket Client** | `native-host/controller-protocol.mjs`, `native-host/controller-host.mjs` (or split helper if paired with tests), `native-host/claim/ipc-client.ts` | ~975 lines total across 3 files -> split into **PR-2a** (`controller-protocol.mjs` + `ipc-client.ts` ~500 lines -> move `ipc-client` tests to PR-2b) + **PR-2b** (`controller-host.mjs`, 475 lines) | PR-1 | `npm run test:native`, `npm run check` |
| **PR-3** | **MV3 Target Binding, Input-Only Content Script & Popup Opt-In** | **PR-3a**: `src/target-binding.ts` (132), `src/dispatch-fence.ts` (91), `src/content-script.ts` (+273/-8) = `~496` lines; **PR-3b**: `src/service-worker.ts` (+187), `src/popup.ts` (+38), `popup.html` (+4/-1), `src/extension-browser-adapter.ts` (376) -> split `extension-browser-adapter.ts` into separate PR | Keep PR-3a `<= 500`, PR-3b `<= 380` | PR-2 | `scripts/input-only-lint.mjs`, `npm run check` |
| **PR-4** | **MV3 Controller Transport & Handshake** | Split `src/controller-transport.ts` (860) into **PR-4a** (`controller-handshake.ts`) and **PR-4b** (`controller-transport.ts` + `controller-transport.test.mjs`) | Each sub-PR `<= 480` lines | PR-2, PR-3 | `npm test`, `npm run check` |
| **PR-5** | **GitHub F1 CAS Ledger** | Split `native-host/claim/github-f1-ledger.ts` (1,106) into `github-ledger-cas.ts`, `github-f1-ledger.ts`, and `github-f1-ledger.test.mjs` across **PR-5a..c** | Each sub-PR `<= 460` lines (or 1 PR with `bke:oversize-ok`) | PR-1 | `test:host-claim` (`github-f1-ledger`) |
| **PR-6** | **Crash-Safe FileExecutionJournal & DesktopController** | Split `desktop-controller.ts` (975) into **PR-6a** (`file-execution-journal.ts` ~390 + `desktop-controller.test.mjs` 82) & **PR-6b** (`desktop-controller.ts` ~480) | Each sub-PR `<= 480` lines | PR-5 | Journal permissions/symlink + crash recovery tests |
| **PR-7** | **F2 Execution Verifier, Authority Provider & Token Lifecycle** | **PR-7a**: `github-app-harness.ts` (471); **PR-7b**: `github-authority-provider.ts` (539, split validator helper so `<= 450` + tests); **PR-7c**: `token-lifecycle.ts` (477); **PR-7d**: `github-app-harness.test.mjs` (498) | Each sub-PR `< 500` lines (`token-lifecycle.ts` tests can live in PR-7c/d within budget) | PR-1, PR-6 | Verifier, REST provider HTTP fixture, token renewal/revocation tests |
| **PR-8** | **F2 Feature-Gated Loopback Daemon, `/halt` Contract & Diagnostics** | Split `controller-daemon.ts` (1,091) into **PR-8a** (routes/daemon core), **PR-8b** (CLI/doctor), **PR-8c** (`controller-daemon.test.mjs` split) | Each sub-PR `<= 450` lines (or `bke:oversize-ok`) | PR-6, PR-7 | Loopback HTTP `/halt` (`x-bke-halt-token`), `403` default `/execution-requests`, `/status`, `controller:doctor` |
| **PR-9** | **F2 Command Center Observer Compatibility (14 States)** | **PR-9a**: `command-center-observer.ts` (408) + `docs/command-center-compatibility.md` (74); **PR-9b**: `command-center-compatibility.test.mjs` (189) | Issue must name `docs/command-center-compatibility.md`; each PR `<= 485` lines | PR-7 | 14-state fail-closed observer tests |
| **PR-10** | **F2 Multi-Process E2E & Adversarial Reliability Suites** | Split `e2e-two-turn-acceptance.test.mjs` (1,111) and `reliability-adversarial.test.mjs` (986) into `<= 480`-line suites (**PR-10a..e**) | Each test PR `<= 480` lines | PR-8, PR-9 | Full 2-turn signed-envelope E2E + Groups 1–7 adversarial tests |
| **PR-11** | **Deterministic Packaging, Templates, Installer Contracts & Docs** | **PR-11a**: `deploy/desktop-controller.env.example` (52), `deploy/owner-native-policy.template.json` (13), `scripts/package-desktop-worker.sh` (298), `scripts/forge-f1-desktop-readiness.sh` (+16/-12), `scripts/prepare-chrome-native-host.sh` (+3/-3) (`~394` lines; `#<issue>` must name `deploy/`); **PR-11b**: `tests/chrome_native_host_installer_contract.{py,sh}` + `docs/{desktop-operator-acceptance,android-reconciliation-audit,canonical-promotion-plan}.md` | Issue for PR-11a names `deploy/`; issue for PR-11b names each added `.md` file explicitly | PR-8 | `package-desktop-worker.sh`, `chrome_native_host_installer_contract.{py,sh}`, `forge_f1_desktop_mvp_contract.py` |

---

## 4. External Prerequisite & Post-Promotion Owner Acceptance Gate

1. **Trusted Real Token Broker / Server Signer (`cloudflare-relay/` Frozen):**
   - `token-lifecycle.ts` defines `ScopedTokenBrokerTransport` (`RemoteBrokerTransportStub` failing closed by default with `REAL_BROKER_TRANSPORT_DISABLED_NOT_AUTHORIZED`).
   - Connecting the real desktop token broker to `jan2xo/bke-worker` or `cloudflare-relay/` requires a **separately authorized** owner design & PR touching the frozen `cloudflare-relay/` surface (explicitly naming `cloudflare-relay/` in a dedicated issue) to mint repository/installation-scoped tokens without shipping App private keys to the desktop.
2. **Owner-Supervised Level 7 Acceptance:**
   - Even after **PR-1..PR-11** pass exact-head CI and merge into `jan2xo/bke-worker`, **Level 7** (`BKE_REAL_CHROME_ACCEPTANCE`) remains `NOT_RUN` until the human owner runs `scripts/forge-f1-desktop-readiness.sh` and supervises a live two-turn run inside an isolated Chrome profile signed into ChatGPT under owner credentials.
