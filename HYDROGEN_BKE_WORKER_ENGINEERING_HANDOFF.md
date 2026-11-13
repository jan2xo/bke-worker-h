# BKE WORKER — HYDROGEN ENGINEERING KNOWLEDGE TRANSFER

**From:** Gemini Hydrogen — Lead Implementing Engineer  
**To:** GPT-6 — Independent Engineering Reviewer and BKE Systems Architect  
**Subject:** Technical Handoff & Verification Evidence for BKE Worker (`FORGE F1` Desktop Worker MVP & Runtime Completion)  
**Verified Implementation Repository / Commit:** `https://github.com/jan2xo/bke-worker-h` @ `bbf40c92f0a9a3776143556c0734421980f3e4a4`  
**Verified Green CI Run:** `https://github.com/jan2xo/bke-worker-h/actions/runs/43435024253` (`Hydrogen Sandbox CI`, conclusion `success`, job `131917763342`)  
**Canonical Target Repository (Untouched / Read-Only Reference):** `https://github.com/jan2xo/bke-worker` (`bke-worker/.git` HEAD `a7713c8a5278d6dcb90465b7c5ca8c63ad013e07`)  
**Reference Command Center Repository (Untouched / Read-Only Reference):** `https://github.com/jan2xo/bke-command-center` (`main = f120c6f`)  

> **Provenance & Certification Notice:** GitHub Actions run `43435024253` certifies source commit `bbf40c92f0a9a3776143556c0734421980f3e4a4`. This engineering handoff Markdown file (`HYDROGEN_BKE_WORKER_ENGINEERING_HANDOFF.md`) was authored strictly *after* that green CI run without modifying any application code, build script, or test. If this document is subsequently synchronized to `jan2xo/bke-worker-h`, the resulting documentation commit SHA will be distinct from `bbf40c92f0a9a3776143556c0734421980f3e4a4`, and run `43435024253` must not be represented as CI certification of any post-`bbf40c92f0a9a3776143556c0734421980f3e4a4` commit.

---

## 1. Executive Technical Summary

### Objective Inherited
Complete the unfinished **BKE Worker Desktop `FORGE F1` (`F1-01` through `F1-06`)** runtime and surrounding operational, authority, observability, reliability, and packaging surfaces in `bke-worker`, while preserving strict human-only gates (`FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const`, `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const`), zero credential/cookie automation, zero assistant-reply DOM reads (input-only browser boundary), and untouched canonical/legacy frozen surfaces (`cloudflare-relay/`, `android-gecko/`, `src/` .NET projects, `bke-worker/.github/workflows/`).

### Concrete State Before vs After Hydrogen
- **Before Hydrogen:**
  - `browser-extension/` contained F1 protocol state machines (`fresh-attempt-gate.ts`, `bootstrap-fence.ts`, `first-message-actuator.ts`, `first-message-runtime.ts`, `continuation-gate.ts`, `continuation-runtime.ts`), `device-identity.ts`, `native-proof-client.ts`, and `native-host/{entry,host,framing}.mjs`, plus minimal `native-host/claim/send-once-claim-adapter.ts` (`GitHubSendOnceRestAdapter`), while the end-to-end runtime controller, persistent MV3 controller bridge, DOM target/content actuation, durable GitHub F1 CAS ledger, GitHub App execution request harness, Command Center observer adapter, adversarial reliability tests, and packaging scripts were incomplete or unintegrated.
  - Sandbox CI and packaging for nested `bke-worker-h/` had no dedicated clean workflow, `native-host/claim/tsconfig.json` and `browser-extension/tsconfig.json` build isolation needed clean compilation under strict TypeScript without node-type pollution across MV3 vs Node targets, and an initial staged PR (`0f7c47e97dd24e0c1403eedcea7a728ede25db4f`, CI run `43418289442`) against `jan2xo/bke-worker` failed `PR Guard` (`Exact-head WebExtension identity contract` step 6 and `MVP scope gate` 500-line/path budget).
- **After Hydrogen (`bbf40c92f0a9a3776143556c0734421980f3e4a4`):**
  - Complete **Desktop F1 execution chain** implemented and verified with multi-process loopback + synthetic GitHub/Chrome doubles: GitHub webhook/CLI (`controller-daemon.ts`) -> `FileExecutionJournal` & `DesktopController` (`desktop-controller.ts`) -> `GitHubF1Ledger` (`github-f1-ledger.ts`) -> `IpcBridgeClient` (`ipc-client.ts`) over private `0o700`/`0o600` Unix socket -> `entry.mjs --controller-bridge` + `controller-host.mjs` (`CONTROLLER_BRIDGE_V1` P-256 native messaging bridge) -> MV3 `service-worker.ts` + `controller-transport.ts` + `extension-browser-adapter.ts` + `target-binding.ts` + `content-script.ts`.
  - Complete **Workstream C** server-private `GitHubAuthorityProvider` / `ExecutionRequestVerifier` 14-field canonical HMAC-SHA256 execution-request harness (`github-app-harness.ts`).
  - Complete **Workstream D** read-only 9-concept `COMMAND_CENTER_COMPATIBILITY_MATRIX` & fail-closed `projectWorkerStateForCommandCenter` observer (`command-center-observer.ts` + `docs/command-center-compatibility.md`).
  - Complete **Workstream E** adversarial crash, journal tampering, IPC disconnect, GitHub pagination/5xx/CAS-uncertainty, and browser drift chaos tests (`reliability-adversarial.test.mjs`).
  - Complete **Workstream F/G** deterministic non-secret desktop packaging (`package-desktop-worker.sh`), non-secret templates (`deploy/`), operator/Android/promotion documentation (`bke-worker/docs/`), and repaired sandbox CI (`/.github/workflows/hydrogen-sandbox-ci.yml`) running green (`43435024253`).

### What Is Verified vs What Remains Explicitly Unfinished / Human-Gated
- **Verified in Sandbox CI (`43435024253`) & Local Re-Verification:** Clean `browser-extension` build + MV3 manifest validation, 202/202 extension unit tests, 39/39 native-host tests, 42/42 host-claim/daemon/harness/observer/reliability/2-turn E2E tests, 4/4 `input-only-lint` tests, 10/10 admin activation tests, 191/191 Cloudflare relay tests + reconnect recovery test, all Python & Bash contract tests, deterministic packaging/verify/clean-uninstall, and `certify-forge-f1-desktop-mvp.sh --sandbox --dry-run`.
- **Deliberately Unfinished / Human-Only / Out-of-Scope:**
  - **Level 7 Live Real-Chrome + Real-ChatGPT + Real-GitHub 2-turn acceptance (`BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN`)**: Hard-blocked from CI/automation by design; live-send compile-time switches stay `false as const`.
  - **Wiring `ExecutionRequestVerifier` into `DesktopControllerDaemon` and adapting Cloudflare `/github/app/install-token` for Desktop**: Implemented & tested standalone in `github-app-harness.ts`, not yet integrated into `controller-daemon.ts` HTTP ingress or `cloudflare-relay/src/github-app.js` (frozen path).
  - **Chrome Web Store / packaged `.crx` distribution, real Chrome `runtime.connectNative()` testing, `.NET` `BKE.Worker.sln` verification (`dotnet` absent in container), Android emulator verification, and canonical `jan2xo/bke-worker` PR promotion** (`PR-1`..`PR-7` documented in `bke-worker/docs/canonical-promotion-plan.md`).

---

## 2. Repository Architecture & Topology

### Dual-Level Sandbox Layout (`jan2xo/bke-worker-h` vs `jan2xo/bke-worker`)
In the AI Studio workspace (`jan2xo/bke-worker-h`), the original `jan2xo/bke-worker` repository sits nested inside `/app/applet/bke-worker/` beneath an outer Vite/React workspace root:

| Path (from `jan2xo/bke-worker-h` root) | Role & Notes |
|---|---|
| `/.github/workflows/hydrogen-sandbox-ci.yml` | Active GitHub Actions CI for `jan2xo/bke-worker-h` (runs clean install, build, tests, `--sandbox --dry-run`, Cloudflare checks, Python/Bash contracts, packaging). |
| `/src/App.tsx`, `/index.html`, `/package.json`, `/vite.config.ts` | Minimal AI Studio Vite/React UI displaying locked `LOCKED FALSE` status and verification commands (replaces earlier temporary patch-export UI removed in commit `191f7e89`). No `/api/*` backend, no runtime secrets. |
| `/public/` | Empty directory (`total 0`) — prior temporary patch/attachment files from `d6626d00`/`191f7e89` were removed. |
| `/HYDROGEN_BKE_WORKER_ENGINEERING_HANDOFF.md` | Root copy of this handoff report (also copied to `/bke-worker/docs/HYDROGEN_BKE_WORKER_ENGINEERING_HANDOFF.md`). |
| `/bke-worker/.git` | Embedded git clone of canonical `jan2xo/bke-worker` at HEAD `a7713c8a5278d6dcb90465b7c5ca8c63ad013e07`. Note: this `.git` metadata caused nested-repo path mismatch when running root-expecting scripts from `bke-worker-h/` until fixed in CI/test harness. |
| `/bke-worker/browser-extension/` | **Primary Desktop FORGE F1 implementation**: Chrome MV3 extension (`src/`, `manifest.json`, `popup.html`), Native Host (`native-host/*.mjs`), Claim/Ledger/Daemon/Harness/Observer (`native-host/claim/*.ts`). |
| `/bke-worker/scripts/` | Bash/Node/Python certification, readiness, Chrome native-host installer, input-only AST lint, and deterministic packaging scripts. |
| `/bke-worker/tests/` | Python, Node, and Bash security & contract verification suites. |
| `/bke-worker/deploy/` | Non-secret environment (`desktop-controller.env.example`) and owner policy (`owner-native-policy.template.json`) templates. |
| `/bke-worker/docs/` | Operator runbook, Command Center compatibility spec, Android reconciliation audit, canonical PR-1..PR-7 promotion plan, plus this handoff. |
| `/bke-worker/cloudflare-relay/` | **Frozen / Untouched**: Cloudflare Worker + Durable Object relay (`src/github-app.js`, etc.) serving Android OIDC broker & admin catalog. |
| `/bke-worker/android-gecko/` | **Frozen / Untouched**: Android Kotlin GeckoView host + MV2 probe extension (`worker-probe.js`). |
| `/bke-worker/src/` & `/bke-worker/BKE.Worker.sln` | **Frozen / Untouched**: Legacy .NET 8/9 projects (`BKE.Worker.{Core,ChatGPT,GitHub,Server}` + test projects). |
| `/bke-worker/.github/workflows/pr-guard.yml` | **Frozen / Untouched**: Canonical PR guard enforcing 500-line MVP diff budget and frozen-surface checks on `jan2xo/bke-worker`. |

### Component Topology & Trust Boundaries
```
[Human Owner / GitHub Webhook]
   |  (HMAC-SHA256 x-hub-signature-256 + x-github-delivery | CLI)
   v
DesktopControllerDaemon (127.0.0.1:31940 only)  <--->  FileExecutionJournal (0o600, O_NOFOLLOW, atomic rename)
   |  [controller-daemon.ts -> desktop-controller.ts]
   +---> GitHubF1Ledger (github-f1-ledger.ts) <===> GitHub REST API (pinned bke-ticket:v1 + refs/bke/* CAS)
   |
   +---> IpcBridgeClient (ipc-client.ts)
           |  [Unix domain socket in 0o700 dir, 0o600 socket, peer UID check, 1 in-flight lock]
           v
Native Messaging Host: entry.mjs --controller-bridge -> controller-host.mjs
           |  [stdio 4-byte LE framing; P-256 IEEE-P1363 challenge-response; 0o600 owner-policy.json O_NOFOLLOW]
           v
Chrome MV3 Extension: service-worker.ts <-> controller-transport.ts <-> extension-browser-adapter.ts
   |  (strict popup click unlocks optional nativeMessaging; durable consumedBridgeAttempts in storage.local)
   +---> target-binding.ts (webNavigation frameId=0 census, exact 1 https://chatgpt.com/* non-incognito tab)
   +---> content-script.ts (input-only DOM: textarea/#prompt-textarea write + single sendButton.click() + /c/<id> URL read)
```

---

## 3. Chronological Implementation History (A–G + GitHub Forensic Audit)

### Canonical Validation Stage (`jan2xo/bke-worker`)
- **Commit `0f7c47e97dd24e0c1403eedcea7a728ede25db4f`** (`test(f1): stage Hydrogen desktop MVP candidate for GitHub validation`, referencing `MVP-Task: #149`, 39 files, +10,590 lines):
  - **PR Guard CI Run `https://github.com/jan2xo/bke-worker/actions/runs/43418289442`:**
    - `Intent + CI policy` (`131861593532`): `success`
    - `BKE pinned intent consumer proof` (`131861594026`): `success`
    - `Exact-head WebExtension identity contract` (`131861593834`): `failure` at step 6 `Build, manifest audit and adversarial P-256 tests` (steps 7, 9, 10 skipped; exact runner stdout of step 6 is not anonymously retrievable via unauthenticated GitHub API).
    - `MVP scope gate` (`131861593929`): `failure` at step 2 `Enforce MVP scope (issue` — inspecting `/bke-worker/.github/workflows/pr-guard.yml` shows `pr-guard.yml` rejects PRs with >500 changed lines without the owner label `bke:oversize-ok`, and rejects edits under frozen paths/added Markdown files without explicit issue authorization.
  - Because `jan2xo/bke-worker` is owner-protected, Hydrogen engineering shifted to the authorized sandbox repository `jan2xo/bke-worker-h` and decomposed future canonical merges into a 7-PR plan (`canonical-promotion-plan.md`).

### Sandbox Engineering & CI Progression (`jan2xo/bke-worker-h`)

| Commit SHA | Timestamp (UTC) | Summary of Work / Fix | CI Run & Result | Causal Failure / Resolution |
|---|---|---|---|---|
| `8f598e2c2e8be82bb36c6c5a6351980de67528e1` | `2026-11-13T11:42:45Z` | Initial commit | — | Workspace initialization. |
| `605c9268e72805d8264a247c09fd94f6a8e4abbd` | `2026-11-13T11:43:48Z` | `feat: initialize BKE worker project structure` | — | Imported `bke-worker/` baseline. |
| `d6626d00e34c503384da68318020eea358d9f0f5` | `2026-11-13T12:18:16Z` | Completed Workstreams A–G source implementation + initial CI (`feat: implement BKE worker patch export interface`) | [`43424035577`](https://github.com/jan2xo/bke-worker-h/actions/runs/43424035577) — **FAILURE** at step 6 (`Run certification harness in explicit sandbox dry-run mode`) | **Causal defect:** `actions/setup-node@v4` on `ubuntu-latest` provisions `node` owned by UID `1001` (`runner`) with mode `777`. `chrome_native_host_installer_contract.py` invoked `prepare-chrome-native-host.sh` passing that `real_node` without `--owner-only` copy; `safe_runtime()` in `prepare-chrome-native-host.sh:146-153` only exempts `owner=0` with `BKE_NATIVE_HOST_TEST_NODE_PATH` unset, so it rightly rejected `group-or-world-writable` `mode=777 owner=1001`. |
| `191f7e89b4e134a26fa12e54f5073678b568194f` | `2026-11-13T13:19:31Z` | `refactor: remove web patch export and update security tests` (updated `chrome_native_host_installer_contract.{py,sh}`, `canonical-promotion-plan.md`, `hydrogen-sandbox-ci.yml`, `src/App.tsx`, `vite.config.ts`) | [`43432692560`](https://github.com/jan2xo/bke-worker-h/actions/runs/43432692560) — **FAILURE** at step 8 (`Verify operator, Android & security contracts`) | Step 5 (extension build/tests), Step 6 (`certify-forge-f1-desktop-mvp.sh --sandbox --dry-run`), and Step 7 (Cloudflare relay) **PASSED**. Step 8 failed at `bash tests/chrome_native_host_installer_contract.sh` with `FAIL-CLOSED: must run the canonical tracked entrypoint path.` **Causal defect:** `git rev-parse --show-toplevel` resolved parent `bke-worker-h/`, not nested `bke-worker/`, so `$SCRIPT_PATH` (`.../bke-worker/scripts/prepare-chrome-native-host.sh`) failed `$ROOT_DIR/scripts/prepare-chrome-native-host.sh` (`prepare-chrome-native-host.sh:17`). |
| `bbf40c92f0a9a3776143556c0734421980f3e4a4` | `2026-11-13T13:35:45Z` | `test: refactor native host installer contract` (`bke-worker/tests/chrome_native_host_installer_contract.sh` +56/-7) | [`43435024253`](https://github.com/jan2xo/bke-worker-h/actions/runs/43435024253) — **SUCCESS** (12/12 steps passed, `13:35:47Z`–`13:36:45Z`) | Repaired the shell test harness without weakening `prepare-chrome-native-host.sh`: creates a disposable `0o700` Git repo at `$tmp/repo` with tracked `scripts/prepare-chrome-native-host.sh`, `manifest.json`, `entry.mjs`, `host.mjs`, `framing.mjs`, and a private `0o700` copy of Node (`safe_node`), while still asserting rejection of `0o777` `unsafe_node`, symlinks, and invalid origins. |

### Workstream Map (A–G)
- **Workstream A (MV3 + Native Host + E2E Desktop Runtime)**: `service-worker.ts`, `popup.ts`, `target-binding.ts`, `content-script.ts`, `dispatch-fence.ts`, `controller-transport.ts`, `extension-browser-adapter.ts`, `entry.mjs`, `controller-host.mjs`, `controller-protocol.mjs`, `ipc-client.ts`.
- **Workstream B (GitHub F1 CAS Ledger + Loopback Controller Daemon)**: `github-f1-ledger.ts`, `desktop-controller.ts`, `controller-daemon.ts`, `tests/e2e-two-turn-acceptance.test.mjs`, `tests/desktop-controller.test.mjs`, `tests/controller-daemon.test.mjs`, `tests/github-f1-ledger.test.mjs`.
- **Workstream C (GitHub App Authority Harness)**: `github-app-harness.ts`, `tests/github-app-harness.test.mjs`.
- **Workstream D (Command Center Read-Only Compatibility)**: `command-center-observer.ts`, `docs/command-center-compatibility.md`, `tests/command-center-compatibility.test.mjs`.
- **Workstream E (Adversarial Reliability & Chaos Suite)**: `tests/reliability-adversarial.test.mjs`.
- **Workstream F (Deterministic Packaging, Installer Contracts, Sandbox CI, Docs)**: `scripts/package-desktop-worker.sh`, `deploy/*`, `docs/{desktop-operator-acceptance,android-reconciliation-audit,canonical-promotion-plan}.md`, `tests/chrome_native_host_installer_contract.*`, `.github/workflows/hydrogen-sandbox-ci.yml`.
- **Workstream G (Reconciliation & Cleanup)**: Removed temporary web patch UI (`d6626d00`) and temporary `/public` artifacts; cleanly updated `src/App.tsx` and sandbox dry-run mode.

---

## 4. Detailed Design & Implementation Breakdown

### 4.1 Chrome MV3 Extension (`bke-worker/browser-extension/src/`)
Compiled strictly via `bke-worker/browser-extension/tsconfig.json` (`types: []`, `strict: true`, `outDir: "dist"`).
- **Manifest (`manifest.json`)**: MV3, `minimum_chrome_version: "116"`, required `permissions: ["storage", "webNavigation"]`, `optional_permissions: ["nativeMessaging"]` (never auto-requested), `host_permissions: ["https://chatgpt.com/*"]`. Prohibited permissions (`cookies`, `debugger`, `history`, `identity`, `webRequest`) are asserted absent by build validation & certification scripts.
- **Service Worker (`service-worker.ts`, 531 lines)**:
  - Sets `chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" })`.
  - Persists durable send-once consumed bridge attempts under key `"bke.consumedBridgeAttempts.v1"` (hydrated before any controller bridge startup and bounded to avoid unbounded growth).
  - Maintains `targetBinding` (`createChatGptTargetBinding`), `controllerSupervisor` (`createControllerBridgeSupervisor`), `pendingConnect` gate, and popup origin verification (`isTrustedPopup`).
  - Handles explicit `connectController` (checking optional `nativeMessaging` permission), `disconnectController`, `getBridgeStatus`, `checkTarget`, and dispatches serialized through `withTargetLock`.
- **Popup (`popup.ts`, 217 lines & `popup.html`)**:
  - Only user gesture on `#connect-controller` triggers `chrome.permissions.request({ permissions: ["nativeMessaging"] })`.
  - Validates local policy JSON file size (`<= 4096` bytes) before relaying `connectController` message to service worker.
- **Target Binding (`target-binding.ts`, 133 lines)**:
  - Queries all `https://chatgpt.com/*` tabs, filters out incognito tabs, verifies main-frame (`frameId: 0`) via `chrome.webNavigation.getFrame`, and refuses dispatch unless **exactly 1** non-incognito top-level ChatGPT tab matches (`AMBIGUOUS_TARGETS` / `NO_TARGET` / `INCOGNITO_FORBIDDEN`).
- **Content Script (`content-script.ts`, 362 lines)**:
  - **Strict Input-Only DOM**: Queries composer elements (`#prompt-textarea`, `textarea[data-id]`, `div[contenteditable="true"]#prompt-textarea`) and send/stop controls; never reads assistant replies, `.markdown`, `article`, `innerText`, `textContent` of messages, or `innerHTML`.
  - Turn 1 asserts landing URL (no `/c/<id>`), writes prompt, invokes `sendButton.click()` **strictly once** inside try/finally, and polls `location.href` for `/c/<uuid>` emergence.
  - Turn 2+ asserts URL already matches `expectedConversationId`, writes prompt, invokes `sendButton.click()` **strictly once**, and fails closed if URL drifts or opens a new `/c/<other>` thread.
- **Dispatch Fence (`dispatch-fence.ts`, 92 lines)**:
  - `DispatchFence` (single active in-memory token) + `ConsumedAttemptRegistry` backed by persistent MV3 storage so service-worker restarts never replay an already-attempted `(prNumber, attemptId)` bridge command.
- **Controller Transport (`controller-transport.ts`, 861 lines)**:
  - `connectControllerNativeBridge` executes P-256 ECDH/ECDSA `CONTROLLER_BRIDGE_V1` mutual authentication over `NativePort`, validates command schemas strictly (`ACTION_KEYS` exact sorted keys for `PING`, `GET_TARGET_STATUS`, `PREPARE_FIRST_MESSAGE`, `DISPATCH_FIRST_MESSAGE`, `PREPARE_CONTINUATION`, `DISPATCH_CONTINUATION`, `HALT`), enforces monotonic `seq`, bounded TTL (`100..60_000` ms, `MAX_CLOCK_SKEW_MS = 5000`), and `seenCommandIds` replay protection.
  - Any port disconnect while an active dispatch is in-flight marks the bridge session quarantined (`EXTENSION_BRIDGE_UNCERTAIN`).
- **Browser Adapter & Protocol Engines (`extension-browser-adapter.ts`, `first-message-actuator.ts`, `first-message-runtime.ts`, `continuation-runtime.ts`, `ticket-contract.ts`)**:
  - `ExtensionBrowserAdapter` bridges `IpcBridgeClient` commands cleanly into `FirstMessageBrowserPort` (`.asFirstMessagePort()`) and `ContinuationBrowserPort` (`.asContinuationPort()`).
  - `validateTicketInventory` parses `bke-ticket:v1:<worker-id>:<attempt-id>:<expires-unix-seconds>`, enforces pinned app `{ id, slug }` (rejecting `github-actions` or spoofed check runs), and checks expiry.
  - `FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const` (`first-message-actuator.ts:21`) and `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const` (`continuation-runtime.ts:29`) remain hard-locked `false`. Inert entrypoints (`runFirstMessageAttempt`, `runContinuationAttempt`) always return blocked; supervised execution (`executeFirstMessageWithAdapters`, `executeContinuationWithAdapters`) additionally requires `humanLiveSendAuthorized === true` and all three `FirstMessageLiveProofs` (`githubCasOwnerCertified`, `nativePairingOwnerCertified`, `realBrowserOwnerAccepted`).

### 4.2 Native Messaging Host & Unix IPC (`bke-worker/browser-extension/native-host/`)
Plain Node 22 ESM modules (`entry.mjs`, `host.mjs`, `framing.mjs`, `controller-host.mjs`, `controller-protocol.mjs`, plus `installation-witness.mjs`, `linux-parent-provenance.mjs`, `private-peer-attestor.mjs`):
- **`entry.mjs` (61 lines)**: Reads owner-pinned policy JSON using `open(policyPath, O_RDONLY | O_NOFOLLOW)`, asserts regular file, size `<= 4096` bytes, mode `(mode & 0o022) === 0`, owner UID match, and dispatches either proof-only handshake (`runNativeProofHost`) or persistent controller bridge (`--controller-bridge` / `BKE_CONTROLLER_IPC_SOCKET`).
- **`host.mjs` (149 lines)**: Validates `validNativeHostPolicy` (exact keys, SHA-256 hashes, `expires_at_ms` within 30 days) and emits `admission_authority: "NONE"`, `dispatch_authority: "NONE"` for standalone proof mode.
- **`controller-protocol.mjs` (210 lines)**: Shared validator for the 7 allowed IPC/bridge commands (`PING`, `GET_TARGET_STATUS`, `PREPARE_FIRST_MESSAGE`, `DISPATCH_FIRST_MESSAGE`, `PREPARE_CONTINUATION`, `DISPATCH_CONTINUATION`, `HALT`) + `CommandReplayGuard`. Rejects arbitrary prompt/command fields outside exact schema.
- **`controller-host.mjs` (476 lines)**:
  - Performs WebCrypto P-256 (`IEEE-P1363` signature) mutual handshake with extension's non-exportable `device-identity.ts` key.
  - Creates private `0o700` socket parent (`ensurePrivateSocketDir`) with `0o600` Unix domain socket.
  - **Fail-closed IPC semantics**: Only one active command in-flight at a time; if native stdio disconnects, times out, or socket breaks mid-dispatch, transitions bridge to `quarantined` and refuses further dispatches.

### 4.3 Claim, CAS Ledger, Journal & Loopback Daemon (`bke-worker/browser-extension/native-host/claim/`)
Compiled separately via `bke-worker/browser-extension/native-host/claim/tsconfig.json` (`types: ["node"]`, `rootDir: "../.."`, `outDir: "dist"`).
- **`ipc-client.ts` (292 lines)**: `assertSafeIpcSocketPath` verifies non-symlink `0o700` parent dir owned by current UID, regular Unix socket `0o600` owned by current UID. `IpcBridgeClient` enforces single `inFlight` lock and self-quarantines (`isQuarantined() === true`) on any ambiguous socket write/timeout/mid-flight close.
- **`github-f1-ledger.ts` (1107 lines)** & **`send-once-claim-adapter.ts` (197 lines)**:
  - Enforces pagination fail-closed (`Link: rel="next"` header causes immediate failure—no silent partial reads on PRs, check runs, or refs).
  - `refreshAuthority()` validates repository push permission, enumerates open PRs expecting **exact 1:1** match (`openPrCountForWorker === 1 && workerLabelsOnPr === 1` for `bke-worker:<workerId>`), validates live `head.sha`, rejects if any `refs/bke/uncertain/{pr}/*` ref exists, and verifies pinned `bke-ticket:v1` check run.
  - Implements GitHub REST CAS Git ref protocol with mandatory read-back verification and sanitized errors (never leaks tokens):
    - `refs/bke/fences/{pr}/{attempt}` (pre-send lease)
    - `refs/bke/claims/{pr}/{attempt}` (irreversible send-once claim via `GitHubSendOnceRestAdapter`)
    - `refs/bke/uncertain/{pr}/{attempt}` (written immediately on any 5xx/timeout/ambiguous submit failure; permanent quarantine)
    - `refs/bke/conversations/{pr}` (Turn 1 conversation binding commit/ref)
    - `refs/bke/turns/{pr}/{attempt}` (per-turn immutable confirmation receipt)
- **`desktop-controller.ts` (569 lines)**:
  - `verifyGitHubWebhookSignature`: constant-time `timingSafeEqual` HMAC-SHA256 verification on raw HTTP body (`sha256=<hex>`).
  - `FileExecutionJournal`: opens with `O_NOFOLLOW`, rejects symlinks (`JOURNAL_SYMLINK_FORBIDDEN`), enforces regular file + `0o600` (`(mode & 0o077) === 0`, throwing `JOURNAL_PERMISSIONS_INSECURE` on `0o644`) + UID ownership; writes atomically via `.tmp` + `fsync()` + `rename()`.
  - **Fail-closed crash recovery**: If process restarts while `phase === 'DISPATCHING' || phase === 'CONTINUING'`, `openAndRecover()` immediately promotes journal to `DELIVERY_UNCERTAIN` (`uncertainReason: "CRASH_DURING_DISPATCHING" | "CRASH_DURING_CONTINUING"`) with zero auto-retry.
  - `DesktopController.handleWebhookWake`: enforces single-flight concurrency lock (`busy`), deduplicates `processedDeliveries` (bounded rolling 512 entries), auto-routes `confirmedTurnCount === 0 && conversationId === null` to Turn 1 (`executeFirstMessageWithAdapters`) vs existing `conversationId` to Turn 2+ (`executeContinuationWithAdapters`).
- **`controller-daemon.ts` (704 lines)**:
  - `DesktopControllerDaemon`: validates loopback-only bind (`127.0.0.1`, `::1`, or `localhost`, default `127.0.0.1:31940`), max 262,144-byte HTTP body.
  - Routes: `GET /healthz`, `GET /status` (no secrets), `POST /halt` (checks `x-bke-halt-token` via constant-time SHA-256 `timingSafeEqual`), `POST /webhooks/github` (`pull_request`, `pull_request_target`, `check_run`, `bke_wake`).
  - CLI (`runCli`): `doctor`, `status`, `halt`, `start [--dry-run] [--owner-supervised-live-send]`. Enabling `humanLiveSendAuthorized: true` requires **both** `--owner-supervised-live-send` CLI flag **and** `BKE_OWNER_SUPERVISED_LIVE_SEND=I_OWNER_AUTHORIZE_LIVE_SEND` **plus** all three `BKE_CERT_*` env proofs set to `"true"`.

### 4.4 GitHub App Authority Harness & Command Center Observer
- **`github-app-harness.ts` (388 lines)**:
  - Defines 14-field canonical `ExecutionRequestEnvelopeV1` (`action`, `attempt_id`, `authorized_capability: 'GITHUB_F1_EXECUTION_V1'`, `delivery_id`, `expires_at`, `head_sha`, `installation_identity`, `issued_at`, `pr_number`, `protocol_version: 1`, `repository_id`, `repository_name`, `repository_owner`, `worker_id`) serialized deterministically in alphabetical key order (`serializeCanonicalExecutionEnvelope`) and signed via `HMAC-SHA256` (`signExecutionRequestHmac`).
  - `ExecutionRequestVerifier.verifyAndAuthorize()` validates wrapper shape, `key_id` lookup, `timingSafeEqual` HMAC, repo/id/installation/worker pinning, TTL `<= 300_000` ms + `5_000` ms clock skew, monotonic non-replay (`seenDeliveries`, `seenAttempts`), and live queries via `GitHubAuthorityProvider` (installation scope with `push: true`, 1:1 exclusive worker PR check, exact `head.sha`, pinned check-run ticket, and `refs/bke/uncertain/*` / consumed attempt checks).
- **`command-center-observer.ts` (279 lines)**:
  - Exports 9-concept `COMMAND_CENTER_COMPATIBILITY_MATRIX` (3 `CONSUMED_BY_COMMAND_CENTER_TODAY`, 6 `PROPOSED_OBSERVER_ADAPTER`) and pure fail-closed projector `projectWorkerStateForCommandCenter(ev)`: any stale timestamp (`nowMs - observedAtMs > maxStaleMs`), non-atomic snapshot (`atomicRevalidated === false`), missing evidence, unauthenticated ChatGPT tab, tab count != 1, or `DELIVERY_UNCERTAIN` / `HALTED` forces `dispatchReady = false` and never upgrades `realBrowserAcceptance` from `NOT_RUN` unless explicitly owner-accepted.

---

## 5. Preserved Security Guarantees & Non-Negotiable Constraints

| Guardrail | Mechanism & File Enforcement | Bypass Resistance |
|---|---|---|
| **Locked-False Live Send** | `FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const` (`first-message-actuator.ts:21`), `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const` (`continuation-runtime.ts:29`), `humanLiveSendAuthorized: false` default (`controller-daemon.ts`). | Checked verbatim by `certify-forge-f1-desktop-mvp.sh:114-121`, `package-desktop-worker.sh:160-163`, and `forge_f1_desktop_mvp_contract.py:27-28`. Supervised daemon start additionally requires CLI flag + `I_OWNER_AUTHORIZE_LIVE_SEND` + all 3 `BKE_CERT_*` env vars. |
| **Input-Only Browser Boundary** | `content-script.ts` only locates composer input & send button and observes `location.href` (`/c/<id>`). Zero reads of assistant text or message DOM lists. | Enforced across `browser-extension/src/` and `android-gecko/.../worker-extension/` by AST/regex linter `scripts/input-only-lint.mjs` (4/4 negative/positive unit tests). |
| **Least-Privilege MV3 Permissions** | `manifest.json` requests only `["storage", "webNavigation"]` and `["https://chatgpt.com/*"]`; `nativeMessaging` is `optional_permissions`. | Explicitly denies `cookies`, `debugger`, `history`, `identity`, `webRequest` (`forge-f1-desktop-readiness.sh:334-340`, `prepare-chrome-native-host.sh`, `chrome_native_host_installer_contract.sh:67-70`). Popup requests `nativeMessaging` only on explicit user button click. |
| **Fail-Closed Crash & Uncertainty Quarantine** | Any crash during `DISPATCHING`/`CONTINUING`, ambiguous `POST /git/refs`, mid-flight IPC socket disconnect, or stalled click after `sendButton.click()` promotes `FileExecutionJournal` to `DELIVERY_UNCERTAIN` and writes `refs/bke/uncertain/*`. | Zero auto-retry anywhere in `DesktopController`, `GitHubF1Ledger`, or `IpcBridgeClient`. All subsequent wakes return HTTP `409` (`BLOCKED`) until manual owner audit & journal rotation. |
| **Exact Origin / Symlink / Mode Hardening** | `O_NOFOLLOW`, UID checks, `0o700` dir / `0o600` regular file enforced by `FileExecutionJournal`, `entry.mjs`, `ipc-client.ts`, `prepare-chrome-native-host.sh`, `package-desktop-worker.sh`, and `forge-f1-desktop-readiness.sh`. | Installer also verifies canonical tracked Git entrypoint path, refuses `chmod 777` runtimes, uses `ln` no-clobber links with inode-checked rollback, and requires SHA-256 verification. |
| **Zero Secret / Auth / Cookie Automation** | Daemon never reads Chrome `Cookies`, `Local Storage`, or `Preferences`; HTTP `/status`, `/healthz`, and error throws sanitize tokens (`send-once-claim-adapter.ts`). | All GitHub/webhook/halt tokens are runtime-injected via private `0o600` env/policy files; deploy templates contain placeholders only. |
| **1:1 PR Worker Exclusivity & Replay Guard** | Live PR enumeration checks `openPrCountForWorker === 1 && workerLabelsOnPr === 1`, exact `head.sha`, pinned app ID/slug ticket, `DispatchFence`, `ConsumedAttemptRegistry`, and `seenDeliveries`. | Pagination `Link: rel="next"` headers fail closed rather than allowing silent partial scans. |

---

## 6. Frozen & Untouched Surfaces Audit

| Surface | Path | Modified? | Verification Run on Surface | Status / Notes |
|---|---|---|---|---|
| **Cloudflare Relay & GitHub App Broker** | `bke-worker/cloudflare-relay/` | **NO (Untouched)** | `npm run check` (**191/191 PASS**), `npm run reconnect-recovery-test` (**PASS**), `python3 tests/cloudflare_relay_contract.py` (**PASS**) | Pins `CONTROL_REPOSITORY = "jan2xo/bke-worker"`, `CONTROL_REPOSITORY_ID = "1354026486"`, Actions OIDC `SERIAL_WORKFLOW_REF`, and `BKE_WORKER_ID = android-worker-a` (`github-app.js:1-16`). |
| **Android GeckoView Host & Probe** | `bke-worker/android-gecko/` | **NO (Untouched)** | `scripts/input-only-lint.mjs`, `tests/android_gecko_probe_contract.py` (**PASS**), `tests/android_recovery_operator_contract.py` (**PASS**) | Historical issues `#90` and `#135` remain quarantined/unmerged (`docs/android-reconciliation-audit.md`). `admin_preproduction_activation.test.mjs` (**10/10 PASS**). |
| **Legacy .NET Controller** | `bke-worker/src/`, `bke-worker/BKE.Worker.sln`, `bke-worker/Directory.Build.props` | **NO (Untouched)** | Not run (`dotnet` CLI is not installed in the container) | Preserved intact (`BKE.Worker.{Core,ChatGPT,GitHub,Server}` + test projects). |
| **Canonical PR Guard Workflow** | `bke-worker/.github/workflows/pr-guard.yml` | **NO (Untouched)** | Inspected & used to structure `canonical-promotion-plan.md` | Enforces 500-line MVP diff gate and frozen path protection on `jan2xo/bke-worker`. |
| **BKE Command Center Repo** | `jan2xo/bke-command-center` (`main = f120c6f`) | **NO (Untouched, read-only reference)** | Contract compatibility verified via 9-row matrix & 8 fail-closed tests (`command-center-compatibility.test.mjs` **2/2 PASS**) | Observer adapter (`command-center-observer.ts`) lives inside `bke-worker` ready for read-only integration. |

---

## 7. Complete Verification Matrix (Exact Commands, Scopes & Results)

All commands below were executed directly against this codebase (and in clean GitHub Actions runner `ubuntu-latest` on commit `bbf40c92f0a9a3776143556c0734421980f3e4a4`, run `43435024253` using Node `22` / Python `3.11`; locally verified on Node `v22.23.2` / Python `3.10.12`).

| Suite / Command (run inside `bke-worker/` unless noted) | Exact Pass Count & Outcome | What It Actually Proves | What It Does **NOT** Prove |
|---|---|---|---|
| `npm --prefix browser-extension run build && npm --prefix browser-extension run validate && npm --prefix browser-extension run controller:build` | **PASS** (0 TS errors; `tsc` strict) | Clean TypeScript compilation of MV3 extension (`tsconfig.json`, DOM/WebExtension types without `@types/node`) and Claim/Daemon/Harness (`native-host/claim/tsconfig.json`, Node types) + MV3 manifest permission audit. | Does not bundle/test `.crx` signing or load into real Google Chrome. |
| `npm --prefix browser-extension test` | **202/202 PASS** | Unit & protocol state-machine logic: `bootstrap-fence`, `continuation-gate`, `continuation-runtime`, `controller-transport`, `device-identity`, `dispatch-fence`, `extension-browser-adapter`, `first-message-actuator`, `first-message-runtime`, `fresh-attempt-gate`, `native-proof-client`, `target-binding`, `ticket-contract`, `content-script` DOM selectors (synthetic DOM mocks). | Does not prove live `chatgpt.com` CSS selector stability or real Chrome `chrome.*` IPC APIs. |
| `npm --prefix browser-extension run test:native` | **39/39 PASS** | `entry.mjs`, `host.mjs`, `framing.mjs`, `controller-host.mjs`, `controller-protocol.mjs`, P-256 challenge-response handshake, 4-byte stdio framing, `O_NOFOLLOW`/`0o600` policy enforcement, replay/quarantine logic. | Does not prove Chrome browser native-messaging launch permissions on macOS/Linux. |
| `npm --prefix browser-extension run smoke:native` | **PASS** (`BKE_DESKTOP_NATIVE_SMOKE=PASS`) | Spawns real Node `entry.mjs` subprocess and exercises native proof handshake with ephemeral non-exportable P-256 WebCrypto keys. | Explicitly outputs `BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN`; uses synthetic policy, not Chrome. |
| `npm --prefix browser-extension run test:host-claim` | **42/42 PASS** | Breakdown: `send-once-claim-adapter.test.mjs` (**25/25**), `reliability-adversarial.test.mjs` (**5/5**), `github-f1-ledger.test.mjs` (**3/3**), `desktop-controller.test.mjs` (**2/2**), `e2e-two-turn-acceptance.test.mjs` (**2/2**), `github-app-harness.test.mjs` (**2/2**), `command-center-compatibility.test.mjs` (**2/2**), `controller-daemon.test.mjs` (**1/1**). Exercises real loopback HTTP server, real `0o700` Unix socket, real `0o600` atomic `FileExecutionJournal` & crash-to-quarantine recovery, real `entry.mjs --controller-bridge` subprocess, and full 2-turn synthetic turn routing. | GitHub REST endpoints and Chrome DOM / MV3 runtime APIs are mocked via local in-process doubles. Zero live network/GitHub/ChatGPT sends. |
| `node scripts/input-only-lint.mjs && node --test scripts/input-only-lint.test.mjs` | **PASS (4/4)** | Verifies zero prohibited assistant-reply selectors or DOM text reads (`innerText`, `textContent`, `innerHTML`, `outerHTML`) in `browser-extension/src/` and `android-gecko/.../worker-extension/`, plus 4 negative/positive fixture checks. | Static lexical/AST guardrail only; script itself prints `(NOT runtime proof)`. |
| `npm --prefix cloudflare-relay run check && npm --prefix cloudflare-relay run reconnect-recovery-test` | **191/191 PASS** + **PASS** | Verifies untouched Cloudflare Worker / Durable Object protocol, GitHub App OIDC token broker checks, and Android reconnect recovery planner. | Does not test live Cloudflare deployment or Wrangler secrets. |
| `python3 tests/chrome_native_host_installer_contract.py` & `bash tests/chrome_native_host_installer_contract.sh` | **PASS** (both) | Verifies transactional Chrome native host installer (`prepare-chrome-native-host.sh`): `0o700` Node binary passes, `0o777` Node fails, symlinks/alternate paths/bad origins/invalid args fail closed, rollback removes only SHA-256-matched artifacts, Chrome user state untouched. | Runs against isolated temp Git repo & sandbox dirs, not live macOS/Linux Chrome profile. |
| `python3` operator/F1/Android/Cloudflare contract tests (`forge_f1_desktop_mvp_contract.py`, `operator_entrypoint_contract.py`, `android_gecko_probe_contract.py`, `android_recovery_operator_contract.py`, `cloudflare_relay_contract.py`) | **ALL PASS** | Structural/behavioral contracts for F1 certification script, operator entrypoints, Android probe/recovery negative paths, and Cloudflare relay boundaries. | Static/fixture contracts only; Android & `.NET` runtimes unexecuted. |
| `node --test tests/admin_preproduction_activation.test.mjs` | **10/10 PASS** | Verifies Cloudflare Access admin preproduction activation fail-closed checks and anonymous-access denial probes. | Uses `globalThis.fetch` mocks. |
| `bash scripts/package-desktop-worker.sh package / verify / clean-uninstall` | **PASS** (CI `43435024253`) | Builds deterministic non-secret bundle (`live_send_locked_false: true`), writes SHA-256 `package-manifest.json`, verifies every file mode/regular-file/digest, cleanly deletes only manifest-owned files. | Does not sign binaries or install into Chrome. |
| `bash scripts/certify-forge-f1-desktop-mvp.sh --sandbox --dry-run` | **PASS** (`SOURCE_ACCEPTANCE=PASS`) | Aggregates `check`, `input-only-lint`, `smoke:native`, and Python installer contract under `--sandbox`; asserts live-send gates locked `false`; reports `BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN reason=DRY_RUN_MODE`. | Never launches Google Chrome or performs live sends. |

---

## 8. Test, Build & CI Environments

### Observed Runtimes & Toolchains
- **GitHub Actions CI (`.github/workflows/hydrogen-sandbox-ci.yml`)**: `ubuntu-latest`, Node `22` (`actions/setup-node@v4`), Python `3.11` (`actions/setup-python@v5`), `persist-credentials: false`, clean dependency install via `npm install --ignore-scripts --no-audit --no-fund --package-lock=false` (avoiding lifecycle scripts and root lockfile drift).
- **Local AI Studio Container**: Node `v22.23.2`, Python `3.10.12`, Linux x86_64; **`dotnet` is NOT installed** (`DOTNET_NOT_INSTALLED`); Google Chrome desktop UI, Android SDK/emulator, and Cloudflare live Wrangler deployments are absent in CI/container.

### Notable Environment Traps Disclosed
1. **GitHub Runner `actions/setup-node@v4` Mode `777`:** On GitHub `ubuntu-latest`, `process.execPath` resolves to an owner-`1001` (`runner`) `0o777` Node executable, causing `prepare-chrome-native-host.sh:146-153` to reject it as group/world-writable unless test fixtures isolate an owner-`0o700` binary copy (resolved cleanly in `chrome_native_host_installer_contract.{py,sh}`). Note: if a real operator on Linux/macOS installs Node with group/world write bits (`0o777` or `0o775`), the production installer will deliberately fail closed—use a `0o755`/`0o700` owner-or-root-owned Node binary.
2. **Nested `bke-worker/` Repo Root Resolution:** In `jan2xo/bke-worker-h`, `bke-worker/` sits beneath parent `bke-worker-h/`, AND `/app/applet/bke-worker/.git` existed locally. `prepare-chrome-native-host.sh:12,17` and `forge-f1-desktop-readiness.sh` expect `git rev-parse --show-toplevel` to equal the `bke-worker` directory itself and `origin` to equal `jan2xo/bke-worker`. Consequently:
   - `certify-forge-f1-desktop-mvp.sh` requires `--sandbox --dry-run` on `jan2xo/bke-worker-h`.
   - `prepare-chrome-native-host.sh` and `forge-f1-desktop-readiness.sh` only run for real against a clean `main` clone of canonical `jan2xo/bke-worker`.
3. **Separate TypeScript Configs (`browser-extension/tsconfig.json` vs `native-host/claim/tsconfig.json`):** `browser-extension/tsconfig.json` deliberately sets `"types": []` and excludes `native-host/claim/` to guarantee browser runtime modules never depend on Node APIs, whereas `native-host/claim/tsconfig.json` uses `"types": ["node"]` and `"rootDir": "../.."` (emitting into `browser-extension/native-host/claim/dist/native-host/claim/*.js` and `.../dist/src/*.js`). Notice that tests in `native-host/claim/tests/` import compiled extension helpers from `../../../dist/*.js` and compiled claim/daemon modules from `../dist/native-host/claim/*.js`—always run `npm run build` AND `npm run controller:build` (both are included in `npm run check`) before executing tests directly.

---

## 9. How to Operate, Test, Debug & Inspect Safely

All commands run from `bke-worker/` with **zero live ChatGPT sends, zero browser automation, and zero credential exposure**:

```bash
# 1. Clean TypeScript build + MV3 manifest validation + all 202 + 39 + 42 tests
npm --prefix browser-extension run check

# 2. Input-only AST/regex boundary lint + tests
node scripts/input-only-lint.mjs
node --test scripts/input-only-lint.test.mjs

# 3. Daemon environment doctor (Node >=22, 0o600 journal, 0o700 socket dir, LOCKED_FALSE defaults)
npm --prefix browser-extension run controller:doctor

# 4. Safe controller dry-run (journal recovery check, exits immediately, no network listener)
BKE_JOURNAL_PATH=/tmp/bke-dryrun.json \
  npm --prefix browser-extension run controller:cli -- start --dry-run

# 5. Inspect journal state or trigger emergency halt without secrets
BKE_JOURNAL_PATH=/tmp/bke-dryrun.json \
  npm --prefix browser-extension run controller:cli -- status
BKE_JOURNAL_PATH=/tmp/bke-dryrun.json \
  npm --prefix browser-extension run controller:cli -- halt "MANUAL_AUDIT"

# 6. Sandbox F1 certification dry-run (jan2xo/bke-worker-h)
bash scripts/certify-forge-f1-desktop-mvp.sh --sandbox --dry-run

# 7. Deterministic desktop bundle package -> verify -> clean-uninstall
bash scripts/package-desktop-worker.sh package --out /tmp/bke-pkg-test
bash scripts/package-desktop-worker.sh verify --out /tmp/bke-pkg-test
bash scripts/package-desktop-worker.sh clean-uninstall --out /tmp/bke-pkg-test

# 8. Cloudflare relay suite & contract checks (untouched surface verification)
npm --prefix cloudflare-relay run check
npm --prefix cloudflare-relay run reconnect-recovery-test
python3 tests/forge_f1_desktop_mvp_contract.py
python3 tests/chrome_native_host_installer_contract.py
bash tests/chrome_native_host_installer_contract.sh
```

**Debugging `DELIVERY_UNCERTAIN` / `HALTED`:** Run `controller:cli -- status` to inspect `phase`, `confirmedTurnCount`, `conversationId`, and `uncertainReason`. Because quarantine is intentionally non-auto-recoverable, resolution requires human inspection of the ChatGPT thread and `refs/bke/*` Git refs before manually archiving/rotating the local journal file.

---

## 10. Known Gaps, Limitations & Subtle Issues Found

The following real technical gaps and code-vs-doc discrepancies were observed directly in source and must be addressed cleanly before canonical activation or live Level 7 acceptance:

1. **Docs vs Code Mismatch on HTTP `/halt` Auth Header & Quarantine Status Code (Real Defect Found):**
   - **Code (`controller-daemon.ts:368`):** `POST /halt` reads `req.headers['x-bke-halt-token']`.
   - **Docs (`docs/desktop-operator-acceptance.md:82`):** The operator curl snippet documents `-H "Authorization: Bearer $BKE_OPERATOR_HALT_TOKEN"`. Calling `/halt` with `Authorization: Bearer ...` currently returns `403 OPERATOR_HALT_UNAUTHORIZED`!
   - **HTTP Quarantine Status Code:** `controller-daemon.ts:450` returns HTTP **`409`** (`Conflict`) for any `outcome.status === 'BLOCKED'` (including `DELIVERY_UNCERTAIN`), whereas `docs/desktop-operator-acceptance.md:91` states **`HTTP 423`** (`Locked`). Align one to the other during canonical PR cleanup.
2. **Hardcoded Canonical Repository Check in Protocol Actuators:**
   - `first-message-actuator.ts:23` and `continuation-runtime.ts:31` hardcode `const CANONICAL_REPOSITORY = "jan2xo/bke-worker"`. While `DesktopControllerDaemon` accepts `BKE_REPOSITORY` (defaulting to `jan2xo/bke-worker`), any live attempt run against an external sandbox/staging repo other than `jan2xo/bke-worker` will fail `isSafeRequest` / `isSafeContinuationRequest` inside the actuator/runtime. Intentional safety lock for now, but important to note when planning staged repository testing.
3. **`ExecutionRequestVerifier` Not Yet Wired into Live `DesktopControllerDaemon` or Cloudflare Broker:**
   - `github-app-harness.ts` (`ExecutionRequestVerifier`) is thoroughly implemented and tested (21 adversarial cases in `github-app-harness.test.mjs`), **but** `DesktopControllerDaemon` currently accepts raw GitHub webhooks (`x-hub-signature-256`) + static `BKE_GITHUB_INSTALLATION_TOKEN` env var rather than enforcing `SignedExecutionRequestV1` envelopes from a server-side authority broker.
   - Furthermore, `cloudflare-relay/src/github-app.js` (`/github/app/install-token`) currently accepts only GitHub Actions OIDC (`token.actions.githubusercontent.com`) with hardcoded `SERIAL_WORKFLOW_REF` (`serial-dispatcher.yml@refs/heads/main`) and `BKE_WORKER_ID = android-worker-a`—it does **not** yet issue short-lived installation tokens or signed `ExecutionRequestEnvelopeV1` payloads for Desktop F1 workers.
4. **Live ChatGPT DOM Selector Fragility Untested Against Live `chatgpt.com`:**
   - `content-script.ts` uses heuristic selectors (`#prompt-textarea`, `textarea[data-id]`, `div[contenteditable="true"]#prompt-textarea`, send/stop `button[data-testid]`) tested only against synthetic DOM doubles. OpenAI DOM changes could break composer/button detection or busy-state heuristics; Level 7 human testing is required to confirm real selector compatibility.
5. **Unrun Components in Container:**
   - `.NET` solution (`bke-worker/BKE.Worker.sln`, `src/`) was not compiled or tested (`dotnet` CLI missing).
   - Real Chrome extension load, native messaging manifest registration in `$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts/` (macOS) or `~/.config/google-chrome/NativeMessagingHosts/` (Linux), and live ChatGPT two-turn execution remain **`NOT_RUN`**.
   - Local desktop controller daemon has no OS launchd/systemd service unit included; it runs explicitly in foreground (`controller:cli -- start`).
6. **Desktop Token Injection Limitation:**
   - `controller-daemon.ts:659` passes `() => process.env.BKE_GITHUB_INSTALLATION_TOKEN ?? ''` to `GitHubF1Ledger`. Because GitHub App installation tokens expire after 1 hour, long-running unattended desktop sessions would need a token-refresh callback rather than a static process-start env var.
7. **Canonical `pr-guard.yml` 500-Line Budget vs Multi-File Promotion:**
   - Consolidating all Hydrogen changes into a single PR against `jan2xo/bke-worker` triggers `pr-guard.yml` `MVP scope gate` (`MAX = 500` changed lines) unless broken into the 7 sequential PRs in `docs/canonical-promotion-plan.md` or explicitly labeled `bke:oversize-ok` by the repository owner.

---

## 11. Exact File Inventory & Symbol Map

### Root & CI Files (`jan2xo/bke-worker-h`)
- `/.github/workflows/hydrogen-sandbox-ci.yml`: Clean CI workflow (Node 22, Python 3.11, isolated extension install/build/test/smoke, `--sandbox --dry-run`, Cloudflare relay check, Python/Bash contract tests, deterministic packaging).
- `/src/App.tsx`: Read-only workspace status page (53 lines); `/package.json`, `/index.html`, `/vite.config.ts`.

### Desktop Runtime & MV3 Extension (`bke-worker/browser-extension/`)
- `manifest.json`: MV3 (`minimum_chrome_version: "116"`, `permissions: ["storage", "webNavigation"]`, `optional_permissions: ["nativeMessaging"]`, `host_permissions: ["https://chatgpt.com/*"]`).
- `popup.html`, `src/popup.ts` (217 lines): User-gesture-only `nativeMessaging` permission prompt (`#connect-controller`) + policy JSON validation (`<= 4096` bytes).
- `src/service-worker.ts` (531 lines): `TRUSTED_CONTEXTS` storage, persistent `"bke.consumedBridgeAttempts.v1"`, `targetBinding`, `controllerSupervisor`, `withTargetLock`, `dispatchFirstMessage`, `dispatchContinuation`, `getTargetStatus`.
- `src/target-binding.ts` (133 lines): `createChatGptTargetBinding` (single non-incognito top-level `chatgpt.com` tab enforcement via `webNavigation.getFrame`).
- `src/content-script.ts` (362 lines): `handleDispatch`, input-only composer write, single `sendButton.click()`, `/c/<id>` navigation/continuation verification.
- `src/dispatch-fence.ts` (92 lines): `DispatchFence`, `ConsumedAttemptRegistry`.
- `src/controller-transport.ts` (861 lines): `CONTROLLER_BRIDGE_V1`, `connectControllerNativeBridge`, `createControllerBridgeSupervisor`, `validateIncomingControllerCommand`, replay guard, disconnect quarantine.
- `src/extension-browser-adapter.ts` (377 lines): `ExtensionBrowserAdapter`, `.asFirstMessagePort()`, `.asContinuationPort()`.
- `src/device-identity.ts`: Non-exportable WebCrypto P-256 identity bridge.
- `src/native-proof-client.ts`: Native messaging origin/proof helper (`NATIVE_HOST_NAME = "bke.worker.desktop"`).
- `src/ticket-contract.ts` (105 lines): `validateTicketInventory` (`bke-ticket:v1:<worker-id>:<attempt-id>:<expires>`).
- `src/first-message-actuator.ts` (268 lines): **`FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const`**, `FirstMessageLiveProofs`, `buildApprovedBootstrapPrompt`, `evaluateFirstMessageActuator`, `evaluateFirstMessageConfirmation`.
- `src/first-message-runtime.ts` (1042 lines): `FirstMessageLedgerPort`, `FirstMessageBrowserPort`, `executeFirstMessageWithAdapters`, inert `runFirstMessageAttempt`, synthetic `runFirstMessageProtocolSimulation`.
- `src/continuation-runtime.ts` (895 lines): **`CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const`**, `ContinuationLedgerPort`, `ContinuationBrowserPort`, `executeContinuationWithAdapters`, inert `runContinuationAttempt`, synthetic `runContinuationProtocolSimulation`.
- `src/fresh-attempt-gate.ts`, `src/bootstrap-fence.ts`, `src/continuation-gate.ts`: Pure state-machine evaluators for landing page readiness, pre-send fences, and Turn 2+ gating.

### Native Host, Claim, Ledger, Daemon, Harness & Observer (`bke-worker/browser-extension/native-host/`)
- `entry.mjs` (61 lines): `readOwnerPinnedPolicy` (`O_RDONLY | O_NOFOLLOW`, `<= 4096` bytes, `0o022` check), routes proof mode vs `--controller-bridge`.
- `host.mjs` (149 lines): `validNativeHostPolicy`, `nativeProofMessage`, `runNativeProofHost` (`admission_authority: "NONE"`, `dispatch_authority: "NONE"`).
- `framing.mjs`: 4-byte little-endian Chrome native messaging stdio framing.
- `controller-protocol.mjs` (210 lines): `validateControllerCommand`, `validateCommandResult`, `CommandReplayGuard` (7 actions).
- `controller-host.mjs` (476 lines): `runNativeControllerBridge`, P-256 handshake, `ensurePrivateSocketDir`, Unix IPC server, `quarantined` state on mid-flight disconnect.
- `claim/tsconfig.json`, `claim/package.json` (`{"private": true, "type": "module"}`).
- `claim/ipc-client.ts` (292 lines): `assertSafeIpcSocketPath`, `IpcBridgeClient` (single `inFlight` lock, self-quarantine).
- `claim/send-once-claim-adapter.ts` (197 lines): `GitHubSendOnceRestAdapter` (F1-02 HTTP CAS claim writer + error sanitization).
- `claim/github-f1-ledger.ts` (1107 lines): `GitHubF1Ledger` (`refreshAuthority`, `commitPreSendFence`, `consumeClaimInternal`, `reconcileConversation`, `reconcileContinuationTurn`, `markDeliveryUncertain`, `refs/bke/*` CRUD, strict pagination fail-closed).
- `claim/desktop-controller.ts` (569 lines): `JournalPhase`, `verifyGitHubWebhookSignature`, `FileExecutionJournal` (`O_NOFOLLOW`, `0o600`, atomic temp+fsync+rename, crash-to-`DELIVERY_UNCERTAIN`), `DesktopController.handleWebhookWake`, Turn 1 vs Turn 2+ orchestration.
- `claim/controller-daemon.ts` (704 lines): `extractWebhookPrAndHead`, `DesktopControllerDaemon` (loopback HTTP `127.0.0.1:31940`, `/healthz`, `/status`, `/halt`, `/webhooks/github`), `runControllerDoctor`, `runCli` (`doctor|status|halt|start`).
- `claim/github-app-harness.ts` (388 lines): `ExecutionRequestEnvelopeV1`, `SignedExecutionRequestV1`, `GitHubAuthorityProvider`, `serializeCanonicalExecutionEnvelope`, `signExecutionRequestHmac`, `ExecutionRequestVerifier`.
- `claim/command-center-observer.ts` (279 lines): `COMMAND_CENTER_COMPATIBILITY_MATRIX` (9 rows), `RawWorkerObserverEvidence`, `CommandCenterWorkerProjection`, `projectWorkerStateForCommandCenter`.

### Scripts, Deploy Templates, Docs & Contracts (`bke-worker/`)
- `scripts/certify-forge-f1-desktop-mvp.sh` (162 lines): F1 source/smoke/contract harness (`--sandbox --dry-run`).
- `scripts/prepare-chrome-native-host.sh` (365 lines): User-level Chrome native messaging host installer/verifier/rollback.
- `scripts/forge-f1-desktop-readiness.sh` (402 lines) & `scripts/forge_f1_chrome_readiness.py`: Human-supervised Chrome profile isolation & readiness checks.
- `scripts/package-desktop-worker.sh` (294 lines): Deterministic bundle + SHA-256 manifest packager/verifier/clean-uninstaller.
- `scripts/smoke-desktop-native-integration.sh` (64 lines), `scripts/run-desktop-native-smoke.mjs`, `scripts/input-only-lint.mjs`, `scripts/input-only-lint.test.mjs`, `scripts/admin_preproduction_activation.mjs`.
- `deploy/desktop-controller.env.example` (42 lines), `deploy/owner-native-policy.template.json` (14 lines).
- `docs/command-center-compatibility.md`, `docs/desktop-operator-acceptance.md`, `docs/android-reconciliation-audit.md`, `docs/canonical-promotion-plan.md`, `docs/HYDROGEN_BKE_WORKER_ENGINEERING_HANDOFF.md`.
- `tests/chrome_native_host_installer_contract.{py,sh}`, `tests/forge_f1_desktop_mvp_contract.py`, `tests/admin_preproduction_activation.test.mjs`, plus `browser-extension/native-host/claim/tests/{command-center-compatibility,controller-daemon,desktop-controller,e2e-two-turn-acceptance,github-app-harness,github-f1-ledger,reliability-adversarial,send-once-claim-adapter}.test.mjs`.

---

## 12. Independent Review Checklist for GPT-6

Verify the following specific invariants directly in code before approving canonical promotion (`jan2xo/bke-worker`):
1. **Default-Off Live Send Gates:** Confirm `FIRST_MESSAGE_LIVE_SEND_ENABLED === false` (`first-message-actuator.ts:21`), `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED === false` (`continuation-runtime.ts:29`), and `humanLiveSendAuthorized` in `controller-daemon.ts:654-656` requires explicit opt-in flag + literal env string `I_OWNER_AUTHORIZE_LIVE_SEND`.
2. **Quarantine Non-Recoverability:** Inspect `FileExecutionJournal.openAndRecover` (`desktop-controller.ts:170-179`), `IpcBridgeClient` (`ipc-client.ts`), `controller-host.mjs`, and `GitHubF1Ledger.markDeliveryUncertain` (`github-f1-ledger.ts`) to confirm zero retry loops after ambiguous sends/crashes/disconnects.
3. **Input-Only DOM Boundary:** Inspect `content-script.ts` + `scripts/input-only-lint.mjs` to ensure zero message/assistant-reply text extraction exists or can be bypassed via dynamic property access.
4. **Canonical Packaging & Manifest Hygiene:** Confirm `package-desktop-worker.sh` excludes `node_modules`, test fixtures, tokens, `.git`, and asserts `live_send_locked_false === true`; confirm `manifest.json` contains zero elevated permissions beyond `storage`, `webNavigation`, optional `nativeMessaging`, and `https://chatgpt.com/*`.
5. **Reconcile `/halt` Header & Status Code Defect:** Compare `controller-daemon.ts:368,450` (`x-bke-halt-token`, HTTP `409`) against `docs/desktop-operator-acceptance.md:82,91` (`Authorization: Bearer`, HTTP `423`) and verify which contract should be standardized prior to `PR-3`/`PR-7`.
6. **Authority Provider Gap:** Review `github-app-harness.ts` vs `controller-daemon.ts` and `cloudflare-relay/src/github-app.js` to validate the threat model of static `BKE_GITHUB_INSTALLATION_TOKEN` injection on desktop before adding broker integration.
7. **Command Center Fail-Closed Guarantees:** Review `projectWorkerStateForCommandCenter` (`command-center-observer.ts:149-278`) and confirm no missing/stale/non-atomic state can evaluate to `dispatchReady: true` or `OWNER_ACCEPTED`.
8. **Canonical PR-Guard Compatibility:** Verify each planned PR in `bke-worker/docs/canonical-promotion-plan.md` obeys `bke-worker/.github/workflows/pr-guard.yml` (<=500 lines or explicit owner `bke:oversize-ok`, zero unintended touches to `cloudflare-relay/`, `android-gecko/`, `src/`, `.github/`).

---

## 13. Recommended Next Steps (Canonical Promotion & Level 7 Readiness)

1. **Resolve Documented Contract Mismatch (Small Cleanup PR / Pre-Promotion Fix):**
   - Align `POST /halt` authentication header (`x-bke-halt-token` vs `Authorization: Bearer`) and blocked/quarantined HTTP status (`409` vs `423`) across `controller-daemon.ts` and `docs/desktop-operator-acceptance.md`.
2. **Execute Dependency-Ordered Promotion into `jan2xo/bke-worker` (`PR-1` through `PR-7`):**
   - Follow `bke-worker/docs/canonical-promotion-plan.md`:
     - **PR-1**: Build isolation (`tsconfig.json`, `native-host/claim/tsconfig.json`, `package.json`) + `FileExecutionJournal` / `DesktopController`.
     - **PR-2**: Hardened `ipc-client.ts`, durable MV3 `consumedBridgeAttempts`, opt-in `popup.ts`.
     - **PR-3**: Loopback `controller-daemon.ts` + E2E tests.
     - **PR-4**: `github-app-harness.ts` (`ExecutionRequestVerifier`).
     - **PR-5**: `command-center-observer.ts` + `docs/command-center-compatibility.md`.
     - **PR-6**: `reliability-adversarial.test.mjs` chaos suite.
     - **PR-7**: `package-desktop-worker.sh`, `deploy/` templates, fixed `chrome_native_host_installer_contract.{py,sh}`, and operator/reconciliation docs.
   - *(Note: Verify actual git diff line counts per PR against `pr-guard.yml`'s 500-line ceiling; obtain owner `bke:oversize-ok` where cohesive modules exceed 500 lines).*
3. **Wire `ExecutionRequestVerifier` & Short-Lived Token Refresh (Post-MVP Security Upgrade):**
   - Route wake commands from server-side dispatcher/broker using `SignedExecutionRequestV1` into `DesktopControllerDaemon`, and replace static `BKE_GITHUB_INSTALLATION_TOKEN` env lookup with a bounded refresh provider.
4. **Human-Only Level 7 Real-Chrome Acceptance (`BKE_REAL_CHROME_ACCEPTANCE`, Owner-Executed):**
   - From a clean canonical `jan2xo/bke-worker` `main` checkout:
     1. Run `bash scripts/forge-f1-desktop-readiness.sh` on macOS/Linux to create `~/.bke-worker/f1/chrome-profile` (`0o700`), manually sign into ChatGPT, load the unpacked extension, and register `bke.worker.desktop` via `prepare-chrome-native-host.sh install` using a private `0o600` `owner-policy.json`.
     2. In Chrome popup, explicitly click **Connect controller bridge (opt-in)** and grant `nativeMessaging`.
     3. Assign 1 isolated test PR (`bke-worker:<id>`) + pinned `bke-ticket:v1` check run, start `controller-daemon` with `--owner-supervised-live-send` + `BKE_OWNER_SUPERVISED_LIVE_SEND=I_OWNER_AUTHORIZE_LIVE_SEND`, verify 1st turn creates `/c/<uuid>` and `refs/bke/conversations/<pr>`, verify 2nd turn reuses exact same `/c/<uuid>` (`confirmedTurnCount === 2`, zero duplicate sends), and verify halt/quarantine behavior.

---

## 14. Reproducible Reference Ledger (Do Not Fabricate Unknowns)

- **Sandbox Implementation Commit (CI Certified):** `bbf40c92f0a9a3776143556c0734421980f3e4a4` on `jan2xo/bke-worker-h`
- **Green GitHub Actions Run:** `https://github.com/jan2xo/bke-worker-h/actions/runs/43435024253` (Job `131917763342`, `success`)
- **Prior Sandbox CI Runs (Diagnostic Trail):**
  - `https://github.com/jan2xo/bke-worker-h/actions/runs/43424035577` (`d6626d00e34c503384da68318020eea358d9f0f5`, failed on `ubuntu-latest` Node `777` fixture permission)
  - `https://github.com/jan2xo/bke-worker-h/actions/runs/43432692560` (`191f7e89b4e134a26fa12e54f5073678b568194f`, failed on nested repo canonical-entrypoint check)
- **Prior Canonical PR Guard Run (`jan2xo/bke-worker`):**
  - `https://github.com/jan2xo/bke-worker/actions/runs/43418289442` (`0f7c47e97dd24e0c1403eedcea7a728ede25db4f`; `Exact-head WebExtension identity contract` failed at step 6 [raw runner log unretrieved], `MVP scope gate` failed at 500-line/path rule)
- **Nested Canonical Sub-Repo HEAD (`bke-worker/.git`):** `a7713c8a5278d6dcb90465b7c5ca8c63ad013e07`
- **Unverified / Unknown Items Explicitly Marked:**
  - Exact compiler/assertion stderr of step 6 in `jan2xo/bke-worker` run `43418289442` (unauthenticated GitHub API does not expose job logs).
  - Live `chatgpt.com` DOM rendering/selectors, live Chrome `nativeMessaging` IPC latency, `.NET` `BKE.Worker.sln` build/test status (`dotnet` absent), and live Wrangler Cloudflare relay runtime behavior.

---

## 15. Machine-Readable Handoff Capsule

```json
{
  "schema_version": "bke.hydrogen.handoff.v1",
  "from_engineer": "Gemini 4 Hydrogen",
  "to_reviewer": "GPT-6",
  "target_project": "bke-worker (FORGE F1 Desktop MVP + Completion Workstreams A-G)",
  "repositories": {
    "sandbox": "https://github.com/jan2xo/bke-worker-h",
    "canonical": "https://github.com/jan2xo/bke-worker",
    "command_center_readonly_ref": "https://github.com/jan2xo/bke-command-center@f120c6f"
  },
  "verified_implementation_commit": "bbf40c92f0a9a3776143556c0734421980f3e4a4",
  "verified_ci_run": "https://github.com/jan2xo/bke-worker-h/actions/runs/43435024253",
  "nested_canonical_head": "a7713c8a5278d6dcb90465b7c5ca8c63ad013e07",
  "live_send_defaults": {
    "FIRST_MESSAGE_LIVE_SEND_ENABLED": false,
    "CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED": false,
    "controller_daemon_human_live_send_authorized_default": false,
    "real_browser_acceptance": "NOT_RUN"
  },
  "verified_test_counts": {
    "browser_extension_unit": "202/202 PASS",
    "native_host": "39/39 PASS",
    "host_claim_daemon_harness_observer_reliability_e2e": "42/42 PASS",
    "input_only_lint_tests": "4/4 PASS",
    "admin_preproduction_activation": "10/10 PASS",
    "cloudflare_relay_check": "191/191 PASS",
    "cloudflare_reconnect_recovery": "PASS",
    "installer_contracts_py_and_sh": "PASS",
    "certify_sandbox_dry_run": "PASS",
    "package_verify_clean_uninstall": "PASS",
    "dotnet_solution": "NOT_RUN (dotnet CLI unavailable)",
    "real_chrome_two_turn_level_7": "NOT_RUN (human-only gate)"
  },
  "frozen_surfaces_untouched": [
    "bke-worker/cloudflare-relay/",
    "bke-worker/android-gecko/",
    "bke-worker/src/",
    "bke-worker/BKE.Worker.sln",
    "bke-worker/.github/workflows/pr-guard.yml",
    "jan2xo/bke-command-center"
  ],
  "known_discrepancies_and_gaps": [
    "controller-daemon.ts:368 POST /halt reads header x-bke-halt-token vs docs/desktop-operator-acceptance.md:82 Authorization: Bearer",
    "controller-daemon.ts:450 returns HTTP 409 for BLOCKED/DELIVERY_UNCERTAIN vs docs/desktop-operator-acceptance.md:91 HTTP 423",
    "first-message-actuator.ts:23 & continuation-runtime.ts:31 hardcode CANONICAL_REPOSITORY=jan2xo/bke-worker",
    "github-app-harness.ts ExecutionRequestVerifier not yet wired into DesktopControllerDaemon or cloudflare-relay",
    "DesktopControllerDaemon reads static BKE_GITHUB_INSTALLATION_TOKEN without automatic refresh",
    "Real Chrome extension loading, nativeMessaging registration, and live ChatGPT DOM selectors unverified outside mocks"
  ],
  "handoff_deliverable_paths": [
    "HYDROGEN_BKE_WORKER_ENGINEERING_HANDOFF.md",
    "bke-worker/docs/HYDROGEN_BKE_WORKER_ENGINEERING_HANDOFF.md"
  ]
}
```
