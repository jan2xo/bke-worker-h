# BKE WORKER — HYDROGEN F2 ENGINEERING KNOWLEDGE TRANSFER

**From:** Gemini Hydrogen — Lead Implementing Engineer  
**To:** GPT-6 — Independent Engineering Reviewer and BKE Systems Architect  
**Subject:** Formal F2 Engineering Handoff & Verification Evidence (`F2-01` through `F2-10`)  
**Assigned Engineering Repository:** `https://github.com/jan2xo/bke-worker-h`  
**Verified Pre-F2 GitHub Baseline SHA:** `66121870f383f6aac8d7ef4cbb21a0569a39b9a8` (`docs: add engineering handoff documentation`)  
**Previous Certified F1 Implementation SHA / Run:** `bbf40c92f0a9a3776143556c0734421980f3e4a4` / [`43435024253`](https://github.com/jan2xo/bke-worker-h/actions/runs/43435024253) (plus docs CI [`43439129656`](https://github.com/jan2xo/bke-worker-h/actions/runs/43439129656))  
**Post-F2 Commit SHA & GitHub CI Run:** `PENDING_EXTERNAL_GITHUB_SYNC` (`null` — container workspace has no Git remote configured for `jan2xo/bke-worker-h`; post-edit synchronization & sandbox CI run occur externally after workspace turn completion)  
**Canonical Target Repository (Untouched / Read-Only):** `https://github.com/jan2xo/bke-worker` (`main = a7713c8a5278d6dcb90465b7c5ca8c63ad013e07`)  
**Command Center Reference (Untouched / Read-Only):** `https://github.com/jan2xo/bke-command-center`

> **Certification & Provenance Notice:** All local TypeScript builds, unit tests, multi-process HTTP/IPC/subprocess integration suites, native smoke tests, input-only lint checks, Cloudflare relay regressions, Python/Bash security contract tests, and deterministic packaging/uninstall checks reported in Section 12 were executed **after the final F2 code edit** (`2026-11-14`). Older green GitHub CI runs (`43435024253`, `43439129656`) certify only commits `bbf40c92f0a9a3776143556c0734421980f3e4a4` / `66121870f383f6aac8d7ef4cbb21a0569a39b9a8` and do **not** certify un-synced F2 edits until synchronized to `jan2xo/bke-worker-h` and verified on the exact resulting commit SHA.

---

## 1. Executive Summary and Actual F2 Completion Status

In F2, the standalone security primitives built in F1 (`ExecutionRequestVerifier`, read-only `GitHubAuthorityProvider`, emergency `/halt`, durable replay boundaries, short-lived credential renewal, and 14-state Command Center observability) were wired into a cohesive, fail-closed, end-to-end execution path inside `DesktopControllerDaemon` -> `DesktopController` -> `FileExecutionJournal` -> `GitHubF1Ledger` -> `IpcBridgeClient` -> `entry.mjs --controller-bridge` -> `ExtensionBrowserAdapter`, while keeping all live ChatGPT send flags locked `false`, signed execution-envelope HTTP ingress `OFF` by default (`403 EXECUTION_ENVELOPE_DISABLED`), and all frozen paths untouched.

| F2 Stage | Scope | Status Classification | Concrete Evidence |
|---|---|---|---|
| **F2-01** | Emergency halt & HTTP conflict response reconciliation | **INTEGRATION VERIFIED** | `POST /halt` preserves `x-bke-halt-token` SHA-256 `timingSafeEqual`, rejects Bearer & invalid tokens (`403`), remains active when quarantined, and HTTP `409` matches `docs/desktop-operator-acceptance.md`. Verified via `controller-daemon.test.mjs`. |
| **F2-02** | Feature-gated signed execution-envelope daemon integration | **INTEGRATION VERIFIED** | `POST /execution-requests` default-OFF (`403`); when enabled, enforces key separation, 14-field canonical HMAC verification, separated `remoteHaltSigningKeysById` + `allowRemoteSignedHalt` (default `false`), and binds envelope -> reservation -> `DesktopController`. |
| **F2-03** | Production-shaped `GitHubAuthorityProvider` adapter | **INTEGRATION VERIFIED** | `RestGitHubAuthorityProvider` (`github-authority-provider.ts`) uses strictly `GET`-only REST calls, enforces immutable repository ID, explicit `GITHUB_AUTHORITY_PERMISSION_MAP`, complete `Link: rel="next"` pagination & `total_count`, and sanitizes errors. Tested against real local HTTP mocks (401/403/404/409/422/429/5xx). |
| **F2-04** | Short-lived credential renewal architecture | **INTEGRATION VERIFIED** (local mock broker) / **EXTERNAL BLOCKED** (real broker) | `ManagedTokenProvider` + `DeterministicMockTokenBroker` + `RemoteBrokerTransportStub` (fails closed `REAL_BROKER_TRANSPORT_DISABLED_NOT_AUTHORIZED`). Preemptive refresh, single-flight coalescing, scope clamping, revocation, abort, and 5-flag status verified in unit & E2E suites. |
| **F2-05** | Persistent replay, reservation, and uncertain-delivery boundaries | **INTEGRATION VERIFIED** | `PersistentReplayStore` + POSIX `withFileLock()` + `lstat()` symlink lock rejection + `RESERVED -> FENCED -> DISPATCHING/CONTINUING` atomic journal phases + monotonic `bridgeSeq` across daemon restarts. Tested in Groups 1–7 (`reliability-adversarial.test.mjs`) + E2E restart replay. |
| **F2-06** | Command Center read-only observer compatibility (14 states) | **UNIT VERIFIED** | All 14 `F2_REQUIRED_VISIBLE_STATES` mapped & fail-closed asserted in `command-center-observer.ts`, `docs/command-center-compatibility.md`, and `command-center-compatibility.test.mjs` (`3/3`). |
| **F2-07** | Multi-process & adversarial security certification | **INTEGRATION VERIFIED** | Full Turn 1 -> restart replay denial -> Turn 2 continuation -> drift quarantine -> post-quarantine remote HALT + 12-case HTTP negative matrix + expired/revoked broker + uncertain ref tests in `e2e-two-turn-acceptance.test.mjs` (`3/3`). |
| **F2-08** | Desktop packaging, operator diagnostics & templates | **INTEGRATION VERIFIED** | Expanded `GET /status` & `controller:doctor` (secret-free), updated `deploy/desktop-controller.env.example` & `package-desktop-worker.sh` (`execution_envelope_default_disabled: true` verified in bundle manifest). |
| **F2-09** | Canonical promotion reconciliation (`pr-guard.yml`) | **IMPLEMENTED** (Doc verified against `pr-guard.yml`) | Updated `docs/canonical-promotion-plan.md` with exact line measurements, 500-line ALL-files constraint, frozen `deploy/` rule, added `.md` filename rule, and `PR-1..PR-11` decomposition. |
| **F2-10** | Sandbox CI update & formal F2 engineering handoff | **IMPLEMENTED** (Local suites 100% PASS; GitHub CI **PENDING SYNC**) | Updated `/.github/workflows/hydrogen-sandbox-ci.yml` and produced this handoff report + `bke.hydrogen.f2.handoff.v1` capsule. Exact-commit GitHub CI awaits external sync to `jan2xo/bke-worker-h`. |
| **External / Human** | Real broker API & Level 7 live Chrome 2-turn acceptance | **EXTERNAL BLOCKED** / **HUMAN ACCEPTANCE REQUIRED** | Real Cloudflare desktop token broker endpoint is not authorized/built on frozen `cloudflare-relay/`; live Chrome + ChatGPT + GitHub acceptance (`BKE_REAL_CHROME_ACCEPTANCE`) remains `NOT_RUN`. |

---

## 2. Verified GitHub Baseline and Final SHAs

- **Assigned Engineering Workspace:** `https://github.com/jan2xo/bke-worker-h`
- **Queried Pre-F2 GitHub `main` (`curl` 2026-11-14):** `66121870f383f6aac8d7ef4cbb21a0569a39b9a8` (`docs: add engineering handoff documentation`, `2026-11-13T14:03:17Z`).
- **Baseline Implementation Certified Commit:** `bbf40c92f0a9a3776143556c0734421980f3e4a4` (Green CI run `43435024253`).
- **Canonical Reference Repository (`jan2xo/bke-worker`):** `main = a7713c8a5278d6dcb90465b7c5ca8c63ad013e07` (`2026-11-04T13:47:29Z`), **untouched**.
- **Post-F2 Commit SHA (`final_sha`):** `null` (not yet synchronized from AI Studio workspace to `jan2xo/bke-worker-h`).
- **Post-F2 GitHub Actions Run (`github_ci_run`):** `null` (must be inspected on the synchronized commit SHA after AI Studio sync triggers `Hydrogen Sandbox CI`).

---

## 3. Exact Files Modified / Added in F2

All F2 code/test/doc changes reside strictly inside `bke-worker/` (plus the sandbox workflow `/.github/workflows/hydrogen-sandbox-ci.yml` and root handoff copy):

| File Path | Role in F2 | Measured Line Count |
|---|---|---:|
| `/.github/workflows/hydrogen-sandbox-ci.yml` | Updated sandbox CI adding `controller:doctor`, `input-only-lint`, `forge_f1_desktop_readiness_contract.py`, and manifest flag assertions | 72 |
| `/bke-worker/browser-extension/native-host/claim/github-authority-provider.ts` | New `F2-03` `RestGitHubAuthorityProvider` (GET-only, immutable repo ID, complete pagination, sanitized errors) | 539 |
| `/bke-worker/browser-extension/native-host/claim/token-lifecycle.ts` | New `F2-04` `ManagedTokenProvider`, `DeterministicMockTokenBroker`, `RemoteBrokerTransportStub`, 5-flag status | 477 |
| `/bke-worker/browser-extension/native-host/claim/github-app-harness.ts` | `F2-02` & `F2-05` `PersistentReplayStore`, `withExclusiveLock`, separated `haltHmacKeysById`, default-OFF `allowRemoteHalt` | 471 |
| `/bke-worker/browser-extension/native-host/claim/desktop-controller.ts` | `F2-05` journal `PersistentReplayStore` backing, `RESERVED`/`FENCED` recovery, `withFileLock()` `lstat` symlink rejection | 975 |
| `/bke-worker/browser-extension/native-host/claim/controller-daemon.ts` | `F2-01`, `F2-02`, `F2-08` loopback feature-gated `POST /execution-requests`, key separation, `/status` v2, `doctor`, monotonic `bridgeSeq` across daemon restarts | 1,097 |
| `/bke-worker/browser-extension/native-host/claim/command-center-observer.ts` | `F2-06` 14-state fail-closed observer projection & evidence rules | 408 |
| `/bke-worker/browser-extension/native-host/claim/tests/github-app-harness.test.mjs` | Expanded verifier, REST authority provider (401/403/404/409/422/429/5xx, pagination), token lifecycle, and `PersistentReplayStore` tests (`6/6`) | 498 |
| `/bke-worker/browser-extension/native-host/claim/tests/command-center-compatibility.test.mjs` | Expanded 14-state visibility + fail-closed invariant tests (`3/3`) | 189 |
| `/bke-worker/browser-extension/native-host/claim/tests/controller-daemon.test.mjs` | Added `/halt` auth contract (`x-bke-halt-token` vs Bearer), blocked `/execution-requests` default-OFF & HTTP `409` tests (`2/2`) | 594 |
| `/bke-worker/browser-extension/native-host/claim/tests/reliability-adversarial.test.mjs` | Added Group 6 (parallel verifiers/daemons, key rotation, clock-skew, lockfile symlink, `RESERVED`/`FENCED` recovery) & Group 7 (HTTP race, `humanLiveSendAuthorized: false` safety) (`7/7`) | 986 |
| `/bke-worker/browser-extension/native-host/claim/tests/e2e-two-turn-acceptance.test.mjs` | Added `F2-07` full signed-envelope 2-turn E2E, token renewal, 12-case HTTP negative matrix, daemon restart replay denial, drift quarantine, and post-quarantine remote HALT (`3/3`) | 1,111 |
| `/bke-worker/deploy/desktop-controller.env.example` | Added default-OFF `BKE_EXECUTION_ENVELOPE_ENABLED=false` & non-secret F2 template variables | 52 |
| `/bke-worker/scripts/package-desktop-worker.sh` | Enforced `BKE_EXECUTION_ENVELOPE_ENABLED=false` check and `execution_envelope_default_disabled: true` in manifest build & `verify_bundle()` | 300 |
| `/bke-worker/docs/desktop-operator-acceptance.md` | Reconciled `/halt` header (`x-bke-halt-token`), HTTP `409` quarantine status, and F2 `/status` + `doctor` fields | 108 |
| `/bke-worker/docs/command-center-compatibility.md` | Documented all 14 F2 visible states & fail-closed evidence rules | 74 |
| `/bke-worker/docs/canonical-promotion-plan.md` | Reconciled F1+F2 promotion wave (`PR-1..PR-11`) against `pr-guard.yml` gates & measured file sizes | 85 |
| `/bke-worker/docs/HYDROGEN_BKE_WORKER_F2_ENGINEERING_HANDOFF.md` & `/HYDROGEN_BKE_WORKER_F2_ENGINEERING_HANDOFF.md` | This formal F2 engineering handoff report | — |

**Frozen Paths Audit (`0` edits):** `bke-worker/cloudflare-relay/`, `bke-worker/android-gecko/`, `bke-worker/src/`, `bke-worker/BKE.Worker.sln`, `bke-worker/Directory.Build.props`, `bke-worker/.github/workflows/pr-guard.yml`, and external repos `jan2xo/bke-worker`, `jan2xo/bke-command-center` are **100% unmodified**.

---

## 4. Emergency Halt Contract Repair (`F2-01`)

- **Defect in F1:** `controller-daemon.ts` required `x-bke-halt-token` and returned HTTP `409` on blocked wakes, whereas `docs/desktop-operator-acceptance.md` documented `Authorization: Bearer ...` and HTTP `423`.
- **Resolution:** Preserved the stricter `x-bke-halt-token` custom header (avoiding accidental proxy/browser Bearer confusion) with SHA-256 constant-time comparison (`constantTimeTokenMatch`), loopback remote-address restriction (`127.0.0.1` / `::1` / `::ffff:127.0.0.1`), and unconfigured fail-closed `403 OPERATOR_HALT_TOKEN_UNCONFIGURED`.
- **Documentation & Tests Aligned:** Updated `docs/desktop-operator-acceptance.md` to document `x-bke-halt-token`, `403 OPERATOR_HALT_UNAUTHORIZED` for missing/Bearer/wrong tokens, and `HTTP 409` for quarantined/blocked responses. Verified in `controller-daemon.test.mjs` and `e2e-two-turn-acceptance.test.mjs` that owner `POST /halt` returns `200` and transitions the journal to `HALTED` even when ordinary dispatch is blocked/quarantined (`DELIVERY_UNCERTAIN`).

---

## 5. Authenticated Execution-Envelope Integration (`F2-02`)

- **Separated Endpoint (`POST /execution-requests`):** Ordinary webhook endpoint (`POST /webhooks/github`) remains notification-only; server-signed execution requests arrive strictly at `POST /execution-requests`.
- **Default-OFF Feature Gate:** `executionEnvelopeEnabled` defaults to `false` (`BKE_EXECUTION_ENVELOPE_ENABLED=false` in CLI & `deploy/desktop-controller.env.example`). When disabled, `POST /execution-requests` fails closed with HTTP `403 EXECUTION_ENVELOPE_DISABLED`.
- **Strict Cryptographic Key Separation (`controller-daemon.ts:257-275`):** Startup constructor refuses to boot if any `executionSigningKeysById` secret equals `webhookSecret`, `operatorHaltToken`, or any `remoteHaltSigningKeysById` secret (`DAEMON_EXECUTION_WEBHOOK_KEY_REUSE_FORBIDDEN`, `DAEMON_EXECUTION_HALT_KEY_REUSE_FORBIDDEN`, `DAEMON_HALT_KEY_SEPARATION_FORBIDDEN`).
- **HALT Authority Isolation (`github-app-harness.ts`):** `allowRemoteSignedHalt` defaults to `false`. Enabling remote HALT requires separate `haltHmacKeysById`; a holder of a general `executionSigningKeysById` key cannot execute `action: "HALT"` (`401 EXEC_REQ_HALT_KEY_UNAUTHORIZED`).
- **Action Binding:**
  - `PREPARE`: read-only authority check + records `lastExpectedHeadSha` (`0` browser dispatches).
  - `DISPATCH_FIRST_MESSAGE`: permitted only when `confirmedTurnCount === 0 && conversationId === null`; validates `humanLiveSendAuthorized` & reserved attempt before browser wake.
  - `DISPATCH_CONTINUATION`: permitted only when `conversationId !== null && confirmedTurnCount >= 1`; enforces same-conversation target binding.

---

## 6. Real `GitHubAuthorityProvider` Adapter (`F2-03`)

- **Shared, Strictly Read-Only Adapter (`github-authority-provider.ts`):**
  - `RestGitHubAuthorityProvider` wraps GitHub REST API calls exclusively using `method: 'GET'` (constructor/method surface contains zero `POST`/`PATCH`/`PUT`/`DELETE` paths, isolating authorization checks from `GitHubF1Ledger` ref mutations).
  - **Immutable Repo Scope:** Verifies `repository.id === expectedRepositoryId` alongside case-insensitive `full_name` and push permission from `/installation/repositories`.
  - **Complete Pagination Fail-Closed:** Rejects any truncated response carrying `Link: rel="next"` header (`GITHUB_PAGINATION_TRUNCATED`) or `check_runs.length < total_count`.
  - **Explicit Permission Map (`GITHUB_AUTHORITY_PERMISSION_MAP`):** Documents minimum scopes (`pull_requests:read`, `checks:read`, `contents:read` for authority inspection vs `contents:write` isolated strictly to `GitHubF1Ledger` ref/commit CAS writes).
  - **Sanitization & HTTP Status Mapping:** Redacts `ghs_`/`gho_`/`ghp_`/`Bearer` tokens from thrown error messages and handles 401 (`GITHUB_AUTH_UNAUTHORIZED`), 403 (`GITHUB_PERMISSION_FORBIDDEN`), 404, 409, 422, 429, and 5xx fail-closed.

---

## 7. Token Lifecycle and Broker Contract (`F2-04`)

- **Five-State Honest Status Reporting (`TokenLifecycleStatus`):**
  1. `tokenLifecycleImplemented: true` (`ManagedTokenProvider` in `token-lifecycle.ts`)
  2. `mockBrokerTestsPassed: true` (exercised in `github-app-harness.test.mjs` and `e2e-two-turn-acceptance.test.mjs`)
  3. `trustedRealBrokerApiAvailable: false` (**EXTERNAL BLOCKED** — `cloudflare-relay/` frozen; existing Actions OIDC `/github/app/install-token` is not an arbitrary desktop endpoint)
  4. `realBrokerTransportConnected: false` (**NOT_AUTHORIZED** — `RemoteBrokerTransportStub` fails closed with `REAL_BROKER_TRANSPORT_DISABLED_NOT_AUTHORIZED`)
  5. `realGitHubAppRenewalCertified: false` (**NOT_RUN** — awaiting owner-authorized broker deployment)
- **Implemented Lifecycle Properties:** Single-flight promise coalescing for concurrent callers, preemptive refresh margin (`refreshMarginMs`), scope & repository ID clamping (rejecting unexpectedly elevated permissions such as `administration: write` or wrong repo/installation IDs), abort/timeout bounds, token revocation handling, and `StaticUnrenewableTokenProvider` fallback for static-token CLI mode with `controller:doctor` visibility (`credentialBrokerKind`).

---

## 8. Persistent Replay and Delivery Guarantees (`F2-05`)

- **Cross-Restart Durable Replay (`PersistentReplayStore`):** `FileExecutionJournal.asPersistentReplayStore()` persists `processedDeliveries`, `processedAttempts`, and `reservedAttempts` atomically via `O_NOFOLLOW`, `fsync()`, and POSIX `rename()`.
- **Symlink Lockfile Vulnerability Found & Fixed During F2 Adversarial Testing:** POSIX `open(..., O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW)` returns `EEXIST` rather than `ELOOP` when a `.lock` symlink already exists; updated `FileExecutionJournal.withFileLock()` (`desktop-controller.ts:147-155`) to invoke `lstat(lockPath)` on `EEXIST` and immediately throw `JOURNAL_LOCK_SYMLINK_FORBIDDEN`.
- **Daemon Restart `bridgeSeq` Collision Found & Fixed During F2 E2E Testing:** Restarting `DesktopControllerDaemon` while `entry.mjs --controller-bridge` remained active previously reset `this.bridgeSeq = 0`, causing `CommandReplayGuard` in `controller-protocol.mjs` to reject post-restart commands with `COMMAND_SEQ_REPLAY`. Fixed in `controller-daemon.ts` via `monotonicDaemonBootOffset` (`wallSeed` / `+1000` step).
- **At-Most-Once & Fail-Closed Quarantine Contract:** Any mid-`DISPATCHING`/`CONTINUING` crash, ambiguous `POST /git/refs`, `submitContinuationOnce` cross-conversation URL drift, or IPC disconnect transitions the journal to `DELIVERY_UNCERTAIN` and writes `refs/bke/uncertain/<pr>/<attempt>` cleanly with zero automatic retry.

---

## 9. Command Center Compatibility (`F2-06`)

- Updated `command-center-observer.ts` and `docs/command-center-compatibility.md` with all **14 required F2 visible states** (`F2_REQUIRED_VISIBLE_STATES`):
  `WORKER_IDENTITY_VERIFIED`, `WORKER_IDENTITY_UNKNOWN`, `PR_ASSIGNMENT_VALID`, `PR_OWNERSHIP_CONFLICT`, `CURRENT_EXACT_SHA`, `STALE_SHA`, `CLAIM_RESERVED`, `EXECUTION_BLOCKED`, `DELIVERY_UNCERTAIN`, `FIRST_CONVERSATION_CONFIRMED`, `CONTINUATION_CONFIRMED`, `EXACT_HEAD_CI_PENDING_OR_FAILED`, `EVIDENCE_INCOMPLETE`, `WORKER_LIVENESS_UNKNOWN`.
- Fail-closed assertions verify missing evidence maps to `UNKNOWN`, inactive/paired workers cannot project as running, GitHub assignment never implies browser readiness, valid token never implies ChatGPT authentication, and `commandCenterDispatcher: false` / `realBrowserAcceptance: NOT_RUN` cannot be bypassed.
- `jan2xo/bke-command-center` was not modified. If Command Center adds F2 status polling in a future task, it remains strictly read-only over GitHub refs + optional loopback read-only `/status`.

---

## 10. Full Synthetic Multi-Process Execution Trace (`F2-07`)

Verified end-to-end in `e2e-two-turn-acceptance.test.mjs` (`F2-07 Full Synthetic Signed-Envelope Two-Turn Acceptance`):
1. Local HTTP GitHub REST double enforces repository ID, GET-only authority checks, check-run ticket `bke-ticket:v1`, and `refs/bke/*` CAS ref writes.
2. `DeterministicMockTokenBroker` + `ManagedTokenProvider` mints repository-scoped installation token (`issueCalls === 1`).
3. Signed `PREPARE` envelope updates `lastExpectedHeadSha` with `0` browser submissions.
4. Early `DISPATCH_CONTINUATION` before Turn 1 rejects `409` (`EXEC_REQ_ACTION_NO_ACTIVE_CONVERSATION`).
5. Signed `DISPATCH_FIRST_MESSAGE` (`attempt-f2-turn-1`) flows through `DesktopControllerDaemon` -> `ExecutionRequestVerifier` -> `RestGitHubAuthorityProvider` -> `FileExecutionJournal` -> `GitHubF1Ledger` -> `IpcBridgeClient` (Unix `0o700`/`0o600` socket) -> real Node child `entry.mjs --controller-bridge` -> P-256 `connectControllerNativeBridge` -> `ExtensionBrowserAdapter` -> simulated landing DOM -> confirms `/c/conv-f2-e2e-01` (Turn 1).
6. Token clock advances `+70s` past `refreshMarginMs` -> `ManagedTokenProvider` renews short-lived token (`issueCalls === 2`) -> signed `DISPATCH_CONTINUATION` confirms Turn 2 on exact same `/c/conv-f2-e2e-01`.
7. 12-case negative HTTP matrix (bad sig, unknown `key_id`, bad `protocol_version`, missing field, extra field, wrong installation, wrong repo ID, wrong worker, wrong PR, stale head SHA, expired envelope, dispatch-key HALT) all return exact `400/401/403/409` with `0` extra submits.
8. Expired broker token, revoked broker token, and existing `refs/bke/uncertain/*` ref each reject `409` before browser dispatch.
9. `daemon.stop()` + fresh `DesktopControllerDaemon` restart on same `journalPath` rejects replayed `deliv-f2-t1` and consumed `attempt-f2-turn-1` (`409`).
10. Simulated Turn 3 cross-conversation URL drift (`conv-other-drifted`) quarantines journal to `DELIVERY_UNCERTAIN`, writes `refs/bke/uncertain/127/attempt-f2-turn-3`, and blocks Turn 4 (`409`).
11. Separate `haltHmacKeysById` signed remote `HALT` cleanly halts quarantined daemon (`200`, `journalPhase === "HALTED"`).

---

## 11. Threat Model and Security Boundaries

- **Compile-time live-send locks preserved:** `FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const`, `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const`.
- **Runtime defaults locked OFF:** `humanLiveSendAuthorized: false`, `executionEnvelopeEnabled: false`, `allowRemoteSignedHalt: false`, `RemoteBrokerTransportStub` disabled.
- **No secret leakage:** `GET /status`, `GET /healthz`, `controller:doctor`, HTTP error responses, and REST exception throws sanitize tokens (`ghs_`/`Bearer`) and never expose HMAC keys, webhook secrets, halt tokens, cookies, or browser profiles.
- **File & socket hardening:** `O_NOFOLLOW`, regular-file checks, `0o700` dirs, `0o600` files/sockets, UID match, and `lstat()` symlink lockfile checks.
- **Input-only Chrome boundary:** `input-only-lint.mjs` enforces zero reads of ChatGPT reply/assistant DOM elements.

---

## 12. GitHub CI History and Exact Verification Counts

### Prior Certified GitHub Actions Runs (Pre-F2 Baseline)
- `bbf40c92f0a9a3776143556c0734421980f3e4a4`: [`43435024253`](https://github.com/jan2xo/bke-worker-h/actions/runs/43435024253) — `success` (F1 baseline).
- `66121870f383f6aac8d7ef4cbb21a0569a39b9a8`: [`43439129656`](https://github.com/jan2xo/bke-worker-h/actions/runs/43439129656) — `success` (F1 handoff doc commit).
- **Post-F2 Sandbox CI:** Pending synchronization to `jan2xo/bke-worker-h` (`github_ci_run: null` for F2 edits).

### Complete Local Post-Final-Edit Verification Ledger (Executed After Final Code & Doc Edit)

| Command / Suite | Exact Verified Result | Scope Covered |
|---|---|---|
| `npm --prefix bke-worker/browser-extension run check` | **PASS** (`tsc` 0 errors; `validate` PASS; `202` + `39` + `51` PASS) | Extension build, claim build, MV3 manifest audit, all 3 JS/TS suites |
| └─ `npm test` (MV3 extension unit suite) | **202/202 PASS** | Extension gates, target binding, P-256 transport, adapter, content-script DOM |
| └─ `npm run test:native` (Native host ESM suite) | **39/39 PASS** | `entry.mjs`, `host.mjs`, `framing.mjs`, `controller-host.mjs`, `controller-protocol.mjs` |
| └─ `npm run test:host-claim` (F1+F2 Claim/Daemon/E2E) | **51/51 PASS** | `send-once-claim-adapter` (`25/25`), `reliability-adversarial` (`7/7`), `github-app-harness` (`6/6`), `command-center-compatibility` (`3/3`), `e2e-two-turn-acceptance` (`3/3`), `github-f1-ledger` (`3/3`), `desktop-controller` (`2/2`), `controller-daemon` (`2/2`) |
| `npm --prefix bke-worker/browser-extension run controller:doctor` | **PASS** (`ok: true`, `LOCKED_FALSE`, `DISABLED_BY_DEFAULT`) | Environment, locked-false defaults, F2 authority/broker flags, missing owner prereqs |
| `npm --prefix bke-worker/browser-extension run smoke:native` | **9/9 PASS** (`BKE_DESKTOP_NATIVE_SMOKE=PASS`, `BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN`) | Real `entry.mjs` subprocess P-256 challenge-response handshake |
| `node bke-worker/scripts/input-only-lint.mjs` & `input-only-lint.test.mjs` | **PASS (4/4)** | Static input-only DOM boundary check + negative/positive AST fixtures |
| `bash bke-worker/scripts/package-desktop-worker.sh package/verify/clean-uninstall` | **PASS** (`53` files SHA-256 verified) | Manifest asserts `live_send_locked_false: true` and `execution_envelope_default_disabled: true` |
| `npm --prefix bke-worker/cloudflare-relay run check` & `reconnect-recovery-test` | **191/191 PASS** + **PASS** | Untouched frozen Cloudflare relay & Android recovery planner |
| All 8 Python/Node/Bash contract suites in `bke-worker/tests/` | **ALL PASS** | `forge_f1_desktop_mvp_contract.py`, `forge_f1_desktop_readiness_contract.py`, `chrome_native_host_installer_contract.{py,sh}`, `operator_entrypoint_contract.py`, `android_gecko_probe_contract.py`, `android_recovery_operator_contract.py`, `cloudflare_relay_contract.py`, `admin_preproduction_activation.test.mjs` (**10/10**) |
| `bash bke-worker/scripts/certify-forge-f1-desktop-mvp.sh --sandbox --dry-run` | `BKE_F1_MVP_CERTIFICATION=BLOCKED reason=NOT_IN_GIT_REPOSITORY` (container has no `.git`; executes on GitHub Actions `actions/checkout@v4`) | Verified via `hydrogen-sandbox-ci.yml` once synced |

---

## 13. Remaining Unverified / Blocked External Integrations

1. **Real Desktop GitHub App Token Broker (`EXTERNAL BLOCKED` / `NOT_AUTHORIZED`):** `cloudflare-relay/` is frozen; no production desktop OAuth/HMAC/OIDC broker endpoint exists yet to vend short-lived installation tokens to desktop controllers without exposing App private keys.
2. **Real GitHub App Production Delivery & `bke-ticket:v1` Signing (`EXTERNAL BLOCKED`):** Local tests verify deterministic HMAC-SHA256 signing & REST fixtures; production signing key provisioning lives outside this sandbox.
3. **Level 7 Live Two-Turn Acceptance in Real Chrome (`HUMAN ACCEPTANCE REQUIRED` / `NOT_RUN`):** Real ChatGPT DOM, signed-in Chrome profile, Chrome extension popup grant, and `BKE_OWNER_SUPERVISED_LIVE_SEND` human gate remain unexecuted by policy.
4. **Post-F2 GitHub Actions Exact-SHA Run (`GITHUB CI PENDING SYNC`):** Synchronization to `jan2xo/bke-worker-h` happens externally after turn completion.
5. **.NET `BKE.Worker.sln`, Android Emulator, CWS `.crx` Packaging:** Out of scope / runtimes absent in container.

---

## 14. Canonical Promotion Plan (`F2-09`)

Fully reconciled in `/bke-worker/docs/canonical-promotion-plan.md` against `bke-worker/.github/workflows/pr-guard.yml` (`Issue #149`):
- Enforces **500 changed lines across ALL files (code + tests + docs combined)** per PR unless owner adds `bke:oversize-ok`.
- Explicitly identifies **`deploy/` as a frozen path prefix** alongside `cloudflare-relay/`, `android-gecko/`, `src/`, `BKE.Worker.sln`, `Directory.Build.props`.
- Explicitly enforces added `.md` filenames appearing in `MVP-Task: #<issue>`, and requires `bke:gate-change` for any `.github/` edits.
- Maps all modified & new F1+F2 files (highlighting each module `> 500` lines such as `controller-daemon.ts` [1,097], `desktop-controller.ts` [975], `github-f1-ledger.ts` [1,106], `controller-transport.ts` [860], `github-authority-provider.ts` [539], plus tests) into a dependency-ordered **11-wave split plan (`PR-1..PR-11`)** so every canonical PR builds cleanly with `npm run check` on its exact head SHA.

---

## 15. Owner-Only Operational Acceptance Requirements

Before attempting supervised Level 7 acceptance on a local workstation (never in CI):
1. Synchronize F2 to `jan2xo/bke-worker-h` and verify green `Hydrogen Sandbox CI` on the exact commit SHA.
2. Manually create `~/.config/bke-worker/f1-controller.env` (`chmod 600`) from `deploy/desktop-controller.env.example` and `~/.config/bke-worker/native-host/owner-policy.json` (`chmod 600`) from `deploy/owner-native-policy.template.json`.
3. Create and manually log into the isolated Chrome profile via `scripts/forge-f1-desktop-readiness.sh`, install native messaging host via `scripts/prepare-chrome-native-host.sh install`, and explicitly click **Connect controller bridge (opt-in)** in the extension popup.
4. Verify `npm --prefix browser-extension run controller:doctor` reports clean configuration.
5. Only when actively supervising at the keyboard, authorize live send explicitly via CLI `--owner-supervised-live-send`, `BKE_OWNER_SUPERVISED_LIVE_SEND=I_OWNER_AUTHORIZE_LIVE_SEND`, and the three owner certification flags (`BKE_CERT_*=true`), keeping emergency stop `curl -H "x-bke-halt-token: ..."` ready.

---

## 16. Independent GPT-6 Review Checklist

- [ ] Inspect external GitHub sync commit SHA on `jan2xo/bke-worker-h` and verify its automatically triggered `Hydrogen Sandbox CI` run passes 100%.
- [ ] Verify frozen directories (`cloudflare-relay/`, `android-gecko/`, `bke-worker/src/`, `BKE.Worker.sln`, `bke-worker/.github/workflows/pr-guard.yml`) show zero changes vs baseline.
- [ ] Audit `controller-daemon.ts` key-separation checks (`webhookSecret` != `executionSigningKeysById` != `remoteHaltSigningKeysById` != `operatorHaltToken`), `POST /execution-requests` default-OFF gate (`403`), and `POST /halt` `x-bke-halt-token` contract (`200` even while quarantined).
- [ ] Audit `github-authority-provider.ts` to confirm zero write/mutating HTTP methods, mandatory `repository_id` check, and fail-closed `Link: rel="next"` pagination checks.
- [ ] Audit `token-lifecycle.ts` `RemoteBrokerTransportStub` to confirm fail-closed `REAL_BROKER_TRANSPORT_DISABLED_NOT_AUTHORIZED` default.
- [ ] Audit `desktop-controller.ts` `withFileLock()` `lstat` symlink check, `PersistentReplayStore` atomic saves, and monotonic `bridgeSeq` in `controller-daemon.ts`.
- [ ] Review `docs/canonical-promotion-plan.md` `PR-1..PR-11` splits against `pr-guard.yml` lines 250–376 prior to opening any canonical PR against `jan2xo/bke-worker`.

---

## 17. Final Machine-Readable Completion Capsule

```json
{
  "schema": "bke.hydrogen.f2.handoff.v1",
  "engineering_repo": "jan2xo/bke-worker-h",
  "base_sha": "66121870f383f6aac8d7ef4cbb21a0569a39b9a8",
  "final_sha": null,
  "github_ci_run": null,
  "halt_contract": "INTEGRATION_VERIFIED",
  "signed_envelope_daemon_integration": "INTEGRATION_VERIFIED",
  "github_authority_provider": "INTEGRATION_VERIFIED",
  "token_lifecycle": "INTEGRATION_VERIFIED",
  "real_broker_connection": "NOT_AUTHORIZED",
  "persistent_replay_safety": "INTEGRATION_VERIFIED",
  "command_center_compatibility": "UNIT_VERIFIED",
  "synthetic_two_turn": "INTEGRATION_VERIFIED",
  "real_chrome_two_turn": "NOT_RUN",
  "live_send_enabled": false,
  "canonical_repo_modified": false,
  "command_center_modified": false,
  "production_modified": false,
  "known_blockers": [
    "EXTERNAL_GITHUB_SYNC_AND_EXACT_SHA_CI_PENDING",
    "REAL_CLOUDFLARE_DESKTOP_TOKEN_BROKER_NOT_AUTHORIZED",
    "LEVEL_7_REAL_CHROME_OWNER_ACCEPTANCE_NOT_RUN",
    "CONTAINER_MISSING_DOTNET_AND_DOT_GIT_FOR_LOCAL_CERTIFY_SH"
  ],
  "next_safe_action": "Synchronize F2 source to jan2xo/bke-worker-h, inspect the exact-commit Hydrogen Sandbox CI run, then decide module splits or bke:oversize-ok labels for PR-1..PR-11 under jan2xo/bke-worker."
}
```
