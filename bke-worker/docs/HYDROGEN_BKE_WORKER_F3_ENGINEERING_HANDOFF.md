# BKE WORKER — HYDROGEN F3 ENGINEERING & SECURITY REVIEW HANDOFF

**From:** Gemini Hydrogen — Lead Implementing Engineer  
**To:** GPT-6 — Independent Engineering Reviewer & BKE Systems Architect  
**Project:** BKE Worker (`Phase F3 — Trusted Broker, Device Enrollment, Authority Integration & Security Review`)  
**Assigned Engineering Repository:** `https://github.com/jan2xo/bke-worker-h`  
**Verified F2 Starting Baseline SHA:** `a3f268f9c2fc16a84ac15d4243569d4fb3860a6e`  
**Verified F2 GitHub Actions Run:** [`43601851926`](https://github.com/jan2xo/bke-worker-h/actions/runs/43601851926)  
**Post-F3 Synchronized Commit SHA (`final_sha`):** `null` *(pending external AI Studio -> `jan2xo/bke-worker-h` GitHub sync)*  
**Post-F3 GitHub CI Run (`github_ci_run`):** `null` *(pending sync to `jan2xo/bke-worker-h`)*  
**Canonical Target Repository (`jan2xo/bke-worker`):** **Untouched / Read-Only**  
**Command Center (`jan2xo/bke-command-center`):** **Untouched / Read-Only**  
**Frozen Production Runtime (`cloudflare-relay/`, `android-gecko/`, `bke-worker/src/`, `BKE.Worker.sln`, `Directory.Build.props`, `bke-worker/.github/workflows/pr-guard.yml`):** **0 modifications**

> **Verification & Honesty Notice:** All builds, TypeScript checks, unit suites, multi-process 3-process E2E suites, 18-scenario adversarial chaos suites, native-host smoke checks, input-only lint checks, frozen Cloudflare relay checks, Python/Bash contract tests, and SHA-256 bundle packaging checks reported below were executed and observed passing **after the final F3 code edit** in this container workspace. This document is a **self-audit preparation package**—it does **not** substitute for independent GPT-6 or human security certification. Real Cloudflare broker deployment, real GitHub App PEM/PAT provisioning, and Level 7 real Chrome two-turn acceptance remain **NOT_AUTHORIZED / NOT_RUN**, and `final_sha` / `github_ci_run` are honestly `null` because this container workspace has no `.git` remote or GitHub push integration.

---

## 1. Executive Engineering Verdict

F3 delivers a cohesive, production-shaped, **integration-verified sandbox system** connecting:
**`SignedAdminApproval (Ed25519)` + `DeviceKeyPairSigner (ECDSA P-256 PoP)` → `TrustedDesktopBroker` (`SandboxBrokerHttpServer`) → `SandboxGitHubAppAdapter` → `SignedExecutionRequestV2 (Ed25519)` → `DesktopControllerDaemon` (`ExecutionRequestVerifier` + `ManagedTokenProvider` + `RestGitHubAuthorityProvider`) → `DesktopController` (`FileExecutionJournal` + `GitHubF1Ledger`) → `IpcBridgeClient` → `entry.mjs --controller-bridge` (`controller-host.mjs`) → `connectControllerNativeBridge` → `ExtensionBrowserAdapter` → synthetic Turn 1 (`CONFIRMED_TURN_1`) & Turn 2 (`CONFIRMED_CONTINUATION`) → `GitHubF1Ledger` refs (`refs/bke/*`) → `projectWorkerStateForCommandCenter()` (14 visible states)**.

| Deliverable | Scope & Verification Classification | Summary Verdict |
|---|---|---|
| **F3-00 (`docs/f3-security-audit.md`)** | **INTEGRATION VERIFIED** | Audited F2 authorization, crypto, replay & credential transport; resolved 9 concrete code gaps (V2 asymmetric Ed25519 signing, V2 HALT public-key separation, `redirect: 'manual'` 3xx blocking, `maintain`/empty permission blocking, `baseApiUrl` ledger wiring, cross-repo worker conflict inspection in broker, bounded pre-claim transient retry). |
| **F3-01 (`docs/f3-existing-github-app-contract.md`)** | **IMPLEMENTED** (Reconciled vs `cloudflare-relay/` & `bke-command-center`) | Mapped all 10 broker dimensions and implemented-vs-proposed endpoints across `cloudflare-relay/src/{github-app,admin-broker,index}.js`. Kept `cloudflare-relay/` 100% frozen. |
| **F3-02 (`device-enrollment.ts` + `docs/f3-desktop-enrollment-contract.md`)** | **INTEGRATION VERIFIED** (`14/14` scenarios PASS) | Unique ECDSA P-256 device identity bound 1:1 to `worker_id`, `installation_id`, `browser_profile_identity`, `native_bridge_identity`, `enrollment_generation`, `revocation_state`, single-use challenge, Admin Ed25519 approval, and rejection of client privilege flags. |
| **F3-03 (`integrations/desktop-broker/`)** | **INTEGRATION VERIFIED** (`17/17` broker security tests PASS) | Production-shaped loopback reference broker verifying Admin approval, device PoP, replay nonces, cross-repo GitHub App scope, V2 Ed25519 signing, key rotation (`k1 -> k2`), HALT key separation, bounded token minting, token revocation, and server-mediated 4-op CAS ledger prototype (`executeServerMediatedLedgerOp`). |
| **F3-04 (`controller-daemon.ts` + `github-app-harness.ts` + `multiprocess-e2e.test.mjs`)** | **INTEGRATION VERIFIED** (3 real OS child processes PASS) | Integrated broker ↔ controller ↔ native-host bridge over real loopback HTTP & Unix IPC sockets, preserving locked-false default (`LIVE_SEND_DISABLED` unless authorized). |
| **F3-05 (`github-app-adapter.ts` + `mock-github-server.mjs`)** | **INTEGRATION VERIFIED** (`7+8+8+6` simulations PASS) | Full repository authority, PR exclusivity, exact head/claim CAS ambiguity/timeout/readback-mismatch, and receipt turn-order/wrong-conversation negative tests. |
| **F3-06 (`token-lifecycle.ts` + `f3-hardening.test.mjs`)** | **INTEGRATION VERIFIED** | Preemptive renewal, single-flight coalescing, revocation check, bounded `PRE_CLAIM_AUTO_RETRY_SAFE` on transient pre-claim outages vs fail-closed `NON_RETRYABLE_ERROR` and zero-retry `DELIVERY_UNCERTAIN`. |
| **F3-07 (`chaos-adversarial.test.mjs`)** | **INTEGRATION VERIFIED** (`18/18` chaos scenarios PASS) | Broker/controller crash boundaries, browser disconnect, lost GitHub write responses, dual-worker/dual-PR races, mid-flight revocation, key rotation, head drift, restart replay, expired envelopes, URL drift, partial CC evidence. |
| **F3-08 (`docs/f3-command-center-integration.md`)** | **UNIT VERIFIED** (`14/14` states PASS on E2E evidence) | Verified `bke-command-center` requires **no** immediate repo edit; documented proposed future read-only observer spec (`src/worker-observer/bke-worker-projection.js`). |
| **F3-09 (`controller-daemon.ts` v3 + `package-desktop-worker.sh`)** | **INTEGRATION VERIFIED** (`doctor` PASS, `53` bundle files SHA-256 verified) | Upgraded `GET /status` & `controller:doctor` to secret-free v3 diagnostics (`deviceIdentity`, `broker`, `installationScope`, `workerAssignment`, `tokenLifecycle`, `missingOwnerPrerequisites`); preserved clean uninstall. |
| **F3-10 (`docs/canonical-promotion-plan.md`)** | **IMPLEMENTED** | Measured exact F1+F2+F3 `wc -l` counts and reconciled `PR-1..PR-14` promotion waves against `pr-guard.yml` 500-line ALL-files gate, `deploy/` frozen prefix, and `.md` filename rules. |
| **External / Live Acceptance** | **EXTERNAL BLOCKED / HUMAN ACCEPTANCE REQUIRED** | Real Cloudflare `/v1/desktop/*` broker (`NOT_AUTHORIZED`), real Chrome 2-turn acceptance (`NOT_RUN`), live send defaults remain locked `false`. |

---

## 2. Verified F2 Starting Point

- **Assigned Sandbox Repository:** `https://github.com/jan2xo/bke-worker-h`
- **Verified F2 Baseline SHA:** `a3f268f9c2fc16a84ac15d4243569d4fb3860a6e`
- **Verified F2 CI Run:** [`43601851926`](https://github.com/jan2xo/bke-worker-h/actions/runs/43601851926) (`Hydrogen Sandbox CI` — green).
- **Inherited F2 Modules Preserved & Extended (Never Replaced):**
  - `bke-worker/browser-extension/native-host/claim/github-app-harness.ts` (`ExecutionRequestVerifier`, V1 HMAC canonical verification, `PersistentReplayStore`)
  - `bke-worker/browser-extension/native-host/claim/github-authority-provider.ts` (`RestGitHubAuthorityProvider`, GET-only REST boundary, `GITHUB_AUTHORITY_PERMISSION_MAP`)
  - `bke-worker/browser-extension/native-host/claim/token-lifecycle.ts` (`ManagedTokenProvider`, single-flight coalescing, scope clamping, 5-flag status)
  - `bke-worker/browser-extension/native-host/claim/github-f1-ledger.ts` (`GitHubF1Ledger`, `refs/bke/{fences,claims,conversations,turns,uncertain}/*` CAS ledger)
  - `bke-worker/browser-extension/native-host/claim/desktop-controller.ts` (`DesktopController`, `FileExecutionJournal`, `withFileLock()` with `lstat()` symlink rejection)
  - `bke-worker/browser-extension/native-host/claim/controller-daemon.ts` (`DesktopControllerDaemon`, `/webhooks/github`, `/execution-requests` default-OFF, `/halt`, `/status`, `/healthz`, `doctor`)
  - `bke-worker/browser-extension/native-host/claim/ipc-client.ts`, `send-once-claim-adapter.ts`, `command-center-observer.ts` (`14` `F2_REQUIRED_VISIBLE_STATES`).

---

## 3. Actual F3 Source Changes & Exact Inventory

All workspace files created or updated for F3 (with exact `wc -l` measurements observed on disk):

### 3.1 Architecture & Trust-Boundary Diagrams

```text
+---------------------------------------------------------------------------------------------------+
|                                     CONTROL PLANE / OWNER TRUST                                   |
|  [Human Owner / Admin Ed25519 Key] ---> SignedAdminApproval ('BKE_ADMIN_APPROVAL_V1\n')           |
|  [BKE Command Center (Read-Only)]  ---> CommandCenterReadBroker RPC / GitHub refs (No Dispatch)   |
+---------------------------------------------------------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------+
| TRUST BOUNDARY 1: PRIVATE TRUSTED BROKER  (bke-worker/integrations/desktop-broker/ — Sandbox)     |
|                                                                                                   |
|  SandboxBrokerHttpServer (127.0.0.1 loopback HTTP; NEVER deployed)                                |
|    ├── DeviceEnrollmentRegistry (0o600, O_NOFOLLOW, Admin Ed25519 + Single-Use Challenge + P-256) |
|    ├── TrustedDesktopBroker     (Ed25519 EXECUTION key_id != HALT key_id, Nonce/Delivery Replay)  |
|    │     ├── authorizeExecution()   -> SignedExecutionRequestV2 ('BKE_EXECUTION_REQUEST_V2\n')    |
|    │     ├── mintScopedToken()      -> <=180s repo-scoped installation token (clamped perms)      |
|    │     └── executeServerMediatedLedgerOp() -> 4 allowlisted CAS ops (no arbitrary proxy)        |
|    └── SandboxGitHubAppAdapter  (App JWT RS256/EdDSA, redirect:'manual', cross-repo PR check)    |
+---------------------------------------------------------------------------------------------------+
                    | SignedExecutionRequestV2 (Ed25519)              | Scoped Token / Authority
                    v                                                 v
+---------------------------------------------------------------------------------------------------+
| TRUST BOUNDARY 2: DESKTOP CONTROLLER DAEMON  (bke-worker/browser-extension/native-host/claim/)    |
|  * Holds ONLY Broker SPKI Public Keys (NO Broker Private Key, NO App PEM, NO Global PAT)         |
|                                                                                                   |
|  DesktopControllerDaemon (127.0.0.1, executionEnvelopeEnabled=false, humanLiveSendAuthorized=false|
|    ├── ExecutionRequestVerifier   (V2 Ed25519 + downgrade lock + issuer/aud/device/gen + revoke)  |
|    ├── RestGitHubAuthorityProvider (HTTP GET only, redirect:'manual', Link pagination, repo ID)   |
|    ├── ManagedTokenProvider       (bounded pre-claim transient retry, zero post-claim retry)      |
|    └── DesktopController -> FileExecutionJournal (0o600 + lstat lock) -> GitHubF1Ledger CAS       |
+---------------------------------------------------------------------------------------------------+
                    | Unix Domain Socket (0o700 dir / 0o600 sock, UID peer check)
                    v
+---------------------------------------------------------------------------------------------------+
| TRUST BOUNDARY 3: NATIVE HOST & CHROME MV3 EXTENSION                                              |
|  entry.mjs --controller-bridge -> controller-host.mjs (stdin/stdout 32-bit framed Native Msg)     |
|    └── ECDSA P-256 challenge/response (connectControllerNativeBridge) -> ExtensionBrowserAdapter  |
|          └── Synthetic / Input-Only ChatGPT Tab (FIRST_MESSAGE_LIVE_SEND_ENABLED = false)         |
+---------------------------------------------------------------------------------------------------+
```

### 3.2 Complete F3 File Inventory (`wc -l`)

| File Path | Role in F3 | Measured Lines |
|---|---|---:|
| **New Sandbox Broker Package (`bke-worker/integrations/desktop-broker/`)** | | |
| `integrations/desktop-broker/src/types.ts` | Canonical F3 contracts (`ExecutionRequestEnvelopeV2`, `EnrolledDeviceRecord`, `SignedAdminApproval`, `ServerMediatedLedgerOpRequest`) | 184 |
| `integrations/desktop-broker/src/device-enrollment.ts` | `F3-02` `DeviceEnrollmentRegistry`, `signAdminApproval`, `verifyAdminApproval`, `0o600`+`O_NOFOLLOW` lock store, key rotation & revocation | 691 |
| `integrations/desktop-broker/src/github-app-adapter.ts` | `F3-03`/`F3-05` `SandboxGitHubAppAdapter` (`redirect: 'manual'`, cross-repo exclusivity sweep, token minting & 4-op server-mediated CAS) | 570 |
| `integrations/desktop-broker/src/broker-service.ts` | `F3-03` `TrustedDesktopBroker` (Ed25519 V2 minting, separate `EXECUTION`/`HALT` key rings, nonce/delivery replay, audit log, token revocation) | 683 |
| `integrations/desktop-broker/src/broker-server.ts` | Loopback-only HTTP server (`/healthz`, `/v1/public-keys`, `/v1/enrollment/*`, `/v1/broker/*`) & CLI child-process runner | 306 |
| `integrations/desktop-broker/src/broker-client.ts` | `DeviceKeyPairSigner` (ECDSA P-256 `prime256v1`) + `SandboxHttpTokenBrokerClient` (`TokenBrokerClient` implementation) | 224 |
| `integrations/desktop-broker/tests/mock-github-server.mjs` | Local HTTP GitHub App & REST simulator (`installations`, `/pulls`, `/check-runs`, `/git/refs`, fault injection modes) | 295 |
| `integrations/desktop-broker/tests/helpers/controller-runner.mjs` | Real OS child process launcher for `DesktopControllerDaemon` wired to broker revocation & REST endpoints | 117 |
| `integrations/desktop-broker/tests/device-enrollment.test.mjs` | `14/14` `F3-02` enrollment, replay, concurrency, key rotation, revocation & corruption scenarios | 446 |
| `integrations/desktop-broker/tests/broker-service.test.mjs` | `17/17` `F3-03`/`F3-05` broker security, key rotation, HALT separation, installation fault & server-CAS tests | 724 |
| `integrations/desktop-broker/tests/multiprocess-e2e.test.mjs` | `F3-04`/`F3-08` 3-process real OS IPC/HTTP E2E (`broker-server` + `controller-runner` + `entry.mjs`) + all 14 CC visible states | 693 |
| `integrations/desktop-broker/tests/chaos-adversarial.test.mjs` | `F3-07`/`F3-05` 18 adversarial chaos scenarios + `GitHubF1Ledger` CAS ambiguity/readback mismatch/drift tests | 734 |
| **Hardened Controller / Claim / Extension Integration (`bke-worker/browser-extension/native-host/claim/`)** | | |
| `native-host/claim/github-app-harness.ts` | V2 Ed25519 verification (`verifyRequest`), `requireAsymmetricV2` downgrade lock, issuer/audience/device/generation checks, V2 HALT key separation, `deviceRevocationChecker` | 744 |
| `native-host/claim/github-authority-provider.ts` | `F3-00` `redirect: 'manual'` 3xx block + fail-closed `maintain`/empty `permissions` checks | 545 |
| `native-host/claim/github-f1-ledger.ts` | `F3-00` `redirect: 'manual'` across GET/POST/PATCH + configurable `baseApiUrl` for sandbox multi-process REST testing | 1,112 |
| `native-host/claim/token-lifecycle.ts` | `F3-06` bounded pre-claim transient retry (`maxTransientRetries`), `lastRecoveryClassification` (`RECOVERED_TRANSIENT` vs `BLOCKED_PERMANENT`) | 511 |
| `native-host/claim/controller-daemon.ts` | `F3-04`/`F3-09` V2 public-key constructor separation, `GET /status` v3 & `doctor` v3 secret-free summaries | 1,244 |
| `native-host/claim/tests/f3-hardening.test.mjs` | Dedicated claim-layer tests (`4/4`): V2 crypto + downgrade/HALT separation, 3xx/`maintain` blocks, pre-claim vs non-retryable, `status` v3/`doctor` | 429 |
| **Templates, Packaging, CI & F3 Engineering Docs** | | |
| `/.github/workflows/hydrogen-sandbox-ci.yml` | Updated sandbox CI running `integrations/desktop-broker` `npm run check` + V2/broker default-OFF grep checks | 83 |
| `bke-worker/deploy/desktop-controller.env.example` | Added 12 default-OFF F3 V2 & remote-broker configuration variables (zero secrets) | 67 |
| `bke-worker/scripts/package-desktop-worker.sh` | Verifies `BKE_EXECUTION_V2_ASYMMETRIC_ENABLED=false`, `BKE_REQUIRE_ASYMMETRIC_V2=false`, `BKE_REMOTE_BROKER_ENABLED=false` during packaging (`53` files) | 305 |
| `bke-worker/docs/f3-security-audit.md` | F3-00 structured 10-finding adversarial audit of F2 | 43 |
| `bke-worker/docs/f3-existing-github-app-contract.md` | F3-01 10-point reconciliation & implemented-vs-proposed interface inventory | 79 |
| `bke-worker/docs/f3-desktop-enrollment-contract.md` | F3-02 device enrollment data model, ceremony domain separators & 14-test contract | 62 |
| `bke-worker/docs/f3-command-center-integration.md` | F3-08 Command Center compatibility verification & optional future observer adapter spec | 40 |
| `bke-worker/docs/desktop-operator-acceptance.md` | F3-06 recovery table, V2 public-key setup & v3 diagnostic documentation | 128 |
| `bke-worker/docs/canonical-promotion-plan.md` | F3-10 updated `PR-1..PR-14` promotion plan with exact `wc -l` measurements | 88 |
| `HYDROGEN_BKE_WORKER_F3_ENGINEERING_HANDOFF.md` & `bke-worker/docs/...` | This formal F3 security review & completion handoff | — |

### 3.3 Symbol & Interface Map

- **Admin Approval & Device Enrollment (`integrations/desktop-broker/src/`):**
  - `signAdminApproval`, `verifyAdminApproval`, `DeviceEnrollmentRegistry` (`issueChallenge`, `completeEnrollment`, `rotateDeviceKey`, `revokeDevice`, `inspectDeviceStatus`, `verifyDeviceAssertion`), `DeviceKeyPairSigner` (`signEnrollmentChallenge`, `signKeyRotationProof`, `signDeviceAssertion`).
- **Sandbox Broker & GitHub App Adapter (`integrations/desktop-broker/src/`):**
  - `TrustedDesktopBroker` (`initialize`, `getPublicVerificationKeys`, `rotateSigningKey`, `authorizeExecution`, `mintScopedToken`, `executeServerMediatedLedgerOp`, `revokeIssuedToken`, `isTokenRevoked`, `getAuditLog`), `SandboxGitHubAppAdapter` (`resolveInstallationAndMintToken`, `verifyExecutionAuthority`, `executeServerMediatedLedgerOp`), `SandboxBrokerHttpServer`, `SandboxHttpTokenBrokerClient`.
- **Desktop Verifier, Authority, Token & Daemon (`browser-extension/native-host/claim/`):**
  - `ExecutionRequestVerifier` (`verifyRequest`), `signExecutionRequestEd25519`, `verifyExecutionRequestEd25519Signature`, `buildExecutionAudience`, `RestGitHubAuthorityProvider`, `ManagedTokenProvider`, `GitHubF1Ledger`, `DesktopController`, `FileExecutionJournal`, `DesktopControllerDaemon` (`runControllerDoctor`), `projectWorkerStateForCommandCenter`.

---

## 4. Independent-Review Preparation Findings (`F3-00`)

Full tabular findings reside in `bke-worker/docs/f3-security-audit.md`. Summary of demonstrated gaps audited in F2 and repaired in F3:

1. **Finding A1 (P0) — Symmetric HMAC Shared-Secret Risk:** In F2 (`protocol_version: 1`), a compromised desktop host holding `BKE_EXECUTION_SIGNING_KEY` could self-mint valid HMAC execution envelopes. **Fix:** Added asymmetric Ed25519 V2 protocol (`protocol_version: 2`) where the desktop stores **only** SPKI public PEMs plus `requireAsymmetricV2` downgrade lock (`EXEC_REQ_DOWNGRADE_FORBIDDEN`).
2. **Finding A2 (P0) — Asymmetric HALT Key Confusion:** **Fix:** Enforced strict non-overlap of public keys between `executionPublicKeysById` and `remoteHaltPublicKeysById` in both `ExecutionRequestVerifier` (`EXEC_REQ_HALT_KEY_SEPARATION_REQUIRED`) and `DesktopControllerDaemon` (`DAEMON_HALT_KEY_SEPARATION_FORBIDDEN`).
3. **Finding A3 (P0) — Missing Device/Generation/Revocation Binding in Envelopes:** **Fix:** Bound V2 envelopes to `broker_issuer`, `audience`, `device_id`, `enrollment_generation`, plus live/cached `deviceRevocationChecker` (`EXEC_REQ_DEVICE_REVOKED`, `EXEC_REQ_ENROLLMENT_STALE`).
4. **Finding B1 (P0) — Automatic 3xx Redirect Following on GitHub HTTP Calls:** **Fix:** Added `redirect: 'manual'` across all `RestGitHubAuthorityProvider` and `GitHubF1Ledger` fetches (plus `SandboxGitHubAppAdapter` and `SandboxHttpTokenBrokerClient`), failing closed on HTTP `300..399` (`GITHUB_REDIRECT_BLOCKED`).
5. **Finding B2 (P1) — `maintain: true` / Empty GitHub Repository Permissions:** **Fix:** `RestGitHubAuthorityProvider` now rejects missing/empty `permissions` (`GITHUB_REPOSITORY_PERMISSIONS_MISSING`) and `maintain === true` (`GITHUB_PERMISSION_FORBIDDEN`).
6. **Finding B3 (P1) — Ledger API URL Hardcoding Blocking Multi-Process Local REST:** **Fix:** Added optional `baseApiUrl` to `GitHubF1LedgerConfig` (defaulting to `'https://api.github.com'`) so isolated OS daemon processes can talk to `MockGitHubServer` over real HTTP.
7. **Finding B4 (P1) — Single-Repo Token Blindness to Cross-Repo Worker PR Conflicts:** **Fix:** `SandboxGitHubAppAdapter.verifyExecutionAuthority()` sweeps open PRs across *all* installation repositories (`BROKER_CROSS_REPO_WORKER_CONFLICT`).
8. **Finding C1 (P1) — Ambiguity Between Pre-Claim Broker Outage & Post-Claim Uncertainty:** **Fix:** Bounded retry in `ManagedTokenProvider` restricted solely to `TOKEN_BROKER_UNAVAILABLE` / `TOKEN_BROKER_TIMEOUT` pre-claim, leaving post-claim / DOM send failures strictly zero-retry `DELIVERY_UNCERTAIN`.
9. **Finding D1 (P2) — Desktop Possession of `contents: write` Installation Tokens:** **Fix:** Prototyped server-mediated 4-op CAS (`executeServerMediatedLedgerOp()`) preventing arbitrary proxy calls while preserving existing desktop ledger compatibility until production migration.

---

## 5. Cryptographic Architecture Decisions

### 5.1 Protocol V2 (`Ed25519` Asymmetric) vs Legacy V1 (`HMAC-SHA256`)

| Dimension | V1 Legacy (`F2`, Compat/Fallback Only) | V2 Production-Shaped (`F3`, Default-OFF Flag) |
|---|---|---|
| **Algorithm & Keys** | `HMAC-SHA256` symmetric shared secret (`64` hex chars) | `Ed25519` asymmetric (`PKCS8` private on broker ONLY; `SPKI` public PEM pinned on desktop) |
| **Compromised Desktop Blast Radius** | Can forge valid envelopes if secret extracted | **Cannot forge** any execution or HALT envelope (`0` signing private keys on desktop) |
| **Domain Separation** | Raw JSON string | `'BKE_EXECUTION_REQUEST_V2\n'` + sorted 18-key canonical JSON |
| **Fields Bound** | 14 fields (`repository_*`, `installation_identity`, `worker_id`, `pr_number`, `head_sha`, `attempt_id`, `delivery_id`, `action`, `issued_at`, `expires_at`, `authorized_capability`) | 18 fields: adds `broker_issuer`, `audience` (`bke-desktop-controller:<repo>:<worker>`), `device_id`, `enrollment_generation` |
| **HALT Key Isolation** | Distinct `remoteHaltSigningKeysById` HMAC secret + `allowRemoteSignedHalt: false` default | Distinct `remoteHaltPublicKeysById` SPKI PEM + `allowRemoteSignedHalt: false` default (`EXEC_REQ_HALT_KEY_SEPARATION_REQUIRED`) |
| **Algorithm Downgrade Prevention** | N/A | When `requireAsymmetricV2: true` (or `BKE_REQUIRE_ASYMMETRIC_V2=true`), presenting `protocol_version: 1` or `HMAC-SHA256` immediately returns `403 EXEC_REQ_DOWNGRADE_FORBIDDEN`; V2 header with `HMAC-SHA256` returns `400 EXEC_REQ_ALGORITHM_MISMATCH`. |

### 5.2 Other Cryptographic Ceremonies & Migration Notes

- **Three Domain-Separated Signing Contexts:**
  1. `'BKE_ADMIN_APPROVAL_V1\n'` (`Ed25519` admin approval tokens for enrollment, key rotation, revocation, dispatch intent, broker key rotation).
  2. `'BKE_DESKTOP_ENROLLMENT_V1\n'` (`ECDSA P-256` / SHA-256 IEEE-P1363 device enrollment & rotation proof).
  3. `'BKE_DESKTOP_DEVICE_POP_V1\n'` (`ECDSA P-256` per-request device PoP assertions scoped to `purpose`, `installation_id`, `enrollment_generation`, `repository`, `nonce`, `issued_at`/`expires_at`).
- **Safe V1 -> V2 Migration Path:** Keep `BKE_EXECUTION_V2_ASYMMETRIC_ENABLED=false` and `BKE_REQUIRE_ASYMMETRIC_V2=false` by default in `deploy/desktop-controller.env.example`. During migration: (Step 1) enroll device & deploy broker SPKI public PEMs (`BKE_BROKER_PUBLIC_KEY_PEM` != `BKE_REMOTE_HALT_PUBLIC_KEY_PEM`), enable compat mode (`V2=true, REQUIRE_V2=false`), then (Step 2) flip `BKE_REQUIRE_ASYMMETRIC_V2=true` (`v2_ed25519_strict`) to permanently disable HMAC V1 (`EXEC_REQ_DOWNGRADE_FORBIDDEN`) and delete `BKE_EXECUTION_SIGNING_KEY`. Verified in `f3-hardening.test.mjs` (#1).

---

## 6. Existing GitHub App Broker Reconciliation (`F3-01`)

Verified directly against frozen `bke-worker/cloudflare-relay/src/{github-app.js,admin-broker.js,index.js}` (`bke-worker/docs/f3-existing-github-app-contract.md`):

- **Key Storage:** `BKE_WORKER_GITHUB_APP_PRIVATE_KEY_PEM` + `BKE_WORKER_GITHUB_APP_ID` reside exclusively in Cloudflare secrets and import non-extractably (`extractable: false`) in WebCrypto. Zero PEMs exist anywhere on desktop or in `integrations/desktop-broker/`.
- **Implemented vs Missing Endpoints:**
  - `POST /github/app/install-token` is strictly scoped to **GitHub Actions OIDC RS256** (`CONTROL_REPOSITORY = "jan2xo/bke-worker"`, `CONTROL_REPOSITORY_ID = "1354026486"`). It is **NOT** a general desktop credential service.
  - `CommandCenterReadBroker` (`WorkerEntrypoint`) exposes 3 read-only service-binding RPCs (`mintReadOnlyGitHubToken`, `listApprovedGitHubRepositories`, `listVerifiedWorkerAssignments`)—**no HTTP ingress**, **no desktop device enrollment**, and **no desktop Ed25519 signing**.
  - Multi-repo discovery already exists for read catalogs/assignments, while `mintInstallationToken` hardcodes `CONTROL_REPOSITORY_ID`. Production desktop activation will require a dedicated owner-authorized PR against `cloudflare-relay/` (`PR-14`).

---

## 7. Worker Identity & Device Enrollment (`F3-02`)

Implemented in `integrations/desktop-broker/src/device-enrollment.ts` (`DeviceEnrollmentRegistry`):

- **Identity Model (`EnrolledDeviceRecord`):** Binds `version: 1`, `installation_id`, `worker_id`, `device_id`, `public_key_spki_pem` (strictly `ec` / `prime256v1`), `public_key_sha256`, `browser_profile_identity` (64-hex), `native_bridge_identity` (64-hex), `authorized_repository_scope`, `enrollment_generation` (`>= 1`), `revocation_state` (`'ACTIVE' | 'REVOKED' | 'LOST'`), `revoked_reason`, `enrolled_at`, `updated_at`, `enrolled_by_admin`.
- **Fail-Closed Pairing Guarantees:**
  - Requires valid Ed25519 Admin signature (`APPROVE_ENROLLMENT`, TTL bounded) + server-issued single-use `challenge_id`/`nonce_b64url` (`CHALLENGE_TTL_MS = 120_000`) + device P-256 signature.
  - Rejects all client privilege flags (`trusted`, `admin_approved`, `self_authorized`, `bypass_admin`, `auto_approve`, `permissions_override`, `live_send_authorized`) with `ENROLLMENT_PRIVILEGE_ESCALATION_FORBIDDEN`.
  - Guarantees 1:1 `worker_id -> device_id` exclusivity (`ENROLLMENT_WORKER_ALREADY_BOUND`), globally unique P-256 keys (`ENROLLMENT_PUBLIC_KEY_REUSED`), globally unique isolated Chrome profiles across workers (`ENROLLMENT_BROWSER_PROFILE_REUSED`), concurrent `Promise.allSettled` single-winner atomicity via POSIX `withFileLock` + `lstat` symlink detection, key rotation (`1 -> 2` immediately invalidating generation `1`), permanent terminal revocation (`REVOKED` / `LOST`), `0o600` file-mode checks, and JSON corruption rejection.

---

## 8. Trusted Broker Reference Implementation (`F3-03`)

Isolated cleanly in `bke-worker/integrations/desktop-broker/` (`SandboxBrokerHttpServer` + `TrustedDesktopBroker` + `SandboxGitHubAppAdapter`):

- **Loopback-Only Sandbox Boundary:** Binds strictly to `127.0.0.1` (`BROKER_NON_LOOPBACK_FORBIDDEN` for non-loopback sockets), uses ephemeral test keys in `statePath` (`0o600`, `O_NOFOLLOW`), logs redacted audit events (`seq <= 500` ring buffer, zero tokens/keys), and has **zero** Cloudflare bindings or deploy scripts.
- **Authorization Gate Pipeline (`authorizeExecution`):**
  1. Verifies Admin Ed25519 `DISPATCH_EXECUTION` approval + scope match (`installation_id`, `worker_id`, `pr_number`, `head_sha`, `attempt_id`, `action`).
  2. Verifies Desktop ECDSA P-256 `AUTHORIZE_EXECUTION` PoP assertion (checks `ACTIVE`, `enrollment_generation`, `authorized_repository_scope`).
  3. Consumes single-use `nonce` and `delivery_id` under exclusive POSIX file lock before authority checks/signing.
  4. Calls `SandboxGitHubAppAdapter.verifyExecutionAuthority()` (`redirect: 'manual'`, installation status, `admin`/`maintain` escalation rejection, cross-repo worker PR sweep, open PR exact `head_sha`, valid `bke-ticket:v1` check run, `refs/bke/uncertain/*` and duplicate claim absence, and conversation existence matching `DISPATCH_FIRST_MESSAGE` vs `DISPATCH_CONTINUATION`).
  5. Mints V2 Ed25519 envelope using role-separated `EXECUTION` or `HALT` key (`broker-exec-k*` vs `broker-halt-k*`), supporting live rotation (`rotateSigningKey`) retaining `VERIFY_ONLY` keys cleanly.
- **Token Minimization vs Server-Mediated Ledger Ops Comparison:**
  - `mintScopedToken()` restricts desktop tokens solely to `{ contents, pull_requests, checks }` (never `admin`/`issues`/`actions`, and `pull_requests`/`checks` forced `read`-only), bound to `repository_ids: [expectedRepositoryId]`, TTL clamped `<= 180s`, with SHA-256 token revocation tracking (`revokeIssuedToken` / `isTokenRevoked`).
  - `executeServerMediatedLedgerOp()` demonstrates eliminating `contents: write` from desktop entirely by allowing ONLY 4 exact operations (`COMMIT_PRE_SEND_FENCE`, `CONSUME_SEND_CLAIM`, `RECONCILE_CONVERSATION`, `MARK_DELIVERY_UNCERTAIN`) and rejecting any non-allowlisted operation or ref path (`BROKER_ARBITRARY_PROXY_FORBIDDEN`, verified in `broker-service.test.mjs` #17). Current desktop controller retains the F2 single-repo token path so frozen production compatibility holds without rewrite.

---

## 9. GitHub Authority, Permission Matrix & Credential Lifecycle (`F3-05`, `F3-06`)

### 9.1 GitHub Provider Permission Matrix

| Component | HTTP Methods | Required Installation Permissions | Forbidden Scopes / Behaviors |
|---|---|---|---|
| **`RestGitHubAuthorityProvider`** (Desktop) | **`GET` ONLY** | `metadata: read`, `pull_requests: read`, `checks: read`, `contents: read` | Rejects `POST/PATCH/PUT/DELETE`, `admin: true`, `maintain: true`, empty `permissions: {}`, `3xx` redirects, truncated `Link: rel="next"`, `check_runs.length < total_count`, `repository.id` mismatch. |
| **`GitHubF1Ledger`** (Desktop) | `GET`, `POST`, `PATCH` (strictly `refs/bke/*` CAS) | `contents: write` (single repo only) | Rejects `3xx` redirects; requires `expectedRepositoryId` & fast-forward/CAS precondition; writes `refs/bke/uncertain/*` on ambiguous `POST /git/refs`. |
| **`SandboxGitHubAppAdapter`** (Broker Reference) | `GET`, `POST` (mint token / mediated CAS), `PATCH` (mediated CAS) | App JWT resolves installation -> clamps single-repo token to `contents`/`pull_requests`/`checks`; cross-repo sweep uses installation token across installed repos | Rejects suspended/revoked/missing installation, `admin`/`maintain`/`administration:write`, cross-repo worker PR conflict (`BROKER_CROSS_REPO_WORKER_CONFLICT`), non-allowlisted mediated ops (`BROKER_ARBITRARY_PROXY_FORBIDDEN`). |

### 9.2 Credential Lifecycle & Recovery Classification (`F3-06`)

| Failure Trigger | Component Classification (`TokenLifecycleStatus.lastRecoveryClassification` / Journal) | Auto-Retry Policy | Required Reconciliation |
|---|---|---|---|
| `TOKEN_BROKER_UNAVAILABLE` / `TOKEN_BROKER_TIMEOUT` before GitHub ref mutation | `RECOVERED_TRANSIENT` (when succeeded within bounded `maxTransientRetries`) or abort pre-claim | Bounded retry (`maxTransientRetries <= 3`, `retryDelayMs <= 250`, caller deadline safe) | Safe automatic recovery when retries succeed; otherwise aborts cleanly (`IDLE`, 0 GitHub writes). |
| `TOKEN_REVOKED`, `EXEC_REQ_DEVICE_REVOKED`, `BROKER_PERMISSION_*`, wrong install/repo | `BLOCKED_PERMANENT` (`NON_RETRYABLE_ERROR`) | **Zero retries** | Human owner must inspect permissions, re-enroll or rotate device key. |
| Timeout / connection drop *after* `POST /git/refs` or lying read-back mismatch | `DELIVERY_UNCERTAIN` quarantine | **Zero retries** (never crosses post-claim boundary) | Quarantined locally + `refs/bke/uncertain/<pr>/<attempt>` on GitHub; human reconciliation mandatory. |
| Browser IPC disconnect mid-send or `submitContinuationOnce` URL conversation drift | `DELIVERY_UNCERTAIN` quarantine (`HTTP 409`) | **Zero retries** (prevents duplicate ChatGPT send) | Owner inspects ChatGPT tab & GitHub refs before manual reset. |

---

## 10. Desktop Broker-Controller Integration (`F3-04`)

Verified in `controller-daemon.ts` + `github-app-harness.ts` + `integrations/desktop-broker/tests/helpers/controller-runner.mjs`:

- `POST /execution-requests` stays **DISABLED by default** (`403 EXECUTION_ENVELOPE_DISABLED`).
- When explicitly configured for V2 (`asymmetricV2Enabled: true`), `DesktopControllerDaemon` enforces constructor-time PEM separation (`DAEMON_HALT_KEY_SEPARATION_FORBIDDEN`), passes `SignedExecutionRequestV2` to `ExecutionRequestVerifier` (checking V2 signature, downgrade policy, issuer, `audience`, `device_id`, `enrollment_generation`, `deviceRevocationChecker`, HALT-vs-dispatch key isolation), revalidates fresh live GitHub state via `RestGitHubAuthorityProvider` (with `ManagedTokenProvider`), reserves atomically in `FileExecutionJournal.asPersistentReplayStore()`, executes claim/fence & synthetic browser dispatch through `DesktopController` -> `IpcBridgeClient` -> `entry.mjs --controller-bridge`, and persists durable Turn 1 / Turn 2 refs.
- **No Permissive Fallback:** Broker downtime, unknown public key, stale `enrollment_generation`, revoked device, or unconfigured `humanLiveSendAuthorized: false` (`409 LIVE_SEND_DISABLED`) unconditionally block browser dispatch (`0` DOM submits).

---

## 11. Replay & Crash Guarantees (`F3-05`, `F3-07`)

- **Local Replay & Reservation (`FileExecutionJournal` + `PersistentReplayStore`):** Single-writer POSIX file lock (`O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW` + `lstat()` symlink rejection on `EEXIST`) guards atomic `O_NOFOLLOW` + `fsync()` + `rename()` state updates (`processedDeliveries`, `processedAttempts`, `reservedAttempts`).
- **Ordered Crash Boundaries:**
  1. *Broker crash before signing* -> Retryable; client holds no valid envelope (`0` controller side effects).
  2. *Broker crash after signing* -> Controller checks replay cache + live GitHub state; duplicate delivery IDs reject `EXEC_REQ_DELIVERY_REPLAYED`.
  3. *Controller crash before reservation* -> Retryable cleanly (`IDLE`).
  4. *Controller crash after `RESERVED` / `FENCED`, or during `DISPATCHING` / `CONTINUING`* -> On restart, `FileExecutionJournal.openAndRecover()` detects incomplete/in-flight dispatch phase, marks `DELIVERY_UNCERTAIN`, preserves replay sets, and blocks duplicate dispatch until owner reconciliation.
  5. *Monotonic Bridge Sequencing:* `controller-daemon.ts` uses `monotonicDaemonBootOffset` so restarting the controller while `entry.mjs --controller-bridge` stays up never triggers false `COMMAND_SEQ_REPLAY` on legitimate subsequent wakes.
- **GitHub CAS & Ambiguity:** `GitHubF1Ledger` fails closed on `409`/`422` existing conflicting refs, network ambiguity after `POST /git/refs`, and read-back SHA mismatches (`CONSUME` vs readback), writing `refs/bke/uncertain/*`.

---

## 12. Full End-to-End Execution Trace (`multiprocess-e2e.test.mjs`)

Observed trace across **three real OS child processes** (`SandboxBrokerHttpServer` + `DesktopControllerDaemon` via `controller-runner.mjs` + `entry.mjs --controller-bridge`) plus `MockGitHubServer` and P-256 MV3 `connectControllerNativeBridge`:

1. **Bootstrap & Enrollment:** `DeviceEnrollmentRegistry` issues challenge -> Admin Ed25519 signs `APPROVE_ENROLLMENT` -> desktop `DeviceKeyPairSigner` completes enrollment (`enrollment_generation: 1`, `ACTIVE`).
2. **Real-Process Launch & Native P-256 Bridge:** `broker-server.js` starts on ephemeral loopback port publishing V2 Ed25519 SPKI public keys; `entry.mjs --controller-bridge` starts private Unix IPC socket (`0o700`/`0o600`) and completes ECDSA P-256 handshake (`connectControllerNativeBridge`) over framed native stdio.
3. **Locked Default Proof (`humanLiveSendAuthorized: false`):** `controller-runner.mjs` starts with live send disabled; signed V2 `PREPARE` succeeds (`head_sha` pinned, `0` submits); signed V2 `DISPATCH_FIRST_MESSAGE` returns `409 LIVE_SEND_DISABLED` (`0` submits).
4. **Authorized Synthetic Turn 1 (`CONFIRMED_TURN_1`):** Supervised daemon instance receives broker-signed V2 `DISPATCH_FIRST_MESSAGE` (`attempt-f3-mp-01`), passes `ExecutionRequestVerifier` + live `RestGitHubAuthorityProvider` + `ManagedTokenProvider` (broker-minted token via `/v1/broker/tokens`) + `GitHubF1Ledger` (`refs/bke/fences/...`, `refs/bke/claims/...`) -> IPC -> `entry.mjs` -> native bridge -> `ExtensionBrowserAdapter` landing submit -> confirms `/c/conv-f3-mp-01` (`confirmedTurnCount: 1`) and writes `refs/bke/conversations/149` + `refs/bke/turns/149/attempt-f3-mp-01`.
5. **Same-Conversation Turn 2 (`CONFIRMED_CONTINUATION`):** Signed V2 `DISPATCH_CONTINUATION` re-verifies broker + GitHub authority + existing conversation commit -> submits Turn 2 inside exact same `/c/conv-f3-mp-01` (`confirmedTurnCount: 2`).
6. **Diagnostics & Fail-Closed Cross-Check:** `GET /status` returns secret-free v3 JSON (`deviceIdentity`, `broker.protocolVersion: "v2_ed25519_strict"`, `tokenLifecycle`, zero leaked `ghs_`/`PRIVATE KEY` strings); replays return `409`; and Command Center projection checks all `14` `F2_REQUIRED_VISIBLE_STATES` pass.

---

## 13. Command Center Compatibility (`F3-08`)

- **Do Any `jan2xo/bke-command-center` Changes Need to Happen Now?** **NO.** Command Center remains read-only over existing `CommandCenterReadBroker` WorkerEntrypoint RPCs (`mintReadOnlyGitHubToken`, `listApprovedGitHubRepositories`, `listVerifiedWorkerAssignments`) and was **0% modified**.
- **F3 Evidence Projection Verification:** Multi-process E2E and chaos outputs were projected through `projectWorkerStateForCommandCenter()` (`command-center-observer.ts`) confirming all `14/14` `F2_REQUIRED_VISIBLE_STATES` plus fail-closed `dispatchReady: false`, `executionState: "UNKNOWN"` on partial evidence, `DELIVERY_UNCERTAIN_BLOCKED`, and `realBrowserAcceptance: "NOT_RUN"`.
- **Proposed Future Read-Only Task (`bke-worker/docs/f3-command-center-integration.md`):** Adds `src/worker-observer/bke-worker-projection.js` (`/api/admin/worker-observer.js`) strictly read-only behind Cloudflare Access Admin auth, consuming `RawWorkerObserverEvidence` + GitHub `refs/bke/*`, treating non-atomic inventories as `NON_ATOMIC_STALE_SNAPSHOT`, and tested with 6 negative fail-closed tests.

---

## 14. Complete Verification Matrix & GitHub CI Evidence

> **Exact-Commit Provenance:** All rows below were executed **after the final F3 code edit** in this container workspace (`2026-11-14`). No claims are carried over unverified from older SHAs (`a3f268f9c2fc16a84ac15d4243569d4fb3860a6e`). External sync to `jan2xo/bke-worker-h` is required to obtain `final_sha` and run `.github/workflows/hydrogen-sandbox-ci.yml`.

### 14.1 Post-Final-Edit Observed Test Results

| Command / Suite | Observed Outcome | Counts & Coverage |
|---|---|---|
| `npm --prefix bke-worker/integrations/desktop-broker run check` | **PASS** (`exit 0`, ~2.4s) | `tsc` 0 errors + **4/4 suites PASS**: `device-enrollment.test.mjs` (**14** enrollment/revocation checks), `broker-service.test.mjs` (**17** broker security + rotation + CAS + F3-05 installation checks), `multiprocess-e2e.test.mjs` (**3-process OS E2E** + 14 CC states), `chaos-adversarial.test.mjs` (**18 chaos scenarios** + F3-05 claim/receipt failures) |
| `npm --prefix bke-worker/browser-extension run check` | **PASS** (`exit 0`) | Strict `tsc`, MV3 `validate`, **202/202** extension tests + **39/39** native-host ESM tests + **55/55** host-claim tests (including `f3-hardening.test.mjs` **4/4**) |
| `npm --prefix bke-worker/browser-extension run controller:doctor` | **PASS** (`exit 0`) | `ok: true`, `liveSendDefaults: "LOCKED_FALSE"`, `broker_protocol_mode: "DISABLED_BY_DEFAULT"`, `execution_envelope_mode: "DISABLED_BY_DEFAULT"`, secret-free v3 JSON |
| `npm --prefix bke-worker/browser-extension run smoke:native` | **PASS** (`exit 0`) | `BKE_DESKTOP_NATIVE_SMOKE=PASS` (`9/9`), `BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN` |
| `node bke-worker/scripts/input-only-lint.mjs` & `node --test bke-worker/scripts/input-only-lint.test.mjs` | **PASS** (`4/4`) | Zero assistant-reply DOM reads across extension sources |
| `npm --prefix bke-worker/cloudflare-relay run check` & `reconnect-recovery-test` | **PASS** (`191/191` + PASS) | Untouched frozen Cloudflare relay & Android recovery planner |
| All Python / Node / Bash contracts in `bke-worker/tests/` | **ALL PASS** (`exit 0`) | `forge_f1_desktop_mvp_contract.py`, `forge_f1_desktop_readiness_contract.py`, `chrome_native_host_installer_contract.{py,sh}`, `operator_entrypoint_contract.py`, `android_gecko_probe_contract.py`, `android_recovery_operator_contract.py`, `cloudflare_relay_contract.py`, `admin_preproduction_activation.test.mjs` (**10/10**) |
| `bash bke-worker/scripts/package-desktop-worker.sh package/verify/clean-uninstall` | **PASS** (`exit 0`) | **53** bundle files SHA-256 verified in `package-manifest.json`; `live_send_locked_false: true`, `execution_envelope_default_disabled: true`; clean removal leaves zero residues |
| `bash bke-worker/scripts/certify-forge-f1-desktop-mvp.sh --sandbox --dry-run` | `BKE_F1_MVP_CERTIFICATION=BLOCKED reason=NOT_IN_GIT_REPOSITORY` | Expected fail-closed behavior in gitless `/app/applet` container; executed against real Git checkout inside `.github/workflows/hydrogen-sandbox-ci.yml` |

---

## 15. Outstanding Security Risks & Known Boundaries

1. **V1 HMAC Compatibility Risk When Upgraded Only Partially:** If an operator enables `BKE_EXECUTION_ENVELOPE_ENABLED=true` and `BKE_EXECUTION_V2_ASYMMETRIC_ENABLED=true` while leaving `BKE_REQUIRE_ASYMMETRIC_V2=false` and populating `BKE_EXECUTION_SIGNING_KEY`, V1 HMAC acceptance stays active. Operators should migrate directly to `BKE_REQUIRE_ASYMMETRIC_V2=true` (`v2_ed25519_strict`) with V1 HMAC keys omitted.
2. **Scoped Desktop Token (`contents: write`) Window:** While `executeServerMediatedLedgerOp` proves server-mediated CAS writes are viable without giving desktop `contents: write`, the active `RestGitHubAuthorityProvider` / `GitHubF1Ledger` runtime currently still consumes single-repo `contents: write` installation tokens (bounded `<= 180s`). Until production migrates to broker-mediated CAS (`PR-14`), a compromised host during an active 180s window can access unprotected refs in that single bound repo.
3. **Trusted Clock Skew & Local File Lock Scope:** Replay/expiry correctness assumes bounded system clock skew (`<= 5s`) and local POSIX `0o700`/`0o600` filesystem isolation (same OS user UID; multi-host concurrent controllers sharing one worker ID are prevented on GitHub via `GitHubF1Ledger` CAS, though local lockfiles protect single-host concurrency).
4. **Revocation Check Latency vs Cached Daemon State:** In `controller-daemon.ts`, `deviceRevocationChecker` invokes `POST /v1/enrollment/status` if configured; if offline/unconfigured in airgapped tests, only `minEnrollmentGeneration` and envelope expiry enforce staleness. Production wiring should make broker revocation checks mandatory on `DISPATCH_*`.
5. **Known Pre-Existing Frozen Architecture Limits:** `cloudflare-relay/` hardcodes `CONTROL_REPOSITORY = "jan2xo/bke-worker"` for webhooks/token minting and has zero desktop device registry.

---

## 16. Unverified External Dependencies & Assumptions

1. **Real Cloudflare Production / Preproduction Broker (`EXTERNAL BLOCKED` / `NOT_AUTHORIZED`):** `cloudflare-relay/` is frozen; `/v1/desktop/enroll/*`, `/v1/broker/authorize`, and `/v1/broker/tokens` do not yet exist in production Cloudflare Workers.
2. **Live GitHub App Secrets & `bke-ticket:v1` Signing (`EXTERNAL BLOCKED`):** No live GitHub App PEM, PAT, or Cloudflare secrets exist in `jan2xo/bke-worker-h`; production `bke-ticket:v1` minting and live GitHub REST rate limits are unexercised here.
3. **Level 7 Real Chrome 2-Turn Acceptance (`HUMAN ACCEPTANCE REQUIRED` / `NOT_RUN`):** Real ChatGPT DOM, signed-in Google/ChatGPT profile, Chrome popup `nativeMessaging` grant, and supervised `BKE_OWNER_SUPERVISED_LIVE_SEND=I_OWNER_AUTHORIZE_LIVE_SEND` remain deliberately unexecuted.
4. **Synchronized GitHub Commit SHA & `Hydrogen Sandbox CI` (`PENDING SYNC`):** Workspace changes must be synced to `jan2xo/bke-worker-h` externally and observed passing on GitHub Actions.
5. **`.NET` (`BKE.Worker.sln`) & Android Emulator Runtime:** Untouched frozen C#/Android runtimes are absent from this Node/Python container.

---

## 17. Canonical Promotion Requirements (`F3-10`)

Reconciled in `bke-worker/docs/canonical-promotion-plan.md` against `jan2xo/bke-worker/.github/workflows/pr-guard.yml`:

- **500-Line ALL-Files Gate:** `pr-guard.yml:341-345` counts `additions + deletions` across **code + tests + docs combined** (`<= 500` lines unless `bke:oversize-ok`). Several modules (`controller-daemon.ts` [1,244], `github-f1-ledger.ts` [1,112], `desktop-controller.ts` [975], `controller-transport.ts` [860], `github-app-harness.ts` [744], `device-enrollment.ts` [691], `broker-service.ts` [683], `github-app-adapter.ts` [570], `github-authority-provider.ts` [545], `token-lifecycle.ts` [511], plus oversized test suites) require either the documented sub-450-line helper decompositions or explicit owner `bke:oversize-ok` labels.
- **`deploy/` Frozen Path Rule:** Only `deploy/desktop-controller.env.example` (67 lines) and `deploy/owner-native-policy.template.json` (13 lines) touch `deploy/`, so **PR-11a**'s `MVP-Task: #<issue>` must explicitly name `deploy/`.
- **Markdown Filename Rule:** Any canonical PR adding new `.md` docs MUST list exact filenames in its linked `#<issue>`.
- **14-Wave Plan (`PR-1..PR-14`):** `PR-1..PR-6` (F1 core), `PR-7` (Verifier V1+V2, authority validators, token lifecycle), `PR-8` (Daemon V1+V2, `status` v3, `doctor` v3), `PR-9` (Command Center 14 states), `PR-10` (Multi-process E2E & reliability tests), `PR-11` (Packaging/templates/docs), `PR-12..PR-13` (F3 sandbox reference broker & chaos suites), `PR-14` (**Future owner-only PR** modifying frozen `cloudflare-relay/`).

---

## 18. Owner-Controlled Operational Acceptance Procedure

When the owner later chooses to certify live desktop execution on an owned workstation (never in CI):

1. Synchronize this workspace to `jan2xo/bke-worker-h` and confirm `Hydrogen Sandbox CI` (`github-sandbox-ci.yml`) is 100% green on the resulting SHA (`certify-forge-f1-desktop-mvp.sh --sandbox --dry-run` included).
2. Build & verify the non-secret desktop package (`bash bke-worker/scripts/package-desktop-worker.sh package`).
3. Provision real broker / GitHub App infrastructure via dedicated owner PR (**PR-14** on `cloudflare-relay/`), keeping Ed25519 signing private keys and App PEM solely in Cloudflare Secrets.
4. Enroll the desktop device (ECDSA P-256 non-exportable WebCrypto key) with explicit Admin Ed25519 approval; place **only** the broker SPKI public keys (`BKE_BROKER_PUBLIC_KEY_PEM` != `BKE_REMOTE_HALT_PUBLIC_KEY_PEM`) into `~/.config/bke-worker/f1-controller.env` (`chmod 600`) with `BKE_REQUIRE_ASYMMETRIC_V2=true` (`v2_ed25519_strict`).
5. Run `npm --prefix bke-worker/browser-extension run controller:doctor` and confirm `ok: true` and `liveSendDefaults: "LOCKED_FALSE"`.
6. Manually authenticate Chrome inside isolated profile (`forge-f1-desktop-readiness.sh`), install native host (`prepare-chrome-native-host.sh install`), click **Connect controller bridge (opt-in)** in the popup, and run single-session supervised two-turn execution with `--owner-supervised-live-send` + `BKE_OWNER_SUPERVISED_LIVE_SEND=I_OWNER_AUTHORIZE_LIVE_SEND`, keeping `curl -H "x-bke-halt-token: ..."` ready.

---

## 19. Independent GPT-6 Security Audit Checklist

- [ ] Inspect the external GitHub sync commit SHA on `jan2xo/bke-worker-h` and verify `Hydrogen Sandbox CI` passes cleanly (`browser-extension`, `integrations/desktop-broker`, `certify-forge-f1-desktop-mvp.sh --sandbox --dry-run`, contracts, packaging).
- [ ] Diff `bke-worker/cloudflare-relay/`, `bke-worker/android-gecko/`, `bke-worker/src/`, `bke-worker/BKE.Worker.sln`, `bke-worker/Directory.Build.props`, and `bke-worker/.github/workflows/pr-guard.yml` against F2 SHA `a3f268f9c2fc16a84ac15d4243569d4fb3860a6e` to confirm `0` changed bytes.
- [ ] Audit `github-app-harness.ts` (`ExecutionRequestVerifier.verifyRequest`) for V2 Ed25519 domain separation (`'BKE_EXECUTION_REQUEST_V2\n'`), strict `requireAsymmetricV2` downgrade block, HALT key isolation (`EXEC_REQ_HALT_KEY_SEPARATION_REQUIRED`), `issuer`/`audience`/`device_id`/`enrollment_generation` checks, and `deviceRevocationChecker`.
- [ ] Audit `device-enrollment.ts` (`DeviceEnrollmentRegistry`) for client privilege-flag rejection, single-use challenge consumption, global public-key / browser-profile uniqueness, `0o600`+`O_NOFOLLOW` lock/state hardening, and terminal `REVOKED`/`LOST` tombstones.
- [ ] Audit `broker-service.ts` and `github-app-adapter.ts` for absence of real secrets, role-separated `EXECUTION` vs `HALT` key generation/rotation, cross-repo worker PR exclusivity sweep, `redirect: 'manual'`, and server-mediated 4-op CAS allowlist (`BROKER_ARBITRARY_PROXY_FORBIDDEN`).
- [ ] Audit `token-lifecycle.ts` (`ManagedTokenProvider`) to verify bounded transient retry strictly stops before claim (`PRE_CLAIM_AUTO_RETRY_SAFE`) and never retries post-claim `DELIVERY_UNCERTAIN` or `BLOCKED_PERMANENT`.
- [ ] Confirm `FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const`, `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const`, `BKE_EXECUTION_ENVELOPE_ENABLED=false`, `BKE_EXECUTION_V2_ASYMMETRIC_ENABLED=false`, `BKE_REQUIRE_ASYMMETRIC_V2=false`, and `BKE_REMOTE_BROKER_ENABLED=false` defaults.

---

## 20. Machine-Readable Completion Capsule

```json
{
  "schema": "bke.hydrogen.f3.handoff.v1",
  "repository": "jan2xo/bke-worker-h",
  "base_sha": "a3f268f9c2fc16a84ac15d4243569d4fb3860a6e",
  "final_sha": null,
  "github_ci_run": null,
  "f2_security_audit": "INTEGRATION_VERIFIED",
  "broker_reference": "INTEGRATION_VERIFIED",
  "device_enrollment": "INTEGRATION_VERIFIED",
  "authorization_protocol": "INTEGRATION_VERIFIED",
  "github_app_scope": "INTEGRATION_VERIFIED",
  "broker_controller_integration": "INTEGRATION_VERIFIED",
  "credential_lifecycle": "INTEGRATION_VERIFIED",
  "persistent_replay": "INTEGRATION_VERIFIED",
  "adversarial_tests": "INTEGRATION_VERIFIED",
  "command_center_compatibility": "UNIT_VERIFIED",
  "real_github_app_connection": "NOT_AUTHORIZED",
  "real_chrome_two_turn": "NOT_RUN",
  "live_send_enabled": false,
  "canonical_repository_modified": false,
  "command_center_modified": false,
  "production_modified": false,
  "remaining_blockers": [
    "EXTERNAL_GITHUB_SYNC_AND_EXACT_SHA_CI_PENDING",
    "REAL_CLOUDFLARE_DESKTOP_TOKEN_BROKER_NOT_AUTHORIZED",
    "REAL_GITHUB_APP_PEM_AND_LIVE_DELIVERY_NOT_AUTHORIZED",
    "LEVEL_7_REAL_CHROME_OWNER_ACCEPTANCE_NOT_RUN",
    "CONTAINER_MISSING_DOTNET_AND_DOT_GIT_FOR_LOCAL_CERTIFY_SH"
  ],
  "smallest_safe_next_step": "Synchronize completed F3 source from AI Studio to jan2xo/bke-worker-h, verify exact-SHA Hydrogen Sandbox CI passes, conduct independent GPT-6 audit against Section 19, and only then schedule owner-authorized Cloudflare broker PR-14 and Level 7 Chrome acceptance."
}
```
