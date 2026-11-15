# F4 Security Review Package — P0 Remediation & Multi-Host Certification

**Scope:** Phase F4 Remediation (`P0-01`, `P0-02`, `P0-03`, `F4-04`, packaging & CI hardening) on `jan2xo/bke-worker-h`
**F3 Verified Baseline:** `98478614932d6ef8b7bcdefd150752af250f2590` (CI Run `43609852033`)
**Frozen Surfaces (`cloudflare-relay/`, `android-gecko/`, `bke-worker/src/`, `BKE.Worker.sln`, `Directory.Build.props`, `bke-worker/.github/workflows/pr-guard.yml`):** `0` modified lines.

---

## 1. P0-01 — Elimination of Legacy V1 Authorization Downgrade

### Finding Addressed
In F3, `ExecutionRequestVerifier` and `DesktopControllerDaemon` allowed partial/mixed V2 configurations (`asymmetricV2Enabled: true` alongside `requireAsymmetricV2: false` or populated HMAC keys), creating a downgrade surface where compromised or misconfigured deployments could accept shared-secret V1 HMAC envelopes even when V2 Ed25519 was enabled.

### Implemented Remediations
- **Strict V2 Isolation (`github-app-harness.ts`):**
  - Enabling `asymmetricV2Enabled: true` implicitly enforces strict V2-only mode and unconditionally forbids V1 downgrade or compat flags:
    - `requireAsymmetricV2: true` with `asymmetricV2Enabled !== true` -> throws `EXEC_REQ_CONFIG_CONTRADICTORY`.
    - `asymmetricV2Enabled: true` with `requireAsymmetricV2 === false` -> throws `EXEC_REQ_CONFIG_DOWNGRADE_FORBIDDEN`.
    - Any populated `hmacKeysById` or `haltHmacKeysById` when `asymmetricV2Enabled: true` -> throws `EXEC_REQ_CONFIG_MIXED_V1_V2_FORBIDDEN`.
    - Missing `publicKeysById`, `expectedBrokerIssuer`, `expectedDeviceId`, or `deviceRevocationChecker` when `asymmetricV2Enabled: true` -> throws `EXEC_REQ_CONFIG_V2_KEYS_MISSING`, `EXEC_REQ_CONFIG_ISSUER_MISSING`, `EXEC_REQ_CONFIG_DEVICE_ID_MISSING`, or `EXEC_REQ_REVOCATION_CHECKER_MISSING`.
  - Runtime verification rejects any V1 payload (`protocol_version !== 2` or `HMAC-SHA256`) when `asymmetricV2Enabled: true` with `EXEC_REQ_DOWNGRADE_FORBIDDEN` (`HTTP 403`).
- **Daemon & Env Hardening (`controller-daemon.ts`, `deploy/desktop-controller.env.example`):**
  - `DesktopControllerDaemon` rejects contradictory, compat-mode, partial, mixed V1+V2, or revocation-checker-less V2 configs at construction (`DAEMON_CONFIG_CONTRADICTORY`, `DAEMON_V2_COMPAT_MODE_FORBIDDEN`, `DAEMON_CONFIG_V2_REQUIRES_ENVELOPE`, `DAEMON_MIXED_V1_V2_CONFIG_FORBIDDEN`, `DAEMON_V2_BINDINGS_INCOMPLETE`, `DAEMON_REVOCATION_CHECKER_MISSING`).
  - `runControllerDoctor` reports `v2_ed25519_strict` vs `v1_hmac_legacy` vs `DISABLED_BY_DEFAULT`, explicitly failing closed on compat downgrade or mixed V1+V2 configuration (`MIXED_V1_V2_FORBIDDEN`, `V2_COMPAT_MODE_FORBIDDEN`).

### Verification Evidence
- `bke-worker/browser-extension/native-host/claim/tests/f3-hardening.test.mjs` (#1)
- `bke-worker/browser-extension/native-host/claim/tests/f4-security-remediation.test.mjs` (P0-01 strict constructor & runtime downgrade suite)

---

## 2. P0-02 — Mandatory Fail-Closed Device & Token Revocation + Exact Generation Binding

### Finding Addressed
In F3, `deviceRevocationChecker` was optional in V2 configs, `ManagedTokenProvider.isRevoked` caught checker errors and returned `false` (fail-open), revocation/token-status HTTP responses lacked broker Ed25519 signatures/replay nonces, and `enrollment_generation` allowed `>= minEnrollmentGeneration` rather than exact generation matching.

### Implemented Remediations
- **Mandatory `deviceRevocationChecker` Returning Tri-State (`'ACTIVE' | 'REVOKED' | 'UNKNOWN'`):**
  - Only a verified `'ACTIVE'` result permits V2 execution (`github-app-harness.ts`).
  - `'REVOKED'` fails closed with `403 EXEC_REQ_DEVICE_REVOKED` (or `EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH`).
  - `'UNKNOWN'` or thrown exceptions fail closed with `503 EXEC_REQ_REVOCATION_UNAVAILABLE`.
  - Missing checker on V2 verifier/daemon fails immediately at constructor (`EXEC_REQ_REVOCATION_CHECKER_MISSING` / `DAEMON_REVOCATION_CHECKER_MISSING`) and runtime.
- **Exact `enrollment_generation` Match:**
  - `ExecutionRequestVerifier` rejects BOTH `< expectedEnrollmentGeneration` AND `> expectedEnrollmentGeneration` (`EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH`), preventing both stale-generation replay and unauthorized future-generation acceptance.
  - `DeviceEnrollmentRegistry.inspectDeviceStatus()` enforces exact `expected_enrollment_generation` equality (`EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH` vs `EXEC_REQ_DEVICE_REVOKED`).
- **Signed Ed25519 Broker Status Responses (`broker-service.ts`, `broker-server.ts`, `broker-client.ts`, `types.ts`):**
  - `/v1/enrollment/status` and `/v1/broker/token-status` return broker Ed25519-signed payloads domain-separated with `'BKE_ENROLLMENT_STATUS_V1\n'` and `'BKE_TOKEN_STATUS_V1\n'`, binding `broker_issuer`, `installation_id`, `worker_id`, `device_id`, `expected_enrollment_generation`, `actual_enrollment_generation`, single-use echoed `nonce`, `issued_at`, and `expires_at`.
  - `SandboxHttpTokenBrokerClient` enforces `redirect: 'manual'` (`3xx` blocked), validates broker SPKI signature + issuer + echoed nonce + freshness window (`<= 5s` skew) + exact generation/identity binding, and fails closed (`status: 'UNKNOWN'`, `code: 'EXEC_REQ_REVOCATION_UNAVAILABLE'`, `revoked: true`) on offline, HTTP `5xx`/`3xx`/timeout, malformed JSON, unsigned/forged/replayed/wrong-nonce/mismatched responses.
- **Fail-Closed Token Lifecycle (`token-lifecycle.ts`):**
  - Removed `.catch(() => false)` fail-open stub. `checkTokenStatus` / `isRevoked` failures fail closed (`TOKEN_REVOCATION_STATUS_UNAVAILABLE`), aborting pre-claim without retries.

### Verification Evidence
- `bke-worker/browser-extension/native-host/claim/tests/f4-security-remediation.test.mjs` (P0-02 tri-state, exact generation, fail-closed token status)
- `bke-worker/integrations/desktop-broker/tests/mediated-cas.test.mjs` (Signed HTTP revocation & token-status full fault matrix: offline, 503, 302 redirect, timeout, malformed JSON, unsigned, forged signature, wrong nonce, identity mismatch, generation `<` and `>`, revoked)

---

## 3. P0-03 — Complete Server-Mediated GitHub CAS (Zero Desktop `contents: write` Tokens)

### Finding Addressed
Although F3 prototyped `executeServerMediatedLedgerOp()` on the broker, desktop execution still relied on `contents: write` GitHub installation tokens in `GitHubF1Ledger` and allowed `mintScopedToken()` to mint `contents: write`.

### Implemented Remediations
- **Zero Desktop `contents: write` Minting (`broker-service.ts`, `token-lifecycle.ts`, `github-f1-ledger.ts`, `controller-daemon.ts`):**
  - `TrustedDesktopBroker.mintScopedToken()` unconditionally rejects `contents: 'write'` with `BROKER_DESKTOP_WRITE_TOKEN_FORBIDDEN` and refuses arbitrary extra permissions (`BROKER_REQUESTED_PERMISSION_FORBIDDEN`).
  - `SandboxHttpTokenBrokerClient.issueToken()` defaults to `{ contents: 'read', pull_requests: 'read', checks: 'read' }` and fails closed if a server attempts to return `contents: 'write'` (`DESKTOP_WRITE_TOKEN_FORBIDDEN`).
  - `GitHubF1Ledger.verifyInstallationRepository()` refuses tokens carrying `contents: 'write'` or `permissions.push === true` (`GITHUB_DESKTOP_WRITE_TOKEN_FORBIDDEN`) whenever `mediatedLedgerClient` or `forbidDesktopWriteToken` is active.
  - `DesktopControllerDaemon` propagates `mediatedCasEnabled` / `forbidDesktopWriteToken: true` and exposes `mediatedCasEnabled`, `desktopWriteTokenForbidden`, and `revocationAuthorityConfigured` in `GET /status` v3 and `controller:doctor`.
- **Full 4-Operation Server-Mediated CAS (`github-app-adapter.ts`, `broker-service.ts`, `broker-server.ts`, `github-f1-ledger.ts`):**
  - Desktop signs ECDSA P-256 `MEDIATED_LEDGER_OP` device PoP assertions to `POST /v1/broker/ledger-op` for ONLY 4 allowlisted operations:
    1. `COMMIT_PRE_SEND_FENCE` (`refs/bke/fences/<pr>/<attempt>`)
    2. `CONSUME_SEND_CLAIM` (`refs/bke/claims/<pr>/<attempt>`)
    3. `RECONCILE_CONVERSATION` (`refs/bke/conversations/<pr>` + `refs/bke/turns/<pr>/<attempt>` with fast-forward `expectedParentSha` CAS check)
    4. `MARK_DELIVERY_UNCERTAIN` (`refs/bke/uncertain/<pr>/<attempt>`)
  - Broker enforces active device status, exact `enrollment_generation`, `worker_id` single-owner PR lock, `expectedRepositoryId` check, exact `refs/bke/*` path binding (`BROKER_ARBITRARY_PROXY_FORBIDDEN`), and `422` CAS conflict preservation.
  - `mock-github-server.mjs` `GET /installation/repositories` enforces per-token permission reflection from `state.issuedTokens` so desktop `contents: read` vs broker-internal `contents: write` behaves identically to real GitHub App tokens.

### Verification Evidence
- `bke-worker/integrations/desktop-broker/tests/mediated-cas.test.mjs` (all 4 CAS ops end-to-end via `GitHubF1Ledger` without `contents: write`, arbitrary ref/method rejection, write-token rejection)
- `bke-worker/integrations/desktop-broker/tests/broker-service.test.mjs`, `chaos-adversarial.test.mjs`, `multiprocess-e2e.test.mjs`

---

## 4. F4-04 — Multi-Host Concurrency, Replacement & CAS Coherence

Verified in `bke-worker/integrations/desktop-broker/tests/multihost-safety.test.mjs`:
- 1:1 `worker_id` active device exclusivity rejects concurrent second host (`ENROLLMENT_DUPLICATE_WORKER_ACTIVE`).
- Concurrent claim race on same PR/head commits strictly 1 winner (`COMMITTED`) and 1 loser (`CONFLICT`).
- Device key rotation `1 -> 2` immediately locks out generation `1` (`DEVICE_ENROLLMENT_GENERATION_STALE`), while a verifier configured for generation `3` rejects generation `2` (`EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH`).
- Post-claim dropped HTTP response on `CONSUME_SEND_CLAIM` transitions Host A journal to `DELIVERY_UNCERTAIN` and persists `refs/bke/uncertain/<pr>/<attempt>` on GitHub; revoking Host A and enrolling Host B leaves Host B **still blocked** (`BROKER_DELIVERY_UNCERTAIN_QUARANTINED`) until human reconciliation.
- Stale `expectedParentSha` on Turn 2 conversation update fails closed (`BROKER_LEDGER_CONVERSATION_CAS_CONFLICT`), preventing conversation forking.

---

## 5. Default-OFF Security Locks & Cleanup Verification

- All production-sensitive toggles remain strictly `false` by default across source, `deploy/desktop-controller.env.example`, `scripts/package-desktop-worker.sh`, and `.github/workflows/hydrogen-sandbox-ci.yml`:
  - `FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const`
  - `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const`
  - `humanLiveSendAuthorized = false`
  - `BKE_EXECUTION_ENVELOPE_ENABLED=false`
  - `BKE_EXECUTION_V2_ASYMMETRIC_ENABLED=false`
  - `BKE_REQUIRE_ASYMMETRIC_V2=false`
  - `BKE_REMOTE_BROKER_ENABLED=false`
  - `BKE_ALLOW_REMOTE_SIGNED_HALT=false`
  - `BKE_SERVER_MEDIATED_CAS_ENABLED=false`
- Workspace media asset check (`public/assets/aistudio/`): `NO CLEANUP REQUIRED` (directory does not exist).

---

## 6. Remaining Production Prerequisites (Outside Sandbox Scope)

1. **Production Cloudflare Broker Deployment (`PR-14` against frozen `cloudflare-relay/`):** Deploy real `/v1/desktop/enroll/*`, `/v1/enrollment/status`, `/v1/broker/authorize`, `/v1/broker/tokens`, `/v1/broker/token-status`, and `/v1/broker/ledger-op` backed by Cloudflare Durable Objects / KMS-protected Ed25519 keys.
2. **Real GitHub App & Level 7 Chrome Owner Acceptance (`NOT_AUTHORIZED` / `NOT_RUN`):** Real ChatGPT DOM, signed-in Google/ChatGPT profile, Chrome `nativeMessaging`, and owner-supervised `BKE_OWNER_SUPERVISED_LIVE_SEND=I_OWNER_AUTHORIZE_LIVE_SEND` remain intentionally unexecuted in sandbox.
3. **External GitHub Sync & Exact-SHA CI Run:** Synchronize F4 changes from AI Studio to `jan2xo/bke-worker-h` and record the resulting commit SHA and green `Hydrogen Sandbox CI` run URL.
