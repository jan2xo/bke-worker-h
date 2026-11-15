# BKE WORKER — HYDROGEN F4.2 SIGNED AUTHORITY BINDING HARDENING HANDOFF

**From:** Gemini Hydrogen — Lead Implementing Engineer  
**To:** GPT-6 — Independent Engineering Reviewer & BKE Systems Architect  
**Project:** BKE Worker (`Phase F4.2 — Signed Authority Binding Hardening`)  
**Assigned Engineering Repository:** `https://github.com/jan2xo/bke-worker-h`  
**Verified F4.1 Starting Baseline SHA:** `dc77b308d808aff8b26c72d659ff3488cdad4da2`  
**Verified F4.1 GitHub Actions Run:** [`43762323895`](https://github.com/jan2xo/bke-worker-h/actions/runs/43762323895)  
**Post-F4.2 Synchronized Commit SHA (`final_sha`):** `NOT_YET_SYNCED` (`null` — *container has no `.git` remote/push access; pending external AI Studio -> `jan2xo/bke-worker-h` GitHub sync*)  
**Post-F4.2 GitHub CI Run (`github_ci_run`):** `NOT_YET_SYNCED` (`null` — *pending external sync to `jan2xo/bke-worker-h`*)  
**Canonical Target Repository (`jan2xo/bke-worker`):** **Untouched / Read-Only**  
**Command Center (`jan2xo/bke-command-center`):** **Untouched / Read-Only**  
**Frozen Paths (`cloudflare-relay/`, `android-gecko/`, `bke-worker/src/`, `BKE.Worker.sln`, `Directory.Build.props`, `bke-worker/.github/workflows/pr-guard.yml`):** **0 modifications**  
**Media Assets Cleanup (`public/assets/aistudio/`):** `NO CLEANUP REQUIRED` *(directory absent)*

> **Verification & Honesty Notice:** All clean-install builds, TypeScript checks, unit suites, cryptographically valid Ed25519 negative fault matrices, real `controller-daemon.js start` multi-process E2E acceptance suites, input-only lint checks, untouched Cloudflare relay checks, all Python/Node/Bash contract suites, and deterministic packaging/verify/clean-uninstall checks reported below were executed and observed passing **from clean `node_modules` installs after the final F4.2 code and documentation edits** (`2026-11-15`). External GitHub synchronization (`final_sha` / `github_ci_run`), real Cloudflare broker deployment (`PR-14`), real GitHub App PEM/PAT provisioning, and Level 7 real Chrome 2-turn acceptance remain **NOT_YET_SYNCED / NOT_AUTHORIZED / NOT_RUN**.

---

## 1. Executive F4.2 Remediation Verdict

Independent source review of the verified F4.1 baseline (`dc77b308d808aff8b26c72d659ff3488cdad4da2`) identified defect **F4.2-01**: `HttpTrustedBrokerClient.checkDeviceRevocation()` used an optional-when-present repository comparison that accepted a validly broker-signed `ACTIVE` status payload omitting `repository` (or containing `repository: undefined` / `null` / non-string). Phase F4.2 eliminates this defect, hardens every adjacent signed-response and broker boundary across both client and server implementations, proves rejection with genuine broker-signed Ed25519 negative matrices and live CLI subprocess runs, and preserves all F1–F4.1 security invariants:

| Requirement | Status | Summary of Implementation |
|---|---|---|
| **F4.2-01: Signed Repository Binding Defect Fixed** | **IMPLEMENTED & VERIFIED** | Both `HttpTrustedBrokerClient.checkDeviceRevocation()` (`runtime-broker-factory.ts`) and `SandboxHttpTokenBrokerClient.checkDeviceRevocation()` (`broker-client.ts`) now strictly require `repository` to be a non-empty valid `owner/repo` string matching `params.repository` (case-insensitive, rejecting omitted, `null`, non-string, `.`/`..`, and wrong-repo payloads fail-closed as `UNKNOWN` -> HTTP `503 EXEC_REQ_REVOCATION_UNAVAILABLE`). |
| **F4.2-02: Adjacent Signed-Response & Schema Hardening** | **IMPLEMENTED & VERIFIED** | Enforced exact strict payload schemas (allowed keys, primitive types, regexes, bounded `4096`-entry `seenStatusNonces` client replay tracking, bounded `120s` TTL / `+5s` future skew, `64`-byte Ed25519 signature check) across `verifyBrokerSignedPayload`, `postJsonWithTimeout`, `checkDeviceRevocation`, `checkTokenStatus`, `issueToken`, `executeLedgerOp`, `broker-service.ts`, `broker-server.ts`, `device-enrollment.ts`, `token-lifecycle.ts`, and `github-app-harness.ts`. |
| **F4.2-03: Cryptographically Valid Ed25519 Negative Matrix** | **IMPLEMENTED & VERIFIED** | Added 24-case genuinely Ed25519-signed device-status negative tests + 10-case signed token-status negative tests + `issueToken`/`executeLedgerOp` negative tests + daemon `503` verification in `runtime-wiring.test.mjs`, and upgraded `mediated-cas.test.mjs` proxy tampering to re-sign payloads with the broker's genuine active Ed25519 `EXECUTION` key. |
| **F4.2-04: Integrated `controller-daemon.js start` Subprocess Proof** | **IMPLEMENTED & VERIFIED** | Added 5-process OS E2E test in `cli-operational-e2e.test.mjs` where a loopback proxy intercepts `/v1/enrollment/status`, strips `repository` from an `ACTIVE` response, and re-signs with the real broker `EXECUTION` key: `controller-daemon.js start` fails closed `503 EXEC_REQ_REVOCATION_UNAVAILABLE` with `submitInvocations: 0`, `journalPhase: 'IDLE'`, zero browser submissions, zero GitHub refs/commits/git POSTs, and zero secret leaks; then switching proxy to `PASS_THROUGH` completes Turn 1 (`CONFIRMED_TURN_1`) -> Turn 2 (`CONFIRMED_CONTINUATION`). |
| **F4.2-05: F4 P0-01/02/03 & 4-Op CAS Preserved** | **IMPLEMENTED & VERIFIED** | Strict V2-only isolation, tri-state revocation (`ACTIVE`/`REVOKED`/`UNKNOWN`), exact `enrollment_generation`, zero desktop `contents: write` tokens, all 4 CAS ops (`COMMIT_PRE_SEND_FENCE`, `CONSUME_SEND_CLAIM`, `RECONCILE_CONVERSATION`, `MARK_DELIVERY_UNCERTAIN`), and all default-OFF locks remain intact. |
| **F4.2-06: Clean-Install Regression Certification** | **PASS (LOCAL)** | Re-ran clean installs and all extension, native, claim, desktop-broker, lint, frozen Cloudflare relay, Python/Node/Bash contract, packaging/verify/clean-uninstall checks after final edits. |
| **F4.2-07: Engineering Handoff & Artifacts** | **COMPLETE** | Written identically to workspace root, `bke-worker/docs/`, and `UserFacing: true` AI Studio artifact; `canonical-promotion-plan.md` updated with measured line counts. |

---

## 2. Root Cause & Fix for F4.2-01 (Signed Repository Binding)

### 2.1 Vulnerable F4.1 Pattern
In F4.1 (`runtime-broker-factory.ts`), `HttpTrustedBrokerClient.checkDeviceRevocation()` allowed a signed status response to pass validation whenever `p.repository` was absent or non-string, checking equality only conditionally when `typeof p.repository === 'string'`:
- A broker-signed `ACTIVE` status payload omitting `repository` (or setting `repository: null`) bypassed repository binding completely.
- `SandboxHttpTokenBrokerClient.checkDeviceRevocation()` (`broker-client.ts`) mirrored the same pattern.

### 2.2 F4.2 Remediation
Both clients now validate signed `DeviceStatusPayload` responses against an explicit closed schema:
1. **Closed Key Set:** Exactly 13 required keys (`broker_issuer`, `device_id`, `installation_id`, `worker_id`, `repository`, `expected_enrollment_generation`, `actual_enrollment_generation`, `status`, `revoked`, `nonce`, `issued_at`, `expires_at`, plus optional `code` which **must** be absent or `null` when `status === 'ACTIVE'`). Any extra/unknown key fails closed (`UNKNOWN`).
2. **Strict `repository` Validation:** `isValidRepoName(p.repository)` enforces `^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$` (rejecting `.` and `..` segments) and requires exact case-insensitive match with `params.repository`.
3. **Strict Identity & State Consistency:** Requires exact equality on `worker_id`, `device_id`, `installation_id`, safe integer `expected_enrollment_generation` & `actual_enrollment_generation` (exact equality on `ACTIVE`), strict boolean `revoked` (`revoked === false` iff `status === 'ACTIVE'`; `revoked === true` iff `status === 'REVOKED'`), and rejects `'UNKNOWN'` or arbitrary strings.
4. **Nonce Replay Protection:** Client tracks verified nonces in a bounded `seenStatusNonces` set (`4096` cap) and verifies echoed nonce equality.

---

## 3. Adjacent Signed-Response & Broker Hardening (F4.2-02)

### 3.1 `bke-worker/browser-extension/native-host/claim/runtime-broker-factory.ts` (1,165 lines)
- **`verifyBrokerSignedPayload()`**: Rejects non-plain-object payloads (`isPlainObject`), enforces `key_id` length `1..128`, requires exact 64-byte Ed25519 `signature_b64url` (`/^[A-Za-z0-9_-]{86}$/` + `sig.length === 64`), enforces strict ISO-8601 regex on `issued_at`/`expires_at`, caps max signature TTL to `120_000ms`, and rejects `issued_at` more than `+5_000ms` in the future.
- **`postJsonWithTimeout()`**: Enforces `isPlainObject(parsed)` so HTTP 200 JSON arrays or primitives (`[]`, `null`, `"ok"`, `123`) fail closed rather than entering response parsers.
- **`checkTokenStatus()`**: Enforces exact closed schema (8 keys max, `code` absent/`null` when `ACTIVE`), validates `token_sha256` (`/^[0-9a-f]{64}$/`), validates `STATUS_NONCE_RE`, tracks `seenStatusNonces`, enforces `revoked === false` iff `status === 'ACTIVE'` and `revoked === true` iff `status === 'REVOKED'`, failing closed on contradictions or `'UNKNOWN'`.
- **`issueToken()`**: Pre-validates `workerId`, `installationId`, `repository`, and optional `repositoryId` (`HttpTrustedBrokerConfig.repositoryId` wired from `createDesktopControllerRuntimeDependencies`), rejects `contents: 'write'` and unknown/write permissions pre-request, and strictly validates returned `IssuedScopedToken` (`token` string, `tokenType === 'github_installation_token'`, exact `installationId`, `[repository]`, numeric `repositoryId` matching config when present, valid `issuedAtMs`/`expiresAtMs`, read-only permissions).
- **`executeLedgerOp()`**: Pre-validates operation allowlist and scope (`workerId`, `installationId`, `repository`, `repositoryId`) returning `CONFLICT` `BROKER_DEVICE_SCOPE_MISMATCH` on scope mismatch; requires valid 40-hex `sha` on `COMMITTED` / `ALREADY_EXISTS` responses, else fails closed `UNCERTAIN` `BROKER_LEDGER_RESPONSE_INVALID`.

### 3.2 `bke-worker/integrations/desktop-broker/src/broker-client.ts` (742 lines)
- Mirrored full F4.2 parity into `SandboxHttpTokenBrokerClient` across `verifyBrokerSignedPayload`, `postJsonWithTimeout`, `checkDeviceRevocation`, `checkTokenStatus`, `issueToken` (switched to `postJsonWithTimeout` for timeout protection + strict `IssuedScopedToken` validation), and `executeLedgerOp` (scope + 40-hex `sha` validation).

### 3.3 `bke-worker/integrations/desktop-broker/src/broker-service.ts` (861 lines)
- Added durable `usedStatusNonces?: string[]` to `BrokerDurableState` (backward-compatible initialization to `[]` in `readOrInitState`), rejecting replayed status nonces with `BROKER_NONCE_REPLAYED` in both `getSignedDeviceStatus()` and `getSignedTokenStatus()`.
- Added pre-signing assertions in `getSignedDeviceStatus()` forbidding signing `status: 'ACTIVE'` unless `status.device` exists and all identity, repository, and generation fields are valid (`BROKER_STATUS_PAYLOAD_INVALID`).
- Validated `isValidRepoName(params.repository)` and positive safe integer `repository_id` in `mintScopedToken()`.
- Hardened `executeServerMediatedLedgerOp()` to check `isValidRepoName(params.ledger_op.repository)` before `verifyDeviceAssertion` and check `params.ledger_op.worker_id !== undefined` rather than truthiness.

### 3.4 `bke-worker/integrations/desktop-broker/src/broker-server.ts` (341 lines)
- Removed unsigned fallbacks on `POST /v1/enrollment/status` and `POST /v1/broker/token-status`: valid string `nonce` is always mandatory, throwing `400 BROKER_STATUS_NONCE_INVALID` when absent/invalid.
- Removed `String(...)` coercion of non-string inputs on `/v1/enrollment/status`, rejecting non-primitive/wrong-type fields with `BROKER_STATUS_PARAMS_INVALID`.

### 3.5 `bke-worker/integrations/desktop-broker/src/device-enrollment.ts` (748 lines)
- Hardened `verifyDeviceAssertion()` with exact 9-key closed schema, `!Array.isArray`, `REPO_RE`, and `nonce.length >= 8`.
- Hardened `inspectDeviceStatus()` to fail closed when optional parameters (`installationId !== undefined`, `repository !== undefined`, `enrollmentGeneration !== undefined`) are malformed or mismatched.

### 3.6 `bke-worker/browser-extension/native-host/claim/token-lifecycle.ts` (550 lines) & `github-app-harness.ts` (821 lines)
- **`token-lifecycle.ts`**: Tightened `validateIssuedToken()` so `REMOTE_OWNER_CERTIFIED_BROKER` fails closed when `this.config.repositoryId !== undefined` and `issued.repositoryId === undefined`, and tightened future `issuedAtMs` skew tolerance to `+5_000ms`.
- **`github-app-harness.ts`**: Hardened `ExecutionRequestVerifier.verifyAndAuthorize()` so V2 mode (`isV2 === true`) strictly requires `rev.status === 'ACTIVE'` (rejecting responses that omit `status`).

---

## 4. Cryptographically Valid Negative Matrix & Live CLI Subprocess Proofs (`F4.2-03` & `F4.2-04`)

### 4.1 `runtime-wiring.test.mjs` (1,052 lines — `F4.2-03`)
All payloads in the F4.2-03 suite are signed with a legitimate broker Ed25519 private key in `brokerPublicKeysById` (testing semantic/identity/schema enforcement, not just broken signatures):
- **24-case signed device-status matrix (`01_omit_repository` .. `24_non_null_code_on_active`):** verifies `checkDeviceRevocation` fails closed (`status: 'UNKNOWN'`, `revoked: true`) for omitted/null/non-string/traversal/wrong repository, mismatched `worker_id`/`device_id`/`installation_id`/`broker_issuer`/`nonce`, replayed nonce, `<` and `>` `actual_enrollment_generation`, `UNKNOWN`/arbitrary status, `ACTIVE`+`revoked: true`, `REVOKED`+`revoked: false`, extra unknown claim, expired window, TTL `> 120s`, future `issued_at > +5s`, invalid `key_id`, malformed signature, and non-null `code` on `ACTIVE`.
- **10-case signed token-status matrix:** verifies `checkTokenStatus` and `isRevoked` reject omitted/wrong `token_sha256`, wrong nonce, replayed nonce, wrong issuer, extra field, `UNKNOWN` status, contradictory `ACTIVE`+`revoked: true`, future `issued_at`, and JSON array HTTP 200 body.
- **`issueToken` & `executeLedgerOp` matrix:** verifies rejection of scope mismatches, `contents: 'write'` requests/responses, missing `repositoryId`, and `sha: null` on `COMMITTED`.
- **Full `DesktopControllerDaemon` test:** verifies a genuinely signed `ACTIVE` response omitting `repository` yields HTTP `503 EXEC_REQ_REVOCATION_UNAVAILABLE`, `submitInvocations: 0`, `journalPhase: 'IDLE'`, and zero leaked secrets.

### 4.2 `mediated-cas.test.mjs` (781 lines)
- Upgraded the `F4 P0-02` proxy fault matrix so all tampered status modes (`WRONG_NONCE`, `EXPIRED`, `WRONG_ISSUER`, `WRONG_DEVICE`, `WRONG_GEN`, `SIGNED_OMIT_REPO`, `SIGNED_WRONG_REPO`, `SIGNED_OMIT_TOKEN_HASH`, `SIGNED_WRONG_TOKEN_HASH`, `SIGNED_STATUS_UNKNOWN`, `SIGNED_CONTRADICTORY_ACTIVE`, `SIGNED_EXTRA_FIELD`, `SIGNED_FUTURE_ISSUED`) are **cryptographically re-signed with the broker's genuine active Ed25519 `EXECUTION` key** read from `broker.json`.
- Added explicit broker-side `BROKER_NONCE_REPLAYED` and missing-nonce `400 BROKER_STATUS_NONCE_INVALID` HTTP assertions.

### 4.3 `cli-operational-e2e.test.mjs` (1,121 lines — `F4.2-04`)
- Spawns real OS subprocesses: `SandboxBrokerHttpServer` + loopback re-signing proxy + compiled `controller-daemon.js start --owner-supervised-live-send` + `entry.mjs` native bridge + `MockGitHubServer`.
- **Negative integrated proof:** Proxy strips `repository` from genuine broker `ACTIVE` status and re-signs with the real broker `EXECUTION` key -> daemon returns HTTP `503 EXEC_REQ_REVOCATION_UNAVAILABLE`, `submitInvocations: 0`, `journalPhase: 'IDLE'`, `browserState.submissions.length === 0`, `mockGh.state.refs.size === 0`, `mockGh.state.commits.size === 1` (seeded base commit only, `commitSeq === 1`, zero `POST /git/` requests), and zero secret leaks.
- **Positive integrated recovery:** Switching the same running proxy to `PASS_THROUGH` immediately succeeds on Turn 1 (`200 CONFIRMED_TURN_1`) and Turn 2 (`200 CONFIRMED_CONTINUATION`, `browserState.submissions.length === 2`) via the same live CLI subprocess.

---

## 5. F4.2 File Inventory (`wc -l` Measured on Disk)

| File Path | Role in F4.2 | Measured Lines |
|---|---|---:|
| `bke-worker/browser-extension/native-host/claim/runtime-broker-factory.ts` | F4.2-01 & F4.2-02 client signed-status, token, ledger, nonce-replay, and `repositoryId` hardening | 1,165 |
| `bke-worker/browser-extension/native-host/claim/token-lifecycle.ts` | Required `repositoryId` on `REMOTE_OWNER_CERTIFIED_BROKER` + `+5s` skew bound | 550 |
| `bke-worker/browser-extension/native-host/claim/github-app-harness.ts` | Strict `rev.status === 'ACTIVE'` requirement in V2 verifier | 821 |
| `bke-worker/browser-extension/native-host/claim/controller-daemon.ts` | Unchanged in F4.2; F4.1 CLI operational wiring preserved | 1,459 |
| `bke-worker/integrations/desktop-broker/src/broker-client.ts` | Full F4.2 signed-status/token/mint/ledger identity & schema parity in `SandboxHttpTokenBrokerClient` | 742 |
| `bke-worker/integrations/desktop-broker/src/broker-service.ts` | `usedStatusNonces` replay persistence, pre-sign `ACTIVE` assertions, `mintScopedToken` & `executeServerMediatedLedgerOp` checks | 861 |
| `bke-worker/integrations/desktop-broker/src/broker-server.ts` | Removed unsigned status fallbacks & non-primitive `String()` coercion | 341 |
| `bke-worker/integrations/desktop-broker/src/device-enrollment.ts` | Closed 9-key `verifyDeviceAssertion` & fail-closed `inspectDeviceStatus` param checks | 748 |
| `bke-worker/browser-extension/native-host/claim/tests/runtime-wiring.test.mjs` | Fixed mock token shape + added `F4.2-03` 24-case device + 10-case token + daemon `503` suite | 1,052 |
| `bke-worker/integrations/desktop-broker/tests/cli-operational-e2e.test.mjs` | Added `F4.2-04` 5-process OS E2E with genuine broker-key re-signing proxy (`503` -> Turn 1/2) | 1,121 |
| `bke-worker/integrations/desktop-broker/tests/mediated-cas.test.mjs` | Upgraded fault matrix to re-sign tampered payloads with broker active `EXECUTION` key + nonce replay/400 checks | 781 |
| `bke-worker/docs/canonical-promotion-plan.md` | Updated measured F4.2 line counts & `broker-client.ts` split guidance | 96 |
| `HYDROGEN_BKE_WORKER_F4_2_SECURITY_HANDOFF.md` | This F4.2 handoff (workspace root, `bke-worker/docs/`, and `UserFacing: true` artifact) | — |

---

## 6. Clean-Install Post-Final-Edit Verification Matrix (`F4.2-06`)

All commands below were executed **after all final F4.2 code and documentation edits** (`2026-11-15`) with `node_modules` deleted and reinstalled cleanly:

| Command / Suite | Observed Outcome | Observed Scope & Exact Counts |
|---|---|---|
| `rm -rf bke-worker/browser-extension/node_modules && env -C bke-worker/browser-extension npm install --ignore-scripts --no-audit --no-fund --package-lock=false && npm run check` | **PASS** (`exit 0`) | Clean `tsc` (`typescript@5.8.3`), MV3 `validate`, **`202/202`** extension tests (`tests/*.test.mjs`) + **`39/39`** native-host tests (`native-host/tests/*.test.mjs`) + **`64/64`** host-claim tests (`native-host/claim/tests/*.test.mjs`, including `F4.2-03`) |
| `env -C bke-worker/browser-extension npm run controller:doctor` | **PASS** (`exit 0`) | `ok: true`, `live_send_default_safe: LOCKED_FALSE`, `execution_envelope_mode: DISABLED_BY_DEFAULT`, `broker_protocol_mode: DISABLED_BY_DEFAULT`, `mediated_cas_mode: DISABLED_BY_DEFAULT` |
| `env -C bke-worker/browser-extension npm run smoke:native -- --report /tmp/desktop-native-smoke-report.json` | **PASS** (`exit 0`) | `BKE_DESKTOP_NATIVE_SMOKE=PASS`, `BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN` (temp report removed) |
| `rm -rf bke-worker/integrations/desktop-broker/node_modules && env -C bke-worker/integrations/desktop-broker npm ci --ignore-scripts --no-audit --no-fund && npm run check` | **PASS** (`exit 0`) | Clean `npm ci` + `tsc -p tsconfig.json` + **`9/9`** integration test cases PASS (`broker-service`, `chaos-adversarial`, `cli-operational-e2e` [2/2 incl. `F4.2-04`], `device-enrollment`, `mediated-cas` [2/2], `multihost-safety`, `multiprocess-e2e`) |
| `env -C bke-worker node scripts/input-only-lint.mjs && node --test scripts/input-only-lint.test.mjs` | **PASS** (`exit 0`) | Zero prohibited assistant-reply patterns + **`4/4`** lint unit tests PASS |
| `env -C bke-worker/cloudflare-relay npm run check && npm run reconnect-recovery-test` | **PASS** (`exit 0`) | Untouched frozen Cloudflare relay (**`191/191`** PASS) & reconnect recovery planner PASS |
| `env -C bke-worker` Python, Node & Bash contract suites | **PASS** (`exit 0`) | All **`18/18`** Python contract files (`tests/*.py`, incl. `27+10+12+12+37` unittest assertions), **`10/10`** `admin_preproduction_activation.test.mjs`, and `bash tests/chrome_native_host_installer_contract.sh` PASS |
| `env -C bke-worker bash scripts/package-desktop-worker.sh package/verify/clean-uninstall --out /tmp/f42-pkg` | **PASS** (`exit 0`) | Deterministic bundle SHA-256 verification + default-OFF env checks + clean uninstall PASS (`/tmp/f42-pkg` removed) |
| `env -C bke-worker/deploy` default-OFF env check | **PASS** (`exit 0`) | `BKE_EXECUTION_ENVELOPE_ENABLED=false`, `BKE_ALLOW_REMOTE_SIGNED_HALT=false`, `BKE_EXECUTION_V2_ASYMMETRIC_ENABLED=false`, `BKE_REQUIRE_ASYMMETRIC_V2=false`, `BKE_REMOTE_BROKER_ENABLED=false`, `BKE_SERVER_MEDIATED_CAS_ENABLED=false` |
| `env -C bke-worker bash scripts/certify-forge-f1-desktop-mvp.sh --sandbox --dry-run` | `BKE_F1_MVP_CERTIFICATION=BLOCKED reason=NOT_IN_GIT_REPOSITORY` | Expected fail-closed behavior in gitless `/app/applet` container; verified on real Git checkout in CI after sync |
| Root AI Studio Applet (`compile_applet` + `lint_applet`) | **PASS** (`exit 0`) | Verified co-executed build & lint after final edits |

---

## 7. Independent GPT-6 F4.2 Security Audit Checklist & Remaining Owner Scope

- [ ] Sync F4.2 workspace to `jan2xo/bke-worker-h` and record exact `final_sha` and green `Hydrogen Sandbox CI` run URL.
- [ ] Diff `bke-worker/cloudflare-relay/`, `bke-worker/android-gecko/`, `bke-worker/src/`, `bke-worker/BKE.Worker.sln`, `bke-worker/Directory.Build.props`, and `bke-worker/.github/workflows/pr-guard.yml` against `dc77b308d808aff8b26c72d659ff3488cdad4da2` to confirm `0` modified lines.
- [ ] Audit `HttpTrustedBrokerClient.checkDeviceRevocation()` (`runtime-broker-factory.ts`) and `SandboxHttpTokenBrokerClient.checkDeviceRevocation()` (`broker-client.ts`) to confirm `repository` is unconditionally mandatory and matched case-insensitively with `isValidRepoName`.
- [ ] Audit `checkTokenStatus()`, `issueToken()`, `executeLedgerOp()`, `verifyBrokerSignedPayload()`, `broker-service.ts` (`usedStatusNonces`), `broker-server.ts`, `device-enrollment.ts`, `token-lifecycle.ts`, and `github-app-harness.ts`.
- [ ] Keep production `cloudflare-relay/` broker deployment (`PR-14`), real GitHub App PEM/PAT provisioning, and Level 7 real Chrome 2-turn acceptance gated on explicit owner authorization.

---

## 8. Machine-Readable Completion Capsule

```json
{
  "schema": "bke.hydrogen.f4_2.handoff.v1",
  "repository": "jan2xo/bke-worker-h",
  "base_f4_1_sha": "dc77b308d808aff8b26c72d659ff3488cdad4da2",
  "base_f4_1_ci_run": "43762323895",
  "final_sha": null,
  "github_ci_run": null,
  "sync_status": "NOT_YET_SYNCED",
  "f4_2_01_signed_repo_binding_fixed": "INTEGRATION_VERIFIED",
  "f4_2_02_adjacent_signed_schema_hardening": "INTEGRATION_VERIFIED",
  "f4_2_03_valid_ed25519_negative_matrix": "INTEGRATION_VERIFIED",
  "f4_2_04_integrated_cli_subprocess_e2e": "INTEGRATION_VERIFIED",
  "f4_2_05_p0_and_4op_cas_preserved": "INTEGRATION_VERIFIED",
  "browser_extension_tests": { "extension": 202, "native": 39, "host_claim": 64, "status": "PASS" },
  "desktop_broker_suites": { "total": 9, "passed": 9, "status": "PASS" },
  "frozen_cloudflare_relay_tests": { "total": 191, "passed": 191, "status": "PASS" },
  "input_only_lint_tests": { "total": 4, "passed": 4, "status": "PASS" },
  "python_contract_files": { "total": 18, "passed": 18, "status": "PASS" },
  "admin_preproduction_activation_tests": { "total": 10, "passed": 10, "status": "PASS" },
  "live_send_defaults_locked_false": true,
  "mediated_cas_default_false": true,
  "canonical_repository_modified": false,
  "command_center_modified": false,
  "frozen_production_modified": false,
  "public_assets_cleanup": "NO CLEANUP REQUIRED",
  "real_github_app_connection": "NOT_AUTHORIZED",
  "real_chrome_two_turn": "NOT_RUN",
  "remaining_blockers": [
    "EXTERNAL_GITHUB_SYNC_AND_EXACT_SHA_CI_PENDING",
    "REAL_CLOUDFLARE_DESKTOP_TOKEN_BROKER_NOT_AUTHORIZED",
    "REAL_GITHUB_APP_PEM_AND_LIVE_DELIVERY_NOT_AUTHORIZED",
    "LEVEL_7_REAL_CHROME_OWNER_ACCEPTANCE_NOT_RUN",
    "CONTAINER_MISSING_DOTNET_AND_DOT_GIT_FOR_LOCAL_CERTIFY_SH"
  ],
  "smallest_safe_next_step": "Synchronize completed F4.2 workspace from AI Studio to jan2xo/bke-worker-h, record exact final_sha and verify green Hydrogen Sandbox CI, complete independent GPT-6 F4.2 audit, and keep live sends / mediated CAS / PR-14 cloudflare-relay deployment gated on explicit owner authorization."
}
```
