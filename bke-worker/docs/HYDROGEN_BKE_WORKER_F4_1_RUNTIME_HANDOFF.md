# BKE WORKER — HYDROGEN F4.1 OPERATIONAL RUNTIME WIRING HANDOFF

**From:** Gemini Hydrogen — Lead Implementing Engineer  
**To:** GPT-6 — Independent Engineering Reviewer & BKE Systems Architect  
**Project:** BKE Worker (`Phase F4.1 — Operational CLI Runtime Wiring`)  
**Assigned Engineering Repository:** `https://github.com/jan2xo/bke-worker-h`  
**Verified F4 Starting Baseline SHA:** `56bcdf18c671c74b1583aae47a60957be283f30b`  
**Verified F4 GitHub Actions Run:** [`43679355493`](https://github.com/jan2xo/bke-worker-h/actions/runs/43679355493)  
**Post-F4.1 Synchronized Commit SHA (`final_sha`):** `NOT_YET_SYNCED` (`null` — *container has no `.git` remote/push access; pending external AI Studio -> `jan2xo/bke-worker-h` GitHub sync*)  
**Post-F4.1 GitHub CI Run (`github_ci_run`):** `NOT_YET_SYNCED` (`null` — *pending external sync to `jan2xo/bke-worker-h`*)  
**Canonical Target Repository (`jan2xo/bke-worker`):** **Untouched / Read-Only**  
**Command Center (`jan2xo/bke-command-center`):** **Untouched / Read-Only**  
**Frozen Paths (`cloudflare-relay/`, `android-gecko/`, `bke-worker/src/`, `BKE.Worker.sln`, `Directory.Build.props`, `bke-worker/.github/workflows/pr-guard.yml`):** **0 modifications**

> **Verification & Honesty Notice:** All clean-install builds, TypeScript checks, unit suites, fail-closed CLI startup subprocess tests, real `controller:cli start` 3-process operational E2E acceptance suites, input-only lint checks, untouched Cloudflare relay checks, Python/Node/Bash contract suites, and deterministic packaging/verify/clean-uninstall checks reported below were executed and observed passing **from clean `node_modules` installs after all final F4.1 code and documentation edits** (`2026-11-15`). External GitHub synchronization (`final_sha` / `github_ci_run`), real Cloudflare broker deployment (`PR-14`), real GitHub App PEM/PAT provisioning, and live ChatGPT sends remain **NOT_YET_SYNCED / NOT_AUTHORIZED / NOT_RUN**.

---

## 1. Executive F4.1 Remediation Verdict

In the F4 baseline (`56bcdf18c671c74b1583aae47a60957be283f30b`), `controller-daemon.ts` (`runCli('start')`) constructed `DesktopControllerDaemon` with a static `BKE_GITHUB_INSTALLATION_TOKEN` provider without supplying the authenticated V2 `deviceRevocationChecker`, `ServerMediatedLedgerClient`, or `ManagedTokenProvider` + trusted broker transport. Phase F4.1 resolves this gap end-to-end:

| Requirement | Status | Summary of Implementation |
|---|---|---|
| **1. Runtime Dependency Factory** | **IMPLEMENTED & VERIFIED** | Created `bke-worker/browser-extension/native-host/claim/runtime-broker-factory.ts` exporting `createDesktopControllerRuntimeDependencies(baseConfig, env)` and `HttpTrustedBrokerClient`. Wired directly into `runCli('start')` in `controller-daemon.ts`. |
| **2. Authenticated V2 Revocation Protocol** | **IMPLEMENTED & VERIFIED** | `HttpTrustedBrokerClient.checkDeviceRevocation()` calls `POST /v1/enrollment/status` with `redirect: 'manual'`, nonce challenge, and verifies Ed25519 SPKI signatures (`BKE_DEVICE_STATUS_V1\n`) + issuer + freshness + worker/device/installation/repository/exact `enrollment_generation`. Only `'ACTIVE'` permits dispatch. |
| **3. Production HTTP Transport in `ManagedTokenProvider`** | **IMPLEMENTED & VERIFIED** | `HttpTrustedBrokerClient` implements `TokenBrokerClient` using ECDSA P-256 `ieee-p1363` PoP (`BKE_DESKTOP_DEVICE_POP_V1\n`), strict `{ contents: 'read', pull_requests: 'read', checks: 'read' }` clamping, and Ed25519-signed token revocation verification (`BKE_TOKEN_STATUS_V1\n`). `ManagedTokenProvider` sets `brokerKind: 'REMOTE_OWNER_CERTIFIED_BROKER'` when connected and keeps `'REMOTE_DISABLED'` by default. |
| **4. Server-Mediated GitHub CAS Wiring** | **IMPLEMENTED & VERIFIED** | When `BKE_SERVER_MEDIATED_CAS_ENABLED=true`, `createDesktopControllerRuntimeDependencies` wires `brokerClient` as `deps.mediatedLedgerClient`, connecting `GitHubF1Ledger` (`COMMIT_PRE_SEND_FENCE`, `CONSUME_SEND_CLAIM`, `RECONCILE_CONVERSATION`, `MARK_DELIVERY_UNCERTAIN`) across `POST /v1/broker/ledger-ops`. |
| **5. Owner Private Device Credentials & Policy Validation** | **IMPLEMENTED & VERIFIED** | `loadOwnerDeviceCredentialsFile()` loads `BKE_DEVICE_CREDENTIALS_PATH` via `O_RDONLY \| O_NOFOLLOW`, rejecting symlinks, non-regular files, group/world-accessible modes (`(st.mode & 0o077) !== 0`), UID mismatches, unsafe parent directories, non-P-256 keys, mismatched keypairs (`pubDer` vs `createPublicKey(priv)`), thumbprint mismatches, invalid Ed25519 SPKI keys, and non-loopback `http://` URLs. `validateOwnerPolicyAgainstDevice()` cross-checks `BKE_NATIVE_POLICY_PATH` (`worker_id`, `browser_profile_identity`, `native_bridge_identity`, and `extension_public_key_sha256` when present). |
| **6. Pre-Ingress Fail-Closed Rejection** | **IMPLEMENTED & VERIFIED** | Missing, unsafe, or contradictory configs throw **before** `DesktopControllerDaemon` construction or `server.listen()`, exiting `controller:cli start` with code `1` and an explicit error code (`DAEMON_REVOCATION_CHECKER_MISSING`, `DAEMON_MEDIATED_CAS_CLIENT_MISSING`, `DAEMON_DEVICE_CREDENTIALS_MISSING`, `DAEMON_DEVICE_CREDENTIALS_UNSAFE_MODE`, etc.). |
| **7. Distinct Error States Preserved** | **IMPLEMENTED & VERIFIED** | Preserved distinct HTTP + error codes end-to-end: **Broker unavailable** (`503` `EXEC_REQ_REVOCATION_UNAVAILABLE` / `TOKEN_BROKER_UNAVAILABLE`), **Device revoked** (`403` `EXEC_REQ_DEVICE_REVOKED` / `TOKEN_DEVICE_REVOKED`), **Credential invalid** (`401` `EXEC_REQ_SIGNATURE_INVALID` / `TOKEN_CREDENTIAL_INVALID`), and **Delivery uncertain** (`409` with `journalPhase: 'DELIVERY_UNCERTAIN'`). |
| **8. No Silent Fixture/Static/V1 Fallback** | **IMPLEMENTED & VERIFIED** | `runtime-broker-factory.ts` imports zero test fixtures and rejects static `BKE_GITHUB_INSTALLATION_TOKEN`, legacy V1 execution (`DAEMON_LEGACY_V1_EXECUTION_FORBIDDEN`), compat downgrade (`DAEMON_V2_COMPAT_MODE_FORBIDDEN`), and mixed V1+V2 (`DAEMON_MIXED_V1_V2_CONFIG_FORBIDDEN`). |
| **9. Default-OFF Locks Preserved** | **IMPLEMENTED & VERIFIED** | All `desktop-controller.env.example` operational flags remain `=false` (`BKE_DEVICE_CREDENTIALS_PATH=` empty); `FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const`, `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const`, and `humanLiveSendAuthorized = false` remain unchanged. Default CLI startup leaves V2, broker, mediated CAS, and live send disabled (`403 EXECUTION_ENVELOPE_DISABLED`). |

---

## 2. Causal Defects Discovered & Repaired During Implementation

1. **Extension Key Thumbprint vs. Broker Device SPKI Hash (`runtime-broker-factory.ts`):**  
   `owner-policy.json` (`BKE_NATIVE_POLICY_PATH`) is consumed by `native-host/entry.mjs --controller-bridge` and stores `public_key_sha256` computed from the WebExtension's non-exportable IndexedDB P-256 JWK, whereas `device-credentials.json` (`BKE_DEVICE_CREDENTIALS_PATH`) stores the broker-enrolled desktop PoP EC P-256 SPKI PEM pair (`sha256(spki_der)`). Comparing those two hashes directly collided on valid multi-process setups. Updated `validateOwnerPolicyAgainstDevice` to bind `owner-policy.json` and `device-credentials.json` via `worker_id`, optional `browser_profile_identity` (`policy.profile_binding_sha256`), `native_bridge_identity` (`policy.resources.bridge_identity_sha256`), and `extension_public_key_sha256` (`policy.public_key_sha256`), while always verifying `credentials.public_key_sha256` against the SPKI DER of `device_public_key_pem`/`device_private_key_pem`.
2. **Token Error Status Mapping Inside `verifyAndAuthorize` (`controller-daemon.ts`):**  
   `ExecutionRequestVerifier.verifyAndAuthorize()` invokes `RestGitHubAuthorityProvider.verifyInstallationScope()`, which invokes `tokenLifecycle.asTokenProvider()` prior to the outer `getToken()` guard. Failures thrown by `HttpTrustedBrokerClient.issueToken()` (`TOKEN_CREDENTIAL_INVALID`, `TOKEN_BROKER_UNAVAILABLE`, `TOKEN_DEVICE_REVOKED`) propagated through `mapVerifierRejectionHttpStatus()` and collapsed to HTTP `409`. Delegating `TOKEN_*` and `GITHUB_AUTH_UNAVAILABLE` codes to `mapTokenErrorHttpStatus()` restores true HTTP `401`, `503`, and `403` error discrimination.

---

## 3. F4.1 File Inventory (`wc -l` Measured on Disk)

| File Path | Role in F4.1 | Measured Lines |
|---|---|---:|
| `bke-worker/browser-extension/native-host/claim/runtime-broker-factory.ts` | **New:** Owner `0o600` device credentials & policy validator, `HttpTrustedBrokerClient`, and `createDesktopControllerRuntimeDependencies` | 902 |
| `bke-worker/browser-extension/native-host/claim/controller-daemon.ts` | Wired `createDesktopControllerRuntimeDependencies` into `runCli('start')`, enhanced `doctor`, and fixed `mapVerifierRejectionHttpStatus` delegation | 1,459 |
| `bke-worker/browser-extension/native-host/claim/token-lifecycle.ts` | Extended `brokerKind` union with `'REMOTE_OWNER_CERTIFIED_BROKER'` while preserving `'REMOTE_DISABLED'` default | 550 |
| `bke-worker/browser-extension/native-host/claim/tsconfig.json` | Included `runtime-broker-factory.ts` in compilation | 14 |
| `bke-worker/deploy/desktop-controller.env.example` | Added empty default `BKE_DEVICE_CREDENTIALS_PATH=` (all boolean flags remain `=false`) | 71 |
| `bke-worker/browser-extension/native-host/claim/tests/runtime-wiring.test.mjs` | **New:** Real `controller:cli start` fail-closed/default-OFF subprocess suite, `doctor` validation, and distinct `503`/`403`/`401`/`409` verification | 702 |
| `bke-worker/integrations/desktop-broker/tests/cli-operational-e2e.test.mjs` | **New:** 3-process E2E using actual compiled `controller:cli start` OS subprocess (Turn 1/2, all 4 mediated CAS ops, zero desktop write tokens, broker outage `503`, restart recovery, `DELIVERY_UNCERTAIN` `409`, and device revocation `403`) | 691 |
| `bke-worker/docs/canonical-promotion-plan.md` | Updated measured file sizes and canonical sub-500-line split guidance for F4.1 files | 95 |
| `bke-worker/docs/desktop-operator-acceptance.md` | Documented `BKE_DEVICE_CREDENTIALS_PATH` and F4.1 fail-closed CLI requirements | 130 |
| `HYDROGEN_BKE_WORKER_F4_1_RUNTIME_HANDOFF.md` | This F4.1 engineering handoff (workspace root, `bke-worker/docs/`, and artifact) | — |

---

## 4. Clean-Install Post-Final-Edit Verification Matrix

All commands below were executed **after all F4.1 code and documentation edits** (`2026-11-15`) with `node_modules` deleted and reinstalled cleanly:

| Command / Suite | Observed Outcome | Observed Scope & Exact Counts |
|---|---|---|
| `rm -rf bke-worker/browser-extension/node_modules && cd bke-worker/browser-extension && npm install --ignore-scripts --no-audit --no-fund --package-lock=false && npm run check` | **PASS** (`exit 0`) | Clean `tsc` (pinned `typescript@5.8.3`), MV3 `validate`, **`202/202`** extension tests + **`39/39`** native-host tests + **`63/63`** host-claim tests (including `runtime-wiring.test.mjs`) |
| `cd bke-worker/browser-extension && npm run controller:doctor` | **PASS** (`exit 0`) | `ok: true`, `live_send_default_safe: LOCKED_FALSE`, `execution_envelope_mode: DISABLED_BY_DEFAULT`, `broker_protocol_mode: DISABLED_BY_DEFAULT`, `mediated_cas_mode: DISABLED_BY_DEFAULT` |
| `cd bke-worker/browser-extension && npm run smoke:native -- --report /tmp/desktop-native-smoke-report.json` | **PASS** (`exit 0`) | `BKE_DESKTOP_NATIVE_SMOKE=PASS`, `BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN` (temp report deleted after check) |
| `rm -rf bke-worker/integrations/desktop-broker/node_modules && cd bke-worker/integrations/desktop-broker && npm ci --ignore-scripts --no-audit --no-fund && npm run check` | **PASS** (`exit 0`) | Clean `npm ci` + `tsc` + **`8/8`** integration suites PASS (including `cli-operational-e2e.test.mjs`, `multiprocess-e2e.test.mjs`, `mediated-cas.test.mjs`, `multihost-safety.test.mjs`, `broker-service.test.mjs`, `chaos-adversarial.test.mjs`, `device-enrollment.test.mjs`) |
| `cd bke-worker && node scripts/input-only-lint.mjs && node --test scripts/input-only-lint.test.mjs` | **PASS** (`exit 0`) | Zero prohibited assistant-reply patterns + **`4/4`** lint unit tests PASS |
| `cd bke-worker/cloudflare-relay && npm run check && npm run reconnect-recovery-test` | **PASS** (`exit 0`) | Frozen Cloudflare relay (**`191/191`** PASS) & reconnect recovery planner PASS |
| `cd bke-worker && python3 tests/*.py && node --test tests/admin_preproduction_activation.test.mjs && bash tests/chrome_native_host_installer_contract.sh` | **PASS** (`exit 0`) | All 7 Python contracts, **`10/10`** `admin_preproduction_activation.test.mjs`, and `chrome_native_host_installer_contract.sh` PASS |
| `cd bke-worker && bash scripts/package-desktop-worker.sh package/verify/clean-uninstall --out /tmp/f41-pkg` | **PASS** (`exit 0`) | Deterministic bundle SHA-256 verification + default-OFF env checks + clean uninstall PASS (`/tmp/f41-pkg` removed) |
| `cd bke-worker && bash scripts/certify-forge-f1-desktop-mvp.sh --sandbox --dry-run` | `BKE_F1_MVP_CERTIFICATION=BLOCKED reason=NOT_IN_GIT_REPOSITORY` | Expected fail-closed behavior in gitless `/app/applet` container; verified on Git checkout in CI after sync |

---

## 5. Remaining Owner-Only Scope Outside Sandbox

1. **External GitHub Synchronization & Exact-SHA CI (`jan2xo/bke-worker-h`):** Trigger sync from AI Studio and verify `.github/workflows/hydrogen-sandbox-ci.yml` passes on the exact resulting commit SHA.
2. **Production Broker Deployment (`cloudflare-relay/`, Future `PR-14`):** Implement the production `/v1/enrollment/status`, `/v1/broker/tokens`, `/v1/broker/token-status`, `/v1/broker/authorize`, and `/v1/broker/ledger-ops` endpoints with owner-provisioned Wrangler Ed25519 + GitHub App secrets.
3. **Owner Device Provisioning & Level 7 Real Chrome Acceptance:** Enroll a physical owner device (`device-credentials.json` `0o600`, `owner-policy.json` `0o600`) and run an explicit single-session owner-supervised 2-turn Chrome acceptance check (`BKE_OWNER_SUPERVISED_LIVE_SEND=I_OWNER_AUTHORIZE_LIVE_SEND`).
