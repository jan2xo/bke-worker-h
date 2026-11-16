# HYDROGEN BKE WORKER — F4.3.1 SECURITY REMEDIATION & VERIFICATION HANDOFF

**FROM:** Gemini Hydrogen — Lead Implementing Engineer  
**TO:** GPT-6 — Independent Security Reviewer and BKE Systems Architect  
**PROJECT:** BKE Desktop Worker (`jan2xo/bke-worker-h` sandbox)  
**BASELINE REVIEWED:** SHA `fdc90bc813014b10e539dac50669315d995d3a86` (`Hydrogen Sandbox CI #43786902925`)  
**TARGET GIT SYNC STATE:** **`NOT_YET_SYNCED`** *(AI Studio container `/app/applet` contains no `.git` metadata or remote push credentials; exact-SHA GitHub Actions verification must be run after syncing workspace changes to `jan2xo/bke-worker-h`)*  
**DISPOSITION:** Both residual F4.3 audit findings (`SEC-06` and `SEC-07`) implemented, tested with dedicated adversarial suites + clean-install builds, and verified locally across all F1–F4.3.1 CI suites. Canonical promotion and external broker activation remain **locked/disabled** pending owner Git sync, exact-SHA CI, and live infrastructure readiness.

---

## 1. Executive Summary of F4.3.1 Changes

F4.3.1 resolves both residual source-level integrity findings from GPT-6's F4.3 independent audit follow-up:

| Finding | Severity | Defect Summary (F4.3) | F4.3.1 Remediation Implemented | Primary Files Changed |
|---|---|---|---|---|
| **SEC-06** | HIGH | `SERVER_MEDIATED_LEDGER_OP` Device PoP bound only 5 target fields (`ledger_op`, `pr_number`, `head_sha`, `attempt_id`, `ref_name`), leaving `repository_id`, `installation_id`, `worker_id`, `turn_ref_name`, `expected_parent_sha`, `is_continuation`, `commit_message`, and `tree_sha` unbound. Also `COMMIT_PRE_SEND_FENCE` fell back silently on non-JSON commit messages. | Replaced partial 5-field PoP binding with a canonical, domain-separated SHA-256 hex digest (`LEDGER_OP_DIGEST_DOMAIN = 'BKE_MEDIATED_LEDGER_OP_V1\n'`) covering all **14 allowlisted ledger operation fields** (`ledger_op_sha256`). Rejects non-allowlisted extra fields, verifies digest + `worker_id` + `installation_id` before nonce consumption or GitHub calls. Removed permissive legacy unstructured `PRE_SEND_FENCE` fallback from trusted mode (`BROKER_LEDGER_FENCE_PAYLOAD_INVALID`), retaining legacy fixture compatibility only behind isolated `allowLegacyUnstructuredFenceForTests?: boolean` (default `false`). | `desktop-broker/src/{types,device-enrollment,broker-client,broker-service,github-app-adapter}.ts`, `native-host/claim/runtime-broker-factory.ts` |
| **SEC-07** | HIGH | `listAllInstallationRepositories()` accepted `/installation/repositories` responses lacking `total_count` or returning truncated/malformed repository pages, enabling an incomplete installation inventory to conceal sibling-repo worker conflicts. | Hardened `listAllInstallationRepositories()` to require non-negative safe integer `total_count` on every page, cross-page `total_count` consistency, plain-object `repositories` items (`id >= 1`, `REPO_RE` `full_name`, plain-object `permissions`), `seenIds` deduplication (`BROKER_DUPLICATE_REPO`), `seenUrls` cycle detection, and `out.length === totalCount` (`BROKER_PAGINATION_INCOMPLETE`). Added `seenUrls` loop guard to `listAllOpenPullsForRepo()`, and propagated `BROKER_DUPLICATE_REPO` / `BROKER_REPO_LIST_INVALID` / `BROKER_REPO_ITEM_INVALID` inside `verifyMediatedPrAndNoUncertain()`. | `desktop-broker/src/github-app-adapter.ts`, `desktop-broker/tests/mock-github-server.mjs` |

---

## 2. Detailed Remediation & Protocol Changes

### 2.1 SEC-06 — Canonical 14-Field Domain-Separated `ledger_op_sha256` & Strict `PRE_SEND_FENCE`
- **Canonicalization & Allowlist (`desktop-broker/src/types.ts`, mirrored in `native-host/claim/runtime-broker-factory.ts`):**
  - `LEDGER_OP_DIGEST_DOMAIN = 'BKE_MEDIATED_LEDGER_OP_V1\n'`.
  - `LEDGER_OP_ALLOWLISTED_KEYS` defines the exact 14 permitted keys:
    `attempt_id`, `commit_message`, `expected_parent_sha`, `head_sha`, `installation_id`, `is_continuation`, `operation`, `pr_number`, `ref_name`, `repository`, `repository_id`, `tree_sha`, `turn_ref_name`, `worker_id`.
  - `canonicalizeServerMediatedLedgerOp()` fails closed with `BROKER_ARBITRARY_PROXY_FORBIDDEN` if `force === true`, `force_update === true`, or any key outside `LEDGER_OP_ALLOWLISTED_KEYS` is present.
  - Enforces non-empty string `worker_id` (`BROKER_LEDGER_OP_INVALID` if missing/empty) and safe-integer / string invariants on all required fields.
  - Optional fields (`turn_ref_name`, `expected_parent_sha`, `is_continuation`) reject empty strings or wrong types (`BROKER_LEDGER_OP_INVALID`) and canonicalize `undefined -> null` so omitted vs `false` vs `true` (`is_continuation`) never collide.
  - Keys are emitted in exact lexicographical order before computing `SHA-256(LEDGER_OP_DIGEST_DOMAIN + JSON.stringify(canonical))` hex (`computeLedgerOpDigestHex()`).
- **10-Key `SERVER_MEDIATED_LEDGER_OP` Device PoP (`device-enrollment.ts`, `broker-client.ts`, `runtime-broker-factory.ts`, `broker-service.ts`):**
  - `verifyDeviceAssertion()` (`device-enrollment.ts`) replaces the partial 5 fields with `ledger_op_sha256` (exact 10 sorted keys: `device_id`, `enrollment_generation`, `expires_at`, `installation_id`, `issued_at`, `ledger_op_sha256`, `nonce`, `purpose`, `repository`, `worker_id`; `/^[a-f0-9]{64}$/`).
  - `DeviceKeyPairSigner.signDeviceAssertion()`, `SandboxHttpTokenBrokerClient.executeLedgerOp()`, and `HttpTrustedBrokerClient.executeLedgerOp()` canonicalize the exact full `ledger_op` object sent over HTTP and sign its `ledger_op_sha256`.
  - `TrustedDesktopBroker.executeServerMediatedLedgerOp()` computes `expectedDigest = computeLedgerOpDigestHex(params.ledger_op)` (rejecting unbound extra fields/invalid shape immediately), verifies `device_assertion`, and validates constant-time `timingSafeEqual` equality against `payload.ledger_op_sha256` plus exact `worker_id` and `installation_id` match (`BROKER_DEVICE_SCOPE_MISMATCH`) **before** consuming the PoP nonce or touching GitHub.
- **Strict Structured `PRE_SEND_FENCE` (`github-app-adapter.ts`):**
  - `GitHubAppAdapterConfig` adds `allowLegacyUnstructuredFenceForTests?: boolean` (strictly `false` by default).
  - `validateFencePayloadMessage(req)` rejects non-JSON or malformed `PRE_SEND_FENCE` messages (`BROKER_LEDGER_FENCE_PAYLOAD_INVALID`) unless `allowLegacyUnstructuredFenceForTests === true` is explicitly passed in isolated legacy test harnesses. Requires `bkeEvent === 'PRE_SEND_FENCE'`, `version === 1`, non-empty `fenceId`, matching `attemptId === req.attempt_id`, `headSha === req.head_sha`, and valid `WORKER_RE` `workerId === req.worker_id`.

### 2.2 SEC-07 — Fail-Closed `/installation/repositories` Enumeration
- **Enumeration Completeness (`github-app-adapter.ts`):**
  - `listAllInstallationRepositories()` verifies every page returns a plain object (`repositories` array + safe non-negative integer `total_count`), rejects inconsistent `total_count` across pages (`BROKER_PAGINATION_INCOMPLETE`), validates every entry (`id >= 1` safe int, `REPO_RE` `full_name`, plain-object `permissions` -> `BROKER_REPO_ITEM_INVALID`), detects duplicate repo IDs (`BROKER_DUPLICATE_REPO`), guards against cyclic `Link: rel="next"` headers (`seenUrls` -> `BROKER_PAGINATION_INCOMPLETE`), and fails closed if `out.length !== totalCount`.
  - `listAllOpenPullsForRepo()` also enforces `seenUrls` cycle detection (`BROKER_PAGINATION_INCOMPLETE`).
  - `verifyMediatedPrAndNoUncertain()` preserves and propagates `BROKER_DUPLICATE_REPO`, `BROKER_REPO_LIST_INVALID`, and `BROKER_REPO_ITEM_INVALID` alongside pagination errors rather than collapsing them.
- **Mock Server & Two-Repository Adversarial Matrix (`mock-github-server.mjs`, `f4-3-1-security-remediation.test.mjs`):**
  - `mock-github-server.mjs` adds fault injection flags for `/installation/repositories`: `omitRepoTotalCount`, `badRepoTotalCount`, `mismatchedRepoTotalCount`, `truncatedRepoPagination`, `duplicateRepoId`, `malformedRepoLink`, and `loopRepoLink`.
  - Verified both `authorizeExecution` and `COMMIT_PRE_SEND_FENCE` (mediated CAS) across a two-repository installation (`jan2xo/bke-worker` PR `#149` + sibling `jan2xo/bke-second-repo` PR `#77` holding the same `worker-f1`), proving all 9 fault cases fail closed and clean 2-page enumeration detects `BROKER_CROSS_REPO_WORKER_CONFLICT` / `BROKER_LEDGER_CROSS_REPO_WORKER_CONFLICT`.

---

## 3. Existing Test Fixtures Updated & New Adversarial Coverage

- **Updated existing fixtures for canonical 14-field digest + structured `PRE_SEND_FENCE` JSON:**
  1. `integrations/desktop-broker/tests/broker-service.test.mjs`: signs full `ledger_op` via `ledger_op_sha256` and uses structured `PRE_SEND_FENCE` JSON (`allowLegacyUnstructuredFenceForTests` not enabled).
  2. `integrations/desktop-broker/tests/mediated-cas.test.mjs`: sends valid `worker_id` + structured `PRE_SEND_FENCE` JSON, binds full `ledger_op` in PoP.
  3. `integrations/desktop-broker/tests/multihost-safety.test.mjs`: signs `ledger_op` digest + emits structured `PRE_SEND_FENCE` JSON.
  4. `integrations/desktop-broker/tests/chaos-adversarial.test.mjs`: signs `ledger_op` digest + emits structured `PRE_SEND_FENCE` JSON.
  5. `integrations/desktop-broker/tests/f4-3-security-remediation.test.mjs`: signs full `ledger_op` digest across SEC-01..SEC-05 and exercises strict `PRE_SEND_FENCE` / `MARK_DELIVERY_UNCERTAIN`.
- **New `integrations/desktop-broker/tests/f4-3-1-security-remediation.test.mjs` (3 tests, 822 lines):**
  - `SEC-06` canonical rules (`is_continuation: true/false/omitted`, empty optional string rejection, non-allowlisted field rejection), 14-field individual post-signing mutation matrix + extra unbound field + positive HTTP verification via both `SandboxHttpTokenBrokerClient` and `HttpTrustedBrokerClient`.
  - `SEC-06` strict trusted rejection across 7 invalid/unstructured `PRE_SEND_FENCE` payloads (`BROKER_LEDGER_FENCE_PAYLOAD_INVALID`) vs explicit `allowLegacyUnstructuredFenceForTests: true` opt-in (preserving post-signing `commit_message` tamper rejection).
  - `SEC-07` two-repository 9-fault `/installation/repositories` failure matrix across both `authorizeExecution` and mediated CAS (`COMMIT_PRE_SEND_FENCE`), plus cross-repo conflict catch when faults clear and positive pass after sibling conflict release.

---

## 4. Verification Executed After Final Code Edits

All checks below ran cleanly after the final source, test, and doc edits using isolated fresh `node_modules` installs matching `.github/workflows/hydrogen-sandbox-ci.yml`:

| Stage / Suite | Command | Outcome | Measured Count / Notes |
|---|---|---|---|
| Clean `browser-extension` build & tests | `rm -rf node_modules dist && npm install --ignore-scripts --no-audit --no-fund --package-lock=false && npm run check` | **PASS** | `tsc -p tsconfig.json` + manifest validate + **202/202** extension tests + **39/39** native-host tests + **64/64** host-claim tests (**305/305 total**) |
| `controller:doctor` & `smoke:native` | `npm run controller:doctor && npm run smoke:native -- --report /tmp/desktop-native-smoke-report.json` | **PASS** | All default flags `LOCKED_FALSE` / `DISABLED_BY_DEFAULT`; `BKE_DESKTOP_NATIVE_SMOKE=PASS` (`BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN`) |
| Clean `desktop-broker` CI check | `rm -rf node_modules dist && npm ci --ignore-scripts --no-audit --no-fund && npm run check` | **PASS** | `tsc -p tsconfig.json` + **16/16** integration/adversarial suites pass (all 13 existing + 3 new F4.3.1 `SEC-06`/`SEC-07` tests) |
| Input-only boundary lint | `node scripts/input-only-lint.mjs && node --test scripts/input-only-lint.test.mjs` | **PASS** | **4/4** tests pass |
| Cloudflare relay verification | `npm run check && npm run reconnect-recovery-test` *(in `bke-worker/cloudflare-relay`)* | **PASS** | **191/191** tests + reconnect recovery pass |
| Python, Shell & Packaging contracts | All 7 `.py` contract scripts + `admin_preproduction_activation.test.mjs` + `chrome_native_host_installer_contract.sh` + `package-desktop-worker.sh {package,verify,clean-uninstall}` + `.env.example` default-OFF greps | **PASS** | **10/10** activation tests + all contracts pass; `MANIFEST_OK` + default flags verified `false` |
| Sandbox F1 MVP certifier | `bash scripts/certify-forge-f1-desktop-mvp.sh --sandbox --dry-run` | **BLOCKED (expected in container)** | Outputs `BKE_F1_MVP_CERTIFICATION=BLOCKED reason=NOT_IN_GIT_REPOSITORY` because `/app/applet` lacks `.git` |

---

## 5. Governance, Frozen Surfaces, and Unverified External Boundaries

### 5.1 Untouched / Locked Surfaces
- **Frozen canonical files untouched:** `cloudflare-relay/`, `android-gecko/`, `bke-worker/src/`, `BKE.Worker.sln`, `Directory.Build.props`, `bke-worker/.github/workflows/pr-guard.yml`.
- **Default-OFF flags preserved (`false`):**
  - `FIRST_MESSAGE_LIVE_SEND_ENABLED = false`
  - `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false`
  - `humanLiveSendAuthorized = false`
  - `BKE_EXECUTION_V2_ASYMMETRIC_ENABLED=false`
  - `BKE_REQUIRE_ASYMMETRIC_V2=false`
  - `BKE_REMOTE_BROKER_ENABLED=false`
  - `BKE_SERVER_MEDIATED_CAS_ENABLED=false`
- **Canonical promotion sizing note:** `bke-worker/docs/canonical-promotion-plan.md` has been updated with post-F4.3.1 measured line counts (`wc -l`) for all modified/added modules exceeding `pr-guard.yml`'s 500-line per-PR ceiling.

### 5.2 Honest Scope & Unproven External Boundaries
- **Git / Exact-SHA CI Status:** **`NOT_YET_SYNCED`** from this container; `/app/applet` has no `.git` history or GitHub token. After syncing these changes to `jan2xo/bke-worker-h`, inspect the resulting `Hydrogen Sandbox CI` exact-SHA workflow run and verify `certify-forge-f1-desktop-mvp.sh --sandbox --dry-run` passes inside a real git checkout.
- **External live systems not exercised:**
  1. Real GitHub App installation private key (RS256 JWT exchange) and live GitHub REST API `/installation/repositories` / CAS writes against live GitHub.
  2. Live Cloudflare Worker (`cloudflare-relay/`) broker endpoints (still outside F4.3.1 sandbox scope).
  3. Physical Chrome browser Level 7 live acceptance session (`BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN`).
