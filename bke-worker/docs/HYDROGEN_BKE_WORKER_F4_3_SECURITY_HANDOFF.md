# HYDROGEN BKE WORKER — F4.3 SECURITY REMEDIATION & VERIFICATION HANDOFF

**FROM:** Gemini Hydrogen — Lead Implementing Engineer  
**TO:** GPT-6 — Independent Security Reviewer and BKE Systems Architect  
**PROJECT:** BKE Desktop Worker (`jan2xo/bke-worker-h` sandbox)  
**BASELINE REVIEWED:** SHA `46a8f3d73b52db17712013fb2d99dbdaa71d3c52` (`Hydrogen Sandbox CI #43768604073`)  
**TARGET GIT SYNC STATE:** **`NOT_YET_SYNCED`** *(AI Studio container `/app/applet` contains no `.git` metadata or remote push credentials; exact-SHA GitHub Actions verification must be run after syncing workspace changes to `jan2xo/bke-worker-h`)*  
**DISPOSITION:** All 5 F4.2 audit findings (`SEC-01` through `SEC-05`) implemented, tested with dedicated adversarial suites + clean-install builds, and verified locally post-final-edit. Canonical promotion and external broker activation remain **locked/disabled** pending owner Git sync, exact-SHA CI, and live infrastructure readiness.

---

## 1. Executive Summary of F4.3 Changes

F4.3 resolves all five source-grounded findings raised in GPT-6's F4.2 Independent Security Audit (`2026-11-16`):

| Finding | Severity | Defect Summary (F4.2) | F4.3 Remediation Implemented | Primary Files Changed |
|---|---|---|---|---|
| **SEC-01** | HIGH | `verifyExecutionAuthority` and mediated CAS used a single-repo token (`repository_ids: [expectedRepositoryId]`) while calling `listAllInstallationRepositories()`, preventing cross-repo worker exclusivity detection (`403` / hidden repos). | Added `mintInstallationWideReadAuthorityToken()` (read-only `{ contents: 'read', pull_requests: 'read', checks: 'read' }`, omits `repository_ids`, never returned outside adapter) for cross-repo enumeration across both `verifyExecutionAuthority()` and `verifyMediatedPrAndNoUncertain()`. Desktop tokens stay single-repo read-only. | `integrations/desktop-broker/src/github-app-adapter.ts`, `tests/mock-github-server.mjs` |
| **SEC-02** | HIGH | `/pulls?state=open&per_page=100`, `/check-runs?per_page=100`, and `/git/matching-refs/bke/` lacked complete `Link: rel="next"` traversal and `total_count` completeness checks in both `verifyExecutionAuthority()` and mediated CAS. | Extracted bounded paginated readers `listAllOpenPullsForRepo()`, `listAllCheckRunsForCommit()` (enforces non-negative consistent `total_count`, deduplicates run IDs, checks `out.length === totalCount`), and `listMatchingBkeRefs()` (`Link` traversal + deduplication). Malformed `Link` / incomplete pages fail closed (`BROKER_GITHUB_PAGINATION_MALFORMED` / `BROKER_PAGINATION_INCOMPLETE`). | `integrations/desktop-broker/src/github-app-adapter.ts`, `tests/mock-github-server.mjs` |
| **SEC-03** | HIGH | `SERVER_MEDIATED_LEDGER_OP` Device PoP assertions did not bind ledger target fields, and `MARK_DELIVERY_UNCERTAIN` created `refs/bke/uncertain/<pr>/<attempt>` without proving the requester owned a prior durable `PRE_SEND_FENCE`. | Bound `ledger_op`, `pr_number`, `head_sha`, `attempt_id`, and `ref_name` (exact 14-key signed schema) into `SERVER_MEDIATED_LEDGER_OP` Device PoP; `TrustedDesktopBroker` enforces exact equality (`BROKER_DEVICE_SCOPE_MISMATCH`). `MARK_DELIVERY_UNCERTAIN` now requires reading `refs/bke/fences/<pr>/<attempt>` (`200`) + commit JSON proving `bkeEvent === 'PRE_SEND_FENCE'`, `workerId`, `attemptId`, `headSha` (`BROKER_LEDGER_FENCE_MISSING` / `BROKER_LEDGER_UNCERTAIN_OWNERSHIP_CONFLICT`). Preserves quarantine recovery even if PR head advances or worker label is removed after fencing. | `desktop-broker/src/{types,device-enrollment,broker-service,broker-client,github-app-adapter}.ts`, `native-host/claim/runtime-broker-factory.ts` |
| **SEC-04** | MEDIUM | `getSignedTokenStatus()` only checked `revokedTokens`, signing `status: 'ACTIVE'` for random, unissued, foreign, or expired tokens. | Broker persists `issuedTokens[sha256]` registry (`usage_expires_at_ms`, `provider_expires_at_ms`, `revoked`, `provider_revoked`). `getSignedTokenStatus()` now signs `'UNKNOWN'` (`revoked: true`) for unissued tokens and `'EXPIRED'` (`revoked: true`) once past `usage_expires_at_ms` or `provider_expires_at_ms`. Both clients fail closed (`TOKEN_UNKNOWN_OR_UNISSUED` / `TOKEN_EXPIRED`), and `ManagedTokenProvider` clears cache on `TOKEN_EXPIRED`. | `desktop-broker/src/{types,broker-service,broker-client}.ts`, `native-host/claim/{token-lifecycle,runtime-broker-factory}.ts` |
| **SEC-05** | MEDIUM | `mintScopedToken()` clamped `expiresAtMs = min(providerExpiry, now + defaultTokenTtlMs)` without surfacing provider expiry, and `revokeIssuedToken()` only stored local SHA-256 without calling GitHub `DELETE /installation/token`. | Surfaced `usageExpiresAtMs` (app budget), `providerExpiresAtMs` (GitHub IAT lifetime), and `revocationScope: 'LOCAL_AND_PROVIDER'`. Added `revokeInstallationTokenAtProvider()` (`DELETE /installation/token`, expects `204`, handles `401`/`404` non-destructively) invoked by default in `revokeIssuedToken()` unless `localOnly: true` (`local_only: true` on `/v1/broker/revoke-token`) is explicitly requested. | `desktop-broker/src/{github-app-adapter,broker-service,broker-server,broker-client}.ts`, `native-host/claim/{token-lifecycle,runtime-broker-factory}.ts`, `tests/mock-github-server.mjs` |

---

## 2. Detailed Remediation & Protocol Changes

### 2.1 SEC-01 — Cross-Repository Worker Exclusivity vs. Scoped Desktop Tokens
- **Problem:** GitHub App installation access tokens scoped with `repository_ids: [<single-repo>]` return only that single repository on `GET /installation/repositories` and `403` on other repositories in the same installation. Using that token for worker exclusivity silently blinded both `verifyExecutionAuthority()` and `verifyMediatedPrAndNoUncertain()` to conflicting PR assignments in sibling repositories.
- **Fix:**
  - `SandboxGitHubAppAdapter.mintInstallationWideReadAuthorityToken(expectedInstallationId)` (`github-app-adapter.ts`) resolves `POST /app/installations/:id/access_tokens` **without `repository_ids`**, requesting strictly read-only `{ contents: 'read', pull_requests: 'read', checks: 'read' }`, verifying granted permissions contain no write/admin escalation, and keeping the token strictly internal to the adapter.
  - Both `verifyExecutionAuthority()` and `verifyMediatedPrAndNoUncertain()` enumerate **all** repositories via `listAllInstallationRepositories(instReadToken)` and **all** open PRs across every repository via `listAllOpenPullsForRepo(instReadToken, repo.full_name)`. Conflicting assignments fail closed with `BROKER_CROSS_REPO_WORKER_CONFLICT` (`authorizeExecution`) or `BROKER_LEDGER_CROSS_REPO_WORKER_CONFLICT` (`executeServerMediatedLedgerOp`).
  - Meanwhile, tokens returned to the desktop controller via `mintScopedToken()` remain pinned to `[expectedRepositoryId]` with read-only permissions (`403` on any other repo).

### 2.2 SEC-02 — Complete GitHub API Pagination & `total_count` Validation
- **Problem:** Single-page `per_page=100` reads could miss conflicting open PRs, `bke-ticket` check runs (or duplicates), or `refs/bke/uncertain/` entries past item 100.
- **Fix:**
  - `parseNextUrl()` (`github-app-adapter.ts`) wraps URL parsing in `try/catch`, throwing `BROKER_GITHUB_PAGINATION_MALFORMED` on invalid `Link` headers and preserving `BROKER_GITHUB_CROSS_ORIGIN_FORBIDDEN` for non-origin next URLs.
  - Bounded pagination readers (`this.maxPages` guard throwing `BROKER_PAGINATION_INCOMPLETE`):
    - `listAllOpenPullsForRepo()`: follows `Link: rel="next"`, deduplicates `pr.number`, rejects duplicates as `BROKER_PAGINATION_INCOMPLETE`.
    - `listAllCheckRunsForCommit()`: follows `Link: rel="next"`, requires valid non-negative integer `total_count` matching across pages (`BROKER_PAGINATION_INCOMPLETE` if missing/mismatched), deduplicates `run.id`, and verifies `out.length === totalCount`. Applied identically to both `verifyExecutionAuthority()` and `verifyPinnedTicketForClaim()` (used by `CONSUME_SEND_CLAIM`).
    - `listMatchingBkeRefs()`: follows `Link: rel="next"` across `/git/matching-refs/bke/?per_page=100`, verifies every returned ref begins with `refs/bke/`, deduplicates ref names.
  - `mock-github-server.mjs` was enhanced with configurable `pullsPageSize`, `checkRunsPageSize`, `refsPageSize`, `incompletePullsPagination`, `malformedPullsLink`, `missingCheckTotalCount`, and `setCheckRuns(repo, headSha, runs)`.

### 2.3 SEC-03 — Device PoP Ledger-Target Bindings & `MARK_DELIVERY_UNCERTAIN` Fence Proof
- **Problem:** Previously, a `SERVER_MEDIATED_LEDGER_OP` Device PoP signed only `{ version, worker_id, device_id, installation_id, enrollment_generation, purpose, repository, nonce, issued_at, expires_at }`, allowing replay from one ledger op/PR/attempt to another. Additionally, `MARK_DELIVERY_UNCERTAIN` checked neither PR state nor fence ownership before writing `refs/bke/uncertain/<pr>/<attempt>`.
- **Fix:**
  - `DeviceSignedAssertionPayload` (`desktop-broker/src/types.ts`) adds optional ledger target bindings (`ledger_op`, `pr_number`, `head_sha`, `attempt_id`, `ref_name`).
  - `verifyDeviceAssertion()` (`device-enrollment.ts`) enforces:
    - Exact 9-key schema for `AUTHORIZE_EXECUTION` and `MINT_SCOPED_TOKEN`.
    - Exact **14-key** schema + format validation (`ledger_op` in allowed 4 ops, integer `pr_number >= 1`, 40-hex `head_sha`, `ATTEMPT_RE` `attempt_id`, `ref_name` length `1..256`) for `SERVER_MEDIATED_LEDGER_OP`. Allowing valid non-`refs/bke/` strings through PoP validation ensures invalid-ref attempts still reach `executeServerMediatedLedgerOp()` and reject deterministically with `BROKER_ARBITRARY_PROXY_FORBIDDEN`.
  - Both `HttpTrustedBrokerClient` (`runtime-broker-factory.ts`) and `SandboxHttpTokenBrokerClient` + `DeviceKeyPairSigner` (`broker-client.ts`) require and sign all 5 target fields on `SERVER_MEDIATED_LEDGER_OP`.
  - `TrustedDesktopBroker.executeServerMediatedLedgerOp()` (`broker-service.ts`) verifies `pop.ledger_op === op.operation`, `pop.pr_number === op.pr_number`, `pop.head_sha === op.head_sha`, `pop.attempt_id === op.attempt_id`, and `pop.ref_name === op.ref_name` (`BROKER_DEVICE_SCOPE_MISMATCH` on mismatch) **before** consuming the PoP nonce.
  - `MARK_DELIVERY_UNCERTAIN` in `github-app-adapter.ts` requires `req.worker_id`, reads `GET /repos/:repo/git/ref/bke/fences/:pr/:attempt` (`BROKER_LEDGER_FENCE_MISSING` if absent) and `GET /git/commits/:sha`, and requires JSON `{ bkeEvent: 'PRE_SEND_FENCE', workerId: req.worker_id, attemptId: req.attempt_id, headSha: req.head_sha }` (`BROKER_LEDGER_UNCERTAIN_OWNERSHIP_CONFLICT` on mismatch). `COMMIT_PRE_SEND_FENCE` also validates structured `PRE_SEND_FENCE` JSON payloads when supplied.
  - Crucially, `MARK_DELIVERY_UNCERTAIN` does **not** require live PR `headSha` match or live worker label presence so that an in-flight worker that legitimately fenced `HEAD_A` can still quarantine delivery uncertainty if the PR advances or label changes mid-send.

### 2.4 SEC-04 — Fail-Closed Signed Token Status (`UNKNOWN` / `EXPIRED`)
- **Problem:** `getSignedTokenStatus()` only checked `state.revokedTokens`, meaning any unknown, unissued, foreign, or usage-expired token received a signed `ACTIVE` (`revoked: false`) assertion.
- **Fix:**
  - `BrokerDurableState` (`broker-service.ts`) adds `issuedTokens?: Record<string, IssuedTokenRecord>` (backward-compatible default `{}` in `readOrInitState`, bounded at 4,096 entries).
  - `getSignedTokenStatus()` evaluates in strict priority:
    1. In `revokedTokens` or `rec?.revoked === true` -> `{ status: 'REVOKED', revoked: true }`
    2. `!rec` (unissued/unknown/foreign) -> `{ status: 'UNKNOWN', revoked: true }`
    3. `now >= rec.usage_expires_at_ms || now >= rec.provider_expires_at_ms` -> `{ status: 'EXPIRED', revoked: true }`
    4. Otherwise -> `{ status: 'ACTIVE', revoked: false }`
  - `HttpTrustedBrokerClient.checkTokenStatus()` and `SandboxHttpTokenBrokerClient.checkTokenStatus()` map signed `EXPIRED` (`revoked === true`) -> `{ status: 'EXPIRED', code: 'TOKEN_EXPIRED' }` and signed `UNKNOWN` (`revoked === true`) -> `{ status: 'UNKNOWN', code: 'TOKEN_UNKNOWN_OR_UNISSUED' }`, while contradictory pairs (e.g., `UNKNOWN` with `revoked: false`, `EXPIRED` with `revoked: false`, `ACTIVE` with `revoked: true`) still fail closed with `{ status: 'UNKNOWN', code: 'TOKEN_REVOCATION_UNAVAILABLE' }`.
  - `ManagedTokenProvider.getToken()` (`token-lifecycle.ts`) clears `this.cached = null` and throws `TOKEN_EXPIRED` when broker reports `status === 'EXPIRED'`.

### 2.5 SEC-05 — Usage-Budget vs. Provider TTL & `DELETE /installation/token` Revocation
- **Problem:** Returning `expiresAtMs = min(providerExpiry, now + defaultTokenTtlMs)` implied GitHub invalidated the token at 5 minutes when GitHub actually honors installation tokens until ~60 minutes unless revoked at the provider; and `revokeIssuedToken()` left tokens valid at GitHub.
- **Fix:**
  - `IssuedScopedToken` (`token-lifecycle.ts`) and `mintScopedToken()` (`broker-service.ts`) now expose `usageExpiresAtMs` (app-enforced refresh/usage budget), `providerExpiresAtMs` (provider IAT expiry), and `revocationScope: 'LOCAL_AND_PROVIDER'`.
  - `SandboxGitHubAppAdapter.revokeInstallationTokenAtProvider(token)` (`github-app-adapter.ts`) calls `DELETE /installation/token` with `Authorization: Bearer <token>`, returning `{ revokedAtProvider: true, status: 204 }` on `204 No Content`, `{ revokedAtProvider: false, status }` on `401`/`404`, and throwing on transient/5xx failures (note `httpJson()` updated to support `'DELETE'` and `204` empty responses).
  - `TrustedDesktopBroker.revokeIssuedToken(token, { localOnly? })` persists local revocation AND invokes `revokeInstallationTokenAtProvider(token)` by default (`localOnly: true` opt-in exposed via `POST /v1/broker/revoke-token` `body.local_only`).
  - `mock-github-server.mjs` enforces `DELETE /installation/token` (`204`, adds token to `state.revokedInstallationTokens`) and returns `401 Bad credentials` for revoked or unrecognized `ghs_sandbox_` tokens.

---

## 3. Pre-Existing Test Fixtures Updated for SEC-03 / SEC-04 Compliance

Four existing test callers signed `SERVER_MEDIATED_LEDGER_OP` assertions directly or exercised `MARK_DELIVERY_UNCERTAIN` without a prerequisite pre-send fence:
1. `integrations/desktop-broker/tests/broker-service.test.mjs`: added the 5 ledger target fields to direct HTTP `SERVER_MEDIATED_LEDGER_OP` Device PoP assertions (`att-cas-01`, `att-evil`).
2. `integrations/desktop-broker/tests/mediated-cas.test.mjs`: added the 5 ledger target fields to the `force: true` rejection PoP, and committed a valid `PRE_SEND_FENCE` (`att-cas-unc-1`) prior to testing `MARK_DELIVERY_UNCERTAIN` -> `COMMITTED` -> `ALREADY_EXISTS`.
3. `integrations/desktop-broker/tests/multihost-safety.test.mjs`: updated `makeMediatedClient()` helper to include `ledger_op`, `pr_number`, `head_sha`, `attempt_id`, and `ref_name` from each op in `signDeviceAssertion`.
4. `integrations/desktop-broker/tests/chaos-adversarial.test.mjs`: updated `mediatedLedgerClient` helper identically.
5. `browser-extension/native-host/claim/tests/runtime-wiring.test.mjs`: added SEC-04 verification for legitimately signed `EXPIRED` (`revoked: true`) -> `TOKEN_EXPIRED` and `UNKNOWN` (`revoked: true`) -> `TOKEN_UNKNOWN_OR_UNISSUED` alongside the existing contradictory-field negative matrix (bringing `runtime-wiring.test.mjs` token negative + signed checks to 12 cases alongside the 24-case device status matrix).

---

## 4. Verification Executed After Final Code Edits

All checks below ran cleanly after the final source & test edits using isolated fresh `node_modules` installs matching `.github/workflows/hydrogen-sandbox-ci.yml`:

| Stage / Suite | Command | Outcome | Measured Count / Notes |
|---|---|---|---|
| Clean `browser-extension` build & tests | `rm -rf node_modules && npm install --ignore-scripts --no-audit --no-fund --package-lock=false && npm run check` | **PASS** | `tsc -p tsconfig.json` + manifest validate + **202/202** extension tests + **39/39** native-host tests + **64/64** host-claim tests (**305/305 total**) |
| `controller:doctor` & `smoke:native` | `npm run controller:doctor && npm run smoke:native -- --report ...` | **PASS** | All default flags `LOCKED_FALSE` / `DISABLED_BY_DEFAULT`; `BKE_DESKTOP_NATIVE_SMOKE=PASS` (`BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN`) |
| Clean `desktop-broker` CI check | `rm -rf node_modules && npm ci --ignore-scripts --no-audit --no-fund && npm run check` | **PASS** | `tsc -p tsconfig.json` + **13/13** integration/adversarial suites pass (all 9 existing + 4 new F4.3 `SEC-01`..`SEC-05` suites) |
| Input-only boundary lint | `node scripts/input-only-lint.mjs && node --test scripts/input-only-lint.test.mjs` | **PASS** | **4/4** tests pass |
| Cloudflare relay verification | `npm run check && npm run reconnect-recovery-test` *(in `bke-worker/cloudflare-relay`)* | **PASS** | **191/191** tests + reconnect recovery pass |
| Python, Shell & Packaging contracts | All 7 `.py` contract scripts + `admin_preproduction_activation.test.mjs` + `chrome_native_host_installer_contract.sh` + `package-desktop-worker.sh {package,verify,clean-uninstall}` + `.env.example` default-OFF greps | **PASS** | **10/10** activation tests + all contracts pass; default flags verified `false` |
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
- **Canonical promotion sizing note:** `bke-worker/docs/canonical-promotion-plan.md` has been updated with post-F4.3 measured line counts (`wc -l`) for all modified/added modules exceeding `pr-guard.yml`'s 500-line per-PR ceiling.

### 5.2 Honest Scope & Unproven External Boundaries
- **Git / Exact-SHA CI Status:** **`NOT_YET_SYNCED`** from this container; `/app/applet` has no `.git` history or GitHub token. After syncing these changes to `jan2xo/bke-worker-h`, inspect the resulting `Hydrogen Sandbox CI` exact-SHA workflow run and verify `certify-forge-f1-desktop-mvp.sh --sandbox --dry-run` passes inside a real git checkout.
- **External live systems not exercised:**
  1. Real GitHub App installation private key (RS256 JWT exchange) and live GitHub REST API `DELETE /installation/token` + multi-repo `/installation/repositories` against live GitHub.
  2. Live Cloudflare Worker (`cloudflare-relay/`) broker endpoints (still outside F4.3 sandbox scope).
  3. Physical Chrome browser Level 7 live acceptance session (`BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN`).
