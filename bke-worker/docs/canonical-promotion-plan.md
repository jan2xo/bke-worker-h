# Canonical Promotion Plan (`jan2xo/bke-worker-h` -> `jan2xo/bke-worker`)

This document reconciles the completed **F1 + F2 + F3 + F4 + F4.1 + F4.2 + F4.3 + F4.3.1** BKE Desktop Worker implementation in `jan2xo/bke-worker-h` against the canonical governance gates enforced by `jan2xo/bke-worker/.github/workflows/pr-guard.yml` (Issue `#149`).

> **Governance Reminder:** Do **NOT** open, merge, or reuse any oversized omnibus PR against `jan2xo/bke-worker` during sandbox engineering. Each canonical promotion PR requires an open `bke:mvp`-labeled GitHub issue referenced via `MVP-Task: #<issue>` in the PR body.

---

## 1. Exact `pr-guard.yml` Rules Reconciled Against Measured F1–F4.3.1 Source

Inspecting canonical `bke-worker/.github/workflows/pr-guard.yml` (lines 250–376) establishes five hard gates:

1. **500-Line Total PR Budget (ALL Files Included — Code + Tests + Docs):**
   - `pr-guard.yml:341-345` computes `files.reduce((n, f) => n + f.additions + f.deletions, 0)` across **every file in the PR**, *including test and documentation files*, unless the owner explicitly adds label `bke:oversize-ok`.
   - Therefore, splitting tests into separate PRs only helps if each PR's combined `(code + test + doc)` diff stays `<= 500` lines, OR an oversize module/test is decomposed into helper modules before canonical PR creation, OR the owner explicitly pre-authorizes `bke:oversize-ok`.
2. **Frozen Surface Allowlist Rule (`deploy/` & `cloudflare-relay/` Are Frozen):**
   - `pr-guard.yml:348-356` blocks any change touching:
     `cloudflare-relay/`, `android-gecko/`, `src/`, **`deploy/`**, `BKE.Worker.sln`, `Directory.Build.props`
     unless the linked `MVP-Task: #<issue>` body/title literally contains the matching path prefix.
   - `cloudflare-relay/`, `android-gecko/`, `src/`, `BKE.Worker.sln`, and `Directory.Build.props` remain **100% untouched** across F1–F4.3.
   - Only `deploy/desktop-controller.env.example` (71 lines, including F3/F4/F4.1 default-OFF V2/broker/mediated-CAS fields) and `deploy/owner-native-policy.template.json` (13 lines) touch `deploy/`, so that specific PR's `#<issue>` must explicitly name `deploy/`.
3. **CI / Workflow Protection Rule:**
   - Any file under `.github/` requires owner label `bke:gate-change` (`pr-guard.yml:360-362`).
   - `.github/workflows/hydrogen-sandbox-ci.yml` (86 lines) lives at the sandbox root (`jan2xo/bke-worker-h`) and is **excluded** from canonical `jan2xo/bke-worker` promotion; `bke-worker/.github/workflows/pr-guard.yml` itself is untouched.
4. **Added Markdown Filename Rule:**
   - Every newly added `.md` file causes `mvp-scope-gate` failure unless its **exact repo-relative filename** appears in the linked `#<issue>` body/title (`pr-guard.yml:365-369`).
   - Any canonical PR adding F2/F3/F4 markdown docs MUST list each exact filename in its issue:
     `docs/command-center-compatibility.md`, `docs/desktop-operator-acceptance.md`, `docs/android-reconciliation-audit.md`, `docs/canonical-promotion-plan.md`, `docs/f3-security-audit.md`, `docs/f3-existing-github-app-contract.md`, `docs/f3-desktop-enrollment-contract.md`, `docs/f3-command-center-integration.md`, `docs/F4_SECURITY_REVIEW_PACKAGE.md`.
5. **Exact-Head WebExtension Identity Contract:**
   - Any PR touching `browser-extension/`, `scripts/prepare-chrome-native-host.sh`, or `tests/chrome_native_host_installer_contract.py` triggers `pr-guard.yml` lines 251–297 on the exact PR head SHA: clean `npm install --ignore-scripts --no-audit --no-fund --package-lock=false`, `npm run check`, `npm run smoke:native`, `bash -n scripts/smoke-desktop-native-integration.sh`, and `git diff --check`.
   - Consequently, **no canonical PR may depend on an unmerged future PR to pass `npm run check`**.

---

## 2. Measured File Sizes & Required Splitting Before Sub-500-Line PR Submission

Measured via `wc -l` on current verified F1+F2+F3+F4+F4.1+F4.2+F4.3+F4.3.1 source:

### 2.1 Oversized Modules (`> 500` lines each in `jan2xo/bke-worker-h`)
The following modules currently exceed 500 lines individually and therefore **either require file-splitting into `<= 450`-line modules before opening canonical PRs OR owner label `bke:oversize-ok`**:

| File (`bke-worker/...`) | Measured Lines | F4–F4.3.1 Change Scope | Recommended Sub-500-Line Split (or `bke:oversize-ok`) |
|---|---:|---|---|
| `browser-extension/src/service-worker.ts` | 530 | Baseline F1 delta (+187) | Fits PR diff budget (`<= 187` added lines on existing baseline file). |
| `browser-extension/src/controller-transport.ts` | 860 | F1/F2 | Split P-256 handshake (`controller-handshake.ts`, ~350) + router (`controller-transport.ts`, ~450). |
| `browser-extension/native-host/claim/github-f1-ledger.ts` | 1,299 | F4 added `mediatedLedgerClient` across all 4 CAS ops & `forbidDesktopWriteToken` (+187) | Split mediated/REST CAS helpers (`github-ledger-cas.ts`, ~430), authority (~430), receipt builders (~430). |
| `browser-extension/native-host/claim/desktop-controller.ts` | 975 | F1/F2 | Split `FileExecutionJournal` + POSIX lock (`file-execution-journal.ts`, ~390) from `DesktopController` (~480). |
| `browser-extension/native-host/claim/controller-daemon.ts` | 1,459 | F4/F4.1 added strict V2 isolation, `503`/`403`/`401` error mapping, `mediatedCasEnabled`, and `runCli('start')` runtime wiring (+215) | Split HTTP route handler (`daemon-http-routes.ts`, ~440), CLI/doctor (`daemon-cli.ts`, ~480), core daemon (~480). |
| `browser-extension/native-host/claim/runtime-broker-factory.ts` | 1,263 | F4.1–F4.3.1 signed authority/schema/replay/14-field ledger-PoP digest/token status validation | Split credentials loader (`device-credentials-loader.ts`, ~325), payload validators (`broker-status-validators.ts`, ~400), HTTP client + factory (~490). |
| `browser-extension/native-host/claim/github-app-harness.ts` | 821 | F4 + F4.2 strict `ACTIVE` requirement, V2 strict config guards, mandatory tri-state `deviceRevocationChecker`, exact `expectedEnrollmentGeneration` | Split V1/V2 cryptographic verifiers (`envelope-crypto.ts`, ~360) + `ExecutionRequestVerifier` (~460). |
| `browser-extension/native-host/claim/github-authority-provider.ts` | 545 | F3 | Extract pagination + permission validators (`github-authority-validators.ts`, ~180) -> core ~365 lines. |
| `browser-extension/native-host/claim/token-lifecycle.ts` | 558 | F4–F4.3 fail-closed revocation (`EXPIRED`/`UNKNOWN`), `usageExpiresAtMs`/`providerExpiresAtMs`, required `repositoryId`, `+5s` skew | Split broker transport stubs/clampers (`token-broker-transport.ts`, ~170) -> provider ~390 lines. |
| `browser-extension/native-host/claim/tests/controller-daemon.test.mjs` | 594 | F2 | Split HTTP tests (~300) and CLI/HALT tests (~295). |
| `browser-extension/native-host/claim/tests/f4-security-remediation.test.mjs` | 692 | New in F4 (P0-01/P0-02/P0-03 claim tests) | Split P0-01/P0-02 tests (~360) and P0-03/daemon tests (~335). |
| `browser-extension/native-host/claim/tests/runtime-wiring.test.mjs` | 1,063 | F4.1–F4.3 24-case signed device status + 12-case token status + daemon `503` test | Split fail-closed CLI startup (~350), error mapping (~350), and F4.2/F4.3 signed-matrix tests (~365). |
| `browser-extension/native-host/claim/tests/reliability-adversarial.test.mjs` | 986 | F1/F2 | Split Groups 1–3 (~440), Groups 4–5 (~300), Groups 6–7 (~320). |
| `browser-extension/native-host/claim/tests/e2e-two-turn-acceptance.test.mjs` | 1,111 | F1/F2 | Keep webhook 2-turn (~480), crash/drift (~180), signed V1 E2E (~450) in separate files. |
| `integrations/desktop-broker/src/broker-client.ts` | 777 | F4–F4.3.1 signed status/token/mint/14-field ledger-PoP digest & schema hardening | Extract signed-status schema validators (`broker-status-validators.ts`, ~350) -> client ~430 lines. |
| `integrations/desktop-broker/src/device-enrollment.ts` | 758 | F4–F4.3.1 strict 9-key/10-key (`ledger_op_sha256`) assertion & `inspectDeviceStatus` param checks | Extract `signAdminApproval`/`verifyAdminApproval` (`admin-approval.ts`, ~260) -> registry ~498 lines. |
| `integrations/desktop-broker/src/github-app-adapter.ts` | 1,309 | F4–F4.3.1 4-op server CAS, fail-closed repo enumeration (`total_count`), full pagination, `DELETE /installation/token`, strict `PRE_SEND_FENCE` | Extract pagination/authority readers (`github-authority-readers.ts`, ~380) and server CAS helper (`server-ledger-ops.ts`, ~460) -> adapter ~470 lines. |
| `integrations/desktop-broker/src/broker-service.ts` | 1,002 | F4–F4.3.1 `usedStatusNonces`, `issuedTokens` registry, pre-nonce 14-field `ledger_op_sha256` verification, `EXPIRED`/`UNKNOWN`, provider revocation | Extract key-ring & status signers (`broker-keystore.ts`, ~450) -> service ~550 (or split token registry). |
| `integrations/desktop-broker/tests/broker-service.test.mjs` | 775 | F4–F4.3.1 updated for `contents: read`, canonical digest PoP, & structured `PRE_SEND_FENCE` | Split broker tests (#1–14, ~450) and rotation/CAS/F3-05 tests (#15–17, ~325). |
| `integrations/desktop-broker/tests/multiprocess-e2e.test.mjs` | 729 | F4 mediated CAS & revocation HTTP assertions (+36) | Move child-process spawner helpers into shared fixture (~250) -> E2E ~480 lines. |
| `integrations/desktop-broker/tests/cli-operational-e2e.test.mjs` | 1,121 | F4.1 + F4.2 `controller:cli start` 3-process E2E + signed omit-repo `503` -> Turn 1/2 | Split F4.1 Turn 1/2 + outage (~450), quarantine/revocation (~250), and F4.2 omit-repo (~425). |
| `integrations/desktop-broker/tests/chaos-adversarial.test.mjs` | 777 | F4–F4.3.1 mediated CAS, `forbidDesktopWriteToken`, canonical PoP, & structured fence updates | Split scenarios #1–9 (~390) and #10–18 (~390). |
| `integrations/desktop-broker/tests/mediated-cas.test.mjs` | 816 | F4–F4.3.1 validly re-signed status fault matrix, replay/no-nonce, & structured fenced `MARK_DELIVERY_UNCERTAIN` | Split signed HTTP revocation matrix (~440) and 4-op CAS tests (~380). |
| `integrations/desktop-broker/tests/multihost-safety.test.mjs` | 618 | F4–F4.3.1 multi-host race/rotation/quarantine + canonical ledger PoP & structured fence | Split race/rotation (~305) and quarantine/Turn2 CAS (~315). |
| `integrations/desktop-broker/tests/f4-3-security-remediation.test.mjs` | 1,083 | F4.3 (`SEC-01`..`SEC-05` adversarial verification, updated for canonical PoP & strict fence) | Split into per-finding suites (`sec01-02`, `sec03`, `sec04-05`, each `~300..420` lines). |
| `integrations/desktop-broker/tests/f4-3-1-security-remediation.test.mjs` | 822 | New in F4.3.1 (`SEC-06` 14-field digest + strict fence, `SEC-07` 2-repo fail-closed enumeration) | Split `sec06-digest-fence.test.mjs` (~490) and `sec07-repo-enum.test.mjs` (~300). |

*(All other F3/F4/F4.3.1 files—`f3-hardening.test.mjs` [457], `command-center-observer.ts` [408], `broker-server.ts` [345], `types.ts` [357], `mock-github-server.mjs` [458], `helpers/controller-runner.mjs` [113], `device-enrollment.test.mjs` [446], `deploy/desktop-controller.env.example` [71], `scripts/package-desktop-worker.sh` [307], `docs/F4_SECURITY_REVIEW_PACKAGE.md` [116]—already sit cleanly below 500 lines.)*

---

## 3. Dependency-Ordered Canonical Promotion Wave (PR-1 through PR-15)

Every PR below must keep `FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const`, `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const`, `humanLiveSendAuthorized = false`, `executionEnvelopeEnabled = false`, `asymmetricV2Enabled = false`, `requireAsymmetricV2 = false`, `BKE_REMOTE_BROKER_ENABLED = false`, `BKE_ALLOW_REMOTE_SIGNED_HALT = false`, and `BKE_SERVER_MEDIATED_CAS_ENABLED = false` by default.

| Wave | Canonical PR Scope | Files / Split Targets | Budget Gate Strategy | Depends On | Exact-Head CI Proof |
|---|---|---|---|---|---|
| **PR-1..PR-6** | **F1 Core Stack** (Build prep, Native IPC, MV3 Transport, GitHub F1 Ledger split, `FileExecutionJournal` + `DesktopController`) | Same sub-500-line split defined in F1/F2 wave (`~325..480` lines each), with `github-ledger-cas.ts` split for F4 `mediatedLedgerClient` | All `<= 485` lines; zero frozen paths | Canonical `main` | `npm run check`, `npm run smoke:native`, `input-only-lint.mjs` |
| **PR-7** | **F2 + F3 + F4 Verifier, Authority Provider & Token Lifecycle** | **PR-7a**: `envelope-crypto.ts` (~360); **PR-7b**: `github-app-harness.ts` (~450) + `f3-hardening.test.mjs` (457, separate PR); **PR-7c**: `github-authority-validators.ts` (~180) + `github-authority-provider.ts` (~365); **PR-7d**: `token-broker-transport.ts` (~160) + `token-lifecycle.ts` (~385); **PR-7e/f**: `github-app-harness.test.mjs` & split `f4-security-remediation.test.mjs` | Every PR `<= 498` lines | PR-1, PR-6 | Verifier V2 strict, P0-01/P0-02/P0-03 claim tests, 3xx/`maintain` blocks, fail-closed revocation |
| **PR-8** | **Loopback Daemon V1+V2, `status` v3 & `doctor` v3** | **PR-8a**: `daemon-http-routes.ts` (~440); **PR-8b**: `daemon-cli.ts` (~440); **PR-8c**: `controller-daemon.ts` (~480); **PR-8d/e**: split `controller-daemon.test.mjs` | Each sub-PR `<= 480` lines | PR-6, PR-7 | Loopback `/halt`, `/status` v3, `controller:doctor`, `503`/`403` revocation/generation enforcement |
| **PR-9** | **Command Center Compatibility (14 States)** | **PR-9a**: `command-center-observer.ts` (408) + `docs/command-center-compatibility.md` (58); **PR-9b**: `command-center-compatibility.test.mjs` (189) + `docs/f3-command-center-integration.md` | Explicit `.md` filenames in linked issue | PR-7 | 14-state fail-closed observer tests |
| **PR-10** | **F2–F4 Multi-Process E2E & Adversarial Reliability** | Split `e2e-two-turn-acceptance.test.mjs` & `reliability-adversarial.test.mjs` into `<= 480`-line PRs | Each PR `<= 480` lines | PR-8, PR-9 | E2E 2-turn + Groups 1–7 adversarial |
| **PR-11** | **Deterministic Packaging, Templates, Installer & Docs** | **PR-11a**: `deploy/desktop-controller.env.example` (70), `deploy/owner-native-policy.template.json` (13), `scripts/package-desktop-worker.sh` (307), readiness/installer updates (`#<issue>` names `deploy/`); **PR-11b**: `tests/chrome_native_host_installer_contract.{py,sh}` + `docs/{desktop-operator-acceptance,android-reconciliation-audit,canonical-promotion-plan,F4_SECURITY_REVIEW_PACKAGE}.md` | PR-11a `#<issue>` MUST include `deploy/`; PR-11b lists exact `.md` filenames | PR-8 | `package-desktop-worker.sh`, `chrome_native_host_installer_contract`, `forge_f1_desktop_mvp_contract.py` |
| **PR-12** *(Sandbox Reference)* | **F3/F4 Device Enrollment Reference Package Foundation** | **PR-12a**: `integrations/desktop-broker/{package.json,package-lock.json,tsconfig.json,src/types.ts,src/broker-client.ts}` (split client or `bke:oversize-ok`); **PR-12b**: `admin-approval.ts` (~260) + `docs/f3-desktop-enrollment-contract.md`; **PR-12c**: `device-enrollment.ts` (~450) + `device-enrollment.test.mjs` (446, separate PR) | Either sub-PRs `<= 495` or `bke:oversize-ok` | PR-7 | 14 enrollment/revocation tests + exact generation enforcement |
| **PR-13** *(Sandbox Reference)* | **F3/F4 Private Trusted Broker Reference, Signed Status & Mediated CAS** | **PR-13a**: `server-ledger-ops.ts` + `github-app-adapter.ts` + `broker-server.ts`; **PR-13b**: `broker-keystore.ts` + `broker-service.ts`; **PR-13c..g**: split `mock-github-server.mjs`, `broker-service.test.mjs`, `multiprocess-e2e.test.mjs`, `chaos-adversarial.test.mjs`, `mediated-cas.test.mjs`, `multihost-safety.test.mjs` + `docs/f3-security-audit.md` + `docs/f3-existing-github-app-contract.md` | Every sub-PR `<= 485` lines; explicit `.md` filenames in issue | PR-8, PR-12 | All 7 broker test suites (mediated CAS, signed HTTP fault matrix, multi-host race, 3-process E2E, 18 chaos tests) |
| **PR-14** *(Future Owner-Only Production PR)* | **Production Broker Deployment in Frozen `cloudflare-relay/`** | **PR-14 (OUTSIDE Sandbox Scope):** Dedicated owner issue naming `cloudflare-relay/` to add `/v1/desktop/enroll/*`, `/v1/enrollment/status`, `/v1/broker/authorize`, `/v1/broker/tokens`, `/v1/broker/token-status`, `/v1/broker/ledger-op` + Wrangler secret bindings (`BKE_BROKER_EXEC_ED25519_PRIVATE_KEY`, `BKE_BROKER_HALT_ED25519_PRIVATE_KEY`). | Requires `cloudflare-relay/` in `#<issue>` | PR-13 & F4 Security Sign-off | Live Cloudflare Staging + Owner Level 7 Chrome Session |

---

## 4. Smallest Safe Authorized Next Step

1. Keep `.github/workflows/hydrogen-sandbox-ci.yml`, `HYDROGEN_BKE_WORKER_*_HANDOFF.md`, and `integrations/desktop-broker/` clearly separated from canonical `jan2xo/bke-worker` promotion PRs unless intentionally promoting `integrations/desktop-broker/` as reference tooling under **PR-12/PR-13**.
2. Begin canonical upstream promotion only when authorized by the owner by opening **Issue + PR-1** (`bke:mvp`, `<= 325` changed lines in `browser-extension/`) against `jan2xo/bke-worker`, verifying exact-head `pr-guard.yml` passes before opening **PR-2..PR-11**.
3. Do **NOT** modify `cloudflare-relay/` (**PR-14**) or enable `BKE_REMOTE_BROKER_ENABLED=true`, `BKE_SERVER_MEDIATED_CAS_ENABLED=true`, or `humanLiveSendAuthorized=true` until an owner-supervised security audit & live Level 7 Chrome session are explicitly scheduled.
