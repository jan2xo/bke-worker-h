# Canonical Promotion Plan (`jan2xo/bke-worker-h` -> `jan2xo/bke-worker`)

This document reconciles the completed **F1 + F2 + F3** BKE Desktop Worker implementation in `jan2xo/bke-worker-h` against the canonical governance gates enforced by `jan2xo/bke-worker/.github/workflows/pr-guard.yml` (Issue `#149`).

> **Governance Reminder:** Do **NOT** open, merge, or reuse any oversized omnibus PR against `jan2xo/bke-worker` during sandbox engineering. Each canonical promotion PR requires an open `bke:mvp`-labeled GitHub issue referenced via `MVP-Task: #<issue>` in the PR body.

---

## 1. Exact `pr-guard.yml` Rules Reconciled Against Measured F1+F2+F3 Source

Inspecting canonical `bke-worker/.github/workflows/pr-guard.yml` (lines 250–376) establishes five hard gates:

1. **500-Line Total PR Budget (ALL Files Included — Code + Tests + Docs):**
   - `pr-guard.yml:341-345` computes `files.reduce((n, f) => n + f.additions + f.deletions, 0)` across **every file in the PR**, *including test and documentation files*, unless the owner explicitly adds label `bke:oversize-ok`.
   - Therefore, splitting tests into separate PRs only helps if each PR's combined `(code + test + doc)` diff stays `<= 500` lines, OR an oversize module/test is decomposed into helper modules before canonical PR creation, OR the owner explicitly pre-authorizes `bke:oversize-ok`.
2. **Frozen Surface Allowlist Rule (`deploy/` & `cloudflare-relay/` Are Frozen):**
   - `pr-guard.yml:348-356` blocks any change touching:
     `cloudflare-relay/`, `android-gecko/`, `src/`, **`deploy/`**, `BKE.Worker.sln`, `Directory.Build.props`
     unless the linked `MVP-Task: #<issue>` body/title literally contains the matching path prefix.
   - `cloudflare-relay/`, `android-gecko/`, `src/`, `BKE.Worker.sln`, and `Directory.Build.props` remain **100% untouched** across F1+F2+F3.
   - Only `deploy/desktop-controller.env.example` (67 lines, including F3 default-OFF V2/broker fields) and `deploy/owner-native-policy.template.json` (13 lines) touch `deploy/`, so that specific PR's `#<issue>` must explicitly name `deploy/`.
3. **CI / Workflow Protection Rule:**
   - Any file under `.github/` requires owner label `bke:gate-change` (`pr-guard.yml:360-362`).
   - `.github/workflows/hydrogen-sandbox-ci.yml` lives at the sandbox root (`jan2xo/bke-worker-h`) and is **excluded** from canonical `jan2xo/bke-worker` promotion; `bke-worker/.github/workflows/pr-guard.yml` itself is untouched.
4. **Added Markdown Filename Rule:**
   - Every newly added `.md` file causes `mvp-scope-gate` failure unless its **exact repo-relative filename** appears in the linked `#<issue>` body/title (`pr-guard.yml:365-369`).
   - Any canonical PR adding F2/F3 markdown docs MUST list each exact filename in its issue:
     `docs/command-center-compatibility.md`, `docs/desktop-operator-acceptance.md`, `docs/android-reconciliation-audit.md`, `docs/canonical-promotion-plan.md`, `docs/f3-security-audit.md`, `docs/f3-existing-github-app-contract.md`, `docs/f3-desktop-enrollment-contract.md`, `docs/f3-command-center-integration.md`.
5. **Exact-Head WebExtension Identity Contract:**
   - Any PR touching `browser-extension/`, `scripts/prepare-chrome-native-host.sh`, or `tests/chrome_native_host_installer_contract.py` triggers `pr-guard.yml` lines 251–297 on the exact PR head SHA: clean `npm install --ignore-scripts --no-audit --no-fund --package-lock=false`, `npm run check`, `npm run smoke:native`, `bash -n scripts/smoke-desktop-native-integration.sh`, and `git diff --check`.
   - Consequently, **no canonical PR may depend on an unmerged future PR to pass `npm run check`**.

---

## 2. Measured File Sizes & Required Splitting Before Sub-500-Line PR Submission

Measured via `wc -l` on current verified F1+F2+F3 source:

### 2.1 Oversized F1 + F2 + F3 Modules (`> 500` lines each in `jan2xo/bke-worker-h`)
The following modules currently exceed 500 lines individually and therefore **either require file-splitting into `<= 450`-line modules before opening canonical PRs OR owner label `bke:oversize-ok`**:

| File (`bke-worker/...`) | Measured Lines | F3 Change Scope | Recommended Sub-500-Line Split (or `bke:oversize-ok`) |
|---|---:|---|---|
| `browser-extension/src/service-worker.ts` | 530 | Baseline F1 delta (+187) | Already fits PR diff budget (`<= 187` added lines on existing baseline file). |
| `browser-extension/src/controller-transport.ts` | 860 | F1/F2 | Split P-256 handshake (`controller-handshake.ts`, ~350) + router (`controller-transport.ts`, ~450). |
| `browser-extension/native-host/claim/github-f1-ledger.ts` | 1,112 | F3 added `redirect: 'manual'` & `baseApiUrl` (+6 lines) | Split REST ref/commit CAS helpers (`github-ledger-cas.ts`, ~420), authority (~400), receipt builders (~290). |
| `browser-extension/native-host/claim/desktop-controller.ts` | 975 | F1/F2 | Split `FileExecutionJournal` + POSIX lock (`file-execution-journal.ts`, ~390) from `DesktopController` (~480). |
| `browser-extension/native-host/claim/controller-daemon.ts` | 1,244 | F3 added V2/HALT config, `status` v3, `doctor` v3 (+153) | Split HTTP route handler (`daemon-http-routes.ts`, ~400), CLI/doctor (`daemon-cli.ts`, ~400), core daemon (~440). |
| `browser-extension/native-host/claim/github-app-harness.ts` | 744 | F3 added Ed25519 V2 verification, downgrade & revocation checks (+273) | Split V1/V2 cryptographic verifiers (`envelope-crypto.ts`, ~330) + `ExecutionRequestVerifier` (~410). |
| `browser-extension/native-host/claim/github-authority-provider.ts` | 545 | F3 added `redirect: 'manual'`, `maintain` & empty perm blocks (+6) | Extract pagination + permission validators (`github-authority-validators.ts`, ~180) -> core ~365 lines. |
| `browser-extension/native-host/claim/token-lifecycle.ts` | 511 | F3 added bounded transient retry + `lastRecoveryClassification` (+34) | Split broker transport stubs/clampers (`token-broker-transport.ts`, ~150) -> provider ~360 lines. |
| `browser-extension/native-host/claim/tests/controller-daemon.test.mjs` | 594 | F2 | Split HTTP tests (~300) and CLI/HALT tests (~295). |
| `browser-extension/native-host/claim/tests/reliability-adversarial.test.mjs` | 986 | F1/F2 | Split Groups 1–3 (~440), Groups 4–5 (~300), Groups 6–7 (~320). |
| `browser-extension/native-host/claim/tests/e2e-two-turn-acceptance.test.mjs` | 1,111 | F1/F2 | Keep webhook 2-turn (~480), crash/drift (~180), signed V1 E2E (~450) in separate files. |
| `integrations/desktop-broker/src/device-enrollment.ts` | 691 | New in F3 | Extract `signAdminApproval`/`verifyAdminApproval` (`admin-approval.ts`, ~260) -> registry ~430 lines. |
| `integrations/desktop-broker/src/github-app-adapter.ts` | 570 | New in F3 | Extract server CAS helper (`server-ledger-ops.ts`, ~150) -> adapter ~420 lines. |
| `integrations/desktop-broker/src/broker-service.ts` | 683 | New in F3 | Extract key-ring & durable audit store (`broker-keystore.ts`, ~240) -> service ~440 lines. |
| `integrations/desktop-broker/tests/broker-service.test.mjs` | 724 | New in F3 | Split broker tests (#1–14, ~450) and rotation/CAS/F3-05 tests (#15–17, ~275). |
| `integrations/desktop-broker/tests/multiprocess-e2e.test.mjs` | 693 | New in F3 | Move child-process spawner helpers into shared fixture (~230) -> E2E ~465 lines. |
| `integrations/desktop-broker/tests/chaos-adversarial.test.mjs` | 734 | New in F3 | Split scenarios #1–9 (~380) and #10–18 (~355). |

*(All other F3 files—`f3-hardening.test.mjs` [429], `command-center-observer.ts` [408], `broker-client.ts` [224], `broker-server.ts` [306], `types.ts` [184], `mock-github-server.mjs` [295], `device-enrollment.test.mjs` [446], `deploy/desktop-controller.env.example` [67], `scripts/package-desktop-worker.sh` [305], `docs/*.md`—already sit cleanly below 500 lines.)*

---

## 3. Dependency-Ordered Canonical Promotion Wave (PR-1 through PR-14)

Every PR below must keep `FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const`, `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const`, `humanLiveSendAuthorized = false`, `executionEnvelopeEnabled = false`, `asymmetricV2Enabled = false`, `requireAsymmetricV2 = false`, and `BKE_REMOTE_BROKER_ENABLED = false` by default.

| Wave | Canonical PR Scope | Files / Split Targets | Budget Gate Strategy | Depends On | Exact-Head CI Proof |
|---|---|---|---|---|---|
| **PR-1..PR-6** | **F1 Core Stack** (Build prep, Native IPC, MV3 Transport, GitHub F1 Ledger, `FileExecutionJournal` + `DesktopController`) | Same sub-500-line split defined in F1/F2 wave (`~325..480` lines each) | All `<= 485` lines; zero frozen paths | Canonical `main` | `npm run check`, `npm run smoke:native`, `input-only-lint.mjs` |
| **PR-7** | **F2 + F3 Verifier, Authority Provider & Token Lifecycle** | **PR-7a**: `envelope-crypto.ts` (~330); **PR-7b**: `github-app-harness.ts` (~410) + `f3-hardening.test.mjs` (or separate test PR); **PR-7c**: `github-authority-validators.ts` (~180) + `github-authority-provider.ts` (~365); **PR-7d**: `token-broker-transport.ts` (~150) + `token-lifecycle.ts` (~360); **PR-7e**: `github-app-harness.test.mjs` (498) | Split `envelope-crypto.ts`, validators & broker transport keeps every PR `<= 498` lines | PR-1, PR-6 | Verifier V1+V2, downgrade/HALT separation, 3xx redirect block, bounded retry tests |
| **PR-8** | **Loopback Daemon V1+V2, `status` v3 & `doctor` v3** | **PR-8a**: `daemon-http-routes.ts` (~400); **PR-8b**: `daemon-cli.ts` (~400); **PR-8c**: `controller-daemon.ts` (~440); **PR-8d/e**: split `controller-daemon.test.mjs` + `f3-hardening.test.mjs` | Each sub-PR `<= 450` lines | PR-6, PR-7 | Loopback `/halt`, `/status` v3, `controller:doctor`, HALT pubkey separation |
| **PR-9** | **Command Center Compatibility (14 States)** | **PR-9a**: `command-center-observer.ts` (408) + `docs/command-center-compatibility.md` (58); **PR-9b**: `command-center-compatibility.test.mjs` (189) + `docs/f3-command-center-integration.md` | Explicit `.md` filenames in linked issue | PR-7 | 14-state fail-closed observer tests |
| **PR-10** | **F2 + F3 Multi-Process E2E & Adversarial Reliability** | Split `e2e-two-turn-acceptance.test.mjs` & `reliability-adversarial.test.mjs` into `<= 480`-line PRs | Each PR `<= 480` lines | PR-8, PR-9 | E2E 2-turn + Groups 1–7 adversarial |
| **PR-11** | **Deterministic Packaging, Templates, Installer & Docs** | **PR-11a**: `deploy/desktop-controller.env.example` (67), `deploy/owner-native-policy.template.json` (13), `scripts/package-desktop-worker.sh` (305), readiness/installer scripts (`~410` lines; `#<issue>` names `deploy/`); **PR-11b**: `tests/chrome_native_host_installer_contract.{py,sh}` + `docs/{desktop-operator-acceptance,android-reconciliation-audit,canonical-promotion-plan}.md` | PR-11a `#<issue>` MUST include `deploy/`; PR-11b lists exact `.md` filenames | PR-8 | `package-desktop-worker.sh`, `chrome_native_host_installer_contract`, `forge_f1_desktop_mvp_contract.py` |
| **PR-12** *(Sandbox Reference)* | **F3 Device Enrollment Reference Package Foundation** | **PR-12a**: `integrations/desktop-broker/{package.json,tsconfig.json,src/types.ts,src/broker-client.ts}` (~440); **PR-12b**: `admin-approval.ts` (~260) + `docs/f3-desktop-enrollment-contract.md`; **PR-12c**: `device-enrollment.ts` (~430) + `device-enrollment.test.mjs` (Split / `bke:oversize-ok` or PR-12d test) | Either sub-PRs `<= 450` or `bke:oversize-ok` | PR-7 | 14 enrollment/revocation tests |
| **PR-13** *(Sandbox Reference)* | **F3 Private Trusted Broker Reference & Chaos Suites** | **PR-13a**: `server-ledger-ops.ts` + `github-app-adapter.ts` + `broker-server.ts`; **PR-13b**: `broker-keystore.ts` + `broker-service.ts`; **PR-13c/d/e**: split `mock-github-server.mjs`, `broker-service.test.mjs`, `multiprocess-e2e.test.mjs`, `chaos-adversarial.test.mjs` + `docs/f3-security-audit.md` + `docs/f3-existing-github-app-contract.md` | Every sub-PR `<= 480` lines; explicit `.md` filenames in issue | PR-8, PR-12 | 17 broker tests, 3-process E2E, 18 chaos tests, server-mediated CAS tests |
| **PR-14** *(Future Owner-Only Production PR)* | **Production Broker Deployment in Frozen `cloudflare-relay/`** | **PR-14 (OUTSIDE Sandbox Scope):** Dedicated owner issue naming `cloudflare-relay/` to add `/v1/desktop/enroll/*`, `/v1/desktop/authorize`, `/v1/desktop/tokens` + Wrangler secret bindings (`BKE_BROKER_EXEC_ED25519_PRIVATE_KEY`, `BKE_BROKER_HALT_ED25519_PRIVATE_KEY`). | Requires `cloudflare-relay/` in `#<issue>` | PR-13 & Owner Security Audit | Live Cloudflare Staging + Owner Level 7 Chrome Session |

---

## 4. Smallest Safe Authorized Next Step

1. Keep `.github/workflows/hydrogen-sandbox-ci.yml`, `HYDROGEN_BKE_WORKER_*_HANDOFF.md`, and `integrations/desktop-broker/` ephemeral test harnesses clearly separated from canonical `jan2xo/bke-worker` promotion PRs unless intentionally promoting `integrations/desktop-broker/` as reference tooling under **PR-12/PR-13**.
2. Begin canonical upstream promotion only when authorized by the owner by opening **Issue + PR-1** (`bke:mvp`, `<= 325` changed lines in `browser-extension/`) against `jan2xo/bke-worker`, verifying exact-head `pr-guard.yml` passes before opening **PR-2..PR-11**.
3. Do **NOT** modify `cloudflare-relay/` (**PR-14**) or enable `BKE_REMOTE_BROKER_ENABLED=true` / `humanLiveSendAuthorized=true` until an owner-supervised security audit & live Level 7 Chrome session are explicitly scheduled.
