# Canonical Promotion Plan (`jan2xo/bke-worker-h` -> `jan2xo/bke-worker`)

This plan sequences the completed BKE Desktop Worker changes from the Hydrogen sandbox (`jan2xo/bke-worker-h`) into reviewable, policy-compliant Pull Requests for optional owner promotion into canonical `jan2xo/bke-worker`.

## Canonical Guardrails Respected (`pr-guard.yml` & Issue `#149`)
1. **Strict Line Budget**: Each PR keeps non-test additions under the canonical 500-line diff threshold (or splits tests cleanly across PRs so `bke:oversize-ok` is avoided unless explicitly applied by the owner).
2. **Frozen Surface Integrity**: `bke-worker/.github/workflows/`, `src/` (.NET legacy controller), `android-gecko/`, and `cloudflare-relay/` remain untouched (requiring zero `bke:gate-change` overrides).
3. **Sandbox-Only Artifacts Stay Excluded**: `.github/workflows/hydrogen-sandbox-ci.yml` at the sandbox root and `--sandbox` flags may remain sandbox-only or require explicit owner decision in `jan2xo/bke-worker`.
4. **Live Send Gates Locked `false`**: `FIRST_MESSAGE_LIVE_SEND_ENABLED = false as const` and `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED = false as const` are preserved in every PR.

---

## Dependency-Ordered PR Wave

| Wave | Proposed Canonical PR Scope | Files Included | Depends On | Primary Verification |
| :--- | :--- | :--- | :--- | :--- |
| **PR-1** | **F1 Build Isolation & Fail-Closed Journal Hardening** | `browser-extension/package.json`, `browser-extension/tsconfig.json`, `browser-extension/native-host/claim/tsconfig.json`, `browser-extension/native-host/claim/desktop-controller.ts` | Canonical `main` | Clean isolated `npm ci/install`, `tsc -p tsconfig.json`, `tsc -p native-host/claim/tsconfig.json`, existing 39+32 tests |
| **PR-2** | **Hardened IPC Client, Durable MV3 Claim Set & Opt-In Popup Bridge** | `browser-extension/native-host/claim/ipc-client.ts`, `browser-extension/src/service-worker.ts`, `browser-extension/popup.html`, `browser-extension/src/popup.ts` | PR-1 | `scripts/input-only-lint.mjs`, `npm run smoke:native`, socket permission & in-flight quarantine unit checks |
| **PR-3** | **Loopback Desktop Controller Daemon & Multi-Process E2E Harness** | `browser-extension/native-host/claim/controller-daemon.ts`, `browser-extension/native-host/claim/tests/controller-daemon.test.mjs` | PR-2 | Multi-process HTTP webhook -> daemon -> IPC -> `entry.mjs --controller-bridge` -> synthetic Turn 1 & Turn 2 test |
| **PR-4** | **GitHub App Authority Harness & 21-Case Adversarial Matrix** | `browser-extension/native-host/claim/github-app-harness.ts`, `browser-extension/native-host/claim/tests/github-app-harness.test.mjs` | PR-1 | `ExecutionRequestVerifier` determinism, replay, TTL, role separation, and 21-case failure matrix |
| **PR-5** | **Command Center Fail-Closed Observer Compatibility Adapter** | `browser-extension/native-host/claim/command-center-observer.ts`, `docs/command-center-compatibility.md`, `browser-extension/native-host/claim/tests/command-center-compatibility.test.mjs` | PR-1 | 9-row `COMMAND_CENTER_COMPATIBILITY_MATRIX` + 8 fail-closed observer tests |
| **PR-6** | **Crash-Recovery, Network, IPC & Browser Chaos Test Suite** | `browser-extension/native-host/claim/tests/reliability-adversarial.test.mjs` | PR-3 | Reliability Groups 1–5 (journal permissions/corruption, multi-phase crash recovery, mid-flight socket kill, GitHub 422/503/pagination, ChatGPT busy/multi-tab/stalled click) |
| **PR-7** | **Deterministic Packaging, Non-Secret Templates & Operator/Audit Docs** | `deploy/desktop-controller.env.example`, `deploy/owner-native-policy.template.json`, `scripts/package-desktop-worker.sh`, `docs/desktop-operator-acceptance.md`, `docs/android-reconciliation-audit.md`, `docs/canonical-promotion-plan.md` | PR-3 | `package-desktop-worker.sh package/verify/clean-uninstall` + `forge_f1_desktop_mvp_contract.py` |

---

## Post-Promotion Owner Acceptance Gate (Level 7)
Even after PR-1..PR-7 are reviewed and merged into `jan2xo/bke-worker`, **Level 7** (`BKE_REAL_CHROME_ACCEPTANCE`) remains `NOT_RUN` until a human owner executes `scripts/forge-f1-desktop-readiness.sh` and supervises a two-turn live acceptance run inside an isolated Chrome profile signed into ChatGPT under owner credentials.
