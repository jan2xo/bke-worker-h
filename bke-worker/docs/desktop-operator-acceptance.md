# Desktop Operator Runbook & FORGE F1 Acceptance Guide

This runbook documents safe operation, diagnostics, packaging, and human-gated acceptance for the BKE Desktop Worker (`FORGE F1-01` through `F1-06` and F2 authorization/reliability integration).

## 1. Environment & Gate Separation

| Mode / Surface | Target Repository | Live ChatGPT Send | Authority & Requirements |
| :--- | :--- | :--- | :--- |
| **Synthetic CI / Sandbox Acceptance** | `jan2xo/bke-worker-h` (sandbox) | **Locked `false`** | Runs `--sandbox --dry-run`, loopback HTTP/IPC tests, RestGitHubAuthorityProvider HTTP fixture tests, mock token lifecycle tests, and signed-envelope multi-process E2E without real GitHub mutations or live ChatGPT sends. |
| **Canonical Source Check (`--dry-run`)** | `jan2xo/bke-worker` (`main`) | **Locked `false`** | Strict repository origin (`jan2xo/bke-worker`), clean tracked `main`, MV3 lint/build, native smoke, contract checks. |
| **Preproduction / Owner-Supervised Live Session** | Owner-configured target | **Explicit single-session CLI + env opt-in required** | Requires pre-established manual Google Chrome login, isolated Chrome profile (`~/.bke-worker/f1/chrome-profile`), owner-pinned policy JSON, explicit `nativeMessaging` popup grant, and `BKE_OWNER_SUPERVISED_LIVE_SEND=I_OWNER_AUTHORIZE_LIVE_SEND`. |
| **Level 7 Live 2-Turn Real Chrome Acceptance** | Live Chrome + ChatGPT + GitHub | **Human-only gate (`NOT_RUN` in CI)** | Never automated in CI or headless runners. Never automates Chrome login, Google/ChatGPT OAuth, MFA, or CAPTCHA. |

> **Security invariant**: `FIRST_MESSAGE_LIVE_SEND_ENABLED` and `CONVERSATION_CONTINUATION_LIVE_SEND_ENABLED` remain `false as const` in source, `DesktopControllerDaemon` initializes `humanLiveSendAuthorized: false`, and signed execution-envelope ingestion (`POST /execution-requests`) stays `executionEnvelopeEnabled: false` by default unless explicitly enabled with isolated HMAC keys.

---

## 2. Diagnostic & Build Commands

Run from `bke-worker/`:

1. **Full extension + native-host + claim + F2 integration/adversarial test suite (`strict: true`)**:
   ```bash
   npm --prefix browser-extension run check
   ```
2. **Input-only AST/regex boundary lint** (verifies zero assistant-reply DOM reads):
   ```bash
   node scripts/input-only-lint.mjs
   node --test scripts/input-only-lint.test.mjs
   ```
3. **Controller daemon diagnostics** (`doctor` validates Node >= 22, journal/policy mode `0o600`, IPC socket parent `0o700`, locked-false send defaults, non-secret authority/token-provider flags, and missing owner prerequisites):
   ```bash
   npm --prefix browser-extension run controller:doctor
   ```
4. **Sandbox certification dry-run**:
   ```bash
   bash scripts/certify-forge-f1-desktop-mvp.sh --sandbox --dry-run
   ```
5. **Deterministic non-secret desktop bundle & verification**:
   ```bash
   bash scripts/package-desktop-worker.sh package
   bash scripts/package-desktop-worker.sh verify
   ```

---

## 3. Human-Controlled Desktop Setup (F1-01 to F2-08)

1. Copy `deploy/desktop-controller.env.example` to a private file (`~/.config/bke-worker/f1-controller.env`, `chmod 600`) and populate repository, repository ID, installation identity, PR number, worker ID, pinned app ID/slug, and loopback secrets (`BKE_WEBHOOK_SECRET`, `BKE_OPERATOR_HALT_TOKEN`). Keep `BKE_EXECUTION_ENVELOPE_ENABLED=false` unless configuring isolated server-signed envelope keys (`BKE_EXECUTION_SIGNING_KEY` must never reuse `BKE_WEBHOOK_SECRET` or `BKE_OPERATOR_HALT_TOKEN`).
2. Copy `deploy/owner-native-policy.template.json` to `~/.config/bke-worker/native-host/owner-policy.json` (`chmod 600`) and fill in your owner-verified extension origin, P-256 key thumbprint SHA-256, profile/target hashes, and expiration timestamp (`<= 30 days`).
3. Create and manually sign into the isolated Chrome profile via `bash scripts/forge-f1-desktop-readiness.sh` (`CREATE_AND_LAUNCH_ISOLATED_CHROME_PROFILE`). Load the unpacked extension from `artifacts/desktop-worker-package/extension` (or `browser-extension/`).
4. Prepare the user-level Chrome Native Messaging host manifest transactionally:
   ```bash
   BKE_NATIVE_HOST_EXTENSION_ORIGIN="chrome-extension://<32-char-id>/" \
     bash scripts/prepare-chrome-native-host.sh install
   ```
5. In the Chrome extension popup, click **Connect controller bridge (opt-in)** only when an owner-approved policy is active; Chrome prompts for the optional `nativeMessaging` permission exclusively upon that explicit user click.

---

## 4. Operating, Halting & Quarantine Recovery

### Dry-Run Start vs Loopback Daemon Start
```bash
# Non-network dry-run verifying journal recovery & locked defaults:
npm --prefix browser-extension run controller:cli -- start --dry-run

# Loopback webhook daemon (127.0.0.1:31940, live send still locked FALSE):
npm --prefix browser-extension run controller:cli -- start
```

### Checking Persisted State, HTTP Diagnostics & Emergency Halt
The loopback daemon exposes secret-free diagnostics on `GET http://127.0.0.1:31940/status` (repository, worker ID, active PR, `expectedHeadSha`, `daemonRunning`, `nativeTransportReady`, `executionEnvelopeEnabled`, `trustedAuthorityConfigured`, 5-flag `tokenLifecycle` state, `quarantined`, `humanLiveSendAuthorized`, and `missingOwnerPrerequisites`). No tokens, cookies, PEMs, or secrets are returned or logged.

```bash
# Inspect journal state without secrets:
npm --prefix browser-extension run controller:cli -- status

# Halt locally & forward HALT over Unix IPC socket:
npm --prefix browser-extension run controller:cli -- halt "OWNER_OPERATOR_STOP"

# Or call loopback HTTP halt endpoint with timing-safe x-bke-halt-token header:
curl -sS -X POST http://127.0.0.1:31940/halt \
  -H "x-bke-halt-token: $BKE_OPERATOR_HALT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason":"OPERATOR_STOP"}'
```

> **Halt authentication rule**: `POST /halt` requires `x-bke-halt-token` matching `BKE_OPERATOR_HALT_TOKEN` using constant-time SHA-256 comparison and loopback binding. Requests using `Authorization: Bearer ...` or missing `x-bke-halt-token` fail closed with `HTTP 403` (`OPERATOR_HALT_UNAUTHORIZED`). Owner `POST /halt` remains operational even when ordinary execution is blocked (`DELIVERY_UNCERTAIN`).

### Handling `DELIVERY_UNCERTAIN` Quarantine
If an HTTP `POST /git/refs`, ChatGPT click submit, or mid-flight IPC socket disconnect occurs cleanly *before* confirmation, the controller and ledger:
1. Write `refs/bke/uncertain/<prNumber>/<attemptId>` (when GitHub writable) and transition the local `FileExecutionJournal` to `DELIVERY_UNCERTAIN`.
2. **Never auto-retry** the ambiguous submit (eliminating duplicate engineering prompts).
3. Block all subsequent webhook or signed-envelope dispatch requests (`HTTP 409`) until the human owner inspects the ChatGPT browser session, resolves or closes the attempt in GitHub, and clears/rotates the local journal cleanly.

---

## 5. Safe Clean Uninstall

To remove packaged artifacts without disturbing your Chrome profile, cookies, local storage, or Git workspace:
```bash
bash scripts/package-desktop-worker.sh clean-uninstall
```
And to cleanly roll back only byte-identical files created by `prepare-chrome-native-host.sh`:
```bash
bash scripts/prepare-chrome-native-host.sh rollback
```
