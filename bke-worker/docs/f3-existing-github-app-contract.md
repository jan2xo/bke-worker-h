# F3-01 Existing GitHub App Broker & Command Center Contract Reconciliation

This document reconciles the **frozen production GitHub App broker** inside `bke-worker/cloudflare-relay/` against Command Center expectations and the F3 sandbox reference broker in `bke-worker/integrations/desktop-broker/`.

> **Frozen Path Notice:** Per F3 governance rules, zero bytes were altered in `bke-worker/cloudflare-relay/`, `jan2xo/bke-worker`, or `jan2xo/bke-command-center`.

---

## 1. Ten-Point Reconciliation Against Existing Implementation

1. **Where the GitHub App Private Key Is Stored and Read Today:**
   - Read from Cloudflare Worker secret environment `env.BKE_WORKER_GITHUB_APP_PRIVATE_KEY_PEM` paired with `env.BKE_WORKER_GITHUB_APP_ID` inside `cloudflare-relay/src/github-app.js:238-244` (`requiredAppConfiguration`).
   - Supports PKCS#8 (`-----BEGIN PRIVATE KEY-----`) and PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`, wrapped cleanly via `pkcs1ToPkcs8()`), imported non-extractably into WebCrypto (`extractable: false`) in `importAppPrivateKey()` (`github-app.js:85-109`).
   - **Never** transmitted to workers, Actions callers in raw form, or desktop devices.

2. **How Installation Lookups Are Scoped Today:**
   - `resolveInstallation(appJwt)` (`github-app.js:272-292`) calls `GET https://api.github.com/repos/jan2xo/bke-worker/installation`, binds to the server-resolved numeric `payload.id`, validates `permissions` (`validateInstallationPermissions`), and never accepts a client-supplied `installation_id`.
   - For multi-repo discovery (`listAdminInstalledRepositories()`, `github-app.js:414-534`), mints an installation token explicitly restricted to `{ permissions: { metadata: "read" } }` across ALL repositories already approved in the App installation, enforcing `redirect: "manual"`, strict regex path validation (`REPO_NAME`), no duplicate IDs, and deterministic pagination completeness.

3. **How Installation Access Tokens Are Minted Today (Three Separate Paths):**
   - **Path A (Serial Dispatcher Actions OIDC):** `POST /github/app/install-token` (`index.js:179-195, 308-313`) authenticates GitHub Actions OIDC JWT (`RS256` against GitHub JWKS, strict `CONTROL_REPOSITORY = "jan2xo/bke-worker"`, `CONTROL_REPOSITORY_ID = "1354026486"`, `SERIAL_WORKFLOW_REF`, `aud = "bke-worker-github-app-broker"`) and returns `mintInstallationToken()` scoped to `repository_ids: [1354026486]` with `REQUIRED_TOKEN_PERMISSIONS = { contents: "write", issues: "write", pull_requests: "write" }`.
   - **Path B (Private Cloudflare Service-Binding RPC `CommandCenterReadBroker`):** Named `WorkerEntrypoint` (`index.js:342-352`, `admin-broker.js:9-138`)—**NOT** an HTTP route—exposing 3 gated RPCs behind `env.BKE_ADMIN_BROKER_ENABLED === "true"`:
     - `mintReadOnlyGitHubToken(request)` (`purpose: "admin_source_discovery"`, `repository: "jan2xo/bke-worker"` -> `{ contents: "read", issues: "read", pull_requests: "read" }`).
     - `listApprovedGitHubRepositories(request)` (`env.BKE_ADMIN_REPO_CATALOG_ENABLED === "true"`, `purpose: "admin_installation_repository_catalog"` -> `metadata: "read"` catalog).
     - `listVerifiedWorkerAssignments(request)` (`env.BKE_ADMIN_PR_INVENTORY_ENABLED === "true"`, `purpose: "admin_worker_assignment_inventory"` -> read-only open PR + single `bke-worker:<id>` label inventory with `consistency: "NON_ATOMIC_ENUMERATION"`).
   - **Path C (Webhook Checkpoints & Worker Wake Recovery inside Relay):** `postRelayCheckpoint` and `recoverAssignedPullRequests` mint `REQUIRED_TOKEN_PERMISSIONS` inside `cloudflare-relay` when handling webhooks or `/relay/:workerId/recover`.

4. **Whether Any Desktop Device Enrollment or Proof-of-Possession Already Exists:**
   - **Partial on desktop; ZERO on Cloudflare Broker today.**
   - Desktop extension & native host already implement local P-256 non-exportable WebCrypto pairing (`device-identity.ts`, `controller-transport.ts`, `owner-native-policy.template.json`), binding `worker_id` + public-key SHA-256 + profile SHA-256 + native bridge policy.
   - `cloudflare-relay/` currently has **no** desktop device registry, **no** admin-signed device enrollment store, **no** `/v1/broker/authorize` endpoint, and **no** desktop token minting RPC/route (relay uses HMAC/bearer `BKE_WORKER_RELAY_TOKEN_KEY` for WebSocket wake transport only).

5. **How Execution Request Signing Would Relate to `cloudflare-relay`:**
   - `cloudflare-relay` currently dispatches unsigned GitHub webhook-derived `wake` payloads over authenticated WebSockets (`handleGitHubWebhook` -> `WorkerSession.dispatch`).
   - F2 added `ExecutionRequestVerifier` (HMAC-SHA256 V1 default-OFF) in `controller-daemon`; F3 adds **V2 Ed25519 asymmetric signing** (`SignedExecutionRequestV2`) in `integrations/desktop-broker/` and `ExecutionRequestVerifier` so a future trusted broker (either `cloudflare-relay` Worker or private control-plane service) can sign `ExecutionRequestEnvelopeV2` using role-separated Ed25519 keys without ever deploying shared HMAC secrets or App PEMs to desktops.

6. **Whether Multi-Repository Support Already Exists or Is Single-Repo Hardcoded:**
   - **Mixed (catalog/assignments multi-repo; token minting & webhooks single-repo hardcoded):**
     - `admin-catalog` (`github-app.js:483`) and `admin-assignment-inventory.js` enumerate **all** repositories installed on the GitHub App (`total_visible_repositories <= 100`).
     - However, `CONTROL_REPOSITORY = "jan2xo/bke-worker"` and `CONTROL_REPOSITORY_ID = "1354026486"` are **hardcoded constants** in `github-app.js:1-2` and `index.js` for `mintInstallationToken()`, `mintAdminReadToken()`, webhook signature routing (`handleGitHubWebhook`), and `recoverAssignedPullRequests()`.
     - F3's `SandboxGitHubAppAdapter` preserves strict least-privilege *single-repo* token minting (`repository_ids: [expectedRepositoryId]`) while generalizing installation lookup (`/repos/:owner/:repo/installation`) and cross-repo worker PR exclusivity sweeps across all installed repos.

7. **How `jan2xo/bke-command-center` Consumes Broker Capabilities Today:**
   - Consumes the 3 `CommandCenterReadBroker` WorkerEntrypoint RPCs over a private Cloudflare same-account service binding (no public HTTP route for admin discovery tokens):
     1. Read-only source discovery token (`admin_source_discovery`) for `jan2xo/bke-worker`.
     2. Approved repository catalog (`admin_installation_repository_catalog`) backing `/api/admin/repositories`.
     3. Read-only worker assignment inventory (`admin_worker_assignment_inventory`) backing `admin-worker-assignments.js`.
   - Also holds a `G0-06` dormant `WorkerSession.inspectRetirementCandidate` DO RPC candidate (`index.js:359-366`), currently fail-closed with no Wrangler flag provisioned.

8. **What Secrets and Bindings Exist vs Must NEVER Touch the Desktop:**
   - **Strictly Server-Side (Broker/Relay Only):** `BKE_WORKER_GITHUB_APP_ID`, `BKE_WORKER_GITHUB_APP_PRIVATE_KEY_PEM`, `BKE_WORKER_GITHUB_WEBHOOK_SECRET`, `BKE_WORKER_RELAY_TOKEN_KEY`, broker Ed25519 signing keys (`EXECUTION` & `HALT`), admin Ed25519 approval trust root.
   - **Desktop-Side Only:** Device non-extractable ECDSA P-256 keypair (private key never leaves device), `owner-policy.json`, loopback `BKE_OPERATOR_HALT_TOKEN`, and broker **public** Ed25519 verification PEMs + short-lived (`<= 180s`) single-repo installation tokens (`contents: write` only if server-mediated CAS is not yet deployed, or zero GitHub tokens when using server-mediated CAS).

9. **Safe Reconciliation Between Production `cloudflare-relay` and Local Desktop Broker Mode:**
   - Both components are kept **cleanly decoupled** via `TokenBrokerClient` (`token-lifecycle.ts`) and `ExecutionRequestVerifier` (`github-app-harness.ts`).
   - Today: `Deploy` defaults stay `BKE_EXECUTION_ENVELOPE_ENABLED=false`, `BKE_EXECUTION_V2_ASYMMETRIC_ENABLED=false`, `BKE_REMOTE_BROKER_ENABLED=false`, preserving F1 webhook/local operation untouched.
   - Sandbox F3 reference (`integrations/desktop-broker/`) mirrors `cloudflare-relay`'s exact fail-closed discipline (`redirect: 'manual'`, opaque `ghs_` validation, pagination completeness checks, explicit permission clamping, non-secret error codes) without modifying `cloudflare-relay/`.

10. **Minimal Owner Action Required Before Enabling Real Token Broker in Production:**
    - Owner opens a dedicated, frozen-path-authorized issue & PR explicitly naming `cloudflare-relay/` in `jan2xo/bke-worker` to:
      1. Add desktop enrollment state storage (DO/KV) + `/v1/desktop/enroll/*` admin-signed approval endpoints.
      2. Generalize `mintDesktopExecutionToken` (parameterized by verified `repository` & `repository_id` inside the installation, clamped strictly to `{ contents: 'write', pull_requests: 'read', checks: 'read' }` or `{ metadata: 'read' }` if paired with `ledger-ops`).
      3. Provision Ed25519 `EXECUTION` and `HALT` signing keys in Cloudflare Secrets and bind `BKE_BROKER_PUBLIC_KEY_PEM` / `BKE_REMOTE_HALT_PUBLIC_KEY_PEM` in operator desktop configs.

---

## 2. Exact Implemented vs Proposed Interface Inventory

| Interface / Surface | Current Status | Location | Callers / Consumers | Scope / Auth |
|---|---|---|---|---|
| `POST /webhooks/github` | **IMPLEMENTED (Frozen `cloudflare-relay`)** | `cloudflare-relay/src/index.js:301` | GitHub Webhooks | HMAC `X-Hub-Signature-256`; hardcoded `CONTROL_REPOSITORY` |
| `POST /github/app/install-token` | **IMPLEMENTED (Frozen `cloudflare-relay`)** | `cloudflare-relay/src/index.js:308` | Serial Dispatcher GH Actions | GitHub Actions OIDC (`RS256` JWKS + claims) |
| `CommandCenterReadBroker.mintReadOnlyGitHubToken` | **IMPLEMENTED (Frozen `cloudflare-relay` RPC)** | `cloudflare-relay/src/admin-broker.js:9` | `bke-command-center` service binding | Feature flag `BKE_ADMIN_BROKER_ENABLED` |
| `CommandCenterReadBroker.listApprovedGitHubRepositories` | **IMPLEMENTED (Frozen `cloudflare-relay` RPC)** | `cloudflare-relay/src/admin-broker.js:31` | `bke-command-center` service binding | Flags `ADMIN_BROKER` + `ADMIN_REPO_CATALOG` |
| `CommandCenterReadBroker.listVerifiedWorkerAssignments` | **IMPLEMENTED (Frozen `cloudflare-relay` RPC)** | `cloudflare-relay/src/admin-broker.js:62` | `bke-command-center` service binding | Flags `ADMIN_BROKER` + `ADMIN_PR_INVENTORY` |
| `WorkerSession.inspectRetirementCandidate` | **DORMANT CANDIDATE (Frozen `cloudflare-relay` RPC)** | `cloudflare-relay/src/index.js:359` | Unprovisioned (`G0-06`) | Fail-closed until owner Wrangler audit |
| `SandboxBrokerHttpServer` (`/v1/enrollment/*`, `/v1/broker/*`) | **SANDBOX REFERENCE (F3 `integrations/desktop-broker`)** | `integrations/desktop-broker/src/broker-server.ts` | F3 E2E / Broker tests ONLY | Loopback-only, synthetic keys, **never deployed** |
| `ExecutionRequestVerifier` V2 (`Ed25519`, `BKE_EXECUTION_REQUEST_V2`) | **IMPLEMENTED (F3 Desktop, Default-OFF)** | `native-host/claim/github-app-harness.ts` | `DesktopControllerDaemon` (`POST /execution-requests`) | Public keys only; device + audience + issuer checks |
| Production Desktop Broker (`cloudflare-relay` `/v1/desktop/*`) | **PROPOSED (Requires Future Owner PR)** | Not yet in `cloudflare-relay/` | Desktop controllers & CC Admin | Needs explicit frozen-path issue (`cloudflare-relay/`) |
