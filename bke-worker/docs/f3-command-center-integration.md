# F3-08 BKE Command Center Read-Only Integration & Compatibility Analysis

This document verifies **read-only** compatibility between BKE Worker F3 integrated evidence and `jan2xo/bke-command-center`, ensuring complete fail-closed observability across all 14 `F2_REQUIRED_VISIBLE_STATES` without modifying `jan2xo/bke-command-center`.

---

## 1. Compatibility Against F3 Integrated Multi-Process Evidence

In `tests/multiprocess-e2e.test.mjs` and `tests/chaos-adversarial.test.mjs`, live outputs produced by:
- `TrustedDesktopBroker` + `SandboxGitHubAppAdapter` (GitHub authority, repository scope, PR exclusivity, exact head SHA, CI check-runs),
- `DesktopControllerDaemon` `GET /status` (schema v3: `deviceIdentity`, `broker`, `installationScope`, `workerAssignment`, `tokenLifecycle`, `journalPhase`, `conversationId`, `confirmedTurnCount`, `humanLiveSendAuthorized`), and
- `ExtensionBrowserAdapter` + `controller-host.mjs` (browser UI state, writable tab count, native pairing policy & active session)

were projected through `projectWorkerStateForCommandCenter()` (`native-host/claim/command-center-observer.ts`).

All **14 required visible states** (`WORKER_IDENTITY_VERIFIED`, `WORKER_IDENTITY_UNKNOWN`, `PR_ASSIGNMENT_VALID`, `PR_OWNERSHIP_CONFLICT`, `CURRENT_EXACT_SHA`, `STALE_SHA`, `CLAIM_RESERVED`, `EXECUTION_BLOCKED`, `DELIVERY_UNCERTAIN`, `FIRST_CONVERSATION_CONFIRMED`, `CONTINUATION_CONFIRMED`, `EXACT_HEAD_CI_PENDING_OR_FAILED`, `EVIDENCE_INCOMPLETE`, `WORKER_LIVENESS_UNKNOWN`) plus fail-closed `realBrowserAcceptance: 'NOT_RUN'` and `executionState: 'UNKNOWN'` on partial evidence passed without exception.

---

## 2. Explicit Assessment: Are Any `jan2xo/bke-command-center` Changes Required?

### Today (Source-Level Integration / Phase F3): **NO immediate Command Center edit is required or allowed**
- Command Center continues to consume the existing `CommandCenterReadBroker` WorkerEntrypoint RPCs in `cloudflare-relay`:
  1. `mintReadOnlyGitHubToken` -> source discovery
  2. `listApprovedGitHubRepositories` -> `/api/admin/repositories`
  3. `listVerifiedWorkerAssignments` -> `admin-worker-assignments.js` (`consistency: 'NON_ATOMIC_ENUMERATION'`)
- Zero modifications were made to `jan2xo/bke-command-center` or `cloudflare-relay/`.

### Future Preproduction Phase (Owner-Scheduled Read-Only Observer Adapter in `bke-command-center`): **YES — Optional Proposed Adapter**
To surface desktop pairing state (`PAIRED_IDLE_ONLY` vs `BRIDGE_ESTABLISHED`), V2 broker device identity (`device_id`, `enrollment_generation`), token lifecycle recovery status, `DELIVERY_UNCERTAIN` quarantine alerts, and Turn 1 / Turn 2 `refs/bke/*` progress inside the Command Center operator UI, the **proposed future external task** in `jan2xo/bke-command-center` is specified below:

| Item | Proposed External Task Specification (Read-Only) |
|---|---|
| **Source file in `jan2xo/bke-command-center`** | `src/worker-observer/bke-worker-projection.js` (paired with `/api/admin/worker-observer.js` route handler) |
| **Input schema** | `RawWorkerObserverEvidence` + GitHub durable refs (`refs/bke/fences/*`, `refs/bke/claims/*`, `refs/bke/conversations/*`, `refs/bke/turns/*`, `refs/bke/uncertain/*`) + optional signed/authenticated broker telemetry (`device_id`, `enrollment_generation`, `broker.protocolVersion`, `tokenLifecycle`) |
| **Output schema** | `CommandCenterWorkerProjection` (`schemaVersion: 1` from `command-center-observer.ts`) enforcing `dispatchReady: false` unless atomic GitHub revalidation + `BRIDGE_ESTABLISHED` + `READY` browser target + valid token + passing CI |
| **Trust boundary** | Read-only projection ONLY. Never mints tokens directly, never stores ChatGPT cookies or App PEMs, and treats `admin-worker-assignments.js` inventory as `NON_ATOMIC_STALE_SNAPSHOT` until refreshed |
| **Authoritative GitHub evidence** | Fresh GitHub REST read via `CommandCenterReadBroker` (`pull`, `check-runs`, `git/matching-refs/bke/`) |
| **Auth requirement** | Cloudflare Access / Command Center Admin authenticated session (`POST`/`GET` `/api/admin/*`) |
| **Required negative tests** | (1) Unauthenticated request -> `401/403`; (2) Missing/stale browser evidence (`nowMs - observedAtMs > maxStaleMs`) -> `EVIDENCE_INCOMPLETE`, `dispatchReady: false`; (3) Paired-idle worker -> `WORKER_LIVENESS_UNKNOWN`; (4) `refs/bke/uncertain/*` present -> `DELIVERY_UNCERTAIN_BLOCKED`; (5) `NON_ATOMIC_STALE_SNAPSHOT` -> `dispatchReady: false`; (6) `realBrowserAcceptance` stays `NOT_RUN` unless explicitly owner-attested |
