# BKE Command Center Compatibility & Read-Only Observer Boundary

Status: **Workstream D Compatibility Contract (Command Center repo not modified)**  
Reference Command Center inspected at read-only `jan2xo/bke-command-center` (`main = f120c6f`).

## Principle

- **GitHub remains the durable authority** for worker-to-PR assignment (`bke-worker:<id>`), exact PR head SHAs, `bke-ticket` check runs, and send-once/conversation CAS refs (`refs/bke/*`).
- **Command Center is a read-only observer** and owner operator console; it NEVER executes ChatGPT automation, holds ChatGPT credentials, or overrides BKE Worker's fail-closed gates.
- Any missing, partial, stale, or uncertain Worker evidence **must project to `UNKNOWN` or `BLOCKED`**, never `READY` or `PASS`.

## 9-Concept Observer Compatibility Matrix

| # | Concept | Worker Source of Truth | Command Center Consumer | Status Today |
|---|---|---|---|---|
| 1 | Installed repositories | GitHub App installation lookup (`cloudflare-relay/src/github-app.js`) | `admin_installation_repository_catalog` -> CC `/api/admin/repositories` | `CONSUMED_BY_COMMAND_CENTER_TODAY` |
| 2 | Worker-to-PR assignment | GitHub live PRs + exclusive `bke-worker:<id>` label (revalidated per wake) | `admin_worker_assignment_inventory` (`consistency: NON_ATOMIC_ENUMERATION`) | `CONSUMED_BY_COMMAND_CENTER_TODAY` |
| 3 | Exact PR head SHA | Live PR `head.sha` + pinned `bke-ticket` check-run `external_id` | CC `admin-worker-assignments.js` snapshot | `CONSUMED_BY_COMMAND_CENTER_TODAY` |
| 4 | Device pairing vs active session | Non-exportable P-256 key + local policy vs active `CONTROLLER_BRIDGE_V1` | `command-center-observer.ts` (`PAIRED_IDLE_ONLY` vs `BRIDGE_ESTABLISHED`) | `PROPOSED_OBSERVER_ADAPTER` |
| 5 | ChatGPT auth / tab readiness | Content-script snapshot + `webNavigation` binding (`AUTH_REQUIRED` vs `READY`) | `projectWorkerStateForCommandCenter` -> `UNKNOWN`/`AUTH_REQUIRED` | `PROPOSED_OBSERVER_ADAPTER` |
| 6 | Send-once claim / uncertainty quarantine | `refs/bke/claims/*` + `refs/bke/uncertain/*` + `FileExecutionJournal` | `DELIVERY_UNCERTAIN_BLOCKED` projection + operator quarantine alert | `PROPOSED_OBSERVER_ADAPTER` |
| 7 | Turn 1 / Turn 2+ conversation progress | `refs/bke/conversations/{pr}` + `refs/bke/turns/{pr}/{attempt}` | Read-only `conversationId` & `confirmedTurnCount` | `PROPOSED_OBSERVER_ADAPTER` |
| 8 | Operator alerts / halt / remediation | Controller `GET /status`, `HALTED` journal phase, PR comments | CC `dashboard.js` / `failure-visibility.js` + halt status | `PROPOSED_OBSERVER_ADAPTER` |
| 9 | Certification vs live acceptance | Source/smoke/synthetic reports vs `BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN` | Strictly distinguishes synthetic `PASS` from `NOT_RUN` live browser acceptance | `PROPOSED_OBSERVER_ADAPTER` |

## Fail-Closed Invariants Verified by Fixture Suite

1. Missing GitHub assignment evidence -> `assignmentState = UNKNOWN`, `dispatchReady = false`, `evidenceIncomplete = true`.
2. Non-atomic enumeration snapshot (`atomicRevalidated = false`) -> `NON_ATOMIC_STALE_SNAPSHOT`, `dispatchReady = false`.
3. Valid local device pairing without active session -> `PAIRED_IDLE_ONLY`, `workerLiveness = IDLE_PAIRED` (`WORKER_LIVENESS_UNKNOWN`), `dispatchReady = false`.
4. Paired device or valid short-lived GitHub token without authenticated ChatGPT tab -> `AUTH_REQUIRED` or `UNKNOWN`, `dispatchReady = false`.
5. Any `DELIVERY_UNCERTAIN` journal phase or `refs/bke/uncertain/*` ref -> `DELIVERY_UNCERTAIN_BLOCKED`, `DELIVERY_UNCERTAIN` visible state, `dispatchReady = false`.
6. Conflicting PR labels or 2 open PRs for 1 worker -> `CONFLICT_BLOCKED`, `PR_OWNERSHIP_CONFLICT` visible state, `dispatchReady = false`.
7. Source CI & synthetic 2-turn tests passing -> `realBrowserAcceptance = NOT_RUN`.
8. Stale evidence (`nowMs - observedAtMs > maxStaleMs`) -> `UNKNOWN`, `EVIDENCE_INCOMPLETE`, `dispatchReady = false`.

---

## F2 14-State Observer Visibility (`F2_REQUIRED_VISIBLE_STATES`)

| # | Visible State Tag | Derived Source of Truth | Fail-Closed Behavior |
|---|---|---|---|
| 1 | `WORKER_IDENTITY_VERIFIED` | Matched owner native policy (`P-256` thumbprint) | Only set when local policy verified |
| 2 | `WORKER_IDENTITY_UNKNOWN` | Missing or unverified native policy | Default when pairing evidence absent or stale |
| 3 | `PR_ASSIGNMENT_VALID` | Exclusive open PR with single `bke-worker:<id>` label | Never inferred from stale snapshot alone |
| 4 | `PR_OWNERSHIP_CONFLICT` | Multiple PRs, missing/multiple worker labels, or uncertain ref | Forces `CONFLICT_BLOCKED` + `dispatchReady = false` |
| 5 | `CURRENT_EXACT_SHA` | Live PR `head.sha === expectedHeadSha` | Blocks dispatch if mismatch occurs |
| 6 | `STALE_SHA` | Live PR `head.sha !== expectedHeadSha` | Forces `CONFLICT_BLOCKED` + `EXECUTION_BLOCKED` |
| 7 | `CLAIM_RESERVED` | Durable journal `RESERVED`/`FENCED` or explicit reservation evidence | Signals active send-once claim lock |
| 8 | `EXECUTION_BLOCKED` | Any guard failure (`dispatchReady = false` before confirmation) | Visible whenever gate denies dispatch |
| 9 | `DELIVERY_UNCERTAIN` | Journal `DELIVERY_UNCERTAIN` or `refs/bke/uncertain/*` present | Latches quarantine until owner remediation |
| 10 | `FIRST_CONVERSATION_CONFIRMED` | Journal `CONFIRMED_CONVERSATION` with `confirmedTurnCount >= 1` | Derived from confirmed Turn 1 receipt |
| 11 | `CONTINUATION_CONFIRMED` | Journal `CONFIRMED_CONVERSATION` with `confirmedTurnCount >= 2` | Derived from same-conversation Turn 2+ receipt |
| 12 | `EXACT_HEAD_CI_PENDING_OR_FAILED` | Exact-head check runs `PENDING` or `FAILED` | Forces `dispatchReady = false` & `EXECUTION_BLOCKED` |
| 13 | `EVIDENCE_INCOMPLETE` | Any missing/stale GitHub, journal, pairing, or browser snapshot | Forces `UNKNOWN` / blocked projection |
| 14 | `WORKER_LIVENESS_UNKNOWN` | Missing heartbeat, stale observation, or `PAIRED_IDLE_ONLY` state | Paired device NEVER upgrades to running worker |

> **Future Command Center API note (not yet implemented in `jan2xo/bke-command-center`)**: When Command Center later adds F2 Worker Observer UI tiles, it should read `CommandCenterWorkerProjection` (schemaVersion `1`) strictly read-only from GitHub + attested worker status exports without adding any browser credential state or dispatch endpoints inside Command Center.
