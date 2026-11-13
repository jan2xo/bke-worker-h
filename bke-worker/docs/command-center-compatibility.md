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

1. Missing GitHub assignment evidence -> `assignmentState = UNKNOWN`, `dispatchReady = false`.
2. Non-atomic enumeration snapshot (`atomicRevalidated = false`) -> `NON_ATOMIC_STALE_SNAPSHOT`, `dispatchReady = false`.
3. Valid local device pairing without active session -> `PAIRED_IDLE_ONLY`, `dispatchReady = false`.
4. Paired device / valid token without authenticated ChatGPT tab -> `AUTH_REQUIRED` or `UNKNOWN`, `dispatchReady = false`.
5. Any `DELIVERY_UNCERTAIN` journal phase or `refs/bke/uncertain/*` ref -> `DELIVERY_UNCERTAIN_BLOCKED`, `dispatchReady = false`.
6. Conflicting PR labels or 2 open PRs for 1 worker -> `CONFLICT_BLOCKED`, `dispatchReady = false`.
7. Source CI & synthetic 2-turn tests passing -> `realBrowserAcceptance = NOT_RUN`.
8. Stale evidence (`nowMs - observedAtMs > maxStaleMs`) -> `UNKNOWN`, `dispatchReady = false`.
