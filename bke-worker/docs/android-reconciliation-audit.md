# Android / GeckoView vs Desktop Chrome Reconciliation Audit

## Scope & Preserved Quarantine Boundaries
- This audit documents the architectural alignment and intentional divergence between:
  1. **Desktop Chrome F1 Surface**: `bke-worker/browser-extension/` (Chrome MV3 extension + Node native-messaging host + local loopback `DesktopControllerDaemon` + direct GitHub F1 CAS ledger).
  2. **Android / GeckoView Relay Surface**: `bke-worker/android-gecko/` + `bke-worker/cloudflare-relay/` (Kotlin GeckoView foreground host + built-in MV2 WebExtension + Android Keystore + Cloudflare Worker Durable Object relay).
- **Quarantined Surfaces Preserved Untouched**:
  - `android-gecko/` and `cloudflare-relay/` were **not modified** by the Desktop FORGE F1 completion wave.
  - Historical quarantine issues `#90` (Android runtime cutover quarantine) and `#135` remain quarantined and unmerged.
  - Existing regression checks (`npm --prefix cloudflare-relay run check`, `reconnect-recovery-test`, `tests/android_gecko_probe_contract.py`, `tests/android_recovery_operator_contract.py`, `tests/cloudflare_relay_contract.py`) continue to run cleanly.

---

## 1. Shared Concepts & Security Invariants

Both platforms enforce identical BKE autonomous-engineering trust invariants:

| Concept | Desktop Chrome F1 (`browser-extension/`) | Android GeckoView (`android-gecko/` + `cloudflare-relay/`) |
| :--- | :--- | :--- |
| **Input-Only DOM Discipline** | Checked at AST/regex lint time across `browser-extension/src/` by `scripts/input-only-lint.mjs`: zero `innerText`, `textContent`, `innerHTML`, `outerHTML`, or assistant-reply DOM selectors. | Checked across `android-gecko/app/src/main/assets/worker-extension/` by `scripts/input-only-lint.mjs` + `tests/android_gecko_probe_contract.py`: only composer write, send click, and BUSY/READY/AUTH boolean state. |
| **Metadata-Only Wake** | Controller/webhook receives PR number, head SHA, worker ID, and verified `bke-ticket:v1` check run; arbitrary remote prompt injection over HTTP/IPC is rejected by schema validators (`validateExecutionEnvelopeShape`, `validBridgeCommand`). | `RelayProtocol.kt` parses strict bounded `wake` JSON (`worker_id`, `repo`, `pr_number`, `expected_head_sha`, `reason`, `delivery_id`) and constructs `CONTINUE FROM PR` locally on Android. |
| **Send-Once & Delivery Deduplication** | Persisted in `chrome.storage.local` (`service-worker.ts`), `FileExecutionJournal` (`desktop-controller.ts`), and immutable GitHub CAS refs (`refs/bke/claims/...`). | Bounded `delivery_id` deduplication set + single active dispatch gate inside `AndroidGeckoWorkerService.kt`. |
| **Uncertain Send Quarantine** | Ambiguous click/POST/mid-flight IPC transitions immediately to `DELIVERY_UNCERTAIN` (`refs/bke/uncertain/...`), blocking all subsequent wakes with zero auto-retry. | Ambiguous native-port disconnect sets `activeWakeUncertain` -> `STATE_BLOCKED_UNCERTAIN`, halting further auto-dispatches without retry. |
| **1:1 PR Worker Exclusivity** | Enforced live against open PRs labeled `bke-worker:<worker_id>` (`github-f1-ledger.ts`, `github-app-harness.ts`). | Enforced by relay routing + PR assignment metadata check before accepting engineering action. |
| **Human-Controlled Login Boundary** | Chrome profile isolation (`forge-f1-desktop-readiness.sh`) with manual user ChatGPT sign-in; zero cookie/OAuth/CAPTCHA automation. | Interactive GeckoView session signed in manually by the user on the Android device. |

---

## 2. Intentionally Desktop-Specific Modules

The following mechanisms exist only in Desktop Chrome F1 due to desktop OS & Chrome MV3 platform boundaries:

1. **Chrome MV3 Extension & Optional `nativeMessaging` (`manifest.json`, `popup.ts`, `service-worker.ts`)**:
   - Requests only `storage`, `webNavigation`, and `https://chatgpt.com/*` at install time; `nativeMessaging` is an `optional_permission` unlocked only by explicit popup user gesture paired with owner policy verification.
2. **Non-Exportable WebCrypto P-256 Identity (`device-identity.ts`)**:
   - Generates hardware/IndexedDB-backed P-256 signing keys inside the extension origin to sign local `host.mjs` challenge proofs.
3. **OS Native Messaging Host & Unix Socket IPC (`entry.mjs`, `controller-host.mjs`, `ipc-client.ts`)**:
   - Bridges the headless Node daemon (`DesktopControllerDaemon`) to Chrome's stdio native-messaging lifetime using `0o700`-directory private Unix sockets with single in-flight locks and client quarantine on mid-flight disconnects.
4. **FileExecutionJournal (`desktop-controller.ts`)**:
   - Local crash-recovery WAL enforcing regular file, `O_NOFOLLOW`, UID ownership, and `0o600` strict permissions (`JOURNAL_PERMISSIONS_INSECURE` on `0o644`).
5. **Direct GitHub F1 CAS Ledger (`github-f1-ledger.ts`) & User-Level Native Host Installer (`prepare-chrome-native-host.sh`)**:
   - Desktop executes CAS Git ref fences/claims/conversation receipts directly via GitHub REST and registers `bke.worker.desktop` transactionally in Chrome's OS `NativeMessagingHosts` directory.

---

## 3. Intentionally Android-Specific Modules

The following mechanisms belong exclusively to Android/GeckoView and are **not** duplicated on Desktop:

1. **GeckoView Foreground Host (`AndroidGeckoWorkerService.kt`)**:
   - Hosts an embedded headless-capable `GeckoRuntime`/`GeckoSession` directly inside the Android app process rather than driving external Google Chrome via native messaging.
2. **MV2 Built-in Extension (`worker-probe.js`)**:
   - Uses `browser.runtime.connectNative("bke.worker.gecko")` bound directly to GeckoView's in-process `WebExtension.Port` (MV2 built-in asset vs Chrome MV3 external unpacked extension).
3. **Android Keystore Encryption (`RelayConfigStore.kt`)**:
   - Protects runtime pairing tokens via Android Keystore AES-GCM rather than OS filesystem `0o600` policy files.
4. **Outbound WSS Durable Object Relay Client (`RelayWebSocketClient.kt` + `cloudflare-relay/`)**:
   - Because mobile devices sit behind carrier NAT without stable loopback webhooks, Android initiates an outbound `wss://` connection to Cloudflare Durable Objects, whereas Desktop runs an inbound loopback webhook HTTP listener (`127.0.0.1:31940`).
5. **Android Recovery & `.recoverycert` Verification Hooks**:
   - `certify-android-chat-target-recovery.sh` and `run-android-recovery-certification.sh` address GeckoView lifecycle/background recovery and remain scoped solely to Android.

---

## 4. Compatibility Matrix Conclusion

- Command Center visibility (`command-center-observer.ts`) projects Desktop state conservatively (`UNKNOWN` / `BLOCKED` on partial/uncertain evidence) using the same semantic states (`OFFLINE`, `IDLE`, `BUSY`, `AUTH_REQUIRED`, `BLOCKED`, `HALTED`) without coupling Desktop or Android runtime transport code.
- Both surfaces share `scripts/input-only-lint.mjs` as a single enforced source-level guardrail while keeping platform-specific transport/storage cleanly decoupled.
