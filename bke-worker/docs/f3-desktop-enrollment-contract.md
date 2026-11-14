# F3-02 Trusted Desktop Device Enrollment & Revocation Contract

This specification defines the cryptographic enrollment, key rotation, and fail-closed revocation contract between the BKE Admin authority (`Ed25519`), Trusted Broker (`DeviceEnrollmentRegistry`), and Desktop Worker (`DeviceKeyPairSigner` / MV3 WebCrypto non-exportable P-256 identity).

---

## 1. Identity & Security Properties

- **1:1 Active Device-to-Worker Binding:** One `worker_id` maps to at most one `ACTIVE` enrolled `device_id`. Duplicate worker enrollment fails closed (`ENROLLMENT_WORKER_ALREADY_BOUND`).
- **Cryptographic Proof-of-Possession (ECDSA P-256 / ES256):** Desktop devices generate ECDSA `prime256v1` keys locally. Private key material **never leaves the device**; in MV3 Chrome extensions it is stored non-extractably (`extractable: false`) in IndexedDB.
- **No Unattended Pairing or Secret Export:** Enrollment cannot succeed without a fresh Admin-signed `APPROVE_ENROLLMENT` assertion (`Ed25519`, domain `'BKE_ADMIN_APPROVAL_V1\n'`) and a single-use server-issued challenge (`expires_at_ms`, `consumed: true`). Client-supplied privilege flags (`trusted`, `admin`, `role`, `skip_approval`, `authorized`) are unconditionally rejected (`ENROLLMENT_PRIVILEGE_ESCALATION_FORBIDDEN`).
- **Private Durable State (`0o600` + `O_NOFOLLOW`):** Registry persistence checks regular-file ownership, rejects symlinks (`ELOOP`) and insecure modes (`(mode & 0o077) !== 0`), uses exclusive `.lock` files, and writes atomically via `fsync` + `rename`.

---

## 2. Canonical Enrolled Device Record (`EnrolledDeviceRecord`)

| Field | Type | Validation / Constraint |
|---|---|---|
| `version` | `1` | Schema version constant |
| `installation_id` | `string` (`^[0-9]{1,20}$`) | Bound GitHub App installation identity |
| `worker_id` | `string` (`^[a-z0-9][a-z0-9-]{0,62}$`) | Exclusive BKE worker label suffix |
| `device_id` | `string` (`^[A-Za-z0-9_-]{8,64}$`) | Unique enrolled desktop device identity |
| `public_key_spki_pem` | `string` (EC P-256 SPKI PEM) | Verified via `createPublicKey()` (`asymmetricKeyType === 'ec'`, `namedCurve === 'prime256v1'`); hash must be globally unused |
| `public_key_sha256` | `string` (64 hex chars) | SHA-256 of SPKI DER bytes; key reuse across devices rejected (`ENROLLMENT_PUBLIC_KEY_REUSED`) |
| `browser_profile_identity` | `string` (64 hex chars) | Bound isolated Chrome profile SHA-256; cross-worker profile sharing rejected (`ENROLLMENT_BROWSER_PROFILE_REUSED`) |
| `native_bridge_identity` | `string` (64 hex chars) | Bound native messaging host / owner-policy attestation SHA-256 |
| `authorized_repository_scope` | `string[]` | Non-empty `owner/repo` list approved by Admin |
| `enrollment_generation` | `number` (`>= 1`) | Increments on key rotation (`rotateDeviceKey`); stale-generation assertions fail (`DEVICE_ASSERTION_STALE_GENERATION`) |
| `revocation_state` | `'ACTIVE' \| 'REVOKED' \| 'LOST'` | Tombstone state; revocation is terminal for `device_id` (`ENROLLMENT_DEVICE_REVOKED`) |
| `revoked_reason` | `string \| null` | Mandatory audit reason when revoked or marked lost |
| `enrolled_at`, `updated_at` | ISO-8601 UTC strings | Bounded clock timestamps |
| `enrolled_by_admin` | `string` | Authenticated `admin_actor_id` from verified Ed25519 Admin signature |

---

## 3. Ceremonies & Domain Separation

| Ceremony | Domain Separator | Required Proof |
|---|---|---|
| Admin Approval (`APPROVE_ENROLLMENT`, `ROTATE_DEVICE_KEY`, `REVOKE_DEVICE`, `DISPATCH_EXECUTION`, `ROTATE_BROKER_SIGNING_KEY`) | `'BKE_ADMIN_APPROVAL_V1\n'` | Ed25519 signature over sorted canonical payload JSON, matching `adminPublicKeysById`, TTL `<= 300s`, clock skew `<= 30s`. |
| Enrollment Completion / Rotation (`completeEnrollment`, `rotateDeviceKey`) | `'BKE_DESKTOP_ENROLLMENT_V1\n'` | ECDSA P-256 (`SHA-256`, IEEE P1363) challenge signature matching bound `challenge_id`, `nonce_b64url`, `worker_id`, `device_id`, `public_key_sha256`, `browser_profile_identity`, `native_bridge_identity`. |
| Runtime Proof-of-Possession (`verifyDeviceAssertion`) | `'BKE_DESKTOP_DEVICE_POP_V1\n'` | ECDSA P-256 signature by `ACTIVE` device at exact `enrollment_generation`, scoped to `purpose`, `installation_id`, and `authorized_repository_scope`. |

---

## 4. Required 14-Scenario Verification Matrix (`tests/device-enrollment.test.mjs`)

1. Happy path admin-approved enrollment + challenge verification + client privilege flag rejection (`trusted: true`).
2. Replayed single-use challenge rejection (`ENROLLMENT_CHALLENGE_REPLAYED`).
3. Expired enrollment challenge rejection (`ENROLLMENT_CHALLENGE_EXPIRED`).
4. Duplicate active worker enrollment rejection (`ENROLLMENT_WORKER_ALREADY_BOUND`).
5. Public key reuse across devices rejected (`ENROLLMENT_PUBLIC_KEY_REUSED`).
6. Browser profile reuse across distinct workers rejected (`ENROLLMENT_BROWSER_PROFILE_REUSED`).
7. Concurrent enrollment race (`Promise.allSettled`) produces exactly 1 winner and 1 fail-closed rejection.
8. Device key rotation increments `enrollment_generation` (`1 -> 2`) cleanly.
9. Old generation-1 key & generation-1 assertions fail immediately after rotation (`DEVICE_ASSERTION_STALE_GENERATION` / signature mismatch).
10. Revoked or marked-`LOST` device fails verification (`DEVICE_REVOKED`) & cannot complete pending challenge.
11. Unknown or forged Admin Ed25519 approval fails (`ADMIN_KEY_UNKNOWN` / `ADMIN_SIGNATURE_INVALID`).
12. Cross-repository assertion outside `authorized_repository_scope` fails (`DEVICE_ASSERTION_REPO_FORBIDDEN`).
13. Corrupt enrollment JSON & insecure file permissions (`0o644`) fail closed (`ENROLLMENT_STORE_CORRUPT`, `ENROLLMENT_STORE_PERMISSIONS_INSECURE`).
14. Restart recovery preserves active records, revocation tombstones, generation counters, and replay protection.
