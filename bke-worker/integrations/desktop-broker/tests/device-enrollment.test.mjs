/**
 * F3-02 Trusted Desktop Device Enrollment & Revocation Security Test Suite (14 Required Scenarios).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  DeviceEnrollmentRegistry,
  signAdminApproval,
} from '../dist/device-enrollment.js';
import { DeviceKeyPairSigner } from '../dist/broker-client.js';

const INSTALL_ID = '987654321';
const REPO = 'jan2xo/bke-worker';
const WORKER_1 = 'worker-f1';
const DEVICE_1 = 'desktop-dev-f3-001';
const PROFILE_HASH_1 = '1'.repeat(64);
const PROFILE_HASH_2 = '2'.repeat(64);
const NATIVE_HASH_1 = '3'.repeat(64);
const BASE_NOW = Date.parse('2026-10-20T12:00:00.000Z');

function genEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

function adminApprove(adminKeys, keyId, action, overrides = {}) {
  return signAdminApproval(
    {
      version: 1,
      action,
      admin_actor_id: 'owner-admin-01',
      installation_id: INSTALL_ID,
      worker_id: WORKER_1,
      device_id: DEVICE_1,
      authorized_repository_scope: [REPO],
      nonce: `admin-nonce-${Math.random().toString(16).slice(2)}`,
      issued_at: new Date(BASE_NOW - 1_000).toISOString(),
      expires_at: new Date(BASE_NOW + 60_000).toISOString(),
      ...overrides,
    },
    adminKeys.privatePem,
    keyId,
  );
}

test('F3-02: Complete 14-scenario enrollment security, replay, concurrency, rotation, and revocation matrix', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f3-enroll-'));
  let now = BASE_NOW;
  const adminKeys = genEd25519();
  const storePath = join(dir, 'enrollment.json');
  const registry = new DeviceEnrollmentRegistry({
    storePath,
    adminPublicKeysById: new Map([['admin-k1', adminKeys.publicPem]]),
    nowMs: () => now,
  });

  const signer1 = new DeviceKeyPairSigner();

  try {
    // 1. Happy path Admin-approved pairing & P-256 verification
    const ch1 = await registry.issueChallenge({
      installation_id: INSTALL_ID,
      worker_id: WORKER_1,
      device_id: DEVICE_1,
      authorized_repository_scope: [REPO],
      admin_approval: adminApprove(adminKeys, 'admin-k1', 'APPROVE_ENROLLMENT'),
    });
    const rec1 = await registry.completeEnrollment({
      challenge_id: ch1.challenge_id,
      installation_id: INSTALL_ID,
      worker_id: WORKER_1,
      device_id: DEVICE_1,
      public_key_spki_pem: signer1.publicKeySpkiPem,
      browser_profile_identity: PROFILE_HASH_1,
      native_bridge_identity: NATIVE_HASH_1,
      challenge_signature_b64url: signer1.signEnrollmentChallenge({
        challenge: ch1,
        browser_profile_identity: PROFILE_HASH_1,
        native_bridge_identity: NATIVE_HASH_1,
      }),
    });
    assert.equal(rec1.enrollment_generation, 1);
    assert.equal(rec1.revocation_state, 'ACTIVE');

    // Client-supplied privilege flags must ALWAYS be rejected
    await assert.rejects(
      () =>
        registry.issueChallenge({
          installation_id: INSTALL_ID,
          worker_id: 'worker-evil',
          device_id: 'desktop-evil-1',
          authorized_repository_scope: [REPO],
          admin_approval: adminApprove(adminKeys, 'admin-k1', 'APPROVE_ENROLLMENT', {
            worker_id: 'worker-evil',
            device_id: 'desktop-evil-1',
          }),
          trusted: true,
        }),
      /ENROLLMENT_PRIVILEGE_ESCALATION_FORBIDDEN/,
    );

    // 2. Replayed challenge fails closed
    await assert.rejects(
      () =>
        registry.completeEnrollment({
          challenge_id: ch1.challenge_id,
          installation_id: INSTALL_ID,
          worker_id: WORKER_1,
          device_id: DEVICE_1,
          public_key_spki_pem: new DeviceKeyPairSigner().publicKeySpkiPem,
          browser_profile_identity: PROFILE_HASH_1,
          native_bridge_identity: NATIVE_HASH_1,
          challenge_signature_b64url: 'x',
        }),
      /ENROLLMENT_CHALLENGE_REPLAYED/,
    );

    // Prepare a second challenge for negative mismatch checks
    const chNeg = await registry.issueChallenge({
      installation_id: INSTALL_ID,
      worker_id: WORKER_1,
      device_id: DEVICE_1,
      authorized_repository_scope: [REPO],
      admin_approval: adminApprove(adminKeys, 'admin-k1', 'APPROVE_ENROLLMENT'),
    });
    const signerTmp = new DeviceKeyPairSigner();

    // 3. Wrong device
    await assert.rejects(
      () =>
        registry.completeEnrollment({
          challenge_id: chNeg.challenge_id,
          installation_id: INSTALL_ID,
          worker_id: WORKER_1,
          device_id: 'wrong-device-999',
          public_key_spki_pem: signerTmp.publicKeySpkiPem,
          browser_profile_identity: PROFILE_HASH_1,
          native_bridge_identity: NATIVE_HASH_1,
          challenge_signature_b64url: 'x',
        }),
      /ENROLLMENT_WRONG_DEVICE/,
    );

    // 4. Wrong worker
    await assert.rejects(
      () =>
        registry.completeEnrollment({
          challenge_id: chNeg.challenge_id,
          installation_id: INSTALL_ID,
          worker_id: 'wrong-worker',
          device_id: DEVICE_1,
          public_key_spki_pem: signerTmp.publicKeySpkiPem,
          browser_profile_identity: PROFILE_HASH_1,
          native_bridge_identity: NATIVE_HASH_1,
          challenge_signature_b64url: 'x',
        }),
      /ENROLLMENT_WRONG_WORKER/,
    );

    // 5. Wrong installation
    await assert.rejects(
      () =>
        registry.completeEnrollment({
          challenge_id: chNeg.challenge_id,
          installation_id: '111111',
          worker_id: WORKER_1,
          device_id: DEVICE_1,
          public_key_spki_pem: signerTmp.publicKeySpkiPem,
          browser_profile_identity: PROFILE_HASH_1,
          native_bridge_identity: NATIVE_HASH_1,
          challenge_signature_b64url: 'x',
        }),
      /ENROLLMENT_WRONG_INSTALLATION/,
    );

    // 6. Duplicate worker identity (different device for already active WORKER_1)
    await assert.rejects(
      () =>
        registry.issueChallenge({
          installation_id: INSTALL_ID,
          worker_id: WORKER_1,
          device_id: 'desktop-dev-duplicate',
          authorized_repository_scope: [REPO],
          admin_approval: adminApprove(adminKeys, 'admin-k1', 'APPROVE_ENROLLMENT', {
            device_id: 'desktop-dev-duplicate',
          }),
        }),
      /ENROLLMENT_DUPLICATE_WORKER_ACTIVE/,
    );

    // 7. Reused public key (signer1 key reused for another worker/device)
    const chW2 = await registry.issueChallenge({
      installation_id: INSTALL_ID,
      worker_id: 'worker-f2',
      device_id: 'desktop-dev-f3-002',
      authorized_repository_scope: [REPO],
      admin_approval: adminApprove(adminKeys, 'admin-k1', 'APPROVE_ENROLLMENT', {
        worker_id: 'worker-f2',
        device_id: 'desktop-dev-f3-002',
      }),
    });
    await assert.rejects(
      () =>
        registry.completeEnrollment({
          challenge_id: chW2.challenge_id,
          installation_id: INSTALL_ID,
          worker_id: 'worker-f2',
          device_id: 'desktop-dev-f3-002',
          public_key_spki_pem: signer1.publicKeySpkiPem,
          browser_profile_identity: PROFILE_HASH_2,
          native_bridge_identity: NATIVE_HASH_1,
          challenge_signature_b64url: signer1.signEnrollmentChallenge({
            challenge: chW2,
            browser_profile_identity: PROFILE_HASH_2,
            native_bridge_identity: NATIVE_HASH_1,
          }),
        }),
      /ENROLLMENT_PUBLIC_KEY_REUSED/,
    );

    // 8. Reused browser profile (worker-f2 tries to reuse PROFILE_HASH_1 owned by DEVICE_1)
    const signer2 = new DeviceKeyPairSigner();
    await assert.rejects(
      () =>
        registry.completeEnrollment({
          challenge_id: chW2.challenge_id,
          installation_id: INSTALL_ID,
          worker_id: 'worker-f2',
          device_id: 'desktop-dev-f3-002',
          public_key_spki_pem: signer2.publicKeySpkiPem,
          browser_profile_identity: PROFILE_HASH_1,
          native_bridge_identity: NATIVE_HASH_1,
          challenge_signature_b64url: signer2.signEnrollmentChallenge({
            challenge: chW2,
            browser_profile_identity: PROFILE_HASH_1,
            native_bridge_identity: NATIVE_HASH_1,
          }),
        }),
      /ENROLLMENT_BROWSER_PROFILE_REUSED/,
    );

    // 9. Concurrent pairing race against same challenge: exactly one succeeds
    const concurrentResults = await Promise.allSettled([
      registry.completeEnrollment({
        challenge_id: chW2.challenge_id,
        installation_id: INSTALL_ID,
        worker_id: 'worker-f2',
        device_id: 'desktop-dev-f3-002',
        public_key_spki_pem: signer2.publicKeySpkiPem,
        browser_profile_identity: PROFILE_HASH_2,
        native_bridge_identity: NATIVE_HASH_1,
        challenge_signature_b64url: signer2.signEnrollmentChallenge({
          challenge: chW2,
          browser_profile_identity: PROFILE_HASH_2,
          native_bridge_identity: NATIVE_HASH_1,
        }),
      }),
      registry.completeEnrollment({
        challenge_id: chW2.challenge_id,
        installation_id: INSTALL_ID,
        worker_id: 'worker-f2',
        device_id: 'desktop-dev-f3-002',
        public_key_spki_pem: new DeviceKeyPairSigner().publicKeySpkiPem,
        browser_profile_identity: '5'.repeat(64),
        native_bridge_identity: NATIVE_HASH_1,
        challenge_signature_b64url: 'x',
      }),
    ]);
    assert.equal(concurrentResults.filter((r) => r.status === 'fulfilled').length, 1);
    assert.equal(concurrentResults.filter((r) => r.status === 'rejected').length, 1);

    // 10. Expired enrollment challenge rejected
    const chExp = await registry.issueChallenge({
      installation_id: INSTALL_ID,
      worker_id: 'worker-f3',
      device_id: 'desktop-dev-f3-003',
      authorized_repository_scope: [REPO],
      admin_approval: adminApprove(adminKeys, 'admin-k1', 'APPROVE_ENROLLMENT', {
        worker_id: 'worker-f3',
        device_id: 'desktop-dev-f3-003',
      }),
    });
    now += 130_000;
    const signer3 = new DeviceKeyPairSigner();
    await assert.rejects(
      () =>
        registry.completeEnrollment({
          challenge_id: chExp.challenge_id,
          installation_id: INSTALL_ID,
          worker_id: 'worker-f3',
          device_id: 'desktop-dev-f3-003',
          public_key_spki_pem: signer3.publicKeySpkiPem,
          browser_profile_identity: '6'.repeat(64),
          native_bridge_identity: NATIVE_HASH_1,
          challenge_signature_b64url: signer3.signEnrollmentChallenge({
            challenge: chExp,
            browser_profile_identity: '6'.repeat(64),
            native_bridge_identity: NATIVE_HASH_1,
          }),
        }),
      /ENROLLMENT_CHALLENGE_EXPIRED/,
    );
    now = BASE_NOW;

    // 11. Missing or stale Admin authorization fails closed
    await assert.rejects(
      () =>
        registry.issueChallenge({
          installation_id: INSTALL_ID,
          worker_id: 'worker-f4',
          device_id: 'desktop-dev-f3-004',
          authorized_repository_scope: [REPO],
          admin_approval: null,
        }),
      /ENROLLMENT_ADMIN_AUTHORIZATION_MISSING/,
    );
    await assert.rejects(
      () =>
        registry.issueChallenge({
          installation_id: INSTALL_ID,
          worker_id: 'worker-f4',
          device_id: 'desktop-dev-f3-004',
          authorized_repository_scope: [REPO],
          admin_approval: adminApprove(adminKeys, 'admin-k1', 'APPROVE_ENROLLMENT', {
            worker_id: 'worker-f4',
            device_id: 'desktop-dev-f3-004',
            issued_at: new Date(BASE_NOW - 120_000).toISOString(),
            expires_at: new Date(BASE_NOW - 1_000).toISOString(),
          }),
        }),
      /ENROLLMENT_ADMIN_AUTHORIZATION_STALE/,
    );

    // 12. Device key rotation increments enrollment_generation and rejects old key assertions
    const signer1Rotated = new DeviceKeyPairSigner();
    const rotNonce = 'rot-nonce-001';
    const rotRec = await registry.rotateDeviceKey({
      device_id: DEVICE_1,
      worker_id: WORKER_1,
      installation_id: INSTALL_ID,
      new_public_key_spki_pem: signer1Rotated.publicKeySpkiPem,
      nonce: rotNonce,
      admin_approval: adminApprove(adminKeys, 'admin-k1', 'ROTATE_DEVICE_KEY'),
      new_key_proof_signature_b64url: signer1Rotated.signKeyRotationProof({
        device_id: DEVICE_1,
        worker_id: WORKER_1,
        installation_id: INSTALL_ID,
        new_generation: 2,
        nonce: rotNonce,
      }),
    });
    assert.equal(rotRec.enrollment_generation, 2);

    // Old signer1 assertion fails as stale generation (or signature invalid)
    await assert.rejects(
      () =>
        registry.verifyDeviceAssertion(
          signer1.signDeviceAssertion({
            worker_id: WORKER_1,
            device_id: DEVICE_1,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: now,
          }),
          'AUTHORIZE_EXECUTION',
          REPO,
        ),
      /DEVICE_ENROLLMENT_GENERATION_STALE/,
    );
    // Rotated key succeeds
    const verifiedRot = await registry.verifyDeviceAssertion(
      signer1Rotated.signDeviceAssertion({
        worker_id: WORKER_1,
        device_id: DEVICE_1,
        installation_id: INSTALL_ID,
        enrollment_generation: 2,
        purpose: 'AUTHORIZE_EXECUTION',
        repository: REPO,
        nowMs: now,
      }),
      'AUTHORIZE_EXECUTION',
      REPO,
    );
    assert.equal(verifiedRot.enrollment_generation, 2);

    // 13. Lost device & Revoked identity permanently block assertions & re-enrollment
    const revoked = await registry.revokeDevice({
      device_id: DEVICE_1,
      worker_id: WORKER_1,
      installation_id: INSTALL_ID,
      state: 'LOST',
      reason: 'LAPTOP_REPORTED_LOST',
      admin_approval: adminApprove(adminKeys, 'admin-k1', 'REVOKE_DEVICE'),
    });
    assert.equal(revoked.revocation_state, 'LOST');
    await assert.rejects(
      () =>
        registry.verifyDeviceAssertion(
          signer1Rotated.signDeviceAssertion({
            worker_id: WORKER_1,
            device_id: DEVICE_1,
            installation_id: INSTALL_ID,
            enrollment_generation: 2,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: now,
          }),
          'AUTHORIZE_EXECUTION',
          REPO,
        ),
      /DEVICE_REVOKED/,
    );
    await assert.rejects(
      () =>
        registry.issueChallenge({
          installation_id: INSTALL_ID,
          worker_id: WORKER_1,
          device_id: DEVICE_1,
          authorized_repository_scope: [REPO],
          admin_approval: adminApprove(adminKeys, 'admin-k1', 'APPROVE_ENROLLMENT'),
        }),
      /ENROLLMENT_DEVICE_REVOKED/,
    );

    // 14. Corrupted device state & insecure permissions fail closed
    await chmod(storePath, 0o644);
    await assert.rejects(() => registry.inspectDeviceStatus({ workerId: WORKER_1 }), /ENROLLMENT_PERMISSIONS_INSECURE/);
    await chmod(storePath, 0o600);
    const saved = await readFile(storePath, 'utf8');
    await writeFile(storePath, '{corrupted-json', { mode: 0o600 });
    await assert.rejects(() => registry.inspectDeviceStatus({ workerId: WORKER_1 }), /ENROLLMENT_STATE_CORRUPT/);
    await writeFile(storePath, saved, { mode: 0o600 });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
