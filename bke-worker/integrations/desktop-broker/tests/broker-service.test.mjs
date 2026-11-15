/**
 * F3-03 / F3-05 / F3-06 Trusted Desktop Broker, Server-Mediated CAS & Authority Matrix Tests.
 *
 * Covers all 17 required F3-03 broker tests + F3-05 Repo/PR authority states +
 * F3-06 token revocation/clamping + zero secret leakage.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  DeviceEnrollmentRegistry,
  signAdminApproval,
} from '../dist/device-enrollment.js';
import { SandboxGitHubAppAdapter } from '../dist/github-app-adapter.js';
import { TrustedDesktopBroker } from '../dist/broker-service.js';
import { SandboxBrokerHttpServer } from '../dist/broker-server.js';
import {
  DeviceKeyPairSigner,
  SandboxHttpTokenBrokerClient,
} from '../dist/broker-client.js';
import { startMockGitHubServer } from './mock-github-server.mjs';
import { ExecutionRequestVerifier } from '../../../browser-extension/native-host/claim/dist/native-host/claim/github-app-harness.js';
import { RestGitHubAuthorityProvider } from '../../../browser-extension/native-host/claim/dist/native-host/claim/github-authority-provider.js';
import { ManagedTokenProvider } from '../../../browser-extension/native-host/claim/dist/native-host/claim/token-lifecycle.js';

const REPO = 'jan2xo/bke-worker';
const [OWNER, REPO_NAME] = REPO.split('/');
const REPO_ID = 1354026486;
const INSTALL_ID = '987654321';
const WORKER = 'worker-f1';
const DEVICE = 'desktop-dev-f3-01';
const PR_NUM = 149;
const HEAD_A = 'a'.repeat(40);
const TREE_A = 'e'.repeat(40);
const PROFILE_HASH = '1'.repeat(64);
const NATIVE_HASH = '2'.repeat(64);
const ISSUER = 'https://broker.bke.sandbox.local';
const AUDIENCE = `bke-desktop-controller:${REPO}:${WORKER}`;
const PINNED_APP = { id: 9001, slug: 'bke-dispatcher-app' };

function genEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

function makeAdminApproval(adminKeys, keyId, action, nowMs, overrides = {}) {
  return signAdminApproval(
    {
      version: 1,
      action,
      admin_actor_id: 'owner-admin-01',
      installation_id: INSTALL_ID,
      worker_id: WORKER,
      device_id: DEVICE,
      authorized_repository_scope: [REPO],
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      nonce: `adm-${Math.random().toString(16).slice(2)}`,
      issued_at: new Date(nowMs - 1_000).toISOString(),
      expires_at: new Date(nowMs + 90_000).toISOString(),
      ...overrides,
    },
    adminKeys.privatePem,
    keyId,
  );
}

async function setupHarness(dir, mockGh, clockRef) {
  const adminKeys = genEd25519();
  const adminMap = new Map([['admin-k1', adminKeys.publicPem]]);
  const storePath = join(dir, 'enrollment.json');
  const statePath = join(dir, 'broker-state.json');

  const registry = new DeviceEnrollmentRegistry({
    storePath,
    adminPublicKeysById: adminMap,
    nowMs: () => clockRef.now,
  });
  const ghAdapter = new SandboxGitHubAppAdapter({
    appId: PINNED_APP.id,
    appSlug: PINNED_APP.slug,
    apiBaseUrl: mockGh.baseUrl,
    nowMs: () => clockRef.now,
    timeoutMs: 250,
  });
  const broker = new TrustedDesktopBroker({
    brokerIssuer: ISSUER,
    statePath,
    enrollmentRegistry: registry,
    githubAppAdapter: ghAdapter,
    adminPublicKeysById: adminMap,
    nowMs: () => clockRef.now,
  });
  await broker.initialize();

  const signer = new DeviceKeyPairSigner();
  const ch = await registry.issueChallenge({
    installation_id: INSTALL_ID,
    worker_id: WORKER,
    device_id: DEVICE,
    authorized_repository_scope: [REPO],
    admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'APPROVE_ENROLLMENT', clockRef.now),
  });
  await registry.completeEnrollment({
    challenge_id: ch.challenge_id,
    installation_id: INSTALL_ID,
    worker_id: WORKER,
    device_id: DEVICE,
    public_key_spki_pem: signer.publicKeySpkiPem,
    browser_profile_identity: PROFILE_HASH,
    native_bridge_identity: NATIVE_HASH,
    challenge_signature_b64url: signer.signEnrollmentChallenge({
      challenge: ch,
      browser_profile_identity: PROFILE_HASH,
      native_bridge_identity: NATIVE_HASH,
    }),
  });

  mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-01', clockRef.now + 300_000);
  return { adminKeys, adminMap, storePath, statePath, registry, ghAdapter, broker, signer };
}

test('F3-03: 17-point broker security, V2 Ed25519 signing, rotation, replay, timeout, clamping, and server CAS ops', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f3-broker-'));
  const clock = { now: Date.parse('2026-10-20T12:00:00.000Z') };
  const mockGh = await startMockGitHubServer({ installationId: INSTALL_ID });

  try {
    const { adminKeys, adminMap, storePath, statePath, registry, ghAdapter, broker, signer } =
      await setupHarness(dir, mockGh, clock);

    const makeExecReq = (attemptId = 'att-01', action = 'DISPATCH_FIRST_MESSAGE', deliveryId) =>
      broker.authorizeExecution({
        repository: REPO,
        expected_repository_id: REPO_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: attemptId,
        action,
        delivery_id: deliveryId,
        device_assertion: signer.signDeviceAssertion({
          worker_id: WORKER,
          device_id: DEVICE,
          installation_id: INSTALL_ID,
          enrollment_generation: 1,
          purpose: 'AUTHORIZE_EXECUTION',
          repository: REPO,
          nowMs: clock.now,
        }),
        admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'DISPATCH_EXECUTION', clock.now, {
          attempt_id: attemptId,
          execution_action: action,
        }),
      });

    const authProvider = new RestGitHubAuthorityProvider(
      (url, init) => globalThis.fetch(url, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() })),
      async () =>
        (
          await broker.mintScopedToken({
            repository: REPO,
            repository_id: REPO_ID,
            installation_id: INSTALL_ID,
            worker_id: WORKER,
            requested_permissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
            device_assertion: signer.signDeviceAssertion({
              worker_id: WORKER,
              device_id: DEVICE,
              installation_id: INSTALL_ID,
              enrollment_generation: 1,
              purpose: 'MINT_SCOPED_TOKEN',
              repository: REPO,
              nowMs: clock.now,
            }),
          })
        ).token,
      { baseApiUrl: mockGh.baseUrl, nowMs: () => clock.now },
    );

    // (1) Valid installation lookup & (2) Scoped authorization & Ed25519 V2 signing
    const signed1 = await makeExecReq('att-01', 'DISPATCH_FIRST_MESSAGE', 'deliv-01');
    assert.equal(signed1.signature_alg, 'Ed25519');
    assert.equal(signed1.key_id, 'broker-exec-k1');
    assert.equal(signed1.envelope.protocol_version, 2);
    assert.equal(signed1.envelope.device_id, DEVICE);

    const pubKeys = await broker.getPublicVerificationKeys();
    assert.ok(pubKeys.executionPublicKeys['broker-exec-k1']);
    assert.ok(pubKeys.haltPublicKeys['broker-halt-k1']);
    assert.notEqual(pubKeys.executionPublicKeys['broker-exec-k1'], pubKeys.haltPublicKeys['broker-halt-k1']);
    assert.ok(!JSON.stringify(pubKeys).includes('PRIVATE KEY'));

    const verifier = new ExecutionRequestVerifier({
      expectedRepositoryOwner: OWNER,
      expectedRepositoryName: REPO_NAME,
      expectedRepositoryId: REPO_ID,
      expectedInstallationId: INSTALL_ID,
      expectedWorkerId: WORKER,
      pinnedApp: PINNED_APP,
      asymmetricV2Enabled: true,
      requireAsymmetricV2: true,
      publicKeysById: new Map(Object.entries(pubKeys.executionPublicKeys)),
      haltPublicKeysById: new Map(Object.entries(pubKeys.haltPublicKeys)),
      expectedAudience: AUDIENCE,
      expectedBrokerIssuer: ISSUER,
      expectedDeviceId: DEVICE,
      expectedEnrollmentGeneration: 1,
      minEnrollmentGeneration: 1,
      deviceRevocationChecker: (info) => registry.inspectDeviceStatus(info),
      allowRemoteHalt: true,
      provider: authProvider,
      nowMs: () => clock.now,
    });
    const verified1 = await verifier.verifyAndAuthorize(signed1);
    assert.equal(verified1.ok, true);
    assert.equal(verified1.envelope.device_id, DEVICE);

    // (3) Expired authorization (admin & device assertion)
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-01',
          action: 'DISPATCH_FIRST_MESSAGE',
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: clock.now - 200_000,
            ttlMs: 30_000,
          }),
          admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'DISPATCH_EXECUTION', clock.now),
        }),
      /DEVICE_ASSERTION_EXPIRED/,
    );

    // (4) Wrong audience rejected by verifier (valid Ed25519 signature, mismatched expectedAudience)
    const wrongAudVerifier = new ExecutionRequestVerifier({
      expectedRepositoryOwner: OWNER,
      expectedRepositoryName: REPO_NAME,
      expectedRepositoryId: REPO_ID,
      expectedInstallationId: INSTALL_ID,
      expectedWorkerId: WORKER,
      pinnedApp: PINNED_APP,
      asymmetricV2Enabled: true,
      requireAsymmetricV2: true,
      publicKeysById: new Map(Object.entries(pubKeys.executionPublicKeys)),
      haltPublicKeysById: new Map(Object.entries(pubKeys.haltPublicKeys)),
      expectedAudience: 'bke-desktop-controller:other/repo:worker-f1',
      expectedBrokerIssuer: ISSUER,
      expectedDeviceId: DEVICE,
      expectedEnrollmentGeneration: 1,
      minEnrollmentGeneration: 1,
      deviceRevocationChecker: (info) => registry.inspectDeviceStatus(info),
      allowRemoteHalt: true,
      provider: authProvider,
      nowMs: () => clock.now,
    });
    assert.equal((await wrongAudVerifier.verifyAndAuthorize(signed1)).code, 'EXEC_REQ_AUDIENCE_MISMATCH');

    // (5) Wrong worker
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: 'worker-other',
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-01',
          action: 'DISPATCH_FIRST_MESSAGE',
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: clock.now,
          }),
          admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'DISPATCH_EXECUTION', clock.now, {
            worker_id: 'worker-other',
          }),
        }),
      /BROKER_DEVICE_SCOPE_MISMATCH/,
    );

    // (6) Wrong repo
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: 'other/repo',
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-01',
          action: 'DISPATCH_FIRST_MESSAGE',
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: 'other/repo',
            nowMs: clock.now,
          }),
          admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'DISPATCH_EXECUTION', clock.now),
        }),
      /DEVICE_REPOSITORY_UNAUTHORIZED/,
    );

    // (7) Wrong installation
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: '111111111',
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-01',
          action: 'DISPATCH_FIRST_MESSAGE',
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: '111111111',
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: clock.now,
          }),
          admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'DISPATCH_EXECUTION', clock.now, {
            installation_id: '111111111',
          }),
        }),
      /DEVICE_INSTALLATION_MISMATCH/,
    );

    // (8) Unauthorized action / forbidden token permission escalation
    await assert.rejects(
      () =>
        broker.mintScopedToken({
          repository: REPO,
          repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          requested_permissions: { admin: 'write', contents: 'write' },
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'MINT_SCOPED_TOKEN',
            repository: REPO,
            nowMs: clock.now,
          }),
        }),
      /BROKER_REQUESTED_PERMISSION_FORBIDDEN/,
    );
    await assert.rejects(
      () =>
        broker.mintScopedToken({
          repository: REPO,
          repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          requested_permissions: { contents: 'write', pull_requests: 'read', checks: 'read' },
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'MINT_SCOPED_TOKEN',
            repository: REPO,
            nowMs: clock.now,
          }),
        }),
      /BROKER_DESKTOP_WRITE_TOKEN_FORBIDDEN/,
    );
    await assert.rejects(
      () =>
        broker.mintScopedToken({
          repository: REPO,
          repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          requested_permissions: { pull_requests: 'write' },
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'MINT_SCOPED_TOKEN',
            repository: REPO,
            nowMs: clock.now,
          }),
        }),
      /BROKER_REQUESTED_PERMISSION_FORBIDDEN/,
    );

    // (10) Replay after broker restart
    const restartedRegistry = new DeviceEnrollmentRegistry({
      storePath,
      adminPublicKeysById: adminMap,
      nowMs: () => clock.now,
    });
    const restartedBroker = new TrustedDesktopBroker({
      brokerIssuer: ISSUER,
      statePath,
      enrollmentRegistry: restartedRegistry,
      githubAppAdapter: ghAdapter,
      adminPublicKeysById: adminMap,
      nowMs: () => clock.now,
    });
    const fixedNonce = 'replay-nonce-across-restart';
    await restartedBroker.authorizeExecution({
      repository: REPO,
      expected_repository_id: REPO_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-01',
      action: 'PREPARE',
      delivery_id: 'deliv-restart-1',
      device_assertion: signer.signDeviceAssertion({
        worker_id: WORKER,
        device_id: DEVICE,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'AUTHORIZE_EXECUTION',
        repository: REPO,
        nowMs: clock.now,
        nonce: fixedNonce,
      }),
      admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'DISPATCH_EXECUTION', clock.now, {
        attempt_id: 'att-01',
        execution_action: 'PREPARE',
      }),
    });
    await assert.rejects(
      () =>
        restartedBroker.authorizeExecution({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-01',
          action: 'PREPARE',
          delivery_id: 'deliv-restart-2',
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: clock.now,
            nonce: fixedNonce,
          }),
          admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'DISPATCH_EXECUTION', clock.now, {
            attempt_id: 'att-01',
            execution_action: 'PREPARE',
          }),
        }),
      /BROKER_NONCE_REPLAYED/,
    );
    await assert.rejects(
      () =>
        restartedBroker.authorizeExecution({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-01',
          action: 'PREPARE',
          delivery_id: 'deliv-restart-1',
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: clock.now,
          }),
          admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'DISPATCH_EXECUTION', clock.now, {
            attempt_id: 'att-01',
            execution_action: 'PREPARE',
          }),
        }),
      /BROKER_DELIVERY_REPLAYED/,
    );

    // (11) Clock skew beyond 30s tolerance rejected
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-01',
          action: 'PREPARE',
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: clock.now + 90_000,
          }),
          admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'DISPATCH_EXECUTION', clock.now, {
            attempt_id: 'att-01',
            execution_action: 'PREPARE',
          }),
        }),
      /DEVICE_ASSERTION_NOT_YET_VALID/,
    );

    // (12) Provider timeout
    mockGh.state.delayMs = 400;
    await assert.rejects(() => makeExecReq('att-01', 'PREPARE'), /BROKER_GITHUB_TIMEOUT/);
    mockGh.state.delayMs = 0;

    // (13) Partial provider failure (incomplete pagination)
    mockGh.state.incompleteRepoPagination = true;
    await assert.rejects(() => makeExecReq('att-01', 'PREPARE'), /BROKER_PAGINATION_INCOMPLETE/);
    mockGh.state.incompleteRepoPagination = false;

    mockGh.state.incompleteCheckPagination = true;
    await assert.rejects(() => makeExecReq('att-01', 'PREPARE'), /BROKER_PAGINATION_INCOMPLETE/);
    mockGh.state.incompleteCheckPagination = false;

    // (14) Duplicate concurrent requests racing on same delivery_id
    const conc = await Promise.allSettled([
      makeExecReq('att-01', 'PREPARE', 'deliv-conc-1'),
      makeExecReq('att-01', 'PREPARE', 'deliv-conc-1'),
    ]);
    assert.equal(conc.filter((r) => r.status === 'fulfilled').length, 1);
    assert.equal(conc.filter((r) => r.status === 'rejected').length, 1);

    // (15) Scoped token minting, HTTP transport lifecycle, expiry refresh, and revocation
    const httpBroker = new SandboxBrokerHttpServer(broker, registry);
    const { port } = await httpBroker.start();
    try {
      const client = new SandboxHttpTokenBrokerClient({
        brokerBaseUrl: `http://127.0.0.1:${port}`,
        deviceId: DEVICE,
        enrollmentGeneration: 1,
        deviceSigner: signer,
        brokerPublicKeysById: new Map(Object.entries(pubKeys.executionPublicKeys)),
        expectedBrokerIssuer: ISSUER,
        repository: REPO,
        installationId: INSTALL_ID,
        workerId: WORKER,
        nowMs: () => clock.now,
      });
      const provider = new ManagedTokenProvider(
        {
          repository: REPO,
          repositoryId: REPO_ID,
          installationId: INSTALL_ID,
          workerId: WORKER,
          allowedPermissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
          nowMs: () => clock.now,
        },
        client,
      );
      const tok1 = await provider.getToken();
      assert.ok(tok1.startsWith('ghs_sandbox_'));
      await fetch(`http://127.0.0.1:${port}/v1/broker/revoke-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: tok1 }),
      });
      await assert.rejects(() => provider.getToken(), /TOKEN_REVOKED/);
      assert.equal(provider.getStatus().revoked, true);

      // (17) Server-mediated CAS ops via HTTP + arbitrary proxy rejection
      const fenceOpRes = await fetch(`http://127.0.0.1:${port}/v1/broker/ledger-ops`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          worker_id: WORKER,
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'SERVER_MEDIATED_LEDGER_OP',
            repository: REPO,
            nowMs: clock.now,
          }),
          ledger_op: {
            operation: 'COMMIT_PRE_SEND_FENCE',
            repository: REPO,
            repository_id: REPO_ID,
            installation_id: INSTALL_ID,
            pr_number: PR_NUM,
            head_sha: HEAD_A,
            attempt_id: 'att-cas-01',
            ref_name: `refs/bke/fences/${PR_NUM}/att-cas-01`,
            commit_message: 'bke: fence att-cas-01',
            tree_sha: TREE_A,
          },
        }),
      });
      assert.equal(fenceOpRes.status, 200);
      const fenceBody = await fenceOpRes.json();
      assert.equal(fenceBody.status, 'COMMITTED');

      const arbitraryOp = await fetch(`http://127.0.0.1:${port}/v1/broker/ledger-ops`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          worker_id: WORKER,
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'SERVER_MEDIATED_LEDGER_OP',
            repository: REPO,
            nowMs: clock.now,
          }),
          ledger_op: {
            operation: 'COMMIT_PRE_SEND_FENCE',
            repository: REPO,
            repository_id: REPO_ID,
            installation_id: INSTALL_ID,
            pr_number: PR_NUM,
            head_sha: HEAD_A,
            attempt_id: 'att-evil',
            ref_name: 'refs/heads/main',
            commit_message: 'evil overwrite main',
            tree_sha: TREE_A,
          },
        }),
      });
      assert.equal(arbitraryOp.status, 409);
      const arbBody = await arbitraryOp.json();
      assert.equal(arbBody.code, 'BROKER_ARBITRARY_PROXY_FORBIDDEN');
    } finally {
      await httpBroker.stop();
    }

    // (16) Signing-key rotation (k1 VERIFY_ONLY -> k2 ACTIVE) + HALT key separation
    const rotated = await broker.rotateSigningKey({
      role: 'EXECUTION',
      newKeyId: 'broker-exec-k2',
      admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'ROTATE_BROKER_SIGNING_KEY', clock.now),
    });
    assert.equal(rotated.activeKeyId, 'broker-exec-k2');
    const signed2 = await makeExecReq('att-01', 'PREPARE', 'deliv-k2');
    assert.equal(signed2.key_id, 'broker-exec-k2');

    const keysAfterRotate = await broker.getPublicVerificationKeys();
    const dualVerifier = new ExecutionRequestVerifier({
      expectedRepositoryOwner: OWNER,
      expectedRepositoryName: REPO_NAME,
      expectedRepositoryId: REPO_ID,
      expectedInstallationId: INSTALL_ID,
      expectedWorkerId: WORKER,
      pinnedApp: PINNED_APP,
      asymmetricV2Enabled: true,
      requireAsymmetricV2: true,
      publicKeysById: new Map(Object.entries(keysAfterRotate.executionPublicKeys)),
      haltPublicKeysById: new Map(Object.entries(keysAfterRotate.haltPublicKeys)),
      expectedAudience: AUDIENCE,
      expectedBrokerIssuer: ISSUER,
      expectedDeviceId: DEVICE,
      expectedEnrollmentGeneration: 1,
      minEnrollmentGeneration: 1,
      deviceRevocationChecker: (info) => registry.inspectDeviceStatus(info),
      allowRemoteHalt: true,
      provider: authProvider,
      nowMs: () => clock.now,
    });
    assert.equal((await dualVerifier.verifyAndAuthorize(signed2)).ok, true);
    const haltReq = await makeExecReq('att-01', 'HALT', 'deliv-halt-1');
    assert.equal(haltReq.key_id, 'broker-halt-k1');
    assert.equal((await dualVerifier.verifyAndAuthorize(haltReq)).ok, true);

    // (F3-05 Repository & PR Authority States)
    mockGh.state.installationMissing = true;
    await assert.rejects(() => makeExecReq('att-01', 'PREPARE'), /BROKER_INSTALLATION_MISSING/);
    mockGh.state.installationMissing = false;

    mockGh.state.installationRevoked = true;
    await assert.rejects(() => makeExecReq('att-01', 'PREPARE'), /BROKER_INSTALLATION_REVOKED/);
    mockGh.state.installationRevoked = false;

    mockGh.state.installationPerms = { contents: 'read', pull_requests: 'read', checks: 'read', admin: true };
    await assert.rejects(() => makeExecReq('att-01', 'PREPARE'), /BROKER_PERMISSION_ESCALATION_DETECTED/);
    mockGh.state.installationPerms = { contents: 'write', pull_requests: 'read', checks: 'read' };

    mockGh.state.repos.push({
      id: 999999,
      full_name: 'jan2xo/bke-second-repo',
      permissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
      prs: [{ number: 55, state: 'open', headSha: 'b'.repeat(40), labels: [`bke-worker:${WORKER}`] }],
    });
    await assert.rejects(() => makeExecReq('att-01', 'PREPARE'), /BROKER_CROSS_REPO_WORKER_CONFLICT/);
    mockGh.state.repos.pop();

    // (9) Revoked device fails closed
    await registry.revokeDevice({
      device_id: DEVICE,
      worker_id: WORKER,
      installation_id: INSTALL_ID,
      state: 'REVOKED',
      reason: 'OWNER_REVOKED_TEST',
      admin_approval: makeAdminApproval(adminKeys, 'admin-k1', 'REVOKE_DEVICE', clock.now),
    });
    await assert.rejects(() => makeExecReq('att-01', 'PREPARE'), /DEVICE_REVOKED/);

    const audit = await broker.getAuditLog();
    assert.ok(audit.length >= 6);
    const auditSerialized = JSON.stringify(audit);
    assert.ok(!auditSerialized.includes('ghs_'));
    assert.ok(!auditSerialized.includes('PRIVATE KEY'));
  } finally {
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});
