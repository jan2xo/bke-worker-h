/**
 * F4.3.1 Independent Audit Follow-Up Adversarial Tests (SEC-06 & SEC-07).
 *
 * Covers the two residual source-level integrity findings from the F4.3 audit:
 * - SEC-06: Full canonical 14-field domain-separated ledger_op_sha256 digest binding
 *           in device PoP + strict structured PRE_SEND_FENCE JSON in trusted mode
 *           (with isolated test-compatibility opt-in only).
 * - SEC-07: Fail-closed /installation/repositories pagination & mandatory total_count
 *           validation across all pages (including two-repo conflict concealment).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  computeLedgerOpDigestHex,
  LEDGER_OP_DIGEST_DOMAIN,
} from '../dist/types.js';
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
import { HttpTrustedBrokerClient } from '../../../browser-extension/native-host/claim/dist/native-host/claim/runtime-broker-factory.js';

const REPO_1 = 'jan2xo/bke-worker';
const REPO_1_ID = 1354026486;
const REPO_2 = 'jan2xo/bke-second-repo';
const REPO_2_ID = 2222222;
const INSTALL_ID = '987654321';
const WORKER_A = 'worker-f1';
const WORKER_B = 'worker-f2';
const DEVICE_A = 'desktop-f431-01';
const PR_NUM = 149;
const HEAD_A = 'a'.repeat(40);
const HEAD_B = 'b'.repeat(40);
const TREE_A = 'e'.repeat(40);
const TREE_B = 'f'.repeat(40);
const PROFILE_HASH = '1'.repeat(64);
const NATIVE_HASH = '2'.repeat(64);
const ISSUER = 'https://broker.bke.f431.local';
const PINNED_APP = { id: 9001, slug: 'bke-dispatcher-app' };

function genEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

function mkAdmin(adminKeys, action, now, extra = {}) {
  return signAdminApproval(
    {
      version: 1,
      action,
      admin_actor_id: 'owner-admin-01',
      installation_id: INSTALL_ID,
      worker_id: WORKER_A,
      device_id: DEVICE_A,
      authorized_repository_scope: [REPO_1, REPO_2],
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      nonce: `adm-${Math.random().toString(16).slice(2)}`,
      issued_at: new Date(now - 1_000).toISOString(),
      expires_at: new Date(now + 120_000).toISOString(),
      ...extra,
    },
    adminKeys.privatePem,
    'admin-k1',
  );
}

async function enrollDevice(registry, adminKeys, signer, now) {
  const ch = await registry.issueChallenge({
    installation_id: INSTALL_ID,
    worker_id: WORKER_A,
    device_id: DEVICE_A,
    authorized_repository_scope: [REPO_1, REPO_2],
    admin_approval: mkAdmin(adminKeys, 'APPROVE_ENROLLMENT', now),
  });
  await registry.completeEnrollment({
    challenge_id: ch.challenge_id,
    installation_id: INSTALL_ID,
    worker_id: WORKER_A,
    device_id: DEVICE_A,
    public_key_spki_pem: signer.publicKeySpkiPem,
    browser_profile_identity: PROFILE_HASH,
    native_bridge_identity: NATIVE_HASH,
    challenge_signature_b64url: signer.signEnrollmentChallenge({
      challenge: ch,
      browser_profile_identity: PROFILE_HASH,
      native_bridge_identity: NATIVE_HASH,
    }),
  });
}

function makeFenceMsg(attemptId, fenceId, workerId = WORKER_A, headSha = HEAD_A) {
  return JSON.stringify({
    bkeEvent: 'PRE_SEND_FENCE',
    version: 1,
    fenceId,
    attemptId,
    workerId,
    headSha,
  });
}

function makeConvMsg(convId, workerId = WORKER_A) {
  return JSON.stringify({
    bkeEvent: 'CONVERSATION_LEDGER_V1',
    version: 1,
    repository: REPO_1,
    prNumber: PR_NUM,
    workerId,
    conversationId: convId,
    turns: [{ turnNumber: 2, prompt: 'continue' }],
  });
}

test('SEC-06: Canonical 14-field digest rules and individual post-signing tamper rejection on every operation field', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f431-sec06-'));
  const now = Date.parse('2026-10-20T12:00:00.000Z');
  const mockGh = await startMockGitHubServer({ installationId: INSTALL_ID });
  const adminKeys = genEd25519();
  const adminMap = new Map([['admin-k1', adminKeys.publicPem]]);
  let httpBroker;

  try {
    const registry = new DeviceEnrollmentRegistry({
      storePath: join(dir, 'enroll.json'),
      adminPublicKeysById: adminMap,
      nowMs: () => now,
    });
    const ghAdapter = new SandboxGitHubAppAdapter({
      appId: PINNED_APP.id,
      appSlug: PINNED_APP.slug,
      apiBaseUrl: mockGh.baseUrl,
      nowMs: () => now,
      timeoutMs: 400,
    });
    const broker = new TrustedDesktopBroker({
      brokerIssuer: ISSUER,
      statePath: join(dir, 'broker.json'),
      enrollmentRegistry: registry,
      githubAppAdapter: ghAdapter,
      adminPublicKeysById: adminMap,
      nowMs: () => now,
    });
    await broker.initialize();

    const { publicKey: devPub, privateKey: devPriv } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const devPubPem = devPub.export({ type: 'spki', format: 'pem' }).toString();
    const devPrivPem = devPriv.export({ type: 'pkcs8', format: 'pem' }).toString();
    const signer = new DeviceKeyPairSigner({ publicKeySpkiPem: devPubPem, privateKeyPem: devPrivPem });
    await enrollDevice(registry, adminKeys, signer, now);

    // Canonical optional-field & domain separation invariants
    assert.equal(LEDGER_OP_DIGEST_DOMAIN, 'BKE_MEDIATED_LEDGER_OP_V1\n');
    const baseOp = {
      operation: 'RECONCILE_CONVERSATION',
      repository: REPO_1,
      repository_id: REPO_1_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER_A,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-f431-t2',
      ref_name: `refs/bke/conversations/${PR_NUM}`,
      turn_ref_name: `refs/bke/turns/${PR_NUM}/att-f431-t2`,
      expected_parent_sha: HEAD_A,
      is_continuation: true,
      commit_message: makeConvMsg('conv-f431-legit'),
      tree_sha: TREE_A,
    };

    const digestTrue = computeLedgerOpDigestHex(baseOp);
    const digestFalse = computeLedgerOpDigestHex({ ...baseOp, is_continuation: false });
    const { is_continuation: _omitCont, ...opWithoutCont } = baseOp;
    const digestOmitted = computeLedgerOpDigestHex(opWithoutCont);
    assert.notEqual(digestTrue, digestFalse);
    assert.notEqual(digestFalse, digestOmitted);
    assert.notEqual(digestTrue, digestOmitted);
    assert.throws(() => computeLedgerOpDigestHex({ ...baseOp, turn_ref_name: '' }), /BROKER_LEDGER_OP_INVALID/);
    assert.throws(() => computeLedgerOpDigestHex({ ...baseOp, expected_parent_sha: '' }), /BROKER_LEDGER_OP_INVALID/);
    assert.throws(() => computeLedgerOpDigestHex({ ...baseOp, extra_unbound: 'evil' }), /BROKER_ARBITRARY_PROXY_FORBIDDEN/);

    // 14-field individual post-signing tamper matrix: mutate ONE field after signing, verify zero GitHub calls
    const mutations = [
      ['operation', (op) => ({ ...op, operation: 'COMMIT_PRE_SEND_FENCE' })],
      ['repository', (op) => ({ ...op, repository: REPO_2 })],
      ['repository_id', (op) => ({ ...op, repository_id: REPO_2_ID })],
      ['installation_id', (op) => ({ ...op, installation_id: '111111111' })],
      ['worker_id', (op) => ({ ...op, worker_id: WORKER_B })],
      ['pr_number', (op) => ({ ...op, pr_number: 150 })],
      ['head_sha', (op) => ({ ...op, head_sha: HEAD_B })],
      ['attempt_id', (op) => ({ ...op, attempt_id: 'att-f431-other' })],
      ['ref_name', (op) => ({ ...op, ref_name: `refs/bke/conversations/999` })],
      ['turn_ref_name', (op) => ({ ...op, turn_ref_name: `refs/bke/turns/${PR_NUM}/att-tamper` })],
      ['expected_parent_sha', (op) => ({ ...op, expected_parent_sha: HEAD_B })],
      ['is_continuation', (op) => ({ ...op, is_continuation: false })],
      ['commit_message', (op) => ({ ...op, commit_message: makeConvMsg('conv-f431-tampered-content') })],
      ['tree_sha', (op) => ({ ...op, tree_sha: TREE_B })],
      ['extra_unbound_field', (op) => ({ ...op, extra_unbound: 'evil' })],
    ];

    for (const [field, mutate] of mutations) {
      const validPop = signer.signDeviceAssertion({
        worker_id: WORKER_A,
        device_id: DEVICE_A,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'SERVER_MEDIATED_LEDGER_OP',
        repository: REPO_1,
        nowMs: now,
        ledger_op: baseOp,
      });
      assert.equal(typeof validPop.payload.ledger_op_sha256, 'string');
      assert.equal(validPop.payload.ledger_op_sha256, digestTrue);

      const tamperedOp = mutate(baseOp);
      const reqCountBefore = mockGh.state.requestLog.length;
      if (field === 'repository') {
        await assert.rejects(
          () =>
            broker.executeServerMediatedLedgerOp({
              worker_id: WORKER_A,
              device_assertion: validPop,
              ledger_op: tamperedOp,
            }),
          /DEVICE_ASSERTION_REPOSITORY_MISMATCH/,
        );
      } else {
        const res = await broker.executeServerMediatedLedgerOp({
          worker_id: WORKER_A,
          device_assertion: validPop,
          ledger_op: tamperedOp,
        });
        assert.equal(res.ok, false, `mutated ${field} must be rejected`);
        assert.equal(res.status, 'CONFLICT');
        assert.equal(
          res.code,
          field === 'extra_unbound_field' ? 'BROKER_ARBITRARY_PROXY_FORBIDDEN' : 'BROKER_DEVICE_SCOPE_MISMATCH',
          `unexpected error code for mutated ${field}: ${res.code}`,
        );
      }
      assert.equal(
        mockGh.state.requestLog.length,
        reqCountBefore,
        `mutated ${field} must fail BEFORE any GitHub API call`,
      );
      assert.equal(mockGh.state.refs.size, 0);
    }

    // Positive end-to-end check over HTTP using BOTH desktop-broker client and runtime-broker-factory HttpTrustedBrokerClient
    httpBroker = new SandboxBrokerHttpServer(broker, registry);
    const { port } = await httpBroker.start();
    const pubKeys = await broker.getPublicVerificationKeys();

    const client = new SandboxHttpTokenBrokerClient({
      brokerBaseUrl: `http://127.0.0.1:${port}`,
      deviceId: DEVICE_A,
      enrollmentGeneration: 1,
      deviceSigner: signer,
      brokerPublicKeysById: new Map(Object.entries(pubKeys.executionPublicKeys)),
      expectedBrokerIssuer: ISSUER,
      repository: REPO_1,
      installationId: INSTALL_ID,
      workerId: WORKER_A,
      nowMs: () => now,
    });

    // Establish Turn 1 conversation tip first so baseOp continuation commits cleanly
    const t1Conv = await client.executeLedgerOp({
      operation: 'RECONCILE_CONVERSATION',
      repository: REPO_1,
      repositoryId: REPO_1_ID,
      installationId: INSTALL_ID,
      workerId: WORKER_A,
      prNumber: PR_NUM,
      headSha: HEAD_A,
      attemptId: 'att-f431-t1',
      refName: `refs/bke/conversations/${PR_NUM}`,
      turnRefName: `refs/bke/turns/${PR_NUM}/att-f431-t1`,
      isContinuation: false,
      commitMessage: makeConvMsg('conv-f431-legit'),
      treeSha: TREE_A,
    });
    assert.equal(t1Conv.ok, true);

    const runtimeClient = new HttpTrustedBrokerClient({
      brokerBaseUrl: `http://127.0.0.1:${port}`,
      deviceId: DEVICE_A,
      enrollmentGeneration: 1,
      devicePublicKeyPem: devPubPem,
      devicePrivateKeyPem: devPrivPem,
      brokerPublicKeysById: new Map(Object.entries(pubKeys.executionPublicKeys)),
      expectedBrokerIssuer: ISSUER,
      repository: REPO_1,
      repositoryId: REPO_1_ID,
      installationId: INSTALL_ID,
      workerId: WORKER_A,
      nowMs: () => now,
    });

    const t2Conv = await runtimeClient.executeLedgerOp({
      operation: 'RECONCILE_CONVERSATION',
      repository: REPO_1,
      repositoryId: REPO_1_ID,
      installationId: INSTALL_ID,
      workerId: WORKER_A,
      prNumber: PR_NUM,
      headSha: HEAD_A,
      attemptId: 'att-f431-t2',
      refName: `refs/bke/conversations/${PR_NUM}`,
      turnRefName: `refs/bke/turns/${PR_NUM}/att-f431-t2`,
      expectedParentSha: t1Conv.sha,
      isContinuation: true,
      commitMessage: makeConvMsg('conv-f431-legit'),
      treeSha: TREE_A,
    });
    assert.equal(t2Conv.ok, true);
    assert.equal(t2Conv.status, 'COMMITTED');
  } finally {
    await httpBroker?.stop();
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('SEC-06: Trusted operational path rejects unstructured/bogus PRE_SEND_FENCE messages while isolated test compat opt-in preserves legacy fixtures', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f431-fence-'));
  const now = Date.parse('2026-10-20T12:00:00.000Z');
  const mockGh = await startMockGitHubServer({ installationId: INSTALL_ID });
  const adminKeys = genEd25519();
  const adminMap = new Map([['admin-k1', adminKeys.publicPem]]);

  try {
    const registry = new DeviceEnrollmentRegistry({
      storePath: join(dir, 'enroll.json'),
      adminPublicKeysById: adminMap,
      nowMs: () => now,
    });
    const strictAdapter = new SandboxGitHubAppAdapter({
      appId: PINNED_APP.id,
      appSlug: PINNED_APP.slug,
      apiBaseUrl: mockGh.baseUrl,
      nowMs: () => now,
      timeoutMs: 400,
    });
    const strictBroker = new TrustedDesktopBroker({
      brokerIssuer: ISSUER,
      statePath: join(dir, 'broker-strict.json'),
      enrollmentRegistry: registry,
      githubAppAdapter: strictAdapter,
      adminPublicKeysById: adminMap,
      nowMs: () => now,
    });
    await strictBroker.initialize();

    const signer = new DeviceKeyPairSigner();
    await enrollDevice(registry, adminKeys, signer, now);

    const invalidFences = [
      'legacy unstructured fence text',
      '{"hello":"world"}',
      JSON.stringify({ bkeEvent: 'PRE_SEND_FENCE', version: 2, fenceId: 'f1', attemptId: 'att-bad-1', workerId: WORKER_A, headSha: HEAD_A }),
      JSON.stringify({ bkeEvent: 'PRE_SEND_FENCE', version: 1, fenceId: '', attemptId: 'att-bad-1', workerId: WORKER_A, headSha: HEAD_A }),
      JSON.stringify({ bkeEvent: 'PRE_SEND_FENCE', version: 1, fenceId: 'f1', attemptId: 'att-other', workerId: WORKER_A, headSha: HEAD_A }),
      JSON.stringify({ bkeEvent: 'PRE_SEND_FENCE', version: 1, fenceId: 'f1', attemptId: 'att-bad-1', workerId: WORKER_B, headSha: HEAD_A }),
      JSON.stringify({ bkeEvent: 'PRE_SEND_FENCE', version: 1, fenceId: 'f1', attemptId: 'att-bad-1', workerId: WORKER_A, headSha: HEAD_B }),
    ];

    for (let i = 0; i < invalidFences.length; i += 1) {
      const attemptId = 'att-bad-1';
      const op = {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: attemptId,
        ref_name: `refs/bke/fences/${PR_NUM}/${attemptId}`,
        commit_message: invalidFences[i],
        tree_sha: TREE_A,
      };
      const res = await strictBroker.executeServerMediatedLedgerOp({
        worker_id: WORKER_A,
        device_assertion: signer.signDeviceAssertion({
          worker_id: WORKER_A,
          device_id: DEVICE_A,
          installation_id: INSTALL_ID,
          enrollment_generation: 1,
          purpose: 'SERVER_MEDIATED_LEDGER_OP',
          repository: REPO_1,
          nowMs: now,
          ledger_op: op,
        }),
        ledger_op: op,
      });
      assert.equal(res.ok, false, `invalid fence case #${i} must be rejected`);
      assert.equal(res.status, 'CONFLICT');
      assert.equal(res.code, 'BROKER_LEDGER_FENCE_PAYLOAD_INVALID');
      assert.equal(mockGh.state.refs.size, 0);
      assert.equal(
        mockGh.state.requestLog.some((r) => r.method === 'POST' && r.path.includes('/git/commits')),
        false,
      );
    }

    // Valid structured PRE_SEND_FENCE JSON succeeds in strict trusted operational mode
    const validOp = {
      operation: 'COMMIT_PRE_SEND_FENCE',
      repository: REPO_1,
      repository_id: REPO_1_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER_A,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-good-fence',
      ref_name: `refs/bke/fences/${PR_NUM}/att-good-fence`,
      commit_message: makeFenceMsg('att-good-fence', 'fence-good-1'),
      tree_sha: TREE_A,
    };
    const validRes = await strictBroker.executeServerMediatedLedgerOp({
      worker_id: WORKER_A,
      device_assertion: signer.signDeviceAssertion({
        worker_id: WORKER_A,
        device_id: DEVICE_A,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'SERVER_MEDIATED_LEDGER_OP',
        repository: REPO_1,
        nowMs: now,
        ledger_op: validOp,
      }),
      ledger_op: validOp,
    });
    assert.equal(validRes.ok, true);
    assert.equal(validRes.status, 'COMMITTED');

    // Explicitly isolated legacy test-compatibility mode preserves legacy unstructured fixtures
    // without weakening PoP digest binding or mismatched structured PRE_SEND_FENCE validation.
    const compatAdapter = new SandboxGitHubAppAdapter({
      appId: PINNED_APP.id,
      appSlug: PINNED_APP.slug,
      apiBaseUrl: mockGh.baseUrl,
      nowMs: () => now,
      timeoutMs: 400,
      allowLegacyUnstructuredFenceForTests: true,
    });
    const compatBroker = new TrustedDesktopBroker({
      brokerIssuer: ISSUER,
      statePath: join(dir, 'broker-compat.json'),
      enrollmentRegistry: registry,
      githubAppAdapter: compatAdapter,
      adminPublicKeysById: adminMap,
      nowMs: () => now,
    });
    await compatBroker.initialize();

    const legacyOp = {
      operation: 'COMMIT_PRE_SEND_FENCE',
      repository: REPO_1,
      repository_id: REPO_1_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER_A,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-legacy-compat',
      ref_name: `refs/bke/fences/${PR_NUM}/att-legacy-compat`,
      commit_message: 'legacy unstructured fence fixture',
      tree_sha: TREE_A,
    };
    const compatOk = await compatBroker.executeServerMediatedLedgerOp({
      worker_id: WORKER_A,
      device_assertion: signer.signDeviceAssertion({
        worker_id: WORKER_A,
        device_id: DEVICE_A,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'SERVER_MEDIATED_LEDGER_OP',
        repository: REPO_1,
        nowMs: now,
        ledger_op: legacyOp,
      }),
      ledger_op: legacyOp,
    });
    assert.equal(compatOk.ok, true);
    assert.equal(compatOk.status, 'COMMITTED');

    // Even in compat mode, tampering legacy commit_message after signing still fails digest check!
    const compatTamper = await compatBroker.executeServerMediatedLedgerOp({
      worker_id: WORKER_A,
      device_assertion: signer.signDeviceAssertion({
        worker_id: WORKER_A,
        device_id: DEVICE_A,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'SERVER_MEDIATED_LEDGER_OP',
        repository: REPO_1,
        nowMs: now,
        ledger_op: legacyOp,
      }),
      ledger_op: {
        ...legacyOp,
        attempt_id: 'att-legacy-compat-2',
        ref_name: `refs/bke/fences/${PR_NUM}/att-legacy-compat-2`,
        commit_message: 'tampered unstructured message',
      },
    });
    assert.equal(compatTamper.ok, false);
    assert.equal(compatTamper.code, 'BROKER_DEVICE_SCOPE_MISMATCH');
  } finally {
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('SEC-07: Two-repository /installation/repositories fail-closed enumeration blocks concealed sibling-repo conflicts', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f431-sec07-'));
  const now = Date.parse('2026-10-20T12:00:00.000Z');
  const mockGh = await startMockGitHubServer({
    installationId: INSTALL_ID,
    repos: [
      {
        id: REPO_1_ID,
        full_name: REPO_1,
        permissions: { contents: 'write', pull_requests: 'read', checks: 'read', pull: true, push: true },
        prs: [{ number: PR_NUM, state: 'open', headSha: HEAD_A, labels: [`bke-worker:${WORKER_A}`] }],
      },
      {
        id: REPO_2_ID,
        full_name: REPO_2,
        permissions: { contents: 'write', pull_requests: 'read', checks: 'read', pull: true, push: true },
        // Sibling repo holds a conflicting assignment for the same WORKER_A!
        prs: [{ number: 77, state: 'open', headSha: HEAD_B, labels: [`bke-worker:${WORKER_A}`] }],
      },
    ],
  });
  const adminKeys = genEd25519();
  const adminMap = new Map([['admin-k1', adminKeys.publicPem]]);

  try {
    const registry = new DeviceEnrollmentRegistry({
      storePath: join(dir, 'enroll.json'),
      adminPublicKeysById: adminMap,
      nowMs: () => now,
    });
    const ghAdapter = new SandboxGitHubAppAdapter({
      appId: PINNED_APP.id,
      appSlug: PINNED_APP.slug,
      apiBaseUrl: mockGh.baseUrl,
      nowMs: () => now,
      timeoutMs: 400,
    });
    const broker = new TrustedDesktopBroker({
      brokerIssuer: ISSUER,
      statePath: join(dir, 'broker.json'),
      enrollmentRegistry: registry,
      githubAppAdapter: ghAdapter,
      adminPublicKeysById: adminMap,
      nowMs: () => now,
    });
    await broker.initialize();

    const signer = new DeviceKeyPairSigner();
    await enrollDevice(registry, adminKeys, signer, now);
    mockGh.setTicket(REPO_1, HEAD_A, WORKER_A, 'att-sec07-ok', now + 180_000);

    const resetFaults = () => {
      mockGh.state.omitRepoTotalCount = false;
      mockGh.state.badRepoTotalCount = null;
      mockGh.state.mismatchedRepoTotalCount = null;
      mockGh.state.truncatedRepoPagination = false;
      mockGh.state.duplicateRepoId = false;
      mockGh.state.malformedRepoLink = false;
      mockGh.state.loopRepoLink = false;
    };

    const faultCases = [
      {
        name: 'omit total_count on page 1',
        setup: () => { mockGh.state.omitRepoTotalCount = true; },
        expectedCode: 'BROKER_PAGINATION_INCOMPLETE',
      },
      {
        name: 'negative total_count',
        setup: () => { mockGh.state.badRepoTotalCount = -1; },
        expectedCode: 'BROKER_PAGINATION_INCOMPLETE',
      },
      {
        name: 'non-integer float total_count',
        setup: () => { mockGh.state.badRepoTotalCount = 1.5; },
        expectedCode: 'BROKER_PAGINATION_INCOMPLETE',
      },
      {
        name: 'string total_count',
        setup: () => { mockGh.state.badRepoTotalCount = '2'; },
        expectedCode: 'BROKER_PAGINATION_INCOMPLETE',
      },
      {
        name: 'truncated page 1 without Link header concealing repo 2',
        setup: () => { mockGh.state.truncatedRepoPagination = true; },
        expectedCode: 'BROKER_PAGINATION_INCOMPLETE',
      },
      {
        name: 'mismatched total_count on page 2',
        setup: () => { mockGh.state.mismatchedRepoTotalCount = 1; },
        expectedCode: 'BROKER_PAGINATION_INCOMPLETE',
      },
      {
        name: 'duplicate repo ID concealing repo 2',
        setup: () => { mockGh.state.duplicateRepoId = true; },
        expectedCode: 'BROKER_DUPLICATE_REPO',
      },
      {
        name: 'malformed Link header on /installation/repositories',
        setup: () => { mockGh.state.malformedRepoLink = true; },
        expectedCode: 'BROKER_GITHUB_PAGINATION_MALFORMED',
      },
      {
        name: 'cyclic Link header looping back to page 1',
        setup: () => { mockGh.state.loopRepoLink = true; },
        expectedCode: 'BROKER_PAGINATION_INCOMPLETE',
      },
    ];

    for (let i = 0; i < faultCases.length; i += 1) {
      const fc = faultCases[i];
      resetFaults();
      fc.setup();

      const attemptId = `att-sec07-${i}`;
      await assert.rejects(
        () =>
          broker.authorizeExecution({
            repository: REPO_1,
            expected_repository_id: REPO_1_ID,
            installation_id: INSTALL_ID,
            worker_id: WORKER_A,
            pr_number: PR_NUM,
            head_sha: HEAD_A,
            attempt_id: attemptId,
            action: 'DISPATCH_FIRST_MESSAGE',
            delivery_id: `deliv-sec07-${i}`,
            admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: attemptId }),
            device_assertion: signer.signDeviceAssertion({
              worker_id: WORKER_A,
              device_id: DEVICE_A,
              installation_id: INSTALL_ID,
              enrollment_generation: 1,
              purpose: 'AUTHORIZE_EXECUTION',
              repository: REPO_1,
              nowMs: now,
            }),
          }),
        new RegExp(fc.expectedCode),
        `authorizeExecution should fail closed for ${fc.name}`,
      );

      const fenceOp = {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: attemptId,
        ref_name: `refs/bke/fences/${PR_NUM}/${attemptId}`,
        commit_message: makeFenceMsg(attemptId, `fence-sec07-${i}`),
        tree_sha: TREE_A,
      };
      const fenceRes = await broker.executeServerMediatedLedgerOp({
        worker_id: WORKER_A,
        device_assertion: signer.signDeviceAssertion({
          worker_id: WORKER_A,
          device_id: DEVICE_A,
          installation_id: INSTALL_ID,
          enrollment_generation: 1,
          purpose: 'SERVER_MEDIATED_LEDGER_OP',
          repository: REPO_1,
          nowMs: now,
          ledger_op: fenceOp,
        }),
        ledger_op: fenceOp,
      });
      assert.equal(fenceRes.ok, false, `mediated CAS must fail closed for ${fc.name}`);
      assert.equal(fenceRes.code, fc.expectedCode, `unexpected CAS code for ${fc.name}: ${fenceRes.code}`);
      assert.equal(mockGh.state.refs.size, 0);
    }

    // With pagination faults cleared, complete 2-page enumeration catches the sibling repo conflict!
    resetFaults();
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO_1,
          expected_repository_id: REPO_1_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER_A,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-sec07-ok',
          action: 'DISPATCH_FIRST_MESSAGE',
          delivery_id: 'deliv-sec07-conflict',
          admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-sec07-ok' }),
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER_A,
            device_id: DEVICE_A,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO_1,
            nowMs: now,
          }),
        }),
      /BROKER_CROSS_REPO_WORKER_CONFLICT/,
    );
    const conflictFenceOp = {
      operation: 'COMMIT_PRE_SEND_FENCE',
      repository: REPO_1,
      repository_id: REPO_1_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER_A,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-sec07-ok',
      ref_name: `refs/bke/fences/${PR_NUM}/att-sec07-ok`,
      commit_message: makeFenceMsg('att-sec07-ok', 'fence-sec07-conflict'),
      tree_sha: TREE_A,
    };
    const conflictFence = await broker.executeServerMediatedLedgerOp({
      worker_id: WORKER_A,
      device_assertion: signer.signDeviceAssertion({
        worker_id: WORKER_A,
        device_id: DEVICE_A,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'SERVER_MEDIATED_LEDGER_OP',
        repository: REPO_1,
        nowMs: now,
        ledger_op: conflictFenceOp,
      }),
      ledger_op: conflictFenceOp,
    });
    assert.equal(conflictFence.ok, false);
    assert.equal(conflictFence.code, 'BROKER_LEDGER_CROSS_REPO_WORKER_CONFLICT');
    assert.equal(mockGh.state.refs.size, 0);

    // Once sibling repo no longer holds WORKER_A, both authorizeExecution and COMMIT_PRE_SEND_FENCE succeed!
    mockGh.state.repos[1].prs[0].labels = [`bke-worker:${WORKER_B}`];
    const okAuth = await broker.authorizeExecution({
      repository: REPO_1,
      expected_repository_id: REPO_1_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER_A,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-sec07-ok',
      action: 'DISPATCH_FIRST_MESSAGE',
      delivery_id: 'deliv-sec07-ok',
      admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-sec07-ok' }),
      device_assertion: signer.signDeviceAssertion({
        worker_id: WORKER_A,
        device_id: DEVICE_A,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'AUTHORIZE_EXECUTION',
        repository: REPO_1,
        nowMs: now,
      }),
    });
    assert.equal(okAuth.envelope.action, 'DISPATCH_FIRST_MESSAGE');

    const okFenceOp = {
      operation: 'COMMIT_PRE_SEND_FENCE',
      repository: REPO_1,
      repository_id: REPO_1_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER_A,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-sec07-ok',
      ref_name: `refs/bke/fences/${PR_NUM}/att-sec07-ok`,
      commit_message: makeFenceMsg('att-sec07-ok', 'fence-sec07-ok'),
      tree_sha: TREE_A,
    };
    const okFence = await broker.executeServerMediatedLedgerOp({
      worker_id: WORKER_A,
      device_assertion: signer.signDeviceAssertion({
        worker_id: WORKER_A,
        device_id: DEVICE_A,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'SERVER_MEDIATED_LEDGER_OP',
        repository: REPO_1,
        nowMs: now,
        ledger_op: okFenceOp,
      }),
      ledger_op: okFenceOp,
    });
    assert.equal(okFence.ok, true);
    assert.equal(okFence.status, 'COMMITTED');
  } finally {
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});
