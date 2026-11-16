/**
 * F4-04 Multi-Host Race & Failure Safety Test Suite:
 * - Two independent host instances racing on identical PR/attempt -> <=1 claim succeeds (CONFLICT)
 * - Stale rotated-out host generation rejected everywhere (exact enrollment_generation check)
 * - Host A revoked & Host B enrolled for worker-f1 -> Host A locked out; uncertain claim blocks Host B & restarts
 * - Turn 1 / Turn 2 CAS fast-forward rejects stale expected_parent_sha without split-brain double send
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
import { DeviceKeyPairSigner } from '../dist/broker-client.js';
import { startMockGitHubServer } from './mock-github-server.mjs';
import { ExecutionRequestVerifier } from '../../../browser-extension/native-host/claim/dist/native-host/claim/github-app-harness.js';
import { RestGitHubAuthorityProvider } from '../../../browser-extension/native-host/claim/dist/native-host/claim/github-authority-provider.js';
import { GitHubF1Ledger } from '../../../browser-extension/native-host/claim/dist/native-host/claim/github-f1-ledger.js';
import {
  DesktopController,
  FileExecutionJournal,
} from '../../../browser-extension/native-host/claim/dist/native-host/claim/desktop-controller.js';
import { ExtensionBrowserAdapter } from '../../../browser-extension/dist/extension-browser-adapter.js';

const REPO = 'jan2xo/bke-worker';
const [OWNER, REPO_NAME] = REPO.split('/');
const REPO_ID = 1354026486;
const INSTALL_ID = '987654321';
const WORKER = 'worker-f1';
const PR_NUM = 149;
const HEAD_A = 'a'.repeat(40);
const TREE_A = 'e'.repeat(40);
const ISSUER = 'https://broker.bke.multihost.local';
const AUDIENCE = `bke-desktop-controller:${REPO}:${WORKER}`;
const PINNED_APP = { id: 9001, slug: 'bke-dispatcher-app' };

function genEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

function mkAdmin(adminKeys, action, deviceId, now, extra = {}) {
  return signAdminApproval(
    {
      version: 1,
      action,
      admin_actor_id: 'owner-admin-01',
      installation_id: INSTALL_ID,
      worker_id: WORKER,
      device_id: deviceId,
      authorized_repository_scope: [REPO],
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

async function enrollDevice(registry, adminKeys, deviceId, signer, profileHash, nativeHash, now) {
  const ch = await registry.issueChallenge({
    installation_id: INSTALL_ID,
    worker_id: WORKER,
    device_id: deviceId,
    authorized_repository_scope: [REPO],
    admin_approval: mkAdmin(adminKeys, 'APPROVE_ENROLLMENT', deviceId, now),
  });
  return registry.completeEnrollment({
    challenge_id: ch.challenge_id,
    installation_id: INSTALL_ID,
    worker_id: WORKER,
    device_id: deviceId,
    public_key_spki_pem: signer.publicKeySpkiPem,
    browser_profile_identity: profileHash,
    native_bridge_identity: nativeHash,
    challenge_signature_b64url: signer.signEnrollmentChallenge({
      challenge: ch,
      browser_profile_identity: profileHash,
      native_bridge_identity: nativeHash,
    }),
  });
}

function makeMediatedClient(broker, signer, deviceId, generation, nowRef) {
  return {
    async executeLedgerOp(op) {
      const ledgerOp = {
        operation: op.operation,
        repository: op.repository,
        repository_id: op.repositoryId,
        installation_id: op.installationId,
        worker_id: op.workerId,
        pr_number: op.prNumber,
        head_sha: op.headSha,
        attempt_id: op.attemptId,
        ref_name: op.refName,
        ...(op.turnRefName !== undefined ? { turn_ref_name: op.turnRefName } : {}),
        ...(op.expectedParentSha !== undefined ? { expected_parent_sha: op.expectedParentSha } : {}),
        ...(op.isContinuation !== undefined ? { is_continuation: op.isContinuation } : {}),
        commit_message: op.commitMessage,
        tree_sha: op.treeSha,
      };
      return broker.executeServerMediatedLedgerOp({
        worker_id: op.workerId,
        device_assertion: signer.signDeviceAssertion({
          worker_id: op.workerId,
          device_id: deviceId,
          installation_id: op.installationId,
          enrollment_generation: generation,
          purpose: 'SERVER_MEDIATED_LEDGER_OP',
          repository: op.repository,
          nowMs: nowRef(),
          ledger_op: ledgerOp,
        }),
        ledger_op: ledgerOp,
      });
    },
  };
}

test('F4-04: Multi-host concurrent claim race, stale generation lockout, uncertain quarantine, and Turn 1/Turn 2 CAS coherence', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f4-multihost-'));
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

    const hostASigner = new DeviceKeyPairSigner();
    await enrollDevice(registry, adminKeys, 'host-a-device-01', hostASigner, '1'.repeat(64), '2'.repeat(64), now);

    // 1:1 active worker invariant: attempting to enroll a second active device for the same worker fails closed
    const hostBSigner = new DeviceKeyPairSigner();
    await assert.rejects(
      () =>
        registry.issueChallenge({
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          device_id: 'host-b-device-02',
          authorized_repository_scope: [REPO],
          admin_approval: mkAdmin(adminKeys, 'APPROVE_ENROLLMENT', 'host-b-device-02', now),
        }),
      /ENROLLMENT_DUPLICATE_WORKER_ACTIVE/,
    );

    const httpFetch = (url, init) =>
      globalThis.fetch(url, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() }));

    const tokenFor = (signer, devId, gen) => async () =>
      (
        await broker.mintScopedToken({
          repository: REPO,
          repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          requested_permissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: devId,
            installation_id: INSTALL_ID,
            enrollment_generation: gen,
            purpose: 'MINT_SCOPED_TOKEN',
            repository: REPO,
            nowMs: now,
          }),
        })
      ).token;

    // 1. Concurrent multi-host race (e.g., two host instances / cloned worker sessions racing on same attempt)
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-race-1', now + 180_000);
    const clientA1 = makeMediatedClient(broker, hostASigner, 'host-a-device-01', 1, () => now);
    const clientA2 = makeMediatedClient(broker, hostASigner, 'host-a-device-01', 1, () => now);

    const fenceA = await clientA1.executeLedgerOp({
      operation: 'COMMIT_PRE_SEND_FENCE',
      repository: REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      prNumber: PR_NUM,
      headSha: HEAD_A,
      attemptId: 'att-race-1',
      refName: `refs/bke/fences/${PR_NUM}/att-race-1`,
      commitMessage: JSON.stringify({
        bkeEvent: 'PRE_SEND_FENCE',
        version: 1,
        fenceId: 'fence-race-1',
        attemptId: 'att-race-1',
        workerId: WORKER,
        headSha: HEAD_A,
      }),
      treeSha: TREE_A,
    });
    assert.equal(fenceA.ok, true);

    const raceClaims = await Promise.all([
      clientA1.executeLedgerOp({
        operation: 'CONSUME_SEND_CLAIM',
        repository: REPO,
        repositoryId: REPO_ID,
        installationId: INSTALL_ID,
        workerId: WORKER,
        prNumber: PR_NUM,
        headSha: HEAD_A,
        attemptId: 'att-race-1',
        refName: `refs/bke/claims/${PR_NUM}/att-race-1`,
        commitMessage: 'claim proc-1',
        treeSha: TREE_A,
      }),
      clientA2.executeLedgerOp({
        operation: 'CONSUME_SEND_CLAIM',
        repository: REPO,
        repositoryId: REPO_ID,
        installationId: INSTALL_ID,
        workerId: WORKER,
        prNumber: PR_NUM,
        headSha: HEAD_A,
        attemptId: 'att-race-1',
        refName: `refs/bke/claims/${PR_NUM}/att-race-1`,
        commitMessage: 'claim proc-2',
        treeSha: TREE_A,
      }),
    ]);
    assert.equal(raceClaims.filter((r) => r.status === 'COMMITTED').length, 1);
    assert.equal(raceClaims.filter((r) => r.status === 'CONFLICT').length, 1);

    // 2. Stale host-a key rotated out to generation 2 -> old generation 1 fails everywhere
    const hostANewSigner = new DeviceKeyPairSigner();
    await registry.rotateDeviceKey({
      device_id: 'host-a-device-01',
      worker_id: WORKER,
      installation_id: INSTALL_ID,
      new_public_key_spki_pem: hostANewSigner.publicKeySpkiPem,
      new_key_proof_signature_b64url: hostANewSigner.signKeyRotationProof({
        device_id: 'host-a-device-01',
        worker_id: WORKER,
        installation_id: INSTALL_ID,
        new_generation: 2,
        nonce: 'rot-gen2-nonce',
      }),
      nonce: 'rot-gen2-nonce',
      admin_approval: mkAdmin(adminKeys, 'ROTATE_DEVICE_KEY', 'host-a-device-01', now),
    });

    await assert.rejects(
      () => tokenFor(hostASigner, 'host-a-device-01', 1)(),
      /DEVICE_ENROLLMENT_GENERATION_STALE/,
    );

    const pubKeys = await broker.getPublicVerificationKeys();
    const gen2Req = await broker.authorizeExecution({
      repository: REPO,
      expected_repository_id: REPO_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-race-1',
      action: 'PREPARE',
      device_assertion: hostANewSigner.signDeviceAssertion({
        worker_id: WORKER,
        device_id: 'host-a-device-01',
        installation_id: INSTALL_ID,
        enrollment_generation: 2,
        purpose: 'AUTHORIZE_EXECUTION',
        repository: REPO,
        nowMs: now,
      }),
      admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', 'host-a-device-01', now, {
        attempt_id: 'att-race-1',
        execution_action: 'PREPARE',
      }),
    });
    assert.equal(gen2Req.envelope.enrollment_generation, 2);

    const authProvA = new RestGitHubAuthorityProvider(httpFetch, tokenFor(hostANewSigner, 'host-a-device-01', 2), {
      baseApiUrl: mockGh.baseUrl,
      nowMs: () => now,
    });
    const gen3Verifier = new ExecutionRequestVerifier({
      expectedRepositoryOwner: OWNER,
      expectedRepositoryName: REPO_NAME,
      expectedRepositoryId: REPO_ID,
      expectedInstallationId: INSTALL_ID,
      expectedWorkerId: WORKER,
      pinnedApp: PINNED_APP,
      asymmetricV2Enabled: true,
      requireAsymmetricV2: true,
      publicKeysById: new Map(Object.entries(pubKeys.executionPublicKeys)),
      expectedAudience: AUDIENCE,
      expectedBrokerIssuer: ISSUER,
      expectedDeviceId: 'host-a-device-01',
      expectedEnrollmentGeneration: 3,
      deviceRevocationChecker: (info) => registry.inspectDeviceStatus(info),
      provider: authProvA,
      nowMs: () => now,
    });
    assert.equal((await gen3Verifier.verifyAndAuthorize(gen2Req)).code, 'EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH');

    // 3. Lost HTTP response on Host A during CONSUME_SEND_CLAIM quarantines PR & blocks replacement Host B
    mockGh.state.refs.clear();
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-mh-unc', now + 180_000);
    let liveSends = 0;
    const makeBrowserAdapter = (devTag) => {
      let seq = 0;
      return new ExtensionBrowserAdapter(
        {
          repository: REPO,
          prNumber: PR_NUM,
          headSha: HEAD_A,
          workerId: WORKER,
          targetId: `target-${devTag}`,
          profileId: `profile-${devTag}`,
          targetTabId: 1,
          nextSeq: () => ++seq,
        },
        {
          async sendCommand(cmd) {
            if (cmd.action === 'GET_TARGET_STATUS') {
              return {
                ok: true,
                code: 'TARGET_OK',
                payload: {
                  observedAt: new Date(now).toISOString(),
                  url: 'https://chatgpt.com/',
                  visible: true,
                  composerAvailable: true,
                  turnBusy: false,
                  uiState: 'NEW_CHAT_LANDING',
                  tabId: 1,
                  targetId: `target-${devTag}`,
                  profileId: `profile-${devTag}`,
                  matchingWritableTargetCount: 1,
                  sharedWritableProfile: false,
                },
              };
            }
            liveSends += 1;
            return {
              ok: true,
              code: 'FIRST_MESSAGE_SENT',
              payload: {
                beforeUrl: 'https://chatgpt.com/',
                afterUrl: 'https://chatgpt.com/c/conv-mh-01',
                conversationId: 'conv-mh-01',
                sendStartedAt: new Date(now).toISOString(),
                confirmedAt: new Date(now).toISOString(),
              },
            };
          },
        },
      );
    };

    const jHostA = new FileExecutionJournal(join(dir, 'journal-host-a.json'), {
      repository: REPO,
      prNumber: PR_NUM,
      workerId: WORKER,
    });
    const jHostB = new FileExecutionJournal(join(dir, 'journal-host-b.json'), {
      repository: REPO,
      prNumber: PR_NUM,
      workerId: WORKER,
    });

    const baseClientAGen2 = makeMediatedClient(broker, hostANewSigner, 'host-a-device-01', 2, () => now);
    const clientAGen2 = {
      async executeLedgerOp(op) {
        const res = await baseClientAGen2.executeLedgerOp(op);
        if (op.operation === 'CONSUME_SEND_CLAIM') {
          throw new Error('ECONNRESET_AFTER_CLAIM_POST');
        }
        return res;
      },
    };
    const makeLedgerFor = (signer, devId, gen, client) => (headSha) =>
      new GitHubF1Ledger(
        {
          repository: REPO,
          prNumber: PR_NUM,
          headSha,
          workerId: WORKER,
          authenticatedWorkerId: WORKER,
          pinnedApp: PINNED_APP,
          executionId: `exec-${devId}`,
          targetId: `target-${devId}`,
          profileId: `profile-${devId}`,
          targetTabId: 1,
          baseApiUrl: mockGh.baseUrl,
          nowIso: () => new Date(now).toISOString(),
          mediatedLedgerClient: client,
          expectedRepositoryId: REPO_ID,
          expectedInstallationId: INSTALL_ID,
          forbidDesktopWriteToken: true,
        },
        httpFetch,
        tokenFor(signer, devId, gen),
      );

    const ctrlA = new DesktopController({
      journal: jHostA,
      liveProofs: { githubCasOwnerCertified: true, nativePairingOwnerCertified: true, realBrowserOwnerAccepted: true },
      nowIso: () => new Date(now).toISOString(),
      createLedger: makeLedgerFor(hostANewSigner, 'host-a-device-01', 2, clientAGen2),
      createBrowserPorts: () => {
        const a = makeBrowserAdapter('host-a-device-01');
        return { firstMessage: a.asFirstMessagePort(), continuation: a.asContinuationPort() };
      },
    });
    await ctrlA.initialize();

    const wakeA = await ctrlA.processAuthorizedWake({
      headSha: HEAD_A,
      prNumber: PR_NUM,
      humanLiveSendAuthorized: true,
    });
    assert.equal(wakeA.status, 'BLOCKED');
    assert.equal(liveSends, 0);
    assert.equal(jHostA.current().phase, 'DELIVERY_UNCERTAIN');
    assert.ok(mockGh.state.refs.has(`${REPO}:refs/bke/uncertain/${PR_NUM}/att-mh-unc`));

    // Revoke Host A (simulating host replacement) and enroll fresh Host B
    await registry.revokeDevice({
      device_id: 'host-a-device-01',
      worker_id: WORKER,
      installation_id: INSTALL_ID,
      state: 'REVOKED',
      reason: 'HOST_A_REPLACED',
      admin_approval: mkAdmin(adminKeys, 'REVOKE_DEVICE', 'host-a-device-01', now),
    });
    await enrollDevice(registry, adminKeys, 'host-b-device-02', hostBSigner, '3'.repeat(64), '4'.repeat(64), now);

    // Host A is permanently blocked by revocation
    await assert.rejects(
      () => tokenFor(hostANewSigner, 'host-a-device-01', 2)(),
      /DEVICE_REVOKED/,
    );

    // Newly enrolled replacement Host B ALSO fails closed on PR #149 due to GitHub uncertain quarantine!
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-mh-unc',
          action: 'DISPATCH_FIRST_MESSAGE',
          device_assertion: hostBSigner.signDeviceAssertion({
            worker_id: WORKER,
            device_id: 'host-b-device-02',
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: now,
          }),
          admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', 'host-b-device-02', now, {
            attempt_id: 'att-mh-unc',
            execution_action: 'DISPATCH_FIRST_MESSAGE',
          }),
        }),
      /BROKER_DELIVERY_UNCERTAIN_QUARANTINED/,
    );

    const clientB = makeMediatedClient(broker, hostBSigner, 'host-b-device-02', 1, () => now);
    const ctrlB = new DesktopController({
      journal: jHostB,
      liveProofs: { githubCasOwnerCertified: true, nativePairingOwnerCertified: true, realBrowserOwnerAccepted: true },
      nowIso: () => new Date(now).toISOString(),
      createLedger: makeLedgerFor(hostBSigner, 'host-b-device-02', 1, clientB),
      createBrowserPorts: () => {
        const b = makeBrowserAdapter('host-b-device-02');
        return { firstMessage: b.asFirstMessagePort(), continuation: b.asContinuationPort() };
      },
    });
    await ctrlB.initialize();
    const wakeB = await ctrlB.processAuthorizedWake({
      headSha: HEAD_A,
      prNumber: PR_NUM,
      humanLiveSendAuthorized: true,
    });
    assert.equal(wakeB.status, 'BLOCKED');
    assert.equal(liveSends, 0);

    // 4. Turn 1 -> Turn 2 CAS fast-forward rejects stale expected_parent_sha so conversation cannot fork
    mockGh.state.refs.clear();
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-conv-1', now + 180_000);
    await clientB.executeLedgerOp({
      operation: 'COMMIT_PRE_SEND_FENCE',
      repository: REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      prNumber: PR_NUM,
      headSha: HEAD_A,
      attemptId: 'att-conv-1',
      refName: `refs/bke/fences/${PR_NUM}/att-conv-1`,
      commitMessage: JSON.stringify({
        bkeEvent: 'PRE_SEND_FENCE',
        version: 1,
        fenceId: 'fence-conv-1',
        attemptId: 'att-conv-1',
        workerId: WORKER,
        headSha: HEAD_A,
      }),
      treeSha: TREE_A,
    });
    await clientB.executeLedgerOp({
      operation: 'CONSUME_SEND_CLAIM',
      repository: REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      prNumber: PR_NUM,
      headSha: HEAD_A,
      attemptId: 'att-conv-1',
      refName: `refs/bke/claims/${PR_NUM}/att-conv-1`,
      commitMessage: 'claim 1',
      treeSha: TREE_A,
    });
    const convTurn1 = await clientB.executeLedgerOp({
      operation: 'RECONCILE_CONVERSATION',
      repository: REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      prNumber: PR_NUM,
      headSha: HEAD_A,
      attemptId: 'att-conv-1',
      refName: `refs/bke/conversations/${PR_NUM}`,
      isContinuation: false,
      commitMessage: JSON.stringify({
        bkeEvent: 'CONVERSATION_LEDGER_V1',
        version: 1,
        repository: REPO,
        prNumber: PR_NUM,
        workerId: WORKER,
        conversationId: 'conv-mh-cas-1',
        turns: [{ turnNumber: 1, attemptId: 'att-conv-1', headSha: HEAD_A }],
      }),
      treeSha: TREE_A,
    });
    assert.equal(convTurn1.ok, true);

    const staleTurn2 = await clientB.executeLedgerOp({
      operation: 'RECONCILE_CONVERSATION',
      repository: REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      prNumber: PR_NUM,
      headSha: HEAD_A,
      attemptId: 'att-conv-2',
      refName: `refs/bke/conversations/${PR_NUM}`,
      turnRefName: `refs/bke/turns/${PR_NUM}/att-conv-2`,
      expectedParentSha: '9'.repeat(40),
      isContinuation: true,
      commitMessage: JSON.stringify({
        bkeEvent: 'CONVERSATION_LEDGER_V1',
        version: 1,
        repository: REPO,
        prNumber: PR_NUM,
        workerId: WORKER,
        conversationId: 'conv-mh-cas-1',
        turns: [
          { turnNumber: 1, attemptId: 'att-conv-1', headSha: HEAD_A },
          { turnNumber: 2, attemptId: 'att-conv-2', headSha: HEAD_A },
        ],
      }),
      treeSha: TREE_A,
    });
    assert.equal(staleTurn2.ok, false);
    assert.equal(staleTurn2.status, 'CONFLICT');
    assert.equal(staleTurn2.code, 'BROKER_LEDGER_CONVERSATION_CAS_CONFLICT');
  } finally {
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});
