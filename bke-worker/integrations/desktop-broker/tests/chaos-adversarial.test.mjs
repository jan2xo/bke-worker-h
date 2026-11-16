/**
 * F3-07 All 18 Adversarial Reliability & Concurrency Chaos Scenarios + F3-05 GitHub Claim/Receipt Edge Cases.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DeviceEnrollmentRegistry, signAdminApproval } from '../dist/device-enrollment.js';
import { SandboxGitHubAppAdapter } from '../dist/github-app-adapter.js';
import { TrustedDesktopBroker } from '../dist/broker-service.js';
import { DeviceKeyPairSigner } from '../dist/broker-client.js';
import { startMockGitHubServer } from './mock-github-server.mjs';
import { ExecutionRequestVerifier } from '../../../browser-extension/native-host/claim/dist/native-host/claim/github-app-harness.js';
import { RestGitHubAuthorityProvider } from '../../../browser-extension/native-host/claim/dist/native-host/claim/github-authority-provider.js';
import { GitHubF1Ledger } from '../../../browser-extension/native-host/claim/dist/native-host/claim/github-f1-ledger.js';
import { ExtensionBrowserAdapter } from '../../../browser-extension/dist/extension-browser-adapter.js';
import {
  DesktopController,
  FileExecutionJournal,
} from '../../../browser-extension/native-host/claim/dist/native-host/claim/desktop-controller.js';
import { ManagedTokenProvider } from '../../../browser-extension/native-host/claim/dist/native-host/claim/token-lifecycle.js';
import { projectWorkerStateForCommandCenter } from '../../../browser-extension/native-host/claim/dist/native-host/claim/command-center-observer.js';

const REPO = 'jan2xo/bke-worker';
const [OWNER, REPO_NAME] = REPO.split('/');
const REPO_ID = 1354026486;
const INSTALL_ID = '987654321';
const WORKER = 'worker-f1';
const DEVICE = 'desktop-chaos-01';
const PR_NUM = 149;
const HEAD_A = 'a'.repeat(40);
const HEAD_B = 'b'.repeat(40);
const TREE_A = 'e'.repeat(40);
const PROFILE_HASH = '1'.repeat(64);
const NATIVE_HASH = '2'.repeat(64);
const ISSUER = 'https://broker.bke.chaos.local';
const AUDIENCE = `bke-desktop-controller:${REPO}:${WORKER}`;
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
      worker_id: WORKER,
      device_id: DEVICE,
      authorized_repository_scope: [REPO],
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      nonce: `adm-${Math.random().toString(16).slice(2)}`,
      issued_at: new Date(now - 1_000).toISOString(),
      expires_at: new Date(now + 90_000).toISOString(),
      ...extra,
    },
    adminKeys.privatePem,
    'admin-k1',
  );
}

test('F3-07 & F3-05: 18 chaos scenarios + Claim/Receipt fail-closed verification', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f3-chaos-'));
  let now = Date.parse('2026-10-20T12:00:00.000Z');
  const mockGh = await startMockGitHubServer({ installationId: INSTALL_ID });
  const adminKeys = genEd25519();
  const adminMap = new Map([['admin-k1', adminKeys.publicPem]]);

  const httpFetch = (url, init) =>
    globalThis.fetch(url, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() }));

  try {
    const storePath = join(dir, 'enroll.json');
    const statePath = join(dir, 'broker.json');
    const registry = new DeviceEnrollmentRegistry({ storePath, adminPublicKeysById: adminMap, nowMs: () => now });
    const ghAdapter = new SandboxGitHubAppAdapter({ appId: PINNED_APP.id, appSlug: PINNED_APP.slug, apiBaseUrl: mockGh.baseUrl, nowMs: () => now });
    const broker = new TrustedDesktopBroker({
      brokerIssuer: ISSUER,
      statePath,
      enrollmentRegistry: registry,
      githubAppAdapter: ghAdapter,
      adminPublicKeysById: adminMap,
      nowMs: () => now,
    });
    await broker.initialize();

    const signer = new DeviceKeyPairSigner();
    const ch = await registry.issueChallenge({
      installation_id: INSTALL_ID,
      worker_id: WORKER,
      device_id: DEVICE,
      authorized_repository_scope: [REPO],
      admin_approval: mkAdmin(adminKeys, 'APPROVE_ENROLLMENT', now),
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

    const tokenMint = async () =>
      broker.mintScopedToken({
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
          nowMs: now,
        }),
      });

    const mediatedLedgerClient = {
      async executeLedgerOp(op) {
        return broker.executeServerMediatedLedgerOp({
          worker_id: op.workerId,
          device_assertion: signer.signDeviceAssertion({
            worker_id: op.workerId,
            device_id: DEVICE,
            installation_id: op.installationId,
            enrollment_generation: 1,
            purpose: 'SERVER_MEDIATED_LEDGER_OP',
            repository: op.repository,
            nowMs: now,
            ledger_op: op.operation,
            pr_number: op.prNumber,
            head_sha: op.headSha,
            attempt_id: op.attemptId,
            ref_name: op.refName,
          }),
          ledger_op: {
            operation: op.operation,
            repository: op.repository,
            repository_id: op.repositoryId,
            installation_id: op.installationId,
            worker_id: op.workerId,
            pr_number: op.prNumber,
            head_sha: op.headSha,
            attempt_id: op.attemptId,
            ref_name: op.refName,
            turn_ref_name: op.turnRefName,
            expected_parent_sha: op.expectedParentSha,
            is_continuation: op.isContinuation,
            commit_message: op.commitMessage,
            tree_sha: op.treeSha,
          },
        });
      },
    };

    // Scenario 1 & 2 & 14: Broker crash before/after signing & delivery replay after restart
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-c1', now + 180_000);
    const signedBeforeCrash = await broker.authorizeExecution({
      repository: REPO,
      expected_repository_id: REPO_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-c1',
      action: 'DISPATCH_FIRST_MESSAGE',
      delivery_id: 'deliv-chaos-crash',
      device_assertion: signer.signDeviceAssertion({
        worker_id: WORKER,
        device_id: DEVICE,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'AUTHORIZE_EXECUTION',
        repository: REPO,
        nowMs: now,
      }),
      admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-c1', execution_action: 'DISPATCH_FIRST_MESSAGE' }),
    });
    const restartedBroker = new TrustedDesktopBroker({
      brokerIssuer: ISSUER,
      statePath,
      enrollmentRegistry: new DeviceEnrollmentRegistry({ storePath, adminPublicKeysById: adminMap, nowMs: () => now }),
      githubAppAdapter: ghAdapter,
      adminPublicKeysById: adminMap,
      nowMs: () => now,
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
          attempt_id: 'att-c1',
          action: 'DISPATCH_FIRST_MESSAGE',
          delivery_id: 'deliv-chaos-crash',
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: now,
          }),
          admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-c1', execution_action: 'DISPATCH_FIRST_MESSAGE' }),
        }),
      /BROKER_DELIVERY_REPLAYED/,
    );

    // Scenario 3, 4, 5, 13: Controller crash recovery across IDLE -> RESERVED -> DISPATCHING -> DELIVERY_UNCERTAIN
    const jCrashPath = join(dir, 'journal-crash.json');
    const jCrash = new FileExecutionJournal(jCrashPath, { repository: REPO, prNumber: PR_NUM, workerId: WORKER });
    assert.equal((await jCrash.openAndRecover()).phase, 'IDLE');
    await jCrash.transition({
      phase: 'RESERVED',
      activeAttemptId: 'att-res-1',
      activeReservation: { attemptId: 'att-res-1', ref: `refs/bke/claims/${PR_NUM}/att-res-1`, commitSha: HEAD_A },
    });
    const recRes = await new FileExecutionJournal(jCrashPath, { repository: REPO, prNumber: PR_NUM, workerId: WORKER }).openAndRecover();
    assert.equal(recRes.phase, 'IDLE');
    assert.ok(recRes.reservedAttempts.includes('att-res-1'));

    await jCrash.transition({ phase: 'DISPATCHING', activeAttemptId: 'att-disp-1', activeReservation: null });
    const recoveredUncertain = await new FileExecutionJournal(jCrashPath, { repository: REPO, prNumber: PR_NUM, workerId: WORKER }).openAndRecover();
    assert.equal(recoveredUncertain.phase, 'DELIVERY_UNCERTAIN');

    const authProv = new RestGitHubAuthorityProvider(
      httpFetch,
      async () => (await tokenMint()).token,
      { baseApiUrl: mockGh.baseUrl, nowMs: () => now },
    );
    const makeLedger = (headSha = HEAD_A) =>
      new GitHubF1Ledger(
        {
          repository: REPO,
          prNumber: PR_NUM,
          headSha,
          workerId: WORKER,
          authenticatedWorkerId: WORKER,
          pinnedApp: PINNED_APP,
          executionId: 'exec-chaos-01',
          targetId: 'target-chaos-01',
          profileId: 'profile-chaos-01',
          targetTabId: 1,
          baseApiUrl: mockGh.baseUrl,
          nowIso: () => new Date(now).toISOString(),
          mediatedLedgerClient,
          expectedRepositoryId: REPO_ID,
          expectedInstallationId: INSTALL_ID,
          forbidDesktopWriteToken: true,
        },
        httpFetch,
        async () => (await tokenMint()).token,
      );

    // Scenario 6: Browser adapter disconnects after send initiation -> DELIVERY_UNCERTAIN, zero auto-retry
    let seq6 = 0;
    const adapter6 = new ExtensionBrowserAdapter(
      {
        repository: REPO,
        prNumber: PR_NUM,
        headSha: HEAD_A,
        workerId: WORKER,
        targetId: 'target-chaos-01',
        profileId: 'profile-chaos-01',
        targetTabId: 1,
        nextSeq: () => ++seq6,
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
                targetId: 'target-chaos-01',
                profileId: 'profile-chaos-01',
                matchingWritableTargetCount: 1,
                sharedWritableProfile: false,
              },
            };
          }
          if (cmd.action === 'DISPATCH_FIRST_MESSAGE') {
            return { ok: false, uncertain: true, code: 'NATIVE_BRIDGE_DISCONNECTED_AFTER_CLICK' };
          }
          return { ok: false, code: 'UNKNOWN_CMD' };
        },
      },
    );
    const jDisconn = new FileExecutionJournal(join(dir, 'journal-disconn.json'), { repository: REPO, prNumber: PR_NUM, workerId: WORKER });
    const ctrlDisconn = new DesktopController({
      journal: jDisconn,
      liveProofs: { githubCasOwnerCertified: true, nativePairingOwnerCertified: true, realBrowserOwnerAccepted: true },
      nowIso: () => new Date(now).toISOString(),
      createLedger: makeLedger,
      createBrowserPorts: () => ({
        firstMessage: adapter6.asFirstMessagePort(),
        continuation: adapter6.asContinuationPort(),
      }),
    });
    await ctrlDisconn.initialize();
    const outcome6 = await ctrlDisconn.processAuthorizedWake({
      headSha: HEAD_A,
      prNumber: PR_NUM,
      humanLiveSendAuthorized: true,
    });
    assert.equal(outcome6.status, 'BLOCKED');
    assert.equal(jDisconn.current().phase, 'DELIVERY_UNCERTAIN');
    assert.ok(mockGh.state.refs.has(`${REPO}:refs/bke/uncertain/${PR_NUM}/att-c1`));
    // Reset repo refs from scenario 6 so later scenarios run cleanly
    mockGh.state.refs.clear();

    // Scenario 7 & F3-05 Claim transport ambiguity + readBack mismatch + duplicate claim conflict
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-drop-1', now + 180_000);
    const ledgerDrop = makeLedger(HEAD_A);
    const fenceDropRes = await ledgerDrop.commitPreSendFence({
      durable: true,
      fenceId: 'fence-drop-01',
      commitSha: HEAD_A,
      attemptId: 'att-drop-1',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-chaos-01',
      profileId: 'profile-chaos-01',
      targetTabId: 1,
      executionId: 'exec-chaos-01',
      generation: 1,
      committedAt: new Date(now).toISOString(),
    });
    assert.equal(fenceDropRes.status, 'COMMITTED');
    mockGh.state.dropAfterMutateCount = 1;
    const dropClaimRes = await ledgerDrop.consumeFirstSendClaim({
      durable: true,
      claimId: 'claim-drop-01',
      commitSha: HEAD_A,
      fenceId: 'fence-drop-01',
      fenceCommitSha: fenceDropRes.commitSha,
      attemptId: 'att-drop-1',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-chaos-01',
      profileId: 'profile-chaos-01',
      targetTabId: 1,
      executionId: 'exec-chaos-01',
      generation: 1,
      claimedAt: new Date(now).toISOString(),
    });
    assert.equal(dropClaimRes.status, 'UNCERTAIN');
    assert.ok(mockGh.state.refs.has(`${REPO}:refs/bke/claims/${PR_NUM}/att-drop-1`));

    mockGh.state.refs.clear();
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-lie-1', now + 180_000);
    const ledgerLie = makeLedger(HEAD_A);
    const fenceLie = await ledgerLie.commitPreSendFence({
      durable: true,
      fenceId: 'fence-lie-01',
      commitSha: HEAD_A,
      attemptId: 'att-lie-1',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-chaos-01',
      profileId: 'profile-chaos-01',
      targetTabId: 1,
      executionId: 'exec-chaos-01',
      generation: 1,
      committedAt: new Date(now).toISOString(),
    });
    assert.equal(fenceLie.status, 'COMMITTED');
    const claimLie = await ledgerLie.consumeFirstSendClaim({
      durable: true,
      claimId: 'claim-lie-01',
      commitSha: HEAD_A,
      fenceId: 'fence-lie-01',
      fenceCommitSha: fenceLie.commitSha,
      attemptId: 'att-lie-1',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-chaos-01',
      profileId: 'profile-chaos-01',
      targetTabId: 1,
      executionId: 'exec-chaos-01',
      generation: 1,
      claimedAt: new Date(now).toISOString(),
    });
    assert.equal(claimLie.status, 'COMMITTED');
    mockGh.state.lyingReadBackSha = '9'.repeat(40);
    assert.equal(await ledgerLie.readBackFirstSendClaim(HEAD_A), false);
    mockGh.state.lyingReadBackSha = null;

    // Second consume on same ref triggers fail-closed CONFLICT (simulate concurrent writer after fence)
    mockGh.state.refs.clear();
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-dup-1', now + 180_000);
    const ledgerDup = makeLedger(HEAD_A);
    const dupFence = await ledgerDup.commitPreSendFence({
      durable: true,
      fenceId: 'fence-dup-01',
      commitSha: HEAD_A,
      attemptId: 'att-dup-1',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-chaos-01',
      profileId: 'profile-chaos-01',
      targetTabId: 1,
      executionId: 'exec-chaos-01',
      generation: 1,
      committedAt: new Date(now).toISOString(),
    });
    assert.equal(dupFence.status, 'COMMITTED');
    mockGh.state.refs.set(`${REPO}:refs/bke/claims/${PR_NUM}/att-dup-1`, HEAD_A);
    const dupClaim = await ledgerDup.consumeFirstSendClaim({
      durable: true,
      claimId: 'claim-dup-01',
      commitSha: HEAD_A,
      fenceId: 'fence-dup-01',
      fenceCommitSha: dupFence.commitSha,
      attemptId: 'att-dup-1',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-chaos-01',
      profileId: 'profile-chaos-01',
      targetTabId: 1,
      executionId: 'exec-chaos-01',
      generation: 1,
      claimedAt: new Date(now).toISOString(),
    });
    assert.equal(dupClaim.status, 'CONFLICT');
    mockGh.state.refs.clear();
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-c1', now + 180_000);

    // Scenario 8 & 9: Two workers request same PR vs One worker assigned two PRs
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: 'worker-two',
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-c1',
          action: 'PREPARE',
          device_assertion: signer.signDeviceAssertion({
            worker_id: 'worker-two',
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: now,
          }),
          admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { worker_id: 'worker-two', attempt_id: 'att-c1' }),
        }),
      /DEVICE_WORKER_MISMATCH/,
    );
    mockGh.state.repos[0].prs.push({ number: 150, state: 'open', headSha: HEAD_A, labels: [`bke-worker:${WORKER}`] });
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-c1',
          action: 'PREPARE',
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: now,
          }),
          admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-c1', execution_action: 'PREPARE' }),
        }),
      /BROKER_MULTI_PR_CONFLICT/,
    );
    mockGh.state.repos[0].prs.pop();

    // Scenario 10: Device revoked during execution -> Verifier rejects V2 envelope via revocationChecker
    const pubKeys = await broker.getPublicVerificationKeys();
    const verifierRevoked = new ExecutionRequestVerifier({
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
      expectedDeviceId: DEVICE,
      minEnrollmentGeneration: 1,
      deviceRevocationChecker: () => ({ revoked: true, code: 'EXEC_REQ_DEVICE_REVOKED' }),
      provider: authProv,
      nowMs: () => now,
    });
    const r10 = await verifierRevoked.verifyAndAuthorize(signedBeforeCrash);
    assert.equal(r10.ok, false);
    assert.equal(r10.code, 'EXEC_REQ_DEVICE_REVOKED');

    // Scenario 11: Signing key rotates k1 -> k2 during active window -> dual keys verify k1 AND k2
    await broker.rotateSigningKey({
      role: 'EXECUTION',
      newKeyId: 'broker-exec-k2',
      admin_approval: mkAdmin(adminKeys, 'ROTATE_BROKER_SIGNING_KEY', now),
    });
    const rotatedPubs = await broker.getPublicVerificationKeys();
    const signedK2 = await broker.authorizeExecution({
      repository: REPO,
      expected_repository_id: REPO_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-c1',
      action: 'PREPARE',
      device_assertion: signer.signDeviceAssertion({
        worker_id: WORKER,
        device_id: DEVICE,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'AUTHORIZE_EXECUTION',
        repository: REPO,
        nowMs: now,
      }),
      admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-c1', execution_action: 'PREPARE' }),
    });
    const dualVerifier = new ExecutionRequestVerifier({
      expectedRepositoryOwner: OWNER,
      expectedRepositoryName: REPO_NAME,
      expectedRepositoryId: REPO_ID,
      expectedInstallationId: INSTALL_ID,
      expectedWorkerId: WORKER,
      pinnedApp: PINNED_APP,
      asymmetricV2Enabled: true,
      requireAsymmetricV2: true,
      publicKeysById: new Map(Object.entries(rotatedPubs.executionPublicKeys)),
      expectedAudience: AUDIENCE,
      expectedBrokerIssuer: ISSUER,
      expectedDeviceId: DEVICE,
      expectedEnrollmentGeneration: 1,
      minEnrollmentGeneration: 1,
      deviceRevocationChecker: (info) => registry.inspectDeviceStatus(info),
      provider: authProv,
      nowMs: () => now,
    });
    assert.equal((await dualVerifier.verifyAndAuthorize(signedBeforeCrash)).ok, true);
    assert.equal((await dualVerifier.verifyAndAuthorize(signedK2)).ok, true);

    // Scenario 12: GitHub head changes during authorization
    mockGh.state.repos[0].prs[0].headSha = HEAD_B;
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-c1',
          action: 'PREPARE',
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
            nowMs: now,
          }),
          admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-c1', execution_action: 'PREPARE' }),
        }),
      /BROKER_HEAD_SHA_STALE/,
    );
    mockGh.state.repos[0].prs[0].headSha = HEAD_A;

    // Scenario 15: Expired signed request rejected
    const verifierFuture = new ExecutionRequestVerifier({
      expectedRepositoryOwner: OWNER,
      expectedRepositoryName: REPO_NAME,
      expectedRepositoryId: REPO_ID,
      expectedInstallationId: INSTALL_ID,
      expectedWorkerId: WORKER,
      pinnedApp: PINNED_APP,
      asymmetricV2Enabled: true,
      requireAsymmetricV2: true,
      publicKeysById: new Map(Object.entries(rotatedPubs.executionPublicKeys)),
      expectedAudience: AUDIENCE,
      expectedBrokerIssuer: ISSUER,
      expectedDeviceId: DEVICE,
      expectedEnrollmentGeneration: 1,
      minEnrollmentGeneration: 1,
      deviceRevocationChecker: (info) => registry.inspectDeviceStatus(info),
      provider: authProv,
      nowMs: () => now + 600_000,
    });
    assert.equal((await verifierFuture.verifyAndAuthorize(signedBeforeCrash)).code, 'EXEC_REQ_EXPIRED');

    // Scenario 16: Bounded pre-claim token retry fails cleanly on timeout when exhausted
    const mProv = new ManagedTokenProvider(
      {
        repository: REPO,
        repositoryId: REPO_ID,
        installationId: INSTALL_ID,
        workerId: WORKER,
        allowedPermissions: { contents: 'write' },
        maxTransientRetries: 1,
        retryDelayMs: 5,
      },
      {
        kind: 'REMOTE_OWNER_CERTIFIED_BROKER',
        issueToken: async () => {
          throw new Error('TOKEN_BROKER_TIMEOUT');
        },
        isRevoked: async () => false,
      },
    );
    await assert.rejects(() => mProv.getToken(), /TOKEN_BROKER_TIMEOUT/);
    assert.equal(mProv.getStatus().lastRecoveryClassification, 'BLOCKED_PERMANENT');

    // Scenario 17: Browser target switches conversation ID mid-flight on Turn 2
    mockGh.state.refs.clear();
    const convSha = 'd'.repeat(40);
    mockGh.state.commits.set(`${REPO}:${convSha}`, {
      sha: convSha,
      tree: { sha: TREE_A },
      parents: [HEAD_A],
      message: JSON.stringify({
        bkeEvent: 'CONVERSATION_LEDGER_V1',
        version: 1,
        repository: REPO,
        prNumber: PR_NUM,
        workerId: WORKER,
        conversationId: 'conv-expected-01',
        turns: [
          {
            turnNumber: 1,
            attemptId: 'att-prev-1',
            headSha: HEAD_A,
            conversationId: 'conv-expected-01',
            beforeUrl: 'https://chatgpt.com/',
            afterUrl: 'https://chatgpt.com/c/conv-expected-01',
            fenceId: 'fence-prev-01',
            sendClaimId: 'claim-prev-01',
            recordedAt: new Date(now - 60_000).toISOString(),
          },
        ],
      }),
    });
    mockGh.state.refs.set(`${REPO}:refs/bke/conversations/${PR_NUM}`, convSha);
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-drift-2', now + 180_000);

    const jT2 = new FileExecutionJournal(join(dir, 'journal-t2-drift.json'), { repository: REPO, prNumber: PR_NUM, workerId: WORKER });
    await jT2.openAndRecover();
    await jT2.transition({
      phase: 'CONFIRMED_CONVERSATION',
      conversationId: 'conv-expected-01',
      conversationUrl: 'https://chatgpt.com/c/conv-expected-01',
      confirmedTurnCount: 1,
    });
    let seq17 = 0;
    let driftSubmits = 0;
    const adapter17 = new ExtensionBrowserAdapter(
      {
        repository: REPO,
        prNumber: PR_NUM,
        headSha: HEAD_A,
        workerId: WORKER,
        targetId: 'target-chaos-01',
        profileId: 'profile-chaos-01',
        targetTabId: 1,
        nextSeq: () => ++seq17,
      },
      {
        async sendCommand(cmd) {
          if (cmd.action === 'GET_TARGET_STATUS') {
            return {
              ok: true,
              code: 'TARGET_OK',
              payload: {
                observedAt: new Date(now).toISOString(),
                url: 'https://chatgpt.com/c/conv-hijacked-99',
                visible: true,
                composerAvailable: true,
                turnBusy: false,
                uiState: 'THREAD',
                tabId: 1,
                targetId: 'target-chaos-01',
                profileId: 'profile-chaos-01',
                matchingWritableTargetCount: 1,
                sharedWritableProfile: false,
              },
            };
          }
          driftSubmits += 1;
          return { ok: false, code: 'UNEXPECTED_DISPATCH' };
        },
      },
    );
    const ctrlDrift = new DesktopController({
      journal: jT2,
      liveProofs: { githubCasOwnerCertified: true, nativePairingOwnerCertified: true, realBrowserOwnerAccepted: true },
      nowIso: () => new Date(now).toISOString(),
      createLedger: makeLedger,
      createBrowserPorts: () => ({
        firstMessage: adapter17.asFirstMessagePort(),
        continuation: adapter17.asContinuationPort(),
      }),
    });
    await ctrlDrift.initialize();
    const driftRes = await ctrlDrift.processAuthorizedWake({
      headSha: HEAD_A,
      prNumber: PR_NUM,
      humanLiveSendAuthorized: true,
    });
    assert.equal(driftRes.status, 'BLOCKED');
    assert.equal(driftSubmits, 0);

    // Scenario 18: Command Center receives partial evidence -> stays fail-closed
    const partialCC = projectWorkerStateForCommandCenter({
      observedAtMs: now,
      nowMs: now,
      githubAssignment: {
        repository: REPO,
        prNumber: PR_NUM,
        workerId: WORKER,
        headSha: HEAD_A,
        openPrCountForWorker: 1,
        workerLabelsOnPr: 1,
        atomicRevalidated: true,
        uncertainRefCount: 0,
      },
    });
    assert.equal(partialCC.dispatchReady, false);
    assert.equal(partialCC.evidenceIncomplete, true);
    assert.ok(partialCC.visibleStates.includes('EVIDENCE_INCOMPLETE'));
    assert.equal(partialCC.executionState, 'UNKNOWN');
    assert.ok(TREE_A.length === 40);
  } finally {
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});
