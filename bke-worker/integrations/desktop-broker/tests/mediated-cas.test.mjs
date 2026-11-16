/**
 * F4 P0-02 & P0-03 Server-Mediated GitHub CAS + Ed25519 Signed HTTP Revocation Fault Matrix.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
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
import { GitHubF1Ledger } from '../../../browser-extension/native-host/claim/dist/native-host/claim/github-f1-ledger.js';
import { ManagedTokenProvider } from '../../../browser-extension/native-host/claim/dist/native-host/claim/token-lifecycle.js';

const REPO = 'jan2xo/bke-worker';
const REPO_ID = 1354026486;
const INSTALL_ID = '987654321';
const WORKER = 'worker-f1';
const DEVICE = 'desktop-f4-cas-01';
const PR_NUM = 149;
const HEAD_A = 'a'.repeat(40);
const TREE_A = 'e'.repeat(40);
const PROFILE_HASH = '1'.repeat(64);
const NATIVE_HASH = '2'.repeat(64);
const ISSUER = 'https://broker.bke.f4.local';
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
      expires_at: new Date(now + 120_000).toISOString(),
      ...extra,
    },
    adminKeys.privatePem,
    'admin-k1',
  );
}

test('F4 P0-03: All 4 Server-Mediated GitHub CAS operations succeed without desktop contents:write tokens and reject arbitrary proxies', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f4-cas-'));
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

    httpBroker = new SandboxBrokerHttpServer(broker, registry);
    const { port } = await httpBroker.start();
    const pubKeys = await broker.getPublicVerificationKeys();

    const brokerClient = new SandboxHttpTokenBrokerClient({
      brokerBaseUrl: `http://127.0.0.1:${port}`,
      deviceId: DEVICE,
      enrollmentGeneration: 1,
      deviceSigner: signer,
      brokerPublicKeysById: new Map(Object.entries(pubKeys.executionPublicKeys)),
      expectedBrokerIssuer: ISSUER,
      repository: REPO,
      installationId: INSTALL_ID,
      workerId: WORKER,
      nowMs: () => now,
    });

    const tokenLifecycle = new ManagedTokenProvider(
      {
        repository: REPO,
        repositoryId: REPO_ID,
        installationId: INSTALL_ID,
        workerId: WORKER,
        allowedPermissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
        nowMs: () => now,
      },
      brokerClient,
    );

    // 1. Desktop token mint is strictly read-only; write token rejected at broker
    await assert.rejects(
      () =>
        broker.mintScopedToken({
          repository: REPO,
          repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          requested_permissions: { contents: 'write', pull_requests: 'read' },
          device_assertion: signer.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'MINT_SCOPED_TOKEN',
            repository: REPO,
            nowMs: now,
          }),
        }),
      /BROKER_DESKTOP_WRITE_TOKEN_FORBIDDEN/,
    );

    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-cas-t1', now + 180_000);
    const ledger = new GitHubF1Ledger(
      {
        repository: REPO,
        prNumber: PR_NUM,
        headSha: HEAD_A,
        workerId: WORKER,
        authenticatedWorkerId: WORKER,
        pinnedApp: PINNED_APP,
        executionId: 'exec-f4-cas-01',
        targetId: 'target-f4-01',
        profileId: 'profile-f4-01',
        targetTabId: 1,
        baseApiUrl: mockGh.baseUrl,
        nowIso: () => new Date(now).toISOString(),
        mediatedLedgerClient: brokerClient,
        expectedRepositoryId: REPO_ID,
        expectedInstallationId: INSTALL_ID,
        forbidDesktopWriteToken: true,
      },
      (url, init) => globalThis.fetch(url, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() })),
      tokenLifecycle.asTokenProvider(),
    );

    // Turn 1 via GitHubF1Ledger mediated CAS: fence -> claim (ref -> HEAD_A, no extra commit) -> conversation receipt
    const fence1 = await ledger.commitPreSendFence({
      durable: true,
      fenceId: 'fence-t1',
      commitSha: HEAD_A,
      attemptId: 'att-cas-t1',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-f4-01',
      profileId: 'profile-f4-01',
      targetTabId: 1,
      executionId: 'exec-f4-cas-01',
      generation: 1,
      committedAt: new Date(now).toISOString(),
    });
    assert.equal(fence1.status, 'COMMITTED');

    const commitsBeforeClaim = mockGh.state.commits.size;
    const claim1 = await ledger.consumeFirstSendClaim({
      durable: true,
      claimId: 'claim-t1',
      commitSha: HEAD_A,
      fenceId: 'fence-t1',
      fenceCommitSha: fence1.commitSha,
      attemptId: 'att-cas-t1',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-f4-01',
      profileId: 'profile-f4-01',
      targetTabId: 1,
      executionId: 'exec-f4-cas-01',
      generation: 1,
      claimedAt: new Date(now).toISOString(),
    });
    assert.equal(claim1.status, 'COMMITTED');
    assert.equal(mockGh.state.commits.size, commitsBeforeClaim, 'CONSUME_SEND_CLAIM must NOT create an extra commit');
    assert.equal(mockGh.state.refs.get(`${REPO}:refs/bke/claims/${PR_NUM}/att-cas-t1`), HEAD_A);

    // Duplicate claim fails closed with CONFLICT
    const dupClaim = await ledger.consumeFirstSendClaim({
      durable: true,
      claimId: 'claim-t1-dup',
      commitSha: HEAD_A,
      fenceId: 'fence-t1',
      fenceCommitSha: fence1.commitSha,
      attemptId: 'att-cas-t1',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-f4-01',
      profileId: 'profile-f4-01',
      targetTabId: 1,
      executionId: 'exec-f4-cas-01',
      generation: 1,
      claimedAt: new Date(now).toISOString(),
    });
    assert.equal(dupClaim.status, 'CONFLICT');

    const conv1 = await ledger.reconcileConversation({
      attemptId: 'att-cas-t1',
      workerId: WORKER,
      headSha: HEAD_A,
      conversationId: 'conv-f4-0001',
      beforeUrl: 'https://chatgpt.com/',
      afterUrl: 'https://chatgpt.com/c/conv-f4-0001',
      fenceId: 'fence-t1',
      sendClaimId: 'claim-t1',
      sendClaimCommitSha: HEAD_A,
      confirmedAt: new Date(now).toISOString(),
    });
    assert.equal(conv1.ok, true);
    const tipTurn1 = mockGh.state.refs.get(`${REPO}:refs/bke/conversations/${PR_NUM}`);
    assert.ok(tipTurn1);

    // Turn 2 CAS fast-forward via RECONCILE_CONVERSATION + immutable refs/bke/turns/149/att-cas-t2
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-cas-t2', now + 180_000);
    const ledgerT2 = new GitHubF1Ledger(
      {
        repository: REPO,
        prNumber: PR_NUM,
        headSha: HEAD_A,
        workerId: WORKER,
        authenticatedWorkerId: WORKER,
        pinnedApp: PINNED_APP,
        executionId: 'exec-f4-cas-02',
        targetId: 'target-f4-01',
        profileId: 'profile-f4-01',
        targetTabId: 1,
        baseApiUrl: mockGh.baseUrl,
        nowIso: () => new Date(now).toISOString(),
        mediatedLedgerClient: brokerClient,
        expectedRepositoryId: REPO_ID,
        expectedInstallationId: INSTALL_ID,
        forbidDesktopWriteToken: true,
      },
      (url, init) => globalThis.fetch(url, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() })),
      tokenLifecycle.asTokenProvider(),
    );
    const fence2 = await ledgerT2.commitPreSendFence({
      durable: true,
      fenceId: 'fence-t2',
      commitSha: HEAD_A,
      attemptId: 'att-cas-t2',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-f4-01',
      profileId: 'profile-f4-01',
      targetTabId: 1,
      executionId: 'exec-f4-cas-02',
      generation: 1,
      committedAt: new Date(now).toISOString(),
    });
    assert.equal(fence2.status, 'COMMITTED');
    const claim2 = await ledgerT2.consumeFirstSendClaim({
      durable: true,
      claimId: 'claim-t2',
      commitSha: HEAD_A,
      fenceId: 'fence-t2',
      fenceCommitSha: fence2.commitSha,
      attemptId: 'att-cas-t2',
      workerId: WORKER,
      headSha: HEAD_A,
      targetId: 'target-f4-01',
      profileId: 'profile-f4-01',
      targetTabId: 1,
      executionId: 'exec-f4-cas-02',
      generation: 1,
      claimedAt: new Date(now).toISOString(),
    });
    assert.equal(claim2.status, 'COMMITTED');
    const conv2 = await ledgerT2.reconcileContinuationTurn({
      attemptId: 'att-cas-t2',
      workerId: WORKER,
      headSha: HEAD_A,
      conversationId: 'conv-f4-0001',
      turnNumber: 2,
      beforeUrl: 'https://chatgpt.com/c/conv-f4-0001',
      afterUrl: 'https://chatgpt.com/c/conv-f4-0001',
      fenceId: 'fence-t2',
      sendClaimId: 'claim-t2',
      sendClaimCommitSha: HEAD_A,
      confirmedAt: new Date(now).toISOString(),
    });
    assert.equal(conv2.ok, true);
    assert.ok(mockGh.state.refs.has(`${REPO}:refs/bke/turns/${PR_NUM}/att-cas-t2`));
    assert.notEqual(mockGh.state.refs.get(`${REPO}:refs/bke/conversations/${PR_NUM}`), tipTurn1);

    // Arbitrary force / arbitrary ref / mismatched turn ref rejected by broker
    for (const badReq of [
      {
        operation: 'COMMIT_PRE_SEND_FENCE',
        refName: 'refs/heads/main',
        commitMessage: 'bad main',
      },
      {
        operation: 'RECONCILE_CONVERSATION',
        refName: `refs/bke/conversations/${PR_NUM}`,
        turnRefName: 'refs/heads/main',
        commitMessage: JSON.stringify({ bkeEvent: 'CONVERSATION_LEDGER_V1', version: 1, repository: REPO, prNumber: PR_NUM, workerId: WORKER, conversationId: 'conv-f4-0001', turns: [{ turnNumber: 1 }] }),
      },
    ]) {
      const badRes = await brokerClient.executeLedgerOp({
        operation: badReq.operation,
        repository: REPO,
        repositoryId: REPO_ID,
        installationId: INSTALL_ID,
        workerId: WORKER,
        prNumber: PR_NUM,
        headSha: HEAD_A,
        attemptId: 'att-evil-1',
        refName: badReq.refName,
        turnRefName: badReq.turnRefName,
        commitMessage: badReq.commitMessage,
        treeSha: TREE_A,
      });
      assert.equal(badRes.ok, false);
      assert.equal(badRes.code, 'BROKER_ARBITRARY_PROXY_FORBIDDEN');
    }

    // force: true rejected over HTTP
    const forceBaseOp = {
      operation: 'COMMIT_PRE_SEND_FENCE',
      repository: REPO,
      repository_id: REPO_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-force-1',
      ref_name: `refs/bke/fences/${PR_NUM}/att-force-1`,
      commit_message: JSON.stringify({
        bkeEvent: 'PRE_SEND_FENCE',
        version: 1,
        fenceId: 'fence-force-1',
        attemptId: 'att-force-1',
        workerId: WORKER,
        headSha: HEAD_A,
      }),
      tree_sha: TREE_A,
    };
    const forceRes = await fetch(`http://127.0.0.1:${port}/v1/broker/ledger-ops`, {
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
          nowMs: now,
          ledger_op: forceBaseOp,
        }),
        ledger_op: {
          ...forceBaseOp,
          force: true,
        },
      }),
    });
    assert.equal(forceRes.status, 409);
    assert.equal((await forceRes.json()).code, 'BROKER_ARBITRARY_PROXY_FORBIDDEN');

    // MARK_DELIVERY_UNCERTAIN: requires prior durable PRE_SEND_FENCE owned by worker, then COMMITTED -> idempotent ALREADY_EXISTS
    const uncFence = await brokerClient.executeLedgerOp({
      operation: 'COMMIT_PRE_SEND_FENCE',
      repository: REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      prNumber: PR_NUM,
      headSha: HEAD_A,
      attemptId: 'att-cas-unc-1',
      refName: `refs/bke/fences/${PR_NUM}/att-cas-unc-1`,
      commitMessage: JSON.stringify({
        bkeEvent: 'PRE_SEND_FENCE',
        version: 1,
        fenceId: 'fence-unc-1',
        attemptId: 'att-cas-unc-1',
        workerId: WORKER,
        headSha: HEAD_A,
      }),
      treeSha: TREE_A,
    });
    assert.equal(uncFence.ok, true);
    assert.equal(uncFence.status, 'COMMITTED');

    const unc1 = await brokerClient.executeLedgerOp({
      operation: 'MARK_DELIVERY_UNCERTAIN',
      repository: REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      prNumber: PR_NUM,
      headSha: HEAD_A,
      attemptId: 'att-cas-unc-1',
      refName: `refs/bke/uncertain/${PR_NUM}/att-cas-unc-1`,
      commitMessage: 'uncertain',
      treeSha: TREE_A,
    });
    assert.equal(unc1.ok, true);
    assert.equal(unc1.status, 'COMMITTED');

    const unc2 = await brokerClient.executeLedgerOp({
      operation: 'MARK_DELIVERY_UNCERTAIN',
      repository: REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      prNumber: PR_NUM,
      headSha: HEAD_A,
      attemptId: 'att-cas-unc-1',
      refName: `refs/bke/uncertain/${PR_NUM}/att-cas-unc-1`,
      commitMessage: 'uncertain',
      treeSha: TREE_A,
    });
    assert.equal(unc2.ok, true);
    assert.equal(unc2.status, 'ALREADY_EXISTS');
  } finally {
    await httpBroker?.stop();
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('F4 P0-02: Ed25519 Signed HTTP Revocation & Token Status checks fail closed across full fault matrix', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f4-rev-'));
  let now = Date.parse('2026-10-20T12:00:00.000Z');
  const mockGh = await startMockGitHubServer({ installationId: INSTALL_ID });
  const adminKeys = genEd25519();
  const rogueKeys = genEd25519();
  const adminMap = new Map([['admin-k1', adminKeys.publicPem]]);

  let httpBroker;
  let proxyServer;

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

    httpBroker = new SandboxBrokerHttpServer(broker, registry);
    const { port: realPort } = await httpBroker.start();
    const pubKeys = await broker.getPublicVerificationKeys();

    const brokerState = JSON.parse(await readFile(join(dir, 'broker.json'), 'utf8'));
    const activeExecKey = brokerState.signingKeys.find((k) => k.role === 'EXECUTION' && k.status === 'ACTIVE');
    const resignStatus = (domain, payloadObj) => {
      const ordered = {};
      for (const k of Object.keys(payloadObj).sort()) ordered[k] = payloadObj[k];
      return {
        payload: payloadObj,
        signature_alg: 'Ed25519',
        key_id: activeExecKey.key_id,
        signature_b64url: cryptoSign(
          null,
          Buffer.from(domain + JSON.stringify(ordered), 'utf8'),
          activeExecKey.private_key_pem,
        ).toString('base64url'),
      };
    };

    // Fault-injecting proxy sitting in front of the real SandboxBrokerHttpServer
    let faultMode = 'PASS_THROUGH';
    proxyServer = createServer(async (req, res) => {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const rawBody = Buffer.concat(chunks).toString('utf8');

      if (req.url === '/v1/enrollment/status' || req.url === '/v1/broker/token-status') {
        if (faultMode === 'HTTP_500') {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false }));
          return;
        }
        if (faultMode === 'REDIRECT_302') {
          res.writeHead(302, { Location: 'https://evil.example/status' });
          res.end();
          return;
        }
        if (faultMode === 'TIMEOUT') {
          await new Promise((r) => setTimeout(r, 200));
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
          return;
        }
        if (faultMode === 'MALFORMED_JSON') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{not-json');
          return;
        }
      }

      const upstream = await fetch(`http://127.0.0.1:${realPort}${req.url}`, {
        method: req.method,
        headers: { 'Content-Type': 'application/json' },
        body: req.method === 'GET' ? undefined : rawBody,
      });
      const json = await upstream.json();

      if ((req.url === '/v1/enrollment/status' || req.url === '/v1/broker/token-status') && json.signed_status) {
        const domain = req.url === '/v1/enrollment/status' ? 'BKE_DEVICE_STATUS_V1\n' : 'BKE_TOKEN_STATUS_V1\n';
        if (faultMode === 'UNSIGNED') {
          delete json.signed_status;
        } else if (faultMode === 'BAD_SIG') {
          json.signed_status.signature_b64url = 'A'.repeat(86);
        } else if (faultMode === 'WRONG_KEY_ID') {
          json.signed_status.key_id = 'rogue-k99';
        } else if (faultMode === 'WRONG_NONCE') {
          json.signed_status = resignStatus(domain, { ...json.signed_status.payload, nonce: 'replayed-stale-nonce' });
        } else if (faultMode === 'EXPIRED') {
          json.signed_status = resignStatus(domain, {
            ...json.signed_status.payload,
            issued_at: new Date(now - 60_000).toISOString(),
            expires_at: new Date(now - 5_000).toISOString(),
          });
        } else if (faultMode === 'WRONG_ISSUER') {
          json.signed_status = resignStatus(domain, {
            ...json.signed_status.payload,
            broker_issuer: 'https://evil-broker.example',
          });
        } else if (faultMode === 'WRONG_DEVICE') {
          json.signed_status = resignStatus(domain, { ...json.signed_status.payload, device_id: 'other-device' });
        } else if (faultMode === 'WRONG_GEN') {
          json.signed_status = resignStatus(domain, { ...json.signed_status.payload, actual_enrollment_generation: 99 });
        } else if (faultMode === 'SIGNED_OMIT_REPO') {
          const p = { ...json.signed_status.payload };
          delete p.repository;
          json.signed_status = resignStatus(domain, p);
        } else if (faultMode === 'SIGNED_WRONG_REPO') {
          json.signed_status = resignStatus(domain, { ...json.signed_status.payload, repository: 'other/repo' });
        } else if (faultMode === 'SIGNED_OMIT_TOKEN_HASH') {
          const p = { ...json.signed_status.payload };
          delete p.token_sha256;
          json.signed_status = resignStatus(domain, p);
        } else if (faultMode === 'SIGNED_WRONG_TOKEN_HASH') {
          json.signed_status = resignStatus(domain, { ...json.signed_status.payload, token_sha256: 'f'.repeat(64) });
        } else if (faultMode === 'SIGNED_STATUS_UNKNOWN') {
          json.signed_status = resignStatus(domain, { ...json.signed_status.payload, status: 'UNKNOWN', revoked: false });
        } else if (faultMode === 'SIGNED_CONTRADICTORY_ACTIVE') {
          json.signed_status = resignStatus(domain, { ...json.signed_status.payload, status: 'ACTIVE', revoked: true });
        } else if (faultMode === 'SIGNED_EXTRA_FIELD') {
          json.signed_status = resignStatus(domain, { ...json.signed_status.payload, extra_claim: 'tamper' });
        } else if (faultMode === 'SIGNED_FUTURE_ISSUED') {
          json.signed_status = resignStatus(domain, {
            ...json.signed_status.payload,
            issued_at: new Date(now + 20_000).toISOString(),
            expires_at: new Date(now + 50_000).toISOString(),
          });
        }
      }
      res.writeHead(upstream.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(json));
    });
    await new Promise((r) => proxyServer.listen(0, '127.0.0.1', r));
    const proxyPort = proxyServer.address().port;

    const client = new SandboxHttpTokenBrokerClient({
      brokerBaseUrl: `http://127.0.0.1:${proxyPort}`,
      deviceId: DEVICE,
      enrollmentGeneration: 1,
      deviceSigner: signer,
      brokerPublicKeysById: new Map([
        ...Object.entries(pubKeys.executionPublicKeys),
        ['rogue-k99', rogueKeys.publicPem],
      ]),
      expectedBrokerIssuer: ISSUER,
      repository: REPO,
      installationId: INSTALL_ID,
      workerId: WORKER,
      timeoutMs: 80,
      nowMs: () => now,
    });

    // Positive ACTIVE check
    const activeDev = await client.checkDeviceRevocation({
      workerId: WORKER,
      deviceId: DEVICE,
      installationId: INSTALL_ID,
      repository: REPO,
      enrollmentGeneration: 1,
    });
    assert.deepEqual(activeDev, { status: 'ACTIVE', revoked: false });

    const minted = await broker.mintScopedToken({
      repository: REPO,
      repository_id: REPO_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER,
      requested_permissions: { contents: 'read' },
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
    assert.equal(await client.isRevoked(minted.token), false);

    // Every single fault MUST return UNKNOWN / fail closed
    const sharedFaults = [
      'HTTP_500',
      'REDIRECT_302',
      'TIMEOUT',
      'MALFORMED_JSON',
      'UNSIGNED',
      'BAD_SIG',
      'WRONG_KEY_ID',
      'WRONG_NONCE',
      'EXPIRED',
      'WRONG_ISSUER',
      'WRONG_DEVICE',
      'WRONG_GEN',
      'SIGNED_STATUS_UNKNOWN',
      'SIGNED_CONTRADICTORY_ACTIVE',
      'SIGNED_EXTRA_FIELD',
      'SIGNED_FUTURE_ISSUED',
    ];
    const deviceFaults = [...sharedFaults, 'SIGNED_OMIT_REPO', 'SIGNED_WRONG_REPO'];
    for (const mode of deviceFaults) {
      faultMode = mode;
      const d = await client.checkDeviceRevocation({
        workerId: WORKER,
        deviceId: DEVICE,
        installationId: INSTALL_ID,
        repository: REPO,
        enrollmentGeneration: 1,
      });
      assert.equal(d.status, 'UNKNOWN', `device fault ${mode} must yield UNKNOWN`);
      assert.equal(d.revoked, true, `device fault ${mode} must fail closed revoked=true`);
    }

    const tokenFaults = [
      ...sharedFaults.filter((m) => m !== 'WRONG_DEVICE' && m !== 'WRONG_GEN'),
      'SIGNED_OMIT_TOKEN_HASH',
      'SIGNED_WRONG_TOKEN_HASH',
    ];
    for (const mode of tokenFaults) {
      faultMode = mode;
      const t = await client.checkTokenStatus(minted.token);
      assert.equal(t.status, 'UNKNOWN', `token fault ${mode} must yield UNKNOWN`);
      await assert.rejects(() => client.isRevoked(minted.token), /TOKEN_REVOCATION_UNAVAILABLE/);
    }

    // Server-side status nonce replay rejection and missing-nonce unsigned fallback removal
    const replayNonce = 'status-replay-nonce-01';
    const firstSigned = await broker.getSignedDeviceStatus({
      workerId: WORKER,
      deviceId: DEVICE,
      installationId: INSTALL_ID,
      repository: REPO,
      enrollmentGeneration: 1,
      nonce: replayNonce,
    });
    assert.equal(firstSigned.payload.status, 'ACTIVE');
    await assert.rejects(
      () =>
        broker.getSignedDeviceStatus({
          workerId: WORKER,
          deviceId: DEVICE,
          installationId: INSTALL_ID,
          repository: REPO,
          enrollmentGeneration: 1,
          nonce: replayNonce,
        }),
      /BROKER_NONCE_REPLAYED/,
    );
    const noNonceHttp = await fetch(`http://127.0.0.1:${realPort}/v1/enrollment/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ worker_id: WORKER, device_id: DEVICE }),
    });
    assert.equal(noNonceHttp.status, 400);
    assert.equal((await noNonceHttp.json()).code, 'BROKER_STATUS_NONCE_INVALID');

    // Wrong generation (< and >) when PASS_THROUGH returns REVOKED with generation mismatch/stale
    faultMode = 'PASS_THROUGH';
    const higherGen = await client.checkDeviceRevocation({
      workerId: WORKER,
      deviceId: DEVICE,
      installationId: INSTALL_ID,
      repository: REPO,
      enrollmentGeneration: 2,
    });
    assert.equal(higherGen.status, 'REVOKED');
    assert.equal(higherGen.code, 'EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH');

    // Genuine revocation via signed response
    await registry.revokeDevice({
      device_id: DEVICE,
      worker_id: WORKER,
      installation_id: INSTALL_ID,
      state: 'REVOKED',
      reason: 'SECURITY_INCIDENT',
      admin_approval: mkAdmin(adminKeys, 'REVOKE_DEVICE', now),
    });
    const revDev = await client.checkDeviceRevocation({
      workerId: WORKER,
      deviceId: DEVICE,
      installationId: INSTALL_ID,
      repository: REPO,
      enrollmentGeneration: 1,
    });
    assert.equal(revDev.status, 'REVOKED');
    assert.equal(revDev.revoked, true);

    await broker.revokeIssuedToken(minted.token);
    assert.equal(await client.isRevoked(minted.token), true);
  } finally {
    await new Promise((r) => (proxyServer ? proxyServer.close(() => r()) : r()));
    await httpBroker?.stop();
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});
