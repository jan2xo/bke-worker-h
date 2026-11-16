/**
 * F4.3 Security Remediation Adversarial Tests (SEC-01 .. SEC-05).
 *
 * Covers every finding from the F4.2 independent security audit:
 * - SEC-01: Installation-wide cross-repo worker exclusivity vs single-repo desktop token
 * - SEC-02: Complete pagination & total_count checks across /pulls, /check-runs, /matching-refs
 * - SEC-03: Device PoP ledger-target bindings + durable PRE_SEND_FENCE ownership proof for MARK_DELIVERY_UNCERTAIN
 * - SEC-04: Fail-closed signed token-status for UNKNOWN (unissued) and EXPIRED tokens
 * - SEC-05: Usage-budget vs provider TTL modeling + DELETE /installation/token provider revocation
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
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
import { ManagedTokenProvider } from '../../../browser-extension/native-host/claim/dist/native-host/claim/token-lifecycle.js';
import { HttpTrustedBrokerClient } from '../../../browser-extension/native-host/claim/dist/native-host/claim/runtime-broker-factory.js';

const REPO_1 = 'jan2xo/bke-worker';
const REPO_1_ID = 1354026486;
const REPO_2 = 'jan2xo/bke-second-repo';
const REPO_2_ID = 2222222;
const INSTALL_ID = '987654321';
const WORKER_A = 'worker-f1';
const WORKER_B = 'worker-f2';
const DEVICE_A = 'desktop-f43-01';
const DEVICE_B = 'desktop-f43-02';
const PR_NUM = 149;
const HEAD_A = 'a'.repeat(40);
const HEAD_B = 'b'.repeat(40);
const TREE_A = 'e'.repeat(40);
const PROFILE_HASH = '1'.repeat(64);
const NATIVE_HASH = '2'.repeat(64);
const ISSUER = 'https://broker.bke.f43.local';
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

function fenceMsg(attemptId, workerId = WORKER_A, headSha = HEAD_A, fenceId = `fence-${attemptId}`) {
  return JSON.stringify({
    bkeEvent: 'PRE_SEND_FENCE',
    version: 1,
    fenceId,
    attemptId,
    workerId,
    headSha,
  });
}

function signedLedgerCall(signer, deviceId, now, ledgerOp) {
  return {
    worker_id: ledgerOp.worker_id,
    device_assertion: signer.signDeviceAssertion({
      worker_id: ledgerOp.worker_id,
      device_id: deviceId,
      installation_id: ledgerOp.installation_id,
      enrollment_generation: 1,
      purpose: 'SERVER_MEDIATED_LEDGER_OP',
      repository: ledgerOp.repository,
      nowMs: now,
      ledger_op: ledgerOp,
    }),
    ledger_op: ledgerOp,
  };
}

async function enrollDevice(
  registry,
  adminKeys,
  signer,
  workerId,
  deviceId,
  scopes,
  now,
  profileHash = PROFILE_HASH,
  nativeHash = NATIVE_HASH,
) {
  const ch = await registry.issueChallenge({
    installation_id: INSTALL_ID,
    worker_id: workerId,
    device_id: deviceId,
    authorized_repository_scope: scopes,
    admin_approval: mkAdmin(adminKeys, 'APPROVE_ENROLLMENT', now, {
      worker_id: workerId,
      device_id: deviceId,
      authorized_repository_scope: scopes,
    }),
  });
  await registry.completeEnrollment({
    challenge_id: ch.challenge_id,
    installation_id: INSTALL_ID,
    worker_id: workerId,
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

test('SEC-01: Installation-wide cross-repo worker exclusivity survives single-repo desktop tokens', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f43-sec01-'));
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
        prs: [{ number: 7, state: 'open', headSha: HEAD_B, labels: [`bke-worker:${WORKER_A}`] }],
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
    await enrollDevice(registry, adminKeys, signer, WORKER_A, DEVICE_A, [REPO_1], now);
    mockGh.setTicket(REPO_1, HEAD_A, WORKER_A, 'att-sec01', now + 180_000);

    // 1. Desktop read token stays strictly pinned to REPO_1 (single repo visible, 403 on REPO_2)
    const desktopTok = await broker.mintScopedToken({
      repository: REPO_1,
      repository_id: REPO_1_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER_A,
      requested_permissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
      device_assertion: signer.signDeviceAssertion({
        worker_id: WORKER_A,
        device_id: DEVICE_A,
        installation_id: INSTALL_ID,
        enrollment_generation: 1,
        purpose: 'MINT_SCOPED_TOKEN',
        repository: REPO_1,
        nowMs: now,
      }),
    });
    const visReposRes = await fetch(`${mockGh.baseUrl}/installation/repositories`, {
      headers: { Authorization: `Bearer ${desktopTok.token}` },
    });
    assert.equal(visReposRes.status, 200);
    const visReposBody = await visReposRes.json();
    assert.equal(visReposBody.repositories.length, 1);
    assert.equal(visReposBody.repositories[0].full_name, REPO_1);

    const foreignPullsRes = await fetch(`${mockGh.baseUrl}/repos/${REPO_2}/pulls`, {
      headers: { Authorization: `Bearer ${desktopTok.token}` },
    });
    assert.equal(foreignPullsRes.status, 403);

    // 2. Broker STILL catches cross-repo worker conflict during authorizeExecution
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO_1,
          expected_repository_id: REPO_1_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER_A,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-sec01',
          action: 'DISPATCH_FIRST_MESSAGE',
          delivery_id: 'deliv-sec01-conflict',
          admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-sec01' }),
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

    // 3. Broker STILL catches cross-repo worker conflict during mediated CAS fence & claim
    const fenceConflict = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec01',
        ref_name: `refs/bke/fences/${PR_NUM}/att-sec01`,
        commit_message: fenceMsg('att-sec01'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(fenceConflict.ok, false);
    assert.equal(fenceConflict.code, 'BROKER_LEDGER_CROSS_REPO_WORKER_CONFLICT');
    assert.equal(mockGh.state.refs.size, 0);

    // 4. Incomplete repo enumeration fails closed
    mockGh.state.repos[1].prs[0].labels = [`bke-worker:${WORKER_B}`];
    mockGh.state.incompleteRepoPagination = true;
    const incompleteRes = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec01-inc',
        ref_name: `refs/bke/fences/${PR_NUM}/att-sec01-inc`,
        commit_message: fenceMsg('att-sec01-inc'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(incompleteRes.ok, false);
    assert.equal(incompleteRes.code, 'BROKER_PAGINATION_INCOMPLETE');

    // 5. Once second repo no longer holds WORKER_A and pagination is complete, operations succeed
    mockGh.state.incompleteRepoPagination = false;
    const okAuth = await broker.authorizeExecution({
      repository: REPO_1,
      expected_repository_id: REPO_1_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER_A,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-sec01',
      action: 'DISPATCH_FIRST_MESSAGE',
      delivery_id: 'deliv-sec01-ok',
      admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-sec01' }),
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
    assert.equal(okAuth.envelope.pr_number, PR_NUM);
  } finally {
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('SEC-02: Complete pagination across /pulls, /check-runs, and /git/matching-refs/bke/ with fail-closed limits', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f43-sec02-'));
  const now = Date.parse('2026-10-20T12:00:00.000Z');
  const mockGh = await startMockGitHubServer({
    installationId: INSTALL_ID,
    repos: [
      {
        id: REPO_1_ID,
        full_name: REPO_1,
        permissions: { contents: 'write', pull_requests: 'read', checks: 'read', pull: true, push: true },
        prs: [
          { number: 10, state: 'open', headSha: HEAD_B, labels: [`bke-worker:${WORKER_B}`] },
          { number: PR_NUM, state: 'open', headSha: HEAD_A, labels: [`bke-worker:${WORKER_A}`] },
          { number: 150, state: 'open', headSha: HEAD_B, labels: [`bke-worker:${WORKER_A}`] },
        ],
      },
    ],
  });
  mockGh.state.pullsPageSize = 1;
  mockGh.state.checkRunsPageSize = 1;
  mockGh.state.refsPageSize = 1;

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
    await enrollDevice(registry, adminKeys, signer, WORKER_A, DEVICE_A, [REPO_1], now);

    // Put valid bke-ticket on page 3 of check-runs
    const expSec = Math.floor((now + 180_000) / 1000);
    mockGh.setCheckRuns(REPO_1, HEAD_A, [
      { id: 1, name: 'ci-lint', app: PINNED_APP, head_sha: HEAD_A, status: 'completed', conclusion: 'success', external_id: 'lint-1' },
      { id: 2, name: 'ci-unit', app: PINNED_APP, head_sha: HEAD_A, status: 'completed', conclusion: 'success', external_id: 'unit-2' },
      {
        id: 3,
        name: 'bke-ticket',
        app: PINNED_APP,
        head_sha: HEAD_A,
        status: 'completed',
        conclusion: 'success',
        external_id: `bke-ticket:v1:${WORKER_A}:att-sec02:${expSec}`,
      },
    ]);

    // 1. Page-3 PR #150 conflict is caught in both authorizeExecution and COMMIT_PRE_SEND_FENCE
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO_1,
          expected_repository_id: REPO_1_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER_A,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-sec02',
          action: 'DISPATCH_FIRST_MESSAGE',
          delivery_id: 'deliv-sec02-mpr',
          admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-sec02' }),
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
      /BROKER_MULTI_PR_CONFLICT/,
    );
    const fenceMpr = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec02',
        ref_name: `refs/bke/fences/${PR_NUM}/att-sec02`,
        commit_message: fenceMsg('att-sec02'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(fenceMpr.ok, false);
    assert.equal(fenceMpr.code, 'BROKER_LEDGER_MULTI_PR_CONFLICT');

    // 2. Remove PR #150; put quarantined uncertain ref on page 2 of matching-refs
    mockGh.state.repos[0].prs = mockGh.state.repos[0].prs.slice(0, 2);
    mockGh.state.refs.set(`${REPO_1}:refs/bke/fences/10/att-other`, HEAD_B);
    mockGh.state.refs.set(`${REPO_1}:refs/bke/uncertain/${PR_NUM}/att-prior`, HEAD_A);

    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO_1,
          expected_repository_id: REPO_1_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER_A,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-sec02',
          action: 'DISPATCH_FIRST_MESSAGE',
          delivery_id: 'deliv-sec02-unc',
          admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-sec02' }),
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
      /BROKER_DELIVERY_UNCERTAIN_QUARANTINED/,
    );
    const fenceUnc = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec02',
        ref_name: `refs/bke/fences/${PR_NUM}/att-sec02`,
        commit_message: fenceMsg('att-sec02'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(fenceUnc.ok, false);
    assert.equal(fenceUnc.code, 'BROKER_DELIVERY_UNCERTAIN_QUARANTINED');

    // 3. Remove uncertain ref -> page-3 check-run ticket succeeds on both authorizeExecution & CONSUME_SEND_CLAIM
    mockGh.state.refs.delete(`${REPO_1}:refs/bke/uncertain/${PR_NUM}/att-prior`);
    const okAuth = await broker.authorizeExecution({
      repository: REPO_1,
      expected_repository_id: REPO_1_ID,
      installation_id: INSTALL_ID,
      worker_id: WORKER_A,
      pr_number: PR_NUM,
      head_sha: HEAD_A,
      attempt_id: 'att-sec02',
      action: 'DISPATCH_FIRST_MESSAGE',
      delivery_id: 'deliv-sec02-p3-ok',
      admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-sec02' }),
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
    assert.equal(okAuth.envelope.pr_number, PR_NUM);

    const fenceSec02 = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec02',
        ref_name: `refs/bke/fences/${PR_NUM}/att-sec02`,
        commit_message: fenceMsg('att-sec02'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(fenceSec02.ok, true);

    const claimOk = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'CONSUME_SEND_CLAIM',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec02',
        ref_name: `refs/bke/claims/${PR_NUM}/att-sec02`,
        commit_message: 'bke claim',
        tree_sha: TREE_A,
      }),
    );
    assert.equal(claimOk.ok, true);
    assert.equal(claimOk.status, 'COMMITTED');

    // 3b. Duplicate valid bke-ticket on page 4 rejects both authorizeExecution and CONSUME_SEND_CLAIM
    mockGh.setCheckRuns(REPO_1, HEAD_A, [
      { id: 1, name: 'ci-lint', app: PINNED_APP, head_sha: HEAD_A, status: 'completed', conclusion: 'success', external_id: 'lint-1' },
      { id: 2, name: 'ci-unit', app: PINNED_APP, head_sha: HEAD_A, status: 'completed', conclusion: 'success', external_id: 'unit-2' },
      {
        id: 3,
        name: 'bke-ticket',
        app: PINNED_APP,
        head_sha: HEAD_A,
        status: 'completed',
        conclusion: 'success',
        external_id: `bke-ticket:v1:${WORKER_A}:att-sec02-dup:${expSec}`,
      },
      {
        id: 4,
        name: 'bke-ticket',
        app: PINNED_APP,
        head_sha: HEAD_A,
        status: 'completed',
        conclusion: 'success',
        external_id: `bke-ticket:v1:${WORKER_A}:att-sec02-dup:${expSec}`,
      },
    ]);
    await assert.rejects(
      () =>
        broker.authorizeExecution({
          repository: REPO_1,
          expected_repository_id: REPO_1_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER_A,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-sec02-dup',
          action: 'DISPATCH_FIRST_MESSAGE',
          delivery_id: 'deliv-sec02-dup',
          admin_approval: mkAdmin(adminKeys, 'DISPATCH_EXECUTION', now, { attempt_id: 'att-sec02-dup' }),
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
      /BROKER_TICKET_INVALID_OR_AMBIGUOUS/,
    );
    const fenceDup = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec02-dup',
        ref_name: `refs/bke/fences/${PR_NUM}/att-sec02-dup`,
        commit_message: fenceMsg('att-sec02-dup'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(fenceDup.ok, true);

    const dupClaim = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'CONSUME_SEND_CLAIM',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec02-dup',
        ref_name: `refs/bke/claims/${PR_NUM}/att-sec02-dup`,
        commit_message: 'bke claim',
        tree_sha: TREE_A,
      }),
    );
    assert.equal(dupClaim.ok, false);
    assert.equal(dupClaim.code, 'BROKER_TICKET_INVALID_OR_AMBIGUOUS');

    // 4. Fail-closed on missing total_count, malformed Link, and exceeded maxPages
    const fenceMiss = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec02-b',
        ref_name: `refs/bke/fences/${PR_NUM}/att-sec02-b`,
        commit_message: fenceMsg('att-sec02-b'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(fenceMiss.ok, true);
    mockGh.state.missingCheckTotalCount = true;
    const claimMissingTotal = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'CONSUME_SEND_CLAIM',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec02-b',
        ref_name: `refs/bke/claims/${PR_NUM}/att-sec02-b`,
        commit_message: 'bke claim',
        tree_sha: TREE_A,
      }),
    );
    assert.equal(claimMissingTotal.ok, false);
    assert.equal(claimMissingTotal.code, 'BROKER_PAGINATION_INCOMPLETE');
    mockGh.state.missingCheckTotalCount = false;

    mockGh.state.malformedPullsLink = true;
    const malLink = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec02-c',
        ref_name: `refs/bke/fences/${PR_NUM}/att-sec02-c`,
        commit_message: fenceMsg('att-sec02-c'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(malLink.ok, false);
    assert.equal(malLink.code, 'BROKER_GITHUB_PAGINATION_MALFORMED');
    mockGh.state.malformedPullsLink = false;

    mockGh.state.incompletePullsPagination = true;
    const infLoop = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signer, DEVICE_A, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec02-d',
        ref_name: `refs/bke/fences/${PR_NUM}/att-sec02-d`,
        commit_message: fenceMsg('att-sec02-d'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(infLoop.ok, false);
    assert.equal(infLoop.code, 'BROKER_PAGINATION_INCOMPLETE');
  } finally {
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('SEC-03: Device PoP ledger-target binding and durable PRE_SEND_FENCE proof for MARK_DELIVERY_UNCERTAIN', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f43-sec03-'));
  const now = Date.parse('2026-10-20T12:00:00.000Z');
  const PR_B = 200;
  const mockGh = await startMockGitHubServer({
    installationId: INSTALL_ID,
    repos: [
      {
        id: REPO_1_ID,
        full_name: REPO_1,
        permissions: { contents: 'write', pull_requests: 'read', checks: 'read', pull: true, push: true },
        prs: [
          { number: PR_NUM, state: 'open', headSha: HEAD_A, labels: [`bke-worker:${WORKER_A}`] },
          { number: PR_B, state: 'open', headSha: HEAD_A, labels: [`bke-worker:${WORKER_B}`] },
        ],
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

    const signerA = new DeviceKeyPairSigner();
    const signerB = new DeviceKeyPairSigner();
    await enrollDevice(registry, adminKeys, signerA, WORKER_A, DEVICE_A, [REPO_1], now, PROFILE_HASH, NATIVE_HASH);
    await enrollDevice(registry, adminKeys, signerB, WORKER_B, DEVICE_B, [REPO_1], now, '3'.repeat(64), '4'.repeat(64));

    // 1. Cross-operation / cross-PR PoP replay rejected before consuming fence or writing GitHub
    const popForFence = signerA.signDeviceAssertion({
      worker_id: WORKER_A,
      device_id: DEVICE_A,
      installation_id: INSTALL_ID,
      enrollment_generation: 1,
      purpose: 'SERVER_MEDIATED_LEDGER_OP',
      repository: REPO_1,
      nowMs: now,
      ledger_op: {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-sec03-a',
        ref_name: `refs/bke/fences/${PR_NUM}/att-sec03-a`,
        commit_message: fenceMsg('att-sec03-a'),
        tree_sha: TREE_A,
      },
    });
    const replayRes = await broker.executeServerMediatedLedgerOp({
      worker_id: WORKER_A,
      device_assertion: popForFence,
      ledger_op: {
        operation: 'MARK_DELIVERY_UNCERTAIN',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_B,
        head_sha: HEAD_A,
        attempt_id: 'att-sec03-a',
        ref_name: `refs/bke/uncertain/${PR_B}/att-sec03-a`,
        commit_message: 'sabotage PR B',
        tree_sha: TREE_A,
      },
    });
    assert.equal(replayRes.ok, false);
    assert.equal(replayRes.code, 'BROKER_DEVICE_SCOPE_MISMATCH');
    assert.equal(mockGh.state.refs.size, 0);

    // 2. Un-fenced MARK_DELIVERY_UNCERTAIN rejected even with matching PoP
    const unfencedUncertain = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signerA, DEVICE_A, now, {
        operation: 'MARK_DELIVERY_UNCERTAIN',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-never-fenced',
        ref_name: `refs/bke/uncertain/${PR_NUM}/att-never-fenced`,
        commit_message: 'uncertain without fence',
        tree_sha: TREE_A,
      }),
    );
    assert.equal(unfencedUncertain.ok, false);
    assert.equal(unfencedUncertain.code, 'BROKER_LEDGER_FENCE_MISSING');
    assert.equal(mockGh.state.refs.size, 0);

    // 3. Worker B commits its own durable PRE_SEND_FENCE on PR #200; Worker A cannot quarantine PR #200
    const fenceB = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signerB, DEVICE_B, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_B,
        pr_number: PR_B,
        head_sha: HEAD_A,
        attempt_id: 'att-worker-b',
        ref_name: `refs/bke/fences/${PR_B}/att-worker-b`,
        commit_message: fenceMsg('att-worker-b', WORKER_B, HEAD_A, 'fence-b-1'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(fenceB.ok, true);

    const crossWorkerSabotage = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signerA, DEVICE_A, now, {
        operation: 'MARK_DELIVERY_UNCERTAIN',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_B,
        head_sha: HEAD_A,
        attempt_id: 'att-worker-b',
        ref_name: `refs/bke/uncertain/${PR_B}/att-worker-b`,
        commit_message: 'sabotage B',
        tree_sha: TREE_A,
      }),
    );
    assert.equal(crossWorkerSabotage.ok, false);
    assert.equal(crossWorkerSabotage.code, 'BROKER_LEDGER_UNCERTAIN_OWNERSHIP_CONFLICT');
    assert.equal(mockGh.state.refs.has(`${REPO_1}:refs/bke/uncertain/${PR_B}/att-worker-b`), false);

    // 4. Legitimate Worker A commits its PRE_SEND_FENCE, PR advances & unlabels mid-flight -> MARK_DELIVERY_UNCERTAIN still succeeds!
    const fenceA = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signerA, DEVICE_A, now, {
        operation: 'COMMIT_PRE_SEND_FENCE',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-worker-a',
        ref_name: `refs/bke/fences/${PR_NUM}/att-worker-a`,
        commit_message: fenceMsg('att-worker-a', WORKER_A, HEAD_A, 'fence-a-1'),
        tree_sha: TREE_A,
      }),
    );
    assert.equal(fenceA.ok, true);

    mockGh.state.repos[0].prs[0].headSha = HEAD_B;
    mockGh.state.repos[0].prs[0].labels = [];
    const safeUncertain = await broker.executeServerMediatedLedgerOp(
      signedLedgerCall(signerA, DEVICE_A, now, {
        operation: 'MARK_DELIVERY_UNCERTAIN',
        repository: REPO_1,
        repository_id: REPO_1_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER_A,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        attempt_id: 'att-worker-a',
        ref_name: `refs/bke/uncertain/${PR_NUM}/att-worker-a`,
        commit_message: 'uncertain after send failure',
        tree_sha: TREE_A,
      }),
    );
    assert.equal(safeUncertain.ok, true);
    assert.equal(safeUncertain.status, 'COMMITTED');
    assert.equal(mockGh.state.refs.has(`${REPO_1}:refs/bke/uncertain/${PR_NUM}/att-worker-a`), true);
  } finally {
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('SEC-04 & SEC-05: Signed UNKNOWN/EXPIRED token status, usage vs provider TTLs, and DELETE /installation/token provider revocation', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f43-sec0405-'));
  let now = Date.parse('2026-10-20T12:00:00.000Z');
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
      defaultTokenTtlMs: 30_000, // distinct usage budget (30s) vs provider 600s
    });
    await broker.initialize();
    const signer = new DeviceKeyPairSigner();
    await enrollDevice(registry, adminKeys, signer, WORKER_A, DEVICE_A, [REPO_1], now);

    httpBroker = new SandboxBrokerHttpServer(broker);
    const { port } = await httpBroker.start();
    const pubKeys = await broker.getPublicVerificationKeys();
    const brokerKeyMap = new Map(Object.entries(pubKeys.executionPublicKeys));

    const brokerClient = new SandboxHttpTokenBrokerClient({
      brokerBaseUrl: `http://127.0.0.1:${port}`,
      workerId: WORKER_A,
      deviceId: DEVICE_A,
      installationId: INSTALL_ID,
      repository: REPO_1,
      repositoryId: REPO_1_ID,
      enrollmentGeneration: 1,
      deviceSigner: signer,
      expectedBrokerIssuer: ISSUER,
      brokerPublicKeysById: brokerKeyMap,
      nowMs: () => now,
    });
    const runtimeClient = new HttpTrustedBrokerClient({
      brokerBaseUrl: `http://127.0.0.1:${port}`,
      workerId: WORKER_A,
      deviceId: DEVICE_A,
      installationId: INSTALL_ID,
      repository: REPO_1,
      repositoryId: REPO_1_ID,
      enrollmentGeneration: 1,
      devicePublicKeyPem: signer.publicKeySpkiPem,
      devicePrivateKeyPem: signer.privateKeyPem,
      expectedBrokerIssuer: ISSUER,
      brokerPublicKeysById: brokerKeyMap,
      nowMs: () => now,
    });

    // SEC-04: Unissued / random token MUST NEVER return ACTIVE
    const randomTok = 'ghs_random_unissued_00000001';
    for (const c of [brokerClient, runtimeClient]) {
      const st = await c.checkTokenStatus(randomTok);
      assert.deepEqual(st, { status: 'UNKNOWN', code: 'TOKEN_UNKNOWN_OR_UNISSUED' });
      await assert.rejects(() => c.isRevoked(randomTok), /TOKEN_UNKNOWN_OR_UNISSUED/);
    }

    // SEC-05: Minted token records distinct usageExpiresAtMs (< providerExpiresAtMs)
    const ac = new AbortController();
    const minted1 = await runtimeClient.issueToken({
      repository: REPO_1,
      repositoryId: REPO_1_ID,
      installationId: INSTALL_ID,
      workerId: WORKER_A,
      requestedPermissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
      reason: 'SEC05_TEST',
      signal: ac.signal,
    });
    assert.equal(minted1.usageExpiresAtMs, now + 30_000);
    assert.equal(minted1.expiresAtMs, minted1.usageExpiresAtMs);
    assert.ok((minted1.providerExpiresAtMs ?? 0) > (minted1.usageExpiresAtMs ?? 0));

    const brokerJson = JSON.parse(await readFile(join(dir, 'broker.json'), 'utf8'));
    const tok1Sha = createHash('sha256').update(minted1.token, 'utf8').digest('hex');
    assert.equal(brokerJson.issuedTokens[tok1Sha].usage_expires_at_ms, minted1.usageExpiresAtMs);
    assert.equal(brokerJson.issuedTokens[tok1Sha].provider_expires_at_ms, minted1.providerExpiresAtMs);

    // Valid unexpired token returns ACTIVE
    assert.deepEqual(await runtimeClient.checkTokenStatus(minted1.token), { status: 'ACTIVE' });
    assert.equal(await runtimeClient.isRevoked(minted1.token), false);

    // ManagedTokenProvider caches minted token while ACTIVE, then clears & throws TOKEN_EXPIRED when usage TTL expires
    const provider = new ManagedTokenProvider(
      {
        repository: REPO_1,
        repositoryId: REPO_1_ID,
        installationId: INSTALL_ID,
        workerId: WORKER_A,
        allowedPermissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
        nowMs: () => now,
      },
      runtimeClient,
    );
    const activeTok = await provider.getToken();
    assert.ok(activeTok.startsWith('ghs_sandbox_'));

    // Advance past usageExpiresAtMs (30s) while still before providerExpiresAtMs (600s)
    now += 31_000;
    for (const c of [brokerClient, runtimeClient]) {
      const expSt = await c.checkTokenStatus(activeTok);
      assert.deepEqual(expSt, { status: 'EXPIRED', code: 'TOKEN_EXPIRED' });
      await assert.rejects(() => c.isRevoked(activeTok), /TOKEN_EXPIRED/);
    }
    await assert.rejects(() => provider.getToken(), /TOKEN_EXPIRED/);

    // SEC-05: Explicit local_only revocation leaves provider token usable until provider expiry
    const mintedLocal = await brokerClient.issueToken({
      repository: REPO_1,
      repositoryId: REPO_1_ID,
      installationId: INSTALL_ID,
      workerId: WORKER_A,
      requestedPermissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
      reason: 'SEC05_LOCAL_ONLY',
      signal: ac.signal,
    });
    const localRevRes = await fetch(`http://127.0.0.1:${port}/v1/broker/revoke-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: mintedLocal.token, local_only: true }),
    });
    assert.equal(localRevRes.status, 200);
    const localRevJson = await localRevRes.json();
    assert.equal(localRevJson.local_revoked, true);
    assert.equal(localRevJson.provider_revoked, false);
    assert.equal((await runtimeClient.checkTokenStatus(mintedLocal.token)).status, 'REVOKED');
    const ghStillOk = await fetch(`${mockGh.baseUrl}/installation/repositories`, {
      headers: { Authorization: `Bearer ${mintedLocal.token}` },
    });
    assert.equal(ghStillOk.status, 200);

    // SEC-05: Default revocation calls DELETE /installation/token -> GitHub immediately returns 401
    const mintedProv = await brokerClient.issueToken({
      repository: REPO_1,
      repositoryId: REPO_1_ID,
      installationId: INSTALL_ID,
      workerId: WORKER_A,
      requestedPermissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
      reason: 'SEC05_PROVIDER_REVOKE',
      signal: ac.signal,
    });
    const provRevRes = await fetch(`http://127.0.0.1:${port}/v1/broker/revoke-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: mintedProv.token }),
    });
    assert.equal(provRevRes.status, 200);
    const provRevJson = await provRevRes.json();
    assert.equal(provRevJson.local_revoked, true);
    assert.equal(provRevJson.provider_revoked, true);
    assert.equal(provRevJson.provider_status, 204);
    assert.equal((await runtimeClient.checkTokenStatus(mintedProv.token)).status, 'REVOKED');

    const ghRejected = await fetch(`${mockGh.baseUrl}/installation/repositories`, {
      headers: { Authorization: `Bearer ${mintedProv.token}` },
    });
    assert.equal(ghRejected.status, 401);
  } finally {
    await httpBroker?.stop();
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});
