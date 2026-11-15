/**
 * F3-00 / F3-06 / F3-09 Security Hardening Unit Tests for claim/ modules:
 * - Ed25519 V2 execution request signing, domain separation, audience/issuer/device/generation binding
 * - Algorithm downgrade protection (requireAsymmetricV2) & HMAC-on-V2 rejection
 * - V2 Ed25519 HALT key separation & revocation checker
 * - 3xx redirect blocking on RestGitHubAuthorityProvider & GitHubF1Ledger
 * - Empty/maintain permissions rejection on RestGitHubAuthorityProvider
 * - Bounded pre-claim transient retry vs non-retry on permanent/revoked failures
 * - DesktopControllerDaemon v3 status & doctor secret-free readiness checks
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  AUTHORIZED_CAPABILITY_V1,
  AUTHORIZED_CAPABILITY_V2,
  EXECUTION_REQUEST_PROTOCOL_VERSION,
  EXECUTION_REQUEST_PROTOCOL_VERSION_V2,
  ExecutionRequestVerifier,
  buildExecutionAudience,
  signExecutionRequestEd25519,
  signExecutionRequestHmac,
  verifyExecutionRequestEd25519Signature,
} from '../dist/native-host/claim/github-app-harness.js';
import { RestGitHubAuthorityProvider } from '../dist/native-host/claim/github-authority-provider.js';
import { GitHubF1Ledger } from '../dist/native-host/claim/github-f1-ledger.js';
import {
  DeterministicMockTokenBroker,
  ManagedTokenProvider,
} from '../dist/native-host/claim/token-lifecycle.js';
import {
  DesktopControllerDaemon,
  runControllerDoctor,
} from '../dist/native-host/claim/controller-daemon.js';

const OWNER = 'jan2xo';
const REPO_NAME = 'bke-worker';
const FULL_REPO = `${OWNER}/${REPO_NAME}`;
const REPO_ID = 1354026486;
const INSTALL_ID = '987654321';
const WORKER = 'worker-f1';
const DEVICE_ID = 'dev-desktop-f3-001';
const BROKER_ISSUER = 'https://broker.bke.internal';
const AUDIENCE = buildExecutionAudience(FULL_REPO, WORKER);
const PR_NUM = 149;
const HEAD = 'a'.repeat(40);
const ATTEMPT = 'attempt-f3-01';
const DELIVERY = 'deliv-f3-0001';
const PINNED_APP = { id: 9001, slug: 'bke-dispatcher-app' };
const BASE_NOW = Date.parse('2026-10-20T12:00:00.000Z');
const HMAC_SECRET = 'f3-hmac-test-secret-material-32bytes!';

function genEd25519PemPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

function makeEnvV2(overrides = {}) {
  return {
    protocol_version: EXECUTION_REQUEST_PROTOCOL_VERSION_V2,
    broker_issuer: BROKER_ISSUER,
    audience: AUDIENCE,
    repository_owner: OWNER,
    repository_name: REPO_NAME,
    repository_id: REPO_ID,
    installation_identity: INSTALL_ID,
    worker_id: WORKER,
    device_id: DEVICE_ID,
    enrollment_generation: 2,
    pr_number: PR_NUM,
    head_sha: HEAD,
    attempt_id: ATTEMPT,
    delivery_id: DELIVERY,
    action: 'DISPATCH_FIRST_MESSAGE',
    issued_at: new Date(BASE_NOW - 5_000).toISOString(),
    expires_at: new Date(BASE_NOW + 60_000).toISOString(),
    authorized_capability: AUTHORIZED_CAPABILITY_V2,
    ...overrides,
  };
}

function makeStubProvider() {
  return {
    async verifyInstallationScope() {
      return {
        ok: true,
        scope: {
          installationId: INSTALL_ID,
          repositoryId: REPO_ID,
          repositoryFullName: FULL_REPO,
          permissions: { contents: 'write', pull_requests: 'read' },
        },
      };
    },
    async readPullRequest() {
      return { number: PR_NUM, state: 'open', headSha: HEAD, workerLabels: [WORKER] };
    },
    async enumerateOpenAssignedPullRequests() {
      return [{ number: PR_NUM, state: 'open', headSha: HEAD, workerLabels: [WORKER] }];
    },
    async readPinnedTicket() {
      return {
        ok: true,
        ticket: {
          contractVersion: 1,
          checkRunId: 777,
          ticketId: 'check-run:777',
          attemptId: ATTEMPT,
          workerId: WORKER,
          expiresAtMs: BASE_NOW + 60_000,
          headSha: HEAD,
        },
      };
    },
    async readBkeRefState() {
      return { consumedAttempts: [], uncertainAttempts: [], conversationTipSha: null };
    },
  };
}

test('F3-00: Ed25519 V2 protocol verification, downgrade prevention, audience/device/revocation binding, and HALT key separation', async () => {
  const execKeys = genEd25519PemPair();
  const haltKeys = genEd25519PemPair();
  let revoked = false;

  // Mixed V1 HMAC keys + V2 asymmetricV2Enabled is strictly forbidden at construction (P0-01)
  assert.throws(
    () =>
      new ExecutionRequestVerifier({
        expectedRepositoryOwner: OWNER,
        expectedRepositoryName: REPO_NAME,
        expectedRepositoryId: REPO_ID,
        expectedInstallationId: INSTALL_ID,
        expectedWorkerId: WORKER,
        pinnedApp: PINNED_APP,
        hmacKeysById: new Map([['v1-hmac', HMAC_SECRET]]),
        asymmetricV2Enabled: true,
        requireAsymmetricV2: true,
        publicKeysById: new Map([['ed-k1', execKeys.publicKeyPem]]),
        expectedBrokerIssuer: BROKER_ISSUER,
        expectedDeviceId: DEVICE_ID,
        deviceRevocationChecker: () => ({ status: 'ACTIVE', revoked: false }),
        provider: makeStubProvider(),
      }),
    /EXEC_REQ_CONFIG_MIXED_V1_V2_FORBIDDEN/,
  );

  const verifier = new ExecutionRequestVerifier({
    expectedRepositoryOwner: OWNER,
    expectedRepositoryName: REPO_NAME,
    expectedRepositoryId: REPO_ID,
    expectedInstallationId: INSTALL_ID,
    expectedWorkerId: WORKER,
    pinnedApp: PINNED_APP,
    asymmetricV2Enabled: true,
    requireAsymmetricV2: true,
    publicKeysById: new Map([['ed-k1', execKeys.publicKeyPem]]),
    haltPublicKeysById: new Map([['ed-halt-1', haltKeys.publicKeyPem]]),
    allowRemoteHalt: true,
    expectedBrokerIssuer: BROKER_ISSUER,
    expectedAudience: AUDIENCE,
    expectedDeviceId: DEVICE_ID,
    minEnrollmentGeneration: 2,
    deviceRevocationChecker: () => ({
      status: revoked ? 'REVOKED' : 'ACTIVE',
      revoked,
      code: revoked ? 'EXEC_REQ_DEVICE_REVOKED' : undefined,
    }),
    provider: makeStubProvider(),
    nowMs: () => BASE_NOW,
  });

  // 1. V2 signed cleanly authorizes
  const signedV2 = signExecutionRequestEd25519(makeEnvV2(), execKeys.privateKeyPem, 'ed-k1');
  assert.equal(verifyExecutionRequestEd25519Signature(signedV2, execKeys.publicKeyPem), true);
  assert.equal((await verifier.verifyAndAuthorize(signedV2)).ok, true);

  // 2. Tampered field fails Ed25519 signature check
  const tampered = { ...signedV2, envelope: { ...signedV2.envelope, pr_number: 999 } };
  assert.equal((await verifier.verifyAndAuthorize(tampered)).code, 'EXEC_REQ_SIGNATURE_INVALID');

  // 3. Downgrade V1 HMAC rejected when asymmetricV2Enabled=true
  const v1Req = signExecutionRequestHmac(
    {
      protocol_version: EXECUTION_REQUEST_PROTOCOL_VERSION,
      repository_owner: OWNER,
      repository_name: REPO_NAME,
      repository_id: REPO_ID,
      installation_identity: INSTALL_ID,
      worker_id: WORKER,
      pr_number: PR_NUM,
      head_sha: HEAD,
      attempt_id: 'attempt-f3-v1',
      delivery_id: 'deliv-f3-v1',
      action: 'DISPATCH_FIRST_MESSAGE',
      issued_at: new Date(BASE_NOW - 5_000).toISOString(),
      expires_at: new Date(BASE_NOW + 60_000).toISOString(),
      authorized_capability: AUTHORIZED_CAPABILITY_V1,
    },
    HMAC_SECRET,
    'v1-hmac',
  );
  assert.equal((await verifier.verifyAndAuthorize(v1Req)).code, 'EXEC_REQ_DOWNGRADE_FORBIDDEN');

  // 4. V2 wrapper claiming HMAC-SHA256 rejected
  assert.equal(
    (await verifier.verifyAndAuthorize({
      envelope: makeEnvV2({ delivery_id: 'deliv-alg', attempt_id: 'attempt-alg' }),
      signature_alg: 'HMAC-SHA256',
      key_id: 'ed-k1',
      signature_hex: 'a'.repeat(64),
    })).code,
    'EXEC_REQ_DOWNGRADE_FORBIDDEN',
  );

  // 5. Audience / Issuer / Device / Enrollment generation mismatches fail closed
  const badChecks = [
    ['issuer', makeEnvV2({ delivery_id: 'd-iss', attempt_id: 'a-iss', broker_issuer: 'https://evil.example' }), 'EXEC_REQ_ISSUER_MISMATCH'],
    ['audience', makeEnvV2({ delivery_id: 'd-aud', attempt_id: 'a-aud', audience: buildExecutionAudience(FULL_REPO, 'other-worker') }), 'EXEC_REQ_AUDIENCE_MISMATCH'],
    ['device', makeEnvV2({ delivery_id: 'd-dev', attempt_id: 'a-dev', device_id: 'wrong-device-id' }), 'EXEC_REQ_DEVICE_MISMATCH'],
    ['gen', makeEnvV2({ delivery_id: 'd-gen', attempt_id: 'a-gen', enrollment_generation: 1 }), 'EXEC_REQ_ENROLLMENT_STALE'],
  ];
  for (const [label, env, expectedCode] of badChecks) {
    const req = signExecutionRequestEd25519(env, execKeys.privateKeyPem, 'ed-k1');
    assert.equal((await verifier.verifyAndAuthorize(req)).code, expectedCode, label);
  }

  // 6. Revoked device blocks even freshly signed valid request
  revoked = true;
  const reqRev = signExecutionRequestEd25519(makeEnvV2({ delivery_id: 'd-rev', attempt_id: 'a-rev' }), execKeys.privateKeyPem, 'ed-k1');
  assert.equal((await verifier.verifyAndAuthorize(reqRev)).code, 'EXEC_REQ_DEVICE_REVOKED');
  revoked = false;

  // 7. V2 HALT requires dedicated HALT key, rejects dispatch key, rejects shared pubkey
  const execSignedHalt = signExecutionRequestEd25519(makeEnvV2({ action: 'HALT', delivery_id: 'd-halt-bad' }), execKeys.privateKeyPem, 'ed-k1');
  assert.equal((await verifier.verifyAndAuthorize(execSignedHalt)).code, 'EXEC_REQ_HALT_KEY_UNAUTHORIZED');

  const properHalt = signExecutionRequestEd25519(makeEnvV2({ action: 'HALT', delivery_id: 'd-halt-ok' }), haltKeys.privateKeyPem, 'ed-halt-1');
  assert.equal((await verifier.verifyAndAuthorize(properHalt)).ok, true);

  const sharedHaltVerifier = new ExecutionRequestVerifier({
    expectedRepositoryOwner: OWNER,
    expectedRepositoryName: REPO_NAME,
    expectedRepositoryId: REPO_ID,
    expectedInstallationId: INSTALL_ID,
    expectedWorkerId: WORKER,
    pinnedApp: PINNED_APP,
    asymmetricV2Enabled: true,
    requireAsymmetricV2: true,
    publicKeysById: new Map([['ed-k1', execKeys.publicKeyPem]]),
    haltPublicKeysById: new Map([['ed-k1', execKeys.publicKeyPem]]),
    expectedBrokerIssuer: BROKER_ISSUER,
    expectedDeviceId: DEVICE_ID,
    deviceRevocationChecker: () => ({ status: 'ACTIVE', revoked: false }),
    allowRemoteHalt: true,
    provider: makeStubProvider(),
    nowMs: () => BASE_NOW,
  });
  assert.equal(
    (await sharedHaltVerifier.verifyAndAuthorize(signExecutionRequestEd25519(makeEnvV2({ action: 'HALT', delivery_id: 'd-halt-shared' }), execKeys.privateKeyPem, 'ed-k1'))).code,
    'EXEC_REQ_HALT_KEY_SEPARATION_REQUIRED',
  );
});

test('F3-00: 3xx redirects, maintain permissions, and empty permissions fail closed on GitHub adapters', async () => {
  let mode = 'REDIRECT_302';
  const server = createServer((_req, res) => {
    if (mode === 'REDIRECT_302') {
      res.writeHead(302, { Location: 'https://attacker.example/steal-token' });
      res.end();
      return;
    }
    if (mode === 'EMPTY_PERMS') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ repositories: [{ id: REPO_ID, full_name: FULL_REPO, permissions: {} }] }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ repositories: [{ id: REPO_ID, full_name: FULL_REPO, permissions: { maintain: true, pull: true } }] }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    const provider = new RestGitHubAuthorityProvider(
      (url, init) => globalThis.fetch(url, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() })),
      async () => 'ghs_test_redirect_guard',
      { baseApiUrl: baseUrl },
    );

    mode = 'REDIRECT_302';
    assert.equal((await provider.verifyInstallationScope(FULL_REPO, REPO_ID, INSTALL_ID)).code, 'GITHUB_REDIRECT_BLOCKED');

    mode = 'EMPTY_PERMS';
    assert.equal((await provider.verifyInstallationScope(FULL_REPO, REPO_ID, INSTALL_ID)).code, 'GITHUB_INSTALLATION_PERMISSIONS_MISSING');

    mode = 'MAINTAIN_PERMS';
    assert.equal((await provider.verifyInstallationScope(FULL_REPO, REPO_ID, INSTALL_ID)).code, 'GITHUB_INSTALLATION_OVERPRIVILEGED');

    mode = 'REDIRECT_302';
    const ledger = new GitHubF1Ledger(
      {
        repository: FULL_REPO,
        prNumber: PR_NUM,
        headSha: HEAD,
        workerId: WORKER,
        authenticatedWorkerId: WORKER,
        pinnedApp: PINNED_APP,
        executionId: 'exec-f3-01',
        targetId: 'target-f3-01',
        profileId: 'profile-f3-01',
        targetTabId: 1,
        baseApiUrl: baseUrl,
      },
      (url, init) => globalThis.fetch(url, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() })),
      async () => 'ghs_test_redirect_guard',
    );
    await assert.rejects(() => ledger.refreshAuthority(), /GITHUB_REDIRECT_BLOCKED/);
  } finally {
    await new Promise((r) => server.close(() => r()));
  }
});

test('F3-06: ManagedTokenProvider retries transient broker errors cleanly before claim, never retries permanent/revoked errors', async () => {
  let clock = BASE_NOW;
  const broker = new DeterministicMockTokenBroker(() => clock);
  let calls = 0;
  const flakyBroker = {
    kind: 'MOCK_BROKER',
    async issueToken(req) {
      calls += 1;
      if (calls === 1) throw Error('TOKEN_BROKER_UNAVAILABLE');
      return broker.issueToken(req);
    },
    isRevoked: (t) => broker.isRevoked(t),
  };

  const provider = new ManagedTokenProvider(
    {
      repository: FULL_REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      allowedPermissions: { contents: 'write' },
      maxTransientRetries: 2,
      retryDelayMs: 5,
      nowMs: () => clock,
    },
    flakyBroker,
  );

  const tok = await provider.getToken();
  assert.ok(tok.startsWith('ghs_mock_inst_'));
  assert.equal(calls, 2);
  assert.equal(provider.getStatus().lastRecoveryClassification, 'RECOVERED_TRANSIENT');

  // Permanent error (permission elevation) must NOT retry
  calls = 0;
  const permElevatedProvider = new ManagedTokenProvider(
    {
      repository: FULL_REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      allowedPermissions: { contents: 'read' },
      maxTransientRetries: 3,
      retryDelayMs: 5,
      nowMs: () => clock,
    },
    {
      kind: 'MOCK_BROKER',
      async issueToken(req) {
        calls += 1;
        return { ...(await broker.issueToken(req)), permissions: { contents: 'write' } };
      },
    },
  );
  await assert.rejects(() => permElevatedProvider.getToken(), /TOKEN_PERMISSION_ELEVATION_FORBIDDEN/);
  assert.equal(calls, 1);
  assert.equal(permElevatedProvider.getStatus().lastRecoveryClassification, 'BLOCKED_PERMANENT');
});

test('F3-09: Daemon constructor rejects shared V2 HALT public keys and exposes secret-free status v3 + doctor fields', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f3-daemon-'));
  try {
    const execKeys = genEd25519PemPair();
    assert.throws(
      () =>
        new DesktopControllerDaemon(
          {
            repository: FULL_REPO,
            prNumber: PR_NUM,
            workerId: WORKER,
            pinnedApp: PINNED_APP,
            executionId: 'exec-f3-status',
            targetId: 'target-f3-01',
            profileId: 'profile-f3-01',
            targetTabId: 1,
            journalPath: join(dir, 'j.json'),
            ipcSocketPath: join(dir, 'ipc.sock'),
            humanLiveSendAuthorized: false,
            liveProofs: { githubCasOwnerCertified: false, nativePairingOwnerCertified: false, realBrowserOwnerAccepted: false },
            asymmetricV2Enabled: true,
            executionPublicKeysById: new Map([['k1', execKeys.publicKeyPem]]),
            remoteHaltPublicKeysById: new Map([['k1', execKeys.publicKeyPem]]),
          },
          { tokenProvider: async () => '' },
        ),
      /DAEMON_HALT_KEY_SEPARATION_FORBIDDEN/,
    );

    const daemon = new DesktopControllerDaemon(
      {
        repository: FULL_REPO,
        prNumber: PR_NUM,
        workerId: WORKER,
        pinnedApp: PINNED_APP,
        executionId: 'exec-f3-status',
        targetId: 'target-f3-01',
        profileId: 'profile-f3-01',
        targetTabId: 1,
        journalPath: join(dir, 'j.json'),
        ipcSocketPath: join(dir, 'ipc.sock'),
        humanLiveSendAuthorized: false,
        liveProofs: { githubCasOwnerCertified: false, nativePairingOwnerCertified: false, realBrowserOwnerAccepted: false },
        expectedDeviceId: DEVICE_ID,
        minEnrollmentGeneration: 2,
      },
      { tokenProvider: async () => '' },
    );
    await daemon.start({ listen: false });
    const status = daemon.buildStatusSnapshot();
    assert.equal(status.version, 3);
    assert.equal(status.liveSendDefaults, 'LOCKED_FALSE');
    assert.equal(status.asymmetricV2Enabled, false);
    assert.equal(status.deviceIdentity.deviceId, DEVICE_ID);
    assert.equal(status.broker.protocolVersion, 'DISABLED');
    await daemon.stop();

    const doc = await runControllerDoctor({
      BKE_JOURNAL_PATH: join(dir, 'j.json'),
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'false',
    });
    assert.equal(doc.ok, true);
    assert.equal(doc.summary.brokerProtocolVersion, 'DISABLED');
    assert.equal(doc.summary.trustedBrokerAvailable, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
