/**
 * F4 P0-01 / P0-02 / P0-03 Security Remediation Unit Tests:
 * - Strict V2 isolation: forbid mixed V1+V2, compat modes, contradictory flags, partial V2 bindings
 * - Mandatory fail-closed device & token revocation + exact enrollment_generation enforcement
 * - GitHubF1Ledger desktop contents:write token refusal & mediated client scoping
 * - Controller doctor fail-closed checks on contradictory/compat/mediated-write configs
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
} from '../dist/native-host/claim/github-app-harness.js';
import { GitHubF1Ledger } from '../dist/native-host/claim/github-f1-ledger.js';
import { ManagedTokenProvider } from '../dist/native-host/claim/token-lifecycle.js';
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
const DEVICE_ID = 'dev-desktop-f4-001';
const BROKER_ISSUER = 'https://broker.bke.internal';
const AUDIENCE = buildExecutionAudience(FULL_REPO, WORKER);
const PR_NUM = 149;
const HEAD = 'a'.repeat(40);
const ATTEMPT = 'attempt-f4-01';
const DELIVERY = 'deliv-f4-0001';
const PINNED_APP = { id: 9001, slug: 'bke-dispatcher-app' };
const BASE_NOW = Date.parse('2026-10-20T12:00:00.000Z');
const HMAC_SECRET = 'f4-hmac-test-secret-material-32bytes!';

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
    enrollment_generation: 3,
    pr_number: PR_NUM,
    head_sha: HEAD,
    attempt_id: ATTEMPT,
    delivery_id: DELIVERY,
    action: 'HALT',
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
          permissions: { contents: 'read', pull_requests: 'read' },
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

test('F4 P0-01: ExecutionRequestVerifier enforces strict V2 isolation and forbids V1 fallback/mixed/contradictory configs', async () => {
  const execKeys = genEd25519PemPair();
  const haltKeys = genEd25519PemPair();

  const baseV2 = {
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
    expectedEnrollmentGeneration: 3,
    deviceRevocationChecker: () => ({ status: 'ACTIVE', revoked: false }),
    provider: makeStubProvider(),
    nowMs: () => BASE_NOW,
  };

  assert.throws(
    () => new ExecutionRequestVerifier({ ...baseV2, asymmetricV2Enabled: false, requireAsymmetricV2: true }),
    /EXEC_REQ_CONFIG_CONTRADICTORY/,
  );
  assert.throws(
    () => new ExecutionRequestVerifier({ ...baseV2, requireAsymmetricV2: false }),
    /EXEC_REQ_CONFIG_DOWNGRADE_FORBIDDEN/,
  );
  assert.throws(
    () => new ExecutionRequestVerifier({ ...baseV2, hmacKeysById: new Map([['v1', HMAC_SECRET]]) }),
    /EXEC_REQ_CONFIG_MIXED_V1_V2_FORBIDDEN/,
  );
  assert.throws(
    () => new ExecutionRequestVerifier({ ...baseV2, haltHmacKeysById: new Map([['v1-halt', HMAC_SECRET]]) }),
    /EXEC_REQ_CONFIG_MIXED_V1_V2_FORBIDDEN/,
  );
  assert.throws(
    () => new ExecutionRequestVerifier({ ...baseV2, publicKeysById: new Map() }),
    /EXEC_REQ_CONFIG_V2_KEYS_MISSING/,
  );
  assert.throws(
    () => new ExecutionRequestVerifier({ ...baseV2, expectedBrokerIssuer: undefined }),
    /EXEC_REQ_CONFIG_ISSUER_MISSING/,
  );
  assert.throws(
    () => new ExecutionRequestVerifier({ ...baseV2, expectedDeviceId: undefined }),
    /EXEC_REQ_CONFIG_DEVICE_ID_MISSING/,
  );
  assert.throws(
    () => new ExecutionRequestVerifier({ ...baseV2, deviceRevocationChecker: undefined }),
    /EXEC_REQ_REVOCATION_CHECKER_MISSING/,
  );

  // Even when requireAsymmetricV2 is omitted, asymmetricV2Enabled=true rejects V1 HMAC requests
  const strictV2Verifier = new ExecutionRequestVerifier({
    ...baseV2,
    requireAsymmetricV2: undefined,
  });
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
      attempt_id: 'attempt-f4-v1',
      delivery_id: 'deliv-f4-v1',
      action: 'HALT',
      issued_at: new Date(BASE_NOW - 5_000).toISOString(),
      expires_at: new Date(BASE_NOW + 60_000).toISOString(),
      authorized_capability: AUTHORIZED_CAPABILITY_V1,
    },
    HMAC_SECRET,
    'v1',
  );
  assert.equal((await strictV2Verifier.verifyAndAuthorize(v1Req)).code, 'EXEC_REQ_DOWNGRADE_FORBIDDEN');

  // Explicit V1-only isolated mode remains intact when asymmetricV2Enabled is false
  const v1OnlyVerifier = new ExecutionRequestVerifier({
    expectedRepositoryOwner: OWNER,
    expectedRepositoryName: REPO_NAME,
    expectedRepositoryId: REPO_ID,
    expectedInstallationId: INSTALL_ID,
    expectedWorkerId: WORKER,
    pinnedApp: PINNED_APP,
    asymmetricV2Enabled: false,
    requireAsymmetricV2: false,
    hmacKeysById: new Map([['v1', HMAC_SECRET]]),
    haltHmacKeysById: new Map([['v1-halt', 'different-halt-secret-material-32bytes']]),
    allowRemoteHalt: true,
    provider: makeStubProvider(),
    nowMs: () => BASE_NOW,
  });
  const v1Halt = signExecutionRequestHmac(
    {
      protocol_version: EXECUTION_REQUEST_PROTOCOL_VERSION,
      repository_owner: OWNER,
      repository_name: REPO_NAME,
      repository_id: REPO_ID,
      installation_identity: INSTALL_ID,
      worker_id: WORKER,
      pr_number: PR_NUM,
      head_sha: HEAD,
      attempt_id: 'attempt-v1-halt',
      delivery_id: 'deliv-v1-halt',
      action: 'HALT',
      issued_at: new Date(BASE_NOW - 5_000).toISOString(),
      expires_at: new Date(BASE_NOW + 60_000).toISOString(),
      authorized_capability: AUTHORIZED_CAPABILITY_V1,
    },
    'different-halt-secret-material-32bytes',
    'v1-halt',
  );
  assert.equal((await v1OnlyVerifier.verifyAndAuthorize(v1Halt)).ok, true);
});

test('F4 P0-02: ExecutionRequestVerifier fails closed on UNKNOWN/throwing revocation and rejects < and > enrollment generations', async () => {
  const execKeys = genEd25519PemPair();
  const haltKeys = genEd25519PemPair();

  let revBehavior = () => ({ status: 'ACTIVE', revoked: false });
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
    expectedEnrollmentGeneration: 3,
    deviceRevocationChecker: () => revBehavior(),
    provider: makeStubProvider(),
    nowMs: () => BASE_NOW,
  });

  // Exact generation 3 passes when ACTIVE
  const okReq = signExecutionRequestEd25519(
    makeEnvV2({ enrollment_generation: 3, delivery_id: 'd-gen3-ok' }),
    haltKeys.privateKeyPem,
    'ed-halt-1',
  );
  assert.equal((await verifier.verifyAndAuthorize(okReq)).ok, true);

  // Lower generation (2 < 3) AND higher generation (4 > 3) both fail
  const lowerGen = signExecutionRequestEd25519(
    makeEnvV2({ enrollment_generation: 2, delivery_id: 'd-gen2-bad' }),
    haltKeys.privateKeyPem,
    'ed-halt-1',
  );
  const higherGen = signExecutionRequestEd25519(
    makeEnvV2({ enrollment_generation: 4, delivery_id: 'd-gen4-bad' }),
    haltKeys.privateKeyPem,
    'ed-halt-1',
  );
  assert.equal((await verifier.verifyAndAuthorize(lowerGen)).code, 'EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH');
  assert.equal((await verifier.verifyAndAuthorize(higherGen)).code, 'EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH');

  // UNKNOWN revocation state -> EXEC_REQ_REVOCATION_UNAVAILABLE
  revBehavior = () => ({ status: 'UNKNOWN', revoked: true });
  assert.equal(
    (await verifier.verifyAndAuthorize(
      signExecutionRequestEd25519(makeEnvV2({ delivery_id: 'd-unknown' }), haltKeys.privateKeyPem, 'ed-halt-1'),
    )).code,
    'EXEC_REQ_REVOCATION_UNAVAILABLE',
  );

  // Throwing revocation check -> EXEC_REQ_REVOCATION_UNAVAILABLE
  revBehavior = () => {
    throw new Error('BROKER_NETWORK_DOWN');
  };
  assert.equal(
    (await verifier.verifyAndAuthorize(
      signExecutionRequestEd25519(makeEnvV2({ delivery_id: 'd-throw' }), haltKeys.privateKeyPem, 'ed-halt-1'),
    )).code,
    'EXEC_REQ_REVOCATION_UNAVAILABLE',
  );

  // REVOKED state -> EXEC_REQ_DEVICE_REVOKED
  revBehavior = () => ({ status: 'REVOKED', revoked: true });
  assert.equal(
    (await verifier.verifyAndAuthorize(
      signExecutionRequestEd25519(makeEnvV2({ delivery_id: 'd-revoked' }), haltKeys.privateKeyPem, 'ed-halt-1'),
    )).code,
    'EXEC_REQ_DEVICE_REVOKED',
  );
});

test('F4 P0-02: ManagedTokenProvider fails closed on UNKNOWN/throwing revocation and missing remote checker', async () => {
  let now = BASE_NOW;
  let tokenCounter = 0;

  let statusMode = 'ACTIVE';
  const makeRemoteBroker = (opts = {}) => ({
    kind: 'REMOTE_OWNER_CERTIFIED_BROKER',
    async issueToken() {
      tokenCounter += 1;
      return {
        token: `ghs_remote_${tokenCounter}`,
        tokenType: 'installation',
        installationId: INSTALL_ID,
        repositoryId: REPO_ID,
        repositories: [FULL_REPO],
        permissions: { contents: 'read', pull_requests: 'read' },
        issuedAtMs: now,
        expiresAtMs: now + 300_000,
      };
    },
    ...(opts.omitChecker
      ? {}
      : opts.legacyIsRevokedOnly
        ? {
            async isRevoked() {
              if (statusMode === 'THROW') throw new Error('NETWORK_FAIL');
              return statusMode === 'REVOKED';
            },
          }
        : {
            async checkTokenStatus() {
              if (statusMode === 'THROW') throw new Error('BROKER_TIMEOUT');
              if (statusMode === 'UNKNOWN') return { status: 'UNKNOWN', code: 'TOKEN_REVOCATION_UNAVAILABLE' };
              if (statusMode === 'REVOKED') return { status: 'REVOKED', code: 'TOKEN_REVOKED' };
              return { status: 'ACTIVE' };
            },
          }),
  });

  // Remote broker with checkTokenStatus
  const provider = new ManagedTokenProvider(
    {
      repository: FULL_REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      allowedPermissions: { contents: 'read', pull_requests: 'read' },
      nowMs: () => now,
    },
    makeRemoteBroker(),
  );
  const t1 = await provider.getToken();
  assert.equal(t1, 'ghs_remote_1');

  // Transient UNKNOWN/throw on cached token must FAIL CLOSED (must NOT return cached token!)
  statusMode = 'UNKNOWN';
  await assert.rejects(() => provider.getToken(), /TOKEN_REVOCATION_UNAVAILABLE/);
  statusMode = 'THROW';
  await assert.rejects(() => provider.getToken(), /TOKEN_REVOCATION_UNAVAILABLE/);
  // Once authority recovers ACTIVE, cached valid token works again; REVOKED permanently invalidates
  statusMode = 'ACTIVE';
  assert.equal(await provider.getToken(), 'ghs_remote_1');
  statusMode = 'REVOKED';
  await assert.rejects(() => provider.getToken(), /TOKEN_REVOKED/);
  assert.equal(provider.getStatus().revoked, true);

  // Legacy isRevoked throwing must ALSO fail closed (no .catch(() => false))
  statusMode = 'ACTIVE';
  const legacyProvider = new ManagedTokenProvider(
    {
      repository: FULL_REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      allowedPermissions: { contents: 'read', pull_requests: 'read' },
      nowMs: () => now,
    },
    makeRemoteBroker({ legacyIsRevokedOnly: true }),
  );
  await legacyProvider.getToken();
  statusMode = 'THROW';
  await assert.rejects(() => legacyProvider.getToken(), /TOKEN_REVOCATION_UNAVAILABLE/);

  // REMOTE_OWNER_CERTIFIED_BROKER missing both checkTokenStatus & isRevoked fails closed
  const noCheckerProvider = new ManagedTokenProvider(
    {
      repository: FULL_REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      allowedPermissions: { contents: 'read', pull_requests: 'read' },
      nowMs: () => now,
    },
    makeRemoteBroker({ omitChecker: true }),
  );
  await noCheckerProvider.getToken();
  await assert.rejects(() => noCheckerProvider.getToken(), /TOKEN_REVOCATION_CHECKER_MISSING/);
});

test('F4 P0-01 / P0-02 / P0-03: DesktopControllerDaemon & doctor fail closed on contradictory/mixed/compat/mediated-write configs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f4-daemon-'));
  const execKeys = genEd25519PemPair();
  const haltKeys = genEd25519PemPair();

  try {
    const baseDaemonCfg = {
      repository: FULL_REPO,
      prNumber: PR_NUM,
      workerId: WORKER,
      pinnedApp: PINNED_APP,
      executionId: 'exec-f4-01',
      targetId: 'target-f4-01',
      profileId: 'profile-f4-01',
      targetTabId: 1,
      journalPath: join(dir, 'j.json'),
      ipcSocketPath: join(dir, 'ipc.sock'),
      humanLiveSendAuthorized: false,
      liveProofs: { githubCasOwnerCertified: false, nativePairingOwnerCertified: false, realBrowserOwnerAccepted: false },
      executionEnvelopeEnabled: true,
      asymmetricV2Enabled: true,
      requireAsymmetricV2: true,
      expectedRepositoryId: REPO_ID,
      expectedInstallationId: INSTALL_ID,
      expectedBrokerIssuer: BROKER_ISSUER,
      expectedDeviceId: DEVICE_ID,
      expectedEnrollmentGeneration: 2,
      executionPublicKeysById: new Map([['exec-k1', execKeys.publicKeyPem]]),
      remoteHaltPublicKeysById: new Map([['halt-k1', haltKeys.publicKeyPem]]),
      deviceRevocationChecker: () => ({ status: 'ACTIVE', revoked: false }),
    };

    const dummyMediated = {
      async executeLedgerOp() {
        return { ok: true, status: 'COMMITTED', sha: HEAD };
      },
    };

    assert.throws(
      () =>
        new DesktopControllerDaemon(
          { ...baseDaemonCfg, asymmetricV2Enabled: false, requireAsymmetricV2: true },
          { tokenProvider: async () => '' },
        ),
      /DAEMON_CONFIG_CONTRADICTORY/,
    );
    assert.throws(
      () =>
        new DesktopControllerDaemon(
          { ...baseDaemonCfg, requireAsymmetricV2: false },
          { tokenProvider: async () => '' },
        ),
      /DAEMON_V2_COMPAT_MODE_FORBIDDEN/,
    );
    assert.throws(
      () =>
        new DesktopControllerDaemon(
          { ...baseDaemonCfg, executionEnvelopeEnabled: false },
          { tokenProvider: async () => '' },
        ),
      /DAEMON_CONFIG_V2_REQUIRES_ENVELOPE/,
    );
    assert.throws(
      () =>
        new DesktopControllerDaemon(
          { ...baseDaemonCfg, executionSigningKeysById: new Map([['v1', HMAC_SECRET]]) },
          { tokenProvider: async () => '' },
        ),
      /DAEMON_MIXED_V1_V2_CONFIG_FORBIDDEN/,
    );
    assert.throws(
      () =>
        new DesktopControllerDaemon(
          { ...baseDaemonCfg, expectedBrokerIssuer: undefined },
          { tokenProvider: async () => '' },
        ),
      /DAEMON_V2_BINDINGS_INCOMPLETE/,
    );
    assert.throws(
      () =>
        new DesktopControllerDaemon(
          { ...baseDaemonCfg, deviceRevocationChecker: undefined },
          { tokenProvider: async () => '' },
        ),
      /DAEMON_REVOCATION_CHECKER_MISSING/,
    );
    assert.throws(
      () =>
        new DesktopControllerDaemon(
          { ...baseDaemonCfg, mediatedCasEnabled: true },
          { tokenProvider: async () => '' },
        ),
      /DAEMON_MEDIATED_CAS_CLIENT_MISSING/,
    );

    const writeTokenLifecycle = new ManagedTokenProvider(
      {
        repository: FULL_REPO,
        repositoryId: REPO_ID,
        installationId: INSTALL_ID,
        workerId: WORKER,
        allowedPermissions: { contents: 'write' },
      },
      {
        kind: 'MOCK_BROKER',
        async issueToken() {
          throw new Error('unused');
        },
      },
    );
    assert.throws(
      () =>
        new DesktopControllerDaemon(
          { ...baseDaemonCfg, mediatedCasEnabled: true },
          {
            tokenProvider: writeTokenLifecycle.asTokenProvider(),
            tokenLifecycle: writeTokenLifecycle,
            mediatedLedgerClient: dummyMediated,
          },
        ),
      /DAEMON_WRITE_TOKEN_FORBIDDEN_IN_MEDIATED_MODE/,
    );

    // Valid V2 + mediated CAS daemon maps revocation/generation status codes cleanly
    let revStatus = { status: 'UNKNOWN', revoked: true };
    const readTokenLifecycle = new ManagedTokenProvider(
      {
        repository: FULL_REPO,
        repositoryId: REPO_ID,
        installationId: INSTALL_ID,
        workerId: WORKER,
        allowedPermissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
      },
      {
        kind: 'MOCK_BROKER',
        async issueToken() {
          throw new Error('unused');
        },
      },
    );
    const daemon = new DesktopControllerDaemon(
      {
        ...baseDaemonCfg,
        allowRemoteSignedHalt: true,
        mediatedCasEnabled: true,
        deviceRevocationChecker: () => revStatus,
      },
      {
        tokenProvider: readTokenLifecycle.asTokenProvider(),
        tokenLifecycle: readTokenLifecycle,
        mediatedLedgerClient: dummyMediated,
        nowMs: () => BASE_NOW,
      },
    );
    const started = await daemon.start({ listen: true });
    try {
      const status = daemon.buildStatusSnapshot();
      assert.equal(status.broker.protocolVersion, 'v2_ed25519_strict');
      assert.equal(status.mediatedCasEnabled, true);
      assert.equal(status.desktopWriteTokenForbidden, true);
      assert.equal(status.revocationAuthorityConfigured, true);

      const haltReq = signExecutionRequestEd25519(
        makeEnvV2({ enrollment_generation: 2, action: 'HALT', delivery_id: 'd-daemon-503' }),
        haltKeys.privateKeyPem,
        'halt-k1',
      );
      const res503 = await fetch(`http://127.0.0.1:${started.port}/execution-requests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(haltReq),
      });
      assert.equal(res503.status, 503);
      assert.equal((await res503.json()).code, 'EXEC_REQ_REVOCATION_UNAVAILABLE');

      revStatus = { status: 'ACTIVE', revoked: false };
      const wrongGenReq = signExecutionRequestEd25519(
        makeEnvV2({ enrollment_generation: 99, action: 'HALT', delivery_id: 'd-daemon-403' }),
        haltKeys.privateKeyPem,
        'halt-k1',
      );
      const res403 = await fetch(`http://127.0.0.1:${started.port}/execution-requests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(wrongGenReq),
      });
      assert.equal(res403.status, 403);
      assert.equal((await res403.json()).code, 'EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH');
    } finally {
      await daemon.stop();
    }

    // Doctor fails closed on contradictory/mixed/mediated-static-write env & never reports compat
    const badMixed = await runControllerDoctor({
      BKE_JOURNAL_PATH: join(dir, 'j.json'),
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REQUIRE_ASYMMETRIC_V2: 'true',
      BKE_EXECUTION_SIGNING_KEY_ID: 'v1',
      BKE_EXECUTION_SIGNING_KEY: HMAC_SECRET,
    });
    assert.equal(badMixed.ok, false);
    assert.ok(!JSON.stringify(badMixed).toLowerCase().includes('compat'));

    const badCompat = await runControllerDoctor({
      BKE_JOURNAL_PATH: join(dir, 'j.json'),
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REQUIRE_ASYMMETRIC_V2: 'false',
    });
    assert.equal(badCompat.ok, false);

    const badMediatedStatic = await runControllerDoctor({
      BKE_JOURNAL_PATH: join(dir, 'j.json'),
      BKE_SERVER_MEDIATED_CAS_ENABLED: 'true',
      BKE_GITHUB_INSTALLATION_TOKEN: 'ghs_static_not_allowed',
    });
    assert.equal(badMediatedStatic.ok, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('F4 P0-03: GitHubF1Ledger rejects contents:write and push:true installation scopes in mediated/desktop read-only mode', async () => {
  let permsMode = 'WRITE';
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (permsMode === 'WRITE') {
      res.end(JSON.stringify({ repositories: [{ id: REPO_ID, full_name: FULL_REPO, permissions: { contents: 'write', pull_requests: 'read' } }] }));
    } else if (permsMode === 'PUSH') {
      res.end(JSON.stringify({ repositories: [{ id: REPO_ID, full_name: FULL_REPO, permissions: { push: true, pull: true } }] }));
    } else {
      res.end(JSON.stringify({ repositories: [{ id: REPO_ID, full_name: FULL_REPO, permissions: { issues: 'read' } }] }));
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const baseApiUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    const ledger = new GitHubF1Ledger(
      {
        repository: FULL_REPO,
        prNumber: PR_NUM,
        headSha: HEAD,
        workerId: WORKER,
        authenticatedWorkerId: WORKER,
        pinnedApp: PINNED_APP,
        executionId: 'exec-f4-ro',
        targetId: 'target-f4-ro',
        profileId: 'profile-f4-ro',
        targetTabId: 1,
        baseApiUrl,
        forbidDesktopWriteToken: true,
        expectedRepositoryId: REPO_ID,
        expectedInstallationId: INSTALL_ID,
      },
      (url, init) => globalThis.fetch(url, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() })),
      async () => 'ghs_read_only_token',
    );

    permsMode = 'WRITE';
    await assert.rejects(() => ledger.refreshAuthority(), /GITHUB_DESKTOP_WRITE_TOKEN_FORBIDDEN/);

    permsMode = 'PUSH';
    await assert.rejects(() => ledger.refreshAuthority(), /GITHUB_DESKTOP_WRITE_TOKEN_FORBIDDEN/);

    permsMode = 'MISSING_READ';
    await assert.rejects(() => ledger.refreshAuthority(), /GITHUB_INSTALLATION_READ_SCOPE_MISSING/);
  } finally {
    await new Promise((r) => server.close(() => r()));
  }
});
