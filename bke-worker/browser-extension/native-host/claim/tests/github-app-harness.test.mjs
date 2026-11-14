/**
 * Workstream C: 21-case Adversarial & Boundary Test Suite for GitHubApp Integration Harness.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  AUTHORIZED_CAPABILITY_V1,
  EXECUTION_REQUEST_PROTOCOL_VERSION,
  ExecutionRequestVerifier,
  serializeCanonicalExecutionEnvelope,
  signExecutionRequestHmac,
  validateExecutionEnvelopeShape,
} from '../dist/native-host/claim/github-app-harness.js';

const OWNER = 'jan2xo';
const REPO_NAME = 'bke-worker';
const FULL_REPO = `${OWNER}/${REPO_NAME}`;
const REPO_ID = 1354026486;
const INSTALL_ID = '987654321';
const WORKER = 'worker-f1';
const PR_NUM = 149;
const HEAD = 'a'.repeat(40);
const OTHER_HEAD = 'b'.repeat(40);
const ATTEMPT = 'attempt-c-01';
const DELIVERY = 'deliv-c-0001';
const KEY_ID = 'broker-key-2026-1';
const SECRET = 'super-secret-broker-hmac-key-material-32bytes';
const PINNED_APP = { id: 9001, slug: 'bke-dispatcher-app' };
const BASE_NOW = Date.parse('2026-10-20T12:00:00.000Z');

function makeValidEnvelope(overrides = {}) {
  return {
    protocol_version: EXECUTION_REQUEST_PROTOCOL_VERSION,
    repository_owner: OWNER,
    repository_name: REPO_NAME,
    repository_id: REPO_ID,
    installation_identity: INSTALL_ID,
    worker_id: WORKER,
    pr_number: PR_NUM,
    head_sha: HEAD,
    attempt_id: ATTEMPT,
    delivery_id: DELIVERY,
    action: 'DISPATCH_FIRST_MESSAGE',
    issued_at: new Date(BASE_NOW - 10_000).toISOString(),
    expires_at: new Date(BASE_NOW + 60_000).toISOString(),
    authorized_capability: AUTHORIZED_CAPABILITY_V1,
    ...overrides,
  };
}

function makeProvider(state = {}) {
  const cfg = {
    installOk: true,
    openPrs: [{ number: PR_NUM, state: 'open', headSha: HEAD, workerLabels: [WORKER] }],
    pr: { number: PR_NUM, state: 'open', headSha: HEAD, workerLabels: [WORKER] },
    consumedAttempts: [],
    uncertainAttempts: [],
    ticketOk: true,
    ticketAttempt: ATTEMPT,
    ...state,
  };

  return {
    cfg,
    provider: {
      async verifyInstallationScope() {
        return cfg.installOk
          ? { ok: true, scope: { installationId: INSTALL_ID, repositoryId: REPO_ID, repositoryFullName: FULL_REPO, permissions: { contents: 'write', issues: 'write', pull_requests: 'write' } } }
          : { ok: false, code: 'GITHUB_INSTALLATION_SCOPE_MISMATCH' };
      },
      async readPullRequest() { return cfg.pr; },
      async enumerateOpenAssignedPullRequests() { return cfg.openPrs; },
      async readPinnedTicket() {
        return cfg.ticketOk
          ? { ok: true, ticket: { contractVersion: 1, checkRunId: 101, ticketId: 'check-run:101', attemptId: cfg.ticketAttempt, workerId: WORKER, expiresAtMs: BASE_NOW + 60_000, headSha: HEAD } }
          : { ok: false, code: 'GITHUB_TICKET_INVALID_OR_CONSUMED' };
      },
      async readBkeRefState() {
        return {
          consumedAttempts: cfg.consumedAttempts,
          uncertainAttempts: cfg.uncertainAttempts,
          conversationTipSha: null,
        };
      },
    },
  };
}

function makeVerifier(providerHolder, nowFn = () => BASE_NOW) {
  return new ExecutionRequestVerifier({
    expectedRepositoryOwner: OWNER,
    expectedRepositoryName: REPO_NAME,
    expectedRepositoryId: REPO_ID,
    expectedInstallationId: INSTALL_ID,
    expectedWorkerId: WORKER,
    pinnedApp: PINNED_APP,
    hmacKeysById: new Map([[KEY_ID, SECRET]]),
    provider: providerHolder.provider,
    nowMs: nowFn,
  });
}

test('Workstream C: Valid canonical signed execution request authorizes cleanly', async () => {
  const ph = makeProvider();
  const verifier = makeVerifier(ph);
  const signed = signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID);
  const res = await verifier.verifyAndAuthorize(signed);
  assert.equal(res.ok, true);
  if (res.ok) {
    assert.equal(res.envelope.attempt_id, ATTEMPT);
    assert.equal(res.ticket.attemptId, ATTEMPT);
  }
});

test('Workstream C: 21-case adversarial security & authority boundary matrix', async () => {
  const cases = [
    // 1. Missing wrapper / non-object
    { name: '1. non-object wrapper', req: null, code: 'EXEC_REQ_WRAPPER_INVALID' },
    // 2. Extra field injected in wrapper (role separation)
    { name: '2. injected wrapper field', req: { ...signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), authorized: true }, code: 'EXEC_REQ_SIGNATURE_ENVELOPE_INVALID' },
    // 3. Unknown signing key ID
    { name: '3. unknown key_id', req: signExecutionRequestHmac(makeValidEnvelope(), SECRET, 'wrong-key'), code: 'EXEC_REQ_SIGNING_KEY_UNKNOWN' },
    // 4. Tampered HMAC signature
    { name: '4. tampered signature', req: { ...signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), signature_hex: '0'.repeat(64) }, code: 'EXEC_REQ_SIGNATURE_INVALID' },
    // 5. Unsupported protocol_version
    { name: '5. wrong protocol version', req: { ...signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), envelope: { ...makeValidEnvelope(), protocol_version: 2 } }, code: 'EXEC_REQ_UNSUPPORTED_VERSION' },
    // 6. Client injected extra property in envelope (trusted: true)
    { name: '6. extra field in envelope', req: { ...signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), envelope: { ...makeValidEnvelope(), trusted: true } }, code: 'EXEC_REQ_SCHEMA_MISMATCH' },
    // 7. Forbidden raw capability string
    { name: '7. forged capability', req: { envelope: makeValidEnvelope({ authorized_capability: 'ADMIN_ALL' }), signature_alg: 'HMAC-SHA256', key_id: KEY_ID, signature_hex: 'a'.repeat(64) }, code: 'EXEC_REQ_CAPABILITY_INVALID' },
    // 8. Wrong repository owner/name
    { name: '8. wrong repository owner', req: signExecutionRequestHmac(makeValidEnvelope({ repository_owner: 'evil-org' }), SECRET, KEY_ID), code: 'EXEC_REQ_TARGET_REPOSITORY_MISMATCH' },
    // 9. Wrong immutable repository_id
    { name: '9. wrong repository_id', req: signExecutionRequestHmac(makeValidEnvelope({ repository_id: 999999 }), SECRET, KEY_ID), code: 'EXEC_REQ_TARGET_REPOSITORY_MISMATCH' },
    // 10. Wrong installation_identity
    { name: '10. wrong installation_identity', req: signExecutionRequestHmac(makeValidEnvelope({ installation_identity: '111111' }), SECRET, KEY_ID), code: 'EXEC_REQ_INSTALLATION_MISMATCH' },
    // 11. Wrong worker_id
    { name: '11. wrong worker_id', req: signExecutionRequestHmac(makeValidEnvelope({ worker_id: 'worker-b' }), SECRET, KEY_ID), code: 'EXEC_REQ_WORKER_MISMATCH' },
    // 12. Expired envelope
    { name: '12. expired envelope', req: signExecutionRequestHmac(makeValidEnvelope({ issued_at: new Date(BASE_NOW - 120_000).toISOString(), expires_at: new Date(BASE_NOW - 1_000).toISOString() }), SECRET, KEY_ID), code: 'EXEC_REQ_EXPIRED' },
    // 13. Future not-yet-valid issued_at beyond skew
    { name: '13. future issued_at', req: signExecutionRequestHmac(makeValidEnvelope({ issued_at: new Date(BASE_NOW + 60_000).toISOString(), expires_at: new Date(BASE_NOW + 120_000).toISOString() }), SECRET, KEY_ID), code: 'EXEC_REQ_NOT_YET_VALID' },
    // 14. Installation permission/scope check fails
    { name: '14. under-granted installation', providerPatch: { installOk: false }, req: signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), code: 'GITHUB_INSTALLATION_SCOPE_MISMATCH' },
    // 15. Multi-PR assignment conflict
    { name: '15. multi-PR conflict', providerPatch: { openPrs: [{ number: PR_NUM }, { number: PR_NUM + 1 }] }, req: signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), code: 'GITHUB_WORKER_MULTI_PR_CONFLICT' },
    // 16. PR closed
    { name: '16. closed PR', providerPatch: { pr: { number: PR_NUM, state: 'closed', headSha: HEAD, workerLabels: [WORKER] } }, req: signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), code: 'GITHUB_PR_NOT_OPEN' },
    // 17. Worker label removed/changed on PR
    { name: '17. PR label mismatch', providerPatch: { pr: { number: PR_NUM, state: 'open', headSha: HEAD, workerLabels: ['other-worker'] } }, req: signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), code: 'GITHUB_WORKER_ASSIGNMENT_CONFLICT' },
    // 18. Stale head_sha
    { name: '18. stale head_sha', req: signExecutionRequestHmac(makeValidEnvelope({ head_sha: OTHER_HEAD }), SECRET, KEY_ID), code: 'GITHUB_HEAD_SHA_STALE' },
    // 19. Delivery uncertain quarantine present in GitHub
    { name: '19. GitHub uncertain quarantine', providerPatch: { uncertainAttempts: [ATTEMPT] }, req: signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), code: 'GITHUB_DELIVERY_UNCERTAIN_QUARANTINED' },
    // 20. Attempt already consumed in GitHub refs/bke/claims
    { name: '20. consumed claim in GitHub', providerPatch: { consumedAttempts: [ATTEMPT] }, req: signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), code: 'GITHUB_ATTEMPT_ALREADY_CONSUMED' },
    // 21. Pinned ticket attempt mismatch / missing ticket
    { name: '21. ticket attempt mismatch', providerPatch: { ticketAttempt: 'other-attempt' }, req: signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID), code: 'EXEC_REQ_TICKET_ATTEMPT_MISMATCH' },
  ];

  for (const c of cases) {
    const ph = makeProvider(c.providerPatch ?? {});
    const verifier = makeVerifier(ph);
    const res = await verifier.verifyAndAuthorize(c.req);
    assert.equal(res.ok, false, c.name);
    assert.equal(res.code, c.code, c.name);
  }

  // Delivery & attempt replay protection on verifier instance
  const ph = makeProvider();
  const verifier = makeVerifier(ph);
  const first = signExecutionRequestHmac(makeValidEnvelope(), SECRET, KEY_ID);
  assert.equal((await verifier.verifyAndAuthorize(first)).ok, true);
  assert.equal((await verifier.verifyAndAuthorize(first)).code, 'EXEC_REQ_DELIVERY_REPLAY');

  const secondDeliverySameAttempt = signExecutionRequestHmac(makeValidEnvelope({ delivery_id: 'deliv-c-0002' }), SECRET, KEY_ID);
  assert.equal((await verifier.verifyAndAuthorize(secondDeliverySameAttempt)).code, 'EXEC_REQ_ATTEMPT_REPLAY');

  // Canonical serialization determinism check & missing field / action checks
  const env = makeValidEnvelope();
  const s1 = serializeCanonicalExecutionEnvelope(env);
  const s2 = serializeCanonicalExecutionEnvelope({ ...env, worker_id: WORKER, protocol_version: 1 });
  assert.equal(s1, s2);
  assert.equal(validateExecutionEnvelopeShape({ ...env, action: 'UNSAFE_EVAL' }).ok, false);
  const { attempt_id: _omitted, ...missingFieldEnv } = env;
  assert.equal(validateExecutionEnvelopeShape(missingFieldEnv).code, 'EXEC_REQ_SCHEMA_MISMATCH');
});

import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GITHUB_AUTHORITY_PERMISSION_MAP, RestGitHubAuthorityProvider } from '../dist/native-host/claim/github-authority-provider.js';
import { FileExecutionJournal } from '../dist/native-host/claim/desktop-controller.js';
import {
  DeterministicMockTokenBroker,
  ManagedTokenProvider,
  RemoteBrokerTransportStub,
} from '../dist/native-host/claim/token-lifecycle.js';

test('F2-02: Remote signed HALT requires allowRemoteHalt=true and separate haltHmacKeysById', async () => {
  const ph = makeProvider();
  const haltEnv = makeValidEnvelope({ action: 'HALT', delivery_id: 'deliv-halt-1' });
  const dispatchSignedHalt = signExecutionRequestHmac(haltEnv, SECRET, KEY_ID);

  // 1. Default-OFF remote halt blocks even with valid signature
  const vDefault = makeVerifier(ph);
  assert.equal((await vDefault.verifyAndAuthorize(dispatchSignedHalt)).code, 'EXEC_REQ_REMOTE_HALT_DISABLED');

  // 2. Shared dispatch secret cannot authorize HALT even when allowRemoteHalt=true
  const vShared = new ExecutionRequestVerifier({
    expectedRepositoryOwner: OWNER,
    expectedRepositoryName: REPO_NAME,
    expectedRepositoryId: REPO_ID,
    expectedInstallationId: INSTALL_ID,
    expectedWorkerId: WORKER,
    pinnedApp: PINNED_APP,
    hmacKeysById: new Map([[KEY_ID, SECRET]]),
    haltHmacKeysById: new Map([[KEY_ID, SECRET]]),
    allowRemoteHalt: true,
    provider: ph.provider,
    nowMs: () => BASE_NOW,
  });
  assert.equal((await vShared.verifyAndAuthorize(dispatchSignedHalt)).code, 'EXEC_REQ_HALT_KEY_SEPARATION_REQUIRED');

  // 3. Dedicated separated HALT key authorizes cleanly
  const HALT_SECRET = 'dedicated-remote-halt-key-material-64bytes';
  const vSeparated = new ExecutionRequestVerifier({
    expectedRepositoryOwner: OWNER,
    expectedRepositoryName: REPO_NAME,
    expectedRepositoryId: REPO_ID,
    expectedInstallationId: INSTALL_ID,
    expectedWorkerId: WORKER,
    pinnedApp: PINNED_APP,
    hmacKeysById: new Map([[KEY_ID, SECRET]]),
    haltHmacKeysById: new Map([['halt-key-1', HALT_SECRET]]),
    allowRemoteHalt: true,
    provider: ph.provider,
    nowMs: () => BASE_NOW,
  });
  assert.equal((await vSeparated.verifyAndAuthorize(dispatchSignedHalt)).code, 'EXEC_REQ_HALT_KEY_UNAUTHORIZED');
  const validHalt = signExecutionRequestHmac(haltEnv, HALT_SECRET, 'halt-key-1');
  const okRes = await vSeparated.verifyAndAuthorize(validHalt);
  assert.equal(okRes.ok, true);
});

test('F2-03: RestGitHubAuthorityProvider GET-only REST adapter, pagination, ID check, and fail-closed HTTP matrix', async () => {
  const methodsSeen = [];
  let mode = 'OK_PAGINATED';
  let baseUrl = '';
  const SECRET_TOKEN = 'ghs_sensitive_test_installation_token_9999';

  const server = createServer((req, res) => {
    methodsSeen.push(req.method);
    const u = new URL(req.url, 'http://127.0.0.1');
    const page = u.searchParams.get('page') ?? '1';
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };

    if (mode === 'STATUS_401') return send(401, { message: 'Bad credentials' });
    if (mode === 'STATUS_403_PERM') return send(403, { message: 'Resource not accessible by integration' });
    if (mode === 'STATUS_403_RATE') return send(403, { message: 'API rate limit' }, { 'x-ratelimit-remaining': '0' });
    if (mode === 'STATUS_404') return send(404, { message: 'Not Found' });
    if (mode === 'STATUS_409') return send(409, { message: 'Conflict' });
    if (mode === 'STATUS_422') return send(422, { message: 'Unprocessable' });
    if (mode === 'STATUS_429') return send(429, { message: 'Too Many Requests' });
    if (mode === 'STATUS_503') return send(503, { message: 'Service Unavailable' });
    if (mode === 'MALFORMED_JSON') return send(200, '{not-json');
    if (mode === 'BAD_LINK') return send(200, { repositories: [] }, { Link: '<https://evil.example/next>; rel="next"' });

    if (u.pathname === '/installation/repositories') {
      if (mode === 'OVERPRIVILEGED') {
        return send(200, { repositories: [{ id: REPO_ID, full_name: FULL_REPO, permissions: { admin: true, push: true } }] });
      }
      if (mode === 'WRONG_REPO_ID') {
        return send(200, { repositories: [{ id: 123456, full_name: FULL_REPO, permissions: { pull: true } }] });
      }
      if (page === '1') {
        return send(200, { repositories: [{ id: 111, full_name: 'other/repo', permissions: { pull: true } }] }, { Link: `<${baseUrl}/installation/repositories?per_page=100&page=2>; rel="next"` });
      }
      return send(200, { repositories: [{ id: REPO_ID, full_name: FULL_REPO, permissions: { contents: 'read', pull_requests: 'read', checks: 'read' } }] });
    }
    if (u.pathname === `/repos/${FULL_REPO}/pulls`) {
      if (page === '1') {
        return send(200, [{ number: 10, state: 'open', head: { sha: OTHER_HEAD }, labels: [{ name: 'bke-worker:other' }] }], { Link: `<${baseUrl}/repos/${FULL_REPO}/pulls?state=open&page=2>; rel="next"` });
      }
      return send(200, [{ number: PR_NUM, state: 'open', head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] }]);
    }
    if (u.pathname === `/repos/${FULL_REPO}/pulls/${PR_NUM}`) {
      if (mode === 'MULTI_WORKER_LABEL') {
        return send(200, { number: PR_NUM, state: 'open', head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }, { name: 'bke-worker:worker-2' }] });
      }
      return send(200, { number: PR_NUM, state: 'open', head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] });
    }
    if (u.pathname === `/repos/${FULL_REPO}/commits/${HEAD}/check-runs`) {
      if (mode === 'CHECK_TRUNCATED') {
        return send(200, { total_count: 5, check_runs: [] });
      }
      return send(200, {
        total_count: 1,
        check_runs: [{
          id: 501, name: 'bke-ticket', app: PINNED_APP, head_sha: HEAD, status: 'completed', conclusion: 'success',
          external_id: `bke-ticket:v1:${WORKER}:${ATTEMPT}:${Math.floor((BASE_NOW + 60_000) / 1000)}`,
        }],
      });
    }
    if (u.pathname === `/repos/${FULL_REPO}/git/matching-refs/bke/`) {
      return send(200, [
        { ref: `refs/bke/claims/${PR_NUM}/old-attempt`, object: { sha: HEAD } },
      ]);
    }
    return send(404, { message: 'Not Found' });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.deepEqual(GITHUB_AUTHORITY_PERMISSION_MAP.readOnlyAuthorityProvider.allowedHttpMethods, ['GET']);
    const provider = new RestGitHubAuthorityProvider(
      (url, init) => globalThis.fetch(url, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() })),
      async () => SECRET_TOKEN,
      { baseApiUrl: baseUrl, maxPages: 4, nowMs: () => BASE_NOW },
    );

    // Full read-only paginated happy path
    const scope = await provider.verifyInstallationScope(FULL_REPO, REPO_ID, INSTALL_ID);
    assert.equal(scope.ok, true);
    const prs = await provider.enumerateOpenAssignedPullRequests(FULL_REPO, WORKER);
    assert.equal(prs.length, 1);
    assert.equal(prs[0].number, PR_NUM);
    const pr = await provider.readPullRequest(FULL_REPO, PR_NUM);
    assert.equal(pr?.headSha, HEAD);
    const refs = await provider.readBkeRefState(FULL_REPO, PR_NUM);
    assert.deepEqual(refs.consumedAttempts, ['old-attempt']);
    const ticket = await provider.readPinnedTicket(FULL_REPO, HEAD, WORKER, PINNED_APP, new Set(refs.consumedAttempts), BASE_NOW);
    assert.equal(ticket.ok, true);
    assert.ok(methodsSeen.length >= 5 && methodsSeen.every((m) => m === 'GET'));

    // Multi-label PR ownership detection
    mode = 'MULTI_WORKER_LABEL';
    const multiPr = await provider.readPullRequest(FULL_REPO, PR_NUM);
    assert.equal(multiPr?.workerLabels.length, 2);

    // Wrong repo ID, overprivileged admin, cross-origin pagination link, check-run truncation
    mode = 'WRONG_REPO_ID';
    assert.equal((await provider.verifyInstallationScope(FULL_REPO, REPO_ID, INSTALL_ID)).code, 'GITHUB_REPOSITORY_ID_MISMATCH');
    mode = 'OVERPRIVILEGED';
    assert.equal((await provider.verifyInstallationScope(FULL_REPO, REPO_ID, INSTALL_ID)).code, 'GITHUB_INSTALLATION_OVERPRIVILEGED');
    mode = 'BAD_LINK';
    assert.equal((await provider.verifyInstallationScope(FULL_REPO, REPO_ID, INSTALL_ID)).code, 'GITHUB_PAGINATION_CROSS_ORIGIN_FORBIDDEN');
    mode = 'CHECK_TRUNCATED';
    assert.equal((await provider.readPinnedTicket(FULL_REPO, HEAD, WORKER, PINNED_APP, new Set(), BASE_NOW)).code, 'GITHUB_CHECK_RUNS_TRUNCATED');

    // HTTP failure codes (401, 403 perm, 403 rate, 404, 409, 422, 429, 503, malformed JSON) & zero token leak
    for (const [m, expected] of [
      ['STATUS_401', 'GITHUB_AUTH_UNAUTHORIZED'],
      ['STATUS_403_PERM', 'GITHUB_PERMISSION_FORBIDDEN'],
      ['STATUS_403_RATE', 'GITHUB_RATE_LIMITED'],
      ['STATUS_409', 'GITHUB_CONFLICT'],
      ['STATUS_422', 'GITHUB_UNPROCESSABLE'],
      ['STATUS_429', 'GITHUB_RATE_LIMITED'],
      ['STATUS_503', 'GITHUB_INSTALLATION_UNAVAILABLE'],
      ['MALFORMED_JSON', 'GITHUB_MALFORMED_JSON'],
    ]) {
      mode = m;
      const errRes = await provider.verifyInstallationScope(FULL_REPO, REPO_ID, INSTALL_ID);
      assert.equal(errRes.ok, false, m);
      assert.equal(errRes.code, expected, m);
      assert.equal(errRes.code.includes(SECRET_TOKEN), false);
    }
    mode = 'STATUS_404';
    assert.equal(await provider.readPullRequest(FULL_REPO, PR_NUM), null);
  } finally {
    await new Promise((resolve) => server.close(() => resolve()));
  }
});

test('F2-04: ManagedTokenProvider preemptive renewal, single-flight coalescing, scope clamping, revocation, abort, and 5-flag status', async () => {
  let clock = BASE_NOW;
  const broker = new DeterministicMockTokenBroker(() => clock, { ttlMs: 120_000 });
  const provider = new ManagedTokenProvider(
    {
      repository: FULL_REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      allowedPermissions: { contents: 'write', pull_requests: 'read', checks: 'read' },
      refreshMarginMs: 30_000,
      requestTimeoutMs: 250,
      nowMs: () => clock,
    },
    broker,
  );

  // 5 concurrent callers coalesce into 1 broker issuance
  const concurrent = await Promise.all(Array.from({ length: 5 }, () => provider.getToken()));
  assert.equal(new Set(concurrent).size, 1);
  assert.equal(broker.issueCalls, 1);

  const status = provider.getStatus();
  assert.equal(status.tokenLifecycleInterfaceImplemented, true);
  assert.equal(status.mockBrokerSupported, true);
  assert.equal(status.trustedRealBrokerApiAvailable, false);
  assert.equal(status.realBrokerTransportConnected, false);
  assert.equal(status.realGitHubAppRenewalCertified, false);

  // Preemptive renewal inside refreshMarginMs
  clock += 95_000;
  const renewed = await provider.getToken();
  assert.notEqual(renewed, concurrent[0]);
  assert.equal(broker.issueCalls, 2);

  // Revocation detected immediately
  broker.revokeToken(renewed);
  await assert.rejects(() => provider.getToken(), /TOKEN_REVOKED/);

  // Scope & permission elevation protections
  for (const [label, patch, code] of [
    ['wrong installation', { forceInstallationId: '111' }, /TOKEN_INSTALLATION_MISMATCH/],
    ['wrong repo', { forceRepositories: ['evil/repo'] }, /TOKEN_REPOSITORY_SCOPE_MISMATCH/],
    ['wrong repo id', { forceRepositoryId: 999 }, /TOKEN_REPOSITORY_ID_MISMATCH/],
    ['elevated write->admin', { forcePermissions: { contents: 'admin' } }, /TOKEN_PERMISSION_ELEVATION_FORBIDDEN/],
    ['elevated read->write', { forcePermissions: { pull_requests: 'write' } }, /TOKEN_PERMISSION_ELEVATION_FORBIDDEN/],
    ['expired response', { forceExpiresAtMs: clock - 1 }, /TOKEN_ALREADY_EXPIRED_OR_STALE/],
    ['broker unavailable', { unavailable: true }, /TOKEN_BROKER_UNAVAILABLE/],
  ]) {
    broker.behavior = patch;
    provider.invalidate('test_reset');
    await assert.rejects(() => provider.getToken(), code, label);
  }

  // Timeout & caller AbortSignal cancellation without wedging future valid calls
  broker.behavior = { latencyMs: 500 };
  provider.invalidate('test_reset');
  await assert.rejects(() => provider.getToken(), /TOKEN_BROKER_TIMEOUT/);

  broker.behavior = { latencyMs: 10 };
  const ac = new AbortController();
  ac.abort();
  await assert.rejects(() => provider.getToken({ signal: ac.signal }), /TOKEN_REQUEST_ABORTED/);
  const recovered = await provider.getToken();
  assert.ok(recovered.startsWith('ghs_mock_inst_'));

  // Remote broker transport stays explicitly disabled by default
  const stub = new RemoteBrokerTransportStub();
  await assert.rejects(
    () => stub.issueToken({ repository: FULL_REPO, installationId: INSTALL_ID, workerId: WORKER, requestedPermissions: { contents: 'read' }, reason: 't', signal: new AbortController().signal }),
    /REAL_BROKER_TRANSPORT_DISABLED_NOT_AUTHORIZED/,
  );
});

test('F2-05: PersistentReplayStore survives ExecutionRequestVerifier restart for PREPARE, delivery replay, and attempt replay', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f2-replay-'));
  try {
    const jPath = join(dir, 'journal.json');
    const j1 = new FileExecutionJournal(jPath, { repository: FULL_REPO, prNumber: PR_NUM, workerId: WORKER });
    await j1.openAndRecover();
    const ph = makeProvider();

    const v1 = new ExecutionRequestVerifier({
      expectedRepositoryOwner: OWNER, expectedRepositoryName: REPO_NAME, expectedRepositoryId: REPO_ID,
      expectedInstallationId: INSTALL_ID, expectedWorkerId: WORKER, pinnedApp: PINNED_APP,
      hmacKeysById: new Map([[KEY_ID, SECRET]]), provider: ph.provider,
      replayStore: j1.asPersistentReplayStore(), nowMs: () => BASE_NOW,
    });

    // PREPARE does not consume attempt, but deduplicates its delivery_id persistently
    const prep = signExecutionRequestHmac(makeValidEnvelope({ action: 'PREPARE', delivery_id: 'deliv-prep-1' }), SECRET, KEY_ID);
    assert.equal((await v1.verifyAndAuthorize(prep)).ok, true);

    // DISPATCH_FIRST_MESSAGE reserves attempt persistently
    const disp = signExecutionRequestHmac(makeValidEnvelope({ action: 'DISPATCH_FIRST_MESSAGE', delivery_id: 'deliv-disp-1' }), SECRET, KEY_ID);
    assert.equal((await v1.verifyAndAuthorize(disp)).ok, true);

    // Simulate process restart with new FileExecutionJournal + new ExecutionRequestVerifier
    const j2 = new FileExecutionJournal(jPath, { repository: FULL_REPO, prNumber: PR_NUM, workerId: WORKER });
    const rec = await j2.openAndRecover();
    // Pre-dispatch restart restores safe IDLE while keeping reservedAttempts burned
    assert.equal(rec.phase, 'IDLE');
    assert.ok(rec.reservedAttempts.includes(ATTEMPT));

    const v2 = new ExecutionRequestVerifier({
      expectedRepositoryOwner: OWNER, expectedRepositoryName: REPO_NAME, expectedRepositoryId: REPO_ID,
      expectedInstallationId: INSTALL_ID, expectedWorkerId: WORKER, pinnedApp: PINNED_APP,
      hmacKeysById: new Map([[KEY_ID, SECRET]]), provider: ph.provider,
      replayStore: j2.asPersistentReplayStore(), nowMs: () => BASE_NOW,
    });
    assert.equal((await v2.verifyAndAuthorize(prep)).code, 'EXEC_REQ_DELIVERY_REPLAY');
    assert.equal((await v2.verifyAndAuthorize(disp)).code, 'EXEC_REQ_DELIVERY_REPLAY');
    const newDelivSameAttempt = signExecutionRequestHmac(makeValidEnvelope({ delivery_id: 'deliv-disp-2' }), SECRET, KEY_ID);
    assert.equal((await v2.verifyAndAuthorize(newDelivSameAttempt)).code, 'EXEC_REQ_ATTEMPT_REPLAY');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
