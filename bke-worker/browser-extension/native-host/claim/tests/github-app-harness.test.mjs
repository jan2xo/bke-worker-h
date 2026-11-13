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

  // Canonical serialization determinism check
  const env = makeValidEnvelope();
  const s1 = serializeCanonicalExecutionEnvelope(env);
  const s2 = serializeCanonicalExecutionEnvelope({ ...env, worker_id: WORKER, protocol_version: 1 });
  assert.equal(s1, s2);
  assert.equal(validateExecutionEnvelopeShape({ ...env, action: 'UNSAFE_EVAL' }).ok, false);
});
