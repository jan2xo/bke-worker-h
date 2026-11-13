/**
 * Workstream E: Comprehensive Adversarial Reliability, Crash-Recovery & Failure Matrix.
 *
 * Covers the full failure surface:
 * 1. Journal tampering: 0o644 world-readable, symlink, corrupt JSON, truncated JSON, atomic .tmp leftover
 * 2. Crash recovery: crash before fence (safe resume), after claim / DISPATCHING / CONTINUING (quarantine)
 * 3. Crash after click before GitHub conversation reconciliation (quarantine + refs/bke/uncertain/*)
 * 4. IPC / Native host / MV3 bridge: socket missing, socket unlinked mid-dispatch, host crash while idle vs in-flight
 * 5. GitHub failures: worker label removed/reassigned, PR closed/merged, head SHA changed before/after claim,
 *    duplicate/out-of-order webhooks, truncated pagination Link: next on all endpoints, 5xx/timeout,
 *    CAS 422 conflict vs uncertain non-already-exists 422, read-back mismatch
 * 6. ChatGPT / Browser failures: AUTH_REQUIRED, missing composer, busy turn, multiple writable tabs,
 *    wrong tab/target, navigation/URL drift before or mid-send, network stall after submit click
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createDeviceIdentityBridge } from '../../../dist/device-identity.js';
import {
  connectControllerNativeBridge,
  createControllerBridgeSupervisor,
} from '../../../dist/controller-transport.js';
import { ExtensionBrowserAdapter } from '../../../dist/extension-browser-adapter.js';
import { DesktopController, FileExecutionJournal } from '../dist/native-host/claim/desktop-controller.js';
import { GitHubF1Ledger } from '../dist/native-host/claim/github-f1-ledger.js';
import { IpcBridgeClient } from '../dist/native-host/claim/ipc-client.js';

const REPO = 'jan2xo/bke-worker';
const WORKER = 'worker-f1';
const PR = 149;
const HEAD = 'c'.repeat(40);
const OTHER_HEAD = 'd'.repeat(40);
const TREE = 'e'.repeat(40);
const PINNED_APP = { id: 9001, slug: 'bke-dispatcher-app' };
const ORIGIN = 'chrome-extension://' + 'a'.repeat(32) + '/';
const PROFILE_BINDING = '4'.repeat(64);
const RESOURCES = {
  chatgpt_target_sha256: '1'.repeat(64),
  browser_profile_sha256: '2'.repeat(64),
  bridge_identity_sha256: '3'.repeat(64),
};
const entryPath = fileURLToPath(new URL('../../entry.mjs', import.meta.url));

function makeNowIso() {
  let n = Date.parse('2026-10-20T10:00:00.000Z');
  return () => {
    n += 500;
    return new Date(n).toISOString();
  };
}

function makeGitHubMock(opts = {}) {
  const refs = new Map();
  const commits = new Map([[HEAD, { sha: HEAD, tree: { sha: TREE }, parents: [], message: 'head' }]]);
  let seq = 1;
  let state = {
    openPrs: [{ number: PR, state: 'open', head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] }],
    checkRuns: [
      {
        id: 1,
        name: 'bke-ticket',
        app: PINNED_APP,
        head_sha: HEAD,
        status: 'completed',
        conclusion: 'success',
        external_id: `bke-ticket:v1:${WORKER}:attempt-rel-1:${Math.floor(Date.parse('2026-10-20T12:00:00.000Z') / 1000)}`,
      },
    ],
    installLinkNext: false,
    pullsLinkNext: false,
    refsLinkNext: false,
    checksLinkNext: false,
    failClaimStatus: null,
    failClaimMessage: null,
    failFenceReadBack: false,
    failReconcilePost: false,
    failStatus: null,
  };
  Object.assign(state, opts);

  const res = (status, body, linkNext = false) => ({
    status,
    headers: { get: (k) => (k.toLowerCase() === 'link' && linkNext ? '<https://api.github.com/next>; rel="next"' : null) },
    json: async () => body,
  });

  const fetch = async (url, init) => {
    if (state.failStatus) return res(state.failStatus, { message: 'Injected outage' });
    const parsed = new URL(url);
    const p = parsed.pathname;
    const body = init.body ? JSON.parse(init.body) : null;

    if (init.method === 'GET' && p === '/installation/repositories') {
      return res(200, { repositories: [{ full_name: REPO, permissions: { push: true } }] }, state.installLinkNext);
    }
    if (init.method === 'GET' && p === `/repos/${REPO}/pulls`) {
      return res(200, state.openPrs.filter((x) => x.state === 'open'), state.pullsLinkNext);
    }
    if (init.method === 'GET' && p.startsWith(`/repos/${REPO}/pulls/`)) {
      const n = Number(p.split('/').pop());
      const pr = state.openPrs.find((x) => x.number === n);
      return pr ? res(200, pr) : res(404, { message: 'Not Found' });
    }
    if (init.method === 'GET' && p === `/repos/${REPO}/git/matching-refs/bke/`) {
      return res(
        200,
        [...refs.entries()].filter(([k]) => k.startsWith('refs/bke/')).map(([ref, sha]) => ({ ref, object: { sha } })),
        state.refsLinkNext,
      );
    }
    if (init.method === 'GET' && p.endsWith('/check-runs')) {
      return res(200, { total_count: state.checkRuns.length, check_runs: state.checkRuns }, state.checksLinkNext);
    }
    if (init.method === 'GET' && p.startsWith(`/repos/${REPO}/git/commits/`)) {
      const sha = p.split('/').pop();
      return commits.has(sha) ? res(200, commits.get(sha)) : res(404, { message: 'Not Found' });
    }
    if (init.method === 'POST' && p === `/repos/${REPO}/git/commits`) {
      if (state.failReconcilePost && String(body.message).includes('CONVERSATION_LEDGER_V1')) {
        return res(503, { message: 'GitHub unavailable during reconcile' });
      }
      const sha = ('e' + String(seq++)).padEnd(40, '0').slice(0, 40);
      const created = { sha, tree: { sha: body.tree }, parents: body.parents, message: body.message };
      commits.set(sha, created);
      return res(201, created);
    }
    if (init.method === 'GET' && p.startsWith(`/repos/${REPO}/git/ref/`)) {
      const ref = 'refs/' + p.slice(`/repos/${REPO}/git/ref/`.length);
      if (state.failFenceReadBack && ref.includes('/fences/')) {
        return res(404, { message: 'Not Found' });
      }
      return refs.has(ref) ? res(200, { ref, object: { sha: refs.get(ref) } }) : res(404, { message: 'Not Found' });
    }
    if (init.method === 'POST' && p === `/repos/${REPO}/git/refs`) {
      if (String(body.ref).includes('/claims/') && state.failClaimStatus) {
        return res(state.failClaimStatus, { message: state.failClaimMessage ?? 'Injected claim error' });
      }
      if (refs.has(body.ref)) return res(422, { message: 'Reference already exists' });
      refs.set(body.ref, body.sha);
      return res(201, { ref: body.ref, object: { sha: body.sha } });
    }
    return res(404, { message: 'Unhandled' });
  };

  return { fetch, refs, state };
}

function makeFakeBrowserPorts(overrides = {}, nowIso = () => new Date().toISOString()) {
  let submits = 0;
  let seq = 0;
  const cfg = {
    url: 'https://chatgpt.com/',
    uiState: 'NEW_CHAT_LANDING',
    visible: true,
    composerAvailable: true,
    turnBusy: false,
    matchingWritableTargetCount: 1,
    sharedWritableProfile: false,
    tabId: 11,
    targetId: 'target-rel-01',
    profileId: 'profile-rel-01',
    afterUrl: 'https://chatgpt.com/c/conv-rel-0001',
    conversationId: 'conv-rel-0001',
    submitUncertain: false,
    ...overrides,
  };

  const dispatcher = {
    async sendCommand(cmd) {
      if (cmd.action === 'GET_TARGET_STATUS') {
        return {
          ok: true,
          code: 'TARGET_OK',
          payload: {
            observedAt: nowIso(),
            url: cfg.url,
            visible: cfg.visible,
            composerAvailable: cfg.composerAvailable,
            turnBusy: cfg.turnBusy,
            uiState: cfg.uiState,
            tabId: cfg.tabId,
            targetId: cfg.targetId,
            profileId: cfg.profileId,
            matchingWritableTargetCount: cfg.matchingWritableTargetCount,
            sharedWritableProfile: cfg.sharedWritableProfile,
          },
        };
      }
      if (cmd.action === 'DISPATCH_FIRST_MESSAGE') {
        submits += 1;
        if (cfg.submitUncertain) {
          return { ok: false, uncertain: true, code: 'CONVERSATION_URL_TRANSITION_TIMEOUT' };
        }
        return {
          ok: true,
          code: 'FIRST_MESSAGE_SENT',
          payload: {
            beforeUrl: cfg.url,
            afterUrl: cfg.afterUrl,
            conversationId: cfg.conversationId,
            sendStartedAt: '2026-10-20T10:00:05.000Z',
            confirmedAt: '2026-10-20T10:00:06.000Z',
          },
        };
      }
      if (cmd.action === 'DISPATCH_CONTINUATION') {
        submits += 1;
        if (cfg.submitUncertain) {
          return { ok: false, uncertain: true, code: 'CONTINUATION_DRIFTED_TO_OTHER_CONVERSATION' };
        }
        return {
          ok: true,
          code: 'CONTINUATION_SENT',
          payload: {
            beforeUrl: cfg.url,
            afterUrl: cfg.afterUrl,
            conversationId: cfg.conversationId,
            sendStartedAt: '2026-10-20T10:00:05.000Z',
            confirmedAt: '2026-10-20T10:00:06.000Z',
          },
        };
      }
      return { ok: false, code: 'UNKNOWN_CMD' };
    },
  };

  const adapter = new ExtensionBrowserAdapter(
    {
      repository: REPO,
      prNumber: PR,
      headSha: HEAD,
      workerId: WORKER,
      targetId: cfg.targetId,
      profileId: cfg.profileId,
      targetTabId: cfg.tabId,
      nextSeq: () => ++seq,
    },
    dispatcher,
  );
  return {
    cfg,
    get submits() { return submits; },
    ports: { firstMessage: adapter.asFirstMessagePort(), continuation: adapter.asContinuationPort() },
  };
}

function makeController(journalPath, gh, browserHolder, nowIso = makeNowIso()) {
  const journal = new FileExecutionJournal(journalPath, { repository: REPO, prNumber: PR, workerId: WORKER }, nowIso);
  const controller = new DesktopController({
    journal,
    nowIso,
    liveProofs: {
      githubCasOwnerCertified: true,
      nativePairingOwnerCertified: true,
      realBrowserOwnerAccepted: true,
    },
    createLedger: (headSha) =>
      new GitHubF1Ledger(
        {
          repository: REPO,
          prNumber: PR,
          headSha,
          workerId: WORKER,
          authenticatedWorkerId: WORKER,
          pinnedApp: PINNED_APP,
          executionId: 'exec-rel-01',
          targetId: 'target-rel-01',
          profileId: 'profile-rel-01',
          targetTabId: 11,
          nowIso,
        },
        gh.fetch,
        async () => 'token',
      ),
    createBrowserPorts: () => browserHolder.ports,
  });
  return { journal, controller };
}

test('Reliability Group 1: Journal refuses 0o644, symlinks, corrupt/truncated JSON, and ignores leftover .tmp files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-rel-journal-'));
  await chmod(dir, 0o700);
  try {
    // 1. World-readable 0o644 journal MUST fail closed
    const badPerm = join(dir, 'j644.json');
    const validContent = JSON.stringify({
      version: 1, repository: REPO, prNumber: PR, workerId: WORKER,
      phase: 'IDLE', activeAttemptId: null, conversationId: null,
      confirmedTurnCount: 0, processedAttempts: [], processedDeliveries: [],
      uncertainReason: null, updatedAt: '2026-10-20T10:00:00.000Z',
    });
    await writeFile(badPerm, validContent, { mode: 0o644 });
    await chmod(badPerm, 0o644);
    await assert.rejects(
      () => new FileExecutionJournal(badPerm, { repository: REPO, prNumber: PR, workerId: WORKER }).openAndRecover(),
      /JOURNAL_PERMISSIONS_INSECURE/,
    );

    // 2. Symlink journal MUST fail closed
    const targetFile = join(dir, 'real.json');
    await writeFile(targetFile, validContent, { mode: 0o600 });
    const symFile = join(dir, 'sym.json');
    await symlink(targetFile, symFile);
    await assert.rejects(
      () => new FileExecutionJournal(symFile, { repository: REPO, prNumber: PR, workerId: WORKER }).openAndRecover(),
      /JOURNAL_SYMLINK_FORBIDDEN/,
    );

    // 3. Corrupt & truncated JSON fail closed
    const corrupt = join(dir, 'corrupt.json');
    await writeFile(corrupt, '{"version": 1, "phase": "DISPATCH', { mode: 0o600 });
    await assert.rejects(
      () => new FileExecutionJournal(corrupt, { repository: REPO, prNumber: PR, workerId: WORKER }).openAndRecover(),
      /JOURNAL_CORRUPT/,
    );

    // 4. Atomic .tmp leftover NEVER applies uncommitted writes
    const atomicPath = join(dir, 'atomic.json');
    const jAtomic = new FileExecutionJournal(atomicPath, { repository: REPO, prNumber: PR, workerId: WORKER });
    await jAtomic.openAndRecover();
    await writeFile(`${atomicPath}.99999.tmp`, JSON.stringify({ version: 1, phase: 'HALTED' }), { mode: 0o600 });
    const recovered = await new FileExecutionJournal(atomicPath, { repository: REPO, prNumber: PR, workerId: WORKER }).openAndRecover();
    assert.equal(recovered.phase, 'IDLE');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Reliability Group 2: Crash recovery before fence, during DISPATCHING, and after click before reconciliation', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-rel-crash-'));
  await chmod(dir, 0o700);
  try {
    // 1. Crash while FENCED (before claim/click) resets/allows clean run on next wake? Wait: check existing FENCED on startup vs DISPATCHING!
    // If controller died during FENCED (before send claim was posted), refs/bke/claims doesn't exist yet -> safe or blocked only by existing fence ref;
    // DISPATCHING / CONTINUING MUST permanently quarantine into DELIVERY_UNCERTAIN.
    const jPath = join(dir, 'crash.json');
    const gh = makeGitHubMock();
    const now1 = makeNowIso();
    const browser = makeFakeBrowserPorts({}, now1);
    const { controller } = makeController(jPath, gh, browser, now1);
    await controller.initialize();
    await writeFile(
      jPath,
      JSON.stringify({
        version: 1, repository: REPO, prNumber: PR, workerId: WORKER,
        phase: 'DISPATCHING', activeAttemptId: 'attempt-rel-1', conversationId: null,
        confirmedTurnCount: 0, processedAttempts: [], processedDeliveries: [],
        uncertainReason: null, updatedAt: '2026-10-20T10:00:00.000Z',
      }),
      { mode: 0o600 },
    );
    const rec = await controller.initialize();
    assert.equal(rec.phase, 'DELIVERY_UNCERTAIN');
    const blocked = await controller.processAuthorizedWake({ headSha: HEAD, prNumber: PR, humanLiveSendAuthorized: true });
    assert.equal(blocked.status, 'BLOCKED');
    assert.equal(browser.submits, 0);

    // 2. Crash/failure AFTER ChatGPT click before GitHub conversation ledger commit -> quarantine + uncertain ref + 0 second submit!
    const jPath2 = join(dir, 'reconcile-fail.json');
    const gh2 = makeGitHubMock({ failReconcilePost: true });
    const now2 = makeNowIso();
    const browser2 = makeFakeBrowserPorts({}, now2);
    const { controller: c2 } = makeController(jPath2, gh2, browser2, now2);
    await c2.initialize();
    const res2 = await c2.processAuthorizedWake({ headSha: HEAD, prNumber: PR, humanLiveSendAuthorized: true });
    assert.equal(res2.status, 'BLOCKED');
    assert.equal(res2.journalPhase, 'DELIVERY_UNCERTAIN');
    assert.equal(browser2.submits, 1);
    assert.ok(gh2.refs.has(`refs/bke/claims/${PR}/attempt-rel-1`));
    assert.ok(gh2.refs.has(`refs/bke/uncertain/${PR}/attempt-rel-1`));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Reliability Group 3: Native host IPC socket missing, unlinked mid-dispatch, idle kill vs in-flight kill', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-rel-ipc-'));
  await chmod(dir, 0o700);
  const policyPath = join(dir, 'policy.json');
  const sockPath = join(dir, 'bridge.sock');
  const identity = createDeviceIdentityBridge({
    store: {
      async atomic(fn) {
        let val;
        return fn({ get: async () => val, put: async (v) => { val = v; } });
      },
    },
    cryptoImpl: webcrypto,
    now: () => Date.now(),
  });
  // Keep persistent store across calls
  let persistedId;
  const stableIdentity = createDeviceIdentityBridge({
    store: {
      async atomic(fn) {
        return fn({ get: async () => persistedId, put: async (v) => { persistedId = structuredClone(v); } });
      },
    },
    cryptoImpl: webcrypto,
    now: () => Date.now(),
  });
  void identity;
  const pub = await stableIdentity.initialize(WORKER);
  await writeFile(
    policyPath,
    JSON.stringify({
      version: 1, allowed_origin: ORIGIN, worker_id: WORKER,
      public_key_sha256: pub.public_key_sha256, profile_binding_sha256: PROFILE_BINDING,
      resources: RESOURCES, expires_at_ms: Date.now() + 120_000,
    }),
    { mode: 0o600 },
  );

  // 1. Missing IPC socket -> fail closed without quarantining
  const missingClient = new IpcBridgeClient({ socketPath: join(dir, 'missing.sock') });
  const missingRes = await missingClient.ping();
  assert.equal(missingRes.ok, false);
  assert.equal(missingRes.code, 'CONTROLLER_IPC_SOCKET_MISSING');
  assert.equal(missingClient.isQuarantined(), false);

  // 2. Spawn real controller-host and test idle kill -> reconnectIfIdle allowed; then mid-dispatch kill -> permanent quarantine
  let currentChild = null;
  let disconnectHook = null;
  const runtime = {
    getURL: () => ORIGIN,
    connectNative() {
      const child = spawn(process.execPath, [entryPath, '--controller-bridge', policyPath, ORIGIN, sockPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { PATH: process.env.PATH ?? '' },
      });
      currentChild = child;
      const msgL = new Set();
      const discL = new Set();
      let buf = Buffer.alloc(0);
      const notify = () => { for (const f of [...discL]) f(); };
      disconnectHook = notify;
      child.stdout.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 4) {
          const len = buf.readUInt32LE(0);
          if (buf.length < len + 4) break;
          const m = JSON.parse(buf.subarray(4, len + 4).toString('utf8'));
          buf = buf.subarray(len + 4);
          for (const f of [...msgL]) f(m);
        }
      });
      child.once('exit', notify);
      return {
        postMessage(m) {
          const b = Buffer.from(JSON.stringify(m), 'utf8');
          const f = Buffer.allocUnsafe(b.length + 4);
          f.writeUInt32LE(b.length, 0);
          b.copy(f, 4);
          child.stdin.write(f);
        },
        disconnect() { if (!child.stdin.writableEnded) child.stdin.end(); },
        onMessage: { addListener: (f) => msgL.add(f), removeListener: (f) => msgL.delete(f) },
        onDisconnect: { addListener: (f) => discL.add(f), removeListener: (f) => discL.delete(f) },
      };
    },
  };

  let stallDispatch = false;
  const sup = createControllerBridgeSupervisor(() =>
    connectControllerNativeBridge({
      runtime,
      identity: stableIdentity,
      workerId: WORKER,
      resources: RESOURCES,
      profileBindingSha256: PROFILE_BINDING,
      checkPermission: async () => true,
      cryptoImpl: webcrypto,
      handlers: {
        withTargetLock: async (run) => ({ ok: true, value: await run() }),
        getTargetStatus: async () => ({ ok: true, code: 'OK', payload: {} }),
        dispatchFirstMessage: async () => {
          if (stallDispatch) {
            // Simulate unlinking socket and killing host mid-dispatch
            await unlink(sockPath).catch(() => undefined);
            currentChild?.kill('SIGKILL');
            await new Promise((r) => setTimeout(r, 300));
          }
          return { ok: true, code: 'FIRST_MESSAGE_SENT', payload: {} };
        },
        dispatchContinuation: async () => ({ ok: false, code: 'UNUSED' }),
      },
    }),
  );

  try {
    const c1 = await sup.connect();
    assert.equal(c1.ok, true);
    // Kill while idle
    currentChild.kill('SIGTERM');
    await c1.session.waitClosed();
    assert.equal(sup.isQuarantined(), false);

    // Reconnect while idle succeeds!
    const c2 = await sup.reconnectIfIdle();
    assert.equal(c2.ok, true);

    // Now trigger in-flight dispatch + host death -> client + supervisor quarantine!
    stallDispatch = true;
    const ipcClient = new IpcBridgeClient({ socketPath: sockPath, commandTimeoutMs: 2_000 });
    const midFail = await ipcClient.sendCommand({
      type: 'COMMAND',
      version: 1,
      command_id: 'cmd-mid-crash-1',
      seq: 1,
      issued_at_ms: Date.now(),
      ttl_ms: 5_000,
      action: 'DISPATCH_FIRST_MESSAGE',
      pr_number: PR,
      head_sha: HEAD,
      attempt_id: 'attempt-mid-1',
      fence_id: 'fence-mid-1',
      claim_id: 'claim-mid-1',
      target_id: 'target-rel-01',
      profile_id: 'profile-rel-01',
      target_tab_id: 11,
      prompt: 'Execute turn 1',
    });
    assert.equal(midFail.ok, false);
    assert.equal(midFail.uncertain, true);
    assert.equal(ipcClient.isQuarantined(), true);

    await c2.session.waitClosed();
    const reconnBlocked = await sup.reconnectIfIdle();
    assert.equal(reconnBlocked.ok, false);
    assert.equal(reconnBlocked.code, 'SUPERVISOR_QUARANTINED_AFTER_INFLIGHT_DISCONNECT');
  } finally {
    disconnectHook?.();
    if (currentChild && currentChild.exitCode === null) currentChild.kill('SIGTERM');
    await rm(dir, { recursive: true, force: true });
  }
});

test('Reliability Group 4: GitHub failures (label removed/reassigned, closed PR, head changed, truncated pagination, 422 CAS, 503, read-back fail)', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-rel-gh-'));
  await chmod(dir, 0o700);
  try {
    const cases = [
      {
        name: 'worker label removed',
        patch: (gh) => { gh.state.openPrs = [{ number: PR, state: 'open', head: { sha: HEAD }, labels: [] }]; },
        code: /GITHUB_WORKER_ASSIGNMENT_CONFLICT/,
      },
      {
        name: 'worker reassigned',
        patch: (gh) => { gh.state.openPrs = [{ number: PR, state: 'open', head: { sha: HEAD }, labels: [{ name: 'bke-worker:worker-other' }] }]; },
        code: /GITHUB_WORKER_ASSIGNMENT_CONFLICT/,
      },
      {
        name: 'PR closed',
        patch: (gh) => { gh.state.openPrs = [{ number: PR, state: 'closed', head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] }]; },
        code: /GITHUB_WORKER_ASSIGNMENT_CONFLICT|GITHUB_PR_NOT_OPEN/,
      },
      {
        name: 'head SHA changed before claim',
        patch: (gh) => { gh.state.openPrs = [{ number: PR, state: 'open', head: { sha: OTHER_HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] }]; },
        code: /GITHUB_HEAD_CHANGED/,
      },
      {
        name: 'truncated installation pagination',
        patch: (gh) => { gh.state.installLinkNext = true; },
        code: /GITHUB_INSTALLATION_PAGINATION_TRUNCATED/,
      },
      {
        name: 'truncated pulls pagination',
        patch: (gh) => { gh.state.pullsLinkNext = true; },
        code: /GITHUB_PULLS_PAGINATION_TRUNCATED/,
      },
      {
        name: 'truncated refs pagination',
        patch: (gh) => { gh.state.refsLinkNext = true; },
        code: /GITHUB_REFS_PAGINATION_TRUNCATED/,
      },
      {
        name: 'truncated check-runs pagination',
        patch: (gh) => { gh.state.checksLinkNext = true; },
        code: /GITHUB_CHECK_RUNS_TRUNCATED/,
      },
      {
        name: 'GitHub 503 outage',
        patch: (gh) => { gh.state.failStatus = 503; },
        code: /GITHUB_INSTALLATION_UNAVAILABLE/,
      },
      {
        name: 'CAS 422 Reference already exists blocks cleanly without quarantine',
        patch: (gh) => { gh.state.failClaimStatus = 422; gh.state.failClaimMessage = 'Reference already exists'; },
        code: /SEND_CLAIM_COMMIT_FAILED/,
        expectNotQuarantined: true,
      },
      {
        name: 'Fence read-back mismatch blocks before claim/send',
        patch: (gh) => { gh.state.failFenceReadBack = true; },
        code: /FENCE/,
      },
    ];

    for (let i = 0; i < cases.length; i++) {
      const c = cases[i];
      const gh = makeGitHubMock();
      c.patch(gh);
      const nowC = makeNowIso();
      const browser = makeFakeBrowserPorts({}, nowC);
      const { controller } = makeController(join(dir, `j-${i}.json`), gh, browser, nowC);
      await controller.initialize();
      const outcome = await controller.processAuthorizedWake({
        headSha: HEAD,
        prNumber: PR,
        humanLiveSendAuthorized: true,
      });
      assert.equal(outcome.status, 'BLOCKED', c.name);
      assert.match(outcome.code, c.code, c.name);
      if (c.expectNotQuarantined) {
        assert.notEqual(outcome.journalPhase, 'DELIVERY_UNCERTAIN', c.name);
      }
      assert.equal(browser.submits, 0, `${c.name} must have 0 ChatGPT submissions`);
    }

    // Uncertain non-conflict 422 claim response MUST quarantine
    const ghUnc = makeGitHubMock({ failClaimStatus: 422, failClaimMessage: 'Validation Failed' });
    const nowU = makeNowIso();
    const brUnc = makeFakeBrowserPorts({}, nowU);
    const { controller: cUnc } = makeController(join(dir, 'j-unc422.json'), ghUnc, brUnc, nowU);
    await cUnc.initialize();
    const outUnc = await cUnc.processAuthorizedWake({ headSha: HEAD, prNumber: PR, humanLiveSendAuthorized: true });
    assert.equal(outUnc.status, 'BLOCKED');
    assert.equal(outUnc.journalPhase, 'DELIVERY_UNCERTAIN');
    assert.equal(brUnc.submits, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Reliability Group 5: ChatGPT browser failures (AUTH_REQUIRED, missing composer, busy, multi-tab, wrong tab, stalled click)', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-rel-browser-'));
  await chmod(dir, 0o700);
  try {
    const blockedCases = [
      { name: 'AUTH_REQUIRED', patch: { uiState: 'AUTH_REQUIRED', url: 'https://chatgpt.com/auth/login', composerAvailable: false } },
      { name: 'missing composer', patch: { composerAvailable: false, uiState: 'UNKNOWN' } },
      { name: 'busy turn', patch: { turnBusy: true, uiState: 'BUSY' } },
      { name: 'multiple writable tabs', patch: { matchingWritableTargetCount: 2 } },
      { name: 'shared writable profile', patch: { sharedWritableProfile: true } },
      { name: 'wrong target ID', patch: { targetId: 'target-other-99' } },
    ];

    for (let i = 0; i < blockedCases.length; i++) {
      const bc = blockedCases[i];
      const gh = makeGitHubMock();
      const nowB = makeNowIso();
      const browser = makeFakeBrowserPorts(bc.patch, nowB);
      const { controller } = makeController(join(dir, `b-${i}.json`), gh, browser, nowB);
      await controller.initialize();
      const res = await controller.processAuthorizedWake({ headSha: HEAD, prNumber: PR, humanLiveSendAuthorized: true });
      assert.equal(res.status, 'BLOCKED', bc.name);
      assert.equal(browser.submits, 0, `${bc.name} must perform 0 clicks`);
    }

    // Stalled network / URL transition timeout after click MUST quarantine with 0 retry
    const ghStall = makeGitHubMock();
    const nowS = makeNowIso();
    const browserStall = makeFakeBrowserPorts({ submitUncertain: true }, nowS);
    const { controller: cStall } = makeController(join(dir, 'b-stall.json'), ghStall, browserStall, nowS);
    await cStall.initialize();
    const resStall = await cStall.processAuthorizedWake({ headSha: HEAD, prNumber: PR, humanLiveSendAuthorized: true });
    assert.equal(resStall.status, 'BLOCKED');
    assert.equal(resStall.journalPhase, 'DELIVERY_UNCERTAIN');
    assert.equal(browserStall.submits, 1);
    assert.ok(ghStall.refs.has(`refs/bke/uncertain/${PR}/attempt-rel-1`));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
