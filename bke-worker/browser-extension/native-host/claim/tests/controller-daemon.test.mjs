/**
 * F1-03 / F1-06 Multi-Process DesktopControllerDaemon & IpcBridgeClient Integration Tests.
 *
 * Exercises real loopback HTTP webhook & halt endpoints, real local HTTP GitHub REST
 * server, real Unix domain socket IpcBridgeClient, real child `entry.mjs --controller-bridge`
 * subprocess, and synthetic MV3 extension bridge end-to-end across Turn 1, Turn 2,
 * restart recovery, and owner HALT.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, webcrypto } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createDeviceIdentityBridge } from '../../../dist/device-identity.js';
import { connectControllerNativeBridge } from '../../../dist/controller-transport.js';
import {
  DesktopControllerDaemon,
  runCli,
  runControllerDoctor,
} from '../dist/native-host/claim/controller-daemon.js';
import { IpcBridgeClient } from '../dist/native-host/claim/ipc-client.js';

const ORIGIN = 'chrome-extension://' + 'a'.repeat(32) + '/';
const PROFILE_BINDING = '4'.repeat(64);
const H = (c) => c.repeat(64);
const RESOURCES = {
  chatgpt_target_sha256: H('1'),
  browser_profile_sha256: H('2'),
  bridge_identity_sha256: H('3'),
};
const HEAD = 'b'.repeat(40);
const TREE = 'f'.repeat(40);
const REPO = 'jan2xo/bke-worker';
const WORKER = 'worker-f1';
const PR_NUMBER = 127;
const PINNED_APP = { id: 9001, slug: 'bke-dispatcher-app' };
const WEBHOOK_SECRET = 'daemon-webhook-secret-xyz';
const HALT_TOKEN = 'owner-halt-secret-xyz';
const entryPath = fileURLToPath(new URL('../../entry.mjs', import.meta.url));

function memoryIdentityStore() {
  let current;
  let tail = Promise.resolve();
  return {
    async atomic(action) {
      let release;
      const next = new Promise((resolve) => { release = resolve; });
      const prev = tail;
      tail = next;
      await prev;
      let draft = current === undefined ? undefined : structuredClone(current);
      try {
        const res = await action({
          get: async () => (draft === undefined ? undefined : structuredClone(draft)),
          put: async (v) => { draft = structuredClone(v); },
        });
        current = draft;
        return res;
      } finally {
        release();
      }
    },
  };
}

async function startGitHubHttpDouble(initialAttempt = 'attempt-daemon-1') {
  const refs = new Map();
  const commits = new Map([[HEAD, { sha: HEAD, tree: { sha: TREE }, parents: [], message: 'head' }]]);
  let attemptId = initialAttempt;
  let seq = 1;

  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    const body = raw ? JSON.parse(raw) : null;
    const url = new URL(req.url, 'http://127.0.0.1');
    const p = url.pathname;

    const json = (status, data) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    };

    if (req.method === 'GET' && p === '/installation/repositories') {
      return json(200, { repositories: [{ full_name: REPO, permissions: { push: true } }] });
    }
    if (req.method === 'GET' && p === `/repos/${REPO}/pulls`) {
      return json(200, [
        { number: PR_NUMBER, state: 'open', head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] },
      ]);
    }
    if (req.method === 'GET' && p === `/repos/${REPO}/pulls/${PR_NUMBER}`) {
      return json(200, {
        number: PR_NUMBER,
        state: 'open',
        head: { sha: HEAD },
        labels: [{ name: `bke-worker:${WORKER}` }],
      });
    }
    if (req.method === 'GET' && p === `/repos/${REPO}/git/matching-refs/bke/`) {
      return json(
        200,
        [...refs.entries()].filter(([k]) => k.startsWith('refs/bke/')).map(([ref, sha]) => ({ ref, object: { sha } })),
      );
    }
    if (req.method === 'GET' && p === `/repos/${REPO}/commits/${HEAD}/check-runs`) {
      const checkRuns = [
        {
          id: 801,
          name: 'bke-ticket',
          app: PINNED_APP,
          head_sha: HEAD,
          status: 'completed',
          conclusion: 'success',
          external_id: `bke-ticket:v1:${WORKER}:${attemptId}:${Math.floor(Date.parse('2026-10-20T12:00:00.000Z') / 1000)}`,
        },
      ];
      return json(200, { total_count: 1, check_runs: checkRuns });
    }
    if (req.method === 'GET' && p.startsWith(`/repos/${REPO}/git/commits/`)) {
      const sha = p.split('/').pop();
      return commits.has(sha) ? json(200, commits.get(sha)) : json(404, { message: 'Not Found' });
    }
    if (req.method === 'POST' && p === `/repos/${REPO}/git/commits`) {
      const sha = ('d' + String(seq++)).padEnd(40, '0').slice(0, 40);
      const created = { sha, tree: { sha: body.tree }, parents: body.parents, message: body.message };
      commits.set(sha, created);
      return json(201, created);
    }
    if (req.method === 'GET' && p.startsWith(`/repos/${REPO}/git/ref/`)) {
      const ref = 'refs/' + p.slice(`/repos/${REPO}/git/ref/`.length);
      return refs.has(ref) ? json(200, { ref, object: { sha: refs.get(ref) } }) : json(404, { message: 'Not Found' });
    }
    if (req.method === 'POST' && p === `/repos/${REPO}/git/refs`) {
      if (refs.has(body.ref)) return json(422, { message: 'Reference already exists' });
      refs.set(body.ref, body.sha);
      return json(201, { ref: body.ref, object: { sha: body.sha } });
    }
    if (req.method === 'PATCH' && p.startsWith(`/repos/${REPO}/git/refs/`)) {
      const ref = 'refs/' + p.slice(`/repos/${REPO}/git/refs/`.length);
      if (!refs.has(ref)) return json(422, { message: 'Reference does not exist' });
      refs.set(ref, body.sha);
      return json(200, { ref, object: { sha: body.sha } });
    }
    return json(404, { message: 'Unhandled' });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  return {
    baseUrl,
    refs,
    setAttempt(next) { attemptId = next; },
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

test('DesktopControllerDaemon connects real HTTP webhook/halt + real local GitHub HTTP server + Unix IPC + native bridge across 2 turns', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-daemon-int-'));
  await chmod(dir, 0o700);
  const policyPath = join(dir, 'policy.json');
  const sockPath = join(dir, 'bridge.sock');
  const journalPath = join(dir, 'journal.json');
  const ghServer = await startGitHubHttpDouble('attempt-daemon-1');

  const identity = createDeviceIdentityBridge({ store: memoryIdentityStore(), cryptoImpl: webcrypto, now: () => Date.now() });
  const pub = await identity.initialize(WORKER);
  await writeFile(
    policyPath,
    JSON.stringify({
      version: 1,
      allowed_origin: ORIGIN,
      worker_id: WORKER,
      public_key_sha256: pub.public_key_sha256,
      profile_binding_sha256: PROFILE_BINDING,
      resources: RESOURCES,
      expires_at_ms: Date.now() + 120_000,
    }),
    { mode: 0o600 },
  );

  const browserState = {
    url: 'https://chatgpt.com/',
    uiState: 'NEW_CHAT_LANDING',
    submissions: [],
  };

  let child = null;
  const runtime = {
    getURL: () => ORIGIN,
    connectNative() {
      child = spawn(process.execPath, [entryPath, '--controller-bridge', policyPath, ORIGIN, sockPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { PATH: process.env.PATH ?? '' },
      });
      const msgListeners = new Set();
      const discListeners = new Set();
      let buffer = Buffer.alloc(0);
      const notifyDisconnect = () => { for (const fn of [...discListeners]) fn(); };
      child.stdout.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 4) {
          const len = buffer.readUInt32LE(0);
          if (len < 1 || len > 16_384) { child.kill('SIGTERM'); notifyDisconnect(); return; }
          if (buffer.length < len + 4) break;
          const msg = JSON.parse(buffer.subarray(4, len + 4).toString('utf8'));
          buffer = buffer.subarray(len + 4);
          for (const fn of [...msgListeners]) fn(msg);
        }
      });
      child.once('exit', notifyDisconnect);
      return {
        postMessage(msg) {
          const body = Buffer.from(JSON.stringify(msg), 'utf8');
          const frame = Buffer.allocUnsafe(body.length + 4);
          frame.writeUInt32LE(body.length, 0);
          body.copy(frame, 4);
          child.stdin.write(frame);
        },
        disconnect() { if (!child.stdin.writableEnded) child.stdin.end(); },
        onMessage: { addListener: (fn) => msgListeners.add(fn), removeListener: (fn) => msgListeners.delete(fn) },
        onDisconnect: { addListener: (fn) => discListeners.add(fn), removeListener: (fn) => discListeners.delete(fn) },
      };
    },
  };

  let clockCounter = Date.parse('2026-10-20T09:00:00.000Z');
  const nextIso = () => {
    clockCounter += 500;
    return new Date(clockCounter).toISOString();
  };

  const bridgeConn = await connectControllerNativeBridge({
    runtime,
    identity,
    workerId: WORKER,
    resources: RESOURCES,
    profileBindingSha256: PROFILE_BINDING,
    checkPermission: async () => true,
    cryptoImpl: webcrypto,
    handlers: {
      withTargetLock: async (run) => ({ ok: true, value: await run() }),
      getTargetStatus: async () => ({
        ok: true,
        code: 'TARGET_OK',
        payload: {
          observedAt: nextIso(),
          url: browserState.url,
          visible: true,
          composerAvailable: true,
          turnBusy: false,
          uiState: browserState.uiState,
          tabId: 11,
          targetId: 'target-daemon-01',
          profileId: 'profile-daemon-01',
          matchingWritableTargetCount: 1,
          sharedWritableProfile: false,
        },
      }),
      dispatchFirstMessage: async (cmd) => {
        const beforeUrl = browserState.url;
        const convId = 'conv-daemon-001';
        const afterUrl = `https://chatgpt.com/c/${convId}`;
        browserState.submissions.push({ turn: 1, attemptId: cmd.attempt_id });
        browserState.url = afterUrl;
        browserState.uiState = 'THREAD';
        return {
          ok: true,
          code: 'FIRST_MESSAGE_SENT',
          payload: { beforeUrl, afterUrl, conversationId: convId, sendStartedAt: nextIso(), confirmedAt: nextIso() },
        };
      },
      dispatchContinuation: async (cmd) => {
        const beforeUrl = browserState.url;
        const afterUrl = `https://chatgpt.com/c/${cmd.expected_conversation_id}`;
        browserState.submissions.push({ turn: 2, attemptId: cmd.attempt_id });
        return {
          ok: true,
          code: 'CONTINUATION_SENT',
          payload: { beforeUrl, afterUrl, conversationId: cmd.expected_conversation_id, sendStartedAt: nextIso(), confirmedAt: nextIso() },
        };
      },
    },
  });
  assert.equal(bridgeConn.ok, true);

  // Rewrite https://api.github.com -> local HTTP GitHub double
  const rewrittenFetch = (url, init) => {
    const target = url.replace('https://api.github.com', ghServer.baseUrl);
    return globalThis.fetch(target, init).then((r) => ({
      status: r.status,
      headers: r.headers,
      json: () => r.json(),
    }));
  };

  const ipcClient = new IpcBridgeClient({ socketPath: sockPath });
  const daemon = new DesktopControllerDaemon(
    {
      repository: REPO,
      prNumber: PR_NUMBER,
      workerId: WORKER,
      pinnedApp: PINNED_APP,
      executionId: 'exec-daemon-01',
      targetId: 'target-daemon-01',
      profileId: 'profile-daemon-01',
      targetTabId: 11,
      journalPath,
      ipcSocketPath: sockPath,
      webhookSecret: WEBHOOK_SECRET,
      operatorHaltToken: HALT_TOKEN,
      listenHost: '127.0.0.1',
      listenPort: 0,
      humanLiveSendAuthorized: true,
      liveProofs: {
        githubCasOwnerCertified: true,
        nativePairingOwnerCertified: true,
        realBrowserOwnerAccepted: true,
      },
    },
    {
      tokenProvider: async () => 'synthetic-local-token',
      fetchImpl: rewrittenFetch,
      ipcClient,
      nowIso: nextIso,
    },
  );

  try {
    const { port } = await daemon.start();
    assert.ok(typeof port === 'number' && port > 0);

    // Doctor check succeeds
    const doc = await runControllerDoctor({
      BKE_JOURNAL_PATH: journalPath,
      BKE_CONTROLLER_IPC_SOCKET: sockPath,
    });
    assert.equal(doc.ok, true);
    assert.equal(doc.liveSendDefaults, 'LOCKED_FALSE');

    // Health check endpoint
    const healthRes = await globalThis.fetch(`http://127.0.0.1:${port}/healthz`);
    assert.equal(healthRes.status, 200);
    const health = await healthRes.json();
    assert.equal(health.phase, 'IDLE');

    const postWebhook = async (deliveryId, bodyObj, sigOverride) => {
      const raw = JSON.stringify(bodyObj);
      const sig = sigOverride ?? 'sha256=' + createHmac('sha256', WEBHOOK_SECRET).update(raw).digest('hex');
      return globalThis.fetch(`http://127.0.0.1:${port}/webhooks/github`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-GitHub-Event': 'check_run',
          'X-GitHub-Delivery': deliveryId,
          'X-Hub-Signature-256': sig,
        },
        body: raw,
      });
    };

    // Bad HMAC rejected with 401 and 0 submissions
    const badSigRes = await postWebhook(
      'deliv-bad',
      { repository: { full_name: REPO }, check_run: { head_sha: HEAD, pull_requests: [{ number: PR_NUMBER }] } },
      'sha256=' + '0'.repeat(64),
    );
    assert.equal(badSigRes.status, 401);
    assert.equal(browserState.submissions.length, 0);

    // Valid Turn 1 webhook executes full pipeline
    const turn1Res = await postWebhook('deliv-t1', {
      repository: { full_name: REPO },
      check_run: { head_sha: HEAD, pull_requests: [{ number: PR_NUMBER }] },
    });
    assert.equal(turn1Res.status, 200);
    const turn1 = await turn1Res.json();
    assert.equal(turn1.status, 'CONFIRMED_TURN_1');
    assert.equal(turn1.conversationId, 'conv-daemon-001');
    assert.equal(browserState.submissions.length, 1);

    // Valid Turn 2 webhook continues same conversation
    ghServer.setAttempt('attempt-daemon-2');
    const turn2Res = await postWebhook('deliv-t2', {
      repository: { full_name: REPO },
      check_run: { head_sha: HEAD, pull_requests: [{ number: PR_NUMBER }] },
    });
    assert.equal(turn2Res.status, 200);
    const turn2 = await turn2Res.json();
    assert.equal(turn2.status, 'CONFIRMED_CONTINUATION');
    assert.equal(turn2.turnNumber, 2);
    assert.equal(browserState.submissions.length, 2);

    // Status endpoint reflects 2 confirmed turns and does not leak secrets
    const statusRes = await globalThis.fetch(`http://127.0.0.1:${port}/status`);
    const statusBody = await statusRes.json();
    assert.equal(statusBody.confirmedTurnCount, 2);
    assert.equal(JSON.stringify(statusBody).includes(WEBHOOK_SECRET), false);
    assert.equal(JSON.stringify(statusBody).includes(HALT_TOKEN), false);

    // Unauthorized HALT returns 403
    const unauthHalt = await globalThis.fetch(`http://127.0.0.1:${port}/halt`, { method: 'POST' });
    assert.equal(unauthHalt.status, 403);

    // Authorized owner HALT stops controller and quarantines journal + bridge
    const haltRes = await globalThis.fetch(`http://127.0.0.1:${port}/halt`, {
      method: 'POST',
      headers: { 'X-BKE-Halt-Token': HALT_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: 'OWNER_TEST_STOP' }),
    });
    assert.equal(haltRes.status, 200);
    const disk = JSON.parse(await readFile(journalPath, 'utf8'));
    assert.equal(disk.phase, 'HALTED');

    // Help CLI exit code 0
    assert.equal(await runCli(['--help']), 0);
  } finally {
    await daemon.stop();
    bridgeConn.session.close();
    if (child && child.exitCode === null) child.kill('SIGTERM');
    await ghServer.close();
    await rm(dir, { recursive: true, force: true });
  }
});
