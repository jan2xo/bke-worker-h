/**
 * F3-04 / F3-06 / F3-08 Genuine Multi-Process End-to-End Integration Test Suite.
 *
 * Spawns THREE genuine separate OS child processes talking strictly over HTTP/TCP & Unix sockets:
 *   Process 1: SandboxBrokerHttpServer (`dist/broker-server.js`)
 *   Process 2: DesktopControllerDaemon (`tests/helpers/controller-runner.mjs`)
 *   Process 3: Native Messaging Bridge (`browser-extension/native-host/entry.mjs --controller-bridge`)
 * Plus local in-process MockGitHubServer (`127.0.0.1`) & synthetic ChatGPT browser adapter.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createDeviceIdentityBridge } from '../../../browser-extension/dist/device-identity.js';
import { connectControllerNativeBridge } from '../../../browser-extension/dist/controller-transport.js';
import { ExtensionBrowserAdapter } from '../../../browser-extension/dist/extension-browser-adapter.js';
import {
  F2_REQUIRED_VISIBLE_STATES,
  projectWorkerStateForCommandCenter,
} from '../../../browser-extension/native-host/claim/dist/native-host/claim/command-center-observer.js';
import { signAdminApproval } from '../dist/device-enrollment.js';
import { DeviceKeyPairSigner } from '../dist/broker-client.js';
import { startMockGitHubServer } from './mock-github-server.mjs';

const ORIGIN = 'chrome-extension://' + 'b'.repeat(32) + '/';
const PROFILE_BINDING = '5'.repeat(64);
const H = (c) => c.repeat(64);
const RESOURCES = {
  chatgpt_target_sha256: H('1'),
  browser_profile_sha256: H('2'),
  bridge_identity_sha256: H('3'),
};
const REPO = 'jan2xo/bke-worker';
const REPO_ID = 1354026486;
const INSTALL_ID = '987654321';
const PR_NUM = 149;
const WORKER = 'worker-f1';
const DEVICE_ID = 'desktop-dev-f3-mp-01';
const HEAD_A = 'a'.repeat(40);
const ISSUER = 'http://127.0.0.1';
const AUDIENCE = `bke-desktop-controller:${REPO}:${WORKER}`;
const entryPath = fileURLToPath(new URL('../../../browser-extension/native-host/entry.mjs', import.meta.url));
const brokerServerPath = fileURLToPath(new URL('../dist/broker-server.js', import.meta.url));
const controllerRunnerPath = fileURLToPath(new URL('./helpers/controller-runner.mjs', import.meta.url));

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

function genEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

function waitFirstLine(proc, timeoutMs = 6_000) {
  return new Promise((resolveLine, rejectLine) => {
    let buf = '';
    let stderr = '';
    const timer = setTimeout(() => {
      rejectLine(new Error(`PROCESS_READY_TIMEOUT stderr=${stderr}`));
    }, timeoutMs);
    proc.stderr.on('data', (d) => {
      stderr += d.toString('utf8');
    });
    proc.stdout.on('data', (d) => {
      buf += d.toString('utf8');
      const idx = buf.indexOf('\n');
      if (idx >= 0) {
        clearTimeout(timer);
        try {
          resolveLine(JSON.parse(buf.slice(0, idx)));
        } catch (e) {
          rejectLine(e);
        }
      }
    });
    proc.once('exit', (code) => {
      clearTimeout(timer);
      rejectLine(new Error(`PROCESS_EXITED_EARLY_${code} stderr=${stderr}`));
    });
  });
}

async function stopProc(proc) {
  if (!proc || proc.exitCode !== null) return;
  proc.kill('SIGTERM');
  await new Promise((r) => {
    const t = setTimeout(() => {
      try { proc.kill('SIGKILL'); } catch {}
      r();
    }, 1_500);
    proc.once('exit', () => {
      clearTimeout(t);
      r();
    });
  });
}

test('F3-04 / F3-08: Multi-process sandbox E2E (Broker -> V2 Daemon -> Native IPC -> Extension Bridge) + 14-state Command Center proof', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f3-mp-'));
  const mockGh = await startMockGitHubServer({ installationId: INSTALL_ID });
  const adminKeys = genEd25519();
  const adminKeyFile = join(dir, 'admin-keys.json');
  const enrollmentPath = join(dir, 'enrollment.json');
  const brokerStatePath = join(dir, 'broker-state.json');
  const policyPath = join(dir, 'owner-policy.json');
  const sockPath = join(dir, 'bridge.sock');
  const journalPath = join(dir, 'journal.json');
  const runnerConfigPath = join(dir, 'runner-config.json');

  await writeFile(adminKeyFile, JSON.stringify({ 'admin-k1': adminKeys.publicPem }), { mode: 0o600 });

  let brokerProc = null;
  let daemonProc = null;
  let entryProc = null;
  let bridgeConn = null;

  try {
    brokerProc = spawn(process.execPath, [brokerServerPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        PATH: process.env.PATH ?? '',
        BKE_BROKER_ISSUER: ISSUER,
        BKE_BROKER_ENROLLMENT_PATH: enrollmentPath,
        BKE_BROKER_STATE_PATH: brokerStatePath,
        BKE_GITHUB_API_BASE_URL: mockGh.baseUrl,
        BKE_BROKER_ADMIN_PUBLIC_KEYS_FILE: adminKeyFile,
        BKE_PINNED_APP_ID: '9001',
        BKE_PINNED_APP_SLUG: 'bke-dispatcher-app',
      },
    });
    const brokerBoot = await waitFirstLine(brokerProc);
    assert.equal(brokerBoot.ok, true);
    const brokerUrl = `http://127.0.0.1:${brokerBoot.port}`;

    const { publicKey: devPub, privateKey: devPriv } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const devPubPem = devPub.export({ type: 'spki', format: 'pem' }).toString();
    const devPrivPem = devPriv.export({ type: 'pkcs8', format: 'pem' }).toString();
    const deviceSigner = new DeviceKeyPairSigner({ publicKeySpkiPem: devPubPem, privateKeyPem: devPrivPem });

    const now = Date.now();
    const mkAdmin = (action, extra = {}) =>
      signAdminApproval(
        {
          version: 1,
          action,
          admin_actor_id: 'owner-admin-01',
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          device_id: DEVICE_ID,
          authorized_repository_scope: [REPO],
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          nonce: `adm-${Math.random().toString(16).slice(2)}`,
          issued_at: new Date(now - 2_000).toISOString(),
          expires_at: new Date(now + 120_000).toISOString(),
          ...extra,
        },
        adminKeys.privatePem,
        'admin-k1',
      );

    const chRes = await fetch(`${brokerUrl}/v1/enrollment/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        installation_id: INSTALL_ID,
        worker_id: WORKER,
        device_id: DEVICE_ID,
        authorized_repository_scope: [REPO],
        admin_approval: mkAdmin('APPROVE_ENROLLMENT'),
      }),
    });
    assert.equal(chRes.status, 200);
    const { challenge } = await chRes.json();

    const compRes = await fetch(`${brokerUrl}/v1/enrollment/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_id: challenge.challenge_id,
        installation_id: INSTALL_ID,
        worker_id: WORKER,
        device_id: DEVICE_ID,
        public_key_spki_pem: devPubPem,
        browser_profile_identity: PROFILE_BINDING,
        native_bridge_identity: RESOURCES.bridge_identity_sha256,
        challenge_signature_b64url: deviceSigner.signEnrollmentChallenge({
          challenge,
          browser_profile_identity: PROFILE_BINDING,
          native_bridge_identity: RESOURCES.bridge_identity_sha256,
        }),
      }),
    });
    assert.equal(compRes.status, 200);

    const identity = createDeviceIdentityBridge({
      store: memoryIdentityStore(),
      cryptoImpl: webcrypto,
      now: () => Date.now(),
    });
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
        expires_at_ms: Date.now() + 180_000,
      }),
      { mode: 0o600 },
    );

    const browserState = {
      url: 'https://chatgpt.com/',
      uiState: 'NEW_CHAT_LANDING',
      tabId: 42,
      targetId: 'target-mp-01',
      profileId: 'profile-mp-01',
      submissions: [],
    };
    const runtime = {
      getURL: () => ORIGIN,
      connectNative() {
        entryProc = spawn(process.execPath, [entryPath, '--controller-bridge', policyPath, ORIGIN, sockPath], {
          stdio: ['pipe', 'pipe', 'pipe'],
          env: { PATH: process.env.PATH ?? '' },
        });
        const msgListeners = new Set();
        const discListeners = new Set();
        let buffer = Buffer.alloc(0);
        const notifyDisc = () => {
          for (const fn of [...discListeners]) fn();
        };
        entryProc.stdout.on('data', (chunk) => {
          buffer = Buffer.concat([buffer, chunk]);
          while (buffer.length >= 4) {
            const len = buffer.readUInt32LE(0);
            if (buffer.length < len + 4) break;
            const msg = JSON.parse(buffer.subarray(4, len + 4).toString('utf8'));
            buffer = buffer.subarray(len + 4);
            for (const fn of [...msgListeners]) fn(msg);
          }
        });
        entryProc.once('exit', notifyDisc);
        return {
          postMessage(msg) {
            const body = Buffer.from(JSON.stringify(msg), 'utf8');
            const frame = Buffer.allocUnsafe(body.length + 4);
            frame.writeUInt32LE(body.length, 0);
            body.copy(frame, 4);
            entryProc.stdin.write(frame);
          },
          disconnect() {
            if (!entryProc.stdin.writableEnded) entryProc.stdin.end();
          },
          onMessage: { addListener: (fn) => msgListeners.add(fn), removeListener: (fn) => msgListeners.delete(fn) },
          onDisconnect: { addListener: (fn) => discListeners.add(fn), removeListener: (fn) => discListeners.delete(fn) },
        };
      },
    };

    let lastClock = 0;
    const nextIso = () => {
      lastClock = Math.max(Date.now(), lastClock + 10);
      return new Date(lastClock).toISOString();
    };
    bridgeConn = await connectControllerNativeBridge({
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
            tabId: browserState.tabId,
            targetId: browserState.targetId,
            profileId: browserState.profileId,
            matchingWritableTargetCount: 1,
            sharedWritableProfile: false,
          },
        }),
        dispatchFirstMessage: async (cmd) => {
          const beforeUrl = browserState.url;
          const convId = 'conv-f3-mp-01';
          const afterUrl = `https://chatgpt.com/c/${convId}`;
          browserState.submissions.push({ turn: 1, attemptId: cmd.attempt_id, prompt: cmd.prompt, convId });
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
          browserState.submissions.push({ turn: cmd.expected_turn_number, attemptId: cmd.attempt_id, prompt: cmd.prompt });
          return {
            ok: true,
            code: 'CONTINUATION_SENT',
            payload: {
              beforeUrl,
              afterUrl,
              conversationId: cmd.expected_conversation_id,
              sendStartedAt: nextIso(),
              confirmedAt: nextIso(),
            },
          };
        },
      },
    });
    assert.equal(bridgeConn.ok, true);
    assert.equal(typeof ExtensionBrowserAdapter, 'function');

    // Default humanLiveSendAuthorized=false blocks sends even with valid Broker V2 request!
    await writeFile(
      runnerConfigPath,
      JSON.stringify({
        brokerBaseUrl: brokerUrl,
        deviceId: DEVICE_ID,
        enrollmentGeneration: 1,
        devicePublicKeyPem: devPubPem,
        devicePrivateKeyPem: devPrivPem,
        repository: REPO,
        repositoryId: REPO_ID,
        installationId: INSTALL_ID,
        prNumber: PR_NUM,
        workerId: WORKER,
        pinnedApp: { id: 9001, slug: 'bke-dispatcher-app' },
        executionId: 'exec-f3-mp-01',
        targetId: browserState.targetId,
        profileId: browserState.profileId,
        targetTabId: browserState.tabId,
        journalPath,
        ipcSocketPath: sockPath,
        policyPath,
        webhookSecret: 'unused-when-require-v2',
        operatorHaltToken: 'halt-secret-mp-01',
        humanLiveSendAuthorized: false,
        liveProofs: { githubCasOwnerCertified: true, nativePairingOwnerCertified: true, realBrowserOwnerAccepted: false },
        executionPublicKeys: brokerBoot.executionPublicKeys,
        haltPublicKeys: brokerBoot.haltPublicKeys,
        expectedAudience: AUDIENCE,
        expectedBrokerIssuer: ISSUER,
        githubApiBaseUrl: mockGh.baseUrl,
      }),
      { mode: 0o600 },
    );

    daemonProc = spawn(process.execPath, [controllerRunnerPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH ?? '', BKE_TEST_RUNNER_CONFIG_FILE: runnerConfigPath },
    });
    const daemonBootLocked = await waitFirstLine(daemonProc);
    assert.equal(daemonBootLocked.ok, true);
    const daemonUrlLocked = `http://127.0.0.1:${daemonBootLocked.port}`;

    const statusLockedRes = await fetch(`${daemonUrlLocked}/status`);
    assert.equal(statusLockedRes.status, 200);
    const statusLocked = await statusLockedRes.json();
    assert.equal(statusLocked.humanLiveSendAuthorized, false);
    assert.equal(statusLocked.broker.protocolVersion, 'v2_ed25519_strict');
    assert.equal(statusLocked.deviceIdentity.deviceId, DEVICE_ID);
    assert.ok(!JSON.stringify(statusLocked).includes('ghs_'));
    assert.ok(!JSON.stringify(statusLocked).includes('PRIVATE KEY'));

    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-f3-locked', Date.now() + 180_000);
    const signedLocked = await (
      await fetch(`${brokerUrl}/v1/broker/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-f3-locked',
          action: 'DISPATCH_FIRST_MESSAGE',
          device_assertion: deviceSigner.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE_ID,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
          }),
          admin_approval: mkAdmin('DISPATCH_EXECUTION', { attempt_id: 'att-f3-locked', execution_action: 'DISPATCH_FIRST_MESSAGE' }),
        }),
      })
    ).json();
    assert.equal(signedLocked.ok, true);

    const lockedDispatchRes = await fetch(`${daemonUrlLocked}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedLocked.signed_request),
    });
    const lockedDispatchBody = await lockedDispatchRes.json();
    assert.equal(lockedDispatchBody.status, 'BLOCKED');
    assert.equal(lockedDispatchBody.code, 'LIVE_SEND_DISABLED');
    assert.equal(browserState.submissions.length, 0);

    await stopProc(daemonProc);
    daemonProc = null;

    // Re-launch Daemon with explicit supervised session flag and run Turn 1 -> Turn 2 multi-process!
    await writeFile(
      runnerConfigPath,
      JSON.stringify({
        brokerBaseUrl: brokerUrl,
        deviceId: DEVICE_ID,
        enrollmentGeneration: 1,
        devicePublicKeyPem: devPubPem,
        devicePrivateKeyPem: devPrivPem,
        repository: REPO,
        repositoryId: REPO_ID,
        installationId: INSTALL_ID,
        prNumber: PR_NUM,
        workerId: WORKER,
        pinnedApp: { id: 9001, slug: 'bke-dispatcher-app' },
        executionId: 'exec-f3-mp-01',
        targetId: browserState.targetId,
        profileId: browserState.profileId,
        targetTabId: browserState.tabId,
        journalPath,
        ipcSocketPath: sockPath,
        policyPath,
        webhookSecret: 'unused-when-require-v2',
        operatorHaltToken: 'halt-secret-mp-01',
        humanLiveSendAuthorized: true,
        liveProofs: { githubCasOwnerCertified: true, nativePairingOwnerCertified: true, realBrowserOwnerAccepted: true },
        executionPublicKeys: brokerBoot.executionPublicKeys,
        haltPublicKeys: brokerBoot.haltPublicKeys,
        expectedAudience: AUDIENCE,
        expectedBrokerIssuer: ISSUER,
        githubApiBaseUrl: mockGh.baseUrl,
      }),
      { mode: 0o600 },
    );

    daemonProc = spawn(process.execPath, [controllerRunnerPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH ?? '', BKE_TEST_RUNNER_CONFIG_FILE: runnerConfigPath },
    });
    const daemonBoot = await waitFirstLine(daemonProc);
    const daemonUrl = `http://127.0.0.1:${daemonBoot.port}`;

    // Turn 1
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-f3-turn-1', Date.now() + 180_000);
    const authT1 = await (
      await fetch(`${brokerUrl}/v1/broker/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-f3-turn-1',
          action: 'DISPATCH_FIRST_MESSAGE',
          device_assertion: deviceSigner.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE_ID,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
          }),
          admin_approval: mkAdmin('DISPATCH_EXECUTION', { attempt_id: 'att-f3-turn-1', execution_action: 'DISPATCH_FIRST_MESSAGE' }),
        }),
      })
    ).json();
    assert.equal(authT1.ok, true);

    const execT1 = await (
      await fetch(`${daemonUrl}/execution-requests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(authT1.signed_request),
      })
    ).json();
    assert.equal(execT1.status, 'CONFIRMED_TURN_1');
    assert.equal(execT1.conversationId, 'conv-f3-mp-01');

    // Turn 2
    mockGh.setTicket(REPO, HEAD_A, WORKER, 'att-f3-turn-2', Date.now() + 180_000);
    const authT2 = await (
      await fetch(`${brokerUrl}/v1/broker/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: 'att-f3-turn-2',
          action: 'DISPATCH_CONTINUATION',
          device_assertion: deviceSigner.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE_ID,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
          }),
          admin_approval: mkAdmin('DISPATCH_EXECUTION', { attempt_id: 'att-f3-turn-2', execution_action: 'DISPATCH_CONTINUATION' }),
        }),
      })
    ).json();
    assert.equal(authT2.ok, true);

    const execT2 = await (
      await fetch(`${daemonUrl}/execution-requests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(authT2.signed_request),
      })
    ).json();
    assert.equal(execT2.status, 'CONFIRMED_CONTINUATION');
    assert.equal(execT2.turnNumber, 2);
    assert.equal(browserState.submissions.length, 2);

    assert.ok(mockGh.state.refs.has(`${REPO}:refs/bke/fences/${PR_NUM}/att-f3-turn-1`));
    assert.ok(mockGh.state.refs.has(`${REPO}:refs/bke/claims/${PR_NUM}/att-f3-turn-1`));
    assert.ok(mockGh.state.refs.has(`${REPO}:refs/bke/claims/${PR_NUM}/att-f3-turn-2`));
    assert.ok(mockGh.state.refs.has(`${REPO}:refs/bke/conversations/${PR_NUM}`));
    assert.ok(mockGh.state.refs.has(`${REPO}:refs/bke/turns/${PR_NUM}/att-f3-turn-2`));

    const finalStatus = await (await fetch(`${daemonUrl}/status`)).json();
    assert.equal(finalStatus.confirmedTurnCount, 2);
    assert.equal(finalStatus.conversationId, 'conv-f3-mp-01');
    assert.equal(finalStatus.tokenLifecycle.realBrokerTransportConnected, true);
    assert.equal(finalStatus.tokenLifecycle.requestedContentsLevel, 'read');
    assert.equal(finalStatus.mediatedCasEnabled, true);
    assert.equal(finalStatus.desktopWriteTokenForbidden, true);
    assert.equal(finalStatus.revocationAuthorityConfigured, true);

    // P0-03 Verification: Broker refuses desktop contents:write token requests across HTTP too
    const forbiddenMintRes = await fetch(`${brokerUrl}/v1/broker/tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repository: REPO,
        repository_id: REPO_ID,
        installation_id: INSTALL_ID,
        worker_id: WORKER,
        requested_permissions: { contents: 'write', pull_requests: 'read', checks: 'read' },
        device_assertion: deviceSigner.signDeviceAssertion({
          worker_id: WORKER,
          device_id: DEVICE_ID,
          installation_id: INSTALL_ID,
          enrollment_generation: 1,
          purpose: 'MINT_SCOPED_TOKEN',
          repository: REPO,
        }),
      }),
    });
    assert.equal(forbiddenMintRes.status, 403);
    const forbiddenMintBody = await forbiddenMintRes.json();
    assert.equal(forbiddenMintBody.code, 'BROKER_DESKTOP_WRITE_TOKEN_FORBIDDEN');

    const auditBody = await (await fetch(`${brokerUrl}/v1/broker/audit`)).json();
    assert.equal(auditBody.ok, true);
    const auditOps = new Set(auditBody.events.map((e) => e.operation));
    assert.ok(auditOps.has('MINT_SCOPED_TOKEN'));
    assert.ok(auditOps.has('MEDIATED_COMMIT_PRE_SEND_FENCE'));
    assert.ok(auditOps.has('MEDIATED_CONSUME_SEND_CLAIM'));
    assert.ok(auditOps.has('MEDIATED_RECONCILE_CONVERSATION'));

    // F3-08: Verify integrated F3 evidence maps cleanly across all 14 Command Center visible states
    const observedTags = new Set();
    const baseNow = Date.now();
    const projConfirmed2 = projectWorkerStateForCommandCenter({
      observedAtMs: baseNow,
      nowMs: baseNow,
      expectedHeadSha: HEAD_A,
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
      exactHeadCi: { status: 'PASS' },
      tokenLifecycle: finalStatus.tokenLifecycle,
      workerHeartbeat: { fresh: true },
      journal: {
        phase: finalStatus.journalPhase,
        conversationId: finalStatus.conversationId,
        confirmedTurnCount: finalStatus.confirmedTurnCount,
        uncertainReason: null,
      },
      pairing: { policyMatched: true, activeBridgeSession: true, bridgeQuarantined: false },
      browser: {
        uiState: 'THREAD',
        composerAvailable: true,
        matchingWritableTargetCount: 1,
        observedAtMs: baseNow,
      },
      certification: { sourceTestsPassed: true, syntheticE2ePassed: true, realBrowserAccepted: false },
    });
    assert.equal(projConfirmed2.realBrowserAcceptance, 'NOT_RUN');
    assert.equal(projConfirmed2.confirmedTurnCount, 2);
    for (const t of projConfirmed2.visibleStates) observedTags.add(t);

    for (const s of [
      {
        observedAtMs: baseNow,
        nowMs: baseNow,
        expectedHeadSha: HEAD_A,
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
        journal: { phase: 'CONFIRMED_CONVERSATION', conversationId: 'conv-f3-mp-01', confirmedTurnCount: 1, uncertainReason: null },
        pairing: { policyMatched: true, activeBridgeSession: true, bridgeQuarantined: false },
        browser: { uiState: 'THREAD', composerAvailable: true, matchingWritableTargetCount: 1, observedAtMs: baseNow },
      },
      {
        observedAtMs: baseNow,
        nowMs: baseNow,
        expectedHeadSha: 'f'.repeat(40),
        githubAssignment: {
          repository: REPO,
          prNumber: PR_NUM,
          workerId: WORKER,
          headSha: HEAD_A,
          openPrCountForWorker: 1,
          workerLabelsOnPr: 1,
          atomicRevalidated: true,
          uncertainRefCount: 1,
        },
        exactHeadCi: { status: 'PENDING' },
        claimReserved: true,
        journal: { phase: 'DELIVERY_UNCERTAIN', conversationId: null, confirmedTurnCount: 0, uncertainReason: 'UNCERTAIN_CAS' },
      },
      {
        observedAtMs: baseNow,
        nowMs: baseNow,
        expectedHeadSha: HEAD_A,
        githubAssignment: {
          repository: REPO,
          prNumber: PR_NUM,
          workerId: WORKER,
          headSha: HEAD_A,
          openPrCountForWorker: 2,
          workerLabelsOnPr: 1,
          atomicRevalidated: true,
          uncertainRefCount: 0,
        },
      },
    ]) {
      for (const t of projectWorkerStateForCommandCenter(s).visibleStates) observedTags.add(t);
    }
    for (const reqTag of F2_REQUIRED_VISIBLE_STATES) {
      assert.ok(observedTags.has(reqTag), `Missing Command Center visible state: ${reqTag}`);
    }
  } finally {
    await stopProc(daemonProc);
    await stopProc(brokerProc);
    if (bridgeConn?.port?.disconnect) {
      bridgeConn.port.disconnect();
    }
    await stopProc(entryProc);
    await mockGh.close();
    await rm(dir, { recursive: true, force: true });
  }
});
