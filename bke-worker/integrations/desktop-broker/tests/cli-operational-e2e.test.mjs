/**
 * F4.1 Genuine Operational CLI Multi-Process Acceptance Suite.
 *
 * Spawns the ACTUAL compiled operator CLI (`controller-daemon.js start`) as a real OS subprocess
 * wired via `runtime-broker-factory.ts` (`HttpTrustedBrokerClient` + owner 0o600 credentials)
 * against:
 *   Process 1: SandboxBrokerHttpServer (`dist/broker-server.js`)
 *   Process 2: Production CLI Daemon (`browser-extension/native-host/claim/dist/native-host/claim/controller-daemon.js start`)
 *   Process 3: Native Messaging Bridge (`browser-extension/native-host/entry.mjs --controller-bridge`)
 * plus in-process MockGitHubServer (`127.0.0.1`) & synthetic ChatGPT browser handlers (ZERO real ChatGPT sends).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, webcrypto } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createDeviceIdentityBridge } from '../../../browser-extension/dist/device-identity.js';
import { connectControllerNativeBridge } from '../../../browser-extension/dist/controller-transport.js';
import {
  AUTHORIZED_CAPABILITY_V2,
  EXECUTION_REQUEST_PROTOCOL_VERSION_V2,
  signExecutionRequestEd25519,
} from '../../../browser-extension/native-host/claim/dist/native-host/claim/github-app-harness.js';
import { signAdminApproval } from '../dist/device-enrollment.js';
import { DeviceKeyPairSigner } from '../dist/broker-client.js';
import { startMockGitHubServer } from './mock-github-server.mjs';

const ORIGIN = 'chrome-extension://' + 'b'.repeat(32) + '/';
const PROFILE_BINDING = '5'.repeat(64);
const RESOURCES = {
  chatgpt_target_sha256: '1'.repeat(64),
  browser_profile_sha256: '2'.repeat(64),
  bridge_identity_sha256: '3'.repeat(64),
};
const REPO = 'jan2xo/bke-worker';
const REPO_ID = 1354026486;
const INSTALL_ID = '987654321';
const PR_NUM = 149;
const WORKER = 'worker-f1';
const DEVICE_ID = 'desktop-dev-f41-cli-01';
const HEAD_A = 'a'.repeat(40);
const ISSUER = 'http://127.0.0.1';
const AUDIENCE = `bke-desktop-controller:${REPO}:${WORKER}`;

const entryPath = fileURLToPath(new URL('../../../browser-extension/native-host/entry.mjs', import.meta.url));
const brokerServerPath = fileURLToPath(new URL('../dist/broker-server.js', import.meta.url));
const controllerCliPath = fileURLToPath(
  new URL('../../../browser-extension/native-host/claim/dist/native-host/claim/controller-daemon.js', import.meta.url),
);

function memoryIdentityStore() {
  let current;
  let tail = Promise.resolve();
  return {
    async atomic(action) {
      let release;
      const next = new Promise((resolve) => {
        release = resolve;
      });
      const prev = tail;
      tail = next;
      await prev;
      const draft = current === undefined ? undefined : structuredClone(current);
      try {
        const res = await action({
          get: async () => (draft === undefined ? undefined : structuredClone(draft)),
          put: async (v) => {
            current = structuredClone(v);
          },
        });
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
      try {
        proc.kill('SIGKILL');
      } catch {}
      r();
    }, 1_500);
    proc.once('exit', () => {
      clearTimeout(t);
      r();
    });
  });
}

test('F4.1 operational CLI E2E: controller:cli start runs V2 + mediated CAS + revocation + outage + restart + quarantine with zero desktop write tokens', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f41-cli-e2e-'));
  await chmod(dir, 0o700);
  const mockGh = await startMockGitHubServer({ installationId: INSTALL_ID });
  const adminKeys = genEd25519();
  const wrongSignKey = genEd25519();
  const adminKeyFile = join(dir, 'admin-keys.json');
  const enrollmentPath = join(dir, 'enrollment.json');
  const brokerStatePath = join(dir, 'broker-state.json');
  const policyPath = join(dir, 'owner-policy.json');
  const credsPath = join(dir, 'device-credentials.json');
  const sockPath = join(dir, 'bridge.sock');
  const journalPath = join(dir, 'journal.json');

  await writeFile(adminKeyFile, JSON.stringify({ 'admin-k1': adminKeys.publicPem }), { mode: 0o600 });

  let brokerProc = null;
  let daemonProc = null;
  let entryProc = null;
  let bridgeConn = null;

  const spawnBroker = async (port = 0) => {
    const proc = spawn(process.execPath, [brokerServerPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        PATH: process.env.PATH ?? '',
        BKE_BROKER_ISSUER: ISSUER,
        BKE_BROKER_PORT: String(port),
        BKE_BROKER_ENROLLMENT_PATH: enrollmentPath,
        BKE_BROKER_STATE_PATH: brokerStatePath,
        BKE_GITHUB_API_BASE_URL: mockGh.baseUrl,
        BKE_BROKER_ADMIN_PUBLIC_KEYS_FILE: adminKeyFile,
        BKE_PINNED_APP_ID: '9001',
        BKE_PINNED_APP_SLUG: 'bke-dispatcher-app',
      },
    });
    const boot = await waitFirstLine(proc);
    assert.equal(boot.ok, true);
    return { proc, boot };
  };

  try {
    const firstBroker = await spawnBroker(0);
    brokerProc = firstBroker.proc;
    const brokerBoot = firstBroker.boot;
    const brokerPort = brokerBoot.port;
    const brokerUrl = `http://127.0.0.1:${brokerPort}`;

    const { publicKey: devPub, privateKey: devPriv } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const devPubPem = devPub.export({ type: 'spki', format: 'pem' }).toString();
    const devPrivPem = devPriv.export({ type: 'pkcs8', format: 'pem' }).toString();
    const devPubSha = createHash('sha256').update(devPub.export({ type: 'spki', format: 'der' })).digest('hex');
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
          expires_at: new Date(now + 180_000).toISOString(),
          ...extra,
        },
        adminKeys.privatePem,
        'admin-k1',
      );

    // Enroll device against sandbox broker
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

    // Extension WebCrypto identity & owner-policy.json (0o600) + owner device-credentials.json (0o600)
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

    await writeFile(
      credsPath,
      JSON.stringify({
        version: 1,
        device_id: DEVICE_ID,
        worker_id: WORKER,
        installation_id: INSTALL_ID,
        repository: REPO,
        repository_id: REPO_ID,
        enrollment_generation: 1,
        device_public_key_pem: devPubPem,
        device_private_key_pem: devPrivPem,
        public_key_sha256: devPubSha,
        browser_profile_identity: PROFILE_BINDING,
        native_bridge_identity: RESOURCES.bridge_identity_sha256,
        extension_public_key_sha256: pub.public_key_sha256,
        broker_issuer: ISSUER,
        broker_base_url: brokerUrl,
        broker_public_keys_by_id: brokerBoot.executionPublicKeys,
        halt_public_keys_by_id: brokerBoot.haltPublicKeys,
      }),
      { mode: 0o600 },
    );

    const browserState = {
      url: 'https://chatgpt.com/',
      uiState: 'NEW_CHAT_LANDING',
      tabId: 42,
      targetId: 'target-cli-01',
      profileId: 'profile-cli-01',
      forceUncertainOnAttempt: null,
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
          const convId = 'conv-f41-cli-01';
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
          if (browserState.forceUncertainOnAttempt === cmd.attempt_id) {
            return {
              ok: false,
              code: 'CONTINUATION_SUBMISSION_UNCERTAIN',
              payload: { reason: 'SIMULATED_POST_CLICK_AMBIGUITY' },
            };
          }
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

    const commonCliEnv = {
      PATH: process.env.PATH ?? '',
      BKE_REPOSITORY: REPO,
      BKE_PR_NUMBER: String(PR_NUM),
      BKE_WORKER_ID: WORKER,
      BKE_PINNED_APP_ID: '9001',
      BKE_PINNED_APP_SLUG: 'bke-dispatcher-app',
      BKE_EXECUTION_ID: 'exec-f41-cli-01',
      BKE_TARGET_ID: browserState.targetId,
      BKE_PROFILE_ID: browserState.profileId,
      BKE_TARGET_TAB_ID: String(browserState.tabId),
      BKE_JOURNAL_PATH: journalPath,
      BKE_CONTROLLER_IPC_SOCKET: sockPath,
      BKE_NATIVE_POLICY_PATH: policyPath,
      BKE_DEVICE_CREDENTIALS_PATH: credsPath,
      BKE_OPERATOR_HALT_TOKEN: 'halt-secret-f41-01',
      BKE_CONTROLLER_HOST: '127.0.0.1',
      BKE_CONTROLLER_PORT: '0',
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REQUIRE_ASYMMETRIC_V2: 'true',
      BKE_SERVER_MEDIATED_CAS_ENABLED: 'true',
      BKE_REMOTE_BROKER_ENABLED: 'true',
      BKE_BROKER_BASE_URL: brokerUrl,
      BKE_EXECUTION_AUDIENCE: AUDIENCE,
      BKE_ALLOW_REMOTE_SIGNED_HALT: 'true',
      BKE_GITHUB_API_BASE_URL: mockGh.baseUrl,
      BKE_CERT_GITHUB_CAS: 'true',
      BKE_CERT_NATIVE_PAIRING: 'true',
      BKE_CERT_REAL_BROWSER: 'true',
    };

    // 1. Verify normal CLI start keeps live send locked FALSE by default while wiring V2 + mediated CAS + broker
    daemonProc = spawn(process.execPath, [controllerCliPath, 'start'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: commonCliEnv,
    });
    const cliLockedBoot = await waitFirstLine(daemonProc);
    assert.equal(cliLockedBoot.ok, true);
    assert.equal(cliLockedBoot.mediatedCasEnabled, true);
    assert.equal(cliLockedBoot.desktopWriteTokenForbidden, true);
    assert.equal(cliLockedBoot.revocationAuthorityConfigured, true);
    assert.equal(cliLockedBoot.brokerConnected, true);
    assert.equal(cliLockedBoot.humanLiveSendAuthorized, false);

    const daemonUrlLocked = `http://127.0.0.1:${cliLockedBoot.port}`;
    const lockedStatus = await (await fetch(`${daemonUrlLocked}/status`)).json();
    assert.equal(lockedStatus.humanLiveSendAuthorized, false);
    assert.equal(lockedStatus.broker.protocolVersion, 'v2_ed25519_strict');
    assert.equal(lockedStatus.broker.realBrokerTransportConnected, true);
    assert.equal(lockedStatus.mediatedCasEnabled, true);
    assert.equal(lockedStatus.revocationAuthorityConfigured, true);
    assert.ok(!JSON.stringify(lockedStatus).includes('ghs_'));
    assert.ok(!JSON.stringify(lockedStatus).includes('PRIVATE KEY'));

    await stopProc(daemonProc);
    daemonProc = null;

    // 2. Start actual controller:cli start with supervised synthetic harness flag & run full lifecycle
    const spawnSupervisedCli = async () => {
      const proc = spawn(process.execPath, [controllerCliPath, 'start', '--owner-supervised-live-send'], {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...commonCliEnv,
          BKE_OWNER_SUPERVISED_LIVE_SEND: 'I_OWNER_AUTHORIZE_LIVE_SEND',
        },
      });
      const boot = await waitFirstLine(proc);
      assert.equal(boot.ok, true);
      assert.equal(boot.humanLiveSendAuthorized, true);
      return { proc, boot, url: `http://127.0.0.1:${boot.port}` };
    };

    const authorizeAtBroker = async (attemptId, action) => {
      mockGh.setTicket(REPO, HEAD_A, WORKER, attemptId, Date.now() + 180_000);
      const res = await fetch(`${brokerUrl}/v1/broker/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository: REPO,
          expected_repository_id: REPO_ID,
          installation_id: INSTALL_ID,
          worker_id: WORKER,
          pr_number: PR_NUM,
          head_sha: HEAD_A,
          attempt_id: attemptId,
          action,
          device_assertion: deviceSigner.signDeviceAssertion({
            worker_id: WORKER,
            device_id: DEVICE_ID,
            installation_id: INSTALL_ID,
            enrollment_generation: 1,
            purpose: 'AUTHORIZE_EXECUTION',
            repository: REPO,
          }),
          admin_approval: mkAdmin('DISPATCH_EXECUTION', { attempt_id: attemptId, execution_action: action }),
        }),
      });
      const body = await res.json();
      assert.equal(res.status, 200);
      assert.equal(body.ok, true);
      return body.signed_request;
    };

    const s1 = await spawnSupervisedCli();
    daemonProc = s1.proc;
    let daemonUrl = s1.url;

    // Invalid credential / signature -> 401
    const forgedReq = signExecutionRequestEd25519(
      {
        protocol_version: EXECUTION_REQUEST_PROTOCOL_VERSION_V2,
        authorized_capability: AUTHORIZED_CAPABILITY_V2,
        broker_issuer: ISSUER,
        audience: AUDIENCE,
        device_id: DEVICE_ID,
        enrollment_generation: 1,
        delivery_id: 'del-forged-01',
        repository_owner: 'jan2xo',
        repository_name: 'bke-worker',
        repository_id: REPO_ID,
        installation_identity: INSTALL_ID,
        pr_number: PR_NUM,
        head_sha: HEAD_A,
        worker_id: WORKER,
        attempt_id: 'att-f41-forged',
        action: 'DISPATCH_FIRST_MESSAGE',
        issued_at: new Date(Date.now() - 1_000).toISOString(),
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      },
      wrongSignKey.privatePem,
      brokerBoot.activeExecutionKeyId,
    );
    const forgedRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(forgedReq),
    });
    assert.equal(forgedRes.status, 401);
    assert.equal((await forgedRes.json()).code, 'EXEC_REQ_SIGNATURE_INVALID');

    // Turn 1 via real CLI daemon
    const reqT1 = await authorizeAtBroker('att-f41-turn-1', 'DISPATCH_FIRST_MESSAGE');
    const execT1Res = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqT1),
    });
    assert.equal(execT1Res.status, 200);
    const execT1 = await execT1Res.json();
    assert.equal(execT1.status, 'CONFIRMED_TURN_1');
    assert.equal(execT1.conversationId, 'conv-f41-cli-01');

    // Turn 2 via real CLI daemon
    const reqT2 = await authorizeAtBroker('att-f41-turn-2', 'DISPATCH_CONTINUATION');
    const execT2Res = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqT2),
    });
    assert.equal(execT2Res.status, 200);
    const execT2 = await execT2Res.json();
    assert.equal(execT2.status, 'CONFIRMED_CONTINUATION');
    assert.equal(execT2.turnNumber, 2);
    assert.equal(browserState.submissions.length, 2);

    // Check broker audit and verify zero contents:write tokens issued to desktop
    const auditAfterT2 = await (await fetch(`${brokerUrl}/v1/broker/audit`)).json();
    const auditOps = new Set(auditAfterT2.events.map((e) => e.operation));
    assert.ok(auditOps.has('MINT_SCOPED_TOKEN'));
    assert.ok(auditOps.has('MEDIATED_COMMIT_PRE_SEND_FENCE'));
    assert.ok(auditOps.has('MEDIATED_CONSUME_SEND_CLAIM'));
    assert.ok(auditOps.has('MEDIATED_RECONCILE_CONVERSATION'));
    const statusMid = await (await fetch(`${daemonUrl}/status`)).json();
    assert.equal(statusMid.tokenLifecycle.requestedContentsLevel, 'read');
    assert.equal(statusMid.desktopWriteTokenForbidden, true);

    // Pre-sign Turn 3 (for outage) and Turn 5 (for post-restart quarantine check) while broker is up
    const reqT3Outage = await authorizeAtBroker('att-f41-outage-3', 'DISPATCH_CONTINUATION');
    const reqT5AfterQuarantine = await authorizeAtBroker('att-f41-after-quarantine-5', 'DISPATCH_CONTINUATION');
    await stopProc(brokerProc);
    brokerProc = null;

    const outageRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqT3Outage),
    });
    assert.equal(outageRes.status, 503);
    const outageBody = await outageRes.json();
    assert.equal(outageBody.code, 'EXEC_REQ_REVOCATION_UNAVAILABLE');
    assert.equal(outageBody.submitInvocations, 0);
    assert.equal(browserState.submissions.length, 2);

    // Restart broker on the EXACT same port and simulate post-claim uncertainty -> MEDIATED_MARK_DELIVERY_UNCERTAIN + 409 quarantine
    const restartedBroker = await spawnBroker(brokerPort);
    brokerProc = restartedBroker.proc;

    browserState.forceUncertainOnAttempt = 'att-f41-uncertain-4';
    const reqT4Uncertain = await authorizeAtBroker('att-f41-uncertain-4', 'DISPATCH_CONTINUATION');
    const uncertainRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqT4Uncertain),
    });
    assert.equal(uncertainRes.status, 409);
    const uncertainBody = await uncertainRes.json();
    assert.equal(uncertainBody.status, 'BLOCKED');
    assert.equal(uncertainBody.journalPhase, 'DELIVERY_UNCERTAIN');
    assert.ok(mockGh.state.refs.has(`${REPO}:refs/bke/uncertain/${PR_NUM}/att-f41-uncertain-4`));

    const auditAfterUncertain = await (await fetch(`${brokerUrl}/v1/broker/audit`)).json();
    assert.ok(auditAfterUncertain.events.some((e) => e.operation === 'MEDIATED_MARK_DELIVERY_UNCERTAIN'));

    // Restart controller:cli start OS subprocess on SAME journalPath -> verify replay & DELIVERY_UNCERTAIN quarantine persist!
    await stopProc(daemonProc);
    daemonProc = null;
    const s2 = await spawnSupervisedCli();
    daemonProc = s2.proc;
    daemonUrl = s2.url;

    const recoveredStatus = await (await fetch(`${daemonUrl}/status`)).json();
    assert.equal(recoveredStatus.journalPhase, 'DELIVERY_UNCERTAIN');
    assert.equal(recoveredStatus.quarantined, true);
    assert.equal(recoveredStatus.confirmedTurnCount, 2);
    assert.equal(recoveredStatus.conversationId, 'conv-f41-cli-01');

    // Turn 1 replay rejected across CLI daemon restart
    const replayRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqT1),
    });
    assert.equal(replayRes.status, 409);

    // Pre-authorized Turn 5 sent after restart while quarantined returns 409 with journalPhase DELIVERY_UNCERTAIN
    const qRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqT5AfterQuarantine),
    });
    assert.equal(qRes.status, 409);
    const qBody = await qRes.json();
    assert.equal(qBody.journalPhase, 'DELIVERY_UNCERTAIN');
    assert.equal(qBody.submitInvocations, 0);

    // Revoke device on broker and verify CLI daemon rejects with distinct 403 EXEC_REQ_DEVICE_REVOKED
    const revRes = await fetch(`${brokerUrl}/v1/enrollment/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        installation_id: INSTALL_ID,
        worker_id: WORKER,
        device_id: DEVICE_ID,
        state: 'REVOKED',
        reason: 'OWNER_F41_REVOCATION_DRILL',
        admin_approval: mkAdmin('REVOKE_DEVICE', { reason: 'OWNER_F41_REVOCATION_DRILL' }),
      }),
    });
    assert.equal(revRes.status, 200);

    const revokedStatusRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqT3Outage),
    });
    assert.equal(revokedStatusRes.status, 403);
    assert.equal((await revokedStatusRes.json()).code, 'EXEC_REQ_DEVICE_REVOKED');
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
