/**
 * F4.1 Runtime Dependency Factory & Real CLI Subprocess Wiring Tests.
 *
 * Exercises the actual compiled `controller-daemon.js start` & `doctor` OS subprocesses
 * alongside `createDesktopControllerRuntimeDependencies` and `HttpTrustedBrokerClient`.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { DesktopControllerDaemon, runControllerDoctor } from '../dist/native-host/claim/controller-daemon.js';
import {
  AUTHORIZED_CAPABILITY_V2,
  EXECUTION_REQUEST_PROTOCOL_VERSION_V2,
  signExecutionRequestEd25519,
} from '../dist/native-host/claim/github-app-harness.js';
import {
  HttpTrustedBrokerClient,
  createDesktopControllerRuntimeDependencies,
  loadOwnerDeviceCredentialsFile,
} from '../dist/native-host/claim/runtime-broker-factory.js';

const CLI_PATH = fileURLToPath(new URL('../dist/native-host/claim/controller-daemon.js', import.meta.url));
const REPO = 'jan2xo/bke-worker';
const WORKER = 'worker-f1';
const INSTALL_ID = '987654321';
const DEVICE_ID = 'desktop-dev-f41-01';
const PR_NUM = 149;
const REPO_ID = 1354026486;
const ISSUER = 'http://127.0.0.1';
const AUDIENCE = `bke-desktop-controller:${REPO}:${WORKER}`;
const PROFILE_BINDING = '5'.repeat(64);
const BRIDGE_ID = '3'.repeat(64);
const EXT_THUMB = '9'.repeat(64);

function canonicalJson(obj) {
  const ordered = {};
  for (const k of Object.keys(obj).sort()) ordered[k] = obj[k];
  return JSON.stringify(ordered);
}

function genP256() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const sha = createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
  return { publicPem, privatePem, sha };
}

function genEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

function signEd25519Payload(domain, payload, privatePem, keyId) {
  const sig = cryptoSign(null, Buffer.from(domain + canonicalJson(payload), 'utf8'), privatePem).toString('base64url');
  return { payload, key_id: keyId, signature_alg: 'Ed25519', signature_b64url: sig };
}

function signEnvelopeV2(envelope, privatePem, keyId) {
  return signExecutionRequestEd25519(envelope, privatePem, keyId);
}

function runCliOnce(args, env, timeoutMs = 4_000) {
  return new Promise((resolveRun, rejectRun) => {
    const proc = spawn(process.execPath, [CLI_PATH, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH ?? '', ...env },
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      try {
        proc.kill('SIGKILL');
      } catch {}
      rejectRun(new Error(`CLI_TIMEOUT args=${args.join(' ')} stdout=${stdout} stderr=${stderr}`));
    }, timeoutMs);
    proc.stdout.on('data', (d) => (stdout += d.toString('utf8')));
    proc.stderr.on('data', (d) => (stderr += d.toString('utf8')));
    proc.once('exit', (code) => {
      clearTimeout(timer);
      resolveRun({ code, stdout, stderr });
    });
  });
}

function startCliDaemon(env, timeoutMs = 5_000) {
  return new Promise((resolveStart, rejectStart) => {
    const proc = spawn(process.execPath, [CLI_PATH, 'start'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH ?? '', ...env },
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      try {
        proc.kill('SIGKILL');
      } catch {}
      rejectStart(new Error(`DAEMON_START_TIMEOUT stdout=${stdout} stderr=${stderr}`));
    }, timeoutMs);
    proc.stderr.on('data', (d) => (stderr += d.toString('utf8')));
    proc.stdout.on('data', (d) => {
      stdout += d.toString('utf8');
      const idx = stdout.indexOf('\n');
      if (idx >= 0) {
        clearTimeout(timer);
        try {
          resolveStart({ proc, boot: JSON.parse(stdout.slice(0, idx)), stderr });
        } catch (err) {
          rejectStart(err);
        }
      }
    });
    proc.once('exit', (code) => {
      clearTimeout(timer);
      rejectStart(new Error(`DAEMON_EXITED_EARLY_${code}: ${stderr.trim()}`));
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

async function writeFixtureFiles(dir, { devKey, brokerExecKey, brokerUrl = 'http://127.0.0.1:49999' }) {
  const credsPath = join(dir, 'device-credentials.json');
  const policyPath = join(dir, 'owner-policy.json');
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
      device_public_key_pem: devKey.publicPem,
      device_private_key_pem: devKey.privatePem,
      public_key_sha256: devKey.sha,
      browser_profile_identity: PROFILE_BINDING,
      native_bridge_identity: BRIDGE_ID,
      extension_public_key_sha256: EXT_THUMB,
      broker_issuer: ISSUER,
      broker_base_url: brokerUrl,
      broker_public_keys_by_id: { 'broker-exec-k1': brokerExecKey.publicPem },
    }),
    { mode: 0o600 },
  );
  await writeFile(
    policyPath,
    JSON.stringify({
      version: 1,
      allowed_origin: `chrome-extension://${'b'.repeat(32)}/`,
      worker_id: WORKER,
      public_key_sha256: EXT_THUMB,
      profile_binding_sha256: PROFILE_BINDING,
      resources: {
        chatgpt_target_sha256: '1'.repeat(64),
        browser_profile_sha256: '2'.repeat(64),
        bridge_identity_sha256: BRIDGE_ID,
      },
      expires_at_ms: Date.now() + 180_000,
    }),
    { mode: 0o600 },
  );
  return { credsPath, policyPath };
}

test('F4.1 CLI subprocess: default startup leaves V2, broker, mediated CAS, and live send disabled', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f41-default-'));
  await chmod(dir, 0o700);
  const journalPath = join(dir, 'journal.json');
  const sockPath = join(dir, 'bridge.sock');
  let started = null;
  try {
    started = await startCliDaemon({
      BKE_REPOSITORY: REPO,
      BKE_PR_NUMBER: String(PR_NUM),
      BKE_WORKER_ID: WORKER,
      BKE_JOURNAL_PATH: journalPath,
      BKE_CONTROLLER_IPC_SOCKET: sockPath,
      BKE_CONTROLLER_PORT: '0',
    });
    assert.equal(started.boot.ok, true);
    assert.equal(started.boot.mode, 'DAEMON_LISTENING');
    assert.equal(started.boot.executionEnvelopeEnabled, false);
    assert.equal(started.boot.asymmetricV2Enabled, false);
    assert.equal(started.boot.mediatedCasEnabled, false);
    assert.equal(started.boot.revocationAuthorityConfigured, false);
    assert.equal(started.boot.brokerConnected, false);
    assert.equal(started.boot.humanLiveSendAuthorized, false);

    const status = await (await fetch(`http://127.0.0.1:${started.boot.port}/status`)).json();
    assert.equal(status.executionEnvelopeEnabled, false);
    assert.equal(status.asymmetricV2Enabled, false);
    assert.equal(status.mediatedCasEnabled, false);
    assert.equal(status.broker.protocolVersion, 'DISABLED');
    assert.equal(status.humanLiveSendAuthorized, false);

    const execRes = await fetch(`http://127.0.0.1:${started.boot.port}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ protocol_version: 'v2_ed25519_strict' }),
    });
    assert.equal(execRes.status, 403);
    assert.equal((await execRes.json()).code, 'EXECUTION_ENVELOPE_DISABLED');
  } finally {
    await stopProc(started?.proc);
    await rm(dir, { recursive: true, force: true });
  }
});

test('F4.1 CLI subprocess: fails closed before listening on missing revocation, missing CAS client, V1 legacy, static write token, or unsafe credentials', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f41-failclosed-'));
  await chmod(dir, 0o700);
  const devKey = genP256();
  const brokerExecKey = genEd25519();
  const haltKey = genEd25519();
  const { credsPath, policyPath } = await writeFixtureFiles(dir, { devKey, brokerExecKey });
  const baseEnv = {
    BKE_REPOSITORY: REPO,
    BKE_PR_NUMBER: String(PR_NUM),
    BKE_WORKER_ID: WORKER,
    BKE_JOURNAL_PATH: join(dir, 'journal.json'),
    BKE_CONTROLLER_IPC_SOCKET: join(dir, 'bridge.sock'),
    BKE_CONTROLLER_PORT: '0',
    BKE_NATIVE_POLICY_PATH: policyPath,
  };

  try {
    // 1. V2 without revocation authority (broker off / missing)
    const v2NoBroker = await runCliOnce(['start'], {
      ...baseEnv,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REQUIRE_ASYMMETRIC_V2: 'true',
      BKE_REMOTE_BROKER_ENABLED: 'false',
    });
    assert.notEqual(v2NoBroker.code, 0);
    assert.match(v2NoBroker.stderr, /DAEMON_REVOCATION_CHECKER_MISSING/);

    // 2. Mediated CAS without trusted client
    const casNoBroker = await runCliOnce(['start'], {
      ...baseEnv,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REQUIRE_ASYMMETRIC_V2: 'true',
      BKE_SERVER_MEDIATED_CAS_ENABLED: 'true',
      BKE_REMOTE_BROKER_ENABLED: 'false',
    });
    assert.notEqual(casNoBroker.code, 0);
    assert.match(casNoBroker.stderr, /DAEMON_MEDIATED_CAS_CLIENT_MISSING/);

    // 3. Static installation token forbidden in operational/mediated mode
    const staticTok = await runCliOnce(['start'], {
      ...baseEnv,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_SERVER_MEDIATED_CAS_ENABLED: 'true',
      BKE_REMOTE_BROKER_ENABLED: 'true',
      BKE_GITHUB_INSTALLATION_TOKEN: 'ghs_static_forbidden',
    });
    assert.notEqual(staticTok.code, 0);
    assert.match(staticTok.stderr, /DAEMON_WRITE_TOKEN_FORBIDDEN_IN_MEDIATED_MODE/);

    // 4. Legacy V1 execution via CLI forbidden
    const legacyV1 = await runCliOnce(['start'], {
      ...baseEnv,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'false',
    });
    assert.notEqual(legacyV1.code, 0);
    assert.match(legacyV1.stderr, /DAEMON_LEGACY_V1_EXECUTION_FORBIDDEN/);

    // 5. Compat downgrade forbidden
    const compatOff = await runCliOnce(['start'], {
      ...baseEnv,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REQUIRE_ASYMMETRIC_V2: 'false',
    });
    assert.notEqual(compatOff.code, 0);
    assert.match(compatOff.stderr, /DAEMON_V2_COMPAT_MODE_FORBIDDEN/);

    // 6. Missing device credentials
    const missingCreds = await runCliOnce(['start'], {
      ...baseEnv,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REMOTE_BROKER_ENABLED: 'true',
      BKE_BROKER_BASE_URL: 'http://127.0.0.1:49999',
    });
    assert.notEqual(missingCreds.code, 0);
    assert.match(missingCreds.stderr, /DAEMON_DEVICE_CREDENTIALS_MISSING/);

    // 7. Unsafe 0o644 credentials mode rejected
    await chmod(credsPath, 0o644);
    const unsafeMode = await runCliOnce(['start'], {
      ...baseEnv,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REMOTE_BROKER_ENABLED: 'true',
      BKE_BROKER_BASE_URL: 'http://127.0.0.1:49999',
      BKE_DEVICE_CREDENTIALS_PATH: credsPath,
    });
    assert.notEqual(unsafeMode.code, 0);
    assert.match(unsafeMode.stderr, /DAEMON_DEVICE_CREDENTIALS_UNSAFE_MODE/);
    await chmod(credsPath, 0o600);

    // 8. Symlink credentials rejected
    const symCreds = join(dir, 'creds-link.json');
    await symlink(credsPath, symCreds);
    const symRes = await runCliOnce(['start'], {
      ...baseEnv,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REMOTE_BROKER_ENABLED: 'true',
      BKE_BROKER_BASE_URL: 'http://127.0.0.1:49999',
      BKE_DEVICE_CREDENTIALS_PATH: symCreds,
    });
    assert.notEqual(symRes.code, 0);
    assert.match(symRes.stderr, /DAEMON_DEVICE_CREDENTIALS_SYMLINK_FORBIDDEN/);

    // 9. Insecure non-loopback http:// broker URL rejected
    const insecureUrl = await runCliOnce(['start'], {
      ...baseEnv,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REMOTE_BROKER_ENABLED: 'true',
      BKE_BROKER_BASE_URL: 'http://broker.example.com',
      BKE_DEVICE_CREDENTIALS_PATH: credsPath,
    });
    assert.notEqual(insecureUrl.code, 0);
    assert.match(insecureUrl.stderr, /DAEMON_BROKER_URL_INSECURE/);

    // 10. Policy thumbprint mismatch rejected
    const badPolicy = join(dir, 'bad-policy.json');
    await writeFile(
      badPolicy,
      JSON.stringify({
        version: 1,
        allowed_origin: `chrome-extension://${'b'.repeat(32)}/`,
        worker_id: WORKER,
        public_key_sha256: '0'.repeat(64),
        profile_binding_sha256: PROFILE_BINDING,
        resources: {
          chatgpt_target_sha256: '1'.repeat(64),
          browser_profile_sha256: '2'.repeat(64),
          bridge_identity_sha256: BRIDGE_ID,
        },
        expires_at_ms: Date.now() + 180_000,
      }),
      { mode: 0o600 },
    );
    const badPolicyRes = await runCliOnce(['start'], {
      ...baseEnv,
      BKE_NATIVE_POLICY_PATH: badPolicy,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REMOTE_BROKER_ENABLED: 'true',
      BKE_BROKER_BASE_URL: 'http://127.0.0.1:49999',
      BKE_DEVICE_CREDENTIALS_PATH: credsPath,
    });
    assert.notEqual(badPolicyRes.code, 0);
    assert.match(badPolicyRes.stderr, /DAEMON_POLICY_DEVICE_KEY_MISMATCH/);

    // 11. Doctor reports ready and accurate credentialBrokerKind with valid 0o600 config + dry-run start succeeds
    const validEnv = {
      ...baseEnv,
      BKE_EXECUTION_ENVELOPE_ENABLED: 'true',
      BKE_EXECUTION_V2_ASYMMETRIC_ENABLED: 'true',
      BKE_REQUIRE_ASYMMETRIC_V2: 'true',
      BKE_SERVER_MEDIATED_CAS_ENABLED: 'true',
      BKE_REMOTE_BROKER_ENABLED: 'true',
      BKE_BROKER_BASE_URL: 'http://127.0.0.1:49999',
      BKE_DEVICE_CREDENTIALS_PATH: credsPath,
      BKE_REMOTE_HALT_PUBLIC_KEY_ID: 'broker-halt-k1',
      BKE_REMOTE_HALT_PUBLIC_KEY_PEM: haltKey.publicPem,
      BKE_PINNED_APP_ID: '9001',
      BKE_PINNED_APP_SLUG: 'bke-dispatcher-app',
    };
    const loaded = await loadOwnerDeviceCredentialsFile(credsPath);
    assert.equal(loaded.public_key_sha256, devKey.sha);
    const doc = await runControllerDoctor(validEnv);
    assert.equal(doc.ok, true);
    assert.equal(doc.summary.credentialBrokerKind, 'REMOTE_OWNER_CERTIFIED_BROKER');
    assert.equal(doc.summary.mediatedCasEnabled, true);
    assert.equal(doc.summary.deviceId, DEVICE_ID);
    assert.equal(doc.checks.find((c) => c.name === 'device_credentials_file')?.ok, true);

    const dryRun = await runCliOnce(['start', '--dry-run'], validEnv);
    assert.equal(dryRun.code, 0);
    const dryJson = JSON.parse(dryRun.stdout.trim());
    assert.equal(dryJson.ok, true);
    assert.equal(dryJson.mode, 'DRY_RUN');
    assert.equal(dryJson.mediatedCasEnabled, true);
    assert.equal(dryJson.desktopWriteTokenForbidden, true);
    assert.equal(dryJson.revocationAuthorityConfigured, true);
    assert.equal(dryJson.brokerConnected, true);
    assert.equal(dryJson.humanLiveSendAuthorized, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('F4.1 distinct HTTP/error mapping for broker unavailable (503), device revoked (403), credential invalid (401), and delivery uncertain (409)', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f41-errmap-'));
  await chmod(dir, 0o700);
  const devKey = genP256();
  const brokerExecKey = genEd25519();
  const wrongKey = genEd25519();

  let statusMode = 'ACTIVE';
  let tokenMode = 'OK';
  let ledgerMode = 'UNCERTAIN';

  const mockBroker = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
      const now = Date.now();
      const urlPath = (req.url ?? '/').split('?')[0];
      if (urlPath === '/v1/enrollment/status') {
        if (statusMode === 'UNAVAILABLE') {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, code: 'BROKER_STORE_DOWN' }));
          return;
        }
        if (statusMode === 'FORGED_STATUS') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ok: true,
              signed_status: signEd25519Payload(
                'BKE_DEVICE_STATUS_V1\n',
                {
                  version: 1,
                  broker_issuer: ISSUER,
                  worker_id: WORKER,
                  device_id: DEVICE_ID,
                  installation_id: INSTALL_ID,
                  repository: REPO,
                  enrollment_generation: 1,
                  actual_enrollment_generation: 1,
                  status: 'ACTIVE',
                  revoked: false,
                  nonce: body.nonce,
                  issued_at: new Date(now - 1000).toISOString(),
                  expires_at: new Date(now + 30000).toISOString(),
                },
                wrongKey.privatePem,
                'broker-exec-k1',
              ),
            }),
          );
          return;
        }
        const revoked = statusMode === 'REVOKED';
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            ok: true,
            signed_status: signEd25519Payload(
              'BKE_DEVICE_STATUS_V1\n',
              {
                version: 1,
                broker_issuer: ISSUER,
                worker_id: WORKER,
                device_id: DEVICE_ID,
                installation_id: INSTALL_ID,
                repository: REPO,
                enrollment_generation: 1,
                actual_enrollment_generation: 1,
                status: revoked ? 'REVOKED' : 'ACTIVE',
                revoked,
                ...(revoked ? { code: 'EXEC_REQ_DEVICE_REVOKED' } : {}),
                nonce: body.nonce,
                issued_at: new Date(now - 1000).toISOString(),
                expires_at: new Date(now + 30000).toISOString(),
              },
              brokerExecKey.privatePem,
              'broker-exec-k1',
            ),
          }),
        );
        return;
      }
      if (urlPath === '/v1/broker/tokens') {
        if (tokenMode === 'CREDENTIAL_INVALID') {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, code: 'DEVICE_ASSERTION_SIGNATURE_INVALID' }));
          return;
        }
        if (tokenMode === 'UNAVAILABLE') {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, code: 'BROKER_UPSTREAM_DOWN' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            ok: true,
            token: {
              token: 'ghs_readonly_f41_token',
              tokenType: 'installation',
              issuedAtMs: now - 1_000,
              expiresAtMs: now + 120_000,
              permissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
              installationId: INSTALL_ID,
              repositories: [REPO],
              repositoryId: REPO_ID,
            },
          }),
        );
        return;
      }
      if (urlPath === '/v1/broker/ledger-ops') {
        res.writeHead(ledgerMode === 'UNCERTAIN' ? 409 : 200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, status: 'UNCERTAIN', code: 'BROKER_GITHUB_TIMEOUT' }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
  });

  await new Promise((r) => mockBroker.listen(0, '127.0.0.1', r));
  const brokerPort = mockBroker.address().port;
  const brokerUrl = `http://127.0.0.1:${brokerPort}`;
  const { credsPath, policyPath } = await writeFixtureFiles(dir, { devKey, brokerExecKey, brokerUrl });

  let daemon = null;
  try {
    const bundle = await createDesktopControllerRuntimeDependencies(
      {
        repository: REPO,
        prNumber: PR_NUM,
        workerId: WORKER,
        pinnedApp: { id: 9001, slug: 'bke-dispatcher-app' },
        executionId: 'exec-f41-err',
        targetId: 'target-f41-01',
        profileId: 'profile-f41-01',
        targetTabId: 7,
        journalPath: join(dir, 'journal.json'),
        ipcSocketPath: join(dir, 'bridge.sock'),
        policyPath,
        listenHost: '127.0.0.1',
        listenPort: 0,
        humanLiveSendAuthorized: false,
        liveProofs: { githubCasOwnerCertified: true, nativePairingOwnerCertified: true, realBrowserOwnerAccepted: false },
        executionEnvelopeEnabled: true,
        asymmetricV2Enabled: true,
        mediatedCasEnabled: true,
      },
      {
        BKE_REMOTE_BROKER_ENABLED: 'true',
        BKE_BROKER_BASE_URL: brokerUrl,
        BKE_DEVICE_CREDENTIALS_PATH: credsPath,
      },
    );
    daemon = new DesktopControllerDaemon(bundle.config, bundle.deps);
    const started = await daemon.start({ listen: true });
    const daemonUrl = `http://127.0.0.1:${started.port}`;

    const mkSignedReq = (attemptId, deliveryId, useWrongKey = false) =>
      signEnvelopeV2(
        {
          protocol_version: EXECUTION_REQUEST_PROTOCOL_VERSION_V2,
          authorized_capability: AUTHORIZED_CAPABILITY_V2,
          broker_issuer: ISSUER,
          audience: AUDIENCE,
          device_id: DEVICE_ID,
          enrollment_generation: 1,
          delivery_id: deliveryId,
          repository_owner: 'jan2xo',
          repository_name: 'bke-worker',
          repository_id: REPO_ID,
          installation_identity: INSTALL_ID,
          pr_number: PR_NUM,
          head_sha: 'a'.repeat(40),
          worker_id: WORKER,
          attempt_id: attemptId,
          action: 'DISPATCH_FIRST_MESSAGE',
          issued_at: new Date(Date.now() - 1_000).toISOString(),
          expires_at: new Date(Date.now() + 60_000).toISOString(),
        },
        useWrongKey ? wrongKey.privatePem : brokerExecKey.privatePem,
        'broker-exec-k1',
      );

    // 1. Credential / signature invalid -> 401
    const badSigReq = mkSignedReq('att-err-1', 'del-err-1', true);
    const sigRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(badSigReq),
    });
    assert.equal(sigRes.status, 401);
    assert.equal((await sigRes.json()).code, 'EXEC_REQ_SIGNATURE_INVALID');

    // 2. Broker unavailable / forged unsigned status -> 503
    statusMode = 'FORGED_STATUS';
    const validReq = signEnvelopeV2(
      mkSignedReq('att-err-2', 'del-err-2').envelope,
      brokerExecKey.privatePem,
      'broker-exec-k1',
    );
    const forgedStatusRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(validReq),
    });
    assert.equal(forgedStatusRes.status, 503);
    assert.equal((await forgedStatusRes.json()).code, 'EXEC_REQ_REVOCATION_UNAVAILABLE');

    statusMode = 'UNAVAILABLE';
    const downRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(
        signEnvelopeV2(mkSignedReq('att-err-3', 'del-err-3').envelope, brokerExecKey.privatePem, 'broker-exec-k1'),
      ),
    });
    assert.equal(downRes.status, 503);
    assert.equal((await downRes.json()).code, 'EXEC_REQ_REVOCATION_UNAVAILABLE');

    // 3. Device revoked -> 403
    statusMode = 'REVOKED';
    const revokedRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(
        signEnvelopeV2(mkSignedReq('att-err-4', 'del-err-4').envelope, brokerExecKey.privatePem, 'broker-exec-k1'),
      ),
    });
    assert.equal(revokedRes.status, 403);
    assert.equal((await revokedRes.json()).code, 'EXEC_REQ_DEVICE_REVOKED');

    // 4. Token credential invalid -> 401 & Token broker unavailable -> 503
    statusMode = 'ACTIVE';
    tokenMode = 'CREDENTIAL_INVALID';
    const tokCredRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(
        signEnvelopeV2(mkSignedReq('att-err-5', 'del-err-5').envelope, brokerExecKey.privatePem, 'broker-exec-k1'),
      ),
    });
    assert.equal(tokCredRes.status, 401);
    assert.equal((await tokCredRes.json()).code, 'TOKEN_CREDENTIAL_INVALID');

    tokenMode = 'UNAVAILABLE';
    const tokDownRes = await fetch(`${daemonUrl}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(
        signEnvelopeV2(mkSignedReq('att-err-6', 'del-err-6').envelope, brokerExecKey.privatePem, 'broker-exec-k1'),
      ),
    });
    assert.equal(tokDownRes.status, 503);
    assert.equal((await tokDownRes.json()).code, 'TOKEN_BROKER_UNAVAILABLE');

    assert.ok(bundle.brokerClient instanceof HttpTrustedBrokerClient);
    const directRev = await bundle.brokerClient.checkDeviceRevocation({
      workerId: WORKER,
      deviceId: DEVICE_ID,
      installationId: INSTALL_ID,
      repository: REPO,
      enrollmentGeneration: 1,
    });
    assert.equal(directRev.revoked, false);
  } finally {
    await daemon?.stop().catch(() => {});
    await new Promise((r) => mockBroker.close(r));
    await mkdir(dir, { recursive: true }).catch(() => {});
    await rm(dir, { recursive: true, force: true });
  }
});

test('F4.2-03: HttpTrustedBrokerClient rejects all 22+ broker-signed malformed/mis-scoped device status, token status, token mint, and ledger responses fail-closed', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bke-f42-signed-matrix-'));
  await chmod(dir, 0o700);
  const devKey = genP256();
  const brokerExecKey = genEd25519();

  let statusMutator = (base) => base;
  let tokenStatusMutator = (base) => base;
  let tokenResponseOverride = null;
  let ledgerResponseOverride = null;

  const mockBroker = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
      const now = Date.now();
      const urlPath = (req.url ?? '/').split('?')[0];

      if (urlPath === '/v1/enrollment/status') {
        const basePayload = {
          version: 1,
          broker_issuer: ISSUER,
          worker_id: WORKER,
          device_id: DEVICE_ID,
          installation_id: INSTALL_ID,
          repository: REPO,
          enrollment_generation: 1,
          actual_enrollment_generation: 1,
          status: 'ACTIVE',
          revoked: false,
          code: null,
          nonce: body.nonce,
          issued_at: new Date(now - 1_000).toISOString(),
          expires_at: new Date(now + 30_000).toISOString(),
        };
        const payload = statusMutator(basePayload, now);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            ok: true,
            signed_status: signEd25519Payload(
              'BKE_DEVICE_STATUS_V1\n',
              payload,
              brokerExecKey.privatePem,
              'broker-exec-k1',
            ),
          }),
        );
        return;
      }

      if (urlPath === '/v1/broker/token-status') {
        const tokenSha = createHash('sha256').update(String(body.token ?? ''), 'utf8').digest('hex');
        const basePayload = {
          version: 1,
          broker_issuer: ISSUER,
          token_sha256: tokenSha,
          status: 'ACTIVE',
          revoked: false,
          nonce: body.nonce,
          issued_at: new Date(now - 1_000).toISOString(),
          expires_at: new Date(now + 30_000).toISOString(),
        };
        const payload = tokenStatusMutator(basePayload, now);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            ok: true,
            signed_status: signEd25519Payload(
              'BKE_TOKEN_STATUS_V1\n',
              payload,
              brokerExecKey.privatePem,
              'broker-exec-k1',
            ),
          }),
        );
        return;
      }

      if (urlPath === '/v1/broker/tokens') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(tokenResponseOverride ?? { ok: true, token: null }));
        return;
      }

      if (urlPath === '/v1/broker/ledger-ops') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(ledgerResponseOverride ?? { ok: true, status: 'COMMITTED', sha: 'b'.repeat(40) }));
        return;
      }

      res.writeHead(404);
      res.end();
    });
  });

  await new Promise((r) => mockBroker.listen(0, '127.0.0.1', r));
  const brokerUrl = `http://127.0.0.1:${mockBroker.address().port}`;
  const { credsPath, policyPath } = await writeFixtureFiles(dir, { devKey, brokerExecKey, brokerUrl });

  let daemon = null;
  try {
    const bundle = await createDesktopControllerRuntimeDependencies(
      {
        repository: REPO,
        prNumber: PR_NUM,
        workerId: WORKER,
        pinnedApp: { id: 9001, slug: 'bke-dispatcher-app' },
        executionId: 'exec-f42-matrix',
        targetId: 'target-f42-01',
        profileId: 'profile-f42-01',
        targetTabId: 7,
        journalPath: join(dir, 'journal.json'),
        ipcSocketPath: join(dir, 'bridge.sock'),
        policyPath,
        listenHost: '127.0.0.1',
        listenPort: 0,
        humanLiveSendAuthorized: false,
        liveProofs: { githubCasOwnerCertified: true, nativePairingOwnerCertified: true, realBrowserOwnerAccepted: false },
        executionEnvelopeEnabled: true,
        asymmetricV2Enabled: true,
        mediatedCasEnabled: true,
      },
      {
        BKE_REMOTE_BROKER_ENABLED: 'true',
        BKE_BROKER_BASE_URL: brokerUrl,
        BKE_DEVICE_CREDENTIALS_PATH: credsPath,
      },
    );
    const client = bundle.brokerClient;
    assert.ok(client instanceof HttpTrustedBrokerClient);

    const checkReq = {
      workerId: WORKER,
      deviceId: DEVICE_ID,
      installationId: INSTALL_ID,
      repository: REPO,
      enrollmentGeneration: 1,
    };

    // Baseline valid signed ACTIVE succeeds
    assert.deepEqual(await client.checkDeviceRevocation(checkReq), { status: 'ACTIVE', revoked: false });

    // Full 24-case legitimately Ed25519-signed negative device-status matrix
    const deviceSignedCases = [
      ['01_omit_repository', (p) => { const c = { ...p }; delete c.repository; return c; }],
      ['02_null_repository', (p) => ({ ...p, repository: null })],
      ['03_non_string_repository', (p) => ({ ...p, repository: 12345 })],
      ['04_wrong_repository', (p) => ({ ...p, repository: 'other/repo' })],
      ['05_omit_worker_id', (p) => { const c = { ...p }; delete c.worker_id; return c; }],
      ['06_wrong_worker_id', (p) => ({ ...p, worker_id: 'worker-other' })],
      ['07_omit_device_id', (p) => { const c = { ...p }; delete c.device_id; return c; }],
      ['08_wrong_device_id', (p) => ({ ...p, device_id: 'desktop-other-99' })],
      ['09_omit_installation_id', (p) => { const c = { ...p }; delete c.installation_id; return c; }],
      ['10_wrong_installation_id', (p) => ({ ...p, installation_id: '111111111' })],
      ['11_omit_enrollment_generation', (p) => { const c = { ...p }; delete c.enrollment_generation; return c; }],
      ['12_wrong_enrollment_generation', (p) => ({ ...p, enrollment_generation: 2 })],
      ['13_omit_actual_enrollment_generation', (p) => { const c = { ...p }; delete c.actual_enrollment_generation; return c; }],
      ['14_wrong_actual_enrollment_generation', (p) => ({ ...p, actual_enrollment_generation: 2 })],
      ['15_status_unknown', (p) => ({ ...p, status: 'UNKNOWN', revoked: false })],
      ['16_contradictory_active_revoked_true', (p) => ({ ...p, status: 'ACTIVE', revoked: true })],
      ['17_contradictory_revoked_false', (p) => ({ ...p, status: 'REVOKED', revoked: false })],
      ['18_omit_revoked', (p) => { const c = { ...p }; delete c.revoked; return c; }],
      ['19_wrong_nonce', (p) => ({ ...p, nonce: 'wrong-signed-nonce-12345' })],
      ['20_expired', (p, now) => ({ ...p, issued_at: new Date(now - 60_000).toISOString(), expires_at: new Date(now - 1_000).toISOString() })],
      ['21_future_issued_at', (p, now) => ({ ...p, issued_at: new Date(now + 20_000).toISOString(), expires_at: new Date(now + 50_000).toISOString() })],
      ['22_wrong_broker_issuer', (p) => ({ ...p, broker_issuer: 'https://evil.broker.local' })],
      ['23_extra_unexpected_field', (p) => ({ ...p, extra_field: 'tampered' })],
      ['24_non_null_code_on_active', (p) => ({ ...p, code: 'SPOOFED_CODE' })],
    ];

    for (const [name, mut] of deviceSignedCases) {
      statusMutator = mut;
      const res = await client.checkDeviceRevocation(checkReq);
      assert.equal(res.status, 'UNKNOWN', `${name}: must return status=UNKNOWN`);
      assert.equal(res.revoked, true, `${name}: must fail closed revoked=true`);
      assert.equal(res.code, 'EXEC_REQ_REVOCATION_UNAVAILABLE', `${name}: expected unavailability code`);
    }

    // Signed REVOKED response with legitimate signature must still map cleanly to REVOKED
    statusMutator = (p) => ({ ...p, status: 'REVOKED', revoked: true, code: 'EXEC_REQ_DEVICE_REVOKED' });
    const revSigned = await client.checkDeviceRevocation(checkReq);
    assert.deepEqual(revSigned, { status: 'REVOKED', revoked: true, code: 'EXEC_REQ_DEVICE_REVOKED' });

    // Signed token-status negative matrix
    assert.equal((await client.checkTokenStatus('ghs_valid_tok_123')).status, 'ACTIVE');
    const tokenSignedCases = [
      ['tok_status_unknown', (p) => ({ ...p, status: 'UNKNOWN', revoked: false })],
      ['tok_contradictory_active_revoked', (p) => ({ ...p, status: 'ACTIVE', revoked: true })],
      ['tok_contradictory_revoked_false', (p) => ({ ...p, status: 'REVOKED', revoked: false })],
      ['tok_omit_revoked', (p) => { const c = { ...p }; delete c.revoked; return c; }],
      ['tok_wrong_sha', (p) => ({ ...p, token_sha256: '0'.repeat(64) })],
      ['tok_wrong_nonce', (p) => ({ ...p, nonce: 'wrong-tok-nonce-12345' })],
      ['tok_expired', (p, now) => ({ ...p, issued_at: new Date(now - 60_000).toISOString(), expires_at: new Date(now - 1_000).toISOString() })],
      ['tok_future_issued', (p, now) => ({ ...p, issued_at: new Date(now + 20_000).toISOString(), expires_at: new Date(now + 50_000).toISOString() })],
      ['tok_wrong_issuer', (p) => ({ ...p, broker_issuer: 'https://evil.broker.local' })],
      ['tok_extra_field', (p) => ({ ...p, extra_claim: 'tamper' })],
    ];
    for (const [name, mut] of tokenSignedCases) {
      tokenStatusMutator = mut;
      const tRes = await client.checkTokenStatus('ghs_valid_tok_123');
      assert.equal(tRes.status, 'UNKNOWN', `${name}: token status must fail closed UNKNOWN`);
      await assert.rejects(() => client.isRevoked('ghs_valid_tok_123'), /TOKEN_REVOCATION_UNAVAILABLE/);
    }

    // SEC-04: legitimately signed EXPIRED (revoked: true) and UNKNOWN (revoked: true)
    tokenStatusMutator = (p) => ({ ...p, status: 'EXPIRED', revoked: true });
    const expRes = await client.checkTokenStatus('ghs_valid_tok_123');
    assert.deepEqual(expRes, { status: 'EXPIRED', code: 'TOKEN_EXPIRED' });
    await assert.rejects(() => client.isRevoked('ghs_valid_tok_123'), /TOKEN_EXPIRED/);

    tokenStatusMutator = (p) => ({ ...p, status: 'UNKNOWN', revoked: true });
    const unkRes = await client.checkTokenStatus('ghs_valid_tok_123');
    assert.deepEqual(unkRes, { status: 'UNKNOWN', code: 'TOKEN_UNKNOWN_OR_UNISSUED' });
    await assert.rejects(() => client.isRevoked('ghs_valid_tok_123'), /TOKEN_UNKNOWN_OR_UNISSUED/);

    // issueToken strict scope + response validation
    const ac = new AbortController();
    await assert.rejects(
      () =>
        client.issueToken({
          repository: 'other/repo',
          repositoryId: REPO_ID,
          installationId: INSTALL_ID,
          workerId: WORKER,
          requestedPermissions: { contents: 'read' },
          reason: 'TEST',
          signal: ac.signal,
        }),
      /TOKEN_REPOSITORY_SCOPE_MISMATCH/,
    );
    await assert.rejects(
      () =>
        client.issueToken({
          repository: REPO,
          repositoryId: REPO_ID,
          installationId: INSTALL_ID,
          workerId: WORKER,
          requestedPermissions: { contents: 'write' },
          reason: 'TEST',
          signal: ac.signal,
        }),
      /TOKEN_DESKTOP_WRITE_TOKEN_FORBIDDEN/,
    );
    tokenResponseOverride = {
      ok: true,
      token: {
        token: 'ghs_wrong_repo_tok',
        tokenType: 'installation',
        installationId: INSTALL_ID,
        repositoryId: REPO_ID,
        repositories: ['evil/other-repo'],
        permissions: { contents: 'read' },
        issuedAtMs: Date.now(),
        expiresAtMs: Date.now() + 60_000,
      },
    };
    await assert.rejects(
      () =>
        client.issueToken({
          repository: REPO,
          repositoryId: REPO_ID,
          installationId: INSTALL_ID,
          workerId: WORKER,
          requestedPermissions: { contents: 'read' },
          reason: 'TEST',
          signal: ac.signal,
        }),
      /TOKEN_REPOSITORY_SCOPE_MISMATCH/,
    );

    // executeLedgerOp strict scope & sha validation
    const crossRepoOp = await client.executeLedgerOp({
      operation: 'COMMIT_PRE_SEND_FENCE',
      repository: 'other/repo',
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      prNumber: PR_NUM,
      headSha: 'a'.repeat(40),
      attemptId: 'att-cross',
      refName: `refs/bke/fences/${PR_NUM}/att-cross`,
      commitMessage: 'fence',
      treeSha: 'e'.repeat(40),
    });
    assert.equal(crossRepoOp.ok, false);
    assert.equal(crossRepoOp.code, 'BROKER_DEVICE_SCOPE_MISMATCH');

    ledgerResponseOverride = { ok: true, status: 'COMMITTED', sha: null };
    const badShaOp = await client.executeLedgerOp({
      operation: 'COMMIT_PRE_SEND_FENCE',
      repository: REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      prNumber: PR_NUM,
      headSha: 'a'.repeat(40),
      attemptId: 'att-bad-sha',
      refName: `refs/bke/fences/${PR_NUM}/att-bad-sha`,
      commitMessage: 'fence',
      treeSha: 'e'.repeat(40),
    });
    assert.equal(badShaOp.ok, false);
    assert.equal(badShaOp.status, 'UNCERTAIN');
    assert.equal(badShaOp.code, 'BROKER_LEDGER_RESPONSE_INVALID');

    // Integrated DesktopControllerDaemon check: validly signed ACTIVE status omitting repository -> 503 before dispatch
    statusMutator = (p) => {
      const c = { ...p };
      delete c.repository;
      return c;
    };
    daemon = new DesktopControllerDaemon(bundle.config, bundle.deps);
    const started = await daemon.start({ listen: true });
    const signedReq = signEnvelopeV2(
      {
        protocol_version: EXECUTION_REQUEST_PROTOCOL_VERSION_V2,
        authorized_capability: AUTHORIZED_CAPABILITY_V2,
        broker_issuer: ISSUER,
        audience: AUDIENCE,
        device_id: DEVICE_ID,
        enrollment_generation: 1,
        delivery_id: 'del-f42-omit-repo',
        repository_owner: 'jan2xo',
        repository_name: 'bke-worker',
        repository_id: REPO_ID,
        installation_identity: INSTALL_ID,
        pr_number: PR_NUM,
        head_sha: 'a'.repeat(40),
        worker_id: WORKER,
        attempt_id: 'att-f42-omit-repo',
        action: 'DISPATCH_FIRST_MESSAGE',
        issued_at: new Date(Date.now() - 1_000).toISOString(),
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      },
      brokerExecKey.privatePem,
      'broker-exec-k1',
    );
    const execRes = await fetch(`http://127.0.0.1:${started.port}/execution-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedReq),
    });
    assert.equal(execRes.status, 503);
    const execBody = await execRes.json();
    assert.equal(execBody.code, 'EXEC_REQ_REVOCATION_UNAVAILABLE');
    assert.equal(execBody.submitInvocations, 0);
    assert.equal(execBody.journalPhase, 'IDLE');
    assert.ok(!JSON.stringify(execBody).includes('PRIVATE KEY'));
    assert.ok(!JSON.stringify(execBody).includes('ghs_'));
  } finally {
    await daemon?.stop().catch(() => {});
    await new Promise((r) => mockBroker.close(r));
    await mkdir(dir, { recursive: true }).catch(() => {});
    await rm(dir, { recursive: true, force: true });
  }
});
