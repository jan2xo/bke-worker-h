/**
 * F3-03 / F3-04 Sandbox Loopback HTTP Broker Server & CLI.
 *
 * SANDBOX ONLY — never deployed to Cloudflare, binds strictly to loopback (127.0.0.1).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DeviceEnrollmentRegistry } from './device-enrollment.js';
import { SandboxGitHubAppAdapter } from './github-app-adapter.js';
import { TrustedDesktopBroker } from './broker-service.js';

const MAX_BODY_BYTES = 262_144;

function sendJson(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(body) + '\n');
}

function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolveBody, rejectBody) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > MAX_BODY_BYTES) {
        rejectBody(Error('BROKER_BODY_TOO_LARGE'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        const parsed = raw ? JSON.parse(raw) : {};
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          rejectBody(Error('BROKER_JSON_INVALID'));
          return;
        }
        resolveBody(parsed as Record<string, unknown>);
      } catch {
        rejectBody(Error('BROKER_JSON_INVALID'));
      }
    });
    req.on('error', rejectBody);
  });
}

function mapErrorStatus(code: string): number {
  if (
    code.includes('UNAUTHORIZED') ||
    code.includes('SIGNATURE_INVALID') ||
    code.includes('ADMIN_') ||
    code.includes('DEVICE_') ||
    code.includes('REVOKED') ||
    code.includes('FORBIDDEN') ||
    code.includes('ESCALAT') ||
    code.includes('MISMATCH')
  ) {
    return 403;
  }
  if (
    code.includes('INVALID') ||
    code.includes('EXPIRED') ||
    code.includes('REPLAY') ||
    code.includes('UNKNOWN') ||
    code.includes('WRONG_') ||
    code.includes('DUPLICATE')
  ) {
    return 400;
  }
  if (code.includes('CONFLICT') || code.includes('QUARANTINED') || code.includes('CONSUMED')) {
    return 409;
  }
  if (code.includes('TIMEOUT') || code.includes('UNAVAILABLE')) {
    return 503;
  }
  return 409;
}

export class SandboxBrokerHttpServer {
  private server: Server | null = null;
  private actualPort: number | null = null;

  constructor(
    private readonly broker: TrustedDesktopBroker,
    private readonly enrollment: DeviceEnrollmentRegistry,
    private readonly listenPort = 0,
  ) {}

  getPort(): number | null {
    return this.actualPort;
  }

  async start(): Promise<{ port: number }> {
    await this.broker.initialize();
    this.server = createServer((req, res) => {
      void this.handle(req, res);
    });
    await new Promise<void>((resolveListen, rejectListen) => {
      this.server!.once('error', rejectListen);
      this.server!.listen(this.listenPort, '127.0.0.1', () => {
        const addr = this.server!.address();
        this.actualPort = addr && typeof addr === 'object' ? addr.port : null;
        resolveListen();
      });
    });
    return { port: this.actualPort! };
  }

  async stop(): Promise<void> {
    if (this.server) {
      const s = this.server;
      this.server = null;
      this.actualPort = null;
      s.closeAllConnections?.();
      await new Promise<void>((resolveClose) => s.close(() => resolveClose()));
    }
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const addr = req.socket?.remoteAddress;
    if (addr && addr !== '127.0.0.1' && addr !== '::1' && addr !== '::ffff:127.0.0.1') {
      sendJson(res, 403, { ok: false, code: 'BROKER_NON_LOOPBACK_FORBIDDEN' });
      return;
    }

    const method = req.method ?? 'GET';
    const path = (req.url ?? '/').split('?')[0] ?? '/';

    try {
      if (method === 'GET' && path === '/healthz') {
        const keys = await this.broker.getPublicVerificationKeys();
        sendJson(res, 200, {
          ok: true,
          component: 'bke-sandbox-desktop-broker',
          issuer: keys.issuer,
          activeExecutionKeyId: keys.activeExecutionKeyId,
          activeHaltKeyId: keys.activeHaltKeyId,
        });
        return;
      }
      if (method === 'GET' && path === '/v1/public-keys') {
        const keys = await this.broker.getPublicVerificationKeys();
        sendJson(res, 200, { ok: true, ...keys });
        return;
      }
      if (method === 'GET' && path === '/v1/broker/audit') {
        const audit = await this.broker.getAuditLog();
        sendJson(res, 200, { ok: true, events: audit });
        return;
      }
      if (method !== 'POST') {
        sendJson(res, 404, { ok: false, code: 'NOT_FOUND' });
        return;
      }

      const body = await readJsonBody(req);

      if (path === '/v1/enrollment/challenge') {
        const ch = await this.enrollment.issueChallenge(body as never);
        sendJson(res, 200, { ok: true, challenge: ch });
        return;
      }
      if (path === '/v1/enrollment/complete') {
        const rec = await this.enrollment.completeEnrollment(body as never);
        sendJson(res, 200, { ok: true, device: rec });
        return;
      }
      if (path === '/v1/enrollment/rotate') {
        const rec = await this.enrollment.rotateDeviceKey(body as never);
        sendJson(res, 200, { ok: true, device: rec });
        return;
      }
      if (path === '/v1/enrollment/revoke') {
        const rec = await this.enrollment.revokeDevice(body as never);
        sendJson(res, 200, { ok: true, device: rec });
        return;
      }
      if (path === '/v1/enrollment/status') {
        const rawWorker = body.workerId ?? body.worker_id;
        if (typeof rawWorker !== 'string' || !rawWorker) {
          throw Error('BROKER_STATUS_PARAMS_INVALID');
        }
        const rawDevice = body.deviceId ?? body.device_id;
        if (rawDevice !== undefined && typeof rawDevice !== 'string') {
          throw Error('BROKER_STATUS_PARAMS_INVALID');
        }
        const rawInstall = body.installationId ?? body.installation_id;
        if (rawInstall !== undefined && typeof rawInstall !== 'string') {
          throw Error('BROKER_STATUS_PARAMS_INVALID');
        }
        if (body.repository !== undefined && typeof body.repository !== 'string') {
          throw Error('BROKER_STATUS_PARAMS_INVALID');
        }
        const rawGen = body.enrollmentGeneration ?? body.min_generation ?? body.enrollment_generation;
        if (rawGen !== undefined && (typeof rawGen !== 'number' || !Number.isSafeInteger(rawGen))) {
          throw Error('BROKER_STATUS_PARAMS_INVALID');
        }
        if (typeof body.nonce !== 'string' || !body.nonce) {
          throw Error('BROKER_STATUS_NONCE_INVALID');
        }
        const signedStatus = await this.broker.getSignedDeviceStatus({
          workerId: rawWorker,
          deviceId: rawDevice,
          installationId: rawInstall,
          repository: body.repository,
          enrollmentGeneration: rawGen,
          nonce: body.nonce,
        });
        sendJson(res, 200, {
          ok: true,
          status: signedStatus.payload.status,
          revoked: signedStatus.payload.revoked,
          code: signedStatus.payload.code,
          enrollment_generation: signedStatus.payload.actual_enrollment_generation,
          signed_status: signedStatus,
        });
        return;
      }
      if (path === '/v1/broker/authorize') {
        const signed = await this.broker.authorizeExecution(body as never);
        sendJson(res, 200, { ok: true, signed_request: signed });
        return;
      }
      if (path === '/v1/broker/tokens') {
        const tok = await this.broker.mintScopedToken(body as never);
        sendJson(res, 200, { ok: true, token: tok });
        return;
      }
      if (path === '/v1/broker/token-status') {
        if (typeof body.token !== 'string' || !body.token.trim()) {
          throw Error('BROKER_TOKEN_INVALID');
        }
        if (typeof body.nonce !== 'string' || !body.nonce) {
          throw Error('BROKER_STATUS_NONCE_INVALID');
        }
        const signedTokenStatus = await this.broker.getSignedTokenStatus({
          token: body.token,
          nonce: body.nonce,
        });
        sendJson(res, 200, {
          ok: true,
          status: signedTokenStatus.payload.status,
          revoked: signedTokenStatus.payload.revoked,
          signed_status: signedTokenStatus,
        });
        return;
      }
      if (path === '/v1/broker/revoke-token') {
        if (typeof body.token !== 'string' || !body.token.trim()) {
          throw Error('BROKER_TOKEN_INVALID');
        }
        const localOnly = body.local_only === true;
        const revRes = await this.broker.revokeIssuedToken(body.token, { localOnly });
        sendJson(res, 200, revRes);
        return;
      }
      if (path === '/v1/broker/ledger-ops') {
        const opRes = await this.broker.executeServerMediatedLedgerOp(body as never);
        sendJson(res, opRes.ok ? 200 : 409, { ...opRes });
        return;
      }
      if (path === '/v1/broker/rotate-signing-key') {
        const rotated = await this.broker.rotateSigningKey(body as never);
        sendJson(res, 200, { ok: true, ...rotated });
        return;
      }

      sendJson(res, 404, { ok: false, code: 'NOT_FOUND' });
    } catch (err) {
      const code = err instanceof Error ? err.message : 'BROKER_REQUEST_FAILED';
      sendJson(res, mapErrorStatus(code), { ok: false, code });
    }
  }
}

async function runCli(): Promise<void> {
  const issuer = process.env.BKE_BROKER_ISSUER ?? 'http://127.0.0.1';
  const enrollmentPath = process.env.BKE_BROKER_ENROLLMENT_PATH ?? '';
  const brokerStatePath = process.env.BKE_BROKER_STATE_PATH ?? '';
  const githubApiUrl = process.env.BKE_GITHUB_API_BASE_URL ?? '';
  const adminKeyFile = process.env.BKE_BROKER_ADMIN_PUBLIC_KEYS_FILE ?? '';
  const appId = Number(process.env.BKE_PINNED_APP_ID ?? '9001');
  const appSlug = process.env.BKE_PINNED_APP_SLUG ?? 'bke-dispatcher-app';
  const port = Number(process.env.BKE_BROKER_PORT ?? '0');

  if (!enrollmentPath || !brokerStatePath || !githubApiUrl || !adminKeyFile) {
    throw Error('BROKER_CLI_ENV_MISSING');
  }
  const keyMapRaw = JSON.parse(await readFile(adminKeyFile, 'utf8')) as Record<string, string>;
  const adminKeys = new Map<string, string>(Object.entries(keyMapRaw));

  const registry = new DeviceEnrollmentRegistry({
    storePath: enrollmentPath,
    adminPublicKeysById: adminKeys,
  });
  const ghAdapter = new SandboxGitHubAppAdapter({
    appId,
    appSlug,
    apiBaseUrl: githubApiUrl,
  });
  const broker = new TrustedDesktopBroker({
    brokerIssuer: issuer,
    statePath: brokerStatePath,
    enrollmentRegistry: registry,
    githubAppAdapter: ghAdapter,
    adminPublicKeysById: adminKeys,
  });

  const server = new SandboxBrokerHttpServer(broker, registry, port);
  const started = await server.start();
  const keys = await broker.getPublicVerificationKeys();
  process.stdout.write(
    JSON.stringify({
      ok: true,
      port: started.port,
      issuer,
      activeExecutionKeyId: keys.activeExecutionKeyId,
      activeHaltKeyId: keys.activeHaltKeyId,
      executionPublicKeys: keys.executionPublicKeys,
      haltPublicKeys: keys.haltPublicKeys,
    }) + '\n',
  );

  await new Promise<void>((resolveWait) => {
    const stop = () => void server.stop().then(() => resolveWait());
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
}

const isMain =
  typeof process.argv[1] === 'string' && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runCli().catch((err) => {
    process.stderr.write(`${err instanceof Error ? err.message : 'BROKER_CLI_FAILED'}\n`);
    process.exitCode = 1;
  });
}
