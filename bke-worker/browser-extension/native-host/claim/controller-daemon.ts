/**
 * F1-03 / F1-06 Runnable Local Desktop Controller Daemon & Operator CLI.
 *
 * Connects the GitHub webhook / CLI surface -> FileExecutionJournal ->
 * GitHubF1Ledger -> DesktopController -> ExtensionBrowserAdapter ->
 * IpcBridgeClient (controller-host.mjs Unix socket) -> Chrome MV3 extension.
 *
 * Safety defaults:
 * - Binds strictly to loopback 127.0.0.1 by default.
 * - Live ChatGPT message sending remains DISABLED (`humanLiveSendAuthorized: false`)
 *   unless explicitly opted into by the human owner for a single supervised session.
 * - Never writes secrets, tokens, PEMs, or prompts to HTTP responses or logs.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { open, constants } from 'node:fs/promises';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FirstMessageLiveProofs } from '../../src/first-message-actuator.js';
import { ExtensionBrowserAdapter } from '../../src/extension-browser-adapter.js';
import type { PinnedDispatcherApp } from '../../src/ticket-contract.js';
import {
  DesktopController,
  FileExecutionJournal,
  type ControllerWakeOutcome,
  type ExecutionJournalState,
} from './desktop-controller.js';
import { GitHubF1Ledger, type LedgerHttpFetch } from './github-f1-ledger.js';
import { IpcBridgeClient, assertSafeIpcSocketPath } from './ipc-client.js';
import type { TokenProvider } from './send-once-claim-adapter.js';

const MAX_HTTP_BODY_BYTES = 262_144;
const SHA40_RE = /^[a-f0-9]{40}$/;
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const WORKER_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9_-]{8,128}$/;

export interface ControllerRuntimeConfig {
  repository: string;
  prNumber: number;
  workerId: string;
  pinnedApp: PinnedDispatcherApp;
  executionId: string;
  targetId: string;
  profileId: string;
  targetTabId: number;
  journalPath: string;
  ipcSocketPath: string;
  policyPath?: string;
  webhookSecret?: string;
  operatorHaltToken?: string;
  listenHost?: string;
  listenPort?: number;
  humanLiveSendAuthorized: boolean;
  liveProofs: FirstMessageLiveProofs;
}

export interface ControllerDaemonDeps {
  tokenProvider: TokenProvider;
  fetchImpl?: LedgerHttpFetch;
  ipcClient?: IpcBridgeClient;
  nowIso?: () => string;
  nowMs?: () => number;
}

export interface WebhookWakeExtraction {
  ok: true;
  event: string;
  prNumber: number;
  headSha: string;
}

export function extractWebhookPrAndHead(
  eventHeader: string | undefined,
  payload: unknown,
  expectedRepository: string,
  expectedPrNumber: number,
): WebhookWakeExtraction | { ok: false; code: string } {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, code: 'WEBHOOK_PAYLOAD_INVALID' };
  }
  const body = payload as Record<string, unknown>;
  const repoObj = body.repository as Record<string, unknown> | undefined;
  const fullName = typeof repoObj?.full_name === 'string' ? repoObj.full_name : '';
  if (!fullName || fullName.toLowerCase() !== expectedRepository.toLowerCase()) {
    return { ok: false, code: 'WEBHOOK_REPOSITORY_MISMATCH' };
  }

  const event = (eventHeader ?? '').trim();
  if (event === 'pull_request' || event === 'pull_request_target') {
    const pr = body.pull_request as Record<string, unknown> | undefined;
    const prNum = typeof pr?.number === 'number' ? pr.number : NaN;
    const head = (pr?.head as Record<string, unknown> | undefined)?.sha;
    if (prNum !== expectedPrNumber || typeof head !== 'string' || !SHA40_RE.test(head)) {
      return { ok: false, code: 'WEBHOOK_PR_OR_HEAD_MISMATCH' };
    }
    return { ok: true, event, prNumber: prNum, headSha: head };
  }

  if (event === 'check_run') {
    const run = body.check_run as Record<string, unknown> | undefined;
    const head = typeof run?.head_sha === 'string' ? run.head_sha : '';
    const prs = Array.isArray(run?.pull_requests) ? run.pull_requests : [];
    const matchedPr = prs.find(
      (p) => p && typeof p === 'object' && (p as Record<string, unknown>).number === expectedPrNumber,
    ) as Record<string, unknown> | undefined;
    if (!matchedPr || !SHA40_RE.test(head)) {
      return { ok: false, code: 'WEBHOOK_CHECK_RUN_PR_MISMATCH' };
    }
    return { ok: true, event, prNumber: expectedPrNumber, headSha: head };
  }

  if (event === 'bke_wake') {
    const prNum = typeof body.pr_number === 'number' ? body.pr_number : NaN;
    const head = typeof body.head_sha === 'string' ? body.head_sha : '';
    if (prNum !== expectedPrNumber || !SHA40_RE.test(head)) {
      return { ok: false, code: 'WEBHOOK_WAKE_PR_OR_HEAD_MISMATCH' };
    }
    return { ok: true, event, prNumber: prNum, headSha: head };
  }

  return { ok: false, code: 'WEBHOOK_EVENT_IGNORED' };
}

function constantTimeTokenMatch(expected: string, provided: string | undefined): boolean {
  if (!expected || typeof provided !== 'string' || !provided) return false;
  const a = createHash('sha256').update(expected, 'utf8').digest();
  const b = createHash('sha256').update(provided, 'utf8').digest();
  return timingSafeEqual(a, b);
}

function sendJson(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  const encoded = JSON.stringify(body) + '\n';
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(encoded);
}

function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((resolveBody, rejectBody) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_HTTP_BODY_BYTES) {
        rejectBody(Error('HTTP_BODY_TOO_LARGE'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolveBody(Buffer.concat(chunks)));
    req.on('error', rejectBody);
  });
}

export class DesktopControllerDaemon {
  private readonly journal: FileExecutionJournal;
  private readonly controller: DesktopController;
  private readonly ipcClient: IpcBridgeClient;
  private server: Server | null = null;
  private actualPort: number | null = null;
  private bridgeSeq = 0;
  private started = false;
  private stopping = false;

  constructor(
    private readonly config: ControllerRuntimeConfig,
    private readonly deps: ControllerDaemonDeps,
  ) {
    if (
      !REPO_RE.test(config.repository) ||
      !Number.isSafeInteger(config.prNumber) ||
      config.prNumber < 1 ||
      !WORKER_RE.test(config.workerId) ||
      !IDENTIFIER_RE.test(config.targetId) ||
      !IDENTIFIER_RE.test(config.profileId) ||
      !Number.isSafeInteger(config.targetTabId) ||
      config.targetTabId < 0 ||
      !isAbsolute(config.journalPath) ||
      !isAbsolute(config.ipcSocketPath)
    ) {
      throw Error('DAEMON_CONFIG_INVALID');
    }

    const host = config.listenHost ?? '127.0.0.1';
    if (host !== '127.0.0.1' && host !== '::1' && host !== 'localhost') {
      throw Error('DAEMON_NON_LOOPBACK_FORBIDDEN');
    }

    const nowIso = deps.nowIso ?? (() => new Date().toISOString());
    const nowMs = deps.nowMs ?? (() => Date.now());
    this.ipcClient =
      deps.ipcClient ??
      new IpcBridgeClient({
        socketPath: config.ipcSocketPath,
        nowMs,
        nextSeq: () => ++this.bridgeSeq,
      });

    const fetchImpl: LedgerHttpFetch =
      deps.fetchImpl ??
      ((url, init) =>
        globalThis.fetch(url, init).then((r) => ({
          status: r.status,
          headers: r.headers,
          json: () => r.json(),
        })));

    this.journal = new FileExecutionJournal(
      config.journalPath,
      {
        repository: config.repository,
        prNumber: config.prNumber,
        workerId: config.workerId,
      },
      nowIso,
    );

    this.controller = new DesktopController({
      journal: this.journal,
      webhookSecret: config.webhookSecret,
      liveProofs: config.liveProofs,
      nowIso,
      createLedger: (headSha) =>
        new GitHubF1Ledger(
          {
            repository: config.repository,
            prNumber: config.prNumber,
            headSha,
            workerId: config.workerId,
            authenticatedWorkerId: config.workerId,
            pinnedApp: config.pinnedApp,
            executionId: config.executionId,
            targetId: config.targetId,
            profileId: config.profileId,
            targetTabId: config.targetTabId,
            nowIso,
          },
          fetchImpl,
          deps.tokenProvider,
        ),
      createBrowserPorts: (headSha) => {
        const adapter = new ExtensionBrowserAdapter(
          {
            repository: config.repository,
            prNumber: config.prNumber,
            headSha,
            workerId: config.workerId,
            targetId: config.targetId,
            profileId: config.profileId,
            targetTabId: config.targetTabId,
            nowMs,
            nextSeq: () => ++this.bridgeSeq,
          },
          this.ipcClient,
        );
        return {
          firstMessage: adapter.asFirstMessagePort(),
          continuation: adapter.asContinuationPort(),
        };
      },
    });
  }

  getJournal(): ExecutionJournalState {
    return this.journal.current();
  }

  getPort(): number | null {
    return this.actualPort;
  }

  getController(): DesktopController {
    return this.controller;
  }

  async triggerAuthorizedWake(headSha: string): Promise<ControllerWakeOutcome> {
    if (!this.started || this.stopping) {
      return {
        status: 'BLOCKED',
        code: 'DAEMON_NOT_RUNNING',
        turnNumber: null,
        conversationId: null,
        journalPhase: this.journal.current().phase,
        submitInvocations: 0,
      };
    }
    return this.controller.processAuthorizedWake({
      headSha,
      prNumber: this.config.prNumber,
      humanLiveSendAuthorized: this.config.humanLiveSendAuthorized,
    });
  }

  async halt(reason = 'OWNER_OPERATOR_HALT'): Promise<ExecutionJournalState> {
    const state = await this.controller.halt(reason);
    await this.ipcClient.halt(reason).catch(() => undefined);
    return state;
  }

  async start(options: { listen?: boolean } = {}): Promise<{ recoveredState: ExecutionJournalState; port: number | null }> {
    const recoveredState = await this.controller.initialize();
    this.started = true;

    if (options.listen === false) {
      return { recoveredState, port: null };
    }

    const host = this.config.listenHost ?? '127.0.0.1';
    const desiredPort = this.config.listenPort ?? 0;
    this.server = createServer((req, res) => {
      void this.handleHttpRequest(req, res);
    });

    await new Promise<void>((resolveListen, rejectListen) => {
      this.server!.once('error', rejectListen);
      this.server!.listen(desiredPort, host, () => {
        const addr = this.server!.address();
        this.actualPort = addr && typeof addr === 'object' ? addr.port : null;
        resolveListen();
      });
    });

    return { recoveredState, port: this.actualPort };
  }

  private async handleHttpRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? 'GET';
    const path = (req.url ?? '/').split('?')[0] ?? '/';

    if (method === 'GET' && path === '/healthz') {
      const state = this.journal.current();
      sendJson(res, 200, {
        ok: true,
        component: 'bke-desktop-controller',
        phase: state.phase,
        quarantined: state.phase === 'DELIVERY_UNCERTAIN' || state.phase === 'HALTED',
        port: this.actualPort,
      });
      return;
    }

    if (method === 'GET' && path === '/status') {
      const state = this.journal.current();
      sendJson(res, 200, {
        version: 1,
        repository: state.repository,
        prNumber: state.prNumber,
        workerId: state.workerId,
        journalPhase: state.phase,
        conversationId: state.conversationId,
        confirmedTurnCount: state.confirmedTurnCount,
        uncertainReason: state.uncertainReason,
        humanLiveSendAuthorized: this.config.humanLiveSendAuthorized,
        ipcClientQuarantined: this.ipcClient.isQuarantined(),
      });
      return;
    }

    if (method === 'POST' && path === '/halt') {
      if (!this.config.operatorHaltToken) {
        sendJson(res, 403, { ok: false, code: 'OPERATOR_HALT_TOKEN_UNCONFIGURED' });
        return;
      }
      const tokenHeader = req.headers['x-bke-halt-token'];
      const provided = Array.isArray(tokenHeader) ? tokenHeader[0] : tokenHeader;
      if (!constantTimeTokenMatch(this.config.operatorHaltToken, provided)) {
        sendJson(res, 403, { ok: false, code: 'OPERATOR_HALT_UNAUTHORIZED' });
        return;
      }
      let reason = 'OWNER_HTTP_HALT';
      try {
        const raw = await readRawBody(req);
        if (raw.length > 0) {
          const parsed = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
          if (typeof parsed?.reason === 'string' && parsed.reason.trim().length >= 3) {
            reason = parsed.reason.trim().slice(0, 128);
          }
        }
      } catch {
        sendJson(res, 400, { ok: false, code: 'HALT_PAYLOAD_INVALID' });
        return;
      }
      const next = await this.halt(reason);
      sendJson(res, 200, { ok: true, code: 'CONTROLLER_HALTED', journalPhase: next.phase });
      return;
    }

    if (method === 'POST' && path === '/webhooks/github') {
      if (!this.config.webhookSecret) {
        sendJson(res, 503, { ok: false, code: 'WEBHOOK_SECRET_NOT_CONFIGURED' });
        return;
      }
      if (this.stopping) {
        sendJson(res, 503, { ok: false, code: 'DAEMON_STOPPING' });
        return;
      }
      let rawBody: Buffer;
      try {
        rawBody = await readRawBody(req);
      } catch (err) {
        sendJson(res, 413, { ok: false, code: err instanceof Error ? err.message : 'BODY_READ_FAILED' });
        return;
      }

      const sigHeader = req.headers['x-hub-signature-256'];
      const deliveryHeader = req.headers['x-github-delivery'];
      const eventHeader = req.headers['x-github-event'];
      const signature = Array.isArray(sigHeader) ? sigHeader[0] : sigHeader;
      const deliveryId = Array.isArray(deliveryHeader) ? deliveryHeader[0] : deliveryHeader;
      const eventName = Array.isArray(eventHeader) ? eventHeader[0] : eventHeader;

      let parsedPayload: unknown;
      try {
        parsedPayload = JSON.parse(rawBody.toString('utf8'));
      } catch {
        sendJson(res, 400, { ok: false, code: 'WEBHOOK_JSON_INVALID' });
        return;
      }

      const extracted = extractWebhookPrAndHead(
        eventName,
        parsedPayload,
        this.config.repository,
        this.config.prNumber,
      );
      if (!extracted.ok) {
        sendJson(res, 202, { ok: false, code: extracted.code });
        return;
      }

      const outcome = await this.controller.handleWebhookWake({
        signatureHeader: signature,
        deliveryId,
        rawBody,
        headSha: extracted.headSha,
        prNumber: extracted.prNumber,
        humanLiveSendAuthorized: this.config.humanLiveSendAuthorized,
      });

      const status =
        outcome.code === 'WEBHOOK_SIGNATURE_INVALID'
          ? 401
          : outcome.code === 'WEBHOOK_DELIVERY_ID_MISSING'
            ? 400
            : outcome.status === 'BLOCKED'
              ? 409
              : 200;
      sendJson(res, status, { ...outcome });
      return;
    }

    sendJson(res, 404, { ok: false, code: 'NOT_FOUND' });
  }

  async stop(): Promise<void> {
    this.stopping = true;
    this.ipcClient.close();
    if (this.server) {
      const s = this.server;
      this.server = null;
      this.actualPort = null;
      await new Promise<void>((resolveClose) => {
        s.close(() => resolveClose());
      });
    }
  }
}

export interface DoctorCheckResult {
  ok: boolean;
  checks: Array<{ name: string; ok: boolean; detail: string }>;
  liveSendDefaults: 'LOCKED_FALSE';
}

export async function runControllerDoctor(env: Record<string, string | undefined>): Promise<DoctorCheckResult> {
  const checks: Array<{ name: string; ok: boolean; detail: string }> = [];
  const nodeMajor = Number(process.versions.node.split('.')[0]);
  checks.push({
    name: 'node_version',
    ok: Number.isFinite(nodeMajor) && nodeMajor >= 22,
    detail: process.version,
  });

  const liveAuthorizedEnv = env.BKE_HUMAN_LIVE_SEND_AUTHORIZED === 'true';
  checks.push({
    name: 'live_send_default_safe',
    ok: !liveAuthorizedEnv,
    detail: liveAuthorizedEnv ? 'ENV_OVERRIDE_PRESENT' : 'LOCKED_FALSE',
  });

  const journalPath = env.BKE_JOURNAL_PATH;
  if (journalPath) {
    if (!isAbsolute(journalPath)) {
      checks.push({ name: 'journal_file', ok: false, detail: 'NON_ABSOLUTE_PATH' });
    } else {
      try {
        const handle = await open(journalPath, constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
          const st = await handle.stat();
          const safe = st.isFile() && (st.mode & 0o077) === 0;
          checks.push({
            name: 'journal_file',
            ok: safe,
            detail: safe ? 'MODE_0600_OK' : `UNSAFE_MODE_${(st.mode & 0o777).toString(8)}`,
          });
        } finally {
          await handle.close();
        }
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        checks.push({
          name: 'journal_file',
          ok: code === 'ENOENT',
          detail: code === 'ENOENT' ? 'NOT_CREATED_YET' : code === 'ELOOP' ? 'SYMLINK_FORBIDDEN' : 'UNREADABLE',
        });
      }
    }
  }

  const socketPath = env.BKE_CONTROLLER_IPC_SOCKET;
  if (socketPath) {
    try {
      await assertSafeIpcSocketPath(socketPath);
      checks.push({ name: 'ipc_socket', ok: true, detail: 'SOCKET_READY' });
    } catch (err) {
      const code = err instanceof Error ? err.message : 'SOCKET_UNAVAILABLE';
      checks.push({
        name: 'ipc_socket',
        ok: code === 'CONTROLLER_IPC_SOCKET_MISSING',
        detail: code,
      });
    }
  }

  return {
    ok: checks.every((c) => c.ok),
    checks,
    liveSendDefaults: 'LOCKED_FALSE',
  };
}

function loadConfigFromEnv(env: Record<string, string | undefined>, allowLiveSend: boolean): ControllerRuntimeConfig {
  const repository = env.BKE_REPOSITORY ?? 'jan2xo/bke-worker';
  const prNumber = Number(env.BKE_PR_NUMBER ?? '0');
  const workerId = env.BKE_WORKER_ID ?? '';
  const pinnedAppId = Number(env.BKE_PINNED_APP_ID ?? '0');
  const pinnedAppSlug = env.BKE_PINNED_APP_SLUG ?? 'bke-dispatcher-app';
  const executionId = env.BKE_EXECUTION_ID ?? 'exec-desktop-01';
  const targetId = env.BKE_TARGET_ID ?? 'target-desktop-01';
  const profileId = env.BKE_PROFILE_ID ?? 'profile-desktop-01';
  const targetTabId = Number(env.BKE_TARGET_TAB_ID ?? '0');
  const journalPath = env.BKE_JOURNAL_PATH ?? '';
  const ipcSocketPath = env.BKE_CONTROLLER_IPC_SOCKET ?? '';
  const listenHost = env.BKE_CONTROLLER_HOST ?? '127.0.0.1';
  const listenPort = env.BKE_CONTROLLER_PORT ? Number(env.BKE_CONTROLLER_PORT) : 31940;

  return {
    repository,
    prNumber,
    workerId,
    pinnedApp: { id: pinnedAppId, slug: pinnedAppSlug },
    executionId,
    targetId,
    profileId,
    targetTabId,
    journalPath,
    ipcSocketPath,
    webhookSecret: env.BKE_WEBHOOK_SECRET,
    operatorHaltToken: env.BKE_OPERATOR_HALT_TOKEN,
    listenHost,
    listenPort,
    humanLiveSendAuthorized: allowLiveSend,
    liveProofs: {
      githubCasOwnerCertified: env.BKE_CERT_GITHUB_CAS === 'true',
      nativePairingOwnerCertified: env.BKE_CERT_NATIVE_PAIRING === 'true',
      realBrowserOwnerAccepted: allowLiveSend && env.BKE_CERT_REAL_BROWSER === 'true',
    },
  };
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<number> {
  const command = argv[0] ?? '--help';
  if (command === '--help' || command === '-h' || command === 'help') {
    process.stdout.write(
      [
        'Usage: controller-daemon <doctor|status|halt|start> [options]',
        '',
        'Subcommands:',
        '  doctor  Verify Node, journal mode 0o600, IPC socket ownership, and locked defaults.',
        '  status  Inspect persisted FileExecutionJournal state safely.',
        '  halt    Transition local journal to HALTED and send HALT to IPC socket if present.',
        '  start   Start loopback webhook daemon (defaults humanLiveSendAuthorized=false).',
        '',
        'Security:',
        '  Live ChatGPT message sending is LOCKED FALSE by default.',
      ].join('\n') + '\n',
    );
    return 0;
  }

  if (command === 'doctor') {
    const report = await runControllerDoctor(process.env);
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    return report.ok ? 0 : 2;
  }

  if (command === 'status') {
    const cfg = loadConfigFromEnv(process.env, false);
    const journal = new FileExecutionJournal(cfg.journalPath, {
      repository: cfg.repository,
      prNumber: cfg.prNumber,
      workerId: cfg.workerId,
    });
    const state = await journal.openAndRecover();
    process.stdout.write(
      JSON.stringify({
        repository: state.repository,
        prNumber: state.prNumber,
        workerId: state.workerId,
        phase: state.phase,
        confirmedTurnCount: state.confirmedTurnCount,
        conversationId: state.conversationId,
        uncertainReason: state.uncertainReason,
      }, null, 2) + '\n',
    );
    return 0;
  }

  if (command === 'halt') {
    const reason = argv[1] && !argv[1].startsWith('--') ? argv[1] : 'OWNER_CLI_HALT';
    const cfg = loadConfigFromEnv(process.env, false);
    const journal = new FileExecutionJournal(cfg.journalPath, {
      repository: cfg.repository,
      prNumber: cfg.prNumber,
      workerId: cfg.workerId,
    });
    await journal.openAndRecover();
    const halted = await journal.transition({ phase: 'HALTED', uncertainReason: reason });
    if (cfg.ipcSocketPath) {
      const client = new IpcBridgeClient({ socketPath: cfg.ipcSocketPath });
      await client.halt(reason).catch(() => undefined);
      client.close();
    }
    process.stdout.write(JSON.stringify({ ok: true, phase: halted.phase, reason: halted.uncertainReason }) + '\n');
    return 0;
  }

  if (command === 'start') {
    const dryRun = argv.includes('--dry-run');
    const allowLive =
      argv.includes('--owner-supervised-live-send') &&
      process.env.BKE_OWNER_SUPERVISED_LIVE_SEND === 'I_OWNER_AUTHORIZE_LIVE_SEND';
    const cfg = loadConfigFromEnv(process.env, allowLive);
    const daemon = new DesktopControllerDaemon(cfg, {
      tokenProvider: async () => process.env.BKE_GITHUB_INSTALLATION_TOKEN ?? '',
    });
    const started = await daemon.start({ listen: !dryRun });
    process.stdout.write(
      JSON.stringify({
        ok: true,
        mode: dryRun ? 'DRY_RUN' : 'DAEMON_LISTENING',
        port: started.port,
        phase: started.recoveredState.phase,
        humanLiveSendAuthorized: cfg.humanLiveSendAuthorized,
      }) + '\n',
    );
    if (dryRun) {
      await daemon.stop();
      return 0;
    }
    await new Promise<void>((resolveWait) => {
      const stopSignal = () => {
        void daemon.stop().then(() => resolveWait());
      };
      process.once('SIGINT', stopSignal);
      process.once('SIGTERM', stopSignal);
    });
    return 0;
  }

  process.stderr.write(`UNKNOWN_SUBCOMMAND: ${command}\n`);
  return 2;
}

const isEntrypoint =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntrypoint) {
  runCli().then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      process.stderr.write(`${err instanceof Error ? err.message : 'CONTROLLER_DAEMON_FAILED'}\n`);
      process.exitCode = 1;
    },
  );
}
