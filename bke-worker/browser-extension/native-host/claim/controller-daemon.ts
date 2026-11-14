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
import {
  ExecutionRequestVerifier,
  type GitHubAuthorityProvider,
} from './github-app-harness.js';
import { RestGitHubAuthorityProvider } from './github-authority-provider.js';
import { GitHubF1Ledger, type LedgerHttpFetch } from './github-f1-ledger.js';
import { IpcBridgeClient, assertSafeIpcSocketPath } from './ipc-client.js';
import type { TokenProvider } from './send-once-claim-adapter.js';
import {
  StaticUnrenewableTokenProvider,
  type ScopedTokenLifecycleProvider,
  type TokenLifecycleStatus,
} from './token-lifecycle.js';

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
  // F2-02: Default-OFF signed execution envelope configuration
  executionEnvelopeEnabled?: boolean;
  expectedRepositoryId?: number;
  expectedInstallationId?: string;
  executionSigningKeysById?: ReadonlyMap<string, string>;
  remoteHaltSigningKeysById?: ReadonlyMap<string, string>;
  allowRemoteSignedHalt?: boolean;
  githubApiBaseUrl?: string;
}

export interface ControllerDaemonDeps {
  tokenProvider: TokenProvider;
  tokenLifecycle?: ScopedTokenLifecycleProvider;
  authorityProvider?: GitHubAuthorityProvider;
  fetchImpl?: LedgerHttpFetch;
  ipcClient?: IpcBridgeClient;
  nowIso?: () => string;
  nowMs?: () => number;
  initialBridgeSeq?: number;
}

let monotonicDaemonBootOffset = 0;

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

function isLoopbackRemoteAddress(addr: string | undefined): boolean {
  if (!addr) return true;
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}

function mapVerifierRejectionHttpStatus(code: string): number {
  if (
    code === 'EXEC_REQ_SIGNATURE_INVALID' ||
    code === 'EXEC_REQ_SIGNING_KEY_UNKNOWN' ||
    code === 'EXEC_REQ_HALT_KEY_UNAUTHORIZED' ||
    code === 'GITHUB_AUTH_UNAUTHORIZED'
  ) {
    return 401;
  }
  if (
    code === 'EXEC_REQ_TARGET_REPOSITORY_MISMATCH' ||
    code === 'EXEC_REQ_INSTALLATION_MISMATCH' ||
    code === 'EXEC_REQ_WORKER_MISMATCH' ||
    code === 'EXEC_REQ_REMOTE_HALT_DISABLED' ||
    code === 'EXEC_REQ_HALT_KEY_SEPARATION_REQUIRED' ||
    code === 'GITHUB_PERMISSION_FORBIDDEN'
  ) {
    return 403;
  }
  if (
    code.startsWith('EXEC_REQ_WRAPPER') ||
    code.startsWith('EXEC_REQ_SIGNATURE_ENVELOPE') ||
    code === 'EXEC_REQ_NOT_OBJECT' ||
    code === 'EXEC_REQ_SCHEMA_MISMATCH' ||
    code === 'EXEC_REQ_UNSUPPORTED_VERSION' ||
    code === 'EXEC_REQ_CAPABILITY_INVALID' ||
    code === 'EXEC_REQ_ACTION_FORBIDDEN' ||
    code === 'EXEC_REQ_TIMESTAMPS_INVALID' ||
    code === 'EXEC_REQ_TTL_WINDOW_INVALID'
  ) {
    return 400;
  }
  return 409;
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
  private readonly tokenLifecycle: ScopedTokenLifecycleProvider;
  private readonly authorityProvider: GitHubAuthorityProvider;
  private readonly executionVerifier: ExecutionRequestVerifier | null = null;
  private server: Server | null = null;
  private actualPort: number | null = null;
  private bridgeSeq = 0;
  private started = false;
  private stopping = false;

  constructor(
    private readonly config: ControllerRuntimeConfig,
    private readonly deps: ControllerDaemonDeps,
  ) {
    const wallSeed = Math.max(0, (Date.now() - 1_700_000_000_000) * 100);
    monotonicDaemonBootOffset = Math.max(monotonicDaemonBootOffset + 1_000, wallSeed);
    this.bridgeSeq = deps.initialBridgeSeq ?? monotonicDaemonBootOffset;
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

    // Strict key separation: execution-envelope signing secrets MUST NOT reuse webhookSecret or operatorHaltToken.
    if (config.executionSigningKeysById) {
      for (const secret of config.executionSigningKeysById.values()) {
        if (config.webhookSecret && constantTimeTokenMatch(config.webhookSecret, secret)) {
          throw Error('DAEMON_EXECUTION_WEBHOOK_KEY_REUSE_FORBIDDEN');
        }
        if (config.operatorHaltToken && constantTimeTokenMatch(config.operatorHaltToken, secret)) {
          throw Error('DAEMON_EXECUTION_HALT_KEY_REUSE_FORBIDDEN');
        }
      }
    }
    if (config.remoteHaltSigningKeysById && config.executionSigningKeysById) {
      for (const haltSecret of config.remoteHaltSigningKeysById.values()) {
        for (const execSecret of config.executionSigningKeysById.values()) {
          if (constantTimeTokenMatch(execSecret, haltSecret)) {
            throw Error('DAEMON_HALT_KEY_SEPARATION_FORBIDDEN');
          }
        }
      }
    }

    const nowIso = deps.nowIso ?? (() => new Date().toISOString());
    const nowMs = deps.nowMs ?? (() => Date.now());
    this.tokenLifecycle =
      deps.tokenLifecycle ?? new StaticUnrenewableTokenProvider(deps.tokenProvider);

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

    this.authorityProvider =
      deps.authorityProvider ??
      new RestGitHubAuthorityProvider(fetchImpl, this.tokenLifecycle.asTokenProvider(), {
        baseApiUrl: config.githubApiBaseUrl,
        nowMs,
      });

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
          this.tokenLifecycle.asTokenProvider(),
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

    const [owner, repoName] = config.repository.split('/');
    if (
      config.executionEnvelopeEnabled === true &&
      owner &&
      repoName &&
      typeof config.expectedRepositoryId === 'number' &&
      Number.isSafeInteger(config.expectedRepositoryId) &&
      config.expectedRepositoryId > 0 &&
      typeof config.expectedInstallationId === 'string' &&
      config.expectedInstallationId.length > 0 &&
      config.executionSigningKeysById &&
      config.executionSigningKeysById.size > 0
    ) {
      this.executionVerifier = new ExecutionRequestVerifier({
        expectedRepositoryOwner: owner,
        expectedRepositoryName: repoName,
        expectedRepositoryId: config.expectedRepositoryId,
        expectedInstallationId: config.expectedInstallationId,
        expectedWorkerId: config.workerId,
        pinnedApp: config.pinnedApp,
        hmacKeysById: config.executionSigningKeysById,
        haltHmacKeysById: config.remoteHaltSigningKeysById,
        allowRemoteHalt: config.allowRemoteSignedHalt === true,
        provider: this.authorityProvider,
        replayStore: this.journal.asPersistentReplayStore(),
        nowMs,
      });
    }
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

  getTokenLifecycleStatus(): TokenLifecycleStatus {
    return this.tokenLifecycle.getStatus();
  }

  buildStatusSnapshot(): Record<string, unknown> {
    const state = this.journal.current();
    const tokenStatus = this.tokenLifecycle.getStatus();
    const quarantined = state.phase === 'DELIVERY_UNCERTAIN' || state.phase === 'HALTED';
    const trustedAuthorityConfigured = this.executionVerifier !== null;
    const missingOwnerPrerequisites: string[] = [];

    if (!this.config.operatorHaltToken) missingOwnerPrerequisites.push('OPERATOR_HALT_TOKEN_MISSING');
    if (!this.config.webhookSecret && !trustedAuthorityConfigured) {
      missingOwnerPrerequisites.push('REQUEST_AUTHENTICATION_UNCONFIGURED');
    }
    if (!tokenStatus.trustedRealBrokerApiAvailable || !tokenStatus.realBrokerTransportConnected) {
      missingOwnerPrerequisites.push('REAL_TOKEN_BROKER_NOT_CONNECTED');
    }
    if (!this.config.humanLiveSendAuthorized) {
      missingOwnerPrerequisites.push('HUMAN_LIVE_SEND_LOCKED_FALSE');
    }
    if (!this.config.liveProofs.realBrowserOwnerAccepted) {
      missingOwnerPrerequisites.push('REAL_CHROME_ACCEPTANCE_NOT_RUN');
    }

    return {
      version: 2,
      repository: state.repository,
      prNumber: state.prNumber,
      workerId: state.workerId,
      expectedHeadSha: state.lastExpectedHeadSha ?? null,
      daemonRunning: this.started && !this.stopping,
      journalPhase: state.phase,
      quarantined,
      conversationId: state.conversationId,
      confirmedTurnCount: state.confirmedTurnCount,
      uncertainReason: state.uncertainReason,
      nativeTransportReady: this.started && !this.stopping && !this.ipcClient.isQuarantined(),
      ipcClientQuarantined: this.ipcClient.isQuarantined(),
      executionEnvelopeEnabled: this.config.executionEnvelopeEnabled === true,
      trustedAuthorityConfigured,
      credentialProviderAvailable:
        tokenStatus.hasCachedToken || tokenStatus.mockBrokerSupported || tokenStatus.realBrokerTransportConnected,
      tokenLifecycle: tokenStatus,
      humanLiveSendAuthorized: this.config.humanLiveSendAuthorized,
      liveSendDefaults: 'LOCKED_FALSE',
      missingOwnerPrerequisites,
    };
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

  async processSignedExecutionRequest(rawRequest: unknown): Promise<{ httpStatus: number; body: Record<string, unknown> }> {
    if (this.config.executionEnvelopeEnabled !== true) {
      return {
        httpStatus: 403,
        body: { ok: false, status: 'BLOCKED', code: 'EXECUTION_ENVELOPE_DISABLED', submitInvocations: 0 },
      };
    }
    if (!this.executionVerifier) {
      return {
        httpStatus: 503,
        body: { ok: false, status: 'BLOCKED', code: 'EXECUTION_AUTHORITY_NOT_CONFIGURED', submitInvocations: 0 },
      };
    }
    if (!this.started || this.stopping) {
      return {
        httpStatus: 503,
        body: { ok: false, status: 'BLOCKED', code: 'DAEMON_NOT_RUNNING', submitInvocations: 0 },
      };
    }

    const verified = await this.executionVerifier.verifyAndAuthorize(rawRequest);
    if (!verified.ok) {
      return {
        httpStatus: mapVerifierRejectionHttpStatus(verified.code),
        body: {
          ok: false,
          status: 'BLOCKED',
          code: verified.code,
          journalPhase: this.journal.current().phase,
          submitInvocations: 0,
        },
      };
    }

    const env = verified.envelope;
    if (env.action === 'HALT') {
      const next = await this.halt(`REMOTE_SIGNED_HALT:${env.delivery_id}`);
      return {
        httpStatus: 200,
        body: {
          ok: true,
          status: 'HALTED',
          code: 'CONTROLLER_HALTED',
          journalPhase: next.phase,
          submitInvocations: 0,
        },
      };
    }

    if (env.action === 'PREPARE') {
      const prep = await this.controller.prepareFromAuthority({
        headSha: env.head_sha,
        prNumber: env.pr_number,
      });
      return {
        httpStatus: prep.status === 'BLOCKED' ? 409 : 200,
        body: { ok: prep.status !== 'BLOCKED', ...prep },
      };
    }

    // Ensure token lifecycle holds a fresh scoped token before touching claim CAS or browser
    try {
      await this.tokenLifecycle.getToken({ minTtlMs: 5_000 });
    } catch (err) {
      const state = this.journal.current();
      if (state.phase === 'RESERVED') {
        await this.journal.transition({
          phase: state.conversationId ? 'CONFIRMED_CONVERSATION' : 'IDLE',
          activeAttemptId: null,
          activeReservation: null,
        });
      }
      return {
        httpStatus: 409,
        body: {
          ok: false,
          status: 'BLOCKED',
          code: err instanceof Error ? err.message : 'TOKEN_UNAVAILABLE',
          journalPhase: this.journal.current().phase,
          submitInvocations: 0,
        },
      };
    }

    const outcome = await this.controller.processAuthorizedWake({
      headSha: env.head_sha,
      prNumber: env.pr_number,
      humanLiveSendAuthorized: this.config.humanLiveSendAuthorized,
      expectedAction: env.action,
      expectedAttemptId: env.attempt_id,
      reservationAlreadyRecorded: true,
    });

    return {
      httpStatus: outcome.status === 'BLOCKED' ? 409 : 200,
      body: { ok: outcome.status !== 'BLOCKED', ...outcome },
    };
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
    if (!isLoopbackRemoteAddress(req.socket?.remoteAddress)) {
      sendJson(res, 403, { ok: false, code: 'DAEMON_NON_LOOPBACK_REMOTE_FORBIDDEN' });
      return;
    }

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
      sendJson(res, 200, this.buildStatusSnapshot());
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

    if (method === 'POST' && path === '/execution-requests') {
      if (this.config.executionEnvelopeEnabled !== true) {
        sendJson(res, 403, { ok: false, code: 'EXECUTION_ENVELOPE_DISABLED' });
        return;
      }
      let rawBody: Buffer;
      try {
        rawBody = await readRawBody(req);
      } catch (err) {
        sendJson(res, 413, { ok: false, code: err instanceof Error ? err.message : 'BODY_READ_FAILED' });
        return;
      }
      let parsedBody: unknown;
      try {
        parsedBody = JSON.parse(rawBody.toString('utf8'));
      } catch {
        sendJson(res, 400, { ok: false, code: 'EXEC_REQ_JSON_INVALID' });
        return;
      }
      const result = await this.processSignedExecutionRequest(parsedBody);
      sendJson(res, result.httpStatus, result.body);
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
  summary: {
    repository: string;
    prNumber: number | null;
    workerId: string | null;
    executionEnvelopeEnabled: boolean;
    trustedAuthorityConfigured: boolean;
    credentialProviderAvailable: boolean;
    credentialBrokerKind: 'MOCK_BROKER' | 'REMOTE_DISABLED' | 'UNCONFIGURED';
    humanLiveSendAuthorized: boolean;
    missingOwnerPrerequisites: string[];
  };
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

  const envelopeEnabled = env.BKE_EXECUTION_ENVELOPE_ENABLED === 'true';
  checks.push({
    name: 'execution_envelope_mode',
    ok: true,
    detail: envelopeEnabled ? 'ENABLED' : 'DISABLED_BY_DEFAULT',
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

  const policyPath = env.BKE_NATIVE_POLICY_PATH;
  if (policyPath) {
    if (!isAbsolute(policyPath)) {
      checks.push({ name: 'native_policy_file', ok: false, detail: 'NON_ABSOLUTE_PATH' });
    } else {
      try {
        const handle = await open(policyPath, constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
          const st = await handle.stat();
          const safe = st.isFile() && (st.mode & 0o077) === 0;
          checks.push({
            name: 'native_policy_file',
            ok: safe,
            detail: safe ? 'MODE_0600_OK' : `UNSAFE_MODE_${(st.mode & 0o777).toString(8)}`,
          });
        } finally {
          await handle.close();
        }
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        checks.push({
          name: 'native_policy_file',
          ok: false,
          detail: code === 'ENOENT' ? 'MISSING' : code === 'ELOOP' ? 'SYMLINK_FORBIDDEN' : 'UNREADABLE',
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

  const hasExecKey = Boolean(env.BKE_EXECUTION_SIGNING_KEY && env.BKE_EXECUTION_SIGNING_KEY_ID);
  const trustedAuthorityConfigured =
    envelopeEnabled &&
    hasExecKey &&
    Boolean(env.BKE_REPOSITORY_ID && Number(env.BKE_REPOSITORY_ID) > 0 && env.BKE_INSTALLATION_ID);
  const hasStaticToken = Boolean(env.BKE_GITHUB_INSTALLATION_TOKEN && env.BKE_GITHUB_INSTALLATION_TOKEN.trim());
  const missingOwnerPrerequisites: string[] = [];
  if (!env.BKE_OPERATOR_HALT_TOKEN) missingOwnerPrerequisites.push('OPERATOR_HALT_TOKEN_MISSING');
  if (!hasStaticToken) missingOwnerPrerequisites.push('REAL_TOKEN_BROKER_OR_TOKEN_MISSING');
  if (!trustedAuthorityConfigured) missingOwnerPrerequisites.push('TRUSTED_EXECUTION_AUTHORITY_NOT_CONFIGURED');
  if (env.BKE_CERT_REAL_BROWSER !== 'true') missingOwnerPrerequisites.push('REAL_CHROME_ACCEPTANCE_NOT_RUN');

  const prParsed = env.BKE_PR_NUMBER ? Number(env.BKE_PR_NUMBER) : null;

  return {
    ok: checks.every((c) => c.ok),
    checks,
    liveSendDefaults: 'LOCKED_FALSE',
    summary: {
      repository: env.BKE_REPOSITORY ?? 'jan2xo/bke-worker',
      prNumber: prParsed && Number.isSafeInteger(prParsed) && prParsed > 0 ? prParsed : null,
      workerId: env.BKE_WORKER_ID ?? null,
      executionEnvelopeEnabled: envelopeEnabled,
      trustedAuthorityConfigured,
      credentialProviderAvailable: hasStaticToken,
      credentialBrokerKind: hasStaticToken ? 'REMOTE_DISABLED' : 'UNCONFIGURED',
      humanLiveSendAuthorized: liveAuthorizedEnv,
      missingOwnerPrerequisites,
    },
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

  const execKeys = new Map<string, string>();
  if (env.BKE_EXECUTION_SIGNING_KEY_ID && env.BKE_EXECUTION_SIGNING_KEY) {
    execKeys.set(env.BKE_EXECUTION_SIGNING_KEY_ID, env.BKE_EXECUTION_SIGNING_KEY);
  }
  const haltKeys = new Map<string, string>();
  if (env.BKE_REMOTE_HALT_SIGNING_KEY_ID && env.BKE_REMOTE_HALT_SIGNING_KEY) {
    haltKeys.set(env.BKE_REMOTE_HALT_SIGNING_KEY_ID, env.BKE_REMOTE_HALT_SIGNING_KEY);
  }

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
    policyPath: env.BKE_NATIVE_POLICY_PATH,
    webhookSecret: env.BKE_WEBHOOK_SECRET,
    operatorHaltToken: env.BKE_OPERATOR_HALT_TOKEN,
    listenHost,
    listenPort,
    humanLiveSendAuthorized: allowLiveSend,
    executionEnvelopeEnabled: env.BKE_EXECUTION_ENVELOPE_ENABLED === 'true',
    expectedRepositoryId: env.BKE_REPOSITORY_ID ? Number(env.BKE_REPOSITORY_ID) : undefined,
    expectedInstallationId: env.BKE_INSTALLATION_ID,
    executionSigningKeysById: execKeys.size > 0 ? execKeys : undefined,
    remoteHaltSigningKeysById: haltKeys.size > 0 ? haltKeys : undefined,
    allowRemoteSignedHalt: env.BKE_ALLOW_REMOTE_SIGNED_HALT === 'true',
    githubApiBaseUrl: env.BKE_GITHUB_API_BASE_URL,
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
        expectedHeadSha: state.lastExpectedHeadSha ?? null,
        phase: state.phase,
        quarantined: state.phase === 'DELIVERY_UNCERTAIN' || state.phase === 'HALTED',
        confirmedTurnCount: state.confirmedTurnCount,
        conversationId: state.conversationId,
        uncertainReason: state.uncertainReason,
        executionEnvelopeEnabled: cfg.executionEnvelopeEnabled === true,
        humanLiveSendAuthorized: false,
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
    const halted = await journal.transition({
      phase: 'HALTED',
      activeAttemptId: null,
      activeReservation: null,
      uncertainReason: reason,
    });
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
        executionEnvelopeEnabled: cfg.executionEnvelopeEnabled === true,
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
