/**
 * F1-03 Local Desktop Controller daemon/orchestrator.
 *
 * Coordinates:
 * - Authenticated HMAC-SHA256 webhook verification + delivery deduplication
 * - Atomic crash-safe local execution journal (quarantining mid-send restarts)
 * - Authenticated GitHub F1-02 ledger (`GitHubF1Ledger`)
 * - Authenticated F1-03 / F1-04 / F1-05 Chrome extension browser adapter
 * - Automatic turn routing: Turn 1 (new conversation) vs Turn 2+ (same-conversation continuation)
 * - Preserves human-only live-send consent gate (`humanLiveSendAuthorized` must be explicitly true)
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { open, rename, mkdir, unlink, stat, lstat } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { FirstMessageLiveProofs } from '../../src/first-message-actuator.js';
import {
  executeFirstMessageWithAdapters,
  type FirstMessageBrowserPort,
  type FirstMessageLedgerPort,
  type LedgerCasWriteResult,
} from '../../src/first-message-runtime.js';
import {
  executeContinuationWithAdapters,
  type ContinuationBrowserPort,
  type ContinuationLedgerPort,
} from '../../src/continuation-runtime.js';
import type { ExecutionAction, PersistentReplayStore } from './github-app-harness.js';
import type { GitHubAuthoritySnapshot, GitHubF1Ledger } from './github-f1-ledger.js';

export type JournalPhase =
  | 'IDLE'
  | 'RESERVED'
  | 'FENCED'
  | 'DISPATCHING'
  | 'CONFIRMED_CONVERSATION'
  | 'CONTINUING'
  | 'DELIVERY_UNCERTAIN'
  | 'HALTED';

export interface ActiveReservationRecord {
  attemptId: string;
  deliveryId: string;
  action: ExecutionAction;
  headSha: string;
  reservedAt: string;
}

export interface ExecutionJournalState {
  version: 1;
  repository: string;
  prNumber: number;
  workerId: string;
  phase: JournalPhase;
  activeAttemptId: string | null;
  conversationId: string | null;
  confirmedTurnCount: number;
  processedAttempts: string[];
  processedDeliveries: string[];
  uncertainReason: string | null;
  updatedAt: string;
  reservedAttempts?: string[];
  lastExpectedHeadSha?: string | null;
  activeReservation?: ActiveReservationRecord | null;
}

const SHA256_SIG_RE = /^sha256=([a-f0-9]{64})$/;

export function verifyGitHubWebhookSignature(opts: {
  secret: string;
  signatureHeader: string | null | undefined;
  rawBody: string | Buffer;
}): boolean {
  if (typeof opts.secret !== 'string' || opts.secret.length === 0) return false;
  if (typeof opts.signatureHeader !== 'string') return false;
  const match = SHA256_SIG_RE.exec(opts.signatureHeader.trim());
  if (!match || !match[1]) return false;
  const expected = createHmac('sha256', opts.secret).update(opts.rawBody).digest();
  const actual = Buffer.from(match[1], 'hex');
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

export class FileExecutionJournal {
  private state: ExecutionJournalState | null = null;
  private inProcessTail: Promise<void> = Promise.resolve();

  constructor(
    private readonly filePath: string,
    private readonly identity: { repository: string; prNumber: number; workerId: string },
    private readonly nowIso: () => string = () => new Date().toISOString(),
  ) {}

  private initial(): ExecutionJournalState {
    return {
      version: 1,
      repository: this.identity.repository,
      prNumber: this.identity.prNumber,
      workerId: this.identity.workerId,
      phase: 'IDLE',
      activeAttemptId: null,
      conversationId: null,
      confirmedTurnCount: 0,
      processedAttempts: [],
      processedDeliveries: [],
      reservedAttempts: [],
      lastExpectedHeadSha: null,
      activeReservation: null,
      uncertainReason: null,
      updatedAt: this.nowIso(),
    };
  }

  private async withFileLock<T>(fn: () => Promise<T>): Promise<T> {
    let releaseMem!: () => void;
    const nextMem = new Promise<void>((resolve) => {
      releaseMem = resolve;
    });
    const prevMem = this.inProcessTail;
    this.inProcessTail = nextMem;
    await prevMem;

    try {
      await mkdir(dirname(this.filePath), { recursive: true, mode: 0o700 });
      const lockPath = `${this.filePath}.lock`;
      let acquired = false;
      const deadline = Date.now() + 2_500;
      while (!acquired) {
        try {
          const lh = await open(
            lockPath,
            constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
            0o600,
          );
          await lh.writeFile(`${process.pid}\n`, { encoding: 'utf8' });
          await lh.close();
          acquired = true;
        } catch (err) {
          const code = (err as NodeJS.ErrnoException)?.code;
          if (code === 'ELOOP') {
            throw Error('JOURNAL_LOCK_SYMLINK_FORBIDDEN');
          }
          if (code !== 'EEXIST') {
            throw err;
          }
          // Fail closed immediately if lock path is a symlink, otherwise check stale lock older than 30s
          let lst;
          try {
            lst = await lstat(lockPath);
          } catch {
            continue;
          }
          if (lst.isSymbolicLink()) {
            throw Error('JOURNAL_LOCK_SYMLINK_FORBIDDEN');
          }
          if (Date.now() - lst.mtimeMs > 30_000) {
            await unlink(lockPath).catch(() => undefined);
            continue;
          }
          if (Date.now() >= deadline) {
            throw Error('JOURNAL_LOCK_TIMEOUT');
          }
          await new Promise((r) => setTimeout(r, 15));
        }
      }

      try {
        return await fn();
      } finally {
        await unlink(lockPath).catch(() => undefined);
      }
    } finally {
      releaseMem();
    }
  }

  private async atomicWrite(next: ExecutionJournalState): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true, mode: 0o700 });
    const tmpPath = `${this.filePath}.${process.pid}.${Date.now()}.tmp`;
    const handle = await open(
      tmpPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      await handle.writeFile(JSON.stringify(next, null, 2) + '\n', { encoding: 'utf8' });
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(tmpPath, this.filePath);
    this.state = next;
  }

  private async readFromDiskOrCreate(): Promise<ExecutionJournalState> {
    let raw: string;
    let handle;
    try {
      handle = await open(this.filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
        const fresh = this.initial();
        await this.atomicWrite(fresh);
        return fresh;
      }
      if ((err as NodeJS.ErrnoException)?.code === 'ELOOP') {
        throw Error('JOURNAL_SYMLINK_FORBIDDEN');
      }
      throw err;
    }

    try {
      const info = await handle.stat();
      if (!info.isFile()) {
        throw Error('JOURNAL_NOT_REGULAR_FILE');
      }
      if ((info.mode & 0o077) !== 0) {
        throw Error('JOURNAL_PERMISSIONS_INSECURE');
      }
      if (typeof process.getuid === 'function' && info.uid !== process.getuid()) {
        throw Error('JOURNAL_OWNER_INVALID');
      }
      raw = await handle.readFile({ encoding: 'utf8' });
    } finally {
      await handle.close();
    }

    let parsed: ExecutionJournalState;
    try {
      parsed = JSON.parse(raw) as ExecutionJournalState;
    } catch {
      throw Error('JOURNAL_CORRUPT');
    }
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed) ||
      parsed.version !== 1 ||
      parsed.repository !== this.identity.repository ||
      parsed.prNumber !== this.identity.prNumber ||
      parsed.workerId !== this.identity.workerId ||
      !Array.isArray(parsed.processedAttempts) ||
      !Array.isArray(parsed.processedDeliveries)
    ) {
      throw Error('JOURNAL_IDENTITY_MISMATCH');
    }

    parsed.reservedAttempts = Array.isArray(parsed.reservedAttempts) ? parsed.reservedAttempts : [];
    parsed.lastExpectedHeadSha = parsed.lastExpectedHeadSha ?? null;
    parsed.activeReservation = parsed.activeReservation ?? null;
    return parsed;
  }

  async openAndRecover(): Promise<ExecutionJournalState> {
    return this.withFileLock(async () => {
      const parsed = await this.readFromDiskOrCreate();

      // Fail-closed crash recovery: if controller died while DISPATCHING or CONTINUING,
      // delivery status in Chrome/ChatGPT is unknown and MUST stay quarantined.
      if (parsed.phase === 'DISPATCHING' || parsed.phase === 'CONTINUING') {
        const quarantined: ExecutionJournalState = {
          ...parsed,
          phase: 'DELIVERY_UNCERTAIN',
          uncertainReason: `CRASH_DURING_${parsed.phase}`,
          reservedAttempts: [
            ...new Set([
              ...(parsed.reservedAttempts ?? []),
              ...(parsed.activeAttemptId ? [parsed.activeAttemptId] : []),
            ]),
          ],
          updatedAt: this.nowIso(),
        };
        await this.atomicWrite(quarantined);
        return structuredClone(quarantined);
      }

      // Pre-dispatch RESERVED or FENCED recovery: preserve attempt reservation/consumption so
      // duplicate replays of the interrupted attempt remain permanently blocked across restarts,
      // while safely restoring idle/confirmed phase because no ChatGPT send started.
      if (parsed.phase === 'RESERVED' || parsed.phase === 'FENCED') {
        const burned = parsed.activeReservation?.attemptId ?? parsed.activeAttemptId;
        const recovered: ExecutionJournalState = {
          ...parsed,
          phase: parsed.conversationId ? 'CONFIRMED_CONVERSATION' : 'IDLE',
          activeAttemptId: null,
          activeReservation: null,
          reservedAttempts: [
            ...new Set([...(parsed.reservedAttempts ?? []), ...(burned ? [burned] : [])]),
          ],
          updatedAt: this.nowIso(),
        };
        await this.atomicWrite(recovered);
        return structuredClone(recovered);
      }

      this.state = parsed;
      return structuredClone(parsed);
    });
  }

  current(): ExecutionJournalState {
    if (!this.state) throw Error('JOURNAL_NOT_OPEN');
    return structuredClone(this.state);
  }

  async transition(patch: Partial<ExecutionJournalState>): Promise<ExecutionJournalState> {
    return this.withFileLock(async () => {
      const latest = await this.readFromDiskOrCreate();
      const next: ExecutionJournalState = {
        ...latest,
        ...patch,
        updatedAt: this.nowIso(),
      };
      await this.atomicWrite(next);
      return structuredClone(next);
    });
  }

  async recordDelivery(deliveryId: string): Promise<boolean> {
    return this.withFileLock(async () => {
      if (!this.state) throw Error('JOURNAL_NOT_OPEN');
      const latest = await this.readFromDiskOrCreate();
      if (!deliveryId || latest.processedDeliveries.includes(deliveryId)) {
        this.state = latest;
        return false;
      }
      const deliveries = [...latest.processedDeliveries, deliveryId].slice(-512);
      const next: ExecutionJournalState = {
        ...latest,
        processedDeliveries: deliveries,
        updatedAt: this.nowIso(),
      };
      await this.atomicWrite(next);
      return true;
    });
  }

  asPersistentReplayStore(): PersistentReplayStore {
    return {
      hasDelivery: async (deliveryId: string): Promise<boolean> => {
        const latest = await this.readFromDiskOrCreate();
        this.state = latest;
        return latest.processedDeliveries.includes(deliveryId);
      },
      hasOrReservedAttempt: async (attemptId: string): Promise<boolean> => {
        const latest = await this.readFromDiskOrCreate();
        this.state = latest;
        return (
          latest.processedAttempts.includes(attemptId) ||
          (latest.reservedAttempts ?? []).includes(attemptId) ||
          latest.activeAttemptId === attemptId
        );
      },
      reserveExecutionRequest: async (entry) => {
        return this.withFileLock(async () => {
          const latest = await this.readFromDiskOrCreate();
          if (latest.phase === 'DELIVERY_UNCERTAIN') {
            this.state = latest;
            return { ok: false, code: latest.uncertainReason || 'DELIVERY_UNCERTAIN_QUARANTINED' };
          }
          if (latest.phase === 'HALTED') {
            this.state = latest;
            return { ok: false, code: 'CONTROLLER_HALTED' };
          }
          if (
            latest.phase === 'RESERVED' ||
            latest.phase === 'FENCED' ||
            latest.phase === 'DISPATCHING' ||
            latest.phase === 'CONTINUING'
          ) {
            this.state = latest;
            return { ok: false, code: 'EXEC_REQ_CONTROLLER_CONCURRENT_RESERVATION' };
          }
          if (entry.prNumber !== latest.prNumber) {
            this.state = latest;
            return { ok: false, code: 'CONTROLLER_PR_MISMATCH' };
          }
          if (entry.action === 'DISPATCH_FIRST_MESSAGE' && (latest.conversationId !== null || latest.confirmedTurnCount > 0)) {
            this.state = latest;
            return { ok: false, code: 'EXEC_REQ_ACTION_CONVERSATION_ALREADY_EXISTS' };
          }
          if (entry.action === 'DISPATCH_CONTINUATION' && (latest.conversationId === null || latest.confirmedTurnCount < 1)) {
            this.state = latest;
            return { ok: false, code: 'EXEC_REQ_ACTION_NO_ACTIVE_CONVERSATION' };
          }
          if (latest.processedDeliveries.includes(entry.deliveryId)) {
            this.state = latest;
            return { ok: false, code: 'EXEC_REQ_DELIVERY_REPLAY' };
          }
          if (
            latest.processedAttempts.includes(entry.attemptId) ||
            (latest.reservedAttempts ?? []).includes(entry.attemptId)
          ) {
            this.state = latest;
            return { ok: false, code: 'EXEC_REQ_ATTEMPT_REPLAY' };
          }

          const next: ExecutionJournalState = {
            ...latest,
            phase: 'RESERVED',
            activeAttemptId: entry.attemptId,
            lastExpectedHeadSha: entry.headSha,
            processedDeliveries: [...latest.processedDeliveries, entry.deliveryId].slice(-512),
            reservedAttempts: [...(latest.reservedAttempts ?? []), entry.attemptId].slice(-512),
            activeReservation: {
              attemptId: entry.attemptId,
              deliveryId: entry.deliveryId,
              action: entry.action,
              headSha: entry.headSha,
              reservedAt: this.nowIso(),
            },
            updatedAt: this.nowIso(),
          };
          await this.atomicWrite(next);
          return { ok: true };
        });
      },
      recordNonDispatchDelivery: async (deliveryId: string): Promise<void> => {
        await this.recordDelivery(deliveryId);
      },
    };
  }
}

export interface DesktopControllerConfig {
  journal: FileExecutionJournal;
  createLedger: (headSha: string) => GitHubF1Ledger;
  createBrowserPorts: (headSha: string) => {
    firstMessage: FirstMessageBrowserPort;
    continuation: ContinuationBrowserPort;
  };
  liveProofs: FirstMessageLiveProofs;
  webhookSecret?: string;
  nowIso?: () => string;
}

export interface ControllerWakeOutcome {
  status: 'CONFIRMED_TURN_1' | 'CONFIRMED_CONTINUATION' | 'PREPARED' | 'BLOCKED';
  code: string;
  turnNumber: number | null;
  conversationId: string | null;
  journalPhase: JournalPhase;
  submitInvocations: number;
}

export class DesktopController {
  private busy = false;

  constructor(private readonly config: DesktopControllerConfig) {}

  async initialize(): Promise<ExecutionJournalState> {
    return this.config.journal.openAndRecover();
  }

  async halt(reason: string): Promise<ExecutionJournalState> {
    return this.config.journal.transition({
      phase: 'HALTED',
      activeAttemptId: null,
      activeReservation: null,
      uncertainReason: reason || 'OWNER_HALTED',
    });
  }

  async prepareFromAuthority(params: {
    headSha: string;
    prNumber: number;
  }): Promise<ControllerWakeOutcome> {
    const journal = this.config.journal;
    const state = journal.current();
    if (this.busy) {
      return {
        status: 'BLOCKED',
        code: 'CONTROLLER_BUSY',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }
    if (state.phase === 'DELIVERY_UNCERTAIN') {
      return {
        status: 'BLOCKED',
        code: state.uncertainReason || 'DELIVERY_UNCERTAIN_QUARANTINED',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }
    if (state.phase === 'HALTED') {
      return {
        status: 'BLOCKED',
        code: 'CONTROLLER_HALTED',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }
    if (params.prNumber !== state.prNumber) {
      return {
        status: 'BLOCKED',
        code: 'CONTROLLER_PR_MISMATCH',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }

    const ledger = this.config.createLedger(params.headSha);
    try {
      const auth = await ledger.refreshAuthority();
      const updated = await journal.transition({ lastExpectedHeadSha: auth.headSha });
      return {
        status: 'PREPARED',
        code: 'AUTHORITY_PREPARED_READONLY',
        turnNumber: updated.confirmedTurnCount || null,
        conversationId: updated.conversationId,
        journalPhase: updated.phase,
        submitInvocations: 0,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'GITHUB_AUTHORITY_REJECTED';
      return {
        status: 'BLOCKED',
        code: msg,
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: journal.current().phase,
        submitInvocations: 0,
      };
    }
  }

  async handleWebhookWake(params: {
    signatureHeader: string | null | undefined;
    deliveryId: string | null | undefined;
    rawBody: string | Buffer;
    headSha: string;
    prNumber: number;
    humanLiveSendAuthorized: boolean;
  }): Promise<ControllerWakeOutcome> {
    if (this.config.webhookSecret) {
      const valid = verifyGitHubWebhookSignature({
        secret: this.config.webhookSecret,
        signatureHeader: params.signatureHeader,
        rawBody: params.rawBody,
      });
      if (!valid) {
        const state = this.config.journal.current();
        return {
          status: 'BLOCKED',
          code: 'WEBHOOK_SIGNATURE_INVALID',
          turnNumber: state.confirmedTurnCount || null,
          conversationId: state.conversationId,
          journalPhase: state.phase,
          submitInvocations: 0,
        };
      }
    }

    const deliveryId = typeof params.deliveryId === 'string' ? params.deliveryId.trim() : '';
    if (!deliveryId) {
      const state = this.config.journal.current();
      return {
        status: 'BLOCKED',
        code: 'WEBHOOK_DELIVERY_ID_MISSING',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }

    const admitted = await this.config.journal.recordDelivery(deliveryId);
    if (!admitted) {
      const state = this.config.journal.current();
      return {
        status: 'BLOCKED',
        code: 'WEBHOOK_DELIVERY_DUPLICATE',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }

    return this.processAuthorizedWake({
      headSha: params.headSha,
      prNumber: params.prNumber,
      humanLiveSendAuthorized: params.humanLiveSendAuthorized,
    });
  }

  async processAuthorizedWake(params: {
    headSha: string;
    prNumber: number;
    humanLiveSendAuthorized: boolean;
    expectedAction?: 'DISPATCH_FIRST_MESSAGE' | 'DISPATCH_CONTINUATION';
    expectedAttemptId?: string;
    reservationAlreadyRecorded?: boolean;
  }): Promise<ControllerWakeOutcome> {
    const journal = this.config.journal;
    const state = journal.current();

    if (this.busy) {
      return {
        status: 'BLOCKED',
        code: 'CONTROLLER_BUSY',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }
    if (state.phase === 'DELIVERY_UNCERTAIN') {
      return {
        status: 'BLOCKED',
        code: state.uncertainReason || 'DELIVERY_UNCERTAIN_QUARANTINED',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }
    if (state.phase === 'HALTED') {
      return {
        status: 'BLOCKED',
        code: 'CONTROLLER_HALTED',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }
    if (params.prNumber !== state.prNumber) {
      return {
        status: 'BLOCKED',
        code: 'CONTROLLER_PR_MISMATCH',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }
    if (params.humanLiveSendAuthorized !== true) {
      if (params.reservationAlreadyRecorded && state.phase === 'RESERVED') {
        await journal.transition({
          phase: state.conversationId ? 'CONFIRMED_CONVERSATION' : 'IDLE',
          activeAttemptId: null,
          activeReservation: null,
        });
      }
      return {
        status: 'BLOCKED',
        code: 'LIVE_SEND_DISABLED',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: journal.current().phase,
        submitInvocations: 0,
      };
    }

    if (params.reservationAlreadyRecorded) {
      if (state.phase !== 'RESERVED' || !params.expectedAttemptId || state.activeAttemptId !== params.expectedAttemptId) {
        return {
          status: 'BLOCKED',
          code: 'EXEC_REQ_RESERVATION_STATE_INVALID',
          turnNumber: state.confirmedTurnCount || null,
          conversationId: state.conversationId,
          journalPhase: state.phase,
          submitInvocations: 0,
        };
      }
    } else if (state.phase === 'RESERVED') {
      return {
        status: 'BLOCKED',
        code: 'CONTROLLER_RESERVATION_IN_PROGRESS',
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: state.phase,
        submitInvocations: 0,
      };
    }

    this.busy = true;
    try {
      const ledger = this.config.createLedger(params.headSha);
      let auth: GitHubAuthoritySnapshot;
      try {
        auth = await ledger.refreshAuthority();
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'GITHUB_AUTHORITY_REJECTED';
        if (msg.includes('UNCERTAIN')) {
          await journal.transition({ phase: 'DELIVERY_UNCERTAIN', uncertainReason: msg });
        } else if (params.reservationAlreadyRecorded) {
          await journal.transition({
            phase: state.conversationId ? 'CONFIRMED_CONVERSATION' : 'IDLE',
            activeAttemptId: null,
            activeReservation: null,
          });
        }
        return {
          status: 'BLOCKED',
          code: msg,
          turnNumber: state.confirmedTurnCount || null,
          conversationId: state.conversationId,
          journalPhase: journal.current().phase,
          submitInvocations: 0,
        };
      }

      const attemptId = auth.ticket.attemptId;
      if (params.expectedAttemptId && attemptId !== params.expectedAttemptId) {
        if (params.reservationAlreadyRecorded) {
          await journal.transition({
            phase: state.conversationId ? 'CONFIRMED_CONVERSATION' : 'IDLE',
            activeAttemptId: null,
            activeReservation: null,
          });
        }
        return {
          status: 'BLOCKED',
          code: 'EXEC_REQ_TICKET_ATTEMPT_MISMATCH',
          turnNumber: state.confirmedTurnCount || null,
          conversationId: state.conversationId,
          journalPhase: journal.current().phase,
          submitInvocations: 0,
        };
      }

      if (
        state.processedAttempts.includes(attemptId) ||
        (!params.reservationAlreadyRecorded && (state.reservedAttempts ?? []).includes(attemptId))
      ) {
        return {
          status: 'BLOCKED',
          code: 'ATTEMPT_ALREADY_PROCESSED_BY_JOURNAL',
          turnNumber: state.confirmedTurnCount || null,
          conversationId: state.conversationId,
          journalPhase: state.phase,
          submitInvocations: 0,
        };
      }

      const ports = this.config.createBrowserPorts(params.headSha);
      const isTurn1 = auth.conversationLedger === null && state.conversationId === null;
      const nowFn = this.config.nowIso ?? (() => new Date().toISOString());

      if (params.expectedAction === 'DISPATCH_FIRST_MESSAGE' && !isTurn1) {
        await journal.transition({
          phase: state.conversationId ? 'CONFIRMED_CONVERSATION' : 'IDLE',
          activeAttemptId: null,
          activeReservation: null,
        });
        return {
          status: 'BLOCKED',
          code: 'EXEC_REQ_ACTION_TURN_MISMATCH',
          turnNumber: state.confirmedTurnCount || null,
          conversationId: state.conversationId,
          journalPhase: journal.current().phase,
          submitInvocations: 0,
        };
      }
      if (params.expectedAction === 'DISPATCH_CONTINUATION' && isTurn1) {
        await journal.transition({
          phase: 'IDLE',
          activeAttemptId: null,
          activeReservation: null,
        });
        return {
          status: 'BLOCKED',
          code: 'EXEC_REQ_ACTION_TURN_MISMATCH',
          turnNumber: state.confirmedTurnCount || null,
          conversationId: state.conversationId,
          journalPhase: journal.current().phase,
          submitInvocations: 0,
        };
      }

      await journal.transition({ lastExpectedHeadSha: params.headSha });

      if (isTurn1) {
        // Wrap ledger methods to persist crash-safe journal phases synchronously around CAS & submit
        const wrappedLedger: FirstMessageLedgerPort = {
          loadSnapshot: (e, b, t) => ledger.loadSnapshot(e, b, t),
          commitPreSendFence: async (fence) => {
            const res = await ledger.commitPreSendFence(fence);
            if (res.status === 'COMMITTED') {
              await journal.transition({
                phase: 'FENCED',
                activeAttemptId: attemptId,
                reservedAttempts: [...new Set([...(journal.current().reservedAttempts ?? []), attemptId])].slice(-512),
              });
            }
            return res;
          },
          readBackPreSendFence: (sha) => ledger.readBackPreSendFence(sha),
          consumeFirstSendClaim: async (claim): Promise<LedgerCasWriteResult> => {
            const res = await ledger.consumeFirstSendClaim(claim);
            if (res.status === 'COMMITTED') {
              await journal.transition({ phase: 'DISPATCHING', activeAttemptId: attemptId });
            } else if (res.status === 'UNCERTAIN') {
              await journal.transition({
                phase: 'DELIVERY_UNCERTAIN',
                activeAttemptId: attemptId,
                uncertainReason: 'SEND_CLAIM_UNCERTAIN',
              });
            }
            return res;
          },
          readBackFirstSendClaim: (sha) => ledger.readBackFirstSendClaim(sha),
          reconcileConversation: (rec) => ledger.reconcileConversation(rec),
          readBackConversation: (id) => ledger.readBackConversation(id),
          markDeliveryUncertain: async () => {
            await ledger.markDeliveryUncertain();
            await journal.transition({
              phase: 'DELIVERY_UNCERTAIN',
              activeAttemptId: attemptId,
              uncertainReason: 'FIRST_MESSAGE_DELIVERY_UNCERTAIN',
            });
          },
        };

        const outcome = await executeFirstMessageWithAdapters(wrappedLedger, ports.firstMessage, {
          humanLiveSendAuthorized: params.humanLiveSendAuthorized,
          liveProofs: this.config.liveProofs,
          nowIso: nowFn,
        });

        if (outcome.status === 'FIRST_MESSAGE_CONFIRMED' && outcome.conversationId) {
          const updated = await journal.transition({
            phase: 'CONFIRMED_CONVERSATION',
            activeAttemptId: null,
            activeReservation: null,
            conversationId: outcome.conversationId,
            confirmedTurnCount: 1,
            processedAttempts: [...new Set([...journal.current().processedAttempts, attemptId])],
            reservedAttempts: [...new Set([...(journal.current().reservedAttempts ?? []), attemptId])].slice(-512),
          });
          return {
            status: 'CONFIRMED_TURN_1',
            code: outcome.code,
            turnNumber: 1,
            conversationId: updated.conversationId,
            journalPhase: updated.phase,
            submitInvocations: outcome.submitInvocations,
          };
        }

        if (journal.current().phase === 'RESERVED') {
          await journal.transition({
            phase: state.conversationId ? 'CONFIRMED_CONVERSATION' : 'IDLE',
            activeAttemptId: null,
            activeReservation: null,
          });
        }

        return {
          status: 'BLOCKED',
          code: outcome.code,
          turnNumber: state.confirmedTurnCount || null,
          conversationId: state.conversationId,
          journalPhase: journal.current().phase,
          submitInvocations: outcome.submitInvocations,
        };
      }

      // Turn 2+: Same-conversation continuation
      if (!auth.conversationLedger || !state.conversationId) {
        await journal.transition({
          phase: 'DELIVERY_UNCERTAIN',
          activeAttemptId: attemptId,
          uncertainReason: 'CONVERSATION_LEDGER_STATE_DESYNC',
        });
        return {
          status: 'BLOCKED',
          code: 'CONVERSATION_LEDGER_STATE_DESYNC',
          turnNumber: state.confirmedTurnCount || null,
          conversationId: state.conversationId,
          journalPhase: 'DELIVERY_UNCERTAIN',
          submitInvocations: 0,
        };
      }

      const wrappedContLedger: ContinuationLedgerPort = {
        loadSnapshot: (e, b, t) => ledger.loadSnapshot(e, b, t),
        commitPreSendFence: async (fence) => {
          const res = await ledger.commitPreSendFence(fence);
          if (res.status === 'COMMITTED') {
            await journal.transition({
              phase: 'FENCED',
              activeAttemptId: attemptId,
              reservedAttempts: [...new Set([...(journal.current().reservedAttempts ?? []), attemptId])].slice(-512),
            });
          }
          return res;
        },
        readBackPreSendFence: (sha) => ledger.readBackPreSendFence(sha),
        consumeContinuationSendClaim: async (claim): Promise<LedgerCasWriteResult> => {
          const res = await ledger.consumeContinuationSendClaim(claim);
          if (res.status === 'COMMITTED') {
            await journal.transition({ phase: 'CONTINUING', activeAttemptId: attemptId });
          } else if (res.status === 'UNCERTAIN') {
            await journal.transition({
              phase: 'DELIVERY_UNCERTAIN',
              activeAttemptId: attemptId,
              uncertainReason: 'CONTINUATION_CLAIM_UNCERTAIN',
            });
          }
          return res;
        },
        readBackContinuationSendClaim: (sha) => ledger.readBackContinuationSendClaim(sha),
        reconcileContinuationTurn: (rec) => ledger.reconcileContinuationTurn(rec),
        readBackContinuationTurn: (id, turn, aid) => ledger.readBackContinuationTurn(id, turn, aid),
        markDeliveryUncertain: async () => {
          await ledger.markDeliveryUncertain();
          await journal.transition({
            phase: 'DELIVERY_UNCERTAIN',
            activeAttemptId: attemptId,
            uncertainReason: 'CONTINUATION_DELIVERY_UNCERTAIN',
          });
        },
      };

      const outcome = await executeContinuationWithAdapters(wrappedContLedger, ports.continuation, {
        humanLiveSendAuthorized: params.humanLiveSendAuthorized,
        liveProofs: this.config.liveProofs,
        executionAuthoritative: true,
        syntheticEvidence: false,
        nowIso: nowFn,
      });

      if (outcome.status === 'CONTINUATION_CONFIRMED' && outcome.conversationId && outcome.turnNumber) {
        const updated = await journal.transition({
          phase: 'CONFIRMED_CONVERSATION',
          activeAttemptId: null,
          activeReservation: null,
          conversationId: outcome.conversationId,
          confirmedTurnCount: outcome.turnNumber,
          processedAttempts: [...new Set([...journal.current().processedAttempts, attemptId])],
          reservedAttempts: [...new Set([...(journal.current().reservedAttempts ?? []), attemptId])].slice(-512),
        });
        return {
          status: 'CONFIRMED_CONTINUATION',
          code: outcome.code,
          turnNumber: updated.confirmedTurnCount,
          conversationId: updated.conversationId,
          journalPhase: updated.phase,
          submitInvocations: outcome.submitInvocations,
        };
      }

      if (journal.current().phase === 'RESERVED') {
        await journal.transition({
          phase: state.conversationId ? 'CONFIRMED_CONVERSATION' : 'IDLE',
          activeAttemptId: null,
          activeReservation: null,
        });
      }

      return {
        status: 'BLOCKED',
        code: outcome.code,
        turnNumber: state.confirmedTurnCount || null,
        conversationId: state.conversationId,
        journalPhase: journal.current().phase,
        submitInvocations: outcome.submitInvocations,
      };
    } finally {
      this.busy = false;
    }
  }
}
