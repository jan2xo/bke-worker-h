/**
 * F1-03 Controller <-> Chrome Native Host Unix domain socket IPC client.
 *
 * Connects to `controller-host.mjs` (--controller-bridge), verifies local socket
 * ownership and non-symlink safety before sending commands, enforces single-flight
 * serialization and strict deadlines, and quarantines on any ambiguous mid-flight
 * disconnect or timeout without retrying.
 */
import { lstat } from 'node:fs/promises';
import { connect as connectNet } from 'node:net';
import { dirname, isAbsolute } from 'node:path';
import type { ControllerCommandDispatcher } from '../../src/extension-browser-adapter.js';

const MAX_IPC_LINE_BYTES = 65_536;
const DEFAULT_COMMAND_TIMEOUT_MS = 12_000;

export interface IpcCommandResponse {
  ok: boolean;
  code: string;
  uncertain?: boolean;
  payload?: Record<string, unknown>;
}

export interface IpcBridgeClientOptions {
  socketPath: string;
  commandTimeoutMs?: number;
  nowMs?: () => number;
  nextSeq?: () => number;
}

export async function assertSafeIpcSocketPath(socketPath: string): Promise<void> {
  if (typeof socketPath !== 'string' || !isAbsolute(socketPath) || socketPath.includes('\0')) {
    throw Error('CONTROLLER_IPC_PATH_INVALID');
  }

  const parent = dirname(socketPath);
  let parentStat;
  try {
    parentStat = await lstat(parent);
  } catch {
    throw Error('CONTROLLER_IPC_DIR_MISSING');
  }
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
    throw Error('CONTROLLER_IPC_DIR_UNSAFE');
  }
  if ((parentStat.mode & 0o077) !== 0) {
    throw Error('CONTROLLER_IPC_DIR_PERMISSIONS_UNSAFE');
  }
  if (typeof process.getuid === 'function' && parentStat.uid !== process.getuid()) {
    throw Error('CONTROLLER_IPC_DIR_OWNER_INVALID');
  }

  let sockStat;
  try {
    sockStat = await lstat(socketPath);
  } catch {
    throw Error('CONTROLLER_IPC_SOCKET_MISSING');
  }
  if (sockStat.isSymbolicLink() || !sockStat.isSocket()) {
    throw Error('CONTROLLER_IPC_SOCKET_UNSAFE');
  }
  if (typeof process.getuid === 'function' && sockStat.uid !== process.getuid()) {
    throw Error('CONTROLLER_IPC_SOCKET_OWNER_INVALID');
  }
}

export class IpcBridgeClient implements ControllerCommandDispatcher {
  private readonly commandTimeoutMs: number;
  private readonly nowMs: () => number;
  private readonly nextSeqFn: (() => number) | undefined;
  private seq = 0;
  private inFlight = false;
  private quarantined = false;
  private closed = false;

  constructor(private readonly options: IpcBridgeClientOptions) {
    const timeout = options.commandTimeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeout) || timeout < 50 || timeout > 60_000) {
      throw Error('CONTROLLER_IPC_TIMEOUT_INVALID');
    }
    this.commandTimeoutMs = timeout;
    this.nowMs = options.nowMs ?? (() => Date.now());
    this.nextSeqFn = options.nextSeq;
  }

  isQuarantined(): boolean {
    return this.quarantined;
  }

  isClosed(): boolean {
    return this.closed;
  }

  close(): void {
    this.closed = true;
  }

  private allocateSeq(): number {
    if (this.nextSeqFn) {
      return this.nextSeqFn();
    }
    this.seq += 1;
    return this.seq;
  }

  private buildControlCommand(action: 'PING' | 'GET_TARGET_STATUS' | 'HALT', reason?: string): Record<string, unknown> {
    const seq = this.allocateSeq();
    const issuedAtMs = this.nowMs();
    const base: Record<string, unknown> = {
      type: 'COMMAND',
      version: 1,
      command_id: `ipc-ctrl-${issuedAtMs}-${seq}`,
      seq,
      issued_at_ms: issuedAtMs,
      ttl_ms: Math.min(this.commandTimeoutMs, 15_000),
      action,
    };
    if (action === 'HALT') {
      base.reason = reason ?? 'CONTROLLER_DAEMON_HALT';
    }
    return base;
  }

  async ping(): Promise<IpcCommandResponse> {
    return this.sendCommand(this.buildControlCommand('PING'));
  }

  async getTargetStatus(): Promise<IpcCommandResponse> {
    return this.sendCommand(this.buildControlCommand('GET_TARGET_STATUS'));
  }

  async halt(reason = 'OWNER_OPERATOR_HALT'): Promise<IpcCommandResponse> {
    // Allow explicit HALT even if another operation quarantined the client.
    this.quarantined = true;
    if (this.closed) {
      return { ok: false, code: 'CONTROLLER_IPC_CLIENT_CLOSED', uncertain: false };
    }
    return this.dispatchRaw(this.buildControlCommand('HALT', reason), true);
  }

  async sendCommand(command: Record<string, unknown>): Promise<IpcCommandResponse> {
    if (this.closed) {
      return { ok: false, code: 'CONTROLLER_IPC_CLIENT_CLOSED', uncertain: false };
    }
    if (this.quarantined) {
      return { ok: false, code: 'CONTROLLER_IPC_CLIENT_QUARANTINED', uncertain: true };
    }
    if (this.inFlight) {
      return { ok: false, code: 'CONTROLLER_IPC_CLIENT_IN_FLIGHT', uncertain: false };
    }
    return this.dispatchRaw(command, false);
  }

  private async dispatchRaw(command: Record<string, unknown>, isHalt: boolean): Promise<IpcCommandResponse> {
    try {
      await assertSafeIpcSocketPath(this.options.socketPath);
    } catch (err) {
      const code = err instanceof Error ? err.message : 'CONTROLLER_IPC_SOCKET_UNAVAILABLE';
      return { ok: false, code, uncertain: false };
    }

    const action = typeof command.action === 'string' ? command.action : '';
    const isDispatchAction = action === 'DISPATCH_FIRST_MESSAGE' || action === 'DISPATCH_CONTINUATION';

    this.inFlight = true;
    return new Promise<IpcCommandResponse>((resolve) => {
      let settled = false;
      let written = false;
      let buffer = '';
      const socket = connectNet(this.options.socketPath);

      const finish = (response: IpcCommandResponse) => {
        if (settled) return;
        settled = true;
        this.inFlight = false;
        clearTimeout(timer);
        socket.removeAllListeners();
        socket.destroy();
        if (response.uncertain && !isHalt) {
          this.quarantined = true;
        }
        resolve(response);
      };

      const timer = setTimeout(() => {
        finish({
          ok: false,
          code: 'COMMAND_TIMEOUT_UNCERTAIN',
          uncertain: written || isDispatchAction,
        });
      }, this.commandTimeoutMs);
      timer.unref?.();

      socket.once('connect', () => {
        try {
          const line = JSON.stringify(command) + '\n';
          if (Buffer.byteLength(line, 'utf8') > MAX_IPC_LINE_BYTES) {
            finish({ ok: false, code: 'IPC_COMMAND_TOO_LARGE', uncertain: false });
            return;
          }
          socket.write(line, 'utf8', (writeErr) => {
            if (writeErr) {
              finish({
                ok: false,
                code: 'BRIDGE_WRITE_FAILED_UNCERTAIN',
                uncertain: isDispatchAction,
              });
              return;
            }
            written = true;
          });
        } catch {
          finish({ ok: false, code: 'IPC_SERIALIZE_FAILED', uncertain: false });
        }
      });

      socket.on('data', (chunk: Buffer | string) => {
        buffer += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
        if (Buffer.byteLength(buffer, 'utf8') > MAX_IPC_LINE_BYTES) {
          finish({
            ok: false,
            code: 'IPC_RESPONSE_TOO_LARGE_UNCERTAIN',
            uncertain: written || isDispatchAction,
          });
          return;
        }
        const idx = buffer.indexOf('\n');
        if (idx < 0) return;
        const rawLine = buffer.slice(0, idx).trim();
        let parsed: unknown;
        try {
          parsed = JSON.parse(rawLine);
        } catch {
          finish({
            ok: false,
            code: 'IPC_RESPONSE_JSON_INVALID_UNCERTAIN',
            uncertain: written || isDispatchAction,
          });
          return;
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          finish({
            ok: false,
            code: 'IPC_RESPONSE_INVALID_UNCERTAIN',
            uncertain: written || isDispatchAction,
          });
          return;
        }
        const rec = parsed as Record<string, unknown>;
        const ok = rec.ok === true;
        const code = typeof rec.code === 'string' && rec.code.length > 0 ? rec.code : 'IPC_RESPONSE_MISSING_CODE';
        const uncertain = rec.uncertain === true || code.includes('UNCERTAIN');
        const payload =
          rec.payload && typeof rec.payload === 'object' && !Array.isArray(rec.payload)
            ? (rec.payload as Record<string, unknown>)
            : undefined;
        finish({ ok, code, ...(uncertain ? { uncertain: true } : {}), ...(payload ? { payload } : {}) });
      });

      socket.once('end', () => {
        if (!settled) {
          finish({
            ok: false,
            code: 'BRIDGE_DISCONNECTED_UNCERTAIN',
            uncertain: written || isDispatchAction,
          });
        }
      });

      socket.once('close', () => {
        if (!settled) {
          finish({
            ok: false,
            code: 'BRIDGE_DISCONNECTED_UNCERTAIN',
            uncertain: written || isDispatchAction,
          });
        }
      });

      socket.once('error', () => {
        if (!settled) {
          finish({
            ok: false,
            code: written ? 'BRIDGE_DISCONNECTED_UNCERTAIN' : 'CONTROLLER_IPC_CONNECT_FAILED',
            uncertain: written || isDispatchAction,
          });
        }
      });
    });
  }
}
