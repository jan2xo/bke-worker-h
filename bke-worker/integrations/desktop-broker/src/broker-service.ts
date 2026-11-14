/**
 * F3-03 Private Trusted Broker Reference Implementation (Sandbox Only).
 *
 * SECURITY INVARIANT:
 * - Never deployed to Cloudflare, never uses real App PEMs/PATs/secrets, never activates live sends.
 * - Authenticates Admin approvals (Ed25519) + Desktop device PoP (ECDSA P-256), enforces
 *   enrollment & revocation registry, revalidates GitHub App installation + exclusive PR + exact head,
 *   enforces replay protection & signing key rotation, and emits V2 Ed25519 ExecutionRequestEnvelopeV2.
 * - Strictly separates EXECUTION keys from HALT keys and never leaks secrets in responses or audits.
 */
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { DeviceEnrollmentRegistry, verifyAdminApproval } from './device-enrollment.js';
import { SandboxGitHubAppAdapter } from './github-app-adapter.js';
import {
  BROKER_AUTHORIZED_CAPABILITY_V2,
  BROKER_PROTOCOL_VERSION_V2,
  EXECUTION_V2_DOMAIN,
  type BrokerAuditEvent,
  type BrokerSigningKeyEntry,
  type DeviceSignedAssertion,
  type ExecutionAction,
  type ExecutionRequestEnvelopeV2,
  type ServerMediatedLedgerOpRequest,
  type SignedAdminApproval,
  type SignedExecutionRequestV2,
} from './types.js';

const ENVELOPE_V2_KEYS = [
  'action',
  'attempt_id',
  'audience',
  'authorized_capability',
  'broker_issuer',
  'delivery_id',
  'device_id',
  'enrollment_generation',
  'expires_at',
  'head_sha',
  'installation_identity',
  'issued_at',
  'pr_number',
  'protocol_version',
  'repository_id',
  'repository_name',
  'repository_owner',
  'worker_id',
] as const;

interface BrokerDurableState {
  version: 1;
  signingKeys: BrokerSigningKeyEntry[];
  usedNonces: string[];
  usedDeliveryIds: string[];
  revokedTokens: string[];
  auditSeq: number;
  auditEvents: BrokerAuditEvent[];
}

export interface TrustedDesktopBrokerConfig {
  brokerIssuer: string;
  statePath: string;
  enrollmentRegistry: DeviceEnrollmentRegistry;
  githubAppAdapter: SandboxGitHubAppAdapter;
  adminPublicKeysById: ReadonlyMap<string, string>;
  defaultEnvelopeTtlMs?: number;
  defaultTokenTtlMs?: number;
  nowMs?: () => number;
}

function serializeEnvelopeV2(env: ExecutionRequestEnvelopeV2): string {
  const ordered: Record<string, unknown> = {};
  for (const k of ENVELOPE_V2_KEYS) {
    ordered[k] = env[k];
  }
  return JSON.stringify(ordered);
}

function genEd25519Entry(keyId: string, role: 'EXECUTION' | 'HALT', nowIso: string): BrokerSigningKeyEntry {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    key_id: keyId,
    role,
    public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    status: 'ACTIVE',
    created_at: nowIso,
  };
}

export class TrustedDesktopBroker {
  private readonly defaultEnvelopeTtlMs: number;
  private readonly defaultTokenTtlMs: number;
  private readonly nowMs: () => number;
  private lockTail: Promise<void> = Promise.resolve();

  constructor(private readonly config: TrustedDesktopBrokerConfig) {
    this.defaultEnvelopeTtlMs = Math.min(300_000, Math.max(15_000, config.defaultEnvelopeTtlMs ?? 120_000));
    this.defaultTokenTtlMs = Math.min(600_000, Math.max(30_000, config.defaultTokenTtlMs ?? 180_000));
    this.nowMs = config.nowMs ?? (() => Date.now());
  }

  private async withFileLock<T>(fn: () => Promise<T>): Promise<T> {
    let release!: () => void;
    const next = new Promise<void>((r) => {
      release = r;
    });
    const prev = this.lockTail;
    this.lockTail = next;
    await prev;

    try {
      await mkdir(dirname(this.config.statePath), { recursive: true, mode: 0o700 });
      const lockPath = `${this.config.statePath}.lock`;
      const deadline = Date.now() + 2_500;
      let acquired = false;
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
          if (code === 'ELOOP') throw Error('BROKER_LOCK_SYMLINK_FORBIDDEN');
          if (code !== 'EEXIST') throw err;
          const st = await lstat(lockPath).catch(() => null);
          if (st?.isSymbolicLink()) throw Error('BROKER_LOCK_SYMLINK_FORBIDDEN');
          if (st && Date.now() - st.mtimeMs > 30_000) {
            await unlink(lockPath).catch(() => undefined);
            continue;
          }
          if (Date.now() >= deadline) throw Error('BROKER_LOCK_TIMEOUT');
          await new Promise((r) => setTimeout(r, 10));
        }
      }
      try {
        return await fn();
      } finally {
        await unlink(lockPath).catch(() => undefined);
      }
    } finally {
      release();
    }
  }

  private async readOrInitState(): Promise<BrokerDurableState> {
    let handle;
    try {
      handle = await open(this.config.statePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === 'ENOENT') {
        const nowIso = new Date(this.nowMs()).toISOString();
        const fresh: BrokerDurableState = {
          version: 1,
          signingKeys: [
            genEd25519Entry('broker-exec-k1', 'EXECUTION', nowIso),
            genEd25519Entry('broker-halt-k1', 'HALT', nowIso),
          ],
          usedNonces: [],
          usedDeliveryIds: [],
          revokedTokens: [],
          auditSeq: 0,
          auditEvents: [],
        };
        await this.atomicWrite(fresh);
        return fresh;
      }
      if (code === 'ELOOP') throw Error('BROKER_STATE_SYMLINK_FORBIDDEN');
      throw err;
    }

    let raw: string;
    try {
      const st = await handle.stat();
      if (!st.isFile() || (st.mode & 0o077) !== 0) {
        throw Error('BROKER_STATE_PERMISSIONS_INSECURE');
      }
      raw = await handle.readFile({ encoding: 'utf8' });
    } finally {
      await handle.close();
    }

    let parsed: BrokerDurableState;
    try {
      parsed = JSON.parse(raw) as BrokerDurableState;
    } catch {
      throw Error('BROKER_STATE_CORRUPT');
    }
    if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.signingKeys)) {
      throw Error('BROKER_STATE_CORRUPT');
    }
    return parsed;
  }

  private async atomicWrite(state: BrokerDurableState): Promise<void> {
    await mkdir(dirname(this.config.statePath), { recursive: true, mode: 0o700 });
    const tmp = `${this.config.statePath}.${process.pid}.${Date.now()}.tmp`;
    const handle = await open(
      tmp,
      constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      await handle.writeFile(JSON.stringify(state, null, 2) + '\n', { encoding: 'utf8' });
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(tmp, this.config.statePath);
  }

  private appendAudit(
    state: BrokerDurableState,
    event: Omit<BrokerAuditEvent, 'seq' | 'at'>,
  ): void {
    state.auditSeq += 1;
    state.auditEvents.push({
      seq: state.auditSeq,
      at: new Date(this.nowMs()).toISOString(),
      ...event,
    });
    if (state.auditEvents.length > 500) {
      state.auditEvents = state.auditEvents.slice(-500);
    }
  }

  async initialize(): Promise<void> {
    await this.withFileLock(async () => {
      await this.readOrInitState();
    });
  }

  async getPublicVerificationKeys(): Promise<{
    issuer: string;
    executionPublicKeys: Record<string, string>;
    haltPublicKeys: Record<string, string>;
    activeExecutionKeyId: string;
    activeHaltKeyId: string;
  }> {
    return this.withFileLock(async () => {
      const state = await this.readOrInitState();
      const executionPublicKeys: Record<string, string> = {};
      const haltPublicKeys: Record<string, string> = {};
      let activeExecutionKeyId = '';
      let activeHaltKeyId = '';
      for (const k of state.signingKeys) {
        if (k.status === 'RETIRED') continue;
        if (k.role === 'EXECUTION') {
          executionPublicKeys[k.key_id] = k.public_key_pem;
          if (k.status === 'ACTIVE') activeExecutionKeyId = k.key_id;
        } else {
          haltPublicKeys[k.key_id] = k.public_key_pem;
          if (k.status === 'ACTIVE') activeHaltKeyId = k.key_id;
        }
      }
      return {
        issuer: this.config.brokerIssuer,
        executionPublicKeys,
        haltPublicKeys,
        activeExecutionKeyId,
        activeHaltKeyId,
      };
    });
  }

  async rotateSigningKey(params: {
    role: 'EXECUTION' | 'HALT';
    newKeyId: string;
    admin_approval: SignedAdminApproval;
  }): Promise<{ activeKeyId: string; publicKeyPem: string }> {
    const now = this.nowMs();
    verifyAdminApproval(
      params.admin_approval,
      this.config.adminPublicKeysById,
      now,
      'ROTATE_BROKER_SIGNING_KEY',
    );
    if (!/^[A-Za-z0-9._-]{3,64}$/.test(params.newKeyId)) {
      throw Error('BROKER_KEY_ID_INVALID');
    }

    return this.withFileLock(async () => {
      const state = await this.readOrInitState();
      if (state.signingKeys.some((k) => k.key_id === params.newKeyId)) {
        throw Error('BROKER_KEY_ID_ALREADY_EXISTS');
      }
      for (const k of state.signingKeys) {
        if (k.role === params.role && k.status === 'ACTIVE') {
          k.status = 'VERIFY_ONLY';
        }
      }
      const created = genEd25519Entry(params.newKeyId, params.role, new Date(now).toISOString());
      state.signingKeys.push(created);
      this.appendAudit(state, {
        operation: 'ROTATE_SIGNING_KEY',
        outcome: 'ALLOWED',
        code: 'BROKER_KEY_ROTATED',
        key_id: params.newKeyId,
      });
      await this.atomicWrite(state);
      return { activeKeyId: created.key_id, publicKeyPem: created.public_key_pem };
    });
  }

  async authorizeExecution(params: {
    repository: string;
    expected_repository_id: number;
    installation_id: string;
    worker_id: string;
    pr_number: number;
    head_sha: string;
    attempt_id: string;
    action: ExecutionAction;
    device_assertion: DeviceSignedAssertion;
    admin_approval: SignedAdminApproval;
    ttl_ms?: number;
    delivery_id?: string;
  }): Promise<SignedExecutionRequestV2> {
    const now = this.nowMs();

    // 1. Authenticate Admin dispatch intent (or reject stale/invalid admin approval)
    let adminPayload;
    try {
      adminPayload = verifyAdminApproval(
        params.admin_approval,
        this.config.adminPublicKeysById,
        now,
        'DISPATCH_EXECUTION',
      );
      if (
        adminPayload.installation_id !== params.installation_id ||
        adminPayload.worker_id !== params.worker_id ||
        (adminPayload.pr_number !== undefined && adminPayload.pr_number !== params.pr_number) ||
        (adminPayload.head_sha !== undefined && adminPayload.head_sha !== params.head_sha) ||
        (adminPayload.attempt_id !== undefined && adminPayload.attempt_id !== params.attempt_id) ||
        (adminPayload.execution_action !== undefined && adminPayload.execution_action !== params.action)
      ) {
        throw Error('BROKER_ADMIN_SCOPE_MISMATCH');
      }
    } catch (err) {
      const code = err instanceof Error ? err.message : 'BROKER_ADMIN_DENIED';
      await this.recordDeniedAudit('AUTHORIZE_EXECUTION', code, {
        worker_id: params.worker_id,
        repository: params.repository,
        pr_number: params.pr_number,
      });
      throw Error(code);
    }

    // 2. Authenticate Desktop device identity & PoP signature (rejects revoked/wrong/stale device)
    let device;
    try {
      device = await this.config.enrollmentRegistry.verifyDeviceAssertion(
        params.device_assertion,
        'AUTHORIZE_EXECUTION',
        params.repository,
      );
      if (
        device.worker_id !== params.worker_id ||
        device.installation_id !== params.installation_id
      ) {
        throw Error('BROKER_DEVICE_SCOPE_MISMATCH');
      }
    } catch (err) {
      const code = err instanceof Error ? err.message : 'BROKER_DEVICE_DENIED';
      await this.recordDeniedAudit('AUTHORIZE_EXECUTION', code, {
        worker_id: params.worker_id,
        device_id: params.device_assertion?.payload?.device_id,
        repository: params.repository,
        pr_number: params.pr_number,
      });
      throw Error(code);
    }

    // 3. Enforce replay resistance on assertion nonce + delivery_id BEFORE issuing signature
    const deliveryId = params.delivery_id ?? `deliv-${randomBytes(12).toString('hex')}`;
    const nonce = params.device_assertion.payload.nonce;
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      if (state.usedNonces.includes(nonce)) {
        this.appendAudit(state, {
          operation: 'AUTHORIZE_EXECUTION',
          outcome: 'DENIED',
          code: 'BROKER_NONCE_REPLAYED',
          worker_id: device.worker_id,
          device_id: device.device_id,
          repository: params.repository,
          pr_number: params.pr_number,
        });
        await this.atomicWrite(state);
        throw Error('BROKER_NONCE_REPLAYED');
      }
      if (state.usedDeliveryIds.includes(deliveryId)) {
        this.appendAudit(state, {
          operation: 'AUTHORIZE_EXECUTION',
          outcome: 'DENIED',
          code: 'BROKER_DELIVERY_REPLAYED',
          worker_id: device.worker_id,
          device_id: device.device_id,
          repository: params.repository,
          pr_number: params.pr_number,
        });
        await this.atomicWrite(state);
        throw Error('BROKER_DELIVERY_REPLAYED');
      }
      state.usedNonces = [...state.usedNonces, nonce].slice(-1024);
      state.usedDeliveryIds = [...state.usedDeliveryIds, deliveryId].slice(-1024);
      await this.atomicWrite(state);
    });

    // 4. Verify live GitHub App installation scope, cross-repo worker exclusivity, exact PR/head, refs & ticket
    let authority;
    try {
      authority = await this.config.githubAppAdapter.verifyExecutionAuthority({
        repository: params.repository,
        expectedRepositoryId: params.expected_repository_id,
        expectedInstallationId: params.installation_id,
        workerId: params.worker_id,
        prNumber: params.pr_number,
        headSha: params.head_sha,
        attemptId: params.attempt_id,
        requiredAction: params.action,
      });
    } catch (err) {
      const code = err instanceof Error ? err.message : 'BROKER_AUTHORITY_DENIED';
      await this.recordDeniedAudit('AUTHORIZE_EXECUTION', code, {
        worker_id: device.worker_id,
        device_id: device.device_id,
        repository: params.repository,
        pr_number: params.pr_number,
      });
      throw Error(code);
    }

    if (params.action === 'DISPATCH_FIRST_MESSAGE' && authority.conversationExists) {
      await this.recordDeniedAudit('AUTHORIZE_EXECUTION', 'BROKER_CONVERSATION_ALREADY_EXISTS', {
        worker_id: device.worker_id,
        device_id: device.device_id,
        repository: params.repository,
        pr_number: params.pr_number,
      });
      throw Error('BROKER_CONVERSATION_ALREADY_EXISTS');
    }
    if (params.action === 'DISPATCH_CONTINUATION' && !authority.conversationExists) {
      await this.recordDeniedAudit('AUTHORIZE_EXECUTION', 'BROKER_CONVERSATION_MISSING', {
        worker_id: device.worker_id,
        device_id: device.device_id,
        repository: params.repository,
        pr_number: params.pr_number,
      });
      throw Error('BROKER_CONVERSATION_MISSING');
    }

    // 5. Mint signed V2 envelope with role-separated Ed25519 active key
    const [owner, repoName] = params.repository.split('/') as [string, string];
    const ttlMs = Math.min(300_000, Math.max(5_000, params.ttl_ms ?? this.defaultEnvelopeTtlMs));
    const envelope: ExecutionRequestEnvelopeV2 = {
      protocol_version: BROKER_PROTOCOL_VERSION_V2,
      broker_issuer: this.config.brokerIssuer,
      audience: `bke-desktop-controller:${params.repository}:${device.worker_id}`,
      repository_owner: owner,
      repository_name: repoName,
      repository_id: authority.repositoryId,
      installation_identity: authority.installationId,
      worker_id: device.worker_id,
      device_id: device.device_id,
      enrollment_generation: device.enrollment_generation,
      pr_number: authority.prNumber,
      head_sha: authority.headSha,
      attempt_id: params.attempt_id,
      delivery_id: deliveryId,
      action: params.action,
      issued_at: new Date(now).toISOString(),
      expires_at: new Date(now + ttlMs).toISOString(),
      authorized_capability: BROKER_AUTHORIZED_CAPABILITY_V2,
    };

    const role = params.action === 'HALT' ? 'HALT' : 'EXECUTION';
    return this.withFileLock(async () => {
      const state = await this.readOrInitState();
      const signingKey = state.signingKeys.find((k) => k.role === role && k.status === 'ACTIVE');
      if (!signingKey) throw Error('BROKER_SIGNING_KEY_MISSING');

      const signingInput = EXECUTION_V2_DOMAIN + serializeEnvelopeV2(envelope);
      const signature = cryptoSign(null, Buffer.from(signingInput, 'utf8'), signingKey.private_key_pem);
      const signed: SignedExecutionRequestV2 = {
        envelope,
        signature_alg: 'Ed25519',
        key_id: signingKey.key_id,
        signature_b64url: signature.toString('base64url'),
      };
      this.appendAudit(state, {
        operation: `AUTHORIZE_${params.action}`,
        outcome: 'ALLOWED',
        code: 'BROKER_EXECUTION_AUTHORIZED',
        worker_id: device.worker_id,
        device_id: device.device_id,
        repository: params.repository,
        pr_number: params.pr_number,
        key_id: signingKey.key_id,
      });
      await this.atomicWrite(state);
      return signed;
    });
  }

  async mintScopedToken(params: {
    repository: string;
    repository_id: number;
    installation_id: string;
    worker_id: string;
    requested_permissions: Record<string, 'read' | 'write'>;
    device_assertion: DeviceSignedAssertion;
  }): Promise<{
    token: string;
    tokenType: 'installation';
    installationId: string;
    repositoryId: number;
    repositories: string[];
    permissions: Record<string, string>;
    issuedAtMs: number;
    expiresAtMs: number;
  }> {
    const device = await this.config.enrollmentRegistry.verifyDeviceAssertion(
      params.device_assertion,
      'MINT_SCOPED_TOKEN',
      params.repository,
    );
    if (device.worker_id !== params.worker_id || device.installation_id !== params.installation_id) {
      throw Error('BROKER_DEVICE_SCOPE_MISMATCH');
    }

    const nonce = params.device_assertion.payload.nonce;
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      if (state.usedNonces.includes(nonce)) {
        throw Error('BROKER_NONCE_REPLAYED');
      }
      state.usedNonces = [...state.usedNonces, nonce].slice(-1024);
      await this.atomicWrite(state);
    });

    // Strict clamping: only contents/pull_requests/checks allowed; never admin/issues/actions
    const clamped: Record<string, 'read' | 'write'> = {};
    for (const [k, v] of Object.entries(params.requested_permissions)) {
      if (k !== 'contents' && k !== 'pull_requests' && k !== 'checks') {
        throw Error('BROKER_REQUESTED_PERMISSION_FORBIDDEN');
      }
      if (k !== 'contents' && v !== 'read') {
        throw Error('BROKER_REQUESTED_PERMISSION_FORBIDDEN');
      }
      clamped[k] = v;
    }
    if (Object.keys(clamped).length === 0) {
      throw Error('BROKER_REQUESTED_PERMISSION_EMPTY');
    }

    const minted = await this.config.githubAppAdapter.resolveInstallationAndMintToken({
      repository: params.repository,
      expectedRepositoryId: params.repository_id,
      expectedInstallationId: params.installation_id,
      permissions: clamped,
    });

    const now = this.nowMs();
    const boundedExp = Math.min(minted.expiresAtMs, now + this.defaultTokenTtlMs);
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      this.appendAudit(state, {
        operation: 'MINT_SCOPED_TOKEN',
        outcome: 'ALLOWED',
        code: 'BROKER_SCOPED_TOKEN_MINTED',
        worker_id: device.worker_id,
        device_id: device.device_id,
        repository: params.repository,
      });
      await this.atomicWrite(state);
    });

    return {
      token: minted.token,
      tokenType: 'installation',
      installationId: minted.installationId,
      repositoryId: minted.repositoryId,
      repositories: [params.repository],
      permissions: minted.permissions,
      issuedAtMs: now,
      expiresAtMs: boundedExp,
    };
  }

  async executeServerMediatedLedgerOp(params: {
    worker_id: string;
    device_assertion: DeviceSignedAssertion;
    ledger_op: ServerMediatedLedgerOpRequest;
  }): Promise<{ ok: true; status: 'COMMITTED' | 'ALREADY_EXISTS'; sha: string } | { ok: false; code: string }> {
    const device = await this.config.enrollmentRegistry.verifyDeviceAssertion(
      params.device_assertion,
      'SERVER_MEDIATED_LEDGER_OP',
      params.ledger_op.repository,
    );
    if (
      device.worker_id !== params.worker_id ||
      device.installation_id !== params.ledger_op.installation_id
    ) {
      return { ok: false, code: 'BROKER_DEVICE_SCOPE_MISMATCH' };
    }
    const nonce = params.device_assertion.payload.nonce;
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      if (state.usedNonces.includes(nonce)) throw Error('BROKER_NONCE_REPLAYED');
      state.usedNonces = [...state.usedNonces, nonce].slice(-1024);
      await this.atomicWrite(state);
    });

    const res = await this.config.githubAppAdapter.executeServerMediatedLedgerOp(params.ledger_op);
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      this.appendAudit(state, {
        operation: `MEDIATED_${params.ledger_op.operation}`,
        outcome: res.ok ? 'ALLOWED' : 'DENIED',
        code: res.ok ? res.status : res.code,
        worker_id: device.worker_id,
        device_id: device.device_id,
        repository: params.ledger_op.repository,
        pr_number: params.ledger_op.pr_number,
      });
      await this.atomicWrite(state);
    });
    return res;
  }

  async revokeIssuedToken(token: string): Promise<void> {
    const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      if (!state.revokedTokens.includes(tokenHash)) {
        state.revokedTokens.push(tokenHash);
      }
      await this.atomicWrite(state);
    });
  }

  async isTokenRevoked(token: string): Promise<boolean> {
    const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');
    return this.withFileLock(async () => {
      const state = await this.readOrInitState();
      return state.revokedTokens.includes(tokenHash);
    });
  }

  async getAuditLog(): Promise<BrokerAuditEvent[]> {
    return this.withFileLock(async () => {
      const state = await this.readOrInitState();
      return structuredClone(state.auditEvents);
    });
  }

  private async recordDeniedAudit(
    operation: string,
    code: string,
    meta: Partial<Pick<BrokerAuditEvent, 'worker_id' | 'device_id' | 'repository' | 'pr_number'>>,
  ): Promise<void> {
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      this.appendAudit(state, {
        operation,
        outcome: 'DENIED',
        code,
        ...meta,
      });
      await this.atomicWrite(state);
    }).catch(() => undefined);
  }
}
