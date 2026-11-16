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
  DEVICE_STATUS_DOMAIN,
  EXECUTION_V2_DOMAIN,
  TOKEN_STATUS_DOMAIN,
  type BrokerAuditEvent,
  type BrokerSigningKeyEntry,
  type DeviceSignedAssertion,
  type DeviceStatusPayload,
  type ExecutionAction,
  type ExecutionRequestEnvelopeV2,
  type ServerMediatedLedgerOpRequest,
  type ServerMediatedLedgerOpResult,
  type SignedAdminApproval,
  type SignedDeviceStatusResponse,
  type SignedExecutionRequestV2,
  type SignedTokenStatusResponse,
  type TokenStatusPayload,
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

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const WORKER_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const INSTALL_RE = /^[0-9]{1,20}$/;
const DEVICE_ID_RE = /^[A-Za-z0-9._:-]{4,128}$/;

function isValidRepoName(value: unknown): value is string {
  if (typeof value !== 'string' || !REPO_RE.test(value)) return false;
  const parts = value.split('/');
  return parts.length === 2 && parts[0] !== '.' && parts[0] !== '..' && parts[1] !== '.' && parts[1] !== '..';
}

export interface IssuedTokenRecord {
  token_sha256: string;
  installation_id: string;
  repository: string;
  repository_id: number;
  worker_id: string;
  device_id: string;
  issued_at_ms: number;
  usage_expires_at_ms: number;
  provider_expires_at_ms: number;
  revoked: boolean;
  provider_revoked: boolean;
}

interface BrokerDurableState {
  version: 1;
  signingKeys: BrokerSigningKeyEntry[];
  usedNonces: string[];
  usedStatusNonces?: string[];
  usedDeliveryIds: string[];
  revokedTokens: string[];
  issuedTokens?: Record<string, IssuedTokenRecord>;
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

function canonicalJson(value: Record<string, unknown>): string {
  const ordered: Record<string, unknown> = {};
  for (const k of Object.keys(value).sort()) {
    ordered[k] = value[k];
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
          usedStatusNonces: [],
          usedDeliveryIds: [],
          revokedTokens: [],
          issuedTokens: {},
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
    if (!Array.isArray(parsed.usedStatusNonces)) {
      parsed.usedStatusNonces = [];
    }
    if (!parsed.issuedTokens || typeof parsed.issuedTokens !== 'object' || Array.isArray(parsed.issuedTokens)) {
      parsed.issuedTokens = {};
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
    /** Application-enforced usage/refresh budget (GitHub honors bearer until providerExpiresAtMs unless revoked). */
    expiresAtMs: number;
    usageExpiresAtMs: number;
    providerExpiresAtMs: number;
    revocationScope: 'LOCAL_AND_PROVIDER';
  }> {
    if (!isValidRepoName(params.repository)) {
      throw Error('BROKER_REPOSITORY_INVALID');
    }
    if (
      typeof params.repository_id !== 'number' ||
      !Number.isSafeInteger(params.repository_id) ||
      params.repository_id <= 0
    ) {
      throw Error('BROKER_REPOSITORY_ID_INVALID');
    }
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

    // Strict clamping: desktop workers may ONLY request read scopes (0 contents:write tokens!)
    const clamped: Record<string, 'read' | 'write'> = {};
    for (const [k, v] of Object.entries(params.requested_permissions)) {
      if (k !== 'contents' && k !== 'pull_requests' && k !== 'checks') {
        throw Error('BROKER_REQUESTED_PERMISSION_FORBIDDEN');
      }
      if (v !== 'read') {
        throw Error(
          k === 'contents' ? 'BROKER_DESKTOP_WRITE_TOKEN_FORBIDDEN' : 'BROKER_REQUESTED_PERMISSION_FORBIDDEN',
        );
      }
      clamped[k] = 'read';
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
    // Note: `boundedExp` (`usageExpiresAtMs`) is the broker/client usage budget; GitHub itself honors the IAT
    // until `minted.expiresAtMs` (`providerExpiresAtMs`) unless actively revoked via DELETE /installation/token.
    const boundedExp = Math.min(minted.expiresAtMs, now + this.defaultTokenTtlMs);
    const tokenSha = createHash('sha256').update(minted.token, 'utf8').digest('hex');
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      const issuedMap = state.issuedTokens ?? {};
      issuedMap[tokenSha] = {
        token_sha256: tokenSha,
        installation_id: minted.installationId,
        repository: params.repository,
        repository_id: minted.repositoryId,
        worker_id: device.worker_id,
        device_id: device.device_id,
        issued_at_ms: now,
        usage_expires_at_ms: boundedExp,
        provider_expires_at_ms: minted.expiresAtMs,
        revoked: false,
        provider_revoked: false,
      };
      const keys = Object.keys(issuedMap);
      if (keys.length > 4096) {
        const sorted = keys.sort((a, b) => issuedMap[a]!.issued_at_ms - issuedMap[b]!.issued_at_ms);
        for (const k of sorted.slice(0, keys.length - 4096)) {
          delete issuedMap[k];
        }
      }
      state.issuedTokens = issuedMap;
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
      usageExpiresAtMs: boundedExp,
      providerExpiresAtMs: minted.expiresAtMs,
      revocationScope: 'LOCAL_AND_PROVIDER',
    };
  }

  async executeServerMediatedLedgerOp(params: {
    worker_id: string;
    device_assertion: DeviceSignedAssertion;
    ledger_op: ServerMediatedLedgerOpRequest;
  }): Promise<ServerMediatedLedgerOpResult> {
    if (!params.ledger_op || typeof params.ledger_op !== 'object' || Array.isArray(params.ledger_op)) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_OP_INVALID' };
    }
    if (!isValidRepoName(params.ledger_op.repository)) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_OP_INVALID' };
    }
    const device = await this.config.enrollmentRegistry.verifyDeviceAssertion(
      params.device_assertion,
      'SERVER_MEDIATED_LEDGER_OP',
      params.ledger_op.repository,
    );
    const pop = params.device_assertion.payload;
    if (
      device.worker_id !== params.worker_id ||
      device.installation_id !== params.ledger_op.installation_id ||
      (params.ledger_op.worker_id !== undefined && params.ledger_op.worker_id !== params.worker_id) ||
      pop.ledger_op !== params.ledger_op.operation ||
      pop.pr_number !== params.ledger_op.pr_number ||
      pop.head_sha !== params.ledger_op.head_sha ||
      pop.attempt_id !== params.ledger_op.attempt_id ||
      pop.ref_name !== params.ledger_op.ref_name
    ) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_DEVICE_SCOPE_MISMATCH' };
    }
    const nonce = params.device_assertion.payload.nonce;
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      if (state.usedNonces.includes(nonce)) throw Error('BROKER_NONCE_REPLAYED');
      state.usedNonces = [...state.usedNonces, nonce].slice(-1024);
      await this.atomicWrite(state);
    });

    const res = await this.config.githubAppAdapter.executeServerMediatedLedgerOp({
      ...params.ledger_op,
      worker_id: device.worker_id,
    });
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      this.appendAudit(state, {
        operation: `MEDIATED_${params.ledger_op.operation}`,
        outcome: res.ok ? 'ALLOWED' : 'DENIED',
        code: res.ok ? res.status : (res.code ?? res.status),
        worker_id: device.worker_id,
        device_id: device.device_id,
        repository: params.ledger_op.repository,
        pr_number: params.ledger_op.pr_number,
      });
      await this.atomicWrite(state);
    });
    return res;
  }

  async getSignedDeviceStatus(params: {
    workerId: string;
    deviceId?: string;
    installationId?: string;
    repository?: string;
    enrollmentGeneration?: number;
    nonce: string;
  }): Promise<SignedDeviceStatusResponse> {
    if (typeof params.nonce !== 'string' || !/^[A-Za-z0-9._:-]{8,128}$/.test(params.nonce)) {
      throw Error('BROKER_STATUS_NONCE_INVALID');
    }
    if (typeof params.workerId !== 'string' || !WORKER_RE.test(params.workerId)) {
      throw Error('BROKER_STATUS_PARAMS_INVALID');
    }
    const status = await this.config.enrollmentRegistry.inspectDeviceStatus({
      workerId: params.workerId,
      deviceId: params.deviceId,
      installationId: params.installationId,
      repository: params.repository,
      enrollmentGeneration: params.enrollmentGeneration,
    });
    const now = this.nowMs();
    const payload: DeviceStatusPayload = {
      version: 1,
      broker_issuer: this.config.brokerIssuer,
      worker_id: params.workerId,
      device_id: params.deviceId ?? status.device?.device_id ?? '',
      installation_id: params.installationId ?? status.device?.installation_id ?? '',
      repository: params.repository ?? status.device?.authorized_repository_scope[0] ?? '',
      enrollment_generation:
        typeof params.enrollmentGeneration === 'number' ? params.enrollmentGeneration : null,
      actual_enrollment_generation: status.device?.enrollment_generation ?? null,
      status: status.status,
      revoked: status.revoked,
      code: status.code ?? null,
      nonce: params.nonce,
      issued_at: new Date(now).toISOString(),
      expires_at: new Date(now + 30_000).toISOString(),
    };
    if (payload.status === 'ACTIVE') {
      if (
        payload.revoked !== false ||
        !status.device ||
        !WORKER_RE.test(payload.worker_id) ||
        payload.worker_id !== status.device.worker_id ||
        !DEVICE_ID_RE.test(payload.device_id) ||
        payload.device_id !== status.device.device_id ||
        !INSTALL_RE.test(payload.installation_id) ||
        payload.installation_id !== status.device.installation_id ||
        !isValidRepoName(payload.repository) ||
        !status.device.authorized_repository_scope.some((r) => r.toLowerCase() === payload.repository.toLowerCase()) ||
        typeof payload.actual_enrollment_generation !== 'number' ||
        !Number.isSafeInteger(payload.actual_enrollment_generation) ||
        payload.actual_enrollment_generation < 1 ||
        (payload.enrollment_generation !== null &&
          payload.enrollment_generation !== payload.actual_enrollment_generation)
      ) {
        throw Error('BROKER_STATUS_PAYLOAD_INVALID');
      }
    }
    return this.withFileLock(async () => {
      const state = await this.readOrInitState();
      const usedStatusNonces = state.usedStatusNonces ?? [];
      if (usedStatusNonces.includes(params.nonce)) {
        throw Error('BROKER_NONCE_REPLAYED');
      }
      state.usedStatusNonces = [...usedStatusNonces, params.nonce].slice(-2048);
      const signingKey = state.signingKeys.find((k) => k.role === 'EXECUTION' && k.status === 'ACTIVE');
      if (!signingKey) throw Error('BROKER_SIGNING_KEY_MISSING');
      const signingInput = DEVICE_STATUS_DOMAIN + canonicalJson(payload as unknown as Record<string, unknown>);
      const sig = cryptoSign(null, Buffer.from(signingInput, 'utf8'), signingKey.private_key_pem);
      await this.atomicWrite(state);
      return {
        payload,
        signature_alg: 'Ed25519',
        key_id: signingKey.key_id,
        signature_b64url: sig.toString('base64url'),
      };
    });
  }

  async getSignedTokenStatus(params: {
    token: string;
    nonce: string;
  }): Promise<SignedTokenStatusResponse> {
    if (typeof params.nonce !== 'string' || !/^[A-Za-z0-9._:-]{8,128}$/.test(params.nonce)) {
      throw Error('BROKER_STATUS_NONCE_INVALID');
    }
    if (typeof params.token !== 'string' || !params.token.trim()) {
      throw Error('BROKER_TOKEN_INVALID');
    }
    const tokenSha = createHash('sha256').update(params.token, 'utf8').digest('hex');
    const now = this.nowMs();
    return this.withFileLock(async () => {
      const state = await this.readOrInitState();
      const usedStatusNonces = state.usedStatusNonces ?? [];
      if (usedStatusNonces.includes(params.nonce)) {
        throw Error('BROKER_NONCE_REPLAYED');
      }
      state.usedStatusNonces = [...usedStatusNonces, params.nonce].slice(-2048);

      const rec = state.issuedTokens?.[tokenSha];
      const inRevokedList = state.revokedTokens.includes(tokenSha);

      let status: TokenStatusPayload['status'];
      let revoked: boolean;
      if (inRevokedList || rec?.revoked === true) {
        status = 'REVOKED';
        revoked = true;
      } else if (!rec) {
        // SEC-04: Never sign ACTIVE for unissued, foreign, or unknown tokens
        status = 'UNKNOWN';
        revoked = true;
      } else if (now >= rec.usage_expires_at_ms || now >= rec.provider_expires_at_ms) {
        status = 'EXPIRED';
        revoked = true;
      } else {
        status = 'ACTIVE';
        revoked = false;
      }

      const payload: TokenStatusPayload = {
        version: 1,
        broker_issuer: this.config.brokerIssuer,
        token_sha256: tokenSha,
        status,
        revoked,
        nonce: params.nonce,
        issued_at: new Date(now).toISOString(),
        expires_at: new Date(now + 30_000).toISOString(),
      };
      const signingKey = state.signingKeys.find((k) => k.role === 'EXECUTION' && k.status === 'ACTIVE');
      if (!signingKey) throw Error('BROKER_SIGNING_KEY_MISSING');
      const signingInput = TOKEN_STATUS_DOMAIN + canonicalJson(payload as unknown as Record<string, unknown>);
      const sig = cryptoSign(null, Buffer.from(signingInput, 'utf8'), signingKey.private_key_pem);
      await this.atomicWrite(state);
      return {
        payload,
        signature_alg: 'Ed25519',
        key_id: signingKey.key_id,
        signature_b64url: sig.toString('base64url'),
      };
    });
  }

  async revokeIssuedToken(
    token: string,
    options: { localOnly?: boolean } = {},
  ): Promise<{
    ok: boolean;
    token_sha256: string;
    local_revoked: boolean;
    provider_revoked: boolean;
    provider_status?: number;
  }> {
    if (typeof token !== 'string' || !token.trim()) {
      throw Error('BROKER_TOKEN_INVALID');
    }
    const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      if (!state.revokedTokens.includes(tokenHash)) {
        state.revokedTokens.push(tokenHash);
      }
      if (state.issuedTokens?.[tokenHash]) {
        state.issuedTokens[tokenHash]!.revoked = true;
      }
      await this.atomicWrite(state);
    });

    if (options.localOnly === true) {
      await this.withFileLock(async () => {
        const state = await this.readOrInitState();
        this.appendAudit(state, {
          operation: 'REVOKE_TOKEN',
          outcome: 'ALLOWED',
          code: 'BROKER_TOKEN_REVOKED_LOCAL_ONLY',
        });
        await this.atomicWrite(state);
      });
      return {
        ok: true,
        token_sha256: tokenHash,
        local_revoked: true,
        provider_revoked: false,
      };
    }

    const prov = await this.config.githubAppAdapter.revokeInstallationTokenAtProvider(token);
    await this.withFileLock(async () => {
      const state = await this.readOrInitState();
      if (state.issuedTokens?.[tokenHash] && prov.revokedAtProvider) {
        state.issuedTokens[tokenHash]!.provider_revoked = true;
      }
      this.appendAudit(state, {
        operation: 'REVOKE_TOKEN',
        outcome: 'ALLOWED',
        code: prov.revokedAtProvider ? 'BROKER_TOKEN_REVOKED_AT_PROVIDER' : 'BROKER_TOKEN_REVOKED_LOCAL_PROVIDER_UNKNOWN',
      });
      await this.atomicWrite(state);
    });
    return {
      ok: true,
      token_sha256: tokenHash,
      local_revoked: true,
      provider_revoked: prov.revokedAtProvider,
      provider_status: prov.status,
    };
  }

  async isTokenRevoked(token: string): Promise<boolean> {
    const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');
    const now = this.nowMs();
    return this.withFileLock(async () => {
      const state = await this.readOrInitState();
      if (state.revokedTokens.includes(tokenHash)) return true;
      const rec = state.issuedTokens?.[tokenHash];
      if (!rec || rec.revoked) return true;
      if (now >= rec.usage_expires_at_ms || now >= rec.provider_expires_at_ms) return true;
      return false;
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
