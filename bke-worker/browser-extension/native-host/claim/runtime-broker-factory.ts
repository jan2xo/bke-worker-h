/**
 * F4.1 Operational Runtime Dependency Factory & Authenticated Trusted-Broker Client.
 *
 * Bridges `controller-daemon.ts` (`runCli('start')`) to production-shaped runtime
 * dependencies without importing test fixtures or weakening default-OFF locks:
 * - Loads owner-controlled private device credentials (0o600, O_NOFOLLOW, EC P-256)
 * - Verifies owner policy thumbprints & broker Ed25519 SPKI verification keys
 * - Wires authenticated signed revocation (`checkDeviceRevocation`), `ManagedTokenProvider`
 *   (read-only `contents: 'read'`), and `ServerMediatedLedgerClient` (4-op CAS)
 * - Fails closed before opening execution ingress on missing/inconsistent/V1/static configs.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { constants, lstat, open } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import type { ControllerDaemonDeps, ControllerRuntimeConfig } from './controller-daemon.js';
import type { DeviceRevocationCheckResult, DeviceRevocationState } from './github-app-harness.js';
import type {
  ServerMediatedLedgerClient,
  ServerMediatedLedgerOpInput,
  ServerMediatedLedgerOpResult,
} from './github-f1-ledger.js';
import {
  ManagedTokenProvider,
  type IssuedScopedToken,
  type TokenBrokerClient,
  type TokenBrokerRequest,
  type TokenRevocationStatus,
} from './token-lifecycle.js';

const DEVICE_POP_DOMAIN = 'BKE_DESKTOP_DEVICE_POP_V1\n';
const DEVICE_STATUS_DOMAIN = 'BKE_DEVICE_STATUS_V1\n';
const TOKEN_STATUS_DOMAIN = 'BKE_TOKEN_STATUS_V1\n';
const LEDGER_OP_DIGEST_DOMAIN = 'BKE_MEDIATED_LEDGER_OP_V1\n';

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const WORKER_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const INSTALL_RE = /^[0-9]{1,20}$/;
const DEVICE_ID_RE = /^[A-Za-z0-9_.:-]{4,128}$/;
const SHA256_HEX_RE = /^[a-f0-9]{64}$/;
const SHA40_RE = /^[a-f0-9]{40}$/;
const STATUS_NONCE_RE = /^[A-Za-z0-9._:-]{8,128}$/;
const ED25519_SIG_B64URL_RE = /^[A-Za-z0-9_-]{86}$/;
const ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const MAX_SEEN_STATUS_NONCES = 4_096;

const DEVICE_STATUS_REQUIRED_KEYS = [
  'actual_enrollment_generation',
  'broker_issuer',
  'device_id',
  'enrollment_generation',
  'expires_at',
  'installation_id',
  'issued_at',
  'nonce',
  'repository',
  'revoked',
  'status',
  'version',
  'worker_id',
] as const;

const TOKEN_STATUS_REQUIRED_KEYS = [
  'broker_issuer',
  'expires_at',
  'issued_at',
  'nonce',
  'revoked',
  'status',
  'token_sha256',
  'version',
] as const;

const ALLOWED_TOKEN_PERM_SCOPES = new Set(['contents', 'pull_requests', 'checks']);

function isValidRepoName(value: unknown): value is string {
  if (typeof value !== 'string' || !REPO_RE.test(value)) return false;
  const parts = value.split('/');
  return parts.length === 2 && parts[0] !== '.' && parts[0] !== '..' && parts[1] !== '.' && parts[1] !== '..';
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

const ALLOWED_MEDIATED_OPS = new Set([
  'COMMIT_PRE_SEND_FENCE',
  'CONSUME_SEND_CLAIM',
  'RECONCILE_CONVERSATION',
  'MARK_DELIVERY_UNCERTAIN',
]);

function computeLedgerOpDigestHex(op: {
  operation: ServerMediatedLedgerOpInput['operation'];
  repository: string;
  repository_id: number;
  installation_id: string;
  worker_id: string;
  pr_number: number;
  head_sha: string;
  attempt_id: string;
  ref_name: string;
  turn_ref_name?: string;
  expected_parent_sha?: string;
  is_continuation?: boolean;
  commit_message: string;
  tree_sha: string;
}): string {
  if (
    !ALLOWED_MEDIATED_OPS.has(op.operation) ||
    typeof op.repository !== 'string' ||
    typeof op.repository_id !== 'number' ||
    !Number.isSafeInteger(op.repository_id) ||
    typeof op.installation_id !== 'string' ||
    typeof op.worker_id !== 'string' ||
    op.worker_id.length === 0 ||
    typeof op.pr_number !== 'number' ||
    !Number.isSafeInteger(op.pr_number) ||
    typeof op.head_sha !== 'string' ||
    typeof op.attempt_id !== 'string' ||
    typeof op.ref_name !== 'string' ||
    typeof op.commit_message !== 'string' ||
    typeof op.tree_sha !== 'string'
  ) {
    throw Error('BROKER_LEDGER_OP_INVALID');
  }
  if (
    op.turn_ref_name !== undefined &&
    (typeof op.turn_ref_name !== 'string' || op.turn_ref_name.length === 0)
  ) {
    throw Error('BROKER_LEDGER_OP_INVALID');
  }
  if (
    op.expected_parent_sha !== undefined &&
    (typeof op.expected_parent_sha !== 'string' || op.expected_parent_sha.length === 0)
  ) {
    throw Error('BROKER_LEDGER_OP_INVALID');
  }
  if (op.is_continuation !== undefined && typeof op.is_continuation !== 'boolean') {
    throw Error('BROKER_LEDGER_OP_INVALID');
  }
  const canonical = {
    attempt_id: op.attempt_id,
    commit_message: op.commit_message,
    expected_parent_sha: op.expected_parent_sha === undefined ? null : op.expected_parent_sha,
    head_sha: op.head_sha,
    installation_id: op.installation_id,
    is_continuation: op.is_continuation === undefined ? null : op.is_continuation,
    operation: op.operation,
    pr_number: op.pr_number,
    ref_name: op.ref_name,
    repository: op.repository,
    repository_id: op.repository_id,
    tree_sha: op.tree_sha,
    turn_ref_name: op.turn_ref_name === undefined ? null : op.turn_ref_name,
    worker_id: op.worker_id,
  };
  return createHash('sha256')
    .update(LEDGER_OP_DIGEST_DOMAIN + JSON.stringify(canonical), 'utf8')
    .digest('hex');
}

export interface OwnerDeviceCredentials {
  version: 1;
  device_id: string;
  worker_id: string;
  installation_id: string;
  repository: string;
  repository_id?: number;
  enrollment_generation: number;
  device_public_key_pem: string;
  device_private_key_pem: string;
  public_key_sha256: string;
  browser_profile_identity?: string;
  native_bridge_identity?: string;
  extension_public_key_sha256?: string;
  broker_issuer?: string;
  broker_base_url?: string;
  broker_public_keys_by_id?: Record<string, string>;
  halt_public_keys_by_id?: Record<string, string>;
}

export interface HttpTrustedBrokerConfig {
  brokerBaseUrl: string;
  deviceId: string;
  enrollmentGeneration: number;
  devicePublicKeyPem: string;
  devicePrivateKeyPem: string;
  brokerPublicKeysById: ReadonlyMap<string, string>;
  expectedBrokerIssuer: string;
  repository: string;
  repositoryId?: number;
  installationId: string;
  workerId: string;
  timeoutMs?: number;
  nowMs?: () => number;
}

export interface RuntimeDependencyBundle {
  config: ControllerRuntimeConfig;
  deps: ControllerDaemonDeps;
  brokerClient: HttpTrustedBrokerClient | null;
  credentials: OwnerDeviceCredentials | null;
}

function canonicalJson(value: Record<string, unknown>): string {
  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    ordered[key] = value[key];
  }
  return JSON.stringify(ordered);
}

export function assertSafeBrokerBaseUrl(rawUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw Error('DAEMON_BROKER_URL_INVALID');
  }
  const host = parsed.hostname.toLowerCase();
  const isLoopback = host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopback)) {
    throw Error('DAEMON_BROKER_URL_INSECURE');
  }
  if (parsed.username || parsed.password) {
    throw Error('DAEMON_BROKER_URL_CREDENTIALS_FORBIDDEN');
  }
  return parsed.toString().replace(/\/+$/, '');
}

async function readOwnerPrivateJsonFile(
  filePath: string,
  missingCode: string,
  errPrefix: string,
): Promise<Record<string, unknown>> {
  if (!filePath || !isAbsolute(filePath)) {
    throw Error(`${errPrefix}_PATH_NOT_ABSOLUTE`);
  }
  const parentDir = dirname(filePath);
  let parentStat;
  try {
    parentStat = await lstat(parentDir);
  } catch {
    throw Error(missingCode);
  }
  if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) {
    throw Error(`${errPrefix}_PARENT_INVALID`);
  }
  if ((parentStat.mode & 0o022) !== 0 && (parentStat.mode & 0o1000) === 0) {
    throw Error(`${errPrefix}_PARENT_UNSAFE_MODE`);
  }

  let handle;
  try {
    handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') throw Error(missingCode);
    if (code === 'ELOOP') throw Error(`${errPrefix}_SYMLINK_FORBIDDEN`);
    throw Error(`${errPrefix}_UNREADABLE`);
  }

  let rawText: string;
  try {
    const st = await handle.stat();
    if (!st.isFile()) {
      throw Error(`${errPrefix}_NOT_REGULAR_FILE`);
    }
    if ((st.mode & 0o077) !== 0) {
      throw Error(`${errPrefix}_UNSAFE_MODE`);
    }
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
      throw Error(`${errPrefix}_OWNER_MISMATCH`);
    }
    rawText = await handle.readFile({ encoding: 'utf8' });
  } finally {
    await handle.close();
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw Error(`${errPrefix}_INVALID_JSON`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw Error(`${errPrefix}_INVALID`);
  }
  return parsed as Record<string, unknown>;
}

function assertEd25519PublicPem(pem: unknown, errCode: string): string {
  if (typeof pem !== 'string' || !pem.includes('BEGIN PUBLIC KEY')) {
    throw Error(errCode);
  }
  try {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== 'ed25519') {
      throw Error(errCode);
    }
    return pem.trim();
  } catch {
    throw Error(errCode);
  }
}

function validateOptionalPemMap(raw: unknown, errCode: string): Record<string, string> | undefined {
  if (raw === undefined) return undefined;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw Error(errCode);
  }
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!k || k.length > 128) throw Error(errCode);
    out[k] = assertEd25519PublicPem(v, errCode);
  }
  return out;
}

export async function loadOwnerDeviceCredentialsFile(filePath: string): Promise<OwnerDeviceCredentials> {
  const raw = await readOwnerPrivateJsonFile(
    filePath,
    'DAEMON_DEVICE_CREDENTIALS_MISSING',
    'DAEMON_DEVICE_CREDENTIALS',
  );
  if (
    raw.version !== 1 ||
    typeof raw.device_id !== 'string' ||
    !DEVICE_ID_RE.test(raw.device_id) ||
    typeof raw.worker_id !== 'string' ||
    !WORKER_RE.test(raw.worker_id) ||
    typeof raw.installation_id !== 'string' ||
    !INSTALL_RE.test(raw.installation_id) ||
    typeof raw.repository !== 'string' ||
    !REPO_RE.test(raw.repository) ||
    typeof raw.enrollment_generation !== 'number' ||
    !Number.isSafeInteger(raw.enrollment_generation) ||
    raw.enrollment_generation < 1 ||
    typeof raw.device_public_key_pem !== 'string' ||
    typeof raw.device_private_key_pem !== 'string'
  ) {
    throw Error('DAEMON_DEVICE_CREDENTIALS_INVALID');
  }

  let computedSha256: string;
  try {
    const pub = createPublicKey(raw.device_public_key_pem);
    const priv = createPrivateKey(raw.device_private_key_pem);
    if (
      pub.asymmetricKeyType !== 'ec' ||
      pub.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
      priv.asymmetricKeyType !== 'ec' ||
      priv.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
    ) {
      throw Error('DAEMON_DEVICE_KEY_ALGORITHM_INVALID');
    }
    const pubDer = pub.export({ type: 'spki', format: 'der' });
    const derivedDer = createPublicKey(priv).export({ type: 'spki', format: 'der' });
    if (!pubDer.equals(derivedDer)) {
      throw Error('DAEMON_DEVICE_KEYPAIR_MISMATCH');
    }
    computedSha256 = createHash('sha256').update(pubDer).digest('hex');
  } catch (err) {
    const msg = err instanceof Error ? err.message : '';
    if (msg.startsWith('DAEMON_DEVICE_')) throw err;
    throw Error('DAEMON_DEVICE_KEY_INVALID');
  }

  if (raw.public_key_sha256 !== undefined) {
    if (typeof raw.public_key_sha256 !== 'string' || raw.public_key_sha256 !== computedSha256) {
      throw Error('DAEMON_DEVICE_KEY_THUMBPRINT_MISMATCH');
    }
  }
  if (
    raw.repository_id !== undefined &&
    (typeof raw.repository_id !== 'number' || !Number.isSafeInteger(raw.repository_id) || raw.repository_id <= 0)
  ) {
    throw Error('DAEMON_DEVICE_CREDENTIALS_INVALID');
  }
  if (raw.broker_issuer !== undefined && (typeof raw.broker_issuer !== 'string' || raw.broker_issuer.length < 4)) {
    throw Error('DAEMON_DEVICE_CREDENTIALS_INVALID');
  }
  for (const hexField of ['browser_profile_identity', 'native_bridge_identity', 'extension_public_key_sha256'] as const) {
    if (raw[hexField] !== undefined && (typeof raw[hexField] !== 'string' || !SHA256_HEX_RE.test(raw[hexField] as string))) {
      throw Error('DAEMON_DEVICE_CREDENTIALS_INVALID');
    }
  }
  const safeBaseUrl =
    raw.broker_base_url !== undefined
      ? typeof raw.broker_base_url === 'string'
        ? assertSafeBrokerBaseUrl(raw.broker_base_url)
        : (() => {
            throw Error('DAEMON_DEVICE_CREDENTIALS_INVALID');
          })()
      : undefined;

  return {
    version: 1,
    device_id: raw.device_id,
    worker_id: raw.worker_id,
    installation_id: raw.installation_id,
    repository: raw.repository,
    repository_id: raw.repository_id as number | undefined,
    enrollment_generation: raw.enrollment_generation,
    device_public_key_pem: raw.device_public_key_pem,
    device_private_key_pem: raw.device_private_key_pem,
    public_key_sha256: computedSha256,
    browser_profile_identity: raw.browser_profile_identity as string | undefined,
    native_bridge_identity: raw.native_bridge_identity as string | undefined,
    extension_public_key_sha256: raw.extension_public_key_sha256 as string | undefined,
    broker_issuer: raw.broker_issuer as string | undefined,
    broker_base_url: safeBaseUrl,
    broker_public_keys_by_id: validateOptionalPemMap(raw.broker_public_keys_by_id, 'DAEMON_BROKER_PUBLIC_KEY_INVALID'),
    halt_public_keys_by_id: validateOptionalPemMap(raw.halt_public_keys_by_id, 'DAEMON_BROKER_PUBLIC_KEY_INVALID'),
  };
}

export async function validateOwnerPolicyAgainstDevice(
  policyPath: string,
  expectedWorkerId: string,
  credentials: Pick<
    OwnerDeviceCredentials,
    'browser_profile_identity' | 'native_bridge_identity' | 'extension_public_key_sha256'
  >,
  nowMs: () => number = Date.now,
): Promise<void> {
  const policy = await readOwnerPrivateJsonFile(
    policyPath,
    'DAEMON_NATIVE_POLICY_MISSING',
    'DAEMON_NATIVE_POLICY',
  );
  if (
    policy.version !== 1 ||
    typeof policy.worker_id !== 'string' ||
    typeof policy.public_key_sha256 !== 'string' ||
    !SHA256_HEX_RE.test(policy.public_key_sha256)
  ) {
    throw Error('DAEMON_NATIVE_POLICY_INVALID');
  }
  if (policy.worker_id !== expectedWorkerId) {
    throw Error('DAEMON_POLICY_WORKER_MISMATCH');
  }
  if (credentials.extension_public_key_sha256 && policy.public_key_sha256 !== credentials.extension_public_key_sha256) {
    throw Error('DAEMON_POLICY_DEVICE_KEY_MISMATCH');
  }
  if (credentials.browser_profile_identity && policy.profile_binding_sha256 !== credentials.browser_profile_identity) {
    throw Error('DAEMON_POLICY_PROFILE_MISMATCH');
  }
  const resources =
    policy.resources && typeof policy.resources === 'object' && !Array.isArray(policy.resources)
      ? (policy.resources as Record<string, unknown>)
      : null;
  if (credentials.native_bridge_identity && resources?.bridge_identity_sha256 !== credentials.native_bridge_identity) {
    throw Error('DAEMON_POLICY_BRIDGE_IDENTITY_MISMATCH');
  }
  if (typeof policy.expires_at_ms === 'number' && policy.expires_at_ms > 0 && nowMs() >= policy.expires_at_ms) {
    throw Error('DAEMON_NATIVE_POLICY_EXPIRED');
  }
}

export class HttpTrustedBrokerClient implements TokenBrokerClient, ServerMediatedLedgerClient {
  readonly kind = 'REMOTE_OWNER_CERTIFIED_BROKER' as const;
  private readonly brokerBaseUrl: string;
  private readonly nowMs: () => number;
  private readonly seenStatusNonces = new Set<string>();

  constructor(private readonly config: HttpTrustedBrokerConfig) {
    this.brokerBaseUrl = assertSafeBrokerBaseUrl(config.brokerBaseUrl);
    if (!config.expectedBrokerIssuer || config.brokerPublicKeysById.size === 0) {
      throw Error('DAEMON_BROKER_PUBLIC_KEYS_MISSING');
    }
    if (
      !DEVICE_ID_RE.test(config.deviceId) ||
      !WORKER_RE.test(config.workerId) ||
      !INSTALL_RE.test(config.installationId) ||
      !isValidRepoName(config.repository) ||
      !Number.isSafeInteger(config.enrollmentGeneration) ||
      config.enrollmentGeneration < 1
    ) {
      throw Error('DAEMON_V2_BINDINGS_INCOMPLETE');
    }
    this.nowMs = config.nowMs ?? (() => Date.now());
  }

  private recordStatusNonce(nonce: string): void {
    this.seenStatusNonces.add(nonce);
    if (this.seenStatusNonces.size > MAX_SEEN_STATUS_NONCES) {
      const oldest = this.seenStatusNonces.values().next().value;
      if (oldest !== undefined) this.seenStatusNonces.delete(oldest);
    }
  }

  private signDevicePop(
    purpose: 'MINT_SCOPED_TOKEN' | 'SERVER_MEDIATED_LEDGER_OP',
    repository: string,
    ledgerOpDigestHex?: string,
  ) {
    const now = this.nowMs();
    const payload: Record<string, unknown> = {
      worker_id: this.config.workerId,
      device_id: this.config.deviceId,
      installation_id: this.config.installationId,
      enrollment_generation: this.config.enrollmentGeneration,
      purpose,
      repository,
      nonce: randomBytes(16).toString('base64url'),
      issued_at: new Date(now).toISOString(),
      expires_at: new Date(now + 60_000).toISOString(),
    };
    if (purpose === 'SERVER_MEDIATED_LEDGER_OP') {
      if (!ledgerOpDigestHex || !SHA256_HEX_RE.test(ledgerOpDigestHex)) {
        throw Error('DEVICE_ASSERTION_LEDGER_FIELDS_MISSING');
      }
      payload.ledger_op_sha256 = ledgerOpDigestHex;
    }
    const msg = Buffer.from(DEVICE_POP_DOMAIN + canonicalJson(payload), 'utf8');
    const sig = cryptoSign('sha256', msg, {
      key: this.config.devicePrivateKeyPem,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url');
    return {
      payload,
      signature_alg: 'ES256' as const,
      signature_b64url: sig,
    };
  }

  private verifyBrokerSignedPayload(
    domainPrefix: string,
    signedWrapper: unknown,
  ): { ok: true; payload: Record<string, unknown> } | { ok: false } {
    if (!isPlainObject(signedWrapper)) {
      return { ok: false };
    }
    const wrap = signedWrapper;
    if (
      Object.keys(wrap).sort().join(',') !== 'key_id,payload,signature_alg,signature_b64url' ||
      wrap.signature_alg !== 'Ed25519' ||
      typeof wrap.key_id !== 'string' ||
      wrap.key_id.length === 0 ||
      wrap.key_id.length > 128 ||
      typeof wrap.signature_b64url !== 'string' ||
      !ED25519_SIG_B64URL_RE.test(wrap.signature_b64url) ||
      !isPlainObject(wrap.payload)
    ) {
      return { ok: false };
    }
    const pubPem = this.config.brokerPublicKeysById.get(wrap.key_id);
    if (!pubPem) return { ok: false };
    try {
      const keyObj = createPublicKey(pubPem);
      if (keyObj.asymmetricKeyType !== 'ed25519') return { ok: false };
      const payload = wrap.payload;
      const input = Buffer.from(domainPrefix + canonicalJson(payload), 'utf8');
      const sig = Buffer.from(wrap.signature_b64url, 'base64url');
      if (sig.length !== 64 || !cryptoVerify(null, input, keyObj, sig)) return { ok: false };
      if (payload.version !== 1 || payload.broker_issuer !== this.config.expectedBrokerIssuer) {
        return { ok: false };
      }
      if (
        typeof payload.issued_at !== 'string' ||
        typeof payload.expires_at !== 'string' ||
        !ISO8601_RE.test(payload.issued_at) ||
        !ISO8601_RE.test(payload.expires_at)
      ) {
        return { ok: false };
      }
      const now = this.nowMs();
      const issued = Date.parse(payload.issued_at);
      const expires = Date.parse(payload.expires_at);
      if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > 120_000) {
        return { ok: false };
      }
      if (now < issued - 5_000 || now >= expires) {
        return { ok: false };
      }
      return { ok: true, payload };
    } catch {
      return { ok: false };
    }
  }

  private async postJsonWithTimeout(
    path: string,
    body: unknown,
    externalSignal?: AbortSignal,
  ): Promise<{ ok: boolean; status: number; timedOut: boolean; data: Record<string, unknown> | null }> {
    const controller = new AbortController();
    const timeoutMs = this.config.timeoutMs ?? 4_000;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    const onExternalAbort = () => controller.abort();
    externalSignal?.addEventListener('abort', onExternalAbort, { once: true });

    try {
      const res = await globalThis.fetch(`${this.brokerBaseUrl}${path}`, {
        method: 'POST',
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.status >= 300 && res.status < 400) {
        return { ok: false, status: res.status, timedOut: false, data: { code: 'BROKER_REDIRECT_BLOCKED' } };
      }
      const rawData = await res.json().catch(() => null);
      const data = isPlainObject(rawData) ? rawData : null;
      return { ok: res.ok, status: res.status, timedOut: false, data };
    } catch {
      return {
        ok: false,
        status: timedOut ? 504 : 503,
        timedOut,
        data: { code: timedOut ? 'BROKER_TIMEOUT' : 'BROKER_TRANSPORT_UNAVAILABLE' },
      };
    } finally {
      clearTimeout(timer);
      externalSignal?.removeEventListener('abort', onExternalAbort);
    }
  }

  async checkDeviceRevocation(info: {
    workerId: string;
    deviceId?: string;
    installationId?: string;
    repository?: string;
    enrollmentGeneration?: number;
  }): Promise<DeviceRevocationCheckResult> {
    const targetDeviceId = info.deviceId ?? this.config.deviceId;
    const targetInstall = info.installationId ?? this.config.installationId;
    const targetRepo = info.repository ?? this.config.repository;
    const targetGen = info.enrollmentGeneration ?? this.config.enrollmentGeneration;

    if (
      typeof info.workerId !== 'string' ||
      !WORKER_RE.test(info.workerId) ||
      info.workerId !== this.config.workerId ||
      typeof targetDeviceId !== 'string' ||
      !DEVICE_ID_RE.test(targetDeviceId) ||
      targetDeviceId !== this.config.deviceId ||
      typeof targetInstall !== 'string' ||
      !INSTALL_RE.test(targetInstall) ||
      targetInstall !== this.config.installationId ||
      !isValidRepoName(targetRepo) ||
      targetRepo.toLowerCase() !== this.config.repository.toLowerCase() ||
      typeof targetGen !== 'number' ||
      !Number.isSafeInteger(targetGen) ||
      targetGen < 1
    ) {
      return { status: 'UNKNOWN' as DeviceRevocationState, revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
    }

    const nonce = randomBytes(24).toString('base64url');
    const res = await this.postJsonWithTimeout('/v1/enrollment/status', {
      worker_id: info.workerId,
      device_id: targetDeviceId,
      installation_id: targetInstall,
      repository: targetRepo,
      enrollment_generation: targetGen,
      nonce,
    });
    if (!res.ok || !res.data || res.data.ok !== true) {
      return { status: 'UNKNOWN' as DeviceRevocationState, revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
    }
    const verified = this.verifyBrokerSignedPayload(DEVICE_STATUS_DOMAIN, res.data.signed_status);
    if (!verified.ok) {
      return { status: 'UNKNOWN', revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
    }
    const p = verified.payload;

    // Strict exact key-set check (only required 13 keys plus optional 'code')
    const payloadKeysWithoutCode = Object.keys(p)
      .filter((k) => k !== 'code')
      .sort()
      .join(',');
    if (payloadKeysWithoutCode !== DEVICE_STATUS_REQUIRED_KEYS.join(',')) {
      return { status: 'UNKNOWN', revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
    }

    if (
      typeof p.nonce !== 'string' ||
      !STATUS_NONCE_RE.test(p.nonce) ||
      p.nonce !== nonce ||
      this.seenStatusNonces.has(p.nonce) ||
      typeof p.worker_id !== 'string' ||
      p.worker_id !== info.workerId ||
      p.worker_id !== this.config.workerId ||
      typeof p.device_id !== 'string' ||
      p.device_id !== targetDeviceId ||
      p.device_id !== this.config.deviceId ||
      typeof p.installation_id !== 'string' ||
      p.installation_id !== targetInstall ||
      p.installation_id !== this.config.installationId ||
      !isValidRepoName(p.repository) ||
      p.repository.toLowerCase() !== targetRepo.toLowerCase() ||
      p.repository.toLowerCase() !== this.config.repository.toLowerCase() ||
      typeof p.enrollment_generation !== 'number' ||
      !Number.isSafeInteger(p.enrollment_generation) ||
      p.enrollment_generation !== targetGen ||
      typeof p.revoked !== 'boolean'
    ) {
      return { status: 'UNKNOWN', revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
    }
    this.recordStatusNonce(p.nonce);

    if (p.status === 'REVOKED' && p.revoked === true) {
      if (p.code !== undefined && p.code !== null && typeof p.code !== 'string') {
        return { status: 'UNKNOWN', revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
      }
      if (
        p.actual_enrollment_generation !== null &&
        (typeof p.actual_enrollment_generation !== 'number' ||
          !Number.isSafeInteger(p.actual_enrollment_generation) ||
          p.actual_enrollment_generation < 1)
      ) {
        return { status: 'UNKNOWN', revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
      }
      return {
        status: 'REVOKED',
        revoked: true,
        code: typeof p.code === 'string' && p.code ? p.code : 'EXEC_REQ_DEVICE_REVOKED',
      };
    }

    if (
      p.status === 'ACTIVE' &&
      p.revoked === false &&
      (p.code === undefined || p.code === null) &&
      typeof p.actual_enrollment_generation === 'number' &&
      Number.isSafeInteger(p.actual_enrollment_generation) &&
      p.actual_enrollment_generation === targetGen
    ) {
      return { status: 'ACTIVE', revoked: false };
    }

    return { status: 'UNKNOWN', revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
  }

  async issueToken(request: TokenBrokerRequest): Promise<IssuedScopedToken> {
    if (request.workerId !== this.config.workerId) {
      throw Error('TOKEN_WORKER_MISMATCH');
    }
    if (request.installationId !== this.config.installationId) {
      throw Error('TOKEN_INSTALLATION_MISMATCH');
    }
    if (
      !isValidRepoName(request.repository) ||
      request.repository.toLowerCase() !== this.config.repository.toLowerCase()
    ) {
      throw Error('TOKEN_REPOSITORY_SCOPE_MISMATCH');
    }
    if (
      this.config.repositoryId !== undefined &&
      request.repositoryId !== undefined &&
      request.repositoryId !== this.config.repositoryId
    ) {
      throw Error('TOKEN_REPOSITORY_ID_MISMATCH');
    }
    if (!isPlainObject(request.requestedPermissions)) {
      throw Error('TOKEN_PERMISSION_ELEVATION_FORBIDDEN');
    }
    for (const [scope, level] of Object.entries(request.requestedPermissions)) {
      if (scope === 'contents' && level === 'write') {
        throw Error('TOKEN_DESKTOP_WRITE_TOKEN_FORBIDDEN');
      }
      if (!ALLOWED_TOKEN_PERM_SCOPES.has(scope)) {
        if (level !== 'none') throw Error('TOKEN_PERMISSION_ELEVATION_FORBIDDEN');
        continue;
      }
      if (level !== 'read' && level !== 'none') {
        throw Error('TOKEN_PERMISSION_ELEVATION_FORBIDDEN');
      }
    }

    const assertion = this.signDevicePop('MINT_SCOPED_TOKEN', request.repository);
    const clampedPerms: Record<string, 'read'> = {
      contents: 'read',
      pull_requests: 'read',
      checks: 'read',
    };
    const res = await this.postJsonWithTimeout(
      '/v1/broker/tokens',
      {
        repository: request.repository,
        repository_id: request.repositoryId ?? this.config.repositoryId ?? 0,
        installation_id: request.installationId,
        worker_id: request.workerId,
        requested_permissions: clampedPerms,
        device_assertion: assertion,
      },
      request.signal,
    );
    if (res.timedOut) {
      throw Error('TOKEN_BROKER_TIMEOUT');
    }
    if (!res.ok || !res.data || res.data.ok !== true || !isPlainObject(res.data.token)) {
      const code = typeof res.data?.code === 'string' ? res.data.code : 'TOKEN_BROKER_UNAVAILABLE';
      if (code === 'BROKER_DEVICE_REVOKED' || code === 'DEVICE_REVOKED') throw Error('TOKEN_DEVICE_REVOKED');
      if (code.includes('REVOKED')) throw Error('TOKEN_REVOKED');
      if (code === 'BROKER_DESKTOP_WRITE_TOKEN_FORBIDDEN') throw Error('TOKEN_DESKTOP_WRITE_TOKEN_FORBIDDEN');
      if (
        code.includes('ASSERTION') ||
        code.includes('SIGNATURE') ||
        code.includes('GENERATION') ||
        code.includes('DEVICE_')
      ) {
        throw Error('TOKEN_CREDENTIAL_INVALID');
      }
      if (code.includes('PERMISSION') || code.includes('MISMATCH')) {
        throw Error(`TOKEN_${code}`);
      }
      if (code === 'BROKER_REDIRECT_BLOCKED') {
        throw Error('TOKEN_BROKER_REDIRECT_BLOCKED');
      }
      throw Error('TOKEN_BROKER_UNAVAILABLE');
    }

    const rawTok = res.data.token;
    const tokStr = typeof rawTok.token === 'string' ? rawTok.token.trim() : '';
    if (tokStr.length < 8) {
      throw Error('TOKEN_VALUE_INVALID');
    }
    if (rawTok.tokenType !== 'installation') {
      throw Error('TOKEN_TYPE_INVALID');
    }
    if (rawTok.installationId !== this.config.installationId) {
      throw Error('TOKEN_INSTALLATION_MISMATCH');
    }
    if (
      !Array.isArray(rawTok.repositories) ||
      rawTok.repositories.length !== 1 ||
      !isValidRepoName(rawTok.repositories[0]) ||
      rawTok.repositories[0].toLowerCase() !== this.config.repository.toLowerCase()
    ) {
      throw Error('TOKEN_REPOSITORY_SCOPE_MISMATCH');
    }
    const expectedRepoId = this.config.repositoryId ?? request.repositoryId;
    if (
      typeof rawTok.repositoryId !== 'number' ||
      !Number.isSafeInteger(rawTok.repositoryId) ||
      rawTok.repositoryId <= 0 ||
      (expectedRepoId !== undefined && expectedRepoId > 0 && rawTok.repositoryId !== expectedRepoId)
    ) {
      throw Error('TOKEN_REPOSITORY_ID_MISMATCH');
    }
    const now = this.nowMs();
    if (
      typeof rawTok.issuedAtMs !== 'number' ||
      typeof rawTok.expiresAtMs !== 'number' ||
      !Number.isFinite(rawTok.issuedAtMs) ||
      !Number.isFinite(rawTok.expiresAtMs) ||
      rawTok.expiresAtMs <= rawTok.issuedAtMs ||
      rawTok.issuedAtMs > now + 5_000 ||
      now >= rawTok.expiresAtMs
    ) {
      throw Error('TOKEN_TIMESTAMPS_INVALID');
    }
    if (!isPlainObject(rawTok.permissions)) {
      throw Error('TOKEN_PERMISSIONS_INVALID');
    }
    const permEntries = Object.entries(rawTok.permissions);
    if (permEntries.length === 0) {
      throw Error('TOKEN_PERMISSIONS_INVALID');
    }
    const cleanPerms: Record<string, string> = {};
    for (const [scope, level] of permEntries) {
      if ((scope === 'contents' || scope === 'push') && level === 'write') {
        throw Error('TOKEN_DESKTOP_WRITE_TOKEN_FORBIDDEN');
      }
      if (!ALLOWED_TOKEN_PERM_SCOPES.has(scope) || level !== 'read') {
        throw Error('TOKEN_PERMISSION_ELEVATION_FORBIDDEN');
      }
      cleanPerms[scope] = level;
    }

    return {
      token: tokStr,
      tokenType: 'installation',
      installationId: rawTok.installationId,
      repositoryId: rawTok.repositoryId,
      repositories: [rawTok.repositories[0]],
      permissions: cleanPerms,
      issuedAtMs: rawTok.issuedAtMs,
      expiresAtMs: rawTok.expiresAtMs,
      ...(typeof rawTok.usageExpiresAtMs === 'number' ? { usageExpiresAtMs: rawTok.usageExpiresAtMs } : {}),
      ...(typeof rawTok.providerExpiresAtMs === 'number'
        ? { providerExpiresAtMs: rawTok.providerExpiresAtMs }
        : {}),
    };
  }

  async checkTokenStatus(
    token: string,
  ): Promise<{ status: TokenRevocationStatus; code?: string }> {
    if (typeof token !== 'string' || !token.trim()) {
      return { status: 'UNKNOWN', code: 'TOKEN_REVOCATION_UNAVAILABLE' };
    }
    const nonce = randomBytes(24).toString('base64url');
    const tokenSha = createHash('sha256').update(token, 'utf8').digest('hex');
    const res = await this.postJsonWithTimeout('/v1/broker/token-status', { token, nonce });
    if (!res.ok || !res.data || res.data.ok !== true) {
      return { status: 'UNKNOWN', code: 'TOKEN_REVOCATION_UNAVAILABLE' };
    }
    const verified = this.verifyBrokerSignedPayload(TOKEN_STATUS_DOMAIN, res.data.signed_status);
    if (!verified.ok) {
      return { status: 'UNKNOWN', code: 'TOKEN_REVOCATION_UNAVAILABLE' };
    }
    const p = verified.payload;
    if (Object.keys(p).sort().join(',') !== TOKEN_STATUS_REQUIRED_KEYS.join(',')) {
      return { status: 'UNKNOWN', code: 'TOKEN_REVOCATION_UNAVAILABLE' };
    }
    if (
      typeof p.nonce !== 'string' ||
      !STATUS_NONCE_RE.test(p.nonce) ||
      p.nonce !== nonce ||
      this.seenStatusNonces.has(p.nonce) ||
      typeof p.token_sha256 !== 'string' ||
      !SHA256_HEX_RE.test(p.token_sha256) ||
      p.token_sha256 !== tokenSha ||
      typeof p.revoked !== 'boolean'
    ) {
      return { status: 'UNKNOWN', code: 'TOKEN_REVOCATION_UNAVAILABLE' };
    }
    this.recordStatusNonce(p.nonce);

    if (p.status === 'REVOKED' && p.revoked === true) {
      return { status: 'REVOKED', code: 'TOKEN_REVOKED' };
    }
    if (p.status === 'EXPIRED' && p.revoked === true) {
      return { status: 'EXPIRED', code: 'TOKEN_EXPIRED' };
    }
    if (p.status === 'UNKNOWN' && p.revoked === true) {
      return { status: 'UNKNOWN', code: 'TOKEN_UNKNOWN_OR_UNISSUED' };
    }
    if (p.status === 'ACTIVE' && p.revoked === false) {
      return { status: 'ACTIVE' };
    }
    return { status: 'UNKNOWN', code: 'TOKEN_REVOCATION_UNAVAILABLE' };
  }

  async isRevoked(token: string): Promise<boolean> {
    const res = await this.checkTokenStatus(token);
    if (res.status === 'REVOKED') return true;
    if (res.status === 'ACTIVE') return false;
    throw Error(res.code ?? 'TOKEN_REVOCATION_UNAVAILABLE');
  }

  async executeLedgerOp(input: ServerMediatedLedgerOpInput): Promise<ServerMediatedLedgerOpResult> {
    if (!ALLOWED_MEDIATED_OPS.has(input.operation)) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_ARBITRARY_PROXY_FORBIDDEN' };
    }
    if (
      input.workerId !== this.config.workerId ||
      input.installationId !== this.config.installationId ||
      !isValidRepoName(input.repository) ||
      input.repository.toLowerCase() !== this.config.repository.toLowerCase() ||
      (this.config.repositoryId !== undefined && input.repositoryId !== this.config.repositoryId)
    ) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_DEVICE_SCOPE_MISMATCH' };
    }

    const ledgerOp = {
      operation: input.operation,
      repository: input.repository,
      repository_id: input.repositoryId,
      installation_id: input.installationId,
      worker_id: input.workerId,
      pr_number: input.prNumber,
      head_sha: input.headSha,
      attempt_id: input.attemptId,
      ref_name: input.refName,
      ...(input.turnRefName !== undefined ? { turn_ref_name: input.turnRefName } : {}),
      ...(input.expectedParentSha !== undefined ? { expected_parent_sha: input.expectedParentSha } : {}),
      ...(input.isContinuation !== undefined ? { is_continuation: input.isContinuation } : {}),
      commit_message: input.commitMessage,
      tree_sha: input.treeSha,
    };
    let digestHex: string;
    try {
      digestHex = computeLedgerOpDigestHex(ledgerOp);
    } catch {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_OP_INVALID' };
    }
    const assertion = this.signDevicePop('SERVER_MEDIATED_LEDGER_OP', input.repository, digestHex);
    const res = await this.postJsonWithTimeout('/v1/broker/ledger-ops', {
      worker_id: input.workerId,
      device_assertion: assertion,
      ledger_op: ledgerOp,
    });
    if (!res.data) {
      return { ok: false, status: 'UNCERTAIN', code: 'BROKER_LEDGER_TRANSPORT_UNAVAILABLE' };
    }
    const status = res.data.status;
    if (
      res.ok &&
      res.data.ok === true &&
      (status === 'COMMITTED' || status === 'ALREADY_EXISTS')
    ) {
      if (typeof res.data.sha !== 'string' || !SHA40_RE.test(res.data.sha)) {
        return { ok: false, status: 'UNCERTAIN', code: 'BROKER_LEDGER_RESPONSE_INVALID' };
      }
      return {
        ok: true,
        status,
        sha: res.data.sha,
      };
    }
    if (status === 'CONFLICT') {
      return {
        ok: false,
        status: 'CONFLICT',
        code: typeof res.data.code === 'string' ? res.data.code : 'BROKER_LEDGER_CONFLICT',
      };
    }
    return {
      ok: false,
      status: 'UNCERTAIN',
      code: typeof res.data.code === 'string' ? res.data.code : 'BROKER_LEDGER_UNCERTAIN',
    };
  }
}

export async function createDesktopControllerRuntimeDependencies(
  baseConfig: ControllerRuntimeConfig,
  env: Record<string, string | undefined>,
): Promise<RuntimeDependencyBundle> {
  const envelopeEnabled = baseConfig.executionEnvelopeEnabled === true;
  const v2Enabled = baseConfig.asymmetricV2Enabled === true;
  const remoteBrokerEnabled = env.BKE_REMOTE_BROKER_ENABLED === 'true';
  const mediatedCasEnabled = baseConfig.mediatedCasEnabled === true;
  const operationalMode = envelopeEnabled || v2Enabled || remoteBrokerEnabled || mediatedCasEnabled;

  // Safe default startup (all broker/V2/CAS/envelope flags remain OFF)
  if (!operationalMode) {
    if (baseConfig.requireAsymmetricV2 === true) {
      throw Error('DAEMON_CONFIG_CONTRADICTORY');
    }
    return {
      config: {
        ...baseConfig,
        executionEnvelopeEnabled: false,
        asymmetricV2Enabled: false,
        requireAsymmetricV2: false,
        mediatedCasEnabled: false,
        brokerAvailable: false,
      },
      deps: {
        tokenProvider: async () => env.BKE_GITHUB_INSTALLATION_TOKEN ?? '',
      },
      brokerClient: null,
      credentials: null,
    };
  }

  // Operational CLI mode forbids legacy V1 execution, compat downgrade, and static write tokens
  if (env.BKE_GITHUB_INSTALLATION_TOKEN && env.BKE_GITHUB_INSTALLATION_TOKEN.trim()) {
    throw Error(
      mediatedCasEnabled
        ? 'DAEMON_WRITE_TOKEN_FORBIDDEN_IN_MEDIATED_MODE'
        : 'DAEMON_STATIC_TOKEN_FORBIDDEN_IN_BROKER_MODE',
    );
  }
  if (!v2Enabled) {
    throw Error('DAEMON_LEGACY_V1_EXECUTION_FORBIDDEN');
  }
  if (!envelopeEnabled) {
    throw Error('DAEMON_CONFIG_V2_REQUIRES_ENVELOPE');
  }
  if (env.BKE_REQUIRE_ASYMMETRIC_V2 === 'false' || baseConfig.requireAsymmetricV2 === false) {
    throw Error('DAEMON_V2_COMPAT_MODE_FORBIDDEN');
  }
  if (
    (baseConfig.executionSigningKeysById && baseConfig.executionSigningKeysById.size > 0) ||
    (baseConfig.remoteHaltSigningKeysById && baseConfig.remoteHaltSigningKeysById.size > 0)
  ) {
    throw Error('DAEMON_MIXED_V1_V2_CONFIG_FORBIDDEN');
  }
  if (!remoteBrokerEnabled) {
    throw Error(
      mediatedCasEnabled ? 'DAEMON_MEDIATED_CAS_CLIENT_MISSING' : 'DAEMON_REVOCATION_CHECKER_MISSING',
    );
  }
  if (!env.BKE_BROKER_BASE_URL || !env.BKE_BROKER_BASE_URL.trim()) {
    throw Error('DAEMON_BROKER_BASE_URL_MISSING');
  }
  const brokerBaseUrl = assertSafeBrokerBaseUrl(env.BKE_BROKER_BASE_URL.trim());

  const credsPath = env.BKE_DEVICE_CREDENTIALS_PATH?.trim();
  if (!credsPath) {
    throw Error('DAEMON_DEVICE_CREDENTIALS_MISSING');
  }
  const credentials = await loadOwnerDeviceCredentialsFile(credsPath);

  if (baseConfig.policyPath) {
    await validateOwnerPolicyAgainstDevice(
      baseConfig.policyPath,
      baseConfig.workerId,
      credentials,
    );
  }

  // Reconcile env vs owner-private credentials without allowing silent overrides
  if (credentials.worker_id !== baseConfig.workerId) {
    throw Error('DAEMON_DEVICE_WORKER_MISMATCH');
  }
  if (credentials.repository.toLowerCase() !== baseConfig.repository.toLowerCase()) {
    throw Error('DAEMON_DEVICE_REPOSITORY_MISMATCH');
  }
  if (baseConfig.expectedDeviceId && credentials.device_id !== baseConfig.expectedDeviceId) {
    throw Error('DAEMON_DEVICE_ID_MISMATCH');
  }
  if (baseConfig.expectedInstallationId && credentials.installation_id !== baseConfig.expectedInstallationId) {
    throw Error('DAEMON_DEVICE_INSTALLATION_MISMATCH');
  }
  if (
    baseConfig.expectedRepositoryId !== undefined &&
    credentials.repository_id !== undefined &&
    credentials.repository_id !== baseConfig.expectedRepositoryId
  ) {
    throw Error('DAEMON_DEVICE_REPOSITORY_ID_MISMATCH');
  }
  if (
    baseConfig.expectedEnrollmentGeneration !== undefined &&
    credentials.enrollment_generation !== baseConfig.expectedEnrollmentGeneration
  ) {
    throw Error('DAEMON_DEVICE_GENERATION_MISMATCH');
  }
  if (
    baseConfig.expectedBrokerIssuer &&
    credentials.broker_issuer &&
    credentials.broker_issuer !== baseConfig.expectedBrokerIssuer
  ) {
    throw Error('DAEMON_BROKER_ISSUER_MISMATCH');
  }
  if (credentials.broker_base_url && credentials.broker_base_url !== brokerBaseUrl) {
    throw Error('DAEMON_BROKER_URL_MISMATCH');
  }

  const execPublicKeys = new Map<string, string>();
  if (credentials.broker_public_keys_by_id) {
    for (const [kid, pem] of Object.entries(credentials.broker_public_keys_by_id)) {
      execPublicKeys.set(kid, assertEd25519PublicPem(pem, 'DAEMON_BROKER_PUBLIC_KEY_INVALID'));
    }
  }
  if (baseConfig.executionPublicKeysById) {
    for (const [kid, rawPem] of baseConfig.executionPublicKeysById.entries()) {
      const pem = assertEd25519PublicPem(rawPem, 'DAEMON_BROKER_PUBLIC_KEY_INVALID');
      const existing = execPublicKeys.get(kid);
      if (existing && existing !== pem) {
        throw Error('DAEMON_BROKER_PUBLIC_KEY_MISMATCH');
      }
      execPublicKeys.set(kid, pem);
    }
  }
  if (execPublicKeys.size === 0) {
    throw Error('DAEMON_BROKER_PUBLIC_KEYS_MISSING');
  }

  const haltPublicKeys = new Map<string, string>();
  if (credentials.halt_public_keys_by_id) {
    for (const [kid, pem] of Object.entries(credentials.halt_public_keys_by_id)) {
      haltPublicKeys.set(kid, assertEd25519PublicPem(pem, 'DAEMON_BROKER_PUBLIC_KEY_INVALID'));
    }
  }
  if (baseConfig.remoteHaltPublicKeysById) {
    for (const [kid, rawPem] of baseConfig.remoteHaltPublicKeysById.entries()) {
      const pem = assertEd25519PublicPem(rawPem, 'DAEMON_BROKER_PUBLIC_KEY_INVALID');
      const existing = haltPublicKeys.get(kid);
      if (existing && existing !== pem) {
        throw Error('DAEMON_BROKER_PUBLIC_KEY_MISMATCH');
      }
      haltPublicKeys.set(kid, pem);
    }
  }

  const expectedBrokerIssuer = baseConfig.expectedBrokerIssuer ?? credentials.broker_issuer ?? '';
  const expectedRepositoryId = baseConfig.expectedRepositoryId ?? credentials.repository_id;
  const expectedInstallationId = baseConfig.expectedInstallationId || credentials.installation_id;
  const expectedDeviceId = baseConfig.expectedDeviceId || credentials.device_id;
  const expectedEnrollmentGeneration =
    baseConfig.expectedEnrollmentGeneration ?? credentials.enrollment_generation;

  if (
    !expectedBrokerIssuer ||
    typeof expectedRepositoryId !== 'number' ||
    !Number.isSafeInteger(expectedRepositoryId) ||
    expectedRepositoryId <= 0 ||
    !expectedInstallationId ||
    !expectedDeviceId
  ) {
    throw Error('DAEMON_V2_BINDINGS_INCOMPLETE');
  }

  const brokerClient = new HttpTrustedBrokerClient({
    brokerBaseUrl,
    deviceId: expectedDeviceId,
    enrollmentGeneration: expectedEnrollmentGeneration,
    devicePublicKeyPem: credentials.device_public_key_pem,
    devicePrivateKeyPem: credentials.device_private_key_pem,
    brokerPublicKeysById: execPublicKeys,
    expectedBrokerIssuer,
    repository: baseConfig.repository,
    repositoryId: expectedRepositoryId,
    installationId: expectedInstallationId,
    workerId: baseConfig.workerId,
  });

  const tokenLifecycle = new ManagedTokenProvider(
    {
      repository: baseConfig.repository,
      repositoryId: expectedRepositoryId,
      installationId: expectedInstallationId,
      workerId: baseConfig.workerId,
      allowedPermissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
      maxTransientRetries: 2,
      retryDelayMs: 15,
      trustedRealBrokerApiAvailable: true,
      realBrokerTransportConnected: true,
    },
    brokerClient,
  );

  const resolvedConfig: ControllerRuntimeConfig = {
    ...baseConfig,
    executionEnvelopeEnabled: true,
    asymmetricV2Enabled: true,
    requireAsymmetricV2: true,
    expectedRepositoryId,
    expectedInstallationId,
    expectedBrokerIssuer,
    expectedDeviceId,
    expectedEnrollmentGeneration,
    minEnrollmentGeneration: baseConfig.minEnrollmentGeneration ?? expectedEnrollmentGeneration,
    executionPublicKeysById: execPublicKeys,
    remoteHaltPublicKeysById: haltPublicKeys.size > 0 ? haltPublicKeys : undefined,
    deviceRevocationChecker: (info) => brokerClient.checkDeviceRevocation(info),
    brokerEndpointConfigured: true,
    brokerAvailable: true,
    mediatedCasEnabled,
    forbidDesktopWriteToken: true,
  };

  return {
    config: resolvedConfig,
    deps: {
      tokenProvider: tokenLifecycle.asTokenProvider(),
      tokenLifecycle,
      mediatedLedgerClient: mediatedCasEnabled ? brokerClient : undefined,
    },
    brokerClient,
    credentials,
  };
}
