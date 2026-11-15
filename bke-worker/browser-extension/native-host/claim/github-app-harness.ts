/**
 * Workstream C: Server-Private GitHub App Authority Provider & Authenticated
 * Canonical Execution Request Harness.
 *
 * Preserves the jan2xo/bke-worker `/github/app/install-token` Actions-OIDC trust
 * boundary in cloudflare-relay while providing clean, provider-independent interfaces
 * and a canonically serialized, cryptographically verified 14-field execution request
 * protocol with strict replay, expiry, role-separation, and live-GitHub checks.
 */
import { createHmac, createPublicKey, sign as cryptoSign, timingSafeEqual, verify as cryptoVerify } from 'node:crypto';
import type { PinnedDispatcherApp, ValidTicket } from '../../src/ticket-contract.js';

export const EXECUTION_REQUEST_PROTOCOL_VERSION = 1 as const;
export const AUTHORIZED_CAPABILITY_V1 = 'GITHUB_F1_EXECUTION_V1' as const;
export const EXECUTION_REQUEST_PROTOCOL_VERSION_V2 = 2 as const;
export const AUTHORIZED_CAPABILITY_V2 = 'GITHUB_F1_EXECUTION_V2' as const;

export type ExecutionAction =
  | 'PREPARE'
  | 'DISPATCH_FIRST_MESSAGE'
  | 'DISPATCH_CONTINUATION'
  | 'HALT';

export interface ExecutionRequestEnvelopeV1 {
  protocol_version: 1;
  repository_owner: string;
  repository_name: string;
  repository_id: number;
  installation_identity: string;
  worker_id: string;
  pr_number: number;
  head_sha: string;
  attempt_id: string;
  delivery_id: string;
  action: ExecutionAction;
  issued_at: string;
  expires_at: string;
  authorized_capability: typeof AUTHORIZED_CAPABILITY_V1;
}

export interface ExecutionRequestEnvelopeV2 {
  protocol_version: 2;
  broker_issuer: string;
  audience: string;
  repository_owner: string;
  repository_name: string;
  repository_id: number;
  installation_identity: string;
  worker_id: string;
  device_id: string;
  enrollment_generation: number;
  pr_number: number;
  head_sha: string;
  attempt_id: string;
  delivery_id: string;
  action: ExecutionAction;
  issued_at: string;
  expires_at: string;
  authorized_capability: typeof AUTHORIZED_CAPABILITY_V2;
}

export type AnyExecutionRequestEnvelope = ExecutionRequestEnvelopeV1 | ExecutionRequestEnvelopeV2;

export interface SignedExecutionRequestV1 {
  envelope: ExecutionRequestEnvelopeV1;
  signature_alg: 'HMAC-SHA256';
  key_id: string;
  signature_hex: string;
}

export interface SignedExecutionRequestV2 {
  envelope: ExecutionRequestEnvelopeV2;
  signature_alg: 'Ed25519';
  key_id: string;
  signature_b64url: string;
}

export interface GitHubInstallationScope {
  installationId: string;
  repositoryId: number;
  repositoryFullName: string;
  permissions: {
    contents?: string;
    issues?: string;
    pull_requests?: string;
    push?: boolean;
  };
}

export interface PullRequestSummary {
  number: number;
  state: 'open' | 'closed';
  headSha: string;
  workerLabels: string[];
}

export interface GitHubAuthorityProvider {
  verifyInstallationScope(
    repositoryFullName: string,
    expectedRepositoryId: number,
    expectedInstallationId: string,
  ): Promise<{ ok: true; scope: GitHubInstallationScope } | { ok: false; code: string }>;
  readPullRequest(repository: string, prNumber: number): Promise<PullRequestSummary | null>;
  enumerateOpenAssignedPullRequests(repository: string, workerId: string): Promise<PullRequestSummary[]>;
  readPinnedTicket(
    repository: string,
    headSha: string,
    workerId: string,
    pinnedApp: PinnedDispatcherApp,
    consumedAttemptIds: Set<string>,
    nowMs: number,
  ): Promise<{ ok: true; ticket: ValidTicket } | { ok: false; code: string }>;
  readBkeRefState(
    repository: string,
    prNumber: number,
  ): Promise<{ consumedAttempts: string[]; uncertainAttempts: string[]; conversationTipSha: string | null }>;
}

const ENVELOPE_KEYS = [
  'action',
  'attempt_id',
  'authorized_capability',
  'delivery_id',
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

const OWNER_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const REPO_NAME_RE = /^[A-Za-z0-9_.-]{1,100}$/;
const INSTALL_ID_RE = /^[0-9]{1,20}$/;
const WORKER_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const DEVICE_ID_RE = /^[A-Za-z0-9._:-]{6,128}$/;
const ISSUER_RE = /^https?:\/\/[A-Za-z0-9._:-]{3,128}$/;
const AUDIENCE_RE = /^bke-desktop-controller:[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+:[a-z0-9][a-z0-9-]{0,62}$/;
const SHA40_RE = /^[a-f0-9]{40}$/;
const ATTEMPT_RE = /^[a-z0-9][a-z0-9-]{0,95}$/;
const DELIVERY_RE = /^[A-Za-z0-9_.:-]{4,128}$/;
const HEX64_RE = /^[a-f0-9]{64}$/;
const B64URL_SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const V2_DOMAIN_PREFIX = 'BKE_EXECUTION_REQUEST_V2\n';
const MAX_ENVELOPE_TTL_MS = 300_000;
const MAX_CLOCK_SKEW_MS = 5_000;

export function buildExecutionAudience(repositoryFullName: string, workerId: string): string {
  return `bke-desktop-controller:${repositoryFullName}:${workerId}`;
}

export function serializeCanonicalExecutionEnvelope(envelope: ExecutionRequestEnvelopeV1): string {
  const ordered: Record<string, unknown> = {};
  for (const k of ENVELOPE_KEYS) {
    ordered[k] = envelope[k];
  }
  return JSON.stringify(ordered);
}

export function serializeCanonicalExecutionEnvelopeV2(envelope: ExecutionRequestEnvelopeV2): string {
  const ordered: Record<string, unknown> = {};
  for (const k of ENVELOPE_V2_KEYS) {
    ordered[k] = envelope[k];
  }
  return JSON.stringify(ordered);
}

function validateCommonEnvelopeFields(obj: Record<string, unknown>): { ok: true; issuedMs: number; expiresMs: number } | { ok: false; code: string } {
  if (
    typeof obj.repository_owner !== 'string' ||
    !OWNER_RE.test(obj.repository_owner) ||
    obj.repository_owner === '.' ||
    obj.repository_owner === '..' ||
    typeof obj.repository_name !== 'string' ||
    !REPO_NAME_RE.test(obj.repository_name) ||
    obj.repository_name === '.' ||
    obj.repository_name === '..'
  ) {
    return { ok: false, code: 'EXEC_REQ_REPOSITORY_INVALID' };
  }
  if (typeof obj.repository_id !== 'number' || !Number.isSafeInteger(obj.repository_id) || obj.repository_id <= 0) {
    return { ok: false, code: 'EXEC_REQ_REPOSITORY_ID_INVALID' };
  }
  if (typeof obj.installation_identity !== 'string' || !INSTALL_ID_RE.test(obj.installation_identity)) {
    return { ok: false, code: 'EXEC_REQ_INSTALLATION_INVALID' };
  }
  if (typeof obj.worker_id !== 'string' || !WORKER_RE.test(obj.worker_id)) {
    return { ok: false, code: 'EXEC_REQ_WORKER_INVALID' };
  }
  if (typeof obj.pr_number !== 'number' || !Number.isSafeInteger(obj.pr_number) || obj.pr_number < 1) {
    return { ok: false, code: 'EXEC_REQ_PR_INVALID' };
  }
  if (typeof obj.head_sha !== 'string' || !SHA40_RE.test(obj.head_sha)) {
    return { ok: false, code: 'EXEC_REQ_HEAD_SHA_INVALID' };
  }
  if (typeof obj.attempt_id !== 'string' || !ATTEMPT_RE.test(obj.attempt_id)) {
    return { ok: false, code: 'EXEC_REQ_ATTEMPT_INVALID' };
  }
  if (typeof obj.delivery_id !== 'string' || !DELIVERY_RE.test(obj.delivery_id)) {
    return { ok: false, code: 'EXEC_REQ_DELIVERY_INVALID' };
  }
  if (
    obj.action !== 'PREPARE' &&
    obj.action !== 'DISPATCH_FIRST_MESSAGE' &&
    obj.action !== 'DISPATCH_CONTINUATION' &&
    obj.action !== 'HALT'
  ) {
    return { ok: false, code: 'EXEC_REQ_ACTION_FORBIDDEN' };
  }
  const issuedMs = typeof obj.issued_at === 'string' ? Date.parse(obj.issued_at) : NaN;
  const expiresMs = typeof obj.expires_at === 'string' ? Date.parse(obj.expires_at) : NaN;
  if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs)) {
    return { ok: false, code: 'EXEC_REQ_TIMESTAMPS_INVALID' };
  }
  if (expiresMs <= issuedMs || expiresMs - issuedMs > MAX_ENVELOPE_TTL_MS) {
    return { ok: false, code: 'EXEC_REQ_TTL_WINDOW_INVALID' };
  }
  return { ok: true, issuedMs, expiresMs };
}

export function validateExecutionEnvelopeShape(
  raw: unknown,
): { ok: true; envelope: ExecutionRequestEnvelopeV1 } | { ok: false; code: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, code: 'EXEC_REQ_NOT_OBJECT' };
  }
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  if (keys.join(',') !== ENVELOPE_KEYS.join(',')) {
    return { ok: false, code: 'EXEC_REQ_SCHEMA_MISMATCH' };
  }
  if (obj.protocol_version !== EXECUTION_REQUEST_PROTOCOL_VERSION) {
    return { ok: false, code: 'EXEC_REQ_UNSUPPORTED_VERSION' };
  }
  if (obj.authorized_capability !== AUTHORIZED_CAPABILITY_V1) {
    return { ok: false, code: 'EXEC_REQ_CAPABILITY_INVALID' };
  }
  const common = validateCommonEnvelopeFields(obj);
  if (!common.ok) return common;
  return { ok: true, envelope: obj as unknown as ExecutionRequestEnvelopeV1 };
}

export function validateExecutionEnvelopeV2Shape(
  raw: unknown,
): { ok: true; envelope: ExecutionRequestEnvelopeV2 } | { ok: false; code: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, code: 'EXEC_REQ_NOT_OBJECT' };
  }
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  if (keys.join(',') !== ENVELOPE_V2_KEYS.join(',')) {
    return { ok: false, code: 'EXEC_REQ_SCHEMA_MISMATCH' };
  }
  if (obj.protocol_version !== EXECUTION_REQUEST_PROTOCOL_VERSION_V2) {
    return { ok: false, code: 'EXEC_REQ_UNSUPPORTED_VERSION' };
  }
  if (obj.authorized_capability !== AUTHORIZED_CAPABILITY_V2) {
    return { ok: false, code: 'EXEC_REQ_CAPABILITY_INVALID' };
  }
  if (typeof obj.broker_issuer !== 'string' || !ISSUER_RE.test(obj.broker_issuer)) {
    return { ok: false, code: 'EXEC_REQ_ISSUER_INVALID' };
  }
  if (typeof obj.audience !== 'string' || !AUDIENCE_RE.test(obj.audience)) {
    return { ok: false, code: 'EXEC_REQ_AUDIENCE_INVALID' };
  }
  if (typeof obj.device_id !== 'string' || !DEVICE_ID_RE.test(obj.device_id)) {
    return { ok: false, code: 'EXEC_REQ_DEVICE_ID_INVALID' };
  }
  if (
    typeof obj.enrollment_generation !== 'number' ||
    !Number.isSafeInteger(obj.enrollment_generation) ||
    obj.enrollment_generation < 1
  ) {
    return { ok: false, code: 'EXEC_REQ_ENROLLMENT_GEN_INVALID' };
  }
  const common = validateCommonEnvelopeFields(obj);
  if (!common.ok) return common;
  return { ok: true, envelope: obj as unknown as ExecutionRequestEnvelopeV2 };
}

export function signExecutionRequestHmac(
  envelope: ExecutionRequestEnvelopeV1,
  secret: string,
  keyId: string,
): SignedExecutionRequestV1 {
  const checked = validateExecutionEnvelopeShape(envelope);
  if (!checked.ok) {
    throw Error(checked.code);
  }
  if (!secret || secret.length < 16 || !keyId) {
    throw Error('SIGNING_KEY_CONFIG_INVALID');
  }
  const canonical = serializeCanonicalExecutionEnvelope(checked.envelope);
  const sigHex = createHmac('sha256', secret).update(canonical, 'utf8').digest('hex');
  return {
    envelope: checked.envelope,
    signature_alg: 'HMAC-SHA256',
    key_id: keyId,
    signature_hex: sigHex,
  };
}

export function signExecutionRequestEd25519(
  envelope: ExecutionRequestEnvelopeV2,
  privateKeyPem: string,
  keyId: string,
): SignedExecutionRequestV2 {
  const checked = validateExecutionEnvelopeV2Shape(envelope);
  if (!checked.ok) {
    throw Error(checked.code);
  }
  if (!privateKeyPem || !privateKeyPem.includes('BEGIN PRIVATE KEY') || !keyId) {
    throw Error('SIGNING_KEY_CONFIG_INVALID');
  }
  const signingInput = V2_DOMAIN_PREFIX + serializeCanonicalExecutionEnvelopeV2(checked.envelope);
  const signature = cryptoSign(null, Buffer.from(signingInput, 'utf8'), privateKeyPem);
  return {
    envelope: checked.envelope,
    signature_alg: 'Ed25519',
    key_id: keyId,
    signature_b64url: signature.toString('base64url'),
  };
}

export function verifyExecutionRequestEd25519Signature(
  request: SignedExecutionRequestV2,
  publicKeyPem: string,
): boolean {
  try {
    const keyObj = createPublicKey(publicKeyPem);
    if (keyObj.asymmetricKeyType !== 'ed25519') {
      return false;
    }
    const signingInput = V2_DOMAIN_PREFIX + serializeCanonicalExecutionEnvelopeV2(request.envelope);
    const sigBuf = Buffer.from(request.signature_b64url, 'base64url');
    return cryptoVerify(null, Buffer.from(signingInput, 'utf8'), keyObj, sigBuf);
  } catch {
    return false;
  }
}

export interface PersistentReplayStore {
  hasDelivery(deliveryId: string): Promise<boolean> | boolean;
  hasOrReservedAttempt(attemptId: string): Promise<boolean> | boolean;
  reserveExecutionRequest(entry: {
    deliveryId: string;
    attemptId: string;
    action: ExecutionAction;
    headSha: string;
    prNumber: number;
  }): Promise<{ ok: true } | { ok: false; code: string }>;
  recordNonDispatchDelivery?(deliveryId: string): Promise<void>;
}

export type DeviceRevocationState = 'ACTIVE' | 'REVOKED' | 'UNKNOWN';

export interface DeviceRevocationCheckInput {
  workerId: string;
  deviceId?: string;
  installationId?: string;
  repository?: string;
  enrollmentGeneration?: number;
}

export interface DeviceRevocationCheckResult {
  status?: DeviceRevocationState;
  revoked: boolean;
  code?: string;
}

export type DeviceRevocationChecker = (
  info: DeviceRevocationCheckInput,
) => Promise<DeviceRevocationCheckResult> | DeviceRevocationCheckResult;

export interface ExecutionVerifierConfig {
  expectedRepositoryOwner: string;
  expectedRepositoryName: string;
  expectedRepositoryId: number;
  expectedInstallationId: string;
  expectedWorkerId: string;
  pinnedApp: PinnedDispatcherApp;
  hmacKeysById?: ReadonlyMap<string, string>;
  haltHmacKeysById?: ReadonlyMap<string, string>;
  allowRemoteHalt?: boolean;
  // F3-00 / F3-04 / F4 P0-01: Default-OFF asymmetric Ed25519 v2 protocol + strict downgrade elimination
  asymmetricV2Enabled?: boolean;
  requireAsymmetricV2?: boolean;
  publicKeysById?: ReadonlyMap<string, string>;
  haltPublicKeysById?: ReadonlyMap<string, string>;
  expectedAudience?: string;
  expectedBrokerIssuer?: string;
  expectedDeviceId?: string;
  expectedEnrollmentGeneration?: number;
  minEnrollmentGeneration?: number;
  deviceRevocationChecker?: DeviceRevocationChecker;
  provider: GitHubAuthorityProvider;
  replayStore?: PersistentReplayStore;
  nowMs?: () => number;
}

export class ExecutionRequestVerifier {
  private readonly seenDeliveries = new Set<string>();
  private readonly seenAttempts = new Set<string>();
  private readonly nowMs: () => number;
  private mutexTail: Promise<void> = Promise.resolve();

  constructor(private readonly config: ExecutionVerifierConfig) {
    if (config.requireAsymmetricV2 === true && config.asymmetricV2Enabled !== true) {
      throw Error('EXEC_REQ_CONFIG_CONTRADICTORY');
    }
    if (config.asymmetricV2Enabled === true) {
      if (config.requireAsymmetricV2 === false) {
        throw Error('EXEC_REQ_CONFIG_DOWNGRADE_FORBIDDEN');
      }
      if (
        (config.hmacKeysById && config.hmacKeysById.size > 0) ||
        (config.haltHmacKeysById && config.haltHmacKeysById.size > 0)
      ) {
        throw Error('EXEC_REQ_CONFIG_MIXED_V1_V2_FORBIDDEN');
      }
      if (!config.publicKeysById || config.publicKeysById.size === 0) {
        throw Error('EXEC_REQ_CONFIG_V2_KEYS_MISSING');
      }
      if (!config.expectedBrokerIssuer || !ISSUER_RE.test(config.expectedBrokerIssuer)) {
        throw Error('EXEC_REQ_CONFIG_ISSUER_MISSING');
      }
      if (!config.expectedDeviceId || !DEVICE_ID_RE.test(config.expectedDeviceId)) {
        throw Error('EXEC_REQ_CONFIG_DEVICE_ID_MISSING');
      }
      if (typeof config.deviceRevocationChecker !== 'function') {
        throw Error('EXEC_REQ_REVOCATION_CHECKER_MISSING');
      }
    }
    this.nowMs = config.nowMs ?? (() => Date.now());
  }

  private async withExclusiveLock<T>(fn: () => Promise<T>): Promise<T> {
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    const prev = this.mutexTail;
    this.mutexTail = next;
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  private resolveKeyForAction(action: ExecutionAction, keyId: string): { ok: true; secret: string } | { ok: false; code: string } {
    const hmacKeys = this.config.hmacKeysById ?? new Map<string, string>();
    if (action === 'HALT') {
      if (this.config.allowRemoteHalt !== true) {
        return { ok: false, code: 'EXEC_REQ_REMOTE_HALT_DISABLED' };
      }
      const haltSecret = this.config.haltHmacKeysById?.get(keyId);
      if (!haltSecret || haltSecret.length < 16) {
        return { ok: false, code: 'EXEC_REQ_HALT_KEY_UNAUTHORIZED' };
      }
      const dispatchSecretSameId = hmacKeys.get(keyId);
      if (dispatchSecretSameId === haltSecret) {
        return { ok: false, code: 'EXEC_REQ_HALT_KEY_SEPARATION_REQUIRED' };
      }
      for (const dispatchSecret of hmacKeys.values()) {
        if (dispatchSecret === haltSecret) {
          return { ok: false, code: 'EXEC_REQ_HALT_KEY_SEPARATION_REQUIRED' };
        }
      }
      return { ok: true, secret: haltSecret };
    }

    const secret = hmacKeys.get(keyId);
    if (!secret || secret.length < 16) {
      return { ok: false, code: 'EXEC_REQ_SIGNING_KEY_UNKNOWN' };
    }
    return { ok: true, secret };
  }

  private resolvePublicKeyForActionV2(action: ExecutionAction, keyId: string): { ok: true; publicKeyPem: string } | { ok: false; code: string } {
    const pubKeys = this.config.publicKeysById ?? new Map<string, string>();
    if (action === 'HALT') {
      if (this.config.allowRemoteHalt !== true) {
        return { ok: false, code: 'EXEC_REQ_REMOTE_HALT_DISABLED' };
      }
      const haltPub = this.config.haltPublicKeysById?.get(keyId);
      if (!haltPub || !haltPub.includes('BEGIN PUBLIC KEY')) {
        return { ok: false, code: 'EXEC_REQ_HALT_KEY_UNAUTHORIZED' };
      }
      for (const execPub of pubKeys.values()) {
        if (execPub.trim() === haltPub.trim()) {
          return { ok: false, code: 'EXEC_REQ_HALT_KEY_SEPARATION_REQUIRED' };
        }
      }
      return { ok: true, publicKeyPem: haltPub };
    }

    const pub = pubKeys.get(keyId);
    if (!pub || !pub.includes('BEGIN PUBLIC KEY')) {
      return { ok: false, code: 'EXEC_REQ_SIGNING_KEY_UNKNOWN' };
    }
    return { ok: true, publicKeyPem: pub };
  }

  async verifyAndAuthorize(rawRequest: unknown): Promise<
    | {
        ok: true;
        code: 'EXECUTION_REQUEST_AUTHORIZED';
        envelope: AnyExecutionRequestEnvelope;
        ticket: ValidTicket;
      }
    | { ok: false; code: string }
  > {
    if (!rawRequest || typeof rawRequest !== 'object' || Array.isArray(rawRequest)) {
      return { ok: false, code: 'EXEC_REQ_WRAPPER_INVALID' };
    }
    const wrapper = rawRequest as Record<string, unknown>;
    const rawEnv = wrapper.envelope;
    const rawVersion =
      rawEnv && typeof rawEnv === 'object' && !Array.isArray(rawEnv)
        ? (rawEnv as Record<string, unknown>).protocol_version
        : undefined;

    let env: AnyExecutionRequestEnvelope;
    let isV2 = false;

    if (this.config.asymmetricV2Enabled === true) {
      if (rawVersion === EXECUTION_REQUEST_PROTOCOL_VERSION || wrapper.signature_alg === 'HMAC-SHA256') {
        return { ok: false, code: 'EXEC_REQ_DOWNGRADE_FORBIDDEN' };
      }
      if (rawVersion !== EXECUTION_REQUEST_PROTOCOL_VERSION_V2) {
        return { ok: false, code: 'EXEC_REQ_UNSUPPORTED_VERSION' };
      }
      isV2 = true;
      if (
        Object.keys(wrapper).sort().join(',') !== 'envelope,key_id,signature_alg,signature_b64url' ||
        wrapper.signature_alg !== 'Ed25519' ||
        typeof wrapper.key_id !== 'string' ||
        typeof wrapper.signature_b64url !== 'string' ||
        !B64URL_SIG_RE.test(wrapper.signature_b64url)
      ) {
        return { ok: false, code: 'EXEC_REQ_SIGNATURE_ENVELOPE_INVALID' };
      }

      const shapeV2 = validateExecutionEnvelopeV2Shape(rawEnv);
      if (!shapeV2.ok) {
        return shapeV2;
      }
      const envV2 = shapeV2.envelope;
      const keyRes = this.resolvePublicKeyForActionV2(envV2.action, wrapper.key_id);
      if (!keyRes.ok) {
        return keyRes;
      }
      const validSig = verifyExecutionRequestEd25519Signature(
        {
          envelope: envV2,
          signature_alg: 'Ed25519',
          key_id: wrapper.key_id,
          signature_b64url: wrapper.signature_b64url,
        },
        keyRes.publicKeyPem,
      );
      if (!validSig) {
        return { ok: false, code: 'EXEC_REQ_SIGNATURE_INVALID' };
      }
      if (envV2.broker_issuer !== this.config.expectedBrokerIssuer) {
        return { ok: false, code: 'EXEC_REQ_ISSUER_MISMATCH' };
      }
      const expectedAud =
        this.config.expectedAudience ??
        buildExecutionAudience(`${this.config.expectedRepositoryOwner}/${this.config.expectedRepositoryName}`, this.config.expectedWorkerId);
      if (envV2.audience !== expectedAud) {
        return { ok: false, code: 'EXEC_REQ_AUDIENCE_MISMATCH' };
      }
      if (envV2.device_id !== this.config.expectedDeviceId) {
        return { ok: false, code: 'EXEC_REQ_DEVICE_MISMATCH' };
      }
      if (
        typeof this.config.expectedEnrollmentGeneration === 'number' &&
        envV2.enrollment_generation !== this.config.expectedEnrollmentGeneration
      ) {
        return { ok: false, code: 'EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH' };
      }
      if (
        typeof this.config.minEnrollmentGeneration === 'number' &&
        envV2.enrollment_generation < this.config.minEnrollmentGeneration
      ) {
        return { ok: false, code: 'EXEC_REQ_ENROLLMENT_STALE' };
      }
      env = envV2;
    } else {
      if (this.config.requireAsymmetricV2 === true) {
        return { ok: false, code: 'EXEC_REQ_DOWNGRADE_FORBIDDEN' };
      }
      if (rawVersion === EXECUTION_REQUEST_PROTOCOL_VERSION_V2) {
        return { ok: false, code: 'EXEC_REQ_UNSUPPORTED_VERSION' };
      }
      if (
        Object.keys(wrapper).sort().join(',') !== 'envelope,key_id,signature_alg,signature_hex' ||
        wrapper.signature_alg !== 'HMAC-SHA256' ||
        typeof wrapper.key_id !== 'string' ||
        typeof wrapper.signature_hex !== 'string' ||
        !HEX64_RE.test(wrapper.signature_hex)
      ) {
        return { ok: false, code: 'EXEC_REQ_SIGNATURE_ENVELOPE_INVALID' };
      }

      const shape = validateExecutionEnvelopeShape(wrapper.envelope);
      if (!shape.ok) {
        return shape;
      }
      const envV1 = shape.envelope;
      const keyResolution = this.resolveKeyForAction(envV1.action, wrapper.key_id);
      if (!keyResolution.ok) {
        return keyResolution;
      }
      const canonical = serializeCanonicalExecutionEnvelope(envV1);
      const expectedSig = createHmac('sha256', keyResolution.secret).update(canonical, 'utf8').digest();
      const actualSig = Buffer.from(wrapper.signature_hex, 'hex');
      if (expectedSig.length !== actualSig.length || !timingSafeEqual(expectedSig, actualSig)) {
        return { ok: false, code: 'EXEC_REQ_SIGNATURE_INVALID' };
      }
      env = envV1;
    }

    if (
      env.repository_owner !== this.config.expectedRepositoryOwner ||
      env.repository_name !== this.config.expectedRepositoryName ||
      env.repository_id !== this.config.expectedRepositoryId
    ) {
      return { ok: false, code: 'EXEC_REQ_TARGET_REPOSITORY_MISMATCH' };
    }
    if (env.installation_identity !== this.config.expectedInstallationId) {
      return { ok: false, code: 'EXEC_REQ_INSTALLATION_MISMATCH' };
    }
    if (env.worker_id !== this.config.expectedWorkerId) {
      return { ok: false, code: 'EXEC_REQ_WORKER_MISMATCH' };
    }

    const now = this.nowMs();
    const issuedMs = Date.parse(env.issued_at);
    const expiresMs = Date.parse(env.expires_at);
    if (now < issuedMs - MAX_CLOCK_SKEW_MS) {
      return { ok: false, code: 'EXEC_REQ_NOT_YET_VALID' };
    }
    if (now >= expiresMs) {
      return { ok: false, code: 'EXEC_REQ_EXPIRED' };
    }

    if (isV2 && !this.config.deviceRevocationChecker) {
      return { ok: false, code: 'EXEC_REQ_REVOCATION_CHECKER_MISSING' };
    }
    if (this.config.deviceRevocationChecker) {
      let rev: DeviceRevocationCheckResult;
      try {
        rev = await this.config.deviceRevocationChecker({
          workerId: env.worker_id,
          deviceId: isV2 ? (env as ExecutionRequestEnvelopeV2).device_id : undefined,
          installationId: env.installation_identity,
          repository: `${env.repository_owner}/${env.repository_name}`,
          enrollmentGeneration: isV2 ? (env as ExecutionRequestEnvelopeV2).enrollment_generation : undefined,
        });
      } catch {
        return { ok: false, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
      }
      if (!rev || typeof rev !== 'object') {
        return { ok: false, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
      }
      if (rev.status !== undefined) {
        if (rev.status === 'REVOKED') {
          return { ok: false, code: rev.code || 'EXEC_REQ_DEVICE_REVOKED' };
        }
        if (rev.status !== 'ACTIVE') {
          return { ok: false, code: rev.code || 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
        }
      }
      if (rev.revoked !== false) {
        return { ok: false, code: rev.code || 'EXEC_REQ_DEVICE_REVOKED' };
      }
    }

    return this.withExclusiveLock(async () => {
      if (this.seenDeliveries.has(env.delivery_id) || (await this.config.replayStore?.hasDelivery(env.delivery_id))) {
        return { ok: false, code: 'EXEC_REQ_DELIVERY_REPLAY' };
      }
      if (
        env.action !== 'HALT' &&
        env.action !== 'PREPARE' &&
        (this.seenAttempts.has(env.attempt_id) || (await this.config.replayStore?.hasOrReservedAttempt(env.attempt_id)))
      ) {
        return { ok: false, code: 'EXEC_REQ_ATTEMPT_REPLAY' };
      }

      const fullRepo = `${env.repository_owner}/${env.repository_name}`;
      const installCheck = await this.config.provider.verifyInstallationScope(
        fullRepo,
        env.repository_id,
        env.installation_identity,
      );
      if (!installCheck.ok) {
        return { ok: false, code: installCheck.code };
      }

      if (env.action === 'HALT') {
        await this.config.replayStore?.recordNonDispatchDelivery?.(env.delivery_id);
        this.seenDeliveries.add(env.delivery_id);
        return {
          ok: true,
          code: 'EXECUTION_REQUEST_AUTHORIZED',
          envelope: env,
          ticket: {
            contractVersion: 1,
            checkRunId: 0,
            ticketId: `halt:${env.delivery_id}`,
            attemptId: env.attempt_id,
            workerId: env.worker_id,
            expiresAtMs: expiresMs,
            headSha: env.head_sha,
          },
        };
      }

      const openPrs = await this.config.provider.enumerateOpenAssignedPullRequests(fullRepo, env.worker_id);
      if (openPrs.length !== 1) {
        return { ok: false, code: openPrs.length === 0 ? 'GITHUB_PR_NOT_ASSIGNED' : 'GITHUB_WORKER_MULTI_PR_CONFLICT' };
      }
      const pr = await this.config.provider.readPullRequest(fullRepo, env.pr_number);
      if (!pr || pr.state !== 'open') {
        return { ok: false, code: 'GITHUB_PR_NOT_OPEN' };
      }
      if (pr.workerLabels.length !== 1 || pr.workerLabels[0] !== env.worker_id) {
        return { ok: false, code: 'GITHUB_WORKER_ASSIGNMENT_CONFLICT' };
      }
      if (pr.headSha !== env.head_sha) {
        return { ok: false, code: 'GITHUB_HEAD_SHA_STALE' };
      }

      const refState = await this.config.provider.readBkeRefState(fullRepo, env.pr_number);
      if (refState.uncertainAttempts.length > 0) {
        return { ok: false, code: 'GITHUB_DELIVERY_UNCERTAIN_QUARANTINED' };
      }
      if (refState.consumedAttempts.includes(env.attempt_id)) {
        return { ok: false, code: 'GITHUB_ATTEMPT_ALREADY_CONSUMED' };
      }

      const ticketRes = await this.config.provider.readPinnedTicket(
        fullRepo,
        env.head_sha,
        env.worker_id,
        this.config.pinnedApp,
        new Set(refState.consumedAttempts),
        now,
      );
      if (!ticketRes.ok) {
        return { ok: false, code: ticketRes.code };
      }
      if (ticketRes.ticket.attemptId !== env.attempt_id) {
        return { ok: false, code: 'EXEC_REQ_TICKET_ATTEMPT_MISMATCH' };
      }

      if (env.action === 'DISPATCH_FIRST_MESSAGE' || env.action === 'DISPATCH_CONTINUATION') {
        if (this.config.replayStore) {
          const reserved = await this.config.replayStore.reserveExecutionRequest({
            deliveryId: env.delivery_id,
            attemptId: env.attempt_id,
            action: env.action,
            headSha: env.head_sha,
            prNumber: env.pr_number,
          });
          if (!reserved.ok) {
            return { ok: false, code: reserved.code };
          }
        }
        this.seenDeliveries.add(env.delivery_id);
        this.seenAttempts.add(env.attempt_id);
      } else {
        await this.config.replayStore?.recordNonDispatchDelivery?.(env.delivery_id);
        this.seenDeliveries.add(env.delivery_id);
      }

      return {
        ok: true,
        code: 'EXECUTION_REQUEST_AUTHORIZED',
        envelope: env,
        ticket: ticketRes.ticket,
      };
    });
  }
}
