/**
 * F3-02 / F3-04 / F3-06 Device Crypto Signer & Sandbox HTTP Token Broker Client.
 *
 * Generates device-owned ECDSA P-256 keypairs (private key stays strictly on the device),
 * signs pairing challenges & runtime PoP assertions, and implements ManagedTokenProvider's
 * TokenBrokerClient over loopback HTTP for sandbox E2E & lifecycle tests.
 */
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import {
  DEVICE_POP_DOMAIN,
  DEVICE_STATUS_DOMAIN,
  ENROLLMENT_CHALLENGE_DOMAIN,
  TOKEN_STATUS_DOMAIN,
  computeLedgerOpDigestHex,
  type DeviceRevocationStatus,
  type DeviceSignedAssertion,
  type DeviceSignedAssertionPayload,
  type EnrollmentChallengeRecord,
  type ServerMediatedLedgerOpRequest,
  type ServerMediatedLedgerOpResult,
} from './types.js';

function canonicalJson(value: Record<string, unknown>): string {
  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    ordered[key] = value[key];
  }
  return JSON.stringify(ordered);
}

export class DeviceKeyPairSigner {
  readonly publicKeySpkiPem: string;
  readonly publicKeySha256: string;
  private readonly privateKeyPem: string;

  constructor(pair?: { publicKeySpkiPem: string; privateKeyPem: string }) {
    if (pair) {
      this.publicKeySpkiPem = pair.publicKeySpkiPem;
      this.privateKeyPem = pair.privateKeyPem;
      const der = createPublicKey(pair.publicKeySpkiPem).export({ type: 'spki', format: 'der' });
      this.publicKeySha256 = createHash('sha256').update(der).digest('hex');
    } else {
      const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      this.publicKeySpkiPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
      this.privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
      const der = publicKey.export({ type: 'spki', format: 'der' });
      this.publicKeySha256 = createHash('sha256').update(der).digest('hex');
    }
  }

  signEnrollmentChallenge(params: {
    challenge: EnrollmentChallengeRecord;
    browser_profile_identity: string;
    native_bridge_identity: string;
  }): string {
    const payload = {
      browser_profile_identity: params.browser_profile_identity,
      challenge_id: params.challenge.challenge_id,
      device_id: params.challenge.device_id,
      installation_id: params.challenge.installation_id,
      native_bridge_identity: params.native_bridge_identity,
      nonce_b64url: params.challenge.nonce_b64url,
      public_key_sha256: this.publicKeySha256,
      worker_id: params.challenge.worker_id,
    };
    const msg = Buffer.from(ENROLLMENT_CHALLENGE_DOMAIN + canonicalJson(payload), 'utf8');
    return cryptoSign('sha256', msg, { key: this.privateKeyPem, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  }

  signKeyRotationProof(params: {
    device_id: string;
    worker_id: string;
    installation_id: string;
    new_generation: number;
    nonce: string;
  }): string {
    const payload = {
      device_id: params.device_id,
      installation_id: params.installation_id,
      new_generation: params.new_generation,
      new_public_key_sha256: this.publicKeySha256,
      nonce: params.nonce,
      worker_id: params.worker_id,
    };
    const msg = Buffer.from(ENROLLMENT_CHALLENGE_DOMAIN + canonicalJson(payload), 'utf8');
    return cryptoSign('sha256', msg, { key: this.privateKeyPem, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  }

  signDeviceAssertion(params: {
    worker_id: string;
    device_id: string;
    installation_id: string;
    enrollment_generation: number;
    purpose: DeviceSignedAssertionPayload['purpose'];
    repository: string;
    nowMs?: number;
    ttlMs?: number;
    nonce?: string;
    ledger_op?: ServerMediatedLedgerOpRequest;
    ledger_op_sha256?: string;
  }): DeviceSignedAssertion {
    const now = params.nowMs ?? Date.now();
    const payload: DeviceSignedAssertionPayload = {
      worker_id: params.worker_id,
      device_id: params.device_id,
      installation_id: params.installation_id,
      enrollment_generation: params.enrollment_generation,
      purpose: params.purpose,
      repository: params.repository,
      nonce: params.nonce ?? randomBytes(16).toString('base64url'),
      issued_at: new Date(now).toISOString(),
      expires_at: new Date(now + (params.ttlMs ?? 60_000)).toISOString(),
    };
    if (params.purpose === 'SERVER_MEDIATED_LEDGER_OP') {
      const digest =
        typeof params.ledger_op_sha256 === 'string'
          ? params.ledger_op_sha256
          : params.ledger_op
            ? computeLedgerOpDigestHex(params.ledger_op)
            : '';
      if (!SHA256_HEX_RE.test(digest)) {
        throw Error('DEVICE_ASSERTION_LEDGER_FIELDS_MISSING');
      }
      payload.ledger_op_sha256 = digest;
    }
    const msg = Buffer.from(
      DEVICE_POP_DOMAIN + canonicalJson(payload as unknown as Record<string, unknown>),
      'utf8',
    );
    const sig = cryptoSign('sha256', msg, {
      key: this.privateKeyPem,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url');
    return {
      payload,
      signature_alg: 'ES256',
      signature_b64url: sig,
    };
  }
}

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const WORKER_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const INSTALL_RE = /^[0-9]{1,20}$/;
const DEVICE_ID_RE = /^[A-Za-z0-9._:-]{4,128}$/;
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
const ALLOWED_MEDIATED_OPS = new Set([
  'COMMIT_PRE_SEND_FENCE',
  'CONSUME_SEND_CLAIM',
  'RECONCILE_CONVERSATION',
  'MARK_DELIVERY_UNCERTAIN',
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isValidRepoName(value: unknown): value is string {
  if (typeof value !== 'string' || !REPO_RE.test(value)) return false;
  const parts = value.split('/');
  return parts.length === 2 && parts[0] !== '.' && parts[0] !== '..' && parts[1] !== '.' && parts[1] !== '..';
}

export class SandboxHttpTokenBrokerClient {
  readonly kind = 'REMOTE_OWNER_CERTIFIED_BROKER' as const;
  private readonly seenStatusNonces = new Set<string>();

  constructor(
    private readonly config: {
      brokerBaseUrl: string;
      deviceId: string;
      enrollmentGeneration: number;
      deviceSigner: DeviceKeyPairSigner;
      brokerPublicKeysById?: ReadonlyMap<string, string>;
      expectedBrokerIssuer?: string;
      timeoutMs?: number;
      repository?: string;
      repositoryId?: number;
      installationId?: string;
      workerId?: string;
      nowMs?: () => number;
    },
  ) {}

  private recordStatusNonce(nonce: string): void {
    this.seenStatusNonces.add(nonce);
    if (this.seenStatusNonces.size > MAX_SEEN_STATUS_NONCES) {
      const oldest = this.seenStatusNonces.values().next().value;
      if (oldest !== undefined) this.seenStatusNonces.delete(oldest);
    }
  }

  private verifyBrokerSignedPayload(
    domainPrefix: string,
    signedWrapper: unknown,
  ): { ok: true; payload: Record<string, unknown> } | { ok: false } {
    if (!this.config.brokerPublicKeysById || this.config.brokerPublicKeysById.size === 0 || !this.config.expectedBrokerIssuer) {
      return { ok: false };
    }
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
      const now = (this.config.nowMs ?? Date.now)();
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
      const res = await globalThis.fetch(`${this.config.brokerBaseUrl.replace(/\/+$/, '')}${path}`, {
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
      if (timedOut) {
        return { ok: false, status: 504, timedOut: true, data: { code: 'BROKER_TIMEOUT' } };
      }
      return { ok: false, status: 503, timedOut: false, data: { code: 'BROKER_TRANSPORT_UNAVAILABLE' } };
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
  }): Promise<{ status: DeviceRevocationStatus; revoked: boolean; code?: string }> {
    const targetDeviceId = info.deviceId ?? this.config.deviceId;
    const targetInstall = info.installationId ?? this.config.installationId;
    const targetRepo = info.repository ?? this.config.repository;
    const targetGen = info.enrollmentGeneration ?? this.config.enrollmentGeneration;

    if (
      typeof info.workerId !== 'string' ||
      !WORKER_RE.test(info.workerId) ||
      (this.config.workerId !== undefined && info.workerId !== this.config.workerId) ||
      typeof targetDeviceId !== 'string' ||
      !DEVICE_ID_RE.test(targetDeviceId) ||
      targetDeviceId !== this.config.deviceId ||
      typeof targetInstall !== 'string' ||
      !INSTALL_RE.test(targetInstall) ||
      (this.config.installationId !== undefined && targetInstall !== this.config.installationId) ||
      !isValidRepoName(targetRepo) ||
      (this.config.repository !== undefined && targetRepo.toLowerCase() !== this.config.repository.toLowerCase()) ||
      typeof targetGen !== 'number' ||
      !Number.isSafeInteger(targetGen) ||
      targetGen < 1
    ) {
      return { status: 'UNKNOWN', revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
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
      return { status: 'UNKNOWN', revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
    }
    const verified = this.verifyBrokerSignedPayload(DEVICE_STATUS_DOMAIN, res.data.signed_status);
    if (!verified.ok) {
      return { status: 'UNKNOWN', revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
    }
    const p = verified.payload;

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
      (this.config.workerId !== undefined && p.worker_id !== this.config.workerId) ||
      typeof p.device_id !== 'string' ||
      p.device_id !== targetDeviceId ||
      p.device_id !== this.config.deviceId ||
      typeof p.installation_id !== 'string' ||
      p.installation_id !== targetInstall ||
      (this.config.installationId !== undefined && p.installation_id !== this.config.installationId) ||
      !isValidRepoName(p.repository) ||
      p.repository.toLowerCase() !== targetRepo.toLowerCase() ||
      (this.config.repository !== undefined && p.repository.toLowerCase() !== this.config.repository.toLowerCase()) ||
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

  async issueToken(request: {
    repository: string;
    repositoryId?: number;
    installationId: string;
    workerId: string;
    requestedPermissions: Record<string, 'none' | 'read' | 'write'>;
    signal: AbortSignal;
  }): Promise<{
    token: string;
    tokenType: 'installation';
    installationId: string;
    repositoryId?: number;
    repositories: string[];
    permissions: Record<string, string>;
    issuedAtMs: number;
    expiresAtMs: number;
    usageExpiresAtMs?: number;
    providerExpiresAtMs?: number;
  }> {
    if (this.config.workerId !== undefined && request.workerId !== this.config.workerId) {
      throw Error('TOKEN_WORKER_MISMATCH');
    }
    if (this.config.installationId !== undefined && request.installationId !== this.config.installationId) {
      throw Error('TOKEN_INSTALLATION_MISMATCH');
    }
    if (
      !isValidRepoName(request.repository) ||
      (this.config.repository !== undefined && request.repository.toLowerCase() !== this.config.repository.toLowerCase())
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

    const assertion = this.config.deviceSigner.signDeviceAssertion({
      worker_id: request.workerId,
      device_id: this.config.deviceId,
      installation_id: request.installationId,
      enrollment_generation: this.config.enrollmentGeneration,
      purpose: 'MINT_SCOPED_TOKEN',
      repository: request.repository,
      nowMs: (this.config.nowMs ?? Date.now)(),
    });

    const filteredPerms: Record<string, 'read'> = {};
    for (const [k, v] of Object.entries(request.requestedPermissions)) {
      if (v === 'read') filteredPerms[k] = 'read';
    }

    const res = await this.postJsonWithTimeout(
      '/v1/broker/tokens',
      {
        repository: request.repository,
        repository_id: request.repositoryId ?? this.config.repositoryId ?? 0,
        installation_id: request.installationId,
        worker_id: request.workerId,
        requested_permissions: filteredPerms,
        device_assertion: assertion,
      },
      request.signal,
    );

    if (res.timedOut) {
      throw Error('TOKEN_BROKER_TIMEOUT');
    }
    if (res.data?.code === 'BROKER_REDIRECT_BLOCKED') {
      throw Error('TOKEN_BROKER_REDIRECT_BLOCKED');
    }
    if (!res.ok || !res.data || res.data.ok !== true || !isPlainObject(res.data.token)) {
      const code = typeof res.data?.code === 'string' ? res.data.code : 'TOKEN_BROKER_UNAVAILABLE';
      if (code.includes('REVOKED')) throw Error('TOKEN_REVOKED');
      if (code.includes('PERMISSION') || code.includes('MISMATCH') || code.includes('DEVICE')) {
        throw Error(`TOKEN_${code}`);
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
    const expectedInstall = this.config.installationId ?? request.installationId;
    if (rawTok.installationId !== expectedInstall) {
      throw Error('TOKEN_INSTALLATION_MISMATCH');
    }
    const expectedRepo = this.config.repository ?? request.repository;
    if (
      !Array.isArray(rawTok.repositories) ||
      rawTok.repositories.length !== 1 ||
      !isValidRepoName(rawTok.repositories[0]) ||
      rawTok.repositories[0].toLowerCase() !== expectedRepo.toLowerCase()
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
    const now = (this.config.nowMs ?? Date.now)();
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
  ): Promise<{ status: DeviceRevocationStatus | 'EXPIRED'; code?: string }> {
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

  async executeLedgerOp(input: {
    operation:
      | 'COMMIT_PRE_SEND_FENCE'
      | 'CONSUME_SEND_CLAIM'
      | 'RECONCILE_CONVERSATION'
      | 'MARK_DELIVERY_UNCERTAIN';
    repository: string;
    repositoryId: number;
    installationId: string;
    workerId: string;
    prNumber: number;
    headSha: string;
    attemptId: string;
    refName: string;
    turnRefName?: string;
    expectedParentSha?: string;
    isContinuation?: boolean;
    commitMessage: string;
    treeSha: string;
  }): Promise<ServerMediatedLedgerOpResult> {
    if (!ALLOWED_MEDIATED_OPS.has(input.operation)) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_ARBITRARY_PROXY_FORBIDDEN' };
    }
    if (
      (this.config.workerId !== undefined && input.workerId !== this.config.workerId) ||
      (this.config.installationId !== undefined && input.installationId !== this.config.installationId) ||
      !isValidRepoName(input.repository) ||
      (this.config.repository !== undefined && input.repository.toLowerCase() !== this.config.repository.toLowerCase()) ||
      (this.config.repositoryId !== undefined && input.repositoryId !== this.config.repositoryId)
    ) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_DEVICE_SCOPE_MISMATCH' };
    }
    const ledgerOp: ServerMediatedLedgerOpRequest = {
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
    let assertion: DeviceSignedAssertion;
    try {
      assertion = this.config.deviceSigner.signDeviceAssertion({
        worker_id: input.workerId,
        device_id: this.config.deviceId,
        installation_id: input.installationId,
        enrollment_generation: this.config.enrollmentGeneration,
        purpose: 'SERVER_MEDIATED_LEDGER_OP',
        repository: input.repository,
        ledger_op: ledgerOp,
        nowMs: (this.config.nowMs ?? Date.now)(),
      });
    } catch {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_OP_INVALID' };
    }
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
