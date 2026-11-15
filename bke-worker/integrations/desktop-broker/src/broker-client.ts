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
  type DeviceRevocationStatus,
  type DeviceSignedAssertion,
  type DeviceSignedAssertionPayload,
  type EnrollmentChallengeRecord,
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
      expires_at: new Date(now + (params.ttlMs ?? 60_000)).toString() ? new Date(now + (params.ttlMs ?? 60_000)).toISOString() : '',
    };
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

export class SandboxHttpTokenBrokerClient {
  readonly kind = 'REMOTE_OWNER_CERTIFIED_BROKER' as const;

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
      installationId?: string;
      workerId?: string;
      nowMs?: () => number;
    },
  ) {}

  private verifyBrokerSignedPayload(
    domainPrefix: string,
    signedWrapper: unknown,
  ): { ok: true; payload: Record<string, unknown> } | { ok: false } {
    if (!this.config.brokerPublicKeysById || this.config.brokerPublicKeysById.size === 0 || !this.config.expectedBrokerIssuer) {
      return { ok: false };
    }
    if (!signedWrapper || typeof signedWrapper !== 'object' || Array.isArray(signedWrapper)) {
      return { ok: false };
    }
    const wrap = signedWrapper as Record<string, unknown>;
    if (
      Object.keys(wrap).sort().join(',') !== 'key_id,payload,signature_alg,signature_b64url' ||
      wrap.signature_alg !== 'Ed25519' ||
      typeof wrap.key_id !== 'string' ||
      typeof wrap.signature_b64url !== 'string' ||
      !wrap.payload ||
      typeof wrap.payload !== 'object' ||
      Array.isArray(wrap.payload)
    ) {
      return { ok: false };
    }
    const pubPem = this.config.brokerPublicKeysById.get(wrap.key_id);
    if (!pubPem) return { ok: false };
    try {
      const keyObj = createPublicKey(pubPem);
      if (keyObj.asymmetricKeyType !== 'ed25519') return { ok: false };
      const payload = wrap.payload as Record<string, unknown>;
      const input = Buffer.from(domainPrefix + canonicalJson(payload), 'utf8');
      const sig = Buffer.from(wrap.signature_b64url, 'base64url');
      if (!cryptoVerify(null, input, keyObj, sig)) return { ok: false };

      if (payload.version !== 1 || payload.broker_issuer !== this.config.expectedBrokerIssuer) {
        return { ok: false };
      }
      const now = (this.config.nowMs ?? Date.now)();
      const issued = typeof payload.issued_at === 'string' ? Date.parse(payload.issued_at) : NaN;
      const expires = typeof payload.expires_at === 'string' ? Date.parse(payload.expires_at) : NaN;
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
  ): Promise<{ ok: boolean; status: number; data: Record<string, unknown> | null }> {
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
        return { ok: false, status: res.status, data: { code: 'BROKER_REDIRECT_BLOCKED' } };
      }
      const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
      return { ok: res.ok, status: res.status, data };
    } catch {
      if (timedOut) {
        return { ok: false, status: 504, data: { code: 'BROKER_TIMEOUT' } };
      }
      return { ok: false, status: 503, data: { code: 'BROKER_TRANSPORT_UNAVAILABLE' } };
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
    const nonce = randomBytes(24).toString('base64url');
    const targetDeviceId = info.deviceId ?? this.config.deviceId;
    const targetInstall = info.installationId ?? this.config.installationId;
    const targetRepo = info.repository ?? this.config.repository;
    const res = await this.postJsonWithTimeout('/v1/enrollment/status', {
      worker_id: info.workerId,
      device_id: targetDeviceId,
      installation_id: targetInstall,
      repository: targetRepo,
      enrollment_generation: info.enrollmentGeneration,
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
    if (
      p.nonce !== nonce ||
      p.worker_id !== info.workerId ||
      p.device_id !== targetDeviceId ||
      (targetInstall && p.installation_id !== targetInstall) ||
      (targetRepo && typeof p.repository === 'string' && p.repository.toLowerCase() !== targetRepo.toLowerCase()) ||
      (typeof info.enrollmentGeneration === 'number' && p.enrollment_generation !== info.enrollmentGeneration)
    ) {
      return { status: 'UNKNOWN', revoked: true, code: 'EXEC_REQ_REVOCATION_UNAVAILABLE' };
    }
    if (p.status === 'REVOKED' || p.revoked === true) {
      return {
        status: 'REVOKED',
        revoked: true,
        code: typeof p.code === 'string' && p.code ? p.code : 'EXEC_REQ_DEVICE_REVOKED',
      };
    }
    if (
      p.status === 'ACTIVE' &&
      p.revoked === false &&
      (typeof info.enrollmentGeneration !== 'number' ||
        p.actual_enrollment_generation === info.enrollmentGeneration)
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
  }> {
    const assertion = this.config.deviceSigner.signDeviceAssertion({
      worker_id: request.workerId,
      device_id: this.config.deviceId,
      installation_id: request.installationId,
      enrollment_generation: this.config.enrollmentGeneration,
      purpose: 'MINT_SCOPED_TOKEN',
      repository: request.repository,
      nowMs: (this.config.nowMs ?? Date.now)(),
    });

    const filteredPerms: Record<string, 'read' | 'write'> = {};
    for (const [k, v] of Object.entries(request.requestedPermissions)) {
      if (v === 'read' || v === 'write') filteredPerms[k] = v;
    }

    const res = await globalThis.fetch(`${this.config.brokerBaseUrl.replace(/\/+$/, '')}/v1/broker/tokens`, {
      method: 'POST',
      redirect: 'manual',
      signal: request.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repository: request.repository,
        repository_id: request.repositoryId ?? 0,
        installation_id: request.installationId,
        worker_id: request.workerId,
        requested_permissions: filteredPerms,
        device_assertion: assertion,
      }),
    });

    if (res.status >= 300 && res.status < 400) {
      throw Error('TOKEN_BROKER_REDIRECT_BLOCKED');
    }
    const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
    if (!res.ok || !body?.ok || !body.token) {
      const code = typeof body?.code === 'string' ? body.code : 'TOKEN_BROKER_UNAVAILABLE';
      if (code.includes('REVOKED')) throw Error('TOKEN_REVOKED');
      if (code.includes('PERMISSION') || code.includes('MISMATCH') || code.includes('DEVICE')) {
        throw Error(`TOKEN_${code}`);
      }
      throw Error('TOKEN_BROKER_UNAVAILABLE');
    }
    return body.token as {
      token: string;
      tokenType: 'installation';
      installationId: string;
      repositoryId?: number;
      repositories: string[];
      permissions: Record<string, string>;
      issuedAtMs: number;
      expiresAtMs: number;
    };
  }

  async checkTokenStatus(
    token: string,
  ): Promise<{ status: DeviceRevocationStatus; code?: string }> {
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
    if (p.nonce !== nonce || p.token_sha256 !== tokenSha) {
      return { status: 'UNKNOWN', code: 'TOKEN_REVOCATION_UNAVAILABLE' };
    }
    if (p.status === 'REVOKED' || p.revoked === true) {
      return { status: 'REVOKED', code: 'TOKEN_REVOKED' };
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
    const assertion = this.config.deviceSigner.signDeviceAssertion({
      worker_id: input.workerId,
      device_id: this.config.deviceId,
      installation_id: input.installationId,
      enrollment_generation: this.config.enrollmentGeneration,
      purpose: 'SERVER_MEDIATED_LEDGER_OP',
      repository: input.repository,
      nowMs: (this.config.nowMs ?? Date.now)(),
    });
    const res = await this.postJsonWithTimeout('/v1/broker/ledger-ops', {
      worker_id: input.workerId,
      device_assertion: assertion,
      ledger_op: {
        operation: input.operation,
        repository: input.repository,
        repository_id: input.repositoryId,
        installation_id: input.installationId,
        worker_id: input.workerId,
        pr_number: input.prNumber,
        head_sha: input.headSha,
        attempt_id: input.attemptId,
        ref_name: input.refName,
        ...(input.turnRefName ? { turn_ref_name: input.turnRefName } : {}),
        ...(input.expectedParentSha ? { expected_parent_sha: input.expectedParentSha } : {}),
        ...(input.isContinuation !== undefined ? { is_continuation: input.isContinuation } : {}),
        commit_message: input.commitMessage,
        tree_sha: input.treeSha,
      },
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
      return {
        ok: true,
        status,
        sha: typeof res.data.sha === 'string' ? res.data.sha : null,
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
