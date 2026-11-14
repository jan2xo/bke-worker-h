/**
 * F3-02 / F3-04 / F3-06 Device Crypto Signer & Sandbox HTTP Token Broker Client.
 *
 * Generates device-owned ECDSA P-256 keypairs (private key stays strictly on the device),
 * signs pairing challenges & runtime PoP assertions, and implements ManagedTokenProvider's
 * TokenBrokerClient over loopback HTTP for sandbox E2E & lifecycle tests.
 */
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';
import {
  DEVICE_POP_DOMAIN,
  ENROLLMENT_CHALLENGE_DOMAIN,
  type DeviceSignedAssertion,
  type DeviceSignedAssertionPayload,
  type EnrollmentChallengeRecord,
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
      expires_at: new Date(now + (params.ttlMs ?? 60_000)).toISOString(),
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
      nowMs?: () => number;
    },
  ) {}

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

  async isRevoked(token: string): Promise<boolean> {
    try {
      const res = await globalThis.fetch(
        `${this.config.brokerBaseUrl.replace(/\/+$/, '')}/v1/broker/token-status`,
        {
          method: 'POST',
          redirect: 'manual',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token }),
        },
      );
      if (!res.ok) return false;
      const body = (await res.json()) as { revoked?: boolean };
      return body.revoked === true;
    } catch {
      return false;
    }
  }
}
