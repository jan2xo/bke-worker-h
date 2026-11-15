/**
 * F3-02 Trusted Desktop Device Enrollment & Revocation Registry.
 *
 * Implements sandbox-side cryptographic device pairing, Admin approval verification,
 * P-256 ECDSA proof-of-possession, key rotation, lost-device revocation, and atomic
 * 0o600 disk persistence without any automatic ChatGPT auth or profile export.
 */
import { createHash, createPublicKey, randomBytes, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import {
  ADMIN_ASSERTION_DOMAIN,
  DEVICE_POP_DOMAIN,
  ENROLLMENT_CHALLENGE_DOMAIN,
  ENROLLMENT_CONTRACT_VERSION,
  type AdminApprovalPayload,
  type DeviceSignedAssertion,
  type DeviceSignedAssertionPayload,
  type EnrolledDeviceRecord,
  type EnrollmentChallengeRecord,
  type EnrollmentStoreState,
  type SignedAdminApproval,
} from './types.js';

const WORKER_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const DEVICE_ID_RE = /^[A-Za-z0-9._:-]{6,128}$/;
const INSTALL_RE = /^[0-9]{1,20}$/;
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const CHALLENGE_TTL_MS = 120_000;
const MAX_CLOCK_SKEW_MS = 5_000;
const FORBIDDEN_CLIENT_PRIVILEGE_KEYS = new Set([
  'trusted',
  'admin_approved',
  'adminApproved',
  'self_authorized',
  'selfAuthorized',
  'bypass_admin',
  'bypassAdmin',
  'auto_approve',
  'autoApprove',
  'permissions_override',
  'permissionsOverride',
  'live_send_authorized',
  'liveSendAuthorized',
]);

function canonicalJson(value: Record<string, unknown>): string {
  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    ordered[key] = value[key];
  }
  return JSON.stringify(ordered);
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

export function assertNoClientPrivilegeFlags(raw: unknown): void {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw Error('ENROLLMENT_REQUEST_INVALID');
  }
  for (const key of Object.keys(raw as Record<string, unknown>)) {
    if (FORBIDDEN_CLIENT_PRIVILEGE_KEYS.has(key)) {
      throw Error('ENROLLMENT_PRIVILEGE_ESCALATION_FORBIDDEN');
    }
  }
}

export function signAdminApproval(
  payload: AdminApprovalPayload,
  adminPrivateKeyPem: string,
  keyId: string,
): SignedAdminApproval {
  if (!keyId || !adminPrivateKeyPem.includes('BEGIN PRIVATE KEY')) {
    throw Error('ADMIN_SIGNING_KEY_INVALID');
  }
  const msg = ADMIN_ASSERTION_DOMAIN + canonicalJson(payload as unknown as Record<string, unknown>);
  const sig = cryptoSign(null, Buffer.from(msg, 'utf8'), adminPrivateKeyPem);
  return {
    payload,
    signature_alg: 'Ed25519',
    key_id: keyId,
    signature_b64url: sig.toString('base64url'),
  };
}

export function verifyAdminApproval(
  approval: unknown,
  adminPublicKeysById: ReadonlyMap<string, string>,
  nowMs: number,
  expectedAction?: AdminApprovalPayload['action'],
): AdminApprovalPayload {
  if (!approval || typeof approval !== 'object' || Array.isArray(approval)) {
    throw Error('ENROLLMENT_ADMIN_AUTHORIZATION_MISSING');
  }
  const wrap = approval as Record<string, unknown>;
  if (
    Object.keys(wrap).sort().join(',') !== 'key_id,payload,signature_alg,signature_b64url' ||
    wrap.signature_alg !== 'Ed25519' ||
    typeof wrap.key_id !== 'string' ||
    typeof wrap.signature_b64url !== 'string'
  ) {
    throw Error('ENROLLMENT_ADMIN_AUTHORIZATION_INVALID');
  }
  const pubPem = adminPublicKeysById.get(wrap.key_id);
  if (!pubPem) {
    throw Error('ENROLLMENT_ADMIN_KEY_UNKNOWN');
  }
  const rawPayload = wrap.payload;
  if (!rawPayload || typeof rawPayload !== 'object' || Array.isArray(rawPayload)) {
    throw Error('ENROLLMENT_ADMIN_PAYLOAD_INVALID');
  }
  const payload = rawPayload as AdminApprovalPayload;
  if (payload.version !== 1 || !payload.admin_actor_id || !INSTALL_RE.test(payload.installation_id ?? '')) {
    throw Error('ENROLLMENT_ADMIN_PAYLOAD_INVALID');
  }
  if (expectedAction && payload.action !== expectedAction) {
    throw Error('ENROLLMENT_ADMIN_ACTION_MISMATCH');
  }

  const keyObj = createPublicKey(pubPem);
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw Error('ENROLLMENT_ADMIN_KEY_INVALID');
  }
  const msg = ADMIN_ASSERTION_DOMAIN + canonicalJson(payload as unknown as Record<string, unknown>);
  const ok = cryptoVerify(
    null,
    Buffer.from(msg, 'utf8'),
    keyObj,
    Buffer.from(wrap.signature_b64url, 'base64url'),
  );
  if (!ok) {
    throw Error('ENROLLMENT_ADMIN_SIGNATURE_INVALID');
  }

  const iat = Date.parse(payload.issued_at);
  const exp = Date.parse(payload.expires_at);
  if (!Number.isFinite(iat) || !Number.isFinite(exp) || exp <= iat || exp - iat > 600_000) {
    throw Error('ENROLLMENT_ADMIN_WINDOW_INVALID');
  }
  if (nowMs < iat - MAX_CLOCK_SKEW_MS) {
    throw Error('ENROLLMENT_ADMIN_NOT_YET_VALID');
  }
  if (nowMs >= exp) {
    throw Error('ENROLLMENT_ADMIN_AUTHORIZATION_STALE');
  }
  return payload;
}

export function normalizeAndValidateEcP256SpkiPem(publicKeySpkiPem: string): { pem: string; sha256: string } {
  if (typeof publicKeySpkiPem !== 'string' || !publicKeySpkiPem.includes('BEGIN PUBLIC KEY')) {
    throw Error('ENROLLMENT_PUBLIC_KEY_INVALID');
  }
  let keyObj;
  try {
    keyObj = createPublicKey(publicKeySpkiPem);
  } catch {
    throw Error('ENROLLMENT_PUBLIC_KEY_INVALID');
  }
  if (keyObj.asymmetricKeyType !== 'ec' || keyObj.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw Error('ENROLLMENT_PUBLIC_KEY_CURVE_INVALID');
  }
  const der = keyObj.export({ type: 'spki', format: 'der' });
  const pem = keyObj.export({ type: 'spki', format: 'pem' }).toString();
  const sha256 = createHash('sha256').update(der).digest('hex');
  return { pem, sha256 };
}

function verifyEcP256Signature(
  domainPrefix: string,
  payload: Record<string, unknown>,
  signatureB64Url: string,
  publicKeySpkiPem: string,
): boolean {
  if (typeof signatureB64Url !== 'string' || !signatureB64Url) return false;
  try {
    const keyObj = createPublicKey(publicKeySpkiPem);
    const signingInput = Buffer.from(domainPrefix + canonicalJson(payload), 'utf8');
    const sigBuf = Buffer.from(signatureB64Url, 'base64url');
    // Accept standard IEEE-P1363 (WebCrypto default 64-byte) or DER ASN.1 format
    if (sigBuf.length === 64) {
      return cryptoVerify('sha256', signingInput, { key: keyObj, dsaEncoding: 'ieee-p1363' }, sigBuf);
    }
    return cryptoVerify('sha256', signingInput, keyObj, sigBuf);
  } catch {
    return false;
  }
}

export interface DeviceEnrollmentRegistryConfig {
  storePath: string;
  adminPublicKeysById: ReadonlyMap<string, string>;
  nowMs?: () => number;
}

export class DeviceEnrollmentRegistry {
  private readonly nowMs: () => number;
  private inProcessTail: Promise<void> = Promise.resolve();

  constructor(private readonly config: DeviceEnrollmentRegistryConfig) {
    this.nowMs = config.nowMs ?? (() => Date.now());
  }

  private emptyState(): EnrollmentStoreState {
    return {
      version: 1,
      devices: {},
      workerToDeviceId: {},
      usedPublicKeyHashes: [],
      usedBrowserProfileIdentities: {},
      challenges: {},
      revokedDeviceIds: [],
    };
  }

  private async withFileLock<T>(fn: () => Promise<T>): Promise<T> {
    let release!: () => void;
    const next = new Promise<void>((r) => {
      release = r;
    });
    const prev = this.inProcessTail;
    this.inProcessTail = next;
    await prev;

    try {
      await mkdir(dirname(this.config.storePath), { recursive: true, mode: 0o700 });
      const lockPath = `${this.config.storePath}.lock`;
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
          if (code === 'ELOOP') throw Error('ENROLLMENT_LOCK_SYMLINK_FORBIDDEN');
          if (code !== 'EEXIST') throw err;
          const st = await lstat(lockPath).catch(() => null);
          if (st?.isSymbolicLink()) throw Error('ENROLLMENT_LOCK_SYMLINK_FORBIDDEN');
          if (st && Date.now() - st.mtimeMs > 30_000) {
            await unlink(lockPath).catch(() => undefined);
            continue;
          }
          if (Date.now() >= deadline) throw Error('ENROLLMENT_LOCK_TIMEOUT');
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

  private async readStateOrCreate(): Promise<EnrollmentStoreState> {
    let handle;
    try {
      handle = await open(this.config.storePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === 'ENOENT') {
        const fresh = this.emptyState();
        await this.atomicWrite(fresh);
        return fresh;
      }
      if (code === 'ELOOP') throw Error('ENROLLMENT_SYMLINK_FORBIDDEN');
      throw err;
    }

    let raw: string;
    try {
      const st = await handle.stat();
      if (!st.isFile()) throw Error('ENROLLMENT_STATE_CORRUPT');
      if ((st.mode & 0o077) !== 0) throw Error('ENROLLMENT_PERMISSIONS_INSECURE');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
        throw Error('ENROLLMENT_OWNER_INVALID');
      }
      raw = await handle.readFile({ encoding: 'utf8' });
    } finally {
      await handle.close();
    }

    let parsed: EnrollmentStoreState;
    try {
      parsed = JSON.parse(raw) as EnrollmentStoreState;
    } catch {
      throw Error('ENROLLMENT_STATE_CORRUPT');
    }
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed) ||
      parsed.version !== 1 ||
      !parsed.devices ||
      typeof parsed.devices !== 'object' ||
      !parsed.workerToDeviceId ||
      !Array.isArray(parsed.usedPublicKeyHashes) ||
      !parsed.usedBrowserProfileIdentities ||
      !parsed.challenges ||
      !Array.isArray(parsed.revokedDeviceIds)
    ) {
      throw Error('ENROLLMENT_STATE_CORRUPT');
    }
    return parsed;
  }

  private async atomicWrite(state: EnrollmentStoreState): Promise<void> {
    await mkdir(dirname(this.config.storePath), { recursive: true, mode: 0o700 });
    const tmp = `${this.config.storePath}.${process.pid}.${Date.now()}.tmp`;
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
    await rename(tmp, this.config.storePath);
  }

  async issueChallenge(params: {
    installation_id: string;
    worker_id: string;
    device_id: string;
    authorized_repository_scope: string[];
    admin_approval: SignedAdminApproval;
  }): Promise<EnrollmentChallengeRecord> {
    assertNoClientPrivilegeFlags(params);
    if (
      !INSTALL_RE.test(params.installation_id) ||
      !WORKER_RE.test(params.worker_id) ||
      !DEVICE_ID_RE.test(params.device_id) ||
      !Array.isArray(params.authorized_repository_scope) ||
      params.authorized_repository_scope.length === 0 ||
      params.authorized_repository_scope.some((r) => !REPO_RE.test(r))
    ) {
      throw Error('ENROLLMENT_PARAMS_INVALID');
    }

    const now = this.nowMs();
    const approved = verifyAdminApproval(
      params.admin_approval,
      this.config.adminPublicKeysById,
      now,
      'APPROVE_ENROLLMENT',
    );
    if (
      approved.installation_id !== params.installation_id ||
      approved.worker_id !== params.worker_id ||
      (approved.device_id && approved.device_id !== params.device_id)
    ) {
      throw Error('ENROLLMENT_ADMIN_SCOPE_MISMATCH');
    }
    if (approved.authorized_repository_scope) {
      const allowedSet = new Set(approved.authorized_repository_scope);
      if (params.authorized_repository_scope.some((r) => !allowedSet.has(r))) {
        throw Error('ENROLLMENT_REPOSITORY_SCOPE_ESCALATION');
      }
    }

    return this.withFileLock(async () => {
      const state = await this.readStateOrCreate();
      if (state.revokedDeviceIds.includes(params.device_id)) {
        throw Error('ENROLLMENT_DEVICE_REVOKED');
      }
      const existingWorkerDevice = state.workerToDeviceId[params.worker_id];
      if (existingWorkerDevice && existingWorkerDevice !== params.device_id) {
        const rec = state.devices[existingWorkerDevice];
        if (rec && rec.revocation_state === 'ACTIVE') {
          throw Error('ENROLLMENT_DUPLICATE_WORKER_ACTIVE');
        }
      }
      const existingDevice = state.devices[params.device_id];
      if (existingDevice && existingDevice.revocation_state !== 'ACTIVE') {
        throw Error('ENROLLMENT_DEVICE_REVOKED');
      }

      const challenge: EnrollmentChallengeRecord = {
        challenge_id: randomBytes(24).toString('base64url'),
        nonce_b64url: randomBytes(32).toString('base64url'),
        installation_id: params.installation_id,
        worker_id: params.worker_id,
        device_id: params.device_id,
        authorized_repository_scope: [...params.authorized_repository_scope].sort(),
        admin_actor_id: approved.admin_actor_id,
        issued_at_ms: now,
        expires_at_ms: now + CHALLENGE_TTL_MS,
        consumed: false,
      };
      state.challenges[challenge.challenge_id] = challenge;
      await this.atomicWrite(state);
      return structuredClone(challenge);
    });
  }

  async completeEnrollment(params: {
    challenge_id: string;
    installation_id: string;
    worker_id: string;
    device_id: string;
    public_key_spki_pem: string;
    browser_profile_identity: string;
    native_bridge_identity: string;
    challenge_signature_b64url: string;
  }): Promise<EnrolledDeviceRecord> {
    assertNoClientPrivilegeFlags(params);
    if (
      !SHA256_RE.test(params.browser_profile_identity) ||
      !SHA256_RE.test(params.native_bridge_identity)
    ) {
      throw Error('ENROLLMENT_BINDING_HASH_INVALID');
    }
    const { pem: normalizedPem, sha256: pubHash } = normalizeAndValidateEcP256SpkiPem(params.public_key_spki_pem);

    return this.withFileLock(async () => {
      const state = await this.readStateOrCreate();
      const ch = state.challenges[params.challenge_id];
      if (!ch) throw Error('ENROLLMENT_CHALLENGE_UNKNOWN');
      if (ch.consumed) throw Error('ENROLLMENT_CHALLENGE_REPLAYED');

      const now = this.nowMs();
      if (now >= ch.expires_at_ms) throw Error('ENROLLMENT_CHALLENGE_EXPIRED');
      if (ch.device_id !== params.device_id) throw Error('ENROLLMENT_WRONG_DEVICE');
      if (ch.worker_id !== params.worker_id) throw Error('ENROLLMENT_WRONG_WORKER');
      if (ch.installation_id !== params.installation_id) throw Error('ENROLLMENT_WRONG_INSTALLATION');

      if (state.revokedDeviceIds.includes(params.device_id)) {
        throw Error('ENROLLMENT_DEVICE_REVOKED');
      }
      const existingWorkerDevId = state.workerToDeviceId[params.worker_id];
      if (existingWorkerDevId && existingWorkerDevId !== params.device_id) {
        const existingDev = state.devices[existingWorkerDevId];
        if (existingDev && existingDev.revocation_state === 'ACTIVE') {
          throw Error('ENROLLMENT_DUPLICATE_WORKER_ACTIVE');
        }
      }
      if (state.usedPublicKeyHashes.includes(pubHash)) {
        throw Error('ENROLLMENT_PUBLIC_KEY_REUSED');
      }
      const profileOwner = state.usedBrowserProfileIdentities[params.browser_profile_identity];
      if (profileOwner && profileOwner !== params.device_id) {
        const ownerDev = state.devices[profileOwner];
        if (ownerDev && ownerDev.revocation_state === 'ACTIVE') {
          throw Error('ENROLLMENT_BROWSER_PROFILE_REUSED');
        }
      }

      const proofPayload = {
        browser_profile_identity: params.browser_profile_identity,
        challenge_id: ch.challenge_id,
        device_id: params.device_id,
        installation_id: params.installation_id,
        native_bridge_identity: params.native_bridge_identity,
        nonce_b64url: ch.nonce_b64url,
        public_key_sha256: pubHash,
        worker_id: params.worker_id,
      };
      if (!verifyEcP256Signature(ENROLLMENT_CHALLENGE_DOMAIN, proofPayload, params.challenge_signature_b64url, normalizedPem)) {
        throw Error('ENROLLMENT_DEVICE_SIGNATURE_INVALID');
      }

      ch.consumed = true;
      const nowIso = new Date(now).toISOString();
      const prev = state.devices[params.device_id];
      const generation = prev ? prev.enrollment_generation + 1 : 1;
      const record: EnrolledDeviceRecord = {
        version: ENROLLMENT_CONTRACT_VERSION,
        installation_id: params.installation_id,
        worker_id: params.worker_id,
        device_id: params.device_id,
        public_key_spki_pem: normalizedPem,
        public_key_sha256: pubHash,
        browser_profile_identity: params.browser_profile_identity,
        native_bridge_identity: params.native_bridge_identity,
        authorized_repository_scope: [...ch.authorized_repository_scope],
        enrollment_generation: generation,
        revocation_state: 'ACTIVE',
        revoked_reason: null,
        enrolled_at: prev ? prev.enrolled_at : nowIso,
        updated_at: nowIso,
        enrolled_by_admin: ch.admin_actor_id,
      };

      state.devices[params.device_id] = record;
      state.workerToDeviceId[params.worker_id] = params.device_id;
      state.usedPublicKeyHashes.push(pubHash);
      state.usedBrowserProfileIdentities[params.browser_profile_identity] = params.device_id;
      await this.atomicWrite(state);
      return structuredClone(record);
    });
  }

  async rotateDeviceKey(params: {
    device_id: string;
    worker_id: string;
    installation_id: string;
    new_public_key_spki_pem: string;
    admin_approval: SignedAdminApproval;
    new_key_proof_signature_b64url: string;
    nonce: string;
  }): Promise<EnrolledDeviceRecord> {
    assertNoClientPrivilegeFlags(params);
    const { pem: newPem, sha256: newHash } = normalizeAndValidateEcP256SpkiPem(params.new_public_key_spki_pem);
    const now = this.nowMs();
    const approved = verifyAdminApproval(
      params.admin_approval,
      this.config.adminPublicKeysById,
      now,
      'ROTATE_DEVICE_KEY',
    );
    if (
      approved.installation_id !== params.installation_id ||
      approved.worker_id !== params.worker_id ||
      (approved.device_id && approved.device_id !== params.device_id)
    ) {
      throw Error('ENROLLMENT_ADMIN_SCOPE_MISMATCH');
    }

    return this.withFileLock(async () => {
      const state = await this.readStateOrCreate();
      const dev = state.devices[params.device_id];
      if (!dev) throw Error('ENROLLMENT_DEVICE_UNKNOWN');
      if (dev.revocation_state !== 'ACTIVE' || state.revokedDeviceIds.includes(params.device_id)) {
        throw Error('ENROLLMENT_DEVICE_REVOKED');
      }
      if (dev.worker_id !== params.worker_id || dev.installation_id !== params.installation_id) {
        throw Error('ENROLLMENT_DEVICE_BINDING_MISMATCH');
      }
      if (state.usedPublicKeyHashes.includes(newHash)) {
        throw Error('ENROLLMENT_PUBLIC_KEY_REUSED');
      }
      const rotatePayload = {
        device_id: params.device_id,
        installation_id: params.installation_id,
        new_generation: dev.enrollment_generation + 1,
        new_public_key_sha256: newHash,
        nonce: params.nonce,
        worker_id: params.worker_id,
      };
      if (!verifyEcP256Signature(ENROLLMENT_CHALLENGE_DOMAIN, rotatePayload, params.new_key_proof_signature_b64url, newPem)) {
        throw Error('ENROLLMENT_DEVICE_SIGNATURE_INVALID');
      }

      const updated: EnrolledDeviceRecord = {
        ...dev,
        public_key_spki_pem: newPem,
        public_key_sha256: newHash,
        enrollment_generation: dev.enrollment_generation + 1,
        updated_at: new Date(now).toISOString(),
      };
      state.devices[params.device_id] = updated;
      state.usedPublicKeyHashes.push(newHash);
      await this.atomicWrite(state);
      return structuredClone(updated);
    });
  }

  async revokeDevice(params: {
    device_id: string;
    worker_id: string;
    installation_id: string;
    state: 'REVOKED' | 'LOST';
    reason: string;
    admin_approval: SignedAdminApproval;
  }): Promise<EnrolledDeviceRecord> {
    assertNoClientPrivilegeFlags(params);
    const now = this.nowMs();
    const approved = verifyAdminApproval(
      params.admin_approval,
      this.config.adminPublicKeysById,
      now,
      'REVOKE_DEVICE',
    );
    if (
      approved.installation_id !== params.installation_id ||
      approved.worker_id !== params.worker_id ||
      (approved.device_id && approved.device_id !== params.device_id)
    ) {
      throw Error('ENROLLMENT_ADMIN_SCOPE_MISMATCH');
    }

    return this.withFileLock(async () => {
      const store = await this.readStateOrCreate();
      const dev = store.devices[params.device_id];
      if (!dev) throw Error('ENROLLMENT_DEVICE_UNKNOWN');
      const next: EnrolledDeviceRecord = {
        ...dev,
        revocation_state: params.state,
        revoked_reason: params.reason || params.state,
        updated_at: new Date(now).toISOString(),
      };
      store.devices[params.device_id] = next;
      if (!store.revokedDeviceIds.includes(params.device_id)) {
        store.revokedDeviceIds.push(params.device_id);
      }
      await this.atomicWrite(store);
      return structuredClone(next);
    });
  }

  async verifyDeviceAssertion(
    assertion: DeviceSignedAssertion,
    expectedPurpose: DeviceSignedAssertionPayload['purpose'],
    expectedRepository: string,
  ): Promise<EnrolledDeviceRecord> {
    if (!assertion || typeof assertion !== 'object' || Array.isArray(assertion)) {
      throw Error('DEVICE_ASSERTION_INVALID');
    }
    if (assertion.signature_alg !== 'ES256' || typeof assertion.signature_b64url !== 'string') {
      throw Error('DEVICE_ASSERTION_ALG_INVALID');
    }
    const rawPayload = assertion.payload as unknown;
    if (!rawPayload || typeof rawPayload !== 'object' || Array.isArray(rawPayload)) {
      throw Error('DEVICE_ASSERTION_INVALID');
    }
    const pObj = rawPayload as Record<string, unknown>;
    if (
      Object.keys(pObj).sort().join(',') !==
        'device_id,enrollment_generation,expires_at,installation_id,issued_at,nonce,purpose,repository,worker_id' ||
      typeof pObj.worker_id !== 'string' ||
      typeof pObj.device_id !== 'string' ||
      typeof pObj.installation_id !== 'string' ||
      typeof pObj.enrollment_generation !== 'number' ||
      !Number.isSafeInteger(pObj.enrollment_generation) ||
      typeof pObj.purpose !== 'string' ||
      typeof pObj.repository !== 'string' ||
      typeof expectedRepository !== 'string' ||
      typeof pObj.nonce !== 'string' ||
      pObj.nonce.length < 8 ||
      typeof pObj.issued_at !== 'string' ||
      typeof pObj.expires_at !== 'string'
    ) {
      throw Error('DEVICE_ASSERTION_INVALID');
    }
    const p = rawPayload as DeviceSignedAssertionPayload;
    if (p.purpose !== expectedPurpose) {
      throw Error('DEVICE_ASSERTION_PURPOSE_MISMATCH');
    }
    if (!REPO_RE.test(p.repository) || p.repository.toLowerCase() !== expectedRepository.toLowerCase()) {
      throw Error('DEVICE_ASSERTION_REPOSITORY_MISMATCH');
    }

    const now = this.nowMs();
    const issued = Date.parse(p.issued_at);
    const expires = Date.parse(p.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > 120_000) {
      throw Error('DEVICE_ASSERTION_WINDOW_INVALID');
    }
    if (now < issued - MAX_CLOCK_SKEW_MS) throw Error('DEVICE_ASSERTION_NOT_YET_VALID');
    if (now >= expires) throw Error('DEVICE_ASSERTION_EXPIRED');

    const state = await this.withFileLock(() => this.readStateOrCreate());
    const dev = state.devices[p.device_id];
    if (!dev) throw Error('DEVICE_UNKNOWN');
    if (dev.revocation_state !== 'ACTIVE' || state.revokedDeviceIds.includes(dev.device_id)) {
      throw Error('DEVICE_REVOKED');
    }
    if (dev.worker_id !== p.worker_id) throw Error('DEVICE_WORKER_MISMATCH');
    if (dev.installation_id !== p.installation_id) throw Error('DEVICE_INSTALLATION_MISMATCH');
    if (p.enrollment_generation !== dev.enrollment_generation) {
      throw Error('DEVICE_ENROLLMENT_GENERATION_STALE');
    }
    if (!dev.authorized_repository_scope.some((r) => r.toLowerCase() === expectedRepository.toLowerCase())) {
      throw Error('DEVICE_REPOSITORY_UNAUTHORIZED');
    }
    const ok = verifyEcP256Signature(
      DEVICE_POP_DOMAIN,
      p as unknown as Record<string, unknown>,
      assertion.signature_b64url,
      dev.public_key_spki_pem,
    );
    if (!ok) throw Error('DEVICE_SIGNATURE_INVALID');
    return structuredClone(dev);
  }

  async inspectDeviceStatus(info: {
    workerId: string;
    deviceId?: string;
    installationId?: string;
    repository?: string;
    enrollmentGeneration?: number;
  }): Promise<{
    status: 'ACTIVE' | 'REVOKED';
    revoked: boolean;
    code?: string;
    device: EnrolledDeviceRecord | null;
  }> {
    if (typeof info.workerId !== 'string' || !WORKER_RE.test(info.workerId)) {
      return { status: 'REVOKED', revoked: true, code: 'EXEC_REQ_WORKER_MISMATCH', device: null };
    }
    if (info.deviceId !== undefined && (typeof info.deviceId !== 'string' || !info.deviceId)) {
      return { status: 'REVOKED', revoked: true, code: 'EXEC_REQ_DEVICE_UNKNOWN', device: null };
    }
    const state = await this.withFileLock(() => this.readStateOrCreate());
    const devId = info.deviceId ?? state.workerToDeviceId[info.workerId];
    if (!devId) return { status: 'REVOKED', revoked: true, code: 'EXEC_REQ_DEVICE_UNKNOWN', device: null };
    const dev = state.devices[devId] ?? null;
    if (!dev || dev.revocation_state !== 'ACTIVE' || state.revokedDeviceIds.includes(devId)) {
      return { status: 'REVOKED', revoked: true, code: 'EXEC_REQ_DEVICE_REVOKED', device: dev };
    }
    if (dev.worker_id !== info.workerId) {
      return { status: 'REVOKED', revoked: true, code: 'EXEC_REQ_WORKER_MISMATCH', device: dev };
    }
    if (info.installationId !== undefined && (typeof info.installationId !== 'string' || dev.installation_id !== info.installationId)) {
      return { status: 'REVOKED', revoked: true, code: 'EXEC_REQ_INSTALLATION_MISMATCH', device: dev };
    }
    if (
      info.repository !== undefined &&
      (typeof info.repository !== 'string' ||
        !REPO_RE.test(info.repository) ||
        !dev.authorized_repository_scope.some((r) => r.toLowerCase() === info.repository!.toLowerCase()))
    ) {
      return { status: 'REVOKED', revoked: true, code: 'DEVICE_REPOSITORY_UNAUTHORIZED', device: dev };
    }
    if (info.enrollmentGeneration !== undefined) {
      if (
        typeof info.enrollmentGeneration !== 'number' ||
        !Number.isSafeInteger(info.enrollmentGeneration) ||
        info.enrollmentGeneration < 1
      ) {
        return { status: 'REVOKED', revoked: true, code: 'EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH', device: dev };
      }
      if (info.enrollmentGeneration !== dev.enrollment_generation) {
        const code =
          info.enrollmentGeneration < dev.enrollment_generation
            ? 'EXEC_REQ_ENROLLMENT_STALE'
            : 'EXEC_REQ_ENROLLMENT_GENERATION_MISMATCH';
        return { status: 'REVOKED', revoked: true, code, device: dev };
      }
    }
    return { status: 'ACTIVE', revoked: false, device: structuredClone(dev) };
  }
}
