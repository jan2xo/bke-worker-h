/**
 * Shared Sandbox Contracts for F3 Trusted Device Enrollment & Private Broker Reference.
 *
 * SECURITY INVARIANT:
 * - Sandbox reference ONLY. Contains zero real GitHub App PEMs, PATs, Cloudflare secrets,
 *   or production bindings. Never deployed to Cloudflare or attached to canonical CI triggers.
 * - Live ChatGPT message sending remains locked false (`humanLiveSendAuthorized: false`).
 */

import { createHash } from 'node:crypto';

export const ENROLLMENT_CONTRACT_VERSION = 1 as const;
export const BROKER_PROTOCOL_VERSION_V2 = 2 as const;
export const BROKER_AUTHORIZED_CAPABILITY_V2 = 'GITHUB_F1_EXECUTION_V2' as const;
export const ENROLLMENT_CHALLENGE_DOMAIN = 'BKE_DESKTOP_ENROLLMENT_V1\n';
export const DEVICE_POP_DOMAIN = 'BKE_DESKTOP_DEVICE_POP_V1\n';
export const ADMIN_ASSERTION_DOMAIN = 'BKE_ADMIN_APPROVAL_V1\n';
export const EXECUTION_V2_DOMAIN = 'BKE_EXECUTION_REQUEST_V2\n';
export const DEVICE_STATUS_DOMAIN = 'BKE_DEVICE_STATUS_V1\n';
export const TOKEN_STATUS_DOMAIN = 'BKE_TOKEN_STATUS_V1\n';
export const LEDGER_OP_DIGEST_DOMAIN = 'BKE_MEDIATED_LEDGER_OP_V1\n';

export type RevocationState = 'ACTIVE' | 'REVOKED' | 'LOST';
export type DeviceRevocationStatus = 'ACTIVE' | 'REVOKED' | 'UNKNOWN';

export type ExecutionAction =
  | 'PREPARE'
  | 'DISPATCH_FIRST_MESSAGE'
  | 'DISPATCH_CONTINUATION'
  | 'HALT';

export type AdminActionKind =
  | 'APPROVE_ENROLLMENT'
  | 'ROTATE_DEVICE_KEY'
  | 'REVOKE_DEVICE'
  | 'DISPATCH_EXECUTION'
  | 'ROTATE_BROKER_SIGNING_KEY';

export interface AdminApprovalPayload {
  version: 1;
  action: AdminActionKind;
  admin_actor_id: string;
  installation_id: string;
  worker_id: string;
  device_id?: string;
  authorized_repository_scope?: string[];
  pr_number?: number;
  head_sha?: string;
  attempt_id?: string;
  execution_action?: ExecutionAction;
  nonce: string;
  issued_at: string;
  expires_at: string;
}

export interface SignedAdminApproval {
  payload: AdminApprovalPayload;
  signature_alg: 'Ed25519';
  key_id: string;
  signature_b64url: string;
}

export interface EnrollmentChallengeRecord {
  challenge_id: string;
  nonce_b64url: string;
  installation_id: string;
  worker_id: string;
  device_id: string;
  authorized_repository_scope: string[];
  admin_actor_id: string;
  issued_at_ms: number;
  expires_at_ms: number;
  consumed: boolean;
}

export interface EnrolledDeviceRecord {
  version: 1;
  installation_id: string;
  worker_id: string;
  device_id: string;
  public_key_spki_pem: string;
  public_key_sha256: string;
  browser_profile_identity: string;
  native_bridge_identity: string;
  authorized_repository_scope: string[];
  enrollment_generation: number;
  revocation_state: RevocationState;
  revoked_reason: string | null;
  enrolled_at: string;
  updated_at: string;
  enrolled_by_admin: string;
}

export interface EnrollmentStoreState {
  version: 1;
  devices: Record<string, EnrolledDeviceRecord>;
  workerToDeviceId: Record<string, string>;
  usedPublicKeyHashes: string[];
  usedBrowserProfileIdentities: Record<string, string>;
  challenges: Record<string, EnrollmentChallengeRecord>;
  revokedDeviceIds: string[];
}

export interface DeviceSignedAssertionPayload {
  worker_id: string;
  device_id: string;
  installation_id: string;
  enrollment_generation: number;
  purpose: 'AUTHORIZE_EXECUTION' | 'MINT_SCOPED_TOKEN' | 'SERVER_MEDIATED_LEDGER_OP';
  repository: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  ledger_op_sha256?: string;
}

export interface DeviceSignedAssertion {
  payload: DeviceSignedAssertionPayload;
  signature_alg: 'ES256';
  signature_b64url: string;
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
  authorized_capability: typeof BROKER_AUTHORIZED_CAPABILITY_V2;
}

export interface SignedExecutionRequestV2 {
  envelope: ExecutionRequestEnvelopeV2;
  signature_alg: 'Ed25519';
  key_id: string;
  signature_b64url: string;
}

export interface DeviceStatusPayload {
  version: 1;
  broker_issuer: string;
  worker_id: string;
  device_id: string;
  installation_id: string;
  repository: string;
  enrollment_generation: number | null;
  actual_enrollment_generation: number | null;
  status: 'ACTIVE' | 'REVOKED';
  revoked: boolean;
  code: string | null;
  nonce: string;
  issued_at: string;
  expires_at: string;
}

export interface SignedDeviceStatusResponse {
  payload: DeviceStatusPayload;
  signature_alg: 'Ed25519';
  key_id: string;
  signature_b64url: string;
}

export interface TokenStatusPayload {
  version: 1;
  broker_issuer: string;
  token_sha256: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED' | 'UNKNOWN';
  revoked: boolean;
  nonce: string;
  issued_at: string;
  expires_at: string;
}

export interface SignedTokenStatusResponse {
  payload: TokenStatusPayload;
  signature_alg: 'Ed25519';
  key_id: string;
  signature_b64url: string;
}

export interface BrokerSigningKeyEntry {
  key_id: string;
  role: 'EXECUTION' | 'HALT';
  public_key_pem: string;
  private_key_pem: string;
  status: 'ACTIVE' | 'VERIFY_ONLY' | 'RETIRED';
  created_at: string;
}

export interface BrokerAuditEvent {
  seq: number;
  at: string;
  operation: string;
  outcome: 'ALLOWED' | 'DENIED';
  code: string;
  worker_id?: string;
  device_id?: string;
  repository?: string;
  pr_number?: number;
  key_id?: string;
}

export type ServerMediatedLedgerOpKind =
  | 'COMMIT_PRE_SEND_FENCE'
  | 'CONSUME_SEND_CLAIM'
  | 'RECONCILE_CONVERSATION'
  | 'MARK_DELIVERY_UNCERTAIN';

export interface ServerMediatedLedgerOpRequest {
  operation: ServerMediatedLedgerOpKind;
  repository: string;
  repository_id: number;
  installation_id: string;
  worker_id?: string;
  pr_number: number;
  head_sha: string;
  attempt_id: string;
  ref_name: string;
  turn_ref_name?: string;
  expected_parent_sha?: string;
  is_continuation?: boolean;
  commit_message: string;
  tree_sha: string;
}

export interface ServerMediatedLedgerOpResult {
  ok: boolean;
  status: 'COMMITTED' | 'ALREADY_EXISTS' | 'CONFLICT' | 'UNCERTAIN';
  sha?: string | null;
  code?: string;
}

const ALLOWED_LEDGER_OP_KINDS = new Set<string>([
  'COMMIT_PRE_SEND_FENCE',
  'CONSUME_SEND_CLAIM',
  'RECONCILE_CONVERSATION',
  'MARK_DELIVERY_UNCERTAIN',
]);

export const LEDGER_OP_ALLOWLISTED_KEYS = new Set<string>([
  'attempt_id',
  'commit_message',
  'expected_parent_sha',
  'head_sha',
  'installation_id',
  'is_continuation',
  'operation',
  'pr_number',
  'ref_name',
  'repository',
  'repository_id',
  'tree_sha',
  'turn_ref_name',
  'worker_id',
]);

export interface CanonicalServerMediatedLedgerOp {
  attempt_id: string;
  commit_message: string;
  expected_parent_sha: string | null;
  head_sha: string;
  installation_id: string;
  is_continuation: boolean | null;
  operation: ServerMediatedLedgerOpKind;
  pr_number: number;
  ref_name: string;
  repository: string;
  repository_id: number;
  tree_sha: string;
  turn_ref_name: string | null;
  worker_id: string;
}

export function canonicalizeServerMediatedLedgerOp(raw: unknown): CanonicalServerMediatedLedgerOp {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw Error('BROKER_LEDGER_OP_INVALID');
  }
  const obj = raw as Record<string, unknown>;
  if (obj.force === true || obj.force_update === true) {
    throw Error('BROKER_ARBITRARY_PROXY_FORBIDDEN');
  }
  for (const key of Object.keys(obj)) {
    if (!LEDGER_OP_ALLOWLISTED_KEYS.has(key)) {
      throw Error('BROKER_ARBITRARY_PROXY_FORBIDDEN');
    }
  }
  if (
    typeof obj.operation !== 'string' ||
    !ALLOWED_LEDGER_OP_KINDS.has(obj.operation) ||
    typeof obj.repository !== 'string' ||
    typeof obj.repository_id !== 'number' ||
    !Number.isSafeInteger(obj.repository_id) ||
    typeof obj.installation_id !== 'string' ||
    typeof obj.worker_id !== 'string' ||
    obj.worker_id.length === 0 ||
    typeof obj.pr_number !== 'number' ||
    !Number.isSafeInteger(obj.pr_number) ||
    typeof obj.head_sha !== 'string' ||
    typeof obj.attempt_id !== 'string' ||
    typeof obj.ref_name !== 'string' ||
    typeof obj.commit_message !== 'string' ||
    typeof obj.tree_sha !== 'string'
  ) {
    throw Error('BROKER_LEDGER_OP_INVALID');
  }
  if (
    obj.turn_ref_name !== undefined &&
    (typeof obj.turn_ref_name !== 'string' || obj.turn_ref_name.length === 0)
  ) {
    throw Error('BROKER_LEDGER_OP_INVALID');
  }
  if (
    obj.expected_parent_sha !== undefined &&
    (typeof obj.expected_parent_sha !== 'string' || obj.expected_parent_sha.length === 0)
  ) {
    throw Error('BROKER_LEDGER_OP_INVALID');
  }
  if (obj.is_continuation !== undefined && typeof obj.is_continuation !== 'boolean') {
    throw Error('BROKER_LEDGER_OP_INVALID');
  }

  return {
    attempt_id: obj.attempt_id,
    commit_message: obj.commit_message,
    expected_parent_sha: obj.expected_parent_sha === undefined ? null : obj.expected_parent_sha,
    head_sha: obj.head_sha,
    installation_id: obj.installation_id,
    is_continuation: obj.is_continuation === undefined ? null : obj.is_continuation,
    operation: obj.operation as ServerMediatedLedgerOpKind,
    pr_number: obj.pr_number,
    ref_name: obj.ref_name,
    repository: obj.repository,
    repository_id: obj.repository_id,
    tree_sha: obj.tree_sha,
    turn_ref_name: obj.turn_ref_name === undefined ? null : obj.turn_ref_name,
    worker_id: obj.worker_id,
  };
}

export function computeLedgerOpDigestHex(op: ServerMediatedLedgerOpRequest | unknown): string {
  const canonical = canonicalizeServerMediatedLedgerOp(op);
  return createHash('sha256')
    .update(LEDGER_OP_DIGEST_DOMAIN + JSON.stringify(canonical), 'utf8')
    .digest('hex');
}
