/**
 * Shared Sandbox Contracts for F3 Trusted Device Enrollment & Private Broker Reference.
 *
 * SECURITY INVARIANT:
 * - Sandbox reference ONLY. Contains zero real GitHub App PEMs, PATs, Cloudflare secrets,
 *   or production bindings. Never deployed to Cloudflare or attached to canonical CI triggers.
 * - Live ChatGPT message sending remains locked false (`humanLiveSendAuthorized: false`).
 */

export const ENROLLMENT_CONTRACT_VERSION = 1 as const;
export const BROKER_PROTOCOL_VERSION_V2 = 2 as const;
export const BROKER_AUTHORIZED_CAPABILITY_V2 = 'GITHUB_F1_EXECUTION_V2' as const;
export const ENROLLMENT_CHALLENGE_DOMAIN = 'BKE_DESKTOP_ENROLLMENT_V1\n';
export const DEVICE_POP_DOMAIN = 'BKE_DESKTOP_DEVICE_POP_V1\n';
export const ADMIN_ASSERTION_DOMAIN = 'BKE_ADMIN_APPROVAL_V1\n';
export const EXECUTION_V2_DOMAIN = 'BKE_EXECUTION_REQUEST_V2\n';
export const DEVICE_STATUS_DOMAIN = 'BKE_DEVICE_STATUS_V1\n';
export const TOKEN_STATUS_DOMAIN = 'BKE_TOKEN_STATUS_V1\n';

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
  ledger_op?: ServerMediatedLedgerOpKind;
  pr_number?: number;
  head_sha?: string;
  attempt_id?: string;
  ref_name?: string;
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
