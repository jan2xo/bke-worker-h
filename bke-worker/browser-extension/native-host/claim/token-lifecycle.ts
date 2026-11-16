/**
 * F2-04 Short-Lived Scoped Credential Lifecycle Provider & Deterministic Mock Broker.
 *
 * Addresses F1's static startup `BKE_GITHUB_INSTALLATION_TOKEN` limitation by
 * introducing an installation- and repository-scoped credential lifecycle manager
 * with preemptive renewal, single-flight refresh coalescing, permission clamping,
 * bounded timeouts, cancellation, revocation handling, and strict redaction.
 *
 * Security invariants:
 * - No GitHub App private key or Admin PAT ever resides on the desktop worker.
 * - Elevated or cross-repo / cross-installation broker responses fail closed.
 * - Tokens are NEVER written into errors, logs, telemetry, or diagnostics.
 * - Real remote broker transport stays DISABLED by default until owner-certified.
 */
import type { TokenProvider } from './send-once-claim-adapter.js';

export type PermissionAccessLevel = 'none' | 'read' | 'write';

const PERMISSION_RANK: Record<string, number> = {
  none: 0,
  read: 1,
  write: 2,
  admin: 99,
};

const TOKEN_LEAK_RE = /(Bearer\s+[A-Za-z0-9._-]+|gh[pousr]_[A-Za-z0-9_]+)/gi;
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const INSTALL_ID_RE = /^[0-9]{1,20}$/;

export function sanitizeTokenErrorMessage(msg: string, secretCandidates: string[] = []): string {
  let clean = msg.replace(TOKEN_LEAK_RE, '[REDACTED_TOKEN]');
  for (const s of secretCandidates) {
    if (s && s.length >= 4) {
      clean = clean.split(s).join('[REDACTED_TOKEN]');
    }
  }
  return clean.slice(0, 128);
}

export interface TokenBrokerRequest {
  repository: string;
  repositoryId?: number;
  installationId: string;
  workerId: string;
  requestedPermissions: Record<string, PermissionAccessLevel>;
  reason: string;
  signal: AbortSignal;
}

export interface IssuedScopedToken {
  token: string;
  tokenType: 'installation';
  installationId: string;
  repositoryId?: number;
  repositories: string[];
  permissions: Record<string, string>;
  issuedAtMs: number;
  /** Application-enforced usage/refresh deadline (may be shorter than GitHub's provider expiry). */
  expiresAtMs: number;
  usageExpiresAtMs?: number;
  /** GitHub provider-enforced installation token expiry unless revoked via DELETE /installation/token. */
  providerExpiresAtMs?: number;
}

export type TokenRevocationStatus = 'ACTIVE' | 'REVOKED' | 'EXPIRED' | 'UNKNOWN';

export interface TokenBrokerClient {
  readonly kind: 'MOCK_BROKER' | 'REMOTE_OWNER_CERTIFIED_BROKER';
  issueToken(request: TokenBrokerRequest): Promise<IssuedScopedToken>;
  checkTokenStatus?(
    token: string,
  ): Promise<TokenRevocationStatus | { status: TokenRevocationStatus; code?: string }> | TokenRevocationStatus | { status: TokenRevocationStatus; code?: string };
  isRevoked?(token: string): Promise<boolean> | boolean;
}

export interface TokenLifecycleStatus {
  tokenLifecycleInterfaceImplemented: true;
  mockBrokerSupported: boolean;
  trustedRealBrokerApiAvailable: boolean;
  realBrokerTransportConnected: boolean;
  realGitHubAppRenewalCertified: boolean;
  brokerKind: 'MOCK_BROKER' | 'REMOTE_OWNER_CERTIFIED_BROKER' | 'REMOTE_DISABLED' | 'UNCONFIGURED';
  hasCachedToken: boolean;
  expiresAtMs: number | null;
  revoked: boolean;
  requestedContentsLevel?: PermissionAccessLevel;
  lastRecoveryClassification?: 'NONE' | 'RECOVERED_TRANSIENT' | 'BLOCKED_PERMANENT';
}

export interface ScopedTokenLifecycleProvider {
  getToken(options?: { forceRefresh?: boolean; minTtlMs?: number; signal?: AbortSignal }): Promise<string>;
  hasValidToken(minTtlMs?: number): boolean;
  invalidate(reason: string): void;
  getStatus(): TokenLifecycleStatus;
  asTokenProvider(): TokenProvider;
}

export interface ManagedTokenProviderConfig {
  repository: string;
  repositoryId?: number;
  installationId: string;
  workerId: string;
  allowedPermissions: Record<string, PermissionAccessLevel>;
  refreshMarginMs?: number;
  requestTimeoutMs?: number;
  minValidRemainingMs?: number;
  maxTransientRetries?: number;
  retryDelayMs?: number;
  trustedRealBrokerApiAvailable?: boolean;
  realBrokerTransportConnected?: boolean;
  realGitHubAppRenewalCertified?: boolean;
  nowMs?: () => number;
}

export class ManagedTokenProvider implements ScopedTokenLifecycleProvider {
  private readonly refreshMarginMs: number;
  private readonly requestTimeoutMs: number;
  private readonly minValidRemainingMs: number;
  private readonly maxTransientRetries: number;
  private readonly retryDelayMs: number;
  private readonly nowMs: () => number;

  private cached: IssuedScopedToken | null = null;
  private inFlightRefresh: Promise<IssuedScopedToken> | null = null;
  private revokedFlag = false;
  private lastRecoveryClassification: 'NONE' | 'RECOVERED_TRANSIENT' | 'BLOCKED_PERMANENT' = 'NONE';

  constructor(
    private readonly config: ManagedTokenProviderConfig,
    private readonly broker: TokenBrokerClient,
  ) {
    if (
      !REPO_RE.test(config.repository) ||
      !INSTALL_ID_RE.test(config.installationId) ||
      !config.workerId
    ) {
      throw Error('TOKEN_PROVIDER_CONFIG_INVALID');
    }
    this.refreshMarginMs = config.refreshMarginMs ?? 60_000;
    this.requestTimeoutMs = config.requestTimeoutMs ?? 5_000;
    this.minValidRemainingMs = config.minValidRemainingMs ?? 5_000;
    this.maxTransientRetries = Math.max(0, Math.min(3, config.maxTransientRetries ?? 0));
    this.retryDelayMs = Math.max(0, Math.min(250, config.retryDelayMs ?? 15));
    this.nowMs = config.nowMs ?? (() => Date.now());
  }

  hasValidToken(minTtlMs = this.minValidRemainingMs): boolean {
    if (this.revokedFlag || !this.cached) return false;
    const now = this.nowMs();
    return this.cached.expiresAtMs - now > minTtlMs;
  }

  invalidate(_reason: string): void {
    this.cached = null;
    this.revokedFlag = true;
  }

  getStatus(): TokenLifecycleStatus {
    const now = this.nowMs();
    const valid = Boolean(this.cached && !this.revokedFlag && this.cached.expiresAtMs - now > this.minValidRemainingMs);
    return {
      tokenLifecycleInterfaceImplemented: true,
      mockBrokerSupported: this.broker.kind === 'MOCK_BROKER',
      trustedRealBrokerApiAvailable: Boolean(this.config.trustedRealBrokerApiAvailable),
      realBrokerTransportConnected: Boolean(this.config.realBrokerTransportConnected),
      realGitHubAppRenewalCertified: Boolean(this.config.realGitHubAppRenewalCertified),
      brokerKind:
        this.broker.kind === 'MOCK_BROKER'
          ? 'MOCK_BROKER'
          : this.config.trustedRealBrokerApiAvailable && this.config.realBrokerTransportConnected
            ? 'REMOTE_OWNER_CERTIFIED_BROKER'
            : 'REMOTE_DISABLED',
      hasCachedToken: valid,
      expiresAtMs: valid && this.cached ? this.cached.expiresAtMs : null,
      revoked: this.revokedFlag,
      requestedContentsLevel: this.config.allowedPermissions.contents ?? 'none',
      lastRecoveryClassification: this.lastRecoveryClassification,
    };
  }

  asTokenProvider(): TokenProvider {
    return () => this.getToken();
  }

  async getToken(
    options: { forceRefresh?: boolean; minTtlMs?: number; signal?: AbortSignal } = {},
  ): Promise<string> {
    if (options.signal?.aborted) {
      throw Error('TOKEN_REQUEST_ABORTED');
    }

    const now = this.nowMs();
    const minNeeded = Math.max(this.minValidRemainingMs, options.minTtlMs ?? 0);

    // Check revocation hook on broker fail-closed before returning cached credential
    if (this.cached && !this.revokedFlag) {
      if (this.broker.checkTokenStatus) {
        let rawStatus: TokenRevocationStatus | { status: TokenRevocationStatus; code?: string };
        try {
          rawStatus = await Promise.resolve(this.broker.checkTokenStatus(this.cached.token));
        } catch (err) {
          const msg = err instanceof Error ? err.message : '';
          throw Error(msg.startsWith('TOKEN_') ? msg : 'TOKEN_REVOCATION_UNAVAILABLE');
        }
        const status = typeof rawStatus === 'string' ? rawStatus : rawStatus?.status;
        const code = typeof rawStatus === 'object' && rawStatus ? rawStatus.code : undefined;
        if (status === 'REVOKED') {
          this.cached = null;
          this.revokedFlag = true;
          throw Error('TOKEN_REVOKED');
        }
        if (status === 'EXPIRED') {
          this.cached = null;
          throw Error('TOKEN_EXPIRED');
        }
        if (status !== 'ACTIVE') {
          throw Error(code && code.startsWith('TOKEN_') ? code : 'TOKEN_REVOCATION_UNAVAILABLE');
        }
      } else if (this.broker.isRevoked) {
        let revoked: boolean;
        try {
          revoked = await Promise.resolve(this.broker.isRevoked(this.cached.token));
        } catch {
          throw Error('TOKEN_REVOCATION_UNAVAILABLE');
        }
        if (revoked !== false) {
          this.cached = null;
          this.revokedFlag = true;
          throw Error('TOKEN_REVOKED');
        }
      } else if (this.broker.kind === 'REMOTE_OWNER_CERTIFIED_BROKER') {
        throw Error('TOKEN_REVOCATION_CHECKER_MISSING');
      }
    }

    const needsRefresh =
      options.forceRefresh === true ||
      this.revokedFlag ||
      !this.cached ||
      this.cached.expiresAtMs - now <= Math.max(this.refreshMarginMs, minNeeded);

    if (!needsRefresh && this.cached) {
      return this.cached.token;
    }

    const fresh = await this.coalescedRefresh(options.signal);
    const postNow = this.nowMs();
    if (fresh.expiresAtMs - postNow <= minNeeded) {
      throw Error('TOKEN_EXPIRED_OR_INSUFFICIENT_TTL');
    }
    return fresh.token;
  }

  private async coalescedRefresh(callerSignal?: AbortSignal): Promise<IssuedScopedToken> {
    if (!this.inFlightRefresh) {
      this.inFlightRefresh = this.fetchAndValidateFromBroker().finally(() => {
        this.inFlightRefresh = null;
      });
    }

    if (!callerSignal) {
      return this.inFlightRefresh;
    }

    return await new Promise<IssuedScopedToken>((resolve, reject) => {
      if (callerSignal.aborted) {
        reject(Error('TOKEN_REQUEST_ABORTED'));
        return;
      }
      const onAbort = () => reject(Error('TOKEN_REQUEST_ABORTED'));
      callerSignal.addEventListener('abort', onAbort, { once: true });
      this.inFlightRefresh!.then(
        (tok) => {
          callerSignal.removeEventListener('abort', onAbort);
          resolve(tok);
        },
        (err) => {
          callerSignal.removeEventListener('abort', onAbort);
          reject(err);
        },
      );
    });
  }

  private static isRetryableCredentialError(code: string): boolean {
    return code === 'TOKEN_BROKER_UNAVAILABLE' || code === 'TOKEN_BROKER_TIMEOUT';
  }

  private async fetchAndValidateFromBroker(): Promise<IssuedScopedToken> {
    let lastError: Error = Error('TOKEN_BROKER_UNAVAILABLE');
    for (let attempt = 0; attempt <= this.maxTransientRetries; attempt++) {
      try {
        const token = await this.fetchAndValidateOnce();
        this.lastRecoveryClassification = attempt > 0 ? 'RECOVERED_TRANSIENT' : 'NONE';
        return token;
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'TOKEN_BROKER_UNAVAILABLE';
        lastError = err instanceof Error ? err : Error(msg);
        if (!ManagedTokenProvider.isRetryableCredentialError(msg) || attempt === this.maxTransientRetries) {
          this.lastRecoveryClassification = 'BLOCKED_PERMANENT';
          throw lastError;
        }
        if (this.retryDelayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, this.retryDelayMs));
        }
      }
    }
    throw lastError;
  }

  private async fetchAndValidateOnce(): Promise<IssuedScopedToken> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(Error('TOKEN_BROKER_TIMEOUT'));
      }, this.requestTimeoutMs);
    });

    const reqPromise = (async () => {
      let issued: IssuedScopedToken;
      try {
        issued = await this.broker.issueToken({
          repository: this.config.repository,
          repositoryId: this.config.repositoryId,
          installationId: this.config.installationId,
          workerId: this.config.workerId,
          requestedPermissions: { ...this.config.allowedPermissions },
          reason: 'BKE_DESKTOP_WORKER_EXECUTION',
          signal: controller.signal,
        });
      } catch (err) {
        if (controller.signal.aborted) {
          throw Error('TOKEN_BROKER_TIMEOUT');
        }
        const msg = err instanceof Error ? err.message : 'TOKEN_BROKER_UNAVAILABLE';
        const safe = sanitizeTokenErrorMessage(msg);
        if (safe.startsWith('TOKEN_') || safe.startsWith('REAL_BROKER_')) {
          throw Error(safe);
        }
        throw Error('TOKEN_BROKER_UNAVAILABLE');
      }
      return this.validateIssuedToken(issued);
    })();

    try {
      const valid = await Promise.race([reqPromise, timeoutPromise]);
      this.cached = valid;
      this.revokedFlag = false;
      return valid;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private validateIssuedToken(issued: IssuedScopedToken): IssuedScopedToken {
    if (!issued || typeof issued !== 'object' || Array.isArray(issued)) {
      throw Error('TOKEN_RESPONSE_INVALID');
    }
    const rawToken = typeof issued.token === 'string' ? issued.token.trim() : '';
    if (!rawToken || rawToken.length < 8) {
      throw Error('TOKEN_VALUE_INVALID');
    }
    if (issued.tokenType !== 'installation') {
      throw Error('TOKEN_TYPE_INVALID');
    }
    if (issued.installationId !== this.config.installationId) {
      throw Error('TOKEN_INSTALLATION_MISMATCH');
    }
    if (
      !Array.isArray(issued.repositories) ||
      issued.repositories.length !== 1 ||
      issued.repositories[0]?.toLowerCase() !== this.config.repository.toLowerCase()
    ) {
      throw Error('TOKEN_REPOSITORY_SCOPE_MISMATCH');
    }
    if (
      this.config.repositoryId !== undefined &&
      ((this.broker.kind === 'REMOTE_OWNER_CERTIFIED_BROKER' && issued.repositoryId === undefined) ||
        (issued.repositoryId !== undefined && issued.repositoryId !== this.config.repositoryId))
    ) {
      throw Error('TOKEN_REPOSITORY_ID_MISMATCH');
    }

    const now = this.nowMs();
    if (!Number.isFinite(issued.issuedAtMs) || !Number.isFinite(issued.expiresAtMs)) {
      throw Error('TOKEN_TIMESTAMPS_INVALID');
    }
    if (issued.issuedAtMs > now + 5_000) {
      throw Error('TOKEN_ISSUED_IN_FUTURE');
    }
    if (issued.expiresAtMs <= now + this.minValidRemainingMs) {
      throw Error('TOKEN_ALREADY_EXPIRED_OR_STALE');
    }

    // Reject permission elevation: broker may only grant allowed permissions at <= allowed level.
    if (!issued.permissions || typeof issued.permissions !== 'object' || Array.isArray(issued.permissions)) {
      throw Error('TOKEN_PERMISSIONS_INVALID');
    }
    for (const [scope, level] of Object.entries(issued.permissions)) {
      const allowedLevel = this.config.allowedPermissions[scope];
      if (!allowedLevel) {
        throw Error('TOKEN_PERMISSION_ELEVATION_FORBIDDEN');
      }
      const grantedRank = PERMISSION_RANK[String(level)] ?? 99;
      const allowedRank = PERMISSION_RANK[allowedLevel] ?? 0;
      if (grantedRank > allowedRank) {
        throw Error('TOKEN_PERMISSION_ELEVATION_FORBIDDEN');
      }
    }

    return {
      ...issued,
      token: rawToken,
      repositories: [this.config.repository],
      permissions: { ...issued.permissions },
    };
  }
}

export class RemoteBrokerTransportStub implements TokenBrokerClient {
  readonly kind = 'REMOTE_OWNER_CERTIFIED_BROKER' as const;

  constructor(
    private readonly options: {
      endpointUrl?: string;
      ownerCertifiedBrokerEnabled?: boolean;
    } = {},
  ) {}

  async issueToken(_request: TokenBrokerRequest): Promise<IssuedScopedToken> {
    if (this.options.ownerCertifiedBrokerEnabled !== true || !this.options.endpointUrl) {
      throw Error('REAL_BROKER_TRANSPORT_DISABLED_NOT_AUTHORIZED');
    }
    throw Error('REAL_BROKER_TRANSPORT_UNIMPLEMENTED_REQUIRES_OWNER_SPEC');
  }
}

export interface MockBrokerBehavior {
  ttlMs?: number;
  unavailable?: boolean;
  latencyMs?: number;
  revokedAfterIssueCount?: number;
  forceInstallationId?: string;
  forceRepositories?: string[];
  forceRepositoryId?: number;
  forcePermissions?: Record<string, string>;
  forceExpiresAtMs?: number;
  forceIssuedAtMs?: number;
}

export class DeterministicMockTokenBroker implements TokenBrokerClient {
  readonly kind = 'MOCK_BROKER' as const;
  private issueCounter = 0;
  private revokedTokens = new Set<string>();
  public issueCalls = 0;
  public behavior: MockBrokerBehavior;

  constructor(
    private readonly nowMs: () => number = () => Date.now(),
    behavior: MockBrokerBehavior = {},
  ) {
    this.behavior = { ...behavior };
  }

  revokeToken(token: string): void {
    this.revokedTokens.add(token);
  }

  isRevoked(token: string): boolean {
    return this.revokedTokens.has(token);
  }

  async issueToken(request: TokenBrokerRequest): Promise<IssuedScopedToken> {
    this.issueCalls += 1;
    if (this.behavior.latencyMs && this.behavior.latencyMs > 0) {
      await new Promise<void>((resolve, reject) => {
        if (request.signal.aborted) {
          reject(Error('TOKEN_BROKER_ABORTED'));
          return;
        }
        const timer = setTimeout(resolve, this.behavior.latencyMs);
        request.signal.addEventListener(
          'abort',
          () => {
            clearTimeout(timer);
            reject(Error('TOKEN_BROKER_ABORTED'));
          },
          { once: true },
        );
      });
    }
    if (this.behavior.unavailable) {
      throw Error('TOKEN_BROKER_UNAVAILABLE');
    }

    this.issueCounter += 1;
    const token = `ghs_mock_inst_${this.issueCounter}_${request.workerId}`;
    if (
      this.behavior.revokedAfterIssueCount !== undefined &&
      this.issueCounter >= this.behavior.revokedAfterIssueCount
    ) {
      this.revokedTokens.add(token);
    }

    const now = this.nowMs();
    const ttlMs = this.behavior.ttlMs ?? 300_000;
    return {
      token,
      tokenType: 'installation',
      installationId: this.behavior.forceInstallationId ?? request.installationId,
      repositoryId: this.behavior.forceRepositoryId ?? request.repositoryId,
      repositories: this.behavior.forceRepositories ?? [request.repository],
      permissions: this.behavior.forcePermissions ?? { ...request.requestedPermissions },
      issuedAtMs: this.behavior.forceIssuedAtMs ?? now,
      expiresAtMs: this.behavior.forceExpiresAtMs ?? now + ttlMs,
    };
  }
}

export class StaticUnrenewableTokenProvider implements ScopedTokenLifecycleProvider {
  constructor(private readonly getStaticToken: TokenProvider) {}

  async getToken(): Promise<string> {
    const tok = await this.getStaticToken();
    if (!tok || !tok.trim()) {
      throw Error('GITHUB_AUTH_UNAVAILABLE');
    }
    return tok.trim();
  }

  hasValidToken(): boolean {
    return false;
  }

  invalidate(): void {
    // No-op for static env fallback
  }

  getStatus(): TokenLifecycleStatus {
    return {
      tokenLifecycleInterfaceImplemented: true,
      mockBrokerSupported: false,
      trustedRealBrokerApiAvailable: false,
      realBrokerTransportConnected: false,
      realGitHubAppRenewalCertified: false,
      brokerKind: 'REMOTE_DISABLED',
      hasCachedToken: false,
      expiresAtMs: null,
      revoked: false,
    };
  }

  asTokenProvider(): TokenProvider {
    return () => this.getToken();
  }
}
