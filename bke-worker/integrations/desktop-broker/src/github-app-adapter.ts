/**
 * F3-03 / F3-05 Server-Side Sandbox GitHub App Authority & Scoped Token Adapter.
 *
 * SECURITY INVARIANT:
 * - Sandbox simulation only. Uses ephemeral test-only signing keys (NEVER real GitHub App PEMs).
 * - Enforces `redirect: 'manual'`, complete paginated enumeration, installation ID binding,
 *   cross-repository exclusive PR assignment, exact head_sha & bke-ticket:v1 verification,
 *   and strict single-repo / least-privilege token clamping.
 * - Includes server-mediated CAS operation prototype (`COMMIT_PRE_SEND_FENCE`,
 *   `CONSUME_SEND_CLAIM`, `RECONCILE_CONVERSATION`, `MARK_DELIVERY_UNCERTAIN`) and refuses
 *   arbitrary GitHub API proxying.
 */
import { createPrivateKey, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import type { ServerMediatedLedgerOpRequest, ServerMediatedLedgerOpResult } from './types.js';

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA40_RE = /^[a-f0-9]{40}$/;
const WORKER_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const ATTEMPT_RE = /^[a-z0-9][a-z0-9-]{0,95}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9_-]{8,128}$/;
const INSTALL_RE = /^[0-9]{1,20}$/;

function base64UrlJson(obj: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

export interface GitHubAppAdapterConfig {
  appId: number;
  appSlug: string;
  apiBaseUrl: string;
  /** Test-only ephemeral RS256/Ed25519 key in PKCS8 PEM; generated dynamically if omitted. */
  sandboxAppPrivateKeyPem?: string;
  timeoutMs?: number;
  maxPages?: number;
  nowMs?: () => number;
}

export interface VerifiedBrokerAuthority {
  installationId: string;
  repositoryId: number;
  repositoryFullName: string;
  prNumber: number;
  headSha: string;
  attemptId: string;
  ticketCheckRunId: number;
  conversationExists: boolean;
  installedRepoCount: number;
}

export class SandboxGitHubAppAdapter {
  private readonly appId: number;
  private readonly appSlug: string;
  private readonly apiBaseUrl: string;
  private readonly baseOrigin: string;
  private readonly signingPrivateKeyPem: string;
  private readonly signingAlg: 'RS256' | 'EdDSA';
  private readonly timeoutMs: number;
  private readonly maxPages: number;
  private readonly nowMs: () => number;

  constructor(config: GitHubAppAdapterConfig) {
    if (!Number.isSafeInteger(config.appId) || config.appId <= 0 || !config.appSlug) {
      throw Error('BROKER_APP_CONFIG_INVALID');
    }
    const parsedUrl = new URL(config.apiBaseUrl);
    this.appId = config.appId;
    this.appSlug = config.appSlug;
    this.apiBaseUrl = config.apiBaseUrl.replace(/\/+$/, '');
    this.baseOrigin = parsedUrl.origin;
    this.timeoutMs = config.timeoutMs ?? 4_000;
    this.maxPages = config.maxPages ?? 5;
    this.nowMs = config.nowMs ?? (() => Date.now());

    if (config.sandboxAppPrivateKeyPem) {
      this.signingPrivateKeyPem = config.sandboxAppPrivateKeyPem;
      const pk = createPrivateKey(config.sandboxAppPrivateKeyPem);
      this.signingAlg = pk.asymmetricKeyType === 'ed25519' ? 'EdDSA' : 'RS256';
    } else {
      const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      this.signingPrivateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
      this.signingAlg = 'RS256';
    }
  }

  private createSandboxAppJwt(): string {
    const nowSec = Math.floor(this.nowMs() / 1000);
    const header = base64UrlJson({ alg: this.signingAlg, typ: 'JWT' });
    const payload = base64UrlJson({
      iat: nowSec - 30,
      exp: nowSec + 300,
      iss: String(this.appId),
    });
    const signingInput = `${header}.${payload}`;
    const sig =
      this.signingAlg === 'EdDSA'
        ? cryptoSign(null, Buffer.from(signingInput, 'utf8'), this.signingPrivateKeyPem)
        : cryptoSign('sha256', Buffer.from(signingInput, 'utf8'), this.signingPrivateKeyPem);
    return `${signingInput}.${sig.toString('base64url')}`;
  }

  private async httpJson(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    fullUrl: string,
    bearer: string,
    body?: unknown,
  ): Promise<{ status: number; data: unknown; headers: Headers }> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(Error('BROKER_GITHUB_TIMEOUT'));
      }, this.timeoutMs);
    });

    const reqPromise = (async () => {
      let response: Response;
      try {
        response = await globalThis.fetch(fullUrl, {
          method,
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            Accept: 'application/vnd.github+json',
            Authorization: `Bearer ${bearer}`,
            'User-Agent': 'bke-sandbox-trusted-broker',
            'X-GitHub-Api-Version': '2026-03-10',
            ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
          },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
      } catch {
        if (controller.signal.aborted) throw Error('BROKER_GITHUB_TIMEOUT');
        throw Error('BROKER_GITHUB_TRANSPORT_UNAVAILABLE');
      }
      if (response.status >= 300 && response.status < 400) {
        throw Error('BROKER_GITHUB_REDIRECT_BLOCKED');
      }
      if (response.status === 204) {
        return { status: 204, data: null, headers: response.headers };
      }
      const data = await response.json().catch(() => {
        throw Error('BROKER_GITHUB_MALFORMED_JSON');
      });
      return { status: response.status, data, headers: response.headers };
    })();

    try {
      return await Promise.race([reqPromise, timeoutPromise]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private parseNextUrl(headers: Headers): string | null {
    const link = headers.get('link');
    if (!link) return null;
    for (const part of link.split(',')) {
      if (/;\s*rel=["']?next["']?/i.test(part)) {
        const m = /<([^>]+)>/.exec(part);
        if (!m || !m[1]) throw Error('BROKER_GITHUB_PAGINATION_MALFORMED');
        let parsed: URL;
        try {
          parsed = new URL(m[1]);
        } catch {
          throw Error('BROKER_GITHUB_PAGINATION_MALFORMED');
        }
        if (parsed.origin !== this.baseOrigin) {
          throw Error('BROKER_GITHUB_CROSS_ORIGIN_FORBIDDEN');
        }
        return parsed.toString();
      }
    }
    return null;
  }

  async resolveInstallationAndMintToken(params: {
    repository: string;
    expectedRepositoryId: number;
    expectedInstallationId: string;
    permissions: Record<string, 'read' | 'write'>;
  }): Promise<{
    token: string;
    expiresAtMs: number;
    installationId: string;
    repositoryId: number;
    permissions: Record<string, string>;
  }> {
    if (!REPO_RE.test(params.repository) || !INSTALL_RE.test(params.expectedInstallationId)) {
      throw Error('BROKER_INSTALLATION_QUERY_INVALID');
    }
    for (const [scope, lvl] of Object.entries(params.permissions)) {
      if (scope === 'admin' || scope === 'maintain' || (lvl !== 'read' && lvl !== 'write')) {
        throw Error('BROKER_REQUESTED_PERMISSION_FORBIDDEN');
      }
    }

    const appJwt = this.createSandboxAppJwt();
    const instRes = await this.httpJson(
      'GET',
      `${this.apiBaseUrl}/repos/${params.repository}/installation`,
      appJwt,
    );
    if (instRes.status === 404) throw Error('BROKER_INSTALLATION_MISSING');
    if (instRes.status === 403 || instRes.status === 410) throw Error('BROKER_INSTALLATION_REVOKED');
    if (instRes.status < 200 || instRes.status >= 300) {
      throw Error(`BROKER_INSTALLATION_LOOKUP_FAILED_${instRes.status}`);
    }

    const instBody = instRes.data as Record<string, unknown>;
    if (instBody.suspended_at) {
      throw Error('BROKER_INSTALLATION_REVOKED');
    }
    const instId = String(instBody.id ?? '');
    if (!INSTALL_RE.test(instId) || instId !== params.expectedInstallationId) {
      throw Error('BROKER_INSTALLATION_MISMATCH');
    }
    const instPerms = instBody.permissions as Record<string, unknown> | undefined;
    if (!instPerms || typeof instPerms !== 'object' || Object.keys(instPerms).length === 0) {
      throw Error('BROKER_INSTALLATION_PERMISSIONS_MISSING');
    }
    if (instPerms.admin === true || instPerms.maintain === true || String(instPerms.administration ?? '') === 'write') {
      throw Error('BROKER_PERMISSION_ESCALATION_DETECTED');
    }
    for (const [k, reqLevel] of Object.entries(params.permissions)) {
      const granted = String(instPerms[k] ?? 'none');
      if (reqLevel === 'write' && granted !== 'write') {
        throw Error('BROKER_INSTALLATION_PERMISSION_DOWNGRADED');
      }
      if (reqLevel === 'read' && granted !== 'read' && granted !== 'write') {
        throw Error('BROKER_INSTALLATION_PERMISSION_DOWNGRADED');
      }
    }

    const mintRes = await this.httpJson(
      'POST',
      `${this.apiBaseUrl}/app/installations/${instId}/access_tokens`,
      appJwt,
      {
        repository_ids: [params.expectedRepositoryId],
        permissions: params.permissions,
      },
    );
    if (mintRes.status === 403 || mintRes.status === 422 || mintRes.status === 404) {
      throw Error('BROKER_TOKEN_MINT_DENIED_BY_GITHUB');
    }
    if (mintRes.status < 200 || mintRes.status >= 300) {
      throw Error(`BROKER_TOKEN_MINT_FAILED_${mintRes.status}`);
    }

    const minted = mintRes.data as Record<string, unknown>;
    const token = typeof minted.token === 'string' ? minted.token : '';
    const expiresAtMs = typeof minted.expires_at === 'string' ? Date.parse(minted.expires_at) : NaN;
    if (!token.startsWith('ghs_') || !Number.isFinite(expiresAtMs) || expiresAtMs <= this.nowMs() + 5_000) {
      throw Error('BROKER_GITHUB_TOKEN_INVALID');
    }
    const grantedPerms = minted.permissions as Record<string, string> | undefined;
    if (!grantedPerms || typeof grantedPerms !== 'object' || Array.isArray(grantedPerms)) {
      throw Error('BROKER_GITHUB_GRANT_MISSING');
    }
    if (grantedPerms.admin || grantedPerms.maintain || grantedPerms.administration) {
      throw Error('BROKER_PERMISSION_ESCALATION_DETECTED');
    }
    for (const [k, v] of Object.entries(grantedPerms)) {
      const requested = params.permissions[k];
      if (!requested || (requested === 'read' && v === 'write')) {
        throw Error('BROKER_PERMISSION_ESCALATION_DETECTED');
      }
    }

    // Confirm repo ID and presence in installation/repositories
    const installedRepos = await this.listAllInstallationRepositories(token);
    const matchedRepo = installedRepos.find(
      (r) => r.full_name.toLowerCase() === params.repository.toLowerCase(),
    );
    if (!matchedRepo) throw Error('BROKER_REPOSITORY_NOT_AUTHORIZED');
    if (matchedRepo.id !== params.expectedRepositoryId) {
      throw Error('BROKER_REPOSITORY_ID_MISMATCH');
    }
    if (matchedRepo.permissions.admin === true || matchedRepo.permissions.maintain === true) {
      throw Error('BROKER_PERMISSION_ESCALATION_DETECTED');
    }

    return {
      token,
      expiresAtMs,
      installationId: instId,
      repositoryId: matchedRepo.id,
      permissions: grantedPerms,
    };
  }

  /**
   * Internal-only installation-wide read-only token (without `repository_ids`)
   * used strictly by broker cross-repository exclusivity checks and never returned outside.
   */
  private async mintInstallationWideReadAuthorityToken(expectedInstallationId: string): Promise<string> {
    if (!INSTALL_RE.test(expectedInstallationId)) {
      throw Error('BROKER_INSTALLATION_QUERY_INVALID');
    }
    const appJwt = this.createSandboxAppJwt();
    const readPermissions: Record<string, 'read'> = {
      contents: 'read',
      pull_requests: 'read',
      checks: 'read',
    };
    const mintRes = await this.httpJson(
      'POST',
      `${this.apiBaseUrl}/app/installations/${expectedInstallationId}/access_tokens`,
      appJwt,
      {
        permissions: readPermissions,
      },
    );
    if (mintRes.status === 403 || mintRes.status === 422 || mintRes.status === 404) {
      throw Error('BROKER_TOKEN_MINT_DENIED_BY_GITHUB');
    }
    if (mintRes.status < 200 || mintRes.status >= 300) {
      throw Error(`BROKER_TOKEN_MINT_FAILED_${mintRes.status}`);
    }
    const minted = mintRes.data as Record<string, unknown>;
    const token = typeof minted.token === 'string' ? minted.token : '';
    const expiresAtMs = typeof minted.expires_at === 'string' ? Date.parse(minted.expires_at) : NaN;
    if (!token.startsWith('ghs_') || !Number.isFinite(expiresAtMs) || expiresAtMs <= this.nowMs() + 5_000) {
      throw Error('BROKER_GITHUB_TOKEN_INVALID');
    }
    const grantedPerms = minted.permissions as Record<string, string> | undefined;
    if (!grantedPerms || typeof grantedPerms !== 'object' || Array.isArray(grantedPerms)) {
      throw Error('BROKER_GITHUB_GRANT_MISSING');
    }
    if (grantedPerms.admin || grantedPerms.maintain || grantedPerms.administration) {
      throw Error('BROKER_PERMISSION_ESCALATION_DETECTED');
    }
    for (const [k, v] of Object.entries(grantedPerms)) {
      if (!readPermissions[k] || v !== 'read') {
        throw Error('BROKER_PERMISSION_ESCALATION_DETECTED');
      }
    }
    return token;
  }

  async revokeInstallationTokenAtProvider(
    token: string,
  ): Promise<{ revokedAtProvider: boolean; status: number }> {
    if (typeof token !== 'string' || !token.startsWith('ghs_')) {
      throw Error('BROKER_TOKEN_INVALID');
    }
    const res = await this.httpJson('DELETE', `${this.apiBaseUrl}/installation/token`, token);
    if (res.status === 204) {
      return { revokedAtProvider: true, status: 204 };
    }
    if (res.status === 401 || res.status === 404) {
      return { revokedAtProvider: false, status: res.status };
    }
    throw Error(`BROKER_TOKEN_PROVIDER_REVOKE_FAILED_${res.status}`);
  }

  async listAllInstallationRepositories(
    token: string,
  ): Promise<Array<{ id: number; full_name: string; permissions: Record<string, unknown> }>> {
    let nextUrl: string | null = `${this.apiBaseUrl}/installation/repositories?per_page=100`;
    let pages = 0;
    let totalCount: number | null = null;
    const out: Array<{ id: number; full_name: string; permissions: Record<string, unknown> }> = [];
    const seenIds = new Set<number>();

    while (nextUrl) {
      pages += 1;
      if (pages > this.maxPages) throw Error('BROKER_PAGINATION_INCOMPLETE');
      const res = await this.httpJson('GET', nextUrl, token);
      if (res.status !== 200) throw Error(`BROKER_REPO_LIST_FAILED_${res.status}`);
      const body = res.data as Record<string, unknown>;
      if (!Array.isArray(body.repositories)) throw Error('BROKER_REPO_LIST_INVALID');
      if (typeof body.total_count === 'number') {
        if (totalCount !== null && body.total_count !== totalCount) {
          throw Error('BROKER_PAGINATION_INCOMPLETE');
        }
        totalCount = body.total_count;
      }
      for (const raw of body.repositories) {
        const item = raw as Record<string, unknown>;
        if (typeof item.id !== 'number' || typeof item.full_name !== 'string' || !item.permissions) {
          throw Error('BROKER_REPO_ITEM_INVALID');
        }
        if (seenIds.has(item.id)) throw Error('BROKER_DUPLICATE_REPO');
        seenIds.add(item.id);
        out.push({
          id: item.id,
          full_name: item.full_name,
          permissions: item.permissions as Record<string, unknown>,
        });
      }
      nextUrl = this.parseNextUrl(res.headers);
    }

    if (totalCount !== null && out.length !== totalCount) {
      throw Error('BROKER_PAGINATION_INCOMPLETE');
    }
    return out;
  }

  private async listAllOpenPullsForRepo(
    token: string,
    repository: string,
  ): Promise<Array<Record<string, unknown>>> {
    let nextUrl: string | null = `${this.apiBaseUrl}/repos/${repository}/pulls?state=open&per_page=100`;
    let pages = 0;
    const out: Array<Record<string, unknown>> = [];
    const seenPrNumbers = new Set<number>();

    while (nextUrl) {
      pages += 1;
      if (pages > this.maxPages) throw Error('BROKER_PAGINATION_INCOMPLETE');
      const res = await this.httpJson('GET', nextUrl, token);
      if (res.status !== 200 || !Array.isArray(res.data)) {
        throw Error('BROKER_PULLS_READ_FAILED');
      }
      for (const raw of res.data) {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
          throw Error('BROKER_PULLS_READ_FAILED');
        }
        const pr = raw as Record<string, unknown>;
        if (typeof pr.number !== 'number' || !Number.isSafeInteger(pr.number) || pr.number < 1) {
          throw Error('BROKER_PULLS_READ_FAILED');
        }
        if (seenPrNumbers.has(pr.number)) {
          throw Error('BROKER_PAGINATION_INCOMPLETE');
        }
        seenPrNumbers.add(pr.number);
        out.push(pr);
      }
      nextUrl = this.parseNextUrl(res.headers);
    }
    return out;
  }

  private async listAllCheckRunsForCommit(
    token: string,
    repository: string,
    headSha: string,
  ): Promise<Array<Record<string, unknown>>> {
    let nextUrl: string | null = `${this.apiBaseUrl}/repos/${repository}/commits/${headSha}/check-runs?per_page=100`;
    let pages = 0;
    let totalCount: number | null = null;
    const out: Array<Record<string, unknown>> = [];
    const seenRunIds = new Set<number>();

    while (nextUrl) {
      pages += 1;
      if (pages > this.maxPages) throw Error('BROKER_PAGINATION_INCOMPLETE');
      const res = await this.httpJson('GET', nextUrl, token);
      if (res.status !== 200) throw Error('BROKER_CHECK_RUNS_READ_FAILED');
      const crBody = res.data as Record<string, unknown>;
      if (
        !crBody ||
        typeof crBody !== 'object' ||
        Array.isArray(crBody) ||
        !Array.isArray(crBody.check_runs)
      ) {
        throw Error('BROKER_CHECK_RUNS_READ_FAILED');
      }
      if (
        typeof crBody.total_count !== 'number' ||
        !Number.isSafeInteger(crBody.total_count) ||
        crBody.total_count < 0
      ) {
        throw Error('BROKER_PAGINATION_INCOMPLETE');
      }
      if (totalCount !== null && crBody.total_count !== totalCount) {
        throw Error('BROKER_PAGINATION_INCOMPLETE');
      }
      totalCount = crBody.total_count;

      for (const raw of crBody.check_runs) {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
          throw Error('BROKER_CHECK_RUNS_READ_FAILED');
        }
        const run = raw as Record<string, unknown>;
        if (typeof run.id === 'number') {
          if (!Number.isSafeInteger(run.id) || seenRunIds.has(run.id)) {
            throw Error('BROKER_PAGINATION_INCOMPLETE');
          }
          seenRunIds.add(run.id);
        }
        out.push(run);
      }
      nextUrl = this.parseNextUrl(res.headers);
    }

    if (totalCount === null || out.length !== totalCount) {
      throw Error('BROKER_PAGINATION_INCOMPLETE');
    }
    return out;
  }

  private async listMatchingBkeRefs(token: string, repository: string): Promise<string[]> {
    let nextUrl: string | null = `${this.apiBaseUrl}/repos/${repository}/git/matching-refs/bke/?per_page=100`;
    let pages = 0;
    const out: string[] = [];
    const seenRefs = new Set<string>();

    while (nextUrl) {
      pages += 1;
      if (pages > this.maxPages) throw Error('BROKER_PAGINATION_INCOMPLETE');
      const res = await this.httpJson('GET', nextUrl, token);
      if (res.status !== 200 || !Array.isArray(res.data)) {
        throw Error('BROKER_REFS_READ_FAILED');
      }
      for (const raw of res.data) {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
          throw Error('BROKER_REFS_READ_FAILED');
        }
        const refName = (raw as Record<string, unknown>).ref;
        if (typeof refName !== 'string' || !refName.startsWith('refs/bke/')) {
          throw Error('BROKER_REFS_READ_FAILED');
        }
        if (!seenRefs.has(refName)) {
          seenRefs.add(refName);
          out.push(refName);
        }
      }
      nextUrl = this.parseNextUrl(res.headers);
    }
    return out;
  }

  async verifyExecutionAuthority(params: {
    repository: string;
    expectedRepositoryId: number;
    expectedInstallationId: string;
    workerId: string;
    prNumber: number;
    headSha: string;
    attemptId: string;
    requiredAction: 'PREPARE' | 'DISPATCH_FIRST_MESSAGE' | 'DISPATCH_CONTINUATION' | 'HALT';
  }): Promise<VerifiedBrokerAuthority> {
    if (
      !REPO_RE.test(params.repository) ||
      !WORKER_RE.test(params.workerId) ||
      !SHA40_RE.test(params.headSha) ||
      !Number.isSafeInteger(params.prNumber) ||
      params.prNumber < 1
    ) {
      throw Error('BROKER_AUTHORITY_ARGS_INVALID');
    }

    const minted = await this.resolveInstallationAndMintToken({
      repository: params.repository,
      expectedRepositoryId: params.expectedRepositoryId,
      expectedInstallationId: params.expectedInstallationId,
      permissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
    });

    // Cross-repository worker assignment exclusivity across ALL installation repos
    // using an internal installation-wide read-only token (never exposed outside broker).
    const instReadToken = await this.mintInstallationWideReadAuthorityToken(minted.installationId);
    const allRepos = await this.listAllInstallationRepositories(instReadToken);
    if (
      !allRepos.some(
        (r) => r.id === params.expectedRepositoryId && r.full_name.toLowerCase() === params.repository.toLowerCase(),
      )
    ) {
      throw Error('BROKER_REPOSITORY_NOT_AUTHORIZED');
    }
    const matchingWorkerPrs: Array<{ repository: string; number: number; headSha: string }> = [];

    for (const repo of allRepos) {
      const openPrs = await this.listAllOpenPullsForRepo(instReadToken, repo.full_name);
      for (const pr of openPrs) {
        const labels = Array.isArray(pr.labels) ? pr.labels : [];
        const wLabels = labels
          .map((l) => String((l as Record<string, unknown>)?.name ?? ''))
          .filter((n) => n.startsWith('bke-worker:'))
          .map((n) => n.slice('bke-worker:'.length));
        if (wLabels.includes(params.workerId)) {
          if (wLabels.length !== 1) throw Error('BROKER_MULTI_WORKER_LABEL_CONFLICT');
          const head = (pr.head as Record<string, unknown> | undefined)?.sha;
          matchingWorkerPrs.push({
            repository: repo.full_name,
            number: Number(pr.number),
            headSha: String(head ?? ''),
          });
        }
      }
    }

    if (matchingWorkerPrs.length === 0) throw Error('BROKER_PR_NOT_ASSIGNED');
    if (matchingWorkerPrs.length > 1) {
      const multiRepos = new Set(matchingWorkerPrs.map((m) => m.repository.toLowerCase()));
      if (multiRepos.size > 1) throw Error('BROKER_CROSS_REPO_WORKER_CONFLICT');
      throw Error('BROKER_MULTI_PR_CONFLICT');
    }
    const sole = matchingWorkerPrs[0]!;
    if (sole.repository.toLowerCase() !== params.repository.toLowerCase() || sole.number !== params.prNumber) {
      throw Error('BROKER_PR_NOT_ASSIGNED');
    }

    // Re-read exact PR detail directly
    const prRes = await this.httpJson(
      'GET',
      `${this.apiBaseUrl}/repos/${params.repository}/pulls/${params.prNumber}`,
      minted.token,
    );
    if (prRes.status !== 200) throw Error('BROKER_PR_READ_FAILED');
    const prObj = prRes.data as Record<string, unknown>;
    if (prObj.state !== 'open') throw Error('BROKER_PR_NOT_OPEN');
    const prLabels = Array.isArray(prObj.labels)
      ? prObj.labels.map((l) => String((l as Record<string, unknown>)?.name ?? '')).filter((n) => n.startsWith('bke-worker:'))
      : [];
    if (prLabels.length !== 1 || prLabels[0] !== `bke-worker:${params.workerId}`) {
      throw Error('BROKER_WORKER_ASSIGNMENT_CONFLICT');
    }
    const liveHead = String((prObj.head as Record<string, unknown> | undefined)?.sha ?? '');
    if (liveHead !== params.headSha) throw Error('BROKER_HEAD_SHA_STALE');

    // Inspect all paginated refs/bke/* state
    const refNames = await this.listMatchingBkeRefs(minted.token, params.repository);
    const consumedAttempts = new Set<string>();
    const uncertainPrefix = `refs/bke/uncertain/${params.prNumber}/`;
    const claimPrefix = `refs/bke/claims/${params.prNumber}/`;
    const convRef = `refs/bke/conversations/${params.prNumber}`;
    let conversationExists = false;

    for (const refName of refNames) {
      if (refName.startsWith(uncertainPrefix)) {
        throw Error('BROKER_DELIVERY_UNCERTAIN_QUARANTINED');
      }
      if (refName.startsWith(claimPrefix)) {
        consumedAttempts.add(refName.slice(claimPrefix.length));
      }
      if (refName === convRef) {
        conversationExists = true;
      }
    }

    if (params.requiredAction !== 'HALT' && params.requiredAction !== 'PREPARE') {
      if (consumedAttempts.has(params.attemptId)) {
        throw Error('BROKER_ATTEMPT_ALREADY_CONSUMED');
      }
    }

    // Verify pinned check run ticket across all paginated check-runs if non-HALT
    let ticketCheckRunId = 0;
    if (params.requiredAction !== 'HALT') {
      const runs = await this.listAllCheckRunsForCommit(minted.token, params.repository, params.headSha);
      const validRuns = runs.filter((c) => {
        const app = c.app as Record<string, unknown> | undefined;
        const ext = typeof c.external_id === 'string' ? c.external_id : '';
        return (
          c.name === 'bke-ticket' &&
          c.head_sha === params.headSha &&
          c.status === 'completed' &&
          c.conclusion === 'success' &&
          app?.id === this.appId &&
          app?.slug === this.appSlug &&
          ext.startsWith(`bke-ticket:v1:${params.workerId}:${params.attemptId}:`)
        );
      });
      if (validRuns.length !== 1) throw Error('BROKER_TICKET_INVALID_OR_AMBIGUOUS');
      const expEpoch = Number(String(validRuns[0]!.external_id).split(':')[4]);
      if (!Number.isFinite(expEpoch) || expEpoch * 1000 <= this.nowMs()) {
        throw Error('BROKER_TICKET_EXPIRED');
      }
      ticketCheckRunId = Number(validRuns[0]!.id);
    }

    return {
      installationId: minted.installationId,
      repositoryId: minted.repositoryId,
      repositoryFullName: params.repository,
      prNumber: params.prNumber,
      headSha: params.headSha,
      attemptId: params.attemptId,
      ticketCheckRunId,
      conversationExists,
      installedRepoCount: allRepos.length,
    };
  }

  private async verifyMediatedPrAndNoUncertain(
    token: string,
    req: ServerMediatedLedgerOpRequest,
    allowUncertainRefs = false,
  ): Promise<{ ok: true } | { ok: false; code: string }> {
    const prRes = await this.httpJson(
      'GET',
      `${this.apiBaseUrl}/repos/${req.repository}/pulls/${req.pr_number}`,
      token,
    );
    if (prRes.status !== 200) {
      return { ok: false, code: 'BROKER_LEDGER_PR_NOT_FOUND' };
    }
    const prObj = prRes.data as Record<string, unknown>;
    if (prObj.state !== 'open') {
      return { ok: false, code: 'BROKER_LEDGER_PR_NOT_OPEN' };
    }
    const liveHead = String((prObj.head as Record<string, unknown> | undefined)?.sha ?? '');
    if (liveHead !== req.head_sha) {
      return { ok: false, code: 'BROKER_LEDGER_HEAD_STALE' };
    }
    if (req.worker_id) {
      const prOwners = Array.isArray(prObj.labels)
        ? prObj.labels
            .map((l) => String((l as Record<string, unknown>)?.name ?? ''))
            .filter((n) => n.startsWith('bke-worker:'))
            .map((n) => n.slice('bke-worker:'.length))
        : [];
      if (prOwners.length !== 1 || prOwners[0] !== req.worker_id) {
        return { ok: false, code: 'BROKER_LEDGER_WORKER_CONFLICT' };
      }

      // Cross-repository worker exclusivity across ALL installation repositories & all pages
      let allRepos;
      let instReadToken: string;
      try {
        instReadToken = await this.mintInstallationWideReadAuthorityToken(req.installation_id);
        allRepos = await this.listAllInstallationRepositories(instReadToken);
      } catch (err) {
        const msg = err instanceof Error ? err.message : '';
        if (
          msg === 'BROKER_PAGINATION_INCOMPLETE' ||
          msg === 'BROKER_GITHUB_PAGINATION_MALFORMED' ||
          msg === 'BROKER_GITHUB_CROSS_ORIGIN_FORBIDDEN'
        ) {
          return { ok: false, code: msg };
        }
        return { ok: false, code: 'BROKER_LEDGER_PULLS_UNAVAILABLE' };
      }
      if (
        !allRepos.some(
          (r) => r.id === req.repository_id && r.full_name.toLowerCase() === req.repository.toLowerCase(),
        )
      ) {
        return { ok: false, code: 'BROKER_REPOSITORY_NOT_AUTHORIZED' };
      }

      const matchingPrs: Array<{ repository: string; number: number }> = [];
      for (const repo of allRepos) {
        let openPrs;
        try {
          openPrs = await this.listAllOpenPullsForRepo(instReadToken, repo.full_name);
        } catch (err) {
          const msg = err instanceof Error ? err.message : '';
          if (
            msg === 'BROKER_PAGINATION_INCOMPLETE' ||
            msg === 'BROKER_GITHUB_PAGINATION_MALFORMED' ||
            msg === 'BROKER_GITHUB_CROSS_ORIGIN_FORBIDDEN'
          ) {
            return { ok: false, code: msg };
          }
          return { ok: false, code: 'BROKER_LEDGER_PULLS_UNAVAILABLE' };
        }
        for (const p of openPrs) {
          const owners = Array.isArray(p.labels)
            ? p.labels
                .map((l) => String((l as Record<string, unknown>)?.name ?? ''))
                .filter((n) => n.startsWith('bke-worker:'))
                .map((n) => n.slice('bke-worker:'.length))
            : [];
          if (owners.includes(req.worker_id)) {
            if (owners.length !== 1) {
              return { ok: false, code: 'BROKER_MULTI_WORKER_LABEL_CONFLICT' };
            }
            matchingPrs.push({ repository: repo.full_name, number: Number(p.number) });
          }
        }
      }
      if (matchingPrs.length > 1) {
        const repoSet = new Set(matchingPrs.map((m) => m.repository.toLowerCase()));
        if (repoSet.size > 1) {
          return { ok: false, code: 'BROKER_LEDGER_CROSS_REPO_WORKER_CONFLICT' };
        }
        return { ok: false, code: 'BROKER_LEDGER_MULTI_PR_CONFLICT' };
      }
      if (
        matchingPrs.length !== 1 ||
        matchingPrs[0]!.repository.toLowerCase() !== req.repository.toLowerCase() ||
        matchingPrs[0]!.number !== req.pr_number
      ) {
        return { ok: false, code: 'BROKER_LEDGER_WORKER_CONFLICT' };
      }
    }

    if (!allowUncertainRefs) {
      let refNames: string[];
      try {
        refNames = await this.listMatchingBkeRefs(token, req.repository);
      } catch (err) {
        const msg = err instanceof Error ? err.message : '';
        if (
          msg === 'BROKER_PAGINATION_INCOMPLETE' ||
          msg === 'BROKER_GITHUB_PAGINATION_MALFORMED' ||
          msg === 'BROKER_GITHUB_CROSS_ORIGIN_FORBIDDEN'
        ) {
          return { ok: false, code: msg };
        }
        return { ok: false, code: 'BROKER_LEDGER_REFS_UNAVAILABLE' };
      }
      const uncertainPrefix = `refs/bke/uncertain/${req.pr_number}/`;
      for (const refName of refNames) {
        if (refName.startsWith(uncertainPrefix)) {
          return { ok: false, code: 'BROKER_DELIVERY_UNCERTAIN_QUARANTINED' };
        }
      }
    }
    return { ok: true };
  }

  private async verifyPinnedTicketForClaim(
    token: string,
    req: ServerMediatedLedgerOpRequest,
  ): Promise<{ ok: true } | { ok: false; code: string }> {
    if (!req.worker_id) {
      return { ok: true };
    }
    let runs: Array<Record<string, unknown>>;
    try {
      runs = await this.listAllCheckRunsForCommit(token, req.repository, req.head_sha);
    } catch (err) {
      const msg = err instanceof Error ? err.message : '';
      if (
        msg === 'BROKER_PAGINATION_INCOMPLETE' ||
        msg === 'BROKER_GITHUB_PAGINATION_MALFORMED' ||
        msg === 'BROKER_GITHUB_CROSS_ORIGIN_FORBIDDEN'
      ) {
        return { ok: false, code: msg };
      }
      return { ok: false, code: 'BROKER_CHECK_RUNS_READ_FAILED' };
    }
    const validRuns = runs.filter((c) => {
      const app = c.app as Record<string, unknown> | undefined;
      const ext = typeof c.external_id === 'string' ? c.external_id : '';
      return (
        c.name === 'bke-ticket' &&
        c.head_sha === req.head_sha &&
        c.status === 'completed' &&
        c.conclusion === 'success' &&
        app?.id === this.appId &&
        app?.slug === this.appSlug &&
        ext.startsWith(`bke-ticket:v1:${req.worker_id}:${req.attempt_id}:`)
      );
    });
    if (validRuns.length !== 1) {
      return { ok: false, code: 'BROKER_TICKET_INVALID_OR_AMBIGUOUS' };
    }
    const expEpoch = Number(String(validRuns[0]!.external_id).split(':')[4]);
    if (!Number.isFinite(expEpoch) || expEpoch * 1000 <= this.nowMs()) {
      return { ok: false, code: 'BROKER_TICKET_EXPIRED' };
    }
    return { ok: true };
  }

  private validateConversationPayloadMessage(req: ServerMediatedLedgerOpRequest): boolean {
    let parsed: unknown;
    try {
      parsed = JSON.parse(req.commit_message);
    } catch {
      return false;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
    const obj = parsed as Record<string, unknown>;
    if (
      obj.bkeEvent !== 'CONVERSATION_LEDGER_V1' ||
      obj.version !== 1 ||
      obj.repository !== req.repository ||
      obj.prNumber !== req.pr_number ||
      typeof obj.conversationId !== 'string' ||
      !IDENTIFIER_RE.test(obj.conversationId) ||
      !Array.isArray(obj.turns) ||
      obj.turns.length < 1
    ) {
      return false;
    }
    if (req.worker_id && obj.workerId !== req.worker_id) {
      return false;
    }
    return true;
  }

  /**
   * Server-Mediated GitHub CAS (F4 P0-03):
   * Eliminates `contents: write` installation tokens from the desktop worker by
   * permitting ONLY four strict CAS ref operations, never arbitrary GitHub API paths.
   */
  async executeServerMediatedLedgerOp(
    req: ServerMediatedLedgerOpRequest,
  ): Promise<ServerMediatedLedgerOpResult> {
    const rawReq = req as unknown as Record<string, unknown>;
    if (rawReq.force === true || rawReq.force_update === true) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_ARBITRARY_PROXY_FORBIDDEN' };
    }
    if (
      !REPO_RE.test(req.repository) ||
      !INSTALL_RE.test(req.installation_id) ||
      !Number.isSafeInteger(req.repository_id) ||
      req.repository_id <= 0 ||
      !Number.isSafeInteger(req.pr_number) ||
      req.pr_number < 1 ||
      !ATTEMPT_RE.test(req.attempt_id)
    ) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_ARBITRARY_PROXY_FORBIDDEN' };
    }
    const exactRefByOp: Record<ServerMediatedLedgerOpRequest['operation'], string> = {
      COMMIT_PRE_SEND_FENCE: `refs/bke/fences/${req.pr_number}/${req.attempt_id}`,
      CONSUME_SEND_CLAIM: `refs/bke/claims/${req.pr_number}/${req.attempt_id}`,
      RECONCILE_CONVERSATION: `refs/bke/conversations/${req.pr_number}`,
      MARK_DELIVERY_UNCERTAIN: `refs/bke/uncertain/${req.pr_number}/${req.attempt_id}`,
    };
    const expectedExactRef = exactRefByOp[req.operation];
    if (!expectedExactRef || req.ref_name !== expectedExactRef || req.ref_name.includes('..')) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_ARBITRARY_PROXY_FORBIDDEN' };
    }
    if (req.turn_ref_name && req.turn_ref_name !== `refs/bke/turns/${req.pr_number}/${req.attempt_id}`) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_ARBITRARY_PROXY_FORBIDDEN' };
    }
    if (!SHA40_RE.test(req.head_sha) || !SHA40_RE.test(req.tree_sha)) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_SHA_INVALID' };
    }
    if (req.expected_parent_sha !== undefined && !SHA40_RE.test(req.expected_parent_sha)) {
      return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_SHA_INVALID' };
    }

    let minted;
    try {
      minted = await this.resolveInstallationAndMintToken({
        repository: req.repository,
        expectedRepositoryId: req.repository_id,
        expectedInstallationId: req.installation_id,
        permissions: { contents: 'write', pull_requests: 'read', checks: 'read' },
      });
    } catch (err) {
      const code = err instanceof Error ? err.message : 'BROKER_GITHUB_TRANSPORT_UNAVAILABLE';
      return { ok: false, status: 'UNCERTAIN', code };
    }

    try {
      if (req.operation === 'MARK_DELIVERY_UNCERTAIN') {
        if (!req.worker_id || !WORKER_RE.test(req.worker_id)) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_WORKER_CONFLICT' };
        }
        // SEC-03: Prove requesting worker owns an existing durable pre-send fence commit for this PR/attempt/head
        const fenceRefSuffix = `bke/fences/${req.pr_number}/${req.attempt_id}`;
        const fenceRes = await this.httpJson(
          'GET',
          `${this.apiBaseUrl}/repos/${req.repository}/git/ref/${fenceRefSuffix}`,
          minted.token,
        );
        if (fenceRes.status !== 200) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_FENCE_MISSING' };
        }
        const fenceObj = fenceRes.data as Record<string, unknown>;
        const fenceCommitSha = String((fenceObj.object as Record<string, unknown> | undefined)?.sha ?? '');
        if (fenceObj.ref !== `refs/${fenceRefSuffix}` || !SHA40_RE.test(fenceCommitSha)) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_FENCE_INVALID' };
        }
        const fenceCommitRes = await this.httpJson(
          'GET',
          `${this.apiBaseUrl}/repos/${req.repository}/git/commits/${fenceCommitSha}`,
          minted.token,
        );
        if (fenceCommitRes.status !== 200) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_FENCE_INVALID' };
        }
        let fenceMeta: unknown;
        try {
          fenceMeta = JSON.parse(
            String((fenceCommitRes.data as Record<string, unknown> | undefined)?.message ?? ''),
          );
        } catch {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_FENCE_INVALID' };
        }
        if (!fenceMeta || typeof fenceMeta !== 'object' || Array.isArray(fenceMeta)) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_FENCE_INVALID' };
        }
        const fm = fenceMeta as Record<string, unknown>;
        if (
          fm.bkeEvent !== 'PRE_SEND_FENCE' ||
          fm.workerId !== req.worker_id ||
          fm.attemptId !== req.attempt_id ||
          fm.headSha !== req.head_sha
        ) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_UNCERTAIN_OWNERSHIP_CONFLICT' };
        }

        const postRef = await this.httpJson(
          'POST',
          `${this.apiBaseUrl}/repos/${req.repository}/git/refs`,
          minted.token,
          { ref: req.ref_name, sha: req.head_sha },
        );
        if (postRef.status === 201) {
          const obj = postRef.data as Record<string, unknown>;
          const refObj = obj.object as Record<string, unknown> | undefined;
          if (obj.ref === req.ref_name && refObj?.sha === req.head_sha) {
            return { ok: true, status: 'COMMITTED', sha: req.head_sha };
          }
          return { ok: false, status: 'UNCERTAIN', code: 'BROKER_LEDGER_READBACK_MISMATCH' };
        }
        if (postRef.status === 422) {
          const getRef = await this.httpJson(
            'GET',
            `${this.apiBaseUrl}/repos/${req.repository}/git/ref/${req.ref_name.slice('refs/'.length)}`,
            minted.token,
          );
          const getObj = getRef.data as Record<string, unknown>;
          const refSha = (getObj.object as Record<string, unknown> | undefined)?.sha;
          if (getRef.status === 200 && refSha === req.head_sha) {
            return { ok: true, status: 'ALREADY_EXISTS', sha: req.head_sha };
          }
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_UNCERTAIN_CONFLICT' };
        }
        return { ok: false, status: 'UNCERTAIN', code: `BROKER_LEDGER_REF_FAILED_${postRef.status}` };
      }

      if (req.operation === 'COMMIT_PRE_SEND_FENCE') {
        try {
          const parsedFence = JSON.parse(req.commit_message) as unknown;
          if (
            parsedFence &&
            typeof parsedFence === 'object' &&
            !Array.isArray(parsedFence) &&
            (parsedFence as Record<string, unknown>).bkeEvent === 'PRE_SEND_FENCE'
          ) {
            const pf = parsedFence as Record<string, unknown>;
            if (
              (req.worker_id && pf.workerId !== req.worker_id) ||
              pf.attemptId !== req.attempt_id ||
              pf.headSha !== req.head_sha
            ) {
              return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_FENCE_PAYLOAD_INVALID' };
            }
          }
        } catch {
          // Non-JSON legacy test commit messages allowed here; MARK_DELIVERY_UNCERTAIN requires structured PRE_SEND_FENCE JSON.
        }
        const prCheck = await this.verifyMediatedPrAndNoUncertain(minted.token, req);
        if (!prCheck.ok) {
          return { ok: false, status: 'CONFLICT', code: prCheck.code };
        }
        const commitRes = await this.httpJson(
          'POST',
          `${this.apiBaseUrl}/repos/${req.repository}/git/commits`,
          minted.token,
          {
            message: req.commit_message,
            tree: req.tree_sha,
            parents: [req.head_sha],
          },
        );
        if (commitRes.status !== 201) {
          return { ok: false, status: 'UNCERTAIN', code: `BROKER_LEDGER_COMMIT_FAILED_${commitRes.status}` };
        }
        const commitSha = String((commitRes.data as Record<string, unknown>)?.sha ?? '');
        if (!SHA40_RE.test(commitSha)) {
          return { ok: false, status: 'UNCERTAIN', code: 'BROKER_LEDGER_COMMIT_SHA_INVALID' };
        }
        const postRef = await this.httpJson(
          'POST',
          `${this.apiBaseUrl}/repos/${req.repository}/git/refs`,
          minted.token,
          { ref: req.ref_name, sha: commitSha },
        );
        if (postRef.status === 422) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_FENCE_CONFLICT' };
        }
        if (postRef.status !== 201) {
          return { ok: false, status: 'UNCERTAIN', code: `BROKER_LEDGER_REF_FAILED_${postRef.status}` };
        }
        const readBackRef = await this.httpJson(
          'GET',
          `${this.apiBaseUrl}/repos/${req.repository}/git/ref/${req.ref_name.slice('refs/'.length)}`,
          minted.token,
        );
        const readSha = (readBackRef.data as Record<string, unknown> | undefined)?.object as Record<string, unknown> | undefined;
        if (readBackRef.status !== 200 || readSha?.sha !== commitSha) {
          return { ok: false, status: 'UNCERTAIN', code: 'BROKER_LEDGER_READBACK_MISMATCH' };
        }
        return { ok: true, status: 'COMMITTED', sha: commitSha };
      }

      if (req.operation === 'CONSUME_SEND_CLAIM') {
        const prCheck = await this.verifyMediatedPrAndNoUncertain(minted.token, req);
        if (!prCheck.ok) {
          return { ok: false, status: 'CONFLICT', code: prCheck.code };
        }
        const fenceRef = `bke/fences/${req.pr_number}/${req.attempt_id}`;
        const fenceRes = await this.httpJson(
          'GET',
          `${this.apiBaseUrl}/repos/${req.repository}/git/ref/${fenceRef}`,
          minted.token,
        );
        if (fenceRes.status !== 200) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_FENCE_MISSING' };
        }
        const ticketCheck = await this.verifyPinnedTicketForClaim(minted.token, req);
        if (!ticketCheck.ok) {
          return { ok: false, status: 'CONFLICT', code: ticketCheck.code };
        }
        // Claim ref MUST point directly to req.head_sha (no intermediate commit creation)
        const postRef = await this.httpJson(
          'POST',
          `${this.apiBaseUrl}/repos/${req.repository}/git/refs`,
          minted.token,
          { ref: req.ref_name, sha: req.head_sha },
        );
        if (postRef.status === 422) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_CLAIM_CONFLICT' };
        }
        if (postRef.status !== 201) {
          return { ok: false, status: 'UNCERTAIN', code: `BROKER_LEDGER_REF_FAILED_${postRef.status}` };
        }
        const postObj = postRef.data as Record<string, unknown>;
        const postSha = (postObj.object as Record<string, unknown> | undefined)?.sha;
        if (postObj.ref !== req.ref_name || postSha !== req.head_sha) {
          return { ok: false, status: 'UNCERTAIN', code: 'BROKER_LEDGER_READBACK_MISMATCH' };
        }
        const readBackRef = await this.httpJson(
          'GET',
          `${this.apiBaseUrl}/repos/${req.repository}/git/ref/${req.ref_name.slice('refs/'.length)}`,
          minted.token,
        );
        const readSha = ((readBackRef.data as Record<string, unknown> | undefined)?.object as Record<string, unknown> | undefined)?.sha;
        if (readBackRef.status !== 200 || readSha !== req.head_sha) {
          return { ok: false, status: 'UNCERTAIN', code: 'BROKER_LEDGER_READBACK_MISMATCH' };
        }
        const postPr = await this.verifyMediatedPrAndNoUncertain(minted.token, req);
        if (!postPr.ok) {
          return { ok: false, status: 'UNCERTAIN', code: postPr.code };
        }
        return { ok: true, status: 'COMMITTED', sha: req.head_sha };
      }

      // RECONCILE_CONVERSATION
      if (!this.validateConversationPayloadMessage(req)) {
        return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_CONVERSATION_PAYLOAD_INVALID' };
      }
      const prCheck = await this.verifyMediatedPrAndNoUncertain(minted.token, req);
      if (!prCheck.ok) {
        return { ok: false, status: 'CONFLICT', code: prCheck.code };
      }

      const convRefSuffix = req.ref_name.slice('refs/'.length);
      const liveConvRes = await this.httpJson(
        'GET',
        `${this.apiBaseUrl}/repos/${req.repository}/git/ref/${convRefSuffix}`,
        minted.token,
      );
      const isContinuation = req.is_continuation === true || Boolean(req.expected_parent_sha);
      if (isContinuation) {
        const liveTip = ((liveConvRes.data as Record<string, unknown> | undefined)?.object as Record<string, unknown> | undefined)?.sha;
        if (liveConvRes.status !== 200 || !req.expected_parent_sha || liveTip !== req.expected_parent_sha) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_CONVERSATION_CAS_CONFLICT' };
        }
      } else if (liveConvRes.status !== 404) {
        return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_CONVERSATION_ALREADY_EXISTS' };
      }

      const commitRes = await this.httpJson(
        'POST',
        `${this.apiBaseUrl}/repos/${req.repository}/git/commits`,
        minted.token,
        {
          message: req.commit_message,
          tree: req.tree_sha,
          parents: req.expected_parent_sha ? [req.expected_parent_sha] : [req.head_sha],
        },
      );
      if (commitRes.status !== 201) {
        return { ok: false, status: 'UNCERTAIN', code: `BROKER_LEDGER_COMMIT_FAILED_${commitRes.status}` };
      }
      const createdCommitSha = String((commitRes.data as Record<string, unknown>)?.sha ?? '');
      if (!SHA40_RE.test(createdCommitSha)) {
        return { ok: false, status: 'UNCERTAIN', code: 'BROKER_LEDGER_COMMIT_SHA_INVALID' };
      }

      if (isContinuation) {
        const patchRes = await this.httpJson(
          'PATCH',
          `${this.apiBaseUrl}/repos/${req.repository}/git/refs/${convRefSuffix}`,
          minted.token,
          { sha: createdCommitSha, force: false },
        );
        if (patchRes.status !== 200) {
          return { ok: false, status: 'CONFLICT', code: `BROKER_LEDGER_PATCH_CONFLICT_${patchRes.status}` };
        }
      } else {
        const postRef = await this.httpJson(
          'POST',
          `${this.apiBaseUrl}/repos/${req.repository}/git/refs`,
          minted.token,
          { ref: req.ref_name, sha: createdCommitSha },
        );
        if (postRef.status === 422) {
          return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_CONVERSATION_CAS_CONFLICT' };
        }
        if (postRef.status !== 201) {
          return { ok: false, status: 'UNCERTAIN', code: `BROKER_LEDGER_REF_FAILED_${postRef.status}` };
        }
      }

      const turnRefName = req.turn_ref_name ?? `refs/bke/turns/${req.pr_number}/${req.attempt_id}`;
      const turnPost = await this.httpJson(
        'POST',
        `${this.apiBaseUrl}/repos/${req.repository}/git/refs`,
        minted.token,
        { ref: turnRefName, sha: createdCommitSha },
      );
      if (turnPost.status === 422) {
        return { ok: false, status: 'CONFLICT', code: 'BROKER_LEDGER_TURN_CONFLICT' };
      }
      if (turnPost.status !== 201) {
        return { ok: false, status: 'UNCERTAIN', code: `BROKER_LEDGER_TURN_REF_FAILED_${turnPost.status}` };
      }

      const rbConv = await this.httpJson(
        'GET',
        `${this.apiBaseUrl}/repos/${req.repository}/git/ref/${convRefSuffix}`,
        minted.token,
      );
      const rbTurn = await this.httpJson(
        'GET',
        `${this.apiBaseUrl}/repos/${req.repository}/git/ref/${turnRefName.slice('refs/'.length)}`,
        minted.token,
      );
      const rbConvSha = ((rbConv.data as Record<string, unknown> | undefined)?.object as Record<string, unknown> | undefined)?.sha;
      const rbTurnSha = ((rbTurn.data as Record<string, unknown> | undefined)?.object as Record<string, unknown> | undefined)?.sha;
      if (rbConv.status !== 200 || rbTurn.status !== 200 || rbConvSha !== createdCommitSha || rbTurnSha !== createdCommitSha) {
        return { ok: false, status: 'UNCERTAIN', code: 'BROKER_LEDGER_READBACK_MISMATCH' };
      }
      return { ok: true, status: 'COMMITTED', sha: createdCommitSha };
    } catch (err) {
      const code = err instanceof Error ? err.message : 'BROKER_GITHUB_TRANSPORT_UNAVAILABLE';
      return { ok: false, status: 'UNCERTAIN', code };
    }
  }
}
