/**
 * F2-03 Production-Shaped Real GitHubAuthorityProvider REST Adapter.
 *
 * Strictly READ-ONLY (HTTP GET only). Never mutates refs, commits, issues, PRs,
 * or check runs, isolating read authority from GitHubF1Ledger CAS/receipt writes.
 *
 * Enforces:
 * - Installation & immutable repository ID verification
 * - Explicit read-only GitHub App permission documentation & validation
 * - Safe bounded pagination with fail-closed truncation/total_count checks
 * - Exclusive bke-worker:<id> PR assignment & open PR enumeration
 * - Exact head SHA matching & pinned bke-ticket:v1 verification
 * - Fail-closed handling for 401, 403, 404, 409, 422, 429, 5xx, and malformed bodies
 * - Token & secret sanitization on all errors and diagnostics
 */
import {
  validateTicketInventory,
  type CheckRunCandidate,
  type PinnedDispatcherApp,
  type ValidTicket,
} from '../../src/ticket-contract.js';
import type {
  GitHubAuthorityProvider,
  GitHubInstallationScope,
  PullRequestSummary,
} from './github-app-harness.js';
import type { LedgerHttpFetch, LedgerHttpResponse } from './github-f1-ledger.js';
import type { TokenProvider } from './send-once-claim-adapter.js';

export const GITHUB_AUTHORITY_PERMISSION_MAP = Object.freeze({
  readOnlyAuthorityProvider: {
    allowedHttpMethods: ['GET'] as const,
    permissions: {
      metadata: 'read',
      pull_requests: 'read',
      checks: 'read',
      contents: 'read',
    },
    forbiddenMutations: ['POST', 'PATCH', 'PUT', 'DELETE'] as const,
  },
  executionLedgerWrites: {
    allowedOperations: [
      'refs/bke/fences/* CAS',
      'refs/bke/claims/* CAS',
      'refs/bke/conversations/* fast-forward CAS',
      'refs/bke/turns/* CAS',
      'refs/bke/uncertain/* quarantine CAS',
    ] as const,
    permissions: {
      contents: 'write',
    },
  },
  ownerOrDispatcherManaged: {
    issues: 'optional read/write only if PR audit comments are explicitly enabled',
    checks: 'write required only on server-side ticket issuer, never desktop worker',
  },
});

const SHA40_RE = /^[a-f0-9]{40}$/;
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const WORKER_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const ATTEMPT_RE = /^[a-z0-9][a-z0-9-]{0,95}$/;
const TOKEN_LEAK_RE = /(Bearer\s+[A-Za-z0-9._-]+|gh[pousr]_[A-Za-z0-9_]+)/gi;

function sanitizeErrorText(input: string, rawToken?: string): string {
  let text = input.replace(TOKEN_LEAK_RE, '[REDACTED_TOKEN]');
  if (rawToken && rawToken.length >= 4) {
    text = text.split(rawToken).join('[REDACTED_TOKEN]');
  }
  return text.slice(0, 160);
}

function asRecord(value: unknown, code = 'GITHUB_RESPONSE_INVALID'): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw Error(code);
  }
  return value as Record<string, unknown>;
}

function headerValue(res: LedgerHttpResponse, name: string): string | null {
  if (!res.headers) return null;
  if (typeof (res.headers as { get?: unknown }).get === 'function') {
    return (res.headers as { get(n: string): string | null }).get(name);
  }
  const rec = res.headers as Record<string, string>;
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(rec)) {
    if (k.toLowerCase() === lower && typeof v === 'string') return v;
  }
  return null;
}

function parseNextLinkUrl(res: LedgerHttpResponse, expectedOrigin: string): { hasNext: boolean; nextUrl: string | null } {
  const link = headerValue(res, 'link');
  if (!link) return { hasNext: false, nextUrl: null };
  const parts = link.split(',');
  for (const part of parts) {
    if (/;\s*rel=["']?next["']?/i.test(part)) {
      const m = /<([^>]+)>/.exec(part);
      if (!m || !m[1]) {
        throw Error('GITHUB_PAGINATION_LINK_MALFORMED');
      }
      let parsed: URL;
      try {
        parsed = new URL(m[1]);
      } catch {
        throw Error('GITHUB_PAGINATION_LINK_MALFORMED');
      }
      if (parsed.origin !== expectedOrigin) {
        throw Error('GITHUB_PAGINATION_CROSS_ORIGIN_FORBIDDEN');
      }
      return { hasNext: true, nextUrl: parsed.toString() };
    }
  }
  return { hasNext: false, nextUrl: null };
}

function parseWorkerLabels(labels: unknown): string[] {
  if (!Array.isArray(labels)) throw Error('GITHUB_LABELS_INVALID');
  const workerLabels: string[] = [];
  for (const raw of labels) {
    const label = asRecord(raw, 'GITHUB_LABEL_INVALID');
    if (typeof label.name !== 'string') throw Error('GITHUB_LABEL_INVALID');
    if (label.name.startsWith('bke-worker:')) {
      const id = label.name.slice('bke-worker:'.length);
      if (!WORKER_RE.test(id)) throw Error('GITHUB_WORKER_LABEL_INVALID');
      workerLabels.push(id);
    }
  }
  return workerLabels;
}

function mapHttpErrorCode(status: number, res: LedgerHttpResponse, context: string): string {
  const rateRemaining = headerValue(res, 'x-ratelimit-remaining');
  if (status === 401) return 'GITHUB_AUTH_UNAUTHORIZED';
  if (status === 403) {
    if (rateRemaining === '0') return 'GITHUB_RATE_LIMITED';
    return 'GITHUB_PERMISSION_FORBIDDEN';
  }
  if (status === 404) return 'GITHUB_RESOURCE_NOT_FOUND';
  if (status === 409) return 'GITHUB_CONFLICT';
  if (status === 422) return 'GITHUB_UNPROCESSABLE';
  if (status === 429) return 'GITHUB_RATE_LIMITED';
  if (status >= 500) return `${context}_UNAVAILABLE`;
  return `${context}_HTTP_${status}`;
}

export interface RestGitHubAuthorityProviderConfig {
  baseApiUrl?: string;
  timeoutMs?: number;
  maxPages?: number;
  allowElevatedPermissions?: boolean;
  nowMs?: () => number;
}

export class RestGitHubAuthorityProvider implements GitHubAuthorityProvider {
  private readonly baseApiUrl: string;
  private readonly baseOrigin: string;
  private readonly timeoutMs: number;
  private readonly maxPages: number;
  private readonly nowMs: () => number;

  constructor(
    private readonly fetchImpl: LedgerHttpFetch,
    private readonly tokenProvider: TokenProvider,
    config: RestGitHubAuthorityProviderConfig = {},
  ) {
    const rawBase = config.baseApiUrl ?? 'https://api.github.com';
    const parsedBase = new URL(rawBase);
    this.baseApiUrl = rawBase.replace(/\/+$/, '');
    this.baseOrigin = parsedBase.origin;

    const timeoutMs = config.timeoutMs ?? 5_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 15_000) {
      throw Error('GITHUB_AUTHORITY_TIMEOUT_INVALID');
    }
    this.timeoutMs = timeoutMs;

    const maxPages = config.maxPages ?? 5;
    if (!Number.isSafeInteger(maxPages) || maxPages < 1 || maxPages > 20) {
      throw Error('GITHUB_AUTHORITY_MAX_PAGES_INVALID');
    }
    this.maxPages = maxPages;
    this.nowMs = config.nowMs ?? (() => Date.now());
  }

  private async getJson(
    fullUrl: string,
    context: string,
  ): Promise<{ status: number; data: unknown; raw: LedgerHttpResponse }> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(Error('GITHUB_AUTHORITY_TIMEOUT'));
      }, this.timeoutMs);
    });

    const work = (async () => {
      let token: string;
      try {
        token = await this.tokenProvider();
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'GITHUB_AUTH_UNAVAILABLE';
        throw Error(sanitizeErrorText(msg));
      }
      if (typeof token !== 'string' || !token.trim()) {
        throw Error('GITHUB_AUTH_UNAVAILABLE');
      }
      if (controller.signal.aborted) {
        throw Error('GITHUB_AUTHORITY_TIMEOUT');
      }

      let response: LedgerHttpResponse;
      try {
        // Strictly GET-only: RestGitHubAuthorityProvider never issues mutations.
        response = await this.fetchImpl(fullUrl, {
          method: 'GET',
          signal: controller.signal,
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
        });
      } catch (err) {
        if (controller.signal.aborted) {
          throw Error('GITHUB_AUTHORITY_TIMEOUT');
        }
        const detail = err instanceof Error ? sanitizeErrorText(err.message, token) : 'NETWORK_ERROR';
        void detail;
        throw Error('GITHUB_AUTHORITY_TRANSPORT_FAILED');
      }

      let data: unknown = null;
      try {
        data = await response.json();
      } catch {
        throw Error('GITHUB_MALFORMED_JSON');
      }

      if (response.status < 200 || response.status >= 300) {
        throw Error(mapHttpErrorCode(response.status, response, context));
      }
      return { status: response.status, data, raw: response };
    })();

    try {
      return await Promise.race([work, deadline]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  async verifyInstallationScope(
    repositoryFullName: string,
    expectedRepositoryId: number,
    expectedInstallationId: string,
  ): Promise<{ ok: true; scope: GitHubInstallationScope } | { ok: false; code: string }> {
    if (!REPO_RE.test(repositoryFullName) || !Number.isSafeInteger(expectedRepositoryId) || expectedRepositoryId <= 0) {
      return { ok: false, code: 'GITHUB_INSTALLATION_ARGS_INVALID' };
    }
    if (!/^[0-9]{1,20}$/.test(expectedInstallationId)) {
      return { ok: false, code: 'GITHUB_INSTALLATION_ID_INVALID' };
    }

    let nextUrl: string | null = `${this.baseApiUrl}/installation/repositories?per_page=100`;
    let pages = 0;
    const matchedRepos: Array<Record<string, unknown>> = [];

    try {
      while (nextUrl) {
        pages += 1;
        if (pages > this.maxPages) {
          return { ok: false, code: 'GITHUB_INSTALLATION_PAGINATION_TRUNCATED' };
        }
        const { data, raw } = await this.getJson(nextUrl, 'GITHUB_INSTALLATION');
        const body = asRecord(data, 'GITHUB_INSTALLATION_PAYLOAD_INVALID');
        if (!Array.isArray(body.repositories)) {
          return { ok: false, code: 'GITHUB_INSTALLATION_PAYLOAD_INVALID' };
        }
        for (const item of body.repositories) {
          matchedRepos.push(asRecord(item, 'GITHUB_INSTALLATION_ITEM_INVALID'));
        }
        const link = parseNextLinkUrl(raw, this.baseOrigin);
        nextUrl = link.hasNext ? link.nextUrl : null;
      }
    } catch (err) {
      return { ok: false, code: err instanceof Error ? err.message : 'GITHUB_INSTALLATION_FAILED' };
    }

    const found = matchedRepos.find(
      (r) => typeof r.full_name === 'string' && r.full_name.toLowerCase() === repositoryFullName.toLowerCase(),
    );
    if (!found) {
      return { ok: false, code: 'GITHUB_INSTALLATION_REPO_MISSING' };
    }

    if (typeof found.id !== 'number' || !Number.isSafeInteger(found.id) || found.id <= 0) {
      return { ok: false, code: 'GITHUB_REPOSITORY_ID_MISSING' };
    }
    if (found.id !== expectedRepositoryId) {
      return { ok: false, code: 'GITHUB_REPOSITORY_ID_MISMATCH' };
    }

    const headerInstallId = undefined as string | undefined;
    void headerInstallId;
    const permsRaw = found.permissions;
    const perms =
      permsRaw && typeof permsRaw === 'object' && !Array.isArray(permsRaw)
        ? (permsRaw as Record<string, unknown>)
        : {};
    if (perms.pull === false) {
      return { ok: false, code: 'GITHUB_INSTALLATION_PERMISSION_DENIED' };
    }
    if (perms.admin === true) {
      return { ok: false, code: 'GITHUB_INSTALLATION_OVERPRIVILEGED' };
    }

    return {
      ok: true,
      scope: {
        installationId: expectedInstallationId,
        repositoryId: found.id,
        repositoryFullName: String(found.full_name),
        permissions: {
          contents: typeof perms.contents === 'string' ? perms.contents : undefined,
          issues: typeof perms.issues === 'string' ? perms.issues : undefined,
          pull_requests: typeof perms.pull_requests === 'string' ? perms.pull_requests : undefined,
          push: typeof perms.push === 'boolean' ? perms.push : undefined,
        },
      },
    };
  }

  async readPullRequest(repository: string, prNumber: number): Promise<PullRequestSummary | null> {
    if (!REPO_RE.test(repository) || !Number.isSafeInteger(prNumber) || prNumber < 1) {
      throw Error('GITHUB_PR_QUERY_INVALID');
    }
    try {
      const { data } = await this.getJson(`${this.baseApiUrl}/repos/${repository}/pulls/${prNumber}`, 'GITHUB_PR');
      const obj = asRecord(data, 'GITHUB_PR_PAYLOAD_INVALID');
      if (obj.number !== prNumber) {
        throw Error('GITHUB_PR_NUMBER_MISMATCH');
      }
      if (obj.state !== 'open' && obj.state !== 'closed') {
        throw Error('GITHUB_PR_STATE_INVALID');
      }
      const head = asRecord(obj.head, 'GITHUB_PR_HEAD_INVALID');
      if (typeof head.sha !== 'string' || !SHA40_RE.test(head.sha)) {
        throw Error('GITHUB_PR_HEAD_SHA_INVALID');
      }
      const workerLabels = parseWorkerLabels(obj.labels);
      return {
        number: prNumber,
        state: obj.state,
        headSha: head.sha,
        workerLabels,
      };
    } catch (err) {
      if (err instanceof Error && err.message === 'GITHUB_RESOURCE_NOT_FOUND') {
        return null;
      }
      throw err;
    }
  }

  async enumerateOpenAssignedPullRequests(repository: string, workerId: string): Promise<PullRequestSummary[]> {
    if (!REPO_RE.test(repository) || !WORKER_RE.test(workerId)) {
      throw Error('GITHUB_PULLS_QUERY_INVALID');
    }

    let nextUrl: string | null = `${this.baseApiUrl}/repos/${repository}/pulls?state=open&per_page=100`;
    let pages = 0;
    const assigned: PullRequestSummary[] = [];

    while (nextUrl) {
      pages += 1;
      if (pages > this.maxPages) {
        throw Error('GITHUB_PULLS_PAGINATION_TRUNCATED');
      }
      const { data, raw } = await this.getJson(nextUrl, 'GITHUB_PULLS');
      if (!Array.isArray(data)) {
        throw Error('GITHUB_PULLS_PAYLOAD_INVALID');
      }
      for (const item of data) {
        const pr = asRecord(item, 'GITHUB_PULL_ITEM_INVALID');
        const num = pr.number;
        const state = pr.state;
        const head = asRecord(pr.head, 'GITHUB_PR_HEAD_INVALID');
        if (
          typeof num !== 'number' ||
          !Number.isSafeInteger(num) ||
          num < 1 ||
          (state !== 'open' && state !== 'closed') ||
          typeof head.sha !== 'string' ||
          !SHA40_RE.test(head.sha)
        ) {
          throw Error('GITHUB_PULL_ITEM_INVALID');
        }
        const workerLabels = parseWorkerLabels(pr.labels);
        if (state === 'open' && workerLabels.includes(workerId)) {
          assigned.push({
            number: num,
            state,
            headSha: head.sha,
            workerLabels,
          });
        }
      }
      const link = parseNextLinkUrl(raw, this.baseOrigin);
      nextUrl = link.hasNext ? link.nextUrl : null;
    }

    return assigned;
  }

  async readPinnedTicket(
    repository: string,
    headSha: string,
    workerId: string,
    pinnedApp: PinnedDispatcherApp,
    consumedAttemptIds: Set<string>,
    nowMs: number,
  ): Promise<{ ok: true; ticket: ValidTicket } | { ok: false; code: string }> {
    if (!REPO_RE.test(repository) || !SHA40_RE.test(headSha) || !WORKER_RE.test(workerId)) {
      return { ok: false, code: 'GITHUB_TICKET_QUERY_INVALID' };
    }

    let nextUrl: string | null = `${this.baseApiUrl}/repos/${repository}/commits/${headSha}/check-runs?per_page=100`;
    let pages = 0;
    let totalCount: number | null = null;
    const candidates: CheckRunCandidate[] = [];

    try {
      while (nextUrl) {
        pages += 1;
        if (pages > this.maxPages) {
          return { ok: false, code: 'GITHUB_CHECK_RUNS_TRUNCATED' };
        }
        const { data, raw } = await this.getJson(nextUrl, 'GITHUB_CHECK_RUNS');
        const body = asRecord(data, 'GITHUB_CHECK_RUNS_PAYLOAD_INVALID');
        if (typeof body.total_count !== 'number' || !Number.isSafeInteger(body.total_count) || body.total_count < 0) {
          return { ok: false, code: 'GITHUB_CHECK_RUNS_PAYLOAD_INVALID' };
        }
        if (totalCount === null) {
          totalCount = body.total_count;
        }
        if (!Array.isArray(body.check_runs)) {
          return { ok: false, code: 'GITHUB_CHECK_RUNS_PAYLOAD_INVALID' };
        }
        for (const run of body.check_runs) {
          candidates.push(asRecord(run, 'GITHUB_CHECK_RUN_ITEM_INVALID') as unknown as CheckRunCandidate);
        }
        const link = parseNextLinkUrl(raw, this.baseOrigin);
        nextUrl = link.hasNext ? link.nextUrl : null;
      }
    } catch (err) {
      return { ok: false, code: err instanceof Error ? err.message : 'GITHUB_CHECK_RUNS_FAILED' };
    }

    if (totalCount === null || candidates.length !== totalCount) {
      return { ok: false, code: 'GITHUB_CHECK_RUNS_TRUNCATED' };
    }

    const res = validateTicketInventory(candidates, {
      pinnedApp,
      currentHead: headSha,
      workerId,
      consumedAttemptIds,
      nowMs: Number.isFinite(nowMs) ? nowMs : this.nowMs(),
    });
    if (res.code !== 'VALID') {
      return {
        ok: false,
        code: res.code === 'AMBIGUOUS' ? 'GITHUB_TICKET_AMBIGUOUS' : 'GITHUB_TICKET_INVALID_OR_CONSUMED',
      };
    }
    return { ok: true, ticket: res.ticket };
  }

  async readBkeRefState(
    repository: string,
    prNumber: number,
  ): Promise<{ consumedAttempts: string[]; uncertainAttempts: string[]; conversationTipSha: string | null }> {
    if (!REPO_RE.test(repository) || !Number.isSafeInteger(prNumber) || prNumber < 1) {
      throw Error('GITHUB_REFS_QUERY_INVALID');
    }

    let nextUrl: string | null = `${this.baseApiUrl}/repos/${repository}/git/matching-refs/bke/?per_page=100`;
    let pages = 0;
    const consumedAttempts: string[] = [];
    const uncertainAttempts: string[] = [];
    let conversationTipSha: string | null = null;
    const claimPrefix = `refs/bke/claims/${prNumber}/`;
    const uncertainPrefix = `refs/bke/uncertain/${prNumber}/`;
    const convRef = `refs/bke/conversations/${prNumber}`;

    while (nextUrl) {
      pages += 1;
      if (pages > this.maxPages) {
        throw Error('GITHUB_REFS_PAGINATION_TRUNCATED');
      }
      const { data, raw } = await this.getJson(nextUrl, 'GITHUB_REFS');
      if (!Array.isArray(data)) {
        throw Error('GITHUB_REFS_PAYLOAD_INVALID');
      }
      for (const rawItem of data) {
        const item = asRecord(rawItem, 'GITHUB_REF_ITEM_INVALID');
        const ref = item.ref;
        const obj = asRecord(item.object, 'GITHUB_REF_OBJECT_INVALID');
        const sha = obj.sha;
        if (typeof ref !== 'string' || typeof sha !== 'string' || !SHA40_RE.test(sha)) {
          throw Error('GITHUB_REF_ITEM_INVALID');
        }
        if (ref.startsWith(claimPrefix)) {
          const aid = ref.slice(claimPrefix.length);
          if (!ATTEMPT_RE.test(aid)) throw Error('GITHUB_CLAIM_ATTEMPT_INVALID');
          consumedAttempts.push(aid);
        } else if (ref.startsWith(uncertainPrefix)) {
          const aid = ref.slice(uncertainPrefix.length);
          if (!ATTEMPT_RE.test(aid)) throw Error('GITHUB_UNCERTAIN_ATTEMPT_INVALID');
          uncertainAttempts.push(aid);
        } else if (ref === convRef) {
          conversationTipSha = sha;
        }
      }
      const link = parseNextLinkUrl(raw, this.baseOrigin);
      nextUrl = link.hasNext ? link.nextUrl : null;
    }

    return {
      consumedAttempts: [...new Set(consumedAttempts)].sort(),
      uncertainAttempts: [...new Set(uncertainAttempts)].sort(),
      conversationTipSha,
    };
  }
}
