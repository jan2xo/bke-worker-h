/**
 * F3-05 Reusable Local GitHub App & REST Provider Simulation HTTP Server.
 *
 * Simulates GitHub App installation resolution, scoped token minting,
 * paginated `/installation/repositories`, multi-repo `/pulls`, check-runs (`bke-ticket:v1`),
 * and `/repos/:owner/:repo/git/*` commits & CAS refs, with programmable fault injection
 * covering all Repository authority (7), Pull Request authority (8), Claim (8), and Receipt (6) cases.
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';

export async function startMockGitHubServer(initialConfig = {}) {
  const HEAD_A = 'a'.repeat(40);
  const TREE_A = 'e'.repeat(40);

  const state = {
    installationId: initialConfig.installationId ?? '987654321',
    installationMissing: false,
    installationRevoked: false,
    installationPerms: { contents: 'write', pull_requests: 'read', checks: 'read' },
    redirectOnNextCall: false,
    forceStatus: null, // e.g. { pathIncludes: '/pulls', status: 503 }
    dropAfterMutateCount: 0, // Accept POST /git/refs or /git/commits then destroy socket!
    incompleteRepoPagination: false,
    incompleteCheckPagination: false,
    lyingReadBackSha: null,
    repos: initialConfig.repos ?? [
      {
        id: 1354026486,
        full_name: 'jan2xo/bke-worker',
        permissions: { contents: 'write', pull_requests: 'read', checks: 'read', pull: true, push: true },
        prs: [
          {
            number: 149,
            state: 'open',
            headSha: HEAD_A,
            labels: ['bke-worker:worker-f1'],
          },
        ],
      },
    ],
    commits: new Map([
      ['jan2xo/bke-worker:' + HEAD_A, { sha: HEAD_A, tree: { sha: TREE_A }, parents: [], message: 'base' }],
    ]),
    refs: new Map(),
    checkRunsByHead: new Map(),
    issuedTokens: new Map(),
    requestLog: [],
    commitSeq: 1,
    delayMs: 0,
  };

  let baseUrl = '';

  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const rawBody = Buffer.concat(chunks).toString('utf8');
    let body = null;
    try {
      body = rawBody ? JSON.parse(rawBody) : null;
    } catch {
      body = null;
    }

    const u = new URL(req.url, 'http://127.0.0.1');
    const p = u.pathname;
    state.requestLog.push({ method: req.method, path: p, at: Date.now() });

    if (state.delayMs > 0) {
      await new Promise((r) => setTimeout(r, state.delayMs));
    }

    const send = (status, data, headers = {}) => {
      if (res.writableEnded || res.destroyed) return;
      res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
      res.end(typeof data === 'string' ? data : JSON.stringify(data));
    };

    if (state.redirectOnNextCall) {
      state.redirectOnNextCall = false;
      res.writeHead(302, { Location: 'https://evil.example/token-leak' });
      res.end();
      return;
    }

    if (state.forceStatus && p.includes(state.forceStatus.pathIncludes ?? '')) {
      return send(state.forceStatus.status, { message: 'Forced error' });
    }

    // 1. App installation lookup: GET /repos/:owner/:repo/installation
    const instMatch = /^\/repos\/([^/]+\/[^/]+)\/installation$/.exec(p);
    if (req.method === 'GET' && instMatch) {
      if (state.installationMissing) return send(404, { message: 'Not Found' });
      if (state.installationRevoked) {
        return send(200, {
          id: Number(state.installationId),
          suspended_at: '2026-10-20T00:00:00Z',
          permissions: state.installationPerms,
        });
      }
      return send(200, {
        id: Number(state.installationId),
        repository_selection: 'selected',
        permissions: state.installationPerms,
      });
    }

    // 2. Installation token mint: POST /app/installations/:id/access_tokens
    const mintMatch = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(p);
    if (req.method === 'POST' && mintMatch) {
      if (state.installationMissing || mintMatch[1] !== state.installationId) {
        return send(404, { message: 'Unknown installation' });
      }
      if (state.installationRevoked) return send(403, { message: 'Installation suspended' });
      const tok = `ghs_sandbox_${randomBytes(10).toString('hex')}`;
      const requestedPerms = body?.permissions ?? {};
      // Mirror GitHub returning current server perms (allows simulating escalation/downgrade if mutated in state)
      const granted = { ...requestedPerms };
      state.issuedTokens.set(tok, { permissions: granted, repositoryIds: body?.repository_ids ?? [] });
      return send(201, {
        token: tok,
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        permissions: granted,
      });
    }

    // 3. Installation repositories: GET /installation/repositories
    if (req.method === 'GET' && p === '/installation/repositories') {
      const page = Number(u.searchParams.get('page') ?? '1');
      if (state.incompleteRepoPagination) {
        return send(200, { total_count: state.repos.length + 3, repositories: state.repos.slice(0, 1) });
      }
      if (state.repos.length > 1 && page === 1) {
        return send(
          200,
          { total_count: state.repos.length, repositories: [state.repos[0]] },
          { Link: `<${baseUrl}/installation/repositories?per_page=100&page=2>; rel="next"` },
        );
      }
      const slice = state.repos.length > 1 ? state.repos.slice(1) : state.repos;
      return send(200, { total_count: state.repos.length, repositories: slice });
    }

    // 4. Open PRs per repository: GET /repos/:owner/:repo/pulls
    const pullsListMatch = /^\/repos\/([^/]+\/[^/]+)\/pulls$/.exec(p);
    if (req.method === 'GET' && pullsListMatch) {
      const repoName = pullsListMatch[1];
      const repo = state.repos.find((r) => r.full_name.toLowerCase() === repoName.toLowerCase());
      if (!repo) return send(404, { message: 'Repo not found' });
      return send(
        200,
        repo.prs.map((pr) => ({
          number: pr.number,
          state: pr.state,
          head: { sha: pr.headSha },
          labels: pr.labels.map((name) => ({ name })),
        })),
      );
    }

    // 5. Single PR detail: GET /repos/:owner/:repo/pulls/:num
    const prDetailMatch = /^\/repos\/([^/]+\/[^/]+)\/pulls\/(\d+)$/.exec(p);
    if (req.method === 'GET' && prDetailMatch) {
      const repoName = prDetailMatch[1];
      const prNum = Number(prDetailMatch[2]);
      const repo = state.repos.find((r) => r.full_name.toLowerCase() === repoName.toLowerCase());
      const pr = repo?.prs.find((x) => x.number === prNum);
      if (!pr) return send(404, { message: 'PR not found' });
      return send(200, {
        number: pr.number,
        state: pr.state,
        head: { sha: pr.headSha },
        labels: pr.labels.map((name) => ({ name })),
      });
    }

    // 6. Check runs: GET /repos/:owner/:repo/commits/:sha/check-runs
    const crMatch = /^\/repos\/([^/]+\/[^/]+)\/commits\/([a-f0-9]{40})\/check-runs$/.exec(p);
    if (req.method === 'GET' && crMatch) {
      const repoName = crMatch[1];
      const sha = crMatch[2];
      const runs = state.checkRunsByHead.get(`${repoName}:${sha}`) ?? [];
      if (state.incompleteCheckPagination) {
        return send(200, { total_count: runs.length + 5, check_runs: runs });
      }
      return send(200, { total_count: runs.length, check_runs: runs });
    }

    // 7. Matching BKE refs: GET /repos/:owner/:repo/git/matching-refs/bke/
    const matchRef = /^\/repos\/([^/]+\/[^/]+)\/git\/matching-refs\/bke\/?$/.exec(p);
    if (req.method === 'GET' && matchRef) {
      const repoName = matchRef[1];
      const out = [];
      for (const [k, sha] of state.refs.entries()) {
        if (k.startsWith(`${repoName}:refs/bke/`)) {
          out.push({ ref: k.slice(repoName.length + 1), object: { sha } });
        }
      }
      return send(200, out);
    }

    // 8. Get commit: GET /repos/:owner/:repo/git/commits/:sha
    const getCommitMatch = /^\/repos\/([^/]+\/[^/]+)\/git\/commits\/([a-f0-9]{40})$/.exec(p);
    if (req.method === 'GET' && getCommitMatch) {
      const key = `${getCommitMatch[1]}:${getCommitMatch[2]}`;
      const c = state.commits.get(key);
      return c ? send(200, c) : send(404, { message: 'Commit not found' });
    }

    // 9. Create commit: POST /repos/:owner/:repo/git/commits
    const postCommitMatch = /^\/repos\/([^/]+\/[^/]+)\/git\/commits$/.exec(p);
    if (req.method === 'POST' && postCommitMatch) {
      const repoName = postCommitMatch[1];
      const sha = ('c' + String(state.commitSeq++)).padEnd(40, '0').slice(0, 40);
      const created = {
        sha,
        tree: { sha: body.tree },
        parents: body.parents ?? [],
        message: body.message ?? '',
      };
      state.commits.set(`${repoName}:${sha}`, created);
      return send(201, created);
    }

    // 10. Read ref: GET /repos/:owner/:repo/git/ref/*
    const getRefMatch = /^\/repos\/([^/]+\/[^/]+)\/git\/ref\/(.+)$/.exec(p);
    if (req.method === 'GET' && getRefMatch) {
      const repoName = getRefMatch[1];
      const refName = `refs/${getRefMatch[2]}`;
      const key = `${repoName}:${refName}`;
      if (!state.refs.has(key)) return send(404, { message: 'Ref not found' });
      const sha = state.lyingReadBackSha ?? state.refs.get(key);
      return send(200, { ref: refName, object: { sha } });
    }

    // 11. Create ref (CAS): POST /repos/:owner/:repo/git/refs
    const postRefMatch = /^\/repos\/([^/]+\/[^/]+)\/git\/refs$/.exec(p);
    if (req.method === 'POST' && postRefMatch) {
      const repoName = postRefMatch[1];
      const key = `${repoName}:${body.ref}`;
      if (state.refs.has(key)) {
        return send(422, { message: 'Reference already exists' });
      }
      state.refs.set(key, body.sha);
      if (state.dropAfterMutateCount > 0) {
        state.dropAfterMutateCount -= 1;
        req.socket.destroy();
        return;
      }
      return send(201, { ref: body.ref, object: { sha: body.sha } });
    }

    // 12. Update ref (fast-forward CAS): PATCH /repos/:owner/:repo/git/refs/*
    const patchRefMatch = /^\/repos\/([^/]+\/[^/]+)\/git\/refs\/(.+)$/.exec(p);
    if (req.method === 'PATCH' && patchRefMatch) {
      const repoName = patchRefMatch[1];
      const refName = `refs/${patchRefMatch[2]}`;
      const key = `${repoName}:${refName}`;
      if (!state.refs.has(key)) {
        return send(422, { message: 'Reference does not exist' });
      }
      state.refs.set(key, body.sha);
      return send(200, { ref: refName, object: { sha: body.sha } });
    }

    return send(404, { message: `Unhandled ${req.method} ${p}` });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;

  return {
    baseUrl,
    state,
    setTicket(repo, headSha, workerId, attemptId, expMs, app = { id: 9001, slug: 'bke-dispatcher-app' }, checkRunId = 1001) {
      state.commits.set(`${repo}:${headSha}`, { sha: headSha, tree: { sha: TREE_A }, parents: [], message: 'head' });
      state.checkRunsByHead.set(`${repo}:${headSha}`, [
        {
          id: checkRunId,
          name: 'bke-ticket',
          app,
          head_sha: headSha,
          status: 'completed',
          conclusion: 'success',
          external_id: `bke-ticket:v1:${workerId}:${attemptId}:${Math.floor(expMs / 1000)}`,
        },
      ]);
    },
    close: () => {
      server.closeAllConnections?.();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}
