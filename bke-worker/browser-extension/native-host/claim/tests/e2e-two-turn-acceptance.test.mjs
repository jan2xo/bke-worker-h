/**
 * F1-06 Synthetic End-to-End Acceptance Suite (1 worker, 1 isolated PR,
 * 1 authenticated session, 2 genuine turns, 0 duplicate sends + fail-closed adversarial matrix).
 *
 * Exercises the FULL desktop stack end-to-end using local test doubles for GitHub REST and Chrome DOM:
 * - GitHubF1Ledger (F1-02) against stateful local GitHub REST double
 * - FileExecutionJournal & DesktopController (F1-03) with HMAC-SHA256 webhook + crash recovery
 * - Real Node `entry.mjs --controller-bridge` subprocess stdio/IPC bridge (F1-03)
 * - connectControllerNativeBridge + ExtensionBrowserAdapter (F1-03 / F1-04 / F1-05)
 * - Simulated single-tab ChatGPT DOM enforcing landing -> /c/<id> -> same /c/<id>
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, webcrypto } from "node:crypto";
import { spawn } from "node:child_process";
import { connect as connectNet } from "node:net";
import { createServer } from "node:http";
import { chmod, mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { createDeviceIdentityBridge } from "../../../dist/device-identity.js";
import { connectControllerNativeBridge } from "../../../dist/controller-transport.js";
import { ExtensionBrowserAdapter } from "../../../dist/extension-browser-adapter.js";
import { DesktopControllerDaemon } from "../dist/native-host/claim/controller-daemon.js";
import { signExecutionRequestHmac } from "../dist/native-host/claim/github-app-harness.js";
import { GitHubF1Ledger } from "../dist/native-host/claim/github-f1-ledger.js";
import { IpcBridgeClient } from "../dist/native-host/claim/ipc-client.js";
import {
  DesktopController,
  FileExecutionJournal,
} from "../dist/native-host/claim/desktop-controller.js";
import {
  DeterministicMockTokenBroker,
  ManagedTokenProvider,
} from "../dist/native-host/claim/token-lifecycle.js";

const ORIGIN = "chrome-extension://" + "a".repeat(32) + "/";
const PROFILE_BINDING = "4".repeat(64);
const H = (c) => c.repeat(64);
const RESOURCES = {
  chatgpt_target_sha256: H("1"),
  browser_profile_sha256: H("2"),
  bridge_identity_sha256: H("3"),
};
const HEAD = "a".repeat(40);
const TREE = "e".repeat(40);
const REPO = "jan2xo/bke-worker";
const WORKER = "worker-f1";
const PR_NUMBER = 127;
const PINNED_APP = { id: 9001, slug: "bke-dispatcher-app" };
const WEBHOOK_SECRET = "synthetic-local-webhook-secret";
const entryPath = fileURLToPath(new URL("../../entry.mjs", import.meta.url));

function memoryIdentityStore() {
  let current;
  let tail = Promise.resolve();
  return {
    async atomic(action) {
      let release;
      const next = new Promise((resolve) => { release = resolve; });
      const prev = tail;
      tail = next;
      await prev;
      let draft = current === undefined ? undefined : structuredClone(current);
      try {
        const res = await action({
          get: async () => (draft === undefined ? undefined : structuredClone(draft)),
          put: async (v) => { draft = structuredClone(v); },
        });
        current = draft;
        return res;
      } finally {
        release();
      }
    },
  };
}

function createSyntheticGitHub(initialAttempt = "attempt-turn-1") {
  const refs = new Map();
  const commits = new Map([[HEAD, { sha: HEAD, tree: { sha: TREE }, parents: [], message: "head" }]]);
  let openPrs = [
    { number: PR_NUMBER, state: "open", head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] },
  ];
  let checkRuns = [
    {
      id: 701,
      name: "bke-ticket",
      app: PINNED_APP,
      head_sha: HEAD,
      status: "completed",
      conclusion: "success",
      external_id: `bke-ticket:v1:${WORKER}:${initialAttempt}:${Math.floor(Date.parse("2026-10-20T12:00:00.000Z") / 1000)}`,
    },
  ];
  let seq = 1;
  const requests = [];
  const res = (status, body) => ({ status, headers: { get: () => null }, json: async () => body });

  const fetch = async (url, init) => {
    const parsed = new URL(url);
    const p = parsed.pathname;
    const body = init.body ? JSON.parse(init.body) : null;
    requests.push({ method: init.method, path: p, body });

    if (init.method === "GET" && p === "/installation/repositories") {
      return res(200, { repositories: [{ full_name: REPO, permissions: { push: true } }] });
    }
    if (init.method === "GET" && p === `/repos/${REPO}/pulls`) {
      return res(200, openPrs);
    }
    if (init.method === "GET" && p.startsWith(`/repos/${REPO}/pulls/`)) {
      const n = Number(p.split("/").pop());
      const pr = openPrs.find((x) => x.number === n);
      return pr ? res(200, pr) : res(404, { message: "Not Found" });
    }
    if (init.method === "GET" && p === `/repos/${REPO}/git/matching-refs/bke/`) {
      return res(
        200,
        [...refs.entries()].filter(([k]) => k.startsWith("refs/bke/")).map(([ref, sha]) => ({ ref, object: { sha } })),
      );
    }
    if (init.method === "GET" && p.endsWith("/check-runs")) {
      return res(200, { total_count: checkRuns.length, check_runs: checkRuns });
    }
    if (init.method === "GET" && p.startsWith(`/repos/${REPO}/git/commits/`)) {
      const sha = p.split("/").pop();
      return commits.has(sha) ? res(200, commits.get(sha)) : res(404, { message: "Not Found" });
    }
    if (init.method === "POST" && p === `/repos/${REPO}/git/commits`) {
      const sha = String(seq++).padStart(40, "0").slice(-40);
      const created = { sha, tree: { sha: body.tree }, parents: body.parents, message: body.message };
      commits.set(sha, created);
      return res(201, created);
    }
    if (init.method === "GET" && p.startsWith(`/repos/${REPO}/git/ref/`)) {
      const ref = "refs/" + p.slice(`/repos/${REPO}/git/ref/`.length);
      return refs.has(ref) ? res(200, { ref, object: { sha: refs.get(ref) } }) : res(404, { message: "Not Found" });
    }
    if (init.method === "POST" && p === `/repos/${REPO}/git/refs`) {
      if (refs.has(body.ref)) return res(422, { message: "Reference already exists" });
      refs.set(body.ref, body.sha);
      return res(201, { ref: body.ref, object: { sha: body.sha } });
    }
    if (init.method === "PATCH" && p.startsWith(`/repos/${REPO}/git/refs/`)) {
      const ref = "refs/" + p.slice(`/repos/${REPO}/git/refs/`.length);
      if (!refs.has(ref)) return res(422, { message: "Reference does not exist" });
      refs.set(ref, body.sha);
      return res(200, { ref, object: { sha: body.sha } });
    }
    return res(404, { message: "Unhandled" });
  };

  return {
    fetch,
    refs,
    requests,
    setOpenPrs(next) { openPrs = next; },
    setTicket(attemptId, overrides = {}) {
      checkRuns = [
        {
          id: 702,
          name: "bke-ticket",
          app: PINNED_APP,
          head_sha: HEAD,
          status: "completed",
          conclusion: "success",
          external_id: `bke-ticket:v1:${WORKER}:${attemptId}:${Math.floor(Date.parse("2026-10-20T12:00:00.000Z") / 1000)}`,
          ...overrides,
        },
      ];
    },
  };
}

function sendIpc(sockPath, cmd) {
  return new Promise((resolve, reject) => {
    const client = connectNet(sockPath, () => client.write(JSON.stringify(cmd) + "\n"));
    let buf = "";
    client.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      const idx = buf.indexOf("\n");
      if (idx >= 0) {
        const res = JSON.parse(buf.slice(0, idx));
        client.end();
        resolve(res);
      }
    });
    client.once("error", reject);
  });
}

async function createE2eHarness(dir, gh, options = {}) {
  const policyPath = join(dir, "policy.json");
  const sockPath = join(dir, "bridge.sock");
  const journalPath = join(dir, "journal.json");

  const identity = createDeviceIdentityBridge({ store: memoryIdentityStore(), cryptoImpl: webcrypto, now: () => Date.now() });
  const pub = await identity.initialize(WORKER);
  await writeFile(
    policyPath,
    JSON.stringify({
      version: 1,
      allowed_origin: ORIGIN,
      worker_id: WORKER,
      public_key_sha256: pub.public_key_sha256,
      profile_binding_sha256: PROFILE_BINDING,
      resources: RESOURCES,
      expires_at_ms: Date.now() + 120_000,
    }),
    { mode: 0o600 },
  );

  // Simulated browser page state
  const browserState = {
    url: "https://chatgpt.com/",
    uiState: "NEW_CHAT_LANDING",
    tabId: 17,
    targetId: "target-e2e-01",
    profileId: "profile-e2e-01",
    submissions: [],
    throwOnSubmit: options.throwOnSubmit ?? false,
  };

  let child = null;
  const runtime = {
    getURL: () => ORIGIN,
    connectNative() {
      child = spawn(process.execPath, [entryPath, "--controller-bridge", policyPath, ORIGIN, sockPath], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { PATH: process.env.PATH ?? "" },
      });
      const msgListeners = new Set();
      const discListeners = new Set();
      let buffer = Buffer.alloc(0);
      const notifyDisconnect = () => { for (const fn of [...discListeners]) fn(); };
      child.stdout.on("data", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 4) {
          const len = buffer.readUInt32LE(0);
          if (len < 1 || len > 16_384) { child.kill("SIGTERM"); notifyDisconnect(); return; }
          if (buffer.length < len + 4) break;
          const msg = JSON.parse(buffer.subarray(4, len + 4).toString("utf8"));
          buffer = buffer.subarray(len + 4);
          for (const fn of [...msgListeners]) fn(msg);
        }
      });
      child.once("exit", notifyDisconnect);
      return {
        postMessage(msg) {
          const body = Buffer.from(JSON.stringify(msg), "utf8");
          const frame = Buffer.allocUnsafe(body.length + 4);
          frame.writeUInt32LE(body.length, 0);
          body.copy(frame, 4);
          child.stdin.write(frame);
        },
        disconnect() { if (!child.stdin.writableEnded) child.stdin.end(); },
        onMessage: { addListener: (fn) => msgListeners.add(fn), removeListener: (fn) => msgListeners.delete(fn) },
        onDisconnect: { addListener: (fn) => discListeners.add(fn), removeListener: (fn) => discListeners.delete(fn) },
      };
    },
  };

  let clockCounter = Date.parse("2026-10-20T09:00:00.000Z");
  const nextIso = () => {
    clockCounter += 500;
    return new Date(clockCounter).toISOString();
  };

  const bridgeConn = await connectControllerNativeBridge({
    runtime,
    identity,
    workerId: WORKER,
    resources: RESOURCES,
    profileBindingSha256: PROFILE_BINDING,
    checkPermission: async () => true,
    cryptoImpl: webcrypto,
    handlers: {
      withTargetLock: async (run) => ({ ok: true, value: await run() }),
      getTargetStatus: async () => ({
        ok: true,
        code: "TARGET_OK",
        payload: {
          observedAt: nextIso(),
          url: browserState.url,
          visible: true,
          composerAvailable: true,
          turnBusy: false,
          uiState: browserState.uiState,
          tabId: browserState.tabId,
          targetId: browserState.targetId,
          profileId: browserState.profileId,
          matchingWritableTargetCount: 1,
          sharedWritableProfile: false,
        },
      }),
      dispatchFirstMessage: async (cmd) => {
        if (browserState.throwOnSubmit) throw new Error("DOM_SUBMIT_UNCERTAIN");
        const beforeUrl = browserState.url;
        const convId = "conv-e2e-0001";
        const afterUrl = `https://chatgpt.com/c/${convId}`;
        browserState.submissions.push({ turn: 1, attemptId: cmd.attempt_id, beforeUrl, afterUrl, prompt: cmd.prompt });
        browserState.url = afterUrl;
        browserState.uiState = "THREAD";
        return {
          ok: true,
          code: "FIRST_MESSAGE_SENT",
          payload: {
            beforeUrl,
            afterUrl,
            conversationId: convId,
            sendStartedAt: nextIso(),
            confirmedAt: nextIso(),
          },
        };
      },
      dispatchContinuation: async (cmd) => {
        if (browserState.throwOnSubmit) throw new Error("DOM_SUBMIT_UNCERTAIN");
        const beforeUrl = browserState.url;
        const afterUrl = `https://chatgpt.com/c/${cmd.expected_conversation_id}`;
        browserState.submissions.push({ turn: cmd.expected_turn_number, attemptId: cmd.attempt_id, beforeUrl, afterUrl, prompt: cmd.prompt });
        return {
          ok: true,
          code: "CONTINUATION_SENT",
          payload: {
            beforeUrl,
            afterUrl,
            conversationId: cmd.expected_conversation_id,
            sendStartedAt: nextIso(),
            confirmedAt: nextIso(),
          },
        };
      },
    },
  });
  assert.equal(bridgeConn.ok, true);

  let bridgeSeq = 0;
  const nextSeq = () => ++bridgeSeq;

  const journal = new FileExecutionJournal(journalPath, { repository: REPO, prNumber: PR_NUMBER, workerId: WORKER }, nextIso);
  const controller = new DesktopController({
    journal,
    webhookSecret: WEBHOOK_SECRET,
    nowIso: nextIso,
    liveProofs: {
      githubCasOwnerCertified: true,
      nativePairingOwnerCertified: true,
      realBrowserOwnerAccepted: true,
    },
    createLedger: (headSha) =>
      new GitHubF1Ledger(
        {
          repository: REPO,
          prNumber: PR_NUMBER,
          headSha,
          workerId: WORKER,
          authenticatedWorkerId: WORKER,
          pinnedApp: PINNED_APP,
          executionId: "exec-e2e-01",
          targetId: browserState.targetId,
          profileId: browserState.profileId,
          targetTabId: browserState.tabId,
          nowIso: nextIso,
        },
        gh.fetch,
        async () => "synthetic-github-token",
      ),
    createBrowserPorts: (headSha) => {
      const adapter = new ExtensionBrowserAdapter(
        {
          repository: REPO,
          prNumber: PR_NUMBER,
          headSha,
          workerId: WORKER,
          targetId: browserState.targetId,
          profileId: browserState.profileId,
          targetTabId: browserState.tabId,
          nextSeq,
        },
        { sendCommand: (cmd) => sendIpc(sockPath, cmd) },
      );
      return {
        firstMessage: adapter.asFirstMessagePort(),
        continuation: adapter.asContinuationPort(),
      };
    },
  });
  await controller.initialize();

  const signBody = (bodyObj) => {
    const raw = JSON.stringify(bodyObj);
    const sig = "sha256=" + createHmac("sha256", WEBHOOK_SECRET).update(raw).digest("hex");
    return { raw, sig };
  };

  return {
    controller,
    journal,
    journalPath,
    browserState,
    signBody,
    close: () => {
      bridgeConn.session.close();
      if (child && child.exitCode === null) child.kill("SIGTERM");
    },
  };
}

test("F1-06 2-turn acceptance: 1 worker, 1 PR, 1 authenticated session, 2 genuine turns in same conversation, 0 duplicate sends", async () => {
  const dir = await mkdtemp(join(tmpdir(), "bke-e2e-two-turn-"));
  const gh = createSyntheticGitHub("attempt-turn-1");
  const harness = await createE2eHarness(dir, gh);

  try {
    // Gate check: default humanLiveSendAuthorized = false MUST refuse with 0 submissions
    const blockedGate = await harness.controller.processAuthorizedWake({
      headSha: HEAD,
      prNumber: PR_NUMBER,
      humanLiveSendAuthorized: false,
    });
    assert.equal(blockedGate.status, "BLOCKED");
    assert.equal(blockedGate.code, "LIVE_SEND_DISABLED");
    assert.equal(harness.browserState.submissions.length, 0);

    // Turn 1 authorized webhook wake
    const payload1 = harness.signBody({ action: "check_run", pr: PR_NUMBER, attempt: "attempt-turn-1" });
    const turn1 = await harness.controller.handleWebhookWake({
      signatureHeader: payload1.sig,
      deliveryId: "deliv-turn-1",
      rawBody: payload1.raw,
      headSha: HEAD,
      prNumber: PR_NUMBER,
      humanLiveSendAuthorized: true,
    });
    assert.equal(turn1.status, "CONFIRMED_TURN_1");
    assert.equal(turn1.turnNumber, 1);
    assert.equal(turn1.conversationId, "conv-e2e-0001");
    assert.equal(harness.browserState.submissions.length, 1);
    assert.equal(gh.refs.get(`refs/bke/claims/${PR_NUMBER}/attempt-turn-1`), HEAD);

    // Duplicate webhook delivery MUST be rejected with 0 duplicate submissions
    const dupWebhook = await harness.controller.handleWebhookWake({
      signatureHeader: payload1.sig,
      deliveryId: "deliv-turn-1",
      rawBody: payload1.raw,
      headSha: HEAD,
      prNumber: PR_NUMBER,
      humanLiveSendAuthorized: true,
    });
    assert.equal(dupWebhook.code, "WEBHOOK_DELIVERY_DUPLICATE");
    assert.equal(harness.browserState.submissions.length, 1);

    // Reused consumed attempt-turn-1 MUST be blocked even on new webhook delivery
    const replayAttemptPayload = harness.signBody({ action: "check_run", attempt: "attempt-turn-1" });
    const replayAttempt = await harness.controller.handleWebhookWake({
      signatureHeader: replayAttemptPayload.sig,
      deliveryId: "deliv-turn-1-replay",
      rawBody: replayAttemptPayload.raw,
      headSha: HEAD,
      prNumber: PR_NUMBER,
      humanLiveSendAuthorized: true,
    });
    assert.equal(replayAttempt.status, "BLOCKED");
    assert.equal(harness.browserState.submissions.length, 1);

    // Issue fresh ticket for Turn 2 & send continuation wake
    gh.setTicket("attempt-turn-2");
    const payload2 = harness.signBody({ action: "check_run", pr: PR_NUMBER, attempt: "attempt-turn-2" });
    const turn2 = await harness.controller.handleWebhookWake({
      signatureHeader: payload2.sig,
      deliveryId: "deliv-turn-2",
      rawBody: payload2.raw,
      headSha: HEAD,
      prNumber: PR_NUMBER,
      humanLiveSendAuthorized: true,
    });
    assert.equal(turn2.status, "CONFIRMED_CONTINUATION");
    assert.equal(turn2.turnNumber, 2);
    assert.equal(turn2.conversationId, "conv-e2e-0001");
    assert.equal(harness.browserState.submissions.length, 2);
    assert.equal(harness.browserState.submissions[0].turn, 1);
    assert.equal(harness.browserState.submissions[1].turn, 2);
    assert.equal(harness.browserState.submissions[1].beforeUrl, "https://chatgpt.com/c/conv-e2e-0001");
    assert.equal(harness.browserState.submissions[1].afterUrl, "https://chatgpt.com/c/conv-e2e-0001");
    assert.ok(gh.refs.has(`refs/bke/turns/${PR_NUMBER}/attempt-turn-1`));
    assert.ok(gh.refs.has(`refs/bke/turns/${PR_NUMBER}/attempt-turn-2`));
  } finally {
    harness.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("F1-06 adversarial fail-closed matrix: bad HMAC, accidental landing on turn 2, crash mid-send, uncertain submit quarantine", async () => {
  // 1. Bad HMAC & accidental landing on Turn 2
  const dir1 = await mkdtemp(join(tmpdir(), "bke-e2e-adv1-"));
  const gh1 = createSyntheticGitHub("attempt-1");
  const h1 = await createE2eHarness(dir1, gh1);
  try {
    const badSig = await h1.controller.handleWebhookWake({
      signatureHeader: "sha256=" + "0".repeat(64),
      deliveryId: "deliv-bad-sig",
      rawBody: "{}",
      headSha: HEAD,
      prNumber: PR_NUMBER,
      humanLiveSendAuthorized: true,
    });
    assert.equal(badSig.code, "WEBHOOK_SIGNATURE_INVALID");

    // Complete turn 1
    const r1 = await h1.controller.processAuthorizedWake({ headSha: HEAD, prNumber: PR_NUMBER, humanLiveSendAuthorized: true });
    assert.equal(r1.status, "CONFIRMED_TURN_1");

    // Simulate accidental navigation back to https://chatgpt.com/ before Turn 2 -> MUST block & 0 extra sends!
    h1.browserState.url = "https://chatgpt.com/";
    h1.browserState.uiState = "NEW_CHAT_LANDING";
    gh1.setTicket("attempt-2");
    const r2 = await h1.controller.processAuthorizedWake({ headSha: HEAD, prNumber: PR_NUMBER, humanLiveSendAuthorized: true });
    assert.equal(r2.status, "BLOCKED");
    assert.equal(r2.code, "WRONG_CONVERSATION_OR_NEW_CHAT");
    assert.equal(h1.browserState.submissions.length, 1);

    // Multi-PR conflict check
    gh1.setOpenPrs([
      { number: PR_NUMBER, state: "open", head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] },
      { number: PR_NUMBER + 1, state: "open", head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] },
    ]);
    h1.browserState.url = "https://chatgpt.com/c/conv-e2e-0001";
    h1.browserState.uiState = "THREAD";
    const multiPr = await h1.controller.processAuthorizedWake({ headSha: HEAD, prNumber: PR_NUMBER, humanLiveSendAuthorized: true });
    assert.equal(multiPr.code, "GITHUB_WORKER_MULTI_PR_CONFLICT");
    assert.equal(h1.browserState.submissions.length, 1);
  } finally {
    h1.close();
    await rm(dir1, { recursive: true, force: true });
  }

  // 2. Crash recovery while DISPATCHING -> quarantine & refuse retry
  const dir2 = await mkdtemp(join(tmpdir(), "bke-e2e-adv2-"));
  const gh2 = createSyntheticGitHub("attempt-crash");
  const h2 = await createE2eHarness(dir2, gh2);
  try {
    const raw = JSON.parse(await readFile(h2.journalPath, "utf8"));
    raw.phase = "DISPATCHING";
    raw.activeAttemptId = "attempt-crash";
    await writeFile(h2.journalPath, JSON.stringify(raw), { mode: 0o600 });

    const recovered = await h2.controller.initialize();
    assert.equal(recovered.phase, "DELIVERY_UNCERTAIN");
    assert.equal(recovered.uncertainReason, "CRASH_DURING_DISPATCHING");

    const retry = await h2.controller.processAuthorizedWake({ headSha: HEAD, prNumber: PR_NUMBER, humanLiveSendAuthorized: true });
    assert.equal(retry.status, "BLOCKED");
    assert.equal(retry.journalPhase, "DELIVERY_UNCERTAIN");
    assert.equal(h2.browserState.submissions.length, 0);
  } finally {
    h2.close();
    await rm(dir2, { recursive: true, force: true });
  }

  // 3. Submit throw/uncertainty writes GitHub uncertain ref and latches quarantine
  const dir3 = await mkdtemp(join(tmpdir(), "bke-e2e-adv3-"));
  const gh3 = createSyntheticGitHub("attempt-uncertain");
  const h3 = await createE2eHarness(dir3, gh3, { throwOnSubmit: true });
  try {
    const uRes = await h3.controller.processAuthorizedWake({ headSha: HEAD, prNumber: PR_NUMBER, humanLiveSendAuthorized: true });
    assert.equal(uRes.status, "BLOCKED");
    assert.equal(uRes.code, "DELIVERY_UNCERTAIN");
    assert.equal(uRes.journalPhase, "DELIVERY_UNCERTAIN");
    assert.ok(gh3.refs.has(`refs/bke/uncertain/${PR_NUMBER}/attempt-uncertain`));
  } finally {
    h3.close();
    await rm(dir3, { recursive: true, force: true });
  }
});

test("F2-07 Full Synthetic Signed-Envelope Two-Turn Acceptance: Authority -> Verifier -> RestProvider -> TokenRefresh -> Daemon -> Journal -> IPC -> NativeBridge -> 2 Turns -> Remote HALT", async () => {
  const dir = await mkdtemp(join(tmpdir(), "bke-f2-e2e-"));
  await chmod(dir, 0o700);
  const policyPath = join(dir, "policy.json");
  const sockPath = join(dir, "bridge.sock");
  const journalPath = join(dir, "journal.json");

  const REPO_ID = 1354026486;
  const INSTALL_ID = "987654321";
  const EXEC_KEY_ID = "exec-k1";
  const EXEC_SECRET = "trusted-server-execution-signing-secret-64b";
  const HALT_KEY_ID = "halt-k1";
  const HALT_SECRET = "trusted-server-remote-halt-secret-isolated-64b";
  const HALT_TOKEN = "local-owner-halt-token-xyz";
  const WEBHOOK_SECRET_LOCAL = "local-webhook-secret-xyz";
  const baseWallMs = Date.now();
  let tokenClockMs = baseWallMs;
  let isoCounter = baseWallMs;
  const nowIso = () => new Date((isoCounter += 250)).toISOString();

  // Real local GitHub REST HTTP server enforcing immutable ID, GET-only authority, CAS refs, and tickets
  const refs = new Map();
  const commits = new Map([[HEAD, { sha: HEAD, tree: { sha: TREE }, parents: [], message: "head" }]]);
  let currentAttempt = "attempt-f2-turn-1";
  let seq = 1;
  const ghHttpMethods = [];

  const ghServer = createServer(async (req, res) => {
    ghHttpMethods.push(`${req.method} ${req.url}`);
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) : null;
    const u = new URL(req.url, "http://127.0.0.1");
    const p = u.pathname;
    const json = (status, data) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(data));
    };

    if (req.method === "GET" && p === "/installation/repositories") {
      return json(200, {
        repositories: [{
          id: REPO_ID,
          full_name: REPO,
          permissions: { contents: "write", pull_requests: "read", checks: "read", push: true },
        }],
      });
    }
    if (req.method === "GET" && p === `/repos/${REPO}/pulls`) {
      return json(200, [{ number: PR_NUMBER, state: "open", head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] }]);
    }
    if (req.method === "GET" && p === `/repos/${REPO}/pulls/${PR_NUMBER}`) {
      return json(200, { number: PR_NUMBER, state: "open", head: { sha: HEAD }, labels: [{ name: `bke-worker:${WORKER}` }] });
    }
    if (req.method === "GET" && p === `/repos/${REPO}/git/matching-refs/bke/`) {
      return json(200, [...refs.entries()].filter(([k]) => k.startsWith("refs/bke/")).map(([ref, sha]) => ({ ref, object: { sha } })));
    }
    if (req.method === "GET" && p === `/repos/${REPO}/commits/${HEAD}/check-runs`) {
      return json(200, {
        total_count: 1,
        check_runs: [{
          id: 901,
          name: "bke-ticket",
          app: PINNED_APP,
          head_sha: HEAD,
          status: "completed",
          conclusion: "success",
          external_id: `bke-ticket:v1:${WORKER}:${currentAttempt}:${Math.floor((Date.now() + 120_000) / 1000)}`,
        }],
      });
    }
    if (req.method === "GET" && p.startsWith(`/repos/${REPO}/git/commits/`)) {
      const sha = p.split("/").pop();
      return commits.has(sha) ? json(200, commits.get(sha)) : json(404, { message: "Not Found" });
    }
    if (req.method === "POST" && p === `/repos/${REPO}/git/commits`) {
      const sha = ("c" + String(seq++)).padEnd(40, "0").slice(0, 40);
      const created = { sha, tree: { sha: body.tree }, parents: body.parents, message: body.message };
      commits.set(sha, created);
      return json(201, created);
    }
    if (req.method === "GET" && p.startsWith(`/repos/${REPO}/git/ref/`)) {
      const ref = "refs/" + p.slice(`/repos/${REPO}/git/ref/`.length);
      return refs.has(ref) ? json(200, { ref, object: { sha: refs.get(ref) } }) : json(404, { message: "Not Found" });
    }
    if (req.method === "POST" && p === `/repos/${REPO}/git/refs`) {
      if (refs.has(body.ref)) return json(422, { message: "Reference already exists" });
      refs.set(body.ref, body.sha);
      return json(201, { ref: body.ref, object: { sha: body.sha } });
    }
    if (req.method === "PATCH" && p.startsWith(`/repos/${REPO}/git/refs/`)) {
      const ref = "refs/" + p.slice(`/repos/${REPO}/git/refs/`.length);
      if (!refs.has(ref)) return json(422, { message: "Reference does not exist" });
      refs.set(ref, body.sha);
      return json(200, { ref, object: { sha: body.sha } });
    }
    return json(404, { message: "Not Found" });
  });
  await new Promise((r) => ghServer.listen(0, "127.0.0.1", r));
  const ghBaseUrl = `http://127.0.0.1:${ghServer.address().port}`;

  const identity = createDeviceIdentityBridge({ store: memoryIdentityStore(), cryptoImpl: webcrypto, now: () => Date.now() });
  const pub = await identity.initialize(WORKER);
  await writeFile(
    policyPath,
    JSON.stringify({
      version: 1,
      allowed_origin: ORIGIN,
      worker_id: WORKER,
      public_key_sha256: pub.public_key_sha256,
      profile_binding_sha256: PROFILE_BINDING,
      resources: RESOURCES,
      expires_at_ms: Date.now() + 120_000,
    }),
    { mode: 0o600 },
  );

  const browserState = {
    url: "https://chatgpt.com/",
    uiState: "NEW_CHAT_LANDING",
    submissions: [],
    driftTurn2: false,
  };

  let child = null;
  const runtime = {
    getURL: () => ORIGIN,
    connectNative() {
      child = spawn(process.execPath, [entryPath, "--controller-bridge", policyPath, ORIGIN, sockPath], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { PATH: process.env.PATH ?? "" },
      });
      const msgL = new Set();
      const discL = new Set();
      let buf = Buffer.alloc(0);
      const notify = () => { for (const f of [...discL]) f(); };
      child.stdout.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 4) {
          const len = buf.readUInt32LE(0);
          if (len < 1 || len > 16_384) { child.kill("SIGTERM"); notify(); return; }
          if (bufferLen(buf) < len + 4) break;
          const msg = JSON.parse(buf.subarray(4, len + 4).toString("utf8"));
          buf = buf.subarray(len + 4);
          for (const f of [...msgL]) f(msg);
        }
      });
      function bufferLen(b) { return b.length; }
      child.once("exit", notify);
      return {
        postMessage(msg) {
          const body = Buffer.from(JSON.stringify(msg), "utf8");
          const frame = Buffer.allocUnsafe(body.length + 4);
          frame.writeUInt32LE(body.length, 0);
          body.copy(frame, 4);
          child.stdin.write(frame);
        },
        disconnect() { if (!child.stdin.writableEnded) child.stdin.end(); },
        onMessage: { addListener: (f) => msgL.add(f), removeListener: (f) => msgL.delete(f) },
        onDisconnect: { addListener: (f) => discL.add(f), removeListener: (f) => discL.delete(f) },
      };
    },
  };

  const bridgeConn = await connectControllerNativeBridge({
    runtime,
    identity,
    workerId: WORKER,
    resources: RESOURCES,
    profileBindingSha256: PROFILE_BINDING,
    checkPermission: async () => true,
    cryptoImpl: webcrypto,
    handlers: {
      withTargetLock: async (run) => ({ ok: true, value: await run() }),
      getTargetStatus: async () => ({
        ok: true,
        code: "TARGET_OK",
        payload: {
          observedAt: nowIso(),
          url: browserState.url,
          visible: true,
          composerAvailable: true,
          turnBusy: false,
          uiState: browserState.uiState,
          tabId: 19,
          targetId: "target-f2-01",
          profileId: "profile-f2-01",
          matchingWritableTargetCount: 1,
          sharedWritableProfile: false,
        },
      }),
      dispatchFirstMessage: async (cmd) => {
        const beforeUrl = browserState.url;
        const convId = "conv-f2-e2e-01";
        const afterUrl = `https://chatgpt.com/c/${convId}`;
        browserState.submissions.push({ turn: 1, attemptId: cmd.attempt_id, beforeUrl, afterUrl });
        browserState.url = afterUrl;
        browserState.uiState = "THREAD";
        return {
          ok: true,
          code: "FIRST_MESSAGE_SENT",
          payload: { beforeUrl, afterUrl, conversationId: convId, sendStartedAt: nowIso(), confirmedAt: nowIso() },
        };
      },
      dispatchContinuation: async (cmd) => {
        const beforeUrl = browserState.url;
        const afterUrl = browserState.driftTurn2
          ? "https://chatgpt.com/c/conv-other-drifted"
          : `https://chatgpt.com/c/${cmd.expected_conversation_id}`;
        browserState.submissions.push({ turn: 2, attemptId: cmd.attempt_id, beforeUrl, afterUrl });
        return {
          ok: true,
          code: "CONTINUATION_SENT",
          payload: {
            beforeUrl,
            afterUrl,
            conversationId: browserState.driftTurn2 ? "conv-other-drifted" : cmd.expected_conversation_id,
            sendStartedAt: nowIso(),
            confirmedAt: nowIso(),
          },
        };
      },
    },
  });
  assert.equal(bridgeConn.ok, true);

  const broker = new DeterministicMockTokenBroker(() => tokenClockMs, { ttlMs: 90_000 });
  const tokenLifecycle = new ManagedTokenProvider(
    {
      repository: REPO,
      repositoryId: REPO_ID,
      installationId: INSTALL_ID,
      workerId: WORKER,
      allowedPermissions: { contents: "write", pull_requests: "read", checks: "read" },
      refreshMarginMs: 25_000,
      nowMs: () => tokenClockMs,
    },
    broker,
  );
  const ipcClient = new IpcBridgeClient({ socketPath: sockPath });

  const daemon = new DesktopControllerDaemon(
    {
      repository: REPO,
      prNumber: PR_NUMBER,
      workerId: WORKER,
      pinnedApp: PINNED_APP,
      executionId: "exec-f2-e2e",
      targetId: "target-f2-01",
      profileId: "profile-f2-01",
      targetTabId: 19,
      journalPath,
      ipcSocketPath: sockPath,
      webhookSecret: WEBHOOK_SECRET_LOCAL,
      operatorHaltToken: HALT_TOKEN,
      executionEnvelopeEnabled: true,
      expectedRepositoryId: REPO_ID,
      expectedInstallationId: INSTALL_ID,
      executionSigningKeysById: new Map([[EXEC_KEY_ID, EXEC_SECRET]]),
      remoteHaltSigningKeysById: new Map([[HALT_KEY_ID, HALT_SECRET]]),
      allowRemoteSignedHalt: true,
      githubApiBaseUrl: ghBaseUrl,
      listenHost: "127.0.0.1",
      listenPort: 0,
      humanLiveSendAuthorized: true,
      liveProofs: {
        githubCasOwnerCertified: true,
        nativePairingOwnerCertified: true,
        realBrowserOwnerAccepted: true,
      },
    },
    {
      tokenProvider: tokenLifecycle.asTokenProvider(),
      tokenLifecycle,
      fetchImpl: (url, init) => {
        const target = url.replace("https://api.github.com", ghBaseUrl);
        return globalThis.fetch(target, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() }));
      },
      ipcClient,
      nowIso,
      nowMs: () => Date.now(),
    },
  );

  const makeEnv = (overrides = {}) => {
    const now = Date.now();
    return {
      protocol_version: 1,
      repository_owner: "jan2xo",
      repository_name: "bke-worker",
      repository_id: REPO_ID,
      installation_identity: INSTALL_ID,
      worker_id: WORKER,
      pr_number: PR_NUMBER,
      head_sha: HEAD,
      attempt_id: currentAttempt,
      delivery_id: "deliv-f2-default",
      action: "DISPATCH_FIRST_MESSAGE",
      issued_at: new Date(now - 5_000).toISOString(),
      expires_at: new Date(now + 60_000).toISOString(),
      authorized_capability: "GITHUB_F1_EXECUTION_V1",
      ...overrides,
    };
  };

  try {
    const { port } = await daemon.start();
    const postExec = async (signedReq) =>
      globalThis.fetch(`http://127.0.0.1:${port}/execution-requests`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(signedReq),
      });

    // 1. PREPARE (read-only) updates expected head SHA without dispatching to browser
    const prepRes = await postExec(
      signExecutionRequestHmac(makeEnv({ action: "PREPARE", delivery_id: "deliv-f2-prep" }), EXEC_SECRET, EXEC_KEY_ID),
    );
    assert.equal(prepRes.status, 200);
    assert.equal((await prepRes.json()).status, "PREPARED");
    assert.equal(browserState.submissions.length, 0);

    // 2. Negative: DISPATCH_CONTINUATION before Turn 1 MUST reject (409) with 0 submits
    const earlyContRes = await postExec(
      signExecutionRequestHmac(makeEnv({ action: "DISPATCH_CONTINUATION", delivery_id: "deliv-early-cont" }), EXEC_SECRET, EXEC_KEY_ID),
    );
    assert.equal(earlyContRes.status, 409);
    assert.equal((await earlyContRes.json()).code, "EXEC_REQ_ACTION_NO_ACTIVE_CONVERSATION");
    assert.equal(browserState.submissions.length, 0);

    // 3. Turn 1 DISPATCH_FIRST_MESSAGE end-to-end
    const t1Signed = signExecutionRequestHmac(
      makeEnv({ action: "DISPATCH_FIRST_MESSAGE", delivery_id: "deliv-f2-t1" }),
      EXEC_SECRET,
      EXEC_KEY_ID,
    );
    const t1Res = await postExec(t1Signed);
    assert.equal(t1Res.status, 200);
    const t1Body = await t1Res.json();
    assert.equal(t1Body.status, "CONFIRMED_TURN_1");
    assert.equal(t1Body.conversationId, "conv-f2-e2e-01");
    assert.equal(browserState.submissions.length, 1);
    assert.equal(broker.issueCalls, 1);

    // 4. Negative: Replay of Turn 1 delivery and attempt MUST reject (409), 0 extra submits
    assert.equal((await postExec(t1Signed)).status, 409);
    const replayAttemptReq = signExecutionRequestHmac(
      makeEnv({ action: "DISPATCH_FIRST_MESSAGE", delivery_id: "deliv-f2-t1-dup" }),
      EXEC_SECRET,
      EXEC_KEY_ID,
    );
    assert.equal((await postExec(replayAttemptReq)).status, 409);

    // 5. Negative: DISPATCH_FIRST_MESSAGE after Turn 1 MUST reject (409)
    currentAttempt = "attempt-f2-turn-2";
    const secondFirstRes = await postExec(
      signExecutionRequestHmac(makeEnv({ action: "DISPATCH_FIRST_MESSAGE", delivery_id: "deliv-f2-bad-first" }), EXEC_SECRET, EXEC_KEY_ID),
    );
    assert.equal(secondFirstRes.status, 409);
    assert.equal(browserState.submissions.length, 1);

    // 6. Advance token clock past refresh margin -> broker issues renewed short-lived token -> Turn 2 DISPATCH_CONTINUATION
    tokenClockMs += 70_000;
    const t2Res = await postExec(
      signExecutionRequestHmac(makeEnv({ action: "DISPATCH_CONTINUATION", delivery_id: "deliv-f2-t2" }), EXEC_SECRET, EXEC_KEY_ID),
    );
    assert.equal(t2Res.status, 200);
    const t2Body = await t2Res.json();
    assert.equal(t2Body.status, "CONFIRMED_CONTINUATION");
    assert.equal(t2Body.turnNumber, 2);
    assert.equal(t2Body.conversationId, "conv-f2-e2e-01");
    assert.equal(browserState.submissions.length, 2);
    assert.equal(browserState.submissions[1].beforeUrl, "https://chatgpt.com/c/conv-f2-e2e-01");
    assert.equal(browserState.submissions[1].afterUrl, "https://chatgpt.com/c/conv-f2-e2e-01");
    assert.equal(broker.issueCalls, 2);
    assert.ok(refs.has(`refs/bke/turns/${PR_NUMBER}/attempt-f2-turn-1`));
    assert.ok(refs.has(`refs/bke/turns/${PR_NUMBER}/attempt-f2-turn-2`));

    // 7. Mandatory negative HTTP matrix on POST /execution-requests
    currentAttempt = "attempt-f2-turn-3";
    const validForNeg = makeEnv({ action: "DISPATCH_CONTINUATION", delivery_id: "deliv-f2-neg-base" });
    const { attempt_id: _missingAttempt, ...missingFieldEnv } = validForNeg;
    const negMatrix = [
      ["invalid signature", { ...signExecutionRequestHmac(validForNeg, EXEC_SECRET, EXEC_KEY_ID), signature_hex: "0".repeat(64) }, 401],
      ["wrong key_id", signExecutionRequestHmac(validForNeg, EXEC_SECRET, "unknown-kid"), 401],
      ["invalid protocol_version", { ...signExecutionRequestHmac(validForNeg, EXEC_SECRET, EXEC_KEY_ID), envelope: { ...validForNeg, protocol_version: 9 } }, 400],
      ["missing field", { ...signExecutionRequestHmac(validForNeg, EXEC_SECRET, EXEC_KEY_ID), envelope: missingFieldEnv }, 400],
      ["extra field", { ...signExecutionRequestHmac(validForNeg, EXEC_SECRET, EXEC_KEY_ID), envelope: { ...validForNeg, admin: true } }, 400],
      ["wrong installation", signExecutionRequestHmac(makeEnv({ installation_identity: "111", action: "DISPATCH_CONTINUATION", delivery_id: "deliv-neg-inst" }), EXEC_SECRET, EXEC_KEY_ID), 403],
      ["wrong repository_id", signExecutionRequestHmac(makeEnv({ repository_id: 999, action: "DISPATCH_CONTINUATION", delivery_id: "deliv-neg-repo" }), EXEC_SECRET, EXEC_KEY_ID), 403],
      ["wrong worker_id", signExecutionRequestHmac(makeEnv({ worker_id: "other-w", action: "DISPATCH_CONTINUATION", delivery_id: "deliv-neg-w" }), EXEC_SECRET, EXEC_KEY_ID), 403],
      ["wrong pr_number", signExecutionRequestHmac(makeEnv({ pr_number: 999, action: "DISPATCH_CONTINUATION", delivery_id: "deliv-neg-pr" }), EXEC_SECRET, EXEC_KEY_ID), 409],
      ["stale head_sha", signExecutionRequestHmac(makeEnv({ head_sha: "e".repeat(40), action: "DISPATCH_CONTINUATION", delivery_id: "deliv-neg-head" }), EXEC_SECRET, EXEC_KEY_ID), 409],
      ["expired request", signExecutionRequestHmac(makeEnv({ issued_at: new Date(Date.now() - 120_000).toISOString(), expires_at: new Date(Date.now() - 1_000).toISOString(), action: "DISPATCH_CONTINUATION", delivery_id: "deliv-neg-exp" }), EXEC_SECRET, EXEC_KEY_ID), 409],
      ["unauthorized remote HALT with dispatch key", signExecutionRequestHmac(makeEnv({ action: "HALT", delivery_id: "deliv-neg-halt" }), EXEC_SECRET, EXEC_KEY_ID), 401],
    ];
    for (const [label, payload, expectedStatus] of negMatrix) {
      const r = await postExec(payload);
      assert.equal(r.status, expectedStatus, label);
      assert.equal(browserState.submissions.length, 2, `${label} must not trigger submit`);
    }

    // 8. Expired / revoked broker token MUST reject before any Turn 3 submit
    broker.behavior = { forceExpiresAtMs: tokenClockMs - 10 };
    tokenLifecycle.invalidate("simulate_expired_broker");
    const expiredTokRes = await postExec(
      signExecutionRequestHmac(makeEnv({ action: "DISPATCH_CONTINUATION", delivery_id: "deliv-f2-exp-tok" }), EXEC_SECRET, EXEC_KEY_ID),
    );
    assert.equal(expiredTokRes.status, 409);
    assert.equal(browserState.submissions.length, 2);

    broker.behavior = { revokedAfterIssueCount: 1 };
    tokenLifecycle.invalidate("simulate_revoked_broker");
    const firstTok = await tokenLifecycle.getToken();
    broker.revokeToken(firstTok);
    const revokedTokRes = await postExec(
      signExecutionRequestHmac(makeEnv({ action: "DISPATCH_CONTINUATION", delivery_id: "deliv-f2-rev-tok" }), EXEC_SECRET, EXEC_KEY_ID),
    );
    assert.equal(revokedTokRes.status, 409);
    assert.equal(browserState.submissions.length, 2);

    // 9. Ambiguous/uncertain GitHub ref present MUST fail closed before any Turn 3 submit
    broker.behavior = {};
    const validTok = await tokenLifecycle.getToken({ forceRefresh: true });
    assert.ok(validTok.startsWith("ghs_"));
    refs.set(`refs/bke/uncertain/${PR_NUMBER}/attempt-old-uncertain`, HEAD);
    const uncRefRes = await postExec(
      signExecutionRequestHmac(makeEnv({ action: "DISPATCH_CONTINUATION", delivery_id: "deliv-f2-unc-ref" }), EXEC_SECRET, EXEC_KEY_ID),
    );
    assert.equal(uncRefRes.status, 409);
    assert.equal(browserState.submissions.length, 2);
    refs.delete(`refs/bke/uncertain/${PR_NUMBER}/attempt-old-uncertain`);

    // 10. Restart DesktopControllerDaemon on same FileExecutionJournal -> replay of Turn 1 delivery & attempt MUST reject (409)
    await daemon.stop();
    const daemon2 = new DesktopControllerDaemon(
      {
        repository: REPO,
        prNumber: PR_NUMBER,
        workerId: WORKER,
        pinnedApp: PINNED_APP,
        executionId: "exec-f2-e2e-restarted",
        targetId: "target-f2-01",
        profileId: "profile-f2-01",
        targetTabId: 19,
        journalPath,
        ipcSocketPath: sockPath,
        webhookSecret: WEBHOOK_SECRET_LOCAL,
        operatorHaltToken: HALT_TOKEN,
        executionEnvelopeEnabled: true,
        expectedRepositoryId: REPO_ID,
        expectedInstallationId: INSTALL_ID,
        executionSigningKeysById: new Map([[EXEC_KEY_ID, EXEC_SECRET]]),
        remoteHaltSigningKeysById: new Map([[HALT_KEY_ID, HALT_SECRET]]),
        allowRemoteSignedHalt: true,
        githubApiBaseUrl: ghBaseUrl,
        listenHost: "127.0.0.1",
        listenPort: 0,
        humanLiveSendAuthorized: true,
        liveProofs: {
          githubCasOwnerCertified: true,
          nativePairingOwnerCertified: true,
          realBrowserOwnerAccepted: true,
        },
      },
      {
        tokenProvider: tokenLifecycle.asTokenProvider(),
        tokenLifecycle,
        fetchImpl: (url, init) => {
          const target = url.replace("https://api.github.com", ghBaseUrl);
          return globalThis.fetch(target, init).then((r) => ({ status: r.status, headers: r.headers, json: () => r.json() }));
        },
        ipcClient: new IpcBridgeClient({ socketPath: sockPath }),
        nowIso,
        nowMs: () => Date.now(),
      },
    );

    try {
      const { port: port2 } = await daemon2.start();
      const postExec2 = async (signedReq) =>
        globalThis.fetch(`http://127.0.0.1:${port2}/execution-requests`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(signedReq),
        });

      assert.equal((await postExec2(t1Signed)).status, 409, "restarted daemon must reject replayed delivery");
      const replayAttemptAfterRestart = signExecutionRequestHmac(
        makeEnv({ attempt_id: "attempt-f2-turn-1", action: "DISPATCH_FIRST_MESSAGE", delivery_id: "deliv-f2-t1-restart-dup" }),
        EXEC_SECRET,
        EXEC_KEY_ID,
      );
      assert.equal((await postExec2(replayAttemptAfterRestart)).status, 409, "restarted daemon must reject consumed attempt");
      assert.equal(browserState.submissions.length, 2);

      // 11. Cross-conversation continuation drift MUST quarantine journal and block future dispatches
      browserState.driftTurn2 = true;
      currentAttempt = "attempt-f2-turn-3";
      const driftRes = await postExec2(
        signExecutionRequestHmac(makeEnv({ action: "DISPATCH_CONTINUATION", delivery_id: "deliv-f2-drift" }), EXEC_SECRET, EXEC_KEY_ID),
      );
      assert.equal(driftRes.status, 409);
      const driftDisk = JSON.parse(await readFile(journalPath, "utf8"));
      assert.equal(driftDisk.phase, "DELIVERY_UNCERTAIN");
      assert.ok(refs.has(`refs/bke/uncertain/${PR_NUMBER}/attempt-f2-turn-3`));

      currentAttempt = "attempt-f2-turn-4";
      const afterDriftBlocked = await postExec2(
        signExecutionRequestHmac(makeEnv({ action: "DISPATCH_CONTINUATION", delivery_id: "deliv-f2-after-drift" }), EXEC_SECRET, EXEC_KEY_ID),
      );
      assert.equal(afterDriftBlocked.status, 409);
      assert.equal(browserState.submissions.length, 3); // drift happened on Turn 3 attempt once, 0 on Turn 4

      // 12. Authorized remote signed HALT cleanly halts daemon & journal even when quarantined
      const haltRes = await postExec2(
        signExecutionRequestHmac(makeEnv({ action: "HALT", delivery_id: "deliv-f2-halt-ok" }), HALT_SECRET, HALT_KEY_ID),
      );
      assert.equal(haltRes.status, 200);
      const disk = JSON.parse(await readFile(journalPath, "utf8"));
      assert.equal(disk.phase, "HALTED");
    } finally {
      await daemon2.stop();
    }
  } finally {
    await daemon.stop();
    bridgeConn.session.close();
    if (child && child.exitCode === null) child.kill("SIGTERM");
    await ghServer.close();
    await rm(dir, { recursive: true, force: true });
  }
});
