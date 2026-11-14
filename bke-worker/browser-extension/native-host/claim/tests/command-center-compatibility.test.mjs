/**
 * Workstream D: Command Center Compatibility & Fail-Closed Observer Fixture Suite.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  COMMAND_CENTER_COMPATIBILITY_MATRIX,
  F2_REQUIRED_VISIBLE_STATES,
  projectWorkerStateForCommandCenter,
} from '../dist/native-host/claim/command-center-observer.js';

const NOW = Date.parse('2026-10-20T12:00:00.000Z');
const HEAD = 'a'.repeat(40);
const STALE_HEAD = 'b'.repeat(40);

function baseEvidence(overrides = {}) {
  return {
    observedAtMs: NOW - 1_000,
    nowMs: NOW,
    maxStaleMs: 60_000,
    githubAssignment: {
      repository: 'jan2xo/bke-worker',
      prNumber: 149,
      workerId: 'worker-f1',
      headSha: HEAD,
      openPrCountForWorker: 1,
      workerLabelsOnPr: 1,
      atomicRevalidated: true,
      uncertainRefCount: 0,
    },
    journal: {
      phase: 'IDLE',
      conversationId: null,
      confirmedTurnCount: 0,
      uncertainReason: null,
    },
    pairing: {
      policyMatched: true,
      activeBridgeSession: true,
      bridgeQuarantined: false,
    },
    browser: {
      uiState: 'NEW_CHAT_LANDING',
      composerAvailable: true,
      matchingWritableTargetCount: 1,
      observedAtMs: NOW - 500,
    },
    certification: {
      sourceTestsPassed: true,
      syntheticE2ePassed: true,
      realBrowserAccepted: false,
    },
    ...overrides,
  };
}

test('Command Center matrix covers all 9 canonical worker-observer concepts', () => {
  assert.equal(COMMAND_CENTER_COMPATIBILITY_MATRIX.length, 9);
  assert.ok(COMMAND_CENTER_COMPATIBILITY_MATRIX.some((r) => r.integrationStatus === 'CONSUMED_BY_COMMAND_CENTER_TODAY'));
  assert.ok(COMMAND_CENTER_COMPATIBILITY_MATRIX.some((r) => r.integrationStatus === 'PROPOSED_OBSERVER_ADAPTER'));
});

test('Workstream D: 8 fail-closed observer scenarios never forge readiness or PASS from partial/stale/uncertain evidence', () => {
  // 1. Missing GitHub evidence -> UNKNOWN & not ready
  const s1 = projectWorkerStateForCommandCenter(baseEvidence({ githubAssignment: undefined }));
  assert.equal(s1.assignmentState, 'UNKNOWN');
  assert.equal(s1.dispatchReady, false);

  // 2. Non-atomic snapshot inventory -> marked NON_ATOMIC_STALE_SNAPSHOT & dispatchReady=false
  const s2 = projectWorkerStateForCommandCenter(
    baseEvidence({
      githubAssignment: {
        repository: 'jan2xo/bke-worker', prNumber: 149, workerId: 'worker-f1', headSha: HEAD,
        openPrCountForWorker: 1, workerLabelsOnPr: 1, atomicRevalidated: false, uncertainRefCount: 0,
      },
    }),
  );
  assert.equal(s2.inventoryConsistency, 'NON_ATOMIC_STALE_SNAPSHOT');
  assert.equal(s2.dispatchReady, false);

  // 3. Pairing without active controller bridge -> PAIRED_IDLE_ONLY & not ready
  const s3 = projectWorkerStateForCommandCenter(
    baseEvidence({ pairing: { policyMatched: true, activeBridgeSession: false, bridgeQuarantined: false } }),
  );
  assert.equal(s3.pairingState, 'PAIRED_IDLE_ONLY');
  assert.equal(s3.dispatchReady, false);

  // 4. Native proof without ChatGPT auth (AUTH_REQUIRED) -> AUTH_REQUIRED & not ready
  const s4 = projectWorkerStateForCommandCenter(
    baseEvidence({ browser: { uiState: 'AUTH_REQUIRED', composerAvailable: false, matchingWritableTargetCount: 1, observedAtMs: NOW - 500 } }),
  );
  assert.equal(s4.chatgptAuthState, 'AUTH_REQUIRED');
  assert.equal(s4.dispatchReady, false);

  // 5. Journal DELIVERY_UNCERTAIN -> DELIVERY_UNCERTAIN_BLOCKED & not ready
  const s5 = projectWorkerStateForCommandCenter(
    baseEvidence({ journal: { phase: 'DELIVERY_UNCERTAIN', conversationId: null, confirmedTurnCount: 0, uncertainReason: 'CRASH_DURING_DISPATCHING' } }),
  );
  assert.equal(s5.executionState, 'DELIVERY_UNCERTAIN_BLOCKED');
  assert.equal(s5.dispatchReady, false);

  // 6. Conflicting PR labels / multiple open PRs -> CONFLICT_BLOCKED & not ready
  const s6 = projectWorkerStateForCommandCenter(
    baseEvidence({
      githubAssignment: {
        repository: 'jan2xo/bke-worker', prNumber: 149, workerId: 'worker-f1', headSha: HEAD,
        openPrCountForWorker: 2, workerLabelsOnPr: 1, atomicRevalidated: true, uncertainRefCount: 0,
      },
    }),
  );
  assert.equal(s6.assignmentState, 'CONFLICT_BLOCKED');
  assert.equal(s6.executionState, 'CONFLICT_BLOCKED');
  assert.equal(s6.dispatchReady, false);

  // 7. CI/synthetic passing without real browser acceptance -> realBrowserAcceptance remains NOT_RUN
  const s7 = projectWorkerStateForCommandCenter(baseEvidence());
  assert.equal(s7.dispatchReady, true);
  assert.equal(s7.realBrowserAcceptance, 'NOT_RUN');
  assert.ok(s7.blockingReasons.includes('REAL_BROWSER_ACCEPTANCE_NOT_RUN'));

  // 8. Stale timestamps -> UNKNOWN & not ready
  const s8 = projectWorkerStateForCommandCenter(baseEvidence({ observedAtMs: NOW - 300_000 }));
  assert.equal(s8.assignmentState, 'UNKNOWN');
  assert.equal(s8.pairingState, 'UNKNOWN');
  assert.equal(s8.executionState, 'UNKNOWN');
  assert.equal(s8.dispatchReady, false);
});

test('F2-06: Covers all 14 required visible states and fail-closed token/pairing/browser/synthetic separation', () => {
  assert.equal(F2_REQUIRED_VISIBLE_STATES.length, 14);
  const observedTags = new Set();

  const collect = (ev) => {
    const p = projectWorkerStateForCommandCenter(ev);
    for (const tag of p.visibleStates) observedTags.add(tag);
    return p;
  };

  // Valid exact-SHA + verified identity + valid assignment
  const ready = collect(baseEvidence({ expectedHeadSha: HEAD, exactHeadCi: { status: 'PASS' }, tokenLifecycle: { valid: true, brokerConnected: false } }));
  assert.equal(ready.identityState, 'VERIFIED');
  assert.equal(ready.shaState, 'CURRENT_EXACT');
  assert.equal(ready.workerLiveness, 'ALIVE');

  // Stale SHA + exact-head CI pending + claim reserved
  const stale = collect(baseEvidence({
    expectedHeadSha: STALE_HEAD,
    exactHeadCi: { status: 'PENDING' },
    journal: { phase: 'RESERVED', conversationId: null, confirmedTurnCount: 0, uncertainReason: null },
  }));
  assert.equal(stale.shaState, 'STALE');
  assert.equal(stale.claimState, 'RESERVED');
  assert.equal(stale.dispatchReady, false);

  // Valid token does NOT prove ChatGPT auth or browser connectivity
  const tokNoBrowser = collect(baseEvidence({
    tokenLifecycle: { valid: true, brokerConnected: true },
    pairing: undefined,
    browser: undefined,
  }));
  assert.equal(tokNoBrowser.identityState, 'UNKNOWN');
  assert.equal(tokNoBrowser.chatgptAuthState, 'UNKNOWN');
  assert.equal(tokNoBrowser.evidenceIncomplete, true);
  assert.equal(tokNoBrowser.workerLiveness, 'UNKNOWN');
  assert.equal(tokNoBrowser.dispatchReady, false);

  // Ownership conflict & delivery uncertain & paired idle
  collect(baseEvidence({
    githubAssignment: {
      repository: 'jan2xo/bke-worker', prNumber: 149, workerId: 'worker-f1', headSha: HEAD,
      openPrCountForWorker: 2, workerLabelsOnPr: 1, atomicRevalidated: true, uncertainRefCount: 0,
    },
    pairing: { policyMatched: true, activeBridgeSession: false, bridgeQuarantined: false },
  }));
  collect(baseEvidence({
    journal: { phase: 'DELIVERY_UNCERTAIN', conversationId: null, confirmedTurnCount: 0, uncertainReason: 'CRASH_DURING_DISPATCHING' },
  }));

  // First conversation confirmed & continuation confirmed
  collect(baseEvidence({ journal: { phase: 'CONFIRMED_CONVERSATION', conversationId: 'conv-1', confirmedTurnCount: 1, uncertainReason: null } }));
  const turn2 = collect(baseEvidence({ journal: { phase: 'CONFIRMED_CONVERSATION', conversationId: 'conv-1', confirmedTurnCount: 2, uncertainReason: null } }));
  assert.equal(turn2.confirmedTurnCount, 2);
  assert.equal(turn2.realBrowserAcceptance, 'NOT_RUN');

  for (const required of F2_REQUIRED_VISIBLE_STATES) {
    assert.ok(observedTags.has(required), `Missing F2 visible state tag: ${required}`);
  }
});
