/**
 * Workstream D: Read-Only BKE Command Center Compatibility & Observer Projection.
 *
 * Documents and validates the 9 evidence categories shared between BKE Worker,
 * GitHub durable authority, Cloudflare admin broker, and Command Center.
 *
 * Enforces fail-closed observability: missing, partial, stale, or uncertain
 * evidence NEVER upgrades to PAID/ACTIVE/AUTHENTICATED/DISPATCH_READY/PASS.
 */
import type { JournalPhase } from './desktop-controller.js';

export type ObserverConsumptionStatus =
  | 'CONSUMED_BY_COMMAND_CENTER_TODAY'
  | 'PROPOSED_OBSERVER_ADAPTER';

export interface CommandCenterMappingRow {
  id: string;
  concept: string;
  workerSourceOfTruth: string;
  commandCenterConsumer: string;
  integrationStatus: ObserverConsumptionStatus;
}

export const COMMAND_CENTER_COMPATIBILITY_MATRIX: readonly CommandCenterMappingRow[] = [
  {
    id: 'installed_repos',
    concept: 'Installed repositories',
    workerSourceOfTruth: 'GitHub App installation token lookup (admin-broker catalog)',
    commandCenterConsumer: 'cloudflare-relay admin_installation_repository_catalog + CC /api/admin/repositories',
    integrationStatus: 'CONSUMED_BY_COMMAND_CENTER_TODAY',
  },
  {
    id: 'worker_pr_assignment',
    concept: 'Worker-to-PR assignment',
    workerSourceOfTruth: 'GitHub live PRs + exclusive `bke-worker:<id>` label (revalidated per wake)',
    commandCenterConsumer: 'cloudflare-relay admin_worker_assignment_inventory + CC admin-worker-assignments.js',
    integrationStatus: 'CONSUMED_BY_COMMAND_CENTER_TODAY',
  },
  {
    id: 'exact_pr_head',
    concept: 'Exact PR head SHA',
    workerSourceOfTruth: 'GitHub live PR head.sha + pinned bke-ticket external_id',
    commandCenterConsumer: 'CC admin-worker-assignments.js (non-atomic snapshot) / live PR read',
    integrationStatus: 'CONSUMED_BY_COMMAND_CENTER_TODAY',
  },
  {
    id: 'device_pairing_vs_session',
    concept: 'Device pairing vs active session',
    workerSourceOfTruth: 'P-256 non-exportable key + owner-pinned policy vs live CONTROLLER_BRIDGE_V1 session',
    commandCenterConsumer: 'PROPOSED_OBSERVER_ADAPTER (controller status projection distinguishes PAIRED_IDLE_ONLY vs BRIDGE_ESTABLISHED)',
    integrationStatus: 'PROPOSED_OBSERVER_ADAPTER',
  },
  {
    id: 'chatgpt_auth_and_tab_readiness',
    concept: 'ChatGPT auth/tab readiness',
    workerSourceOfTruth: 'MV3 content-script snapshot + webNavigation frame binding (AUTH_REQUIRED vs READY)',
    commandCenterConsumer: 'PROPOSED_OBSERVER_ADAPTER (projected as UNKNOWN/AUTH_REQUIRED unless freshly observed)',
    integrationStatus: 'PROPOSED_OBSERVER_ADAPTER',
  },
  {
    id: 'send_once_claim_quarantine',
    concept: 'Send-once claim / uncertainty quarantine',
    workerSourceOfTruth: 'GitHub refs/bke/claims/{pr}/{attempt} + refs/bke/uncertain/{pr}/{attempt} + FileExecutionJournal',
    commandCenterConsumer: 'PROPOSED_OBSERVER_ADAPTER (maps DELIVERY_UNCERTAIN to operator quarantine alert)',
    integrationStatus: 'PROPOSED_OBSERVER_ADAPTER',
  },
  {
    id: 'turn_and_conversation_progress',
    concept: 'Turn 1 / Turn 2+ conversation progress',
    workerSourceOfTruth: 'GitHub refs/bke/conversations/{pr} + refs/bke/turns/{pr}/{attempt}',
    commandCenterConsumer: 'PROPOSED_OBSERVER_ADAPTER (exposes conversationId + confirmedTurnCount read-only)',
    integrationStatus: 'PROPOSED_OBSERVER_ADAPTER',
  },
  {
    id: 'operator_alerts_halt_remediation',
    concept: 'Operator alerts / halt / remediation state',
    workerSourceOfTruth: 'Controller /status, journal HALTED phase, PR audit comments',
    commandCenterConsumer: 'CC dashboard/failure-visibility patterns + PROPOSED_OBSERVER_ADAPTER',
    integrationStatus: 'PROPOSED_OBSERVER_ADAPTER',
  },
  {
    id: 'certification_and_live_acceptance',
    concept: 'Certification vs live acceptance state',
    workerSourceOfTruth: 'Source/native smoke reports vs explicit BKE_REAL_CHROME_ACCEPTANCE=NOT_RUN gate',
    commandCenterConsumer: 'PROPOSED_OBSERVER_ADAPTER (keeps synthetic PASS distinct from real browser NOT_RUN)',
    integrationStatus: 'PROPOSED_OBSERVER_ADAPTER',
  },
] as const;

export const F2_REQUIRED_VISIBLE_STATES = [
  'WORKER_IDENTITY_VERIFIED',
  'WORKER_IDENTITY_UNKNOWN',
  'PR_ASSIGNMENT_VALID',
  'PR_OWNERSHIP_CONFLICT',
  'CURRENT_EXACT_SHA',
  'STALE_SHA',
  'CLAIM_RESERVED',
  'EXECUTION_BLOCKED',
  'DELIVERY_UNCERTAIN',
  'FIRST_CONVERSATION_CONFIRMED',
  'CONTINUATION_CONFIRMED',
  'EXACT_HEAD_CI_PENDING_OR_FAILED',
  'EVIDENCE_INCOMPLETE',
  'WORKER_LIVENESS_UNKNOWN',
] as const;

export type F2VisibleStateTag = (typeof F2_REQUIRED_VISIBLE_STATES)[number];

export interface RawWorkerObserverEvidence {
  observedAtMs: number;
  nowMs: number;
  maxStaleMs?: number;
  expectedHeadSha?: string;
  claimReserved?: boolean;
  githubAssignment?: {
    repository: string;
    prNumber: number;
    workerId: string;
    headSha: string;
    openPrCountForWorker: number;
    workerLabelsOnPr: number;
    atomicRevalidated: boolean;
    uncertainRefCount: number;
  };
  exactHeadCi?: {
    status: 'PASS' | 'PENDING' | 'FAILED' | 'UNKNOWN';
  };
  tokenLifecycle?: {
    valid: boolean;
    brokerConnected: boolean;
    expired?: boolean;
    revoked?: boolean;
  };
  workerHeartbeat?: {
    fresh: boolean;
  };
  journal?: {
    phase: JournalPhase;
    conversationId: string | null;
    confirmedTurnCount: number;
    uncertainReason: string | null;
  };
  pairing?: {
    policyMatched: boolean;
    activeBridgeSession: boolean;
    bridgeQuarantined: boolean;
  };
  browser?: {
    uiState: 'NEW_CHAT_LANDING' | 'THREAD' | 'BUSY' | 'AUTH_REQUIRED' | 'UNKNOWN';
    composerAvailable: boolean;
    matchingWritableTargetCount: number;
    observedAtMs: number;
  };
  certification?: {
    sourceTestsPassed: boolean;
    syntheticE2ePassed: boolean;
    realBrowserAccepted: boolean;
  };
}

export interface CommandCenterWorkerProjection {
  schemaVersion: 1;
  identityState: 'VERIFIED' | 'UNKNOWN';
  assignmentState: 'UNKNOWN' | 'ASSIGNED_EXCLUSIVE' | 'CONFLICT_BLOCKED';
  inventoryConsistency: 'ATOMIC_REVALIDATED' | 'NON_ATOMIC_STALE_SNAPSHOT' | 'UNKNOWN';
  shaState: 'CURRENT_EXACT' | 'STALE' | 'UNKNOWN';
  claimState: 'NONE' | 'RESERVED' | 'UNKNOWN';
  exactHeadCiState: 'PASS' | 'PENDING' | 'FAILED' | 'UNKNOWN';
  pairingState: 'UNKNOWN' | 'PAIRED_IDLE_ONLY' | 'BRIDGE_ESTABLISHED' | 'QUARANTINED';
  workerLiveness: 'ALIVE' | 'IDLE_PAIRED' | 'HALTED' | 'UNKNOWN';
  chatgptAuthState: 'UNKNOWN' | 'AUTH_REQUIRED' | 'READY' | 'BUSY' | 'AMBIGUOUS_TABS';
  dispatchReady: boolean;
  evidenceIncomplete: boolean;
  executionState:
    | 'UNKNOWN'
    | 'IDLE_BLOCKED'
    | 'READY_SUPERVISED'
    | 'CONFIRMED_CONVERSATION'
    | 'DELIVERY_UNCERTAIN_BLOCKED'
    | 'HALTED_BLOCKED'
    | 'CONFLICT_BLOCKED';
  conversationId: string | null;
  confirmedTurnCount: number;
  realBrowserAcceptance: 'NOT_RUN' | 'OWNER_ACCEPTED';
  visibleStates: F2VisibleStateTag[];
  blockingReasons: string[];
}

export function projectWorkerStateForCommandCenter(
  ev: RawWorkerObserverEvidence,
): CommandCenterWorkerProjection {
  const maxStaleMs = ev.maxStaleMs ?? 60_000;
  const reasons: string[] = [];
  const visibleStates = new Set<F2VisibleStateTag>();
  const staleTop = !Number.isFinite(ev.observedAtMs) || !Number.isFinite(ev.nowMs) || ev.nowMs - ev.observedAtMs > maxStaleMs;
  if (staleTop) {
    reasons.push('EVIDENCE_STALE_OR_CLOCK_INVALID');
  }

  let assignmentState: CommandCenterWorkerProjection['assignmentState'] = 'UNKNOWN';
  let inventoryConsistency: CommandCenterWorkerProjection['inventoryConsistency'] = 'UNKNOWN';
  let shaState: CommandCenterWorkerProjection['shaState'] = 'UNKNOWN';
  if (!staleTop && ev.githubAssignment) {
    const g = ev.githubAssignment;
    inventoryConsistency = g.atomicRevalidated ? 'ATOMIC_REVALIDATED' : 'NON_ATOMIC_STALE_SNAPSHOT';
    if (!g.atomicRevalidated) {
      reasons.push('NON_ATOMIC_SNAPSHOT_REQUIRES_REVALIDATION');
    }
    if (g.uncertainRefCount > 0) {
      assignmentState = 'CONFLICT_BLOCKED';
      reasons.push('GITHUB_UNCERTAIN_REF_PRESENT');
    } else if (g.openPrCountForWorker !== 1 || g.workerLabelsOnPr !== 1) {
      assignmentState = 'CONFLICT_BLOCKED';
      reasons.push('GITHUB_WORKER_EXCLUSIVITY_VIOLATED');
      visibleStates.add('PR_OWNERSHIP_CONFLICT');
    } else {
      assignmentState = 'ASSIGNED_EXCLUSIVE';
      visibleStates.add('PR_ASSIGNMENT_VALID');
    }

    if (ev.expectedHeadSha) {
      if (g.headSha === ev.expectedHeadSha) {
        shaState = 'CURRENT_EXACT';
        visibleStates.add('CURRENT_EXACT_SHA');
      } else {
        shaState = 'STALE';
        visibleStates.add('STALE_SHA');
        reasons.push('GITHUB_HEAD_SHA_STALE');
      }
    } else {
      shaState = 'CURRENT_EXACT';
      visibleStates.add('CURRENT_EXACT_SHA');
    }
  } else {
    reasons.push('GITHUB_ASSIGNMENT_EVIDENCE_MISSING');
  }

  let pairingState: CommandCenterWorkerProjection['pairingState'] = 'UNKNOWN';
  let identityState: CommandCenterWorkerProjection['identityState'] = 'UNKNOWN';
  if (!staleTop && ev.pairing) {
    if (ev.pairing.bridgeQuarantined) {
      pairingState = 'QUARANTINED';
      identityState = ev.pairing.policyMatched ? 'VERIFIED' : 'UNKNOWN';
      reasons.push('NATIVE_BRIDGE_QUARANTINED');
    } else if (ev.pairing.policyMatched && ev.pairing.activeBridgeSession) {
      pairingState = 'BRIDGE_ESTABLISHED';
      identityState = 'VERIFIED';
    } else if (ev.pairing.policyMatched) {
      pairingState = 'PAIRED_IDLE_ONLY';
      identityState = 'VERIFIED';
      reasons.push('PAIRING_WITHOUT_ACTIVE_SESSION');
    } else {
      pairingState = 'UNKNOWN';
      identityState = 'UNKNOWN';
      reasons.push('NATIVE_POLICY_UNVERIFIED');
    }
  } else {
    reasons.push('PAIRING_EVIDENCE_MISSING');
  }
  visibleStates.add(identityState === 'VERIFIED' ? 'WORKER_IDENTITY_VERIFIED' : 'WORKER_IDENTITY_UNKNOWN');

  let chatgptAuthState: CommandCenterWorkerProjection['chatgptAuthState'] = 'UNKNOWN';
  if (!staleTop && ev.browser) {
    const bStale = ev.nowMs - ev.browser.observedAtMs > maxStaleMs;
    if (bStale) {
      chatgptAuthState = 'UNKNOWN';
      reasons.push('BROWSER_OBSERVATION_STALE');
    } else if (ev.browser.uiState === 'AUTH_REQUIRED') {
      chatgptAuthState = 'AUTH_REQUIRED';
      reasons.push('CHATGPT_AUTH_REQUIRED');
    } else if (ev.browser.matchingWritableTargetCount !== 1) {
      chatgptAuthState = 'AMBIGUOUS_TABS';
      reasons.push('CHATGPT_TAB_COUNT_INVALID');
    } else if (ev.browser.uiState === 'BUSY') {
      chatgptAuthState = 'BUSY';
      reasons.push('CHATGPT_TURN_BUSY');
    } else if (ev.browser.composerAvailable && (ev.browser.uiState === 'NEW_CHAT_LANDING' || ev.browser.uiState === 'THREAD')) {
      chatgptAuthState = 'READY';
    } else {
      chatgptAuthState = 'UNKNOWN';
      reasons.push('CHATGPT_COMPOSER_UNAVAILABLE');
    }
  } else {
    reasons.push('BROWSER_EVIDENCE_MISSING');
  }

  const exactHeadCiState: CommandCenterWorkerProjection['exactHeadCiState'] =
    staleTop || !ev.exactHeadCi ? 'UNKNOWN' : ev.exactHeadCi.status;
  if (exactHeadCiState === 'PENDING' || exactHeadCiState === 'FAILED') {
    visibleStates.add('EXACT_HEAD_CI_PENDING_OR_FAILED');
    reasons.push(`EXACT_HEAD_CI_${exactHeadCiState}`);
  }

  const journalPhase = ev.journal?.phase ?? null;
  const claimReserved = Boolean(!staleTop && (ev.claimReserved || journalPhase === 'RESERVED' || journalPhase === 'FENCED'));
  const claimState: CommandCenterWorkerProjection['claimState'] =
    staleTop || !ev.journal ? 'UNKNOWN' : claimReserved ? 'RESERVED' : 'NONE';
  if (claimState === 'RESERVED') {
    visibleStates.add('CLAIM_RESERVED');
  }

  if (!staleTop && ev.tokenLifecycle && !ev.tokenLifecycle.valid) {
    reasons.push(ev.tokenLifecycle.revoked ? 'TOKEN_REVOKED' : ev.tokenLifecycle.expired ? 'TOKEN_EXPIRED' : 'TOKEN_UNAVAILABLE');
  }

  let workerLiveness: CommandCenterWorkerProjection['workerLiveness'] = 'UNKNOWN';
  if (!staleTop && ev.journal && journalPhase === 'HALTED') {
    workerLiveness = 'HALTED';
  } else if (!staleTop && pairingState === 'BRIDGE_ESTABLISHED' && (ev.workerHeartbeat ? ev.workerHeartbeat.fresh : true)) {
    workerLiveness = 'ALIVE';
  } else if (!staleTop && pairingState === 'PAIRED_IDLE_ONLY') {
    workerLiveness = 'IDLE_PAIRED';
    visibleStates.add('WORKER_LIVENESS_UNKNOWN');
    reasons.push('INACTIVE_PAIRED_WORKER_NOT_RUNNING');
  } else {
    workerLiveness = 'UNKNOWN';
    visibleStates.add('WORKER_LIVENESS_UNKNOWN');
  }

  let executionState: CommandCenterWorkerProjection['executionState'] = 'UNKNOWN';
  if (staleTop || !ev.journal) {
    executionState = 'UNKNOWN';
  } else if (journalPhase === 'DELIVERY_UNCERTAIN' || (ev.githubAssignment?.uncertainRefCount ?? 0) > 0) {
    executionState = 'DELIVERY_UNCERTAIN_BLOCKED';
    visibleStates.add('DELIVERY_UNCERTAIN');
    visibleStates.add('EXECUTION_BLOCKED');
    reasons.push(ev.journal.uncertainReason ?? 'DELIVERY_UNCERTAIN');
  } else if (journalPhase === 'HALTED') {
    executionState = 'HALTED_BLOCKED';
    visibleStates.add('EXECUTION_BLOCKED');
    reasons.push(ev.journal.uncertainReason ?? 'CONTROLLER_HALTED');
  } else if (assignmentState === 'CONFLICT_BLOCKED' || shaState === 'STALE') {
    executionState = 'CONFLICT_BLOCKED';
    visibleStates.add('EXECUTION_BLOCKED');
  } else if (journalPhase === 'CONFIRMED_CONVERSATION') {
    executionState = 'CONFIRMED_CONVERSATION';
    if (ev.journal.confirmedTurnCount === 1) {
      visibleStates.add('FIRST_CONVERSATION_CONFIRMED');
    } else if (ev.journal.confirmedTurnCount >= 2) {
      visibleStates.add('FIRST_CONVERSATION_CONFIRMED');
      visibleStates.add('CONTINUATION_CONFIRMED');
    }
  } else if (
    assignmentState === 'ASSIGNED_EXCLUSIVE' &&
    inventoryConsistency === 'ATOMIC_REVALIDATED' &&
    shaState === 'CURRENT_EXACT' &&
    pairingState === 'BRIDGE_ESTABLISHED' &&
    chatgptAuthState === 'READY' &&
    (ev.exactHeadCi ? ev.exactHeadCi.status === 'PASS' : true) &&
    (ev.tokenLifecycle ? ev.tokenLifecycle.valid : true)
  ) {
    executionState = 'READY_SUPERVISED';
  } else {
    executionState = 'IDLE_BLOCKED';
    visibleStates.add('EXECUTION_BLOCKED');
  }

  const evidenceIncomplete =
    staleTop || !ev.githubAssignment || !ev.journal || !ev.pairing || !ev.browser;
  if (evidenceIncomplete) {
    visibleStates.add('EVIDENCE_INCOMPLETE');
  }

  const realBrowserAcceptance: CommandCenterWorkerProjection['realBrowserAcceptance'] =
    ev.certification?.realBrowserAccepted === true ? 'OWNER_ACCEPTED' : 'NOT_RUN';
  if (realBrowserAcceptance === 'NOT_RUN') {
    reasons.push('REAL_BROWSER_ACCEPTANCE_NOT_RUN');
  }

  const dispatchReady =
    !staleTop &&
    assignmentState === 'ASSIGNED_EXCLUSIVE' &&
    inventoryConsistency === 'ATOMIC_REVALIDATED' &&
    shaState === 'CURRENT_EXACT' &&
    pairingState === 'BRIDGE_ESTABLISHED' &&
    chatgptAuthState === 'READY' &&
    (ev.exactHeadCi ? ev.exactHeadCi.status === 'PASS' : true) &&
    (ev.tokenLifecycle ? ev.tokenLifecycle.valid : true) &&
    journalPhase !== 'DELIVERY_UNCERTAIN' &&
    journalPhase !== 'HALTED' &&
    journalPhase !== 'DISPATCHING' &&
    journalPhase !== 'CONTINUING';

  if (!dispatchReady && executionState !== 'CONFIRMED_CONVERSATION') {
    visibleStates.add('EXECUTION_BLOCKED');
  }

  return {
    schemaVersion: 1,
    identityState,
    assignmentState,
    inventoryConsistency,
    shaState,
    claimState,
    exactHeadCiState,
    pairingState,
    workerLiveness,
    chatgptAuthState,
    dispatchReady,
    evidenceIncomplete,
    executionState,
    conversationId: !staleTop && ev.journal ? ev.journal.conversationId : null,
    confirmedTurnCount: !staleTop && ev.journal ? ev.journal.confirmedTurnCount : 0,
    realBrowserAcceptance,
    visibleStates: [...visibleStates],
    blockingReasons: [...new Set(reasons)],
  };
}
