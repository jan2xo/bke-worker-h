/**
 * F3-04 Multi-Process Test Helper: Runs DesktopControllerDaemon inside an isolated child process.
 * Reads configuration from env + public key file, connects over loopback HTTP + Unix IPC socket,
 * and uses SandboxHttpTokenBrokerClient for token provisioning against the separate Broker process.
 */
import { readFile } from 'node:fs/promises';
import { DesktopControllerDaemon } from '../../../../browser-extension/native-host/claim/dist/native-host/claim/controller-daemon.js';
import { ManagedTokenProvider } from '../../../../browser-extension/native-host/claim/dist/native-host/claim/token-lifecycle.js';
import { DeviceKeyPairSigner, SandboxHttpTokenBrokerClient } from '../../dist/broker-client.js';

async function main() {
  const cfgPath = process.env.BKE_TEST_RUNNER_CONFIG_FILE;
  if (!cfgPath) throw new Error('RUNNER_CONFIG_FILE_MISSING');
  const cfg = JSON.parse(await readFile(cfgPath, 'utf8'));

  const deviceSigner = new DeviceKeyPairSigner({
    publicKeySpkiPem: cfg.devicePublicKeyPem,
    privateKeyPem: cfg.devicePrivateKeyPem,
  });

  const executionPublicKeys = new Map(Object.entries(cfg.executionPublicKeys));
  const brokerClient = new SandboxHttpTokenBrokerClient({
    brokerBaseUrl: cfg.brokerBaseUrl,
    deviceId: cfg.deviceId,
    enrollmentGeneration: cfg.enrollmentGeneration,
    deviceSigner,
    brokerPublicKeysById: executionPublicKeys,
    expectedBrokerIssuer: cfg.expectedBrokerIssuer,
    repository: cfg.repository,
    installationId: cfg.installationId,
    workerId: cfg.workerId,
  });

  const tokenLifecycle = new ManagedTokenProvider(
    {
      repository: cfg.repository,
      repositoryId: cfg.repositoryId,
      installationId: cfg.installationId,
      workerId: cfg.workerId,
      allowedPermissions: { contents: 'read', pull_requests: 'read', checks: 'read' },
      maxTransientRetries: cfg.maxTransientRetries ?? 2,
      retryDelayMs: cfg.retryDelayMs ?? 15,
      trustedRealBrokerApiAvailable: true,
      realBrokerTransportConnected: true,
    },
    brokerClient,
  );

  const daemon = new DesktopControllerDaemon(
    {
      repository: cfg.repository,
      prNumber: cfg.prNumber,
      workerId: cfg.workerId,
      pinnedApp: cfg.pinnedApp,
      executionId: cfg.executionId,
      targetId: cfg.targetId,
      profileId: cfg.profileId,
      targetTabId: cfg.targetTabId,
      journalPath: cfg.journalPath,
      ipcSocketPath: cfg.ipcSocketPath,
      policyPath: cfg.policyPath,
      webhookSecret: cfg.webhookSecret,
      operatorHaltToken: cfg.operatorHaltToken,
      listenHost: '127.0.0.1',
      listenPort: cfg.listenPort ?? 0,
      humanLiveSendAuthorized: cfg.humanLiveSendAuthorized === true,
      liveProofs: cfg.liveProofs,
      executionEnvelopeEnabled: true,
      asymmetricV2Enabled: true,
      requireAsymmetricV2: true,
      mediatedCasEnabled: true,
      expectedRepositoryId: cfg.repositoryId,
      expectedInstallationId: cfg.installationId,
      executionPublicKeysById: executionPublicKeys,
      remoteHaltPublicKeysById: new Map(Object.entries(cfg.haltPublicKeys)),
      allowRemoteSignedHalt: true,
      expectedAudience: cfg.expectedAudience,
      expectedBrokerIssuer: cfg.expectedBrokerIssuer,
      expectedDeviceId: cfg.deviceId,
      expectedEnrollmentGeneration: cfg.enrollmentGeneration,
      minEnrollmentGeneration: cfg.enrollmentGeneration,
      brokerAvailable: true,
      brokerEndpointConfigured: true,
      githubApiBaseUrl: cfg.githubApiBaseUrl,
      deviceRevocationChecker: (info) => brokerClient.checkDeviceRevocation(info),
    },
    {
      tokenProvider: tokenLifecycle.asTokenProvider(),
      tokenLifecycle,
      mediatedLedgerClient: brokerClient,
    },
  );

  const started = await daemon.start({ listen: true });
  process.stdout.write(
    JSON.stringify({
      ok: true,
      port: started.port,
      phase: started.recoveredState.phase,
    }) + '\n',
  );

  await new Promise((resolveStop) => {
    const shutdown = () => void daemon.stop().then(() => resolveStop());
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
  });
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack || err.message : String(err)}\n`);
  process.exit(1);
});
