import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  evaluateCanaryIsolationGate,
  generateWorkstationStage0Scripts,
} from './canaryHarness.ts';
import {
  DEFAULT_EXTERNAL_86_MANIFEST,
  DEFAULT_NTFS_STAGE0_CONFIG,
  DEFAULT_WORKFLOW_WEIGHTS,
  SYNTHETIC_UNSANITIZED_LEAK_SAMPLE,
  SYNTHETIC_VALID_STAGE0_FIXTURE,
} from './fixtures.ts';
import {
  classifyWin32AttributesAndReparse,
  evaluatePreOpen86Rules,
  normalizePosixPath,
  normalizeWindowsNtfsPath,
  REPARSE_TAG_MOUNT_POINT,
  Stage0FailClosedError,
  validateStage0Preconditions,
  verifyManifestSha256,
  WIN32_ATTR_RECALL_ON_DATA_ACCESS,
  WIN32_ATTR_REPARSE_POINT,
} from './pathSecurity.ts';
import { computeFourFactorAdapterPriorities } from './priorityModel.ts';
import { runLiveSandboxStage0Verification } from './sandboxVerifier.ts';
import { auditSanitizedStage0Report } from './sanitizer.ts';
import {
  executeStage0Discovery,
  openRegularFileNoFollowVerified,
} from './traversalEngine.ts';
import type { External86Manifest, Stage0Config } from './types.ts';

function sha256(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

test('Requirement 1 & 2: Preconditions fail closed on empty allowlist, missing 86 manifest, or Zone A/B overlap', () => {
  // Empty scan roots allowlist -> FAIL_CLOSED_CONFIG
  assert.throws(
    () =>
      validateStage0Preconditions(
        { ...DEFAULT_NTFS_STAGE0_CONFIG, scanRootsAllowlist: [] },
        DEFAULT_EXTERNAL_86_MANIFEST
      ),
    (err: unknown) =>
      err instanceof Stage0FailClosedError && err.code === 'FAIL_CLOSED_CONFIG'
  );

  // Missing external 86 manifest -> FAIL_CLOSED_86_INIT
  assert.throws(
    () => validateStage0Preconditions(DEFAULT_NTFS_STAGE0_CONFIG, null),
    (err: unknown) =>
      err instanceof Stage0FailClosedError && err.code === 'FAIL_CLOSED_86_INIT'
  );

  // Empty 86 ruleset without explicit allowEmptyRuleset=true -> FAIL_CLOSED_86_INIT
  assert.throws(
    () =>
      validateStage0Preconditions(DEFAULT_NTFS_STAGE0_CONFIG, {
        ...DEFAULT_EXTERNAL_86_MANIFEST,
        rules: [],
        allowEmptyRuleset: false,
      }),
    (err: unknown) =>
      err instanceof Stage0FailClosedError && err.code === 'FAIL_CLOSED_86_INIT'
  );

  // Zone B inside Zone A scan root -> FAIL_CLOSED_ZONE_OVERLAP
  assert.throws(
    () =>
      validateStage0Preconditions(
        {
          ...DEFAULT_NTFS_STAGE0_CONFIG,
          zoneBOutputDir: 'D:\\AI_Archives\\Authorized_Sessions\\stage0_reports',
        },
        DEFAULT_EXTERNAL_86_MANIFEST
      ),
    (err: unknown) =>
      err instanceof Stage0FailClosedError && err.code === 'FAIL_CLOSED_ZONE_OVERLAP'
  );
});

test('Requirement 3: Separate Windows NTFS and POSIX security normalization (ADS, UNC, reserved devices, junctions, OneDrive recall)', () => {
  // Valid NTFS path normalizes to extended \\?\ prefix and case-folded canonical key by default
  const validNtfs = normalizeWindowsNtfsPath('D:/AI_Archives/Session_01');
  assert.equal(validNtfs.ok, true);
  assert.equal(validNtfs.extendedWin32Path, '\\\\?\\D:\\AI_Archives\\Session_01');
  assert.equal(validNtfs.canonicalComparisonKey, 'd:\\ai_archives\\session_01');

  // WSL per-directory case-sensitive flag preserves case in canonicalComparisonKey
  const csNtfs = normalizeWindowsNtfsPath('D:\\WSL_CaseDir\\Alpha', true);
  assert.equal(csNtfs.ok, true);
  assert.equal(csNtfs.canonicalComparisonKey, 'D:\\WSL_CaseDir\\Alpha');

  // Block NTFS Alternate Data Streams (ADS)
  assert.equal(
    normalizeWindowsNtfsPath('D:\\AI_Archives\\chat.json:hidden:$DATA').ok,
    false
  );

  // Block UNC / SMB network shares
  assert.equal(normalizeWindowsNtfsPath('\\\\fileserver\\share\\exports').ok, false);
  assert.equal(normalizeWindowsNtfsPath('\\\\?\\UNC\\server\\share').ok, false);

  // Block trailing dots/spaces & Win32 reserved device names (including extensions like CON.json)
  assert.equal(normalizeWindowsNtfsPath('D:\\AI_Archives\\folder. ').ok, false);
  assert.equal(normalizeWindowsNtfsPath('D:\\AI_Archives\\CON.json').ok, false);
  assert.equal(normalizeWindowsNtfsPath('D:\\AI_Archives\\NUL').ok, false);

  // Classify NTFS Junctions & OneDrive cloud-hydration recall flags
  const junction = classifyWin32AttributesAndReparse(
    WIN32_ATTR_REPARSE_POINT,
    REPARSE_TAG_MOUNT_POINT
  );
  assert.equal(junction.isReparsePoint, true);
  assert.equal(junction.reparseClassification, 'NTFS_JUNCTION_OR_VOLUME_MOUNT');

  const cloudFile = classifyWin32AttributesAndReparse(WIN32_ATTR_RECALL_ON_DATA_ACCESS);
  assert.equal(cloudFile.isCloudHydrationHazard, true);

  // POSIX rules: block root /, /proc, relative paths, and '..'
  assert.equal(normalizePosixPath('/').ok, false);
  assert.equal(normalizePosixPath('/proc/self/environ').ok, false);
  assert.equal(normalizePosixPath('relative/path').ok, false);
  assert.equal(normalizePosixPath('/srv/archives/../secret').ok, false);
  assert.equal(normalizePosixPath('/srv/archives/Alpha').canonicalComparisonKey, '/srv/archives/Alpha');

  // Case-insensitive 86 prefix matching on NTFS blocks mixed-case attempts pre-open
  const ntfs86Hit = evaluatePreOpen86Rules({
    candidatePath: 'd:\\ai_archives\\authorized_sessions\\EXCLUDED_VAULT_86\\sub\\chat.json',
    entryName: 'chat.json',
    mode: 'WINDOWS_NTFS',
    rules: DEFAULT_EXTERNAL_86_MANIFEST.rules,
  });
  assert.equal(ntfs86Hit.matched, true);
  assert.equal(ntfs86Hit.ruleId, 'R86_CLIENT_VAULT_01');
});

test('Requirement 4, 5 & 6: Real OS syscall sandbox proves manifest SHA-256 auth, zero open() on 86/symlink/hardlink, SQLite quarantine & immutability, strict canary gate, and exported runner parity', () => {
  const summary = runLiveSandboxStage0Verification();
  assert.equal(summary.allPassed, true, JSON.stringify(summary.checks, null, 2));
  assert.equal(summary.checks.length, 8);
  assert.equal(summary.generatedReport.securityAudit.manifestIntegrityVerified, true);
  // Every discovered format in Stage 0 must remain strictly UNVERIFIED
  for (const fmt of summary.generatedReport.formatInventory) {
    assert.equal(fmt.verificationStatus, 'UNVERIFIED');
  }
});

test('Requirement 7: Stage 0 Zero-Leak Sanitizer accepts clean structural report and rejects secrets, paths, titles, and premature adapter claims', () => {
  const cleanRes = auditSanitizedStage0Report(SYNTHETIC_VALID_STAGE0_FIXTURE);
  assert.equal(cleanRes.valid, true, cleanRes.violations.join(', '));

  const leakRes = auditSanitizedStage0Report(SYNTHETIC_UNSANITIZED_LEAK_SAMPLE);
  assert.equal(leakRes.valid, false);
  assert.ok(
    leakRes.violations.some((v) => v.includes('PREMATURE_VERIFIED_ADAPTER_CLAIM')),
    'Must flag premature PROVEN adapter status'
  );
  assert.ok(
    leakRes.violations.some((v) => v.includes('FORBIDDEN_KEY:title')),
    'Must flag forbidden conversation title field'
  );
  assert.ok(
    leakRes.violations.some((v) => v.includes('OPENAI_OR_ANTHROPIC_KEY')),
    'Must flag leaked sk-... key'
  );
  assert.ok(
    leakRes.violations.some((v) => v.includes('RAW_PATH_IN_86_RULE_KEY')),
    'Must flag raw path leaked in 86 rule summary'
  );
});

test('Requirement 8: Four-factor adapter prioritization ranks high-importance reusable CLI/agent formats above high-byte mixed monolithic exports', () => {
  const ranked = computeFourFactorAdapterPriorities(
    SYNTHETIC_VALID_STAGE0_FIXTURE.formatInventory,
    DEFAULT_WORKFLOW_WEIGHTS
  );

  assert.ok(ranked.length >= 10);
  const topThreeIds = ranked.slice(0, 3).map((r) => r.ecosystem);
  assert.ok(
    topThreeIds.includes('antigravity') && topThreeIds.includes('gemini_cli'),
    `Expected Antigravity and Gemini CLI in top 3, got: ${topThreeIds.join(', ')}`
  );

  const bottomTwoIds = ranked.slice(-2).map((r) => r.ecosystem);
  assert.ok(
    bottomTwoIds.includes('manus') && bottomTwoIds.includes('grok'),
    `Expected zero-byte formats at bottom, got: ${bottomTwoIds.join(', ')}`
  );

  assert.ok(ranked.every((r) => r.verificationStatus === 'UNVERIFIED'));
});

test('Audit P0 #3: Manifest SHA-256 verification fails closed when missing, malformed, mismatched, or conflicting across dual pins', () => {
  const raw = JSON.stringify(DEFAULT_EXTERNAL_86_MANIFEST);
  const goodHash = sha256(raw);

  assert.equal(verifyManifestSha256(raw, goodHash), goodHash);
  assert.equal(verifyManifestSha256(raw, goodHash.toUpperCase(), goodHash), goodHash);

  assert.throws(
    () => verifyManifestSha256(raw, undefined),
    (err: unknown) =>
      err instanceof Stage0FailClosedError &&
      err.code === 'FAIL_CLOSED_86_INIT' &&
      err.detailCode === 'MISSING_EXPECTED_MANIFEST_SHA256'
  );

  assert.throws(
    () => verifyManifestSha256(raw, 'not-a-valid-sha256'),
    (err: unknown) =>
      err instanceof Stage0FailClosedError &&
      err.code === 'FAIL_CLOSED_86_INIT' &&
      err.detailCode === 'INVALID_EXPECTED_MANIFEST_SHA256_FORMAT'
  );

  assert.throws(
    () => verifyManifestSha256(raw, 'a'.repeat(64)),
    (err: unknown) =>
      err instanceof Stage0FailClosedError &&
      err.code === 'FAIL_CLOSED_86_INIT' &&
      err.detailCode === 'MANIFEST_SHA256_MISMATCH'
  );

  assert.throws(
    () => verifyManifestSha256(raw, goodHash, 'b'.repeat(64)),
    (err: unknown) =>
      err instanceof Stage0FailClosedError &&
      err.code === 'FAIL_CLOSED_86_INIT' &&
      err.detailCode === 'MANIFEST_SHA256_MISMATCH'
  );
});

test('Audit P1 #1: openRegularFileNoFollowVerified defeats check-to-open TOCTOU symlink swap, hardlink addition, and inode swap', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chronos-toctou-'));
  try {
    const rootDir = path.join(tmpDir, 'root');
    const outsideDir = path.join(tmpDir, 'outside');
    fs.mkdirSync(rootDir, { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });

    const rootRealPath = fs.realpathSync(rootDir);
    const victimFile = path.join(rootDir, 'session.json');
    const outsideSecret = path.join(outsideDir, 'secret.json');
    fs.writeFileSync(victimFile, '{"ok":true}');
    fs.writeFileSync(outsideSecret, '{"secret":"do_not_read"}');

    // Capture pre-open lstat of clean regular file, then race-swap with a symlink before open!
    const preStat = fs.lstatSync(victimFile);
    fs.unlinkSync(victimFile);
    fs.symlinkSync(outsideSecret, victimFile);

    const symlinkRaceRes = openRegularFileNoFollowVerified({
      fullPath: victimFile,
      entryName: 'session.json',
      expectedStat: preStat,
      rootRealPath,
      mode: 'POSIX',
      revokedPosixDevInos: new Set(),
      rules: [],
    });
    assert.equal(symlinkRaceRes.ok, false);
    assert.equal(symlinkRaceRes.reason, 'SYMLINK_RACE');

    // Race-swap with a different regular file (create swappedFile BEFORE replacing victimFile
    // so the filesystem cannot recycle the exact same inode number)
    fs.unlinkSync(victimFile);
    fs.writeFileSync(victimFile, '{"original":true}');
    const origStat = fs.lstatSync(victimFile);
    const swappedFile = path.join(rootDir, 'session_swapped.json');
    fs.writeFileSync(swappedFile, '{"swapped":true}');
    fs.renameSync(swappedFile, victimFile);
    const inodeRaceRes = openRegularFileNoFollowVerified({
      fullPath: victimFile,
      entryName: 'session.json',
      expectedStat: origStat,
      rootRealPath,
      mode: 'POSIX',
      revokedPosixDevInos: new Set(),
      rules: [],
    });
    assert.equal(inodeRaceRes.ok, false);
    assert.equal(inodeRaceRes.reason, 'STAT_IDENTITY_MISMATCH');

    // Race-add a hardlink between lstat and open (nlink jumps from 1 to 2)
    const hardlinkTarget = path.join(rootDir, 'hl_target.json');
    fs.writeFileSync(hardlinkTarget, '{"ok":true}');
    const hlPreStat = fs.lstatSync(hardlinkTarget);
    fs.linkSync(hardlinkTarget, path.join(rootDir, 'hl_alias.json'));
    const hlRaceRes = openRegularFileNoFollowVerified({
      fullPath: hardlinkTarget,
      entryName: 'hl_target.json',
      expectedStat: hlPreStat,
      rootRealPath,
      mode: 'POSIX',
      revokedPosixDevInos: new Set(),
      rules: [],
    });
    assert.equal(hlRaceRes.ok, false);
    assert.equal(hlRaceRes.reason, 'HARDLINK_RACE');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Audit P1 #2: SQLite is strictly quarantined unscanned when REVOKED_CONVERSATION_ID rules exist, and safely inspected when absent', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chronos-sqlite-quarantine-'));
  try {
    const zoneA = path.join(tmpDir, 'zone_a');
    const zoneB = path.join(tmpDir, 'zone_b');
    fs.mkdirSync(zoneA, { recursive: true });
    fs.mkdirSync(zoneB, { recursive: true });

    const dbPath = path.join(zoneA, 'conversations.sqlite');
    execFileSync(
      'python3',
      [
        '-c',
        `import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); c.execute("CREATE TABLE convs (id TEXT PRIMARY KEY, body TEXT)"); c.execute("INSERT INTO convs VALUES ('conv_86', 'secret')"); c.commit(); c.close()`,
        dbPath,
      ],
      { timeout: 3000 }
    );

    const baseConfig: Stage0Config = {
      configVersion: '1.0.0',
      hostOsMode: 'POSIX',
      scanRootsAllowlist: [{ alias: 'ROOT_01', absolutePath: zoneA, expectedFsMode: 'POSIX' }],
      external86ManifestPath: path.join(zoneB, 'manifest.json'),
      zoneBOutputDir: zoneB,
      workflowWeights: { ...DEFAULT_WORKFLOW_WEIGHTS },
    };

    const withConvRule: External86Manifest = {
      schemaVersion: '1.0.0',
      manifestId: 'M_CONV',
      ownerApprovedAtIso: new Date().toISOString(),
      rules: [
        {
          ruleId: 'R86_CONV_01',
          kind: 'REVOKED_CONVERSATION_ID',
          targetValue: 'conv_86',
          reasonCode: 'REVOKED_CONV',
        },
      ],
    };
    const withConvRaw = JSON.stringify(withConvRule);
    const resQuarantined = executeStage0Discovery({
      config: baseConfig,
      manifestRawJson: withConvRaw,
      expectedManifestSha256: sha256(withConvRaw),
      evidenceOrigin: 'SANDBOX_SCRATCH_VERIFICATION',
    });
    assert.equal(resQuarantined.report.reuseInventory.sqliteLedgersInspected.length, 0);
    assert.equal(resQuarantined.report.securityAudit.potentialMixedUnscannedCount, 1);

    const withoutConvRule: External86Manifest = {
      schemaVersion: '1.0.0',
      manifestId: 'M_NO_CONV',
      ownerApprovedAtIso: new Date().toISOString(),
      rules: [
        {
          ruleId: 'R86_FILENAME_01',
          kind: 'FILENAME_EXACT',
          targetValue: 'unrelated_secret.json',
          reasonCode: 'UNRELATED',
        },
      ],
    };
    const withoutConvRaw = JSON.stringify(withoutConvRule);
    const resCleared = executeStage0Discovery({
      config: baseConfig,
      manifestRawJson: withoutConvRaw,
      expectedManifestSha256: sha256(withoutConvRaw),
      evidenceOrigin: 'SANDBOX_SCRATCH_VERIFICATION',
    });
    assert.equal(resCleared.report.reuseInventory.sqliteLedgersInspected.length, 1);
    assert.equal(resCleared.report.reuseInventory.sqliteLedgersInspected[0].tableName, 'convs');
    assert.deepEqual(fs.readdirSync(zoneA), ['conversations.sqlite']);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Audit P0 #1/#2 & P1 #3/#4: Exported workstation probe & canary scripts enforce full preconditions, strict canary gating, and zero-leak sanitization standalone in /tmp', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chronos-exported-cli-'));
  try {
    const scriptsDir = path.join(tmpDir, 'scripts');
    const zoneA = path.join(tmpDir, 'zone_a');
    const zoneB = path.join(tmpDir, 'zone_b');
    const lockedVault = path.join(tmpDir, 'locked_vault');
    const openVault = path.join(tmpDir, 'open_vault');
    fs.mkdirSync(scriptsDir, { recursive: true });
    fs.mkdirSync(zoneA, { recursive: true });
    fs.mkdirSync(zoneB, { recursive: true });
    fs.mkdirSync(lockedVault, { recursive: true });
    fs.mkdirSync(openVault, { recursive: true });

    const manifestPath = path.join(zoneB, 'manifest.json');
    const manifestObj: External86Manifest = {
      schemaVersion: '1.0.0',
      manifestId: 'M_EXPORTED_01',
      ownerApprovedAtIso: new Date().toISOString(),
      rules: [
        {
          ruleId: 'R86_GLOB_01',
          kind: 'GLOB_SEGMENT',
          targetValue: '*.secret.json',
          reasonCode: 'GLOB_RULE',
        },
      ],
    };
    const manifestRaw = JSON.stringify(manifestObj, null, 2);
    const manifestHash = sha256(manifestRaw);
    fs.writeFileSync(manifestPath, manifestRaw, 'utf8');

    const config: Stage0Config = {
      configVersion: '1.0.0',
      hostOsMode: 'POSIX',
      scanRootsAllowlist: [{ alias: 'ROOT_01', absolutePath: zoneA, expectedFsMode: 'POSIX' }],
      external86ManifestPath: manifestPath,
      zoneBOutputDir: zoneB,
      workflowWeights: { ...DEFAULT_WORKFLOW_WEIGHTS },
    };

    const { probeScriptMjs, canaryScriptMjs } = generateWorkstationStage0Scripts(config, manifestObj);
    const probePath = path.join(scriptsDir, 'stage0-workstation-probe.mjs');
    const canaryPath = path.join(scriptsDir, 'stage0-multi-identity-canary.mjs');
    fs.writeFileSync(probePath, probeScriptMjs, 'utf8');
    fs.writeFileSync(canaryPath, canaryScriptMjs, 'utf8');

    // 1. Exported probe MUST reject Zone A / Zone B overlap (P0 #1 preflight parity)
    const overlapConfigPath = path.join(zoneB, 'overlap-config.json');
    fs.writeFileSync(
      overlapConfigPath,
      JSON.stringify({ ...config, zoneBOutputDir: path.join(zoneA, 'nested_zone_b') }, null, 2)
    );
    const overlapRun = spawnSync(
      process.execPath,
      [probePath, '--config', overlapConfigPath, '--expected-manifest-sha256', manifestHash],
      { encoding: 'utf8', cwd: scriptsDir, timeout: 5000 }
    );
    assert.equal(overlapRun.status, 4);
    assert.ok(overlapRun.stderr.includes('FAIL_CLOSED_ZONE_OVERLAP'));

    // 2. Exported canary MUST fail closed (exit 4) when protected vault is readable (openVault)
    const exposedCanaryRun = spawnSync(
      process.execPath,
      [canaryPath, '--vault-test-dir', openVault, '--test-current-user-must-deny'],
      { encoding: 'utf8', cwd: scriptsDir, timeout: 5000 }
    );
    assert.equal(exposedCanaryRun.status, 4);
    const exposedJson = JSON.parse(exposedCanaryRun.stdout);
    assert.equal(exposedJson.allProtectedIdentitiesDenied, false);
    assert.equal(exposedJson.protectedIdentitiesExposed, 1);

    // 3. Exported canary MUST pass (exit 0) when protected vault enforces mode 0000 denial
    const lockedCanaryRun = spawnSync(
      process.execPath,
      [
        canaryPath,
        '--vault-test-dir',
        lockedVault,
        '--test-current-user-must-deny',
        '--lock-vault-mode-0000',
      ],
      { encoding: 'utf8', cwd: scriptsDir, timeout: 5000 }
    );
    assert.equal(lockedCanaryRun.status, 0, lockedCanaryRun.stderr || lockedCanaryRun.stdout);
    const lockedJson = JSON.parse(lockedCanaryRun.stdout);
    assert.equal(lockedJson.allProtectedIdentitiesDenied, true);
    assert.equal(lockedJson.protectedIdentitiesDenied, 1);

    // 4. evaluateCanaryIsolationGate MUST reject 3 records if any protected identity is exposed or uncertain
    const strictGateFail = evaluateCanaryIsolationGate([
      {
        identityLabel: 'Control',
        principalKind: 'CLI_AGENT_SAME_UID',
        expectedAccess: 'DIAGNOSTIC_EXPOSURE_CHECK',
        probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
        outcome: 'FAIL_EXPOSED_TO_IDENTITY',
        osErrorCode: 'EXIT_0',
        remediationNote: 'control',
      },
      {
        identityLabel: 'Protected 1',
        principalKind: 'ISOLATED_AGENT_UID',
        expectedAccess: 'MUST_DENY',
        probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
        outcome: 'FAIL_EXPOSED_TO_IDENTITY',
        osErrorCode: 'EXIT_0',
        remediationNote: 'exposed',
      },
      {
        identityLabel: 'Protected 2',
        principalKind: 'SEARCH_SUBPROCESS',
        expectedAccess: 'MUST_DENY',
        probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
        outcome: 'PASS_OS_ENFORCED_DENIED',
        osErrorCode: 'EACCES',
        remediationNote: 'denied',
      },
    ]);
    assert.equal(strictGateFail.allProtectedIdentitiesDenied, false);
    assert.equal(strictGateFail.protectedIdentitiesExposed, 1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
