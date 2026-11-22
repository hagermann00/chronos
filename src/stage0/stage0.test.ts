import assert from 'node:assert/strict';
import test from 'node:test';
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
  WIN32_ATTR_RECALL_ON_DATA_ACCESS,
  WIN32_ATTR_REPARSE_POINT,
} from './pathSecurity.ts';
import { computeFourFactorAdapterPriorities } from './priorityModel.ts';
import { runLiveSandboxStage0Verification } from './sandboxVerifier.ts';
import { auditSanitizedStage0Report } from './sanitizer.ts';

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

test('Requirement 4, 5 & 6: Real OS syscall sandbox proves zero open() on 86/symlink/hardlink, mixed-archive quarantine, SQLite Zone A immutability, and real subprocess canary probes', () => {
  const summary = runLiveSandboxStage0Verification();
  assert.equal(summary.allPassed, true, JSON.stringify(summary.checks, null, 2));
  assert.equal(summary.checks.length, 6);
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
  // Even though ChatGPT has 92 MB (the largest single byte count), Antigravity / Gemini CLI / Codex CLI
  // have CRITICAL_ACTIVE_WORK importance, existing Universal Harness reuse, explicit timestamps, and zero mixed-archive penalty!
  const topThreeIds = ranked.slice(0, 3).map((r) => r.ecosystem);
  assert.ok(
    topThreeIds.includes('antigravity') && topThreeIds.includes('gemini_cli'),
    `Expected Antigravity and Gemini CLI in top 3, got: ${topThreeIds.join(', ')}`
  );

  // Zero-byte ecosystems (Manus, Grok in fixture) rank at the bottom
  const bottomTwoIds = ranked.slice(-2).map((r) => r.ecosystem);
  assert.ok(
    bottomTwoIds.includes('manus') && bottomTwoIds.includes('grok'),
    `Expected zero-byte formats at bottom, got: ${bottomTwoIds.join(', ')}`
  );

  // All ranked items preserve UNVERIFIED status
  assert.ok(ranked.every((r) => r.verificationStatus === 'UNVERIFIED'));
});
