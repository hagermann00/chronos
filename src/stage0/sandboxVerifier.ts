import { execFileSync, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  evaluateCanaryIsolationGate,
  generateWorkstationStage0Scripts,
  runIsolatedCanaryAccessTests,
} from './canaryHarness.ts';
import { Stage0FailClosedError } from './pathSecurity.ts';
import { createEphemeralRamScratchDir } from './ramPartition.ts';
import { auditSanitizedStage0Report } from './sanitizer.ts';
import { executeStage0Discovery } from './traversalEngine.ts';
import type { External86Manifest, SanitizedStage0Report, Stage0Config } from './types.ts';

/**
 * Builds a minimal valid uncompressed ZIP archive buffer in memory containing specified filenames,
 * allowing real binary Central Directory TOC testing without external zip binaries.
 */
export function buildMinimalZipBuffer(entries: Array<{ name: string; body: string }>): Buffer {
  const localParts: Buffer[] = [];
  const cdParts: Buffer[] = [];
  let localOffset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const bodyBuf = Buffer.from(entry.body, 'utf8');

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // Local file header signature
    localHeader.writeUInt16LE(20, 4); // Version needed
    localHeader.writeUInt16LE(0, 6); // GP bit flag (0 = unencrypted)
    localHeader.writeUInt16LE(0, 8); // Compression method 0 = store
    localHeader.writeUInt32LE(0, 14); // CRC-32 (not inflated in Stage 0 TOC check)
    localHeader.writeUInt32LE(bodyBuf.length, 18);
    localHeader.writeUInt32LE(bodyBuf.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    localParts.push(localHeader, nameBuf, bodyBuf);

    const cdHeader = Buffer.alloc(46);
    cdHeader.writeUInt32LE(0x02014b50, 0); // Central directory signature
    cdHeader.writeUInt16LE(20, 4);
    cdHeader.writeUInt16LE(20, 6);
    cdHeader.writeUInt16LE(0, 8); // GP bit flag
    cdHeader.writeUInt16LE(0, 10);
    cdHeader.writeUInt32LE(bodyBuf.length, 20);
    cdHeader.writeUInt32LE(bodyBuf.length, 24);
    cdHeader.writeUInt16LE(nameBuf.length, 28);
    cdHeader.writeUInt16LE(0, 30);
    cdHeader.writeUInt16LE(0, 32);
    cdHeader.writeUInt32LE(localOffset, 42);

    cdParts.push(cdHeader, nameBuf);
    localOffset += localHeader.length + nameBuf.length + bodyBuf.length;
  }

  const cdBuf = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(localOffset, 16);

  return Buffer.concat([...localParts, cdBuf, eocd]);
}

export interface SandboxVerificationCheck {
  checkId: string;
  title: string;
  passed: boolean;
  measuredDetail: string;
}

export interface SandboxVerificationSummary {
  executedAtIso: string;
  environmentBanner: 'ISOLATED_CONTAINER_SCRATCH_SANDBOX_NOT_WORKSTATION';
  scratchBacking: {
    isRamBacked: boolean;
    backingFsType: string;
    mountPoint: string;
    verifiedByKernel: boolean;
  };
  allPassed: boolean;
  checks: SandboxVerificationCheck[];
  generatedReport: SanitizedStage0Report;
}

function sha256Hex(raw: string): string {
  return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
}

/**
 * Runs a complete, real-syscall Stage 0 verification pass inside a disposable kernel-verified
 * RAM partition directory (`tmpfs`/`ramfs` on Linux via `/dev/shm`, or explicit RAM disk) with
 * zero persistent disk writes, proving:
 * - Verified in-memory RAM partition scratch isolation
 * - Precondition fail-closed (allowlist, manifest SHA-256 authentication)
 * - Pre-open 86 pruning across PATH_PREFIX, POSIX_DEV_INO, FILENAME_EXACT, GLOB_SEGMENT,
 *   ARCHIVE_ENTRY_NAME, REVOKED_CONVERSATION_ID, and KNOWN_MIXED_CONTAINER
 * - Symlink & hardlink blocking + O_NOFOLLOW/fstat TOCTOU enforcement
 * - Mixed-ZIP TOC quarantine AND SQLite quarantine when conversation-level 86 rules exist
 * - SQLite Zone A zero-sidecar immutability when no conversation-level 86 rules apply
 * - Strict multi-identity canary isolation enforcement (requiring every protected identity denied)
 * - Independent subprocess execution of the ACTUAL exported workstation scripts in RAM scratch with
 *   exact security parity against the authoritative engine
 * - Zero-leak output sanitization
 */
export function runLiveSandboxStage0Verification(options?: {
  ramScratchDir?: string;
  requireRamPartition?: boolean;
}): SandboxVerificationSummary {
  const scratch = createEphemeralRamScratchDir('chronos-stage0-sandbox-', {
    preferredRamDir: options?.ramScratchDir,
    requireRamPartition: options?.requireRamPartition ?? process.platform === 'linux',
  });
  const scratchBase = scratch.scratchDir;
  const zoneARoot = path.join(scratchBase, 'zone_a_scan_root');
  const zoneBOut = path.join(scratchBase, 'zone_b_authorized_output');
  const zoneBExportedRunnerOut = path.join(scratchBase, 'zone_b_exported_runner_output');
  const outsideSecretDir = path.join(scratchBase, 'outside_86_secret_vault');
  const exportedScriptsDir = path.join(scratchBase, 'standalone_exported_scripts');

  const checks: SandboxVerificationCheck[] = [];
  checks.push({
    checkId: 'RAM_PARTITION_SCRATCH_ISOLATION',
    title: 'Ephemeral Sandbox & Canary Scratch Runs on Verified In-Memory RAM Partition (Zero Persistent Disk Writes)',
    passed: scratch.ramCheck.isRamBacked && scratch.ramCheck.verifiedByKernel,
    measuredDetail: `backingFs=${scratch.ramCheck.backingFsType} · mount=${scratch.ramCheck.mountPoint} · verifiedByKernel=${scratch.ramCheck.verifiedByKernel}`,
  });

  try {
    fs.mkdirSync(zoneARoot, { recursive: true });
    fs.mkdirSync(zoneBOut, { recursive: true });
    fs.mkdirSync(zoneBExportedRunnerOut, { recursive: true });
    fs.mkdirSync(outsideSecretDir, { recursive: true });
    fs.mkdirSync(exportedScriptsDir, { recursive: true });

    // 1. Create an 86'd subdirectory inside Zone A (must NEVER be opened)
    const revokedSubdir = path.join(zoneARoot, 'revoked_client_alpha');
    fs.mkdirSync(revokedSubdir, { recursive: true });
    const revokedSecretFile = path.join(revokedSubdir, 'do_not_open.json');
    fs.writeFileSync(revokedSecretFile, '{"secret":"sk-live1234567890abcdefghijklmnop"}');

    // 1b. Additional 86 fixtures exercising FILENAME_EXACT, GLOB_SEGMENT, REVOKED_CONVERSATION_ID, KNOWN_MIXED_CONTAINER
    const exactRevokedFile = path.join(zoneARoot, 'exact_revoked_creds.json');
    fs.writeFileSync(exactRevokedFile, '{"secret":"exact_filename_revoked"}');

    const globRevokedFile = path.join(zoneARoot, 'audit_private_86_draft.json');
    fs.writeFileSync(globRevokedFile, '{"secret":"glob_segment_revoked"}');

    const convIdFile = path.join(zoneARoot, 'session_conv_86_revoked.json');
    fs.writeFileSync(convIdFile, '{"secret":"revoked_conv_id_file"}');

    const knownMixedContainerFile = path.join(zoneARoot, 'known_mixed_dump.json');
    fs.writeFileSync(knownMixedContainerFile, '{"mixed":true}');

    // 2. Create a symlink attempting to escape Zone A into outsideSecretDir
    const outsideTarget = path.join(outsideSecretDir, 'escaped.json');
    fs.writeFileSync(outsideTarget, '{"mapping":{},"current_node":"1"}');
    const escapeSymlink = path.join(zoneARoot, 'symlink_escape.json');
    fs.symlinkSync(outsideTarget, escapeSymlink);

    // 3. Create a hardlink inside Zone A aliasing the revoked inode
    const hardlinkAlias = path.join(zoneARoot, 'innocent_looking_hardlink.json');
    fs.linkSync(revokedSecretFile, hardlinkAlias);
    const revokedStat = fs.lstatSync(revokedSecretFile);
    const revokedDevIno = `${revokedStat.dev}:${revokedStat.ino}`;

    // 4. Create a mixed ZIP archive containing both an authorized chat and a revoked archive entry
    const mixedZipPath = path.join(zoneARoot, 'bundle_export.zip');
    fs.writeFileSync(
      mixedZipPath,
      buildMinimalZipBuffer([
        { name: 'authorized_session.json', body: '{"sessionId":"ok"}' },
        { name: 'secret_project_86/transcript.json', body: '{"secret":"revoked"}' },
      ])
    );

    // 5. Create a monolithic conversations.json when conversation-level 86 IDs exist
    const monoChatGptPath = path.join(zoneARoot, 'conversations.json');
    fs.writeFileSync(
      monoChatGptPath,
      '[{"id":"conv_ok","mapping":{},"current_node":"1"},{"id":"conv_86_revoked","mapping":{},"current_node":"2"}]'
    );

    // 6. Create real SQLite ledgers in Zone A via python3 sqlite3:
    //    - harness_jobs.sqlite: clean rollback-journal DB (v1/v1, no sidecars)
    //    - wal_ledger.sqlite: WAL-mode DB (v2/v2 header) that MUST fail closed & quarantine unscanned
    const sqliteDir = path.join(zoneARoot, 'existing_ledger');
    fs.mkdirSync(sqliteDir, { recursive: true });
    const sqlitePath = path.join(sqliteDir, 'harness_jobs.sqlite');
    execFileSync(
      'python3',
      [
        '-c',
        `import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); c.execute("CREATE TABLE closeout_sessions (session_id TEXT PRIMARY KEY, status TEXT, created_at TEXT)"); c.execute("INSERT INTO closeout_sessions VALUES ('s1', 'DONE', '2026-11-01')"); c.commit(); c.close()`,
        sqlitePath,
      ],
      { timeout: 3000 }
    );
    const walSqlitePath = path.join(sqliteDir, 'wal_ledger.sqlite');
    execFileSync(
      'python3',
      [
        '-c',
        `import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); c.execute("PRAGMA journal_mode=WAL"); c.execute("CREATE TABLE active_events (id TEXT)"); c.execute("INSERT INTO active_events VALUES ('e1')"); c.commit(); c.close()`,
        walSqlitePath,
      ],
      { timeout: 3000 }
    );
    const sqliteDirBefore = fs.readdirSync(sqliteDir).sort();
    const sqliteHashBefore = fs.readFileSync(sqlitePath);
    const walSqliteHashBefore = fs.readFileSync(walSqlitePath);

    // 7. Create cleared structured session files (Antigravity, Gemini CLI, Claude Code)
    const cleanDir = path.join(zoneARoot, 'active_sessions');
    fs.mkdirSync(cleanDir, { recursive: true });
    fs.writeFileSync(
      path.join(cleanDir, 'antigravity_tree.json'),
      JSON.stringify({
        antigravity: true,
        parent_agent_id: 'root_1',
        subagent_id: 'sub_2',
        timestamp: '2026-11-20T10:00:00Z',
      })
    );
    fs.writeFileSync(
      path.join(cleanDir, 'gemini_cli_01.json'),
      JSON.stringify({
        gemini_cli: true,
        sessionId: 'g_1',
        thoughts: [],
        timestamp: '2026-11-20T11:00:00Z',
      })
    );
    fs.writeFileSync(
      path.join(cleanDir, 'claude_code_01.jsonl'),
      JSON.stringify({
        parentUuid: 'u0',
        cwd: '/workspace',
        toolUseResult: {},
        timestamp: '2026-11-20T12:00:00Z',
      }) + '\n'
    );

    const manifest: External86Manifest = {
      schemaVersion: '1.0.0',
      manifestId: 'MANIFEST_SANDBOX_VERIFY_01',
      ownerApprovedAtIso: new Date().toISOString(),
      rules: [
        {
          ruleId: 'R86_SUBDIR_ALPHA',
          kind: 'PATH_PREFIX',
          targetValue: revokedSubdir,
          reasonCode: 'OWNER_REVOKED_CLIENT',
        },
        {
          ruleId: 'R86_EXACT_FILE',
          kind: 'FILENAME_EXACT',
          targetValue: 'exact_revoked_creds.json',
          reasonCode: 'OWNER_REVOKED_EXACT_FILE',
        },
        {
          ruleId: 'R86_GLOB_PRIVATE',
          kind: 'GLOB_SEGMENT',
          targetValue: '*private_86*',
          reasonCode: 'OWNER_REVOKED_GLOB',
        },
        {
          ruleId: 'R86_KNOWN_MIXED',
          kind: 'KNOWN_MIXED_CONTAINER',
          targetValue: knownMixedContainerFile,
          reasonCode: 'KNOWN_MIXED_DUMP',
        },
        {
          ruleId: 'R86_INODE_GUARD',
          kind: 'POSIX_DEV_INO',
          targetValue: revokedDevIno,
          reasonCode: 'HARDLINK_INODE_BLOCK',
        },
        {
          ruleId: 'R86_ZIP_ENTRY',
          kind: 'ARCHIVE_ENTRY_NAME',
          targetValue: 'secret_project_86',
          reasonCode: 'MIXED_ZIP_REVOKED_ENTRY',
        },
        {
          ruleId: 'R86_CONV_ID',
          kind: 'REVOKED_CONVERSATION_ID',
          targetValue: 'conv_86_revoked',
          reasonCode: 'MIXED_MONOLITHIC_CONV_ID',
        },
      ],
    };

    const manifestRawJson = JSON.stringify(manifest, null, 2);
    const trustedManifestSha256 = sha256Hex(manifestRawJson);
    const manifestPath = path.join(zoneBOut, 'manifest.json');
    fs.writeFileSync(manifestPath, manifestRawJson, 'utf8');

    const config: Stage0Config = {
      configVersion: '1.0.0',
      hostOsMode: 'POSIX',
      scanRootsAllowlist: [
        {
          alias: 'ROOT_01',
          absolutePath: zoneARoot,
          expectedFsMode: 'POSIX',
        },
      ],
      external86ManifestPath: manifestPath,
      zoneBOutputDir: zoneBOut,
      workflowWeights: {
        antigravity: 'CRITICAL_ACTIVE_WORK',
        gemini_cli: 'CRITICAL_ACTIVE_WORK',
        codex_cli: 'CRITICAL_ACTIVE_WORK',
        claude_code: 'CRITICAL_ACTIVE_WORK',
        gemini_web: 'HIGH_REFERENCE',
        chatgpt_openai: 'HIGH_REFERENCE',
        claude_web: 'HIGH_REFERENCE',
        manus: 'ARCHIVAL_LOW',
        grok: 'ARCHIVAL_LOW',
        deepseek: 'ARCHIVAL_LOW',
        unknown_structured: 'ARCHIVAL_LOW',
      },
    };

    // Check A: Fail-closed when scanRootsAllowlist is empty
    let emptyRootBlocked = false;
    try {
      executeStage0Discovery({
        config: { ...config, scanRootsAllowlist: [] },
        manifestRawJson,
        expectedManifestSha256: trustedManifestSha256,
        evidenceOrigin: 'SANDBOX_SCRATCH_VERIFICATION',
      });
    } catch (err) {
      emptyRootBlocked =
        err instanceof Stage0FailClosedError && err.code === 'FAIL_CLOSED_CONFIG';
    }
    checks.push({
      checkId: 'PRECOND_ALLOWLIST_REQUIRED',
      title: 'Fail-Closed on Missing/Empty Scan-Root Allowlist',
      passed: emptyRootBlocked,
      measuredDetail: emptyRootBlocked
        ? 'Aborted with FAIL_CLOSED_CONFIG prior to any readdir/lstat.'
        : 'Unexpectedly continued with empty allowlist.',
    });

    // Check B: Fail-closed when expected manifest SHA-256 is missing or mismatched
    let missingDigestBlocked = false;
    try {
      executeStage0Discovery({
        config,
        manifestRawJson,
        evidenceOrigin: 'SANDBOX_SCRATCH_VERIFICATION',
      });
    } catch (err) {
      missingDigestBlocked =
        err instanceof Stage0FailClosedError &&
        err.code === 'FAIL_CLOSED_86_INIT' &&
        err.detailCode === 'MISSING_EXPECTED_MANIFEST_SHA256';
    }

    let wrongDigestBlocked = false;
    try {
      executeStage0Discovery({
        config,
        manifestRawJson,
        expectedManifestSha256: '0'.repeat(64),
        evidenceOrigin: 'SANDBOX_SCRATCH_VERIFICATION',
      });
    } catch (err) {
      wrongDigestBlocked =
        err instanceof Stage0FailClosedError &&
        err.code === 'FAIL_CLOSED_86_INIT' &&
        err.detailCode === 'MANIFEST_SHA256_MISMATCH';
    }

    checks.push({
      checkId: 'MANIFEST_SHA256_AUTHENTICATED',
      title: 'External 86 Manifest SHA-256 Verified Against Independently Trusted Digest',
      passed: missingDigestBlocked && wrongDigestBlocked,
      measuredDetail: `missingDigestBlocked=${missingDigestBlocked} · wrongDigestBlocked=${wrongDigestBlocked}`,
    });

    // Check C: Run Multi-Identity Canary Access Tests and enforce strict isolation gate
    const canaryResults = runIsolatedCanaryAccessTests(path.join(zoneBOut, 'canary_runs'));
    const canaryGate = evaluateCanaryIsolationGate(canaryResults);
    const sameUidControlDetectedExposure = canaryResults.some(
      (c) =>
        c.principalKind === 'CLI_AGENT_SAME_UID' &&
        c.outcome === 'FAIL_EXPOSED_TO_IDENTITY'
    );

    // Also generate and test the ACTUAL exported standalone canary script for fail-closed behavior
    const exportedScripts = generateWorkstationStage0Scripts(config, manifest);
    const exportedProbePath = path.join(exportedScriptsDir, 'stage0-workstation-probe.mjs');
    const exportedCanaryPath = path.join(exportedScriptsDir, 'stage0-multi-identity-canary.mjs');
    fs.writeFileSync(exportedProbePath, exportedScripts.probeScriptMjs, 'utf8');
    fs.writeFileSync(exportedCanaryPath, exportedScripts.canaryScriptMjs, 'utf8');

    // Verify exported canary refuses to silently substitute current user when a nonexistent agent user is requested
    const canaryTestDir = path.join(zoneBOut, 'exported_canary_vault');
    fs.mkdirSync(canaryTestDir, { recursive: true });
    const fakeAgentRun = spawnSync(
      process.execPath,
      [
        exportedCanaryPath,
        '--vault-test-dir',
        canaryTestDir,
        '--agent-user',
        'chronos_nonexistent_agent_999',
      ],
      { encoding: 'utf8', timeout: 5000 }
    );
    let fakeAgentFailedClosed = false;
    try {
      const parsedFake = JSON.parse(fakeAgentRun.stdout || '{}') as {
        allProtectedIdentitiesDenied?: boolean;
        protectedIdentitiesUncertain?: number;
      };
      fakeAgentFailedClosed =
        fakeAgentRun.status !== 0 &&
        parsedFake.allProtectedIdentitiesDenied === false &&
        parsedFake.protectedIdentitiesUncertain === 1;
    } catch {
      fakeAgentFailedClosed = false;
    }

    checks.push({
      checkId: 'MULTI_IDENTITY_CANARY_STRICT_ENFORCEMENT',
      title: 'Strict Multi-Identity Canary Gate (All Protected Identities Denied + Unverified User Fails Closed)',
      passed:
        canaryGate.allProtectedIdentitiesDenied &&
        canaryGate.protectedIdentitiesTested === 2 &&
        sameUidControlDetectedExposure &&
        fakeAgentFailedClosed,
      measuredDetail: `protectedDenied=${canaryGate.protectedIdentitiesDenied}/${canaryGate.protectedIdentitiesTested} · sameUidControlExposed=${sameUidControlDetectedExposure} · nonexistentAgentFailedClosed=${fakeAgentFailedClosed}`,
    });

    // Check D: Execute full Stage 0 traversal on scratch Zone A (with REVOKED_CONVERSATION_ID active)
    const { report, telemetry } = executeStage0Discovery({
      config,
      manifestRawJson,
      expectedManifestSha256: trustedManifestSha256,
      evidenceOrigin: 'SANDBOX_SCRATCH_VERIFICATION',
      canaryResults,
      writeReportFileToZoneB: true,
    });

    const neverOpenedRevokedOrLinks =
      !telemetry.openedPaths.includes(revokedSecretFile) &&
      !telemetry.openedPaths.includes(exactRevokedFile) &&
      !telemetry.openedPaths.includes(globRevokedFile) &&
      !telemetry.openedPaths.includes(convIdFile) &&
      !telemetry.openedPaths.includes(knownMixedContainerFile) &&
      !telemetry.openedPaths.includes(escapeSymlink) &&
      !telemetry.openedPaths.includes(outsideTarget) &&
      !telemetry.openedPaths.includes(hardlinkAlias) &&
      !telemetry.openedPaths.includes(monoChatGptPath) &&
      !telemetry.openedPaths.includes(sqlitePath) &&
      !telemetry.openedPaths.includes(walSqlitePath);

    checks.push({
      checkId: 'ZERO_OPEN_ON_86_SYMLINK_HARDLINK',
      title: 'Zero open() Calls on All 86 Rule Kinds, Escape Symlink, Hardlink Alias & Quarantined Containers',
      passed:
        neverOpenedRevokedOrLinks &&
        report.securityAudit.reparseOrSymlinkSkippedCount === 1 &&
        report.securityAudit.hardlinkAliasBlockedCount === 1 &&
        report.securityAudit.pruned86ByRuleId['R86_SUBDIR_ALPHA'] === 1 &&
        report.securityAudit.pruned86ByRuleId['R86_EXACT_FILE'] === 1 &&
        report.securityAudit.pruned86ByRuleId['R86_GLOB_PRIVATE'] === 1 &&
        report.securityAudit.pruned86ByRuleId['R86_CONV_ID'] === 1 &&
        report.securityAudit.pruned86ByRuleId['R86_KNOWN_MIXED'] === 1,
      measuredDetail: `openedPaths=${telemetry.openedPaths.length} (clean files + ZIP TOC only) · symlinksSkipped=${report.securityAudit.reparseOrSymlinkSkippedCount} · hardlinkBlocked=${report.securityAudit.hardlinkAliasBlockedCount} · rulesFired=${Object.keys(report.securityAudit.pruned86ByRuleId).length}`,
    });

    // Check E: Mixed ZIP TOC + Monolithic JSON + SQLite Quarantine when REVOKED_CONVERSATION_ID rules exist
    const sqliteQuarantinedUnderConv86 =
      report.securityAudit.mixedContainerQuarantinedCount === 2 && // KNOWN_MIXED_CONTAINER + mixed ZIP
      report.securityAudit.potentialMixedUnscannedCount === 3 && // conversations.json + harness_jobs.sqlite + wal_ledger.sqlite
      report.reuseInventory.sqliteLedgersInspected.length === 0;

    checks.push({
      checkId: 'MIXED_ARCHIVE_AND_SQLITE_QUARANTINE',
      title: 'Mixed ZIP TOC, Monolithic JSON & SQLite Quarantined Unscanned Under Conversation-Level 86 Rules',
      passed: sqliteQuarantinedUnderConv86,
      measuredDetail: `mixedQuarantined=${report.securityAudit.mixedContainerQuarantinedCount} · potentialMixedUnscanned=${report.securityAudit.potentialMixedUnscannedCount} · sqliteDdlOpenedUnderConv86=${report.reuseInventory.sqliteLedgersInspected.length}`,
    });

    // Check F: When NO conversation-level 86 rules exist, clean rollback-journal SQLite immutable DDL
    // inspection runs cleanly while WAL-mode SQLite is quarantined unscanned, with zero -wal/-shm
    // sidecars and zero byte mutations in Zone A
    const noConvManifest: External86Manifest = {
      ...manifest,
      manifestId: 'MANIFEST_SANDBOX_NO_CONV_86',
      rules: manifest.rules.filter((r) => r.kind !== 'REVOKED_CONVERSATION_ID'),
    };
    const noConvManifestRaw = JSON.stringify(noConvManifest, null, 2);
    const noConvRun = executeStage0Discovery({
      config,
      manifestRawJson: noConvManifestRaw,
      expectedManifestSha256: sha256Hex(noConvManifestRaw),
      evidenceOrigin: 'SANDBOX_SCRATCH_VERIFICATION',
      writeReportFileToZoneB: false,
    });

    const sqliteDirAfter = fs.readdirSync(sqliteDir).sort();
    const sqliteHashAfter = fs.readFileSync(sqlitePath);
    const walSqliteHashAfter = fs.readFileSync(walSqlitePath);
    const inspectedTables = noConvRun.report.reuseInventory.sqliteLedgersInspected.map(
      (s) => s.tableName
    );
    const zoneAUntouched =
      JSON.stringify(sqliteDirBefore) === JSON.stringify(sqliteDirAfter) &&
      Buffer.compare(sqliteHashBefore, sqliteHashAfter) === 0 &&
      Buffer.compare(walSqliteHashBefore, walSqliteHashAfter) === 0 &&
      noConvRun.report.reuseInventory.sqliteLedgersInspected.length === 1 &&
      inspectedTables.includes('closeout_sessions') &&
      !inspectedTables.includes('active_events') &&
      noConvRun.report.securityAudit.potentialMixedUnscannedCount >= 1;

    checks.push({
      checkId: 'ZONE_A_SQLITE_IMMUTABILITY',
      title: 'Zone A Read-Only SQLite DDL Inspection When Cleared (WAL Quarantined + Zero Sidecars or Byte Mutations)',
      passed: zoneAUntouched,
      measuredDetail: `Zone A files=${sqliteDirAfter.join(',')} · DDL tables=${inspectedTables.join(',')} · walQuarantined=${noConvRun.report.securityAudit.potentialMixedUnscannedCount} · Row payloads read=0`,
    });

    // Check G: Independently execute the ACTUAL exported standalone workstation probe in /tmp
    // (outside repo / zero node_modules) and verify fail-closed parity + identical sanitized output
    const exportedConfigPath = path.join(zoneBExportedRunnerOut, 'stage0-config.json');
    const exportedConfig: Stage0Config = {
      ...config,
      zoneBOutputDir: zoneBExportedRunnerOut,
    };
    fs.writeFileSync(exportedConfigPath, JSON.stringify(exportedConfig, null, 2), 'utf8');

    // G1: Exported runner MUST fail closed without expected SHA-256
    const probeMissingSha = spawnSync(
      process.execPath,
      [exportedProbePath, '--config', exportedConfigPath],
      { encoding: 'utf8', cwd: exportedScriptsDir, timeout: 8000 }
    );
    // G2: Exported runner MUST fail closed with wrong SHA-256
    const probeWrongSha = spawnSync(
      process.execPath,
      [exportedProbePath, '--config', exportedConfigPath, '--expected-manifest-sha256', 'f'.repeat(64)],
      { encoding: 'utf8', cwd: exportedScriptsDir, timeout: 8000 }
    );
    // G3: Exported runner MUST succeed with valid trusted SHA-256 and match main engine parity
    const probeValidRun = spawnSync(
      process.execPath,
      [
        exportedProbePath,
        '--config',
        exportedConfigPath,
        '--expected-manifest-sha256',
        trustedManifestSha256,
      ],
      { encoding: 'utf8', cwd: exportedScriptsDir, timeout: 8000 }
    );

    let exportedParityOk = false;
    let exportedReportAuditValid = false;
    if (probeValidRun.status === 0) {
      const exportedReportFile = path.join(zoneBExportedRunnerOut, 'stage0-sanitized-report.json');
      if (fs.existsSync(exportedReportFile)) {
        const exportedReport = JSON.parse(
          fs.readFileSync(exportedReportFile, 'utf8')
        ) as SanitizedStage0Report;
        exportedReportAuditValid = auditSanitizedStage0Report(exportedReport).valid;
        exportedParityOk =
          exportedReportAuditValid &&
          exportedReport.securityAudit.manifestSha256 === report.securityAudit.manifestSha256 &&
          exportedReport.securityAudit.manifestIntegrityVerified === true &&
          JSON.stringify(exportedReport.securityAudit.pruned86ByRuleId) ===
            JSON.stringify(report.securityAudit.pruned86ByRuleId) &&
          exportedReport.securityAudit.reparseOrSymlinkSkippedCount ===
            report.securityAudit.reparseOrSymlinkSkippedCount &&
          exportedReport.securityAudit.hardlinkAliasBlockedCount ===
            report.securityAudit.hardlinkAliasBlockedCount &&
          exportedReport.securityAudit.mixedContainerQuarantinedCount ===
            report.securityAudit.mixedContainerQuarantinedCount &&
          exportedReport.securityAudit.potentialMixedUnscannedCount ===
            report.securityAudit.potentialMixedUnscannedCount &&
          exportedReport.reuseInventory.sqliteLedgersInspected.length ===
            report.reuseInventory.sqliteLedgersInspected.length &&
          JSON.stringify(exportedReport.formatInventory) ===
            JSON.stringify(report.formatInventory);
      }
    }

    checks.push({
      checkId: 'EXPORTED_WORKSTATION_RUNNER_PARITY',
      title: 'Independent Subprocess Proof of Exported Standalone Workstation Runner Parity',
      passed:
        probeMissingSha.status !== 0 &&
        probeWrongSha.status !== 0 &&
        probeValidRun.status === 0 &&
        exportedParityOk,
      measuredDetail: `missingShaExit=${probeMissingSha.status} · wrongShaExit=${probeWrongSha.status} · validExit=${probeValidRun.status} · sanitized=${exportedReportAuditValid} · exactParity=${exportedParityOk}`,
    });

    // Check H: Verify Zero-Leak Sanitizer rejects injected secret / raw path
    const poisonedClone = {
      ...report,
      leakedSecretField: 'sk-1234567890abcdefghijklmnop',
    };
    const poisonAudit = auditSanitizedStage0Report(poisonedClone);
    checks.push({
      checkId: 'SANITIZER_BLOCKS_SECRETS_AND_TEXT',
      title: 'Zero-Leak Sanitizer Rejects Secrets, Transcript Keys & Raw Paths',
      passed: !poisonAudit.valid && poisonAudit.violations.length >= 2,
      measuredDetail: `Rejected poisoned payload with ${poisonAudit.violations.length} violation(s): ${poisonAudit.violations[0]}`,
    });

    return {
      executedAtIso: new Date().toISOString(),
      environmentBanner: 'ISOLATED_CONTAINER_SCRATCH_SANDBOX_NOT_WORKSTATION',
      scratchBacking: {
        isRamBacked: scratch.ramCheck.isRamBacked,
        backingFsType: scratch.ramCheck.backingFsType,
        mountPoint: scratch.ramCheck.mountPoint,
        verifiedByKernel: scratch.ramCheck.verifiedByKernel,
      },
      allPassed: checks.every((c) => c.passed),
      checks,
      generatedReport: report,
    };
  } finally {
    scratch.cleanup();
  }
}
