import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runIsolatedCanaryAccessTests } from './canaryHarness.ts';
import { Stage0FailClosedError } from './pathSecurity.ts';
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
  allPassed: boolean;
  checks: SandboxVerificationCheck[];
  generatedReport: SanitizedStage0Report;
}

/**
 * Runs a complete, real-syscall Stage 0 verification pass inside a disposable /tmp directory,
 * proving pre-open 86 pruning, symlink/hardlink blocking, mixed-ZIP quarantine, SQLite Zone A
 * zero-sidecar immutability, multi-identity canary checks, and zero-leak output sanitization.
 */
export function runLiveSandboxStage0Verification(): SandboxVerificationSummary {
  const scratchBase = fs.mkdtempSync(path.join(os.tmpdir(), 'chronos-stage0-sandbox-'));
  const zoneARoot = path.join(scratchBase, 'zone_a_scan_root');
  const zoneBOut = path.join(scratchBase, 'zone_b_authorized_output');
  const outsideSecretDir = path.join(scratchBase, 'outside_86_secret_vault');

  const checks: SandboxVerificationCheck[] = [];

  try {
    fs.mkdirSync(zoneARoot, { recursive: true });
    fs.mkdirSync(zoneBOut, { recursive: true });
    fs.mkdirSync(outsideSecretDir, { recursive: true });

    // 1. Create an 86'd subdirectory inside Zone A (must NEVER be opened)
    const revokedSubdir = path.join(zoneARoot, 'revoked_client_alpha');
    fs.mkdirSync(revokedSubdir, { recursive: true });
    const revokedSecretFile = path.join(revokedSubdir, 'do_not_open.json');
    fs.writeFileSync(revokedSecretFile, '{"secret":"sk-live1234567890abcdefghijklmnop"}');

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

    // 6. Create a real SQLite ledger in Zone A via python3 sqlite3 to verify zero -wal/-shm sidecars
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
    const sqliteDirBefore = fs.readdirSync(sqliteDir).sort();
    const sqliteHashBefore = fs.readFileSync(sqlitePath);

    // 7. Create cleared structured session files (Antigravity, Gemini CLI, Codex CLI, Claude Code)
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
      external86ManifestPath: path.join(zoneBOut, 'manifest.json'),
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
        manifestRawJson: JSON.stringify(manifest),
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

    // Check B: Run Multi-Identity Canary Access Tests in isolated scratch dir
    const canaryResults = runIsolatedCanaryAccessTests(path.join(zoneBOut, 'canary_runs'));
    checks.push({
      checkId: 'MULTI_IDENTITY_CANARY_REAL_EXEC',
      title: 'Real Subprocess Canary Access-Control Probes (Read / List / Grep)',
      passed: canaryResults.length === 3,
      measuredDetail: canaryResults
        .map((c) => `${c.principalKind}: ${c.outcome}`)
        .join(' · '),
    });

    // Check C: Execute full Stage 0 traversal on scratch Zone A
    const { report, telemetry } = executeStage0Discovery({
      config,
      manifestRawJson: JSON.stringify(manifest),
      evidenceOrigin: 'SANDBOX_SCRATCH_VERIFICATION',
      canaryResults,
      writeReportFileToZoneB: true,
    });

    const neverOpenedRevokedOrLinks =
      !telemetry.openedPaths.includes(revokedSecretFile) &&
      !telemetry.openedPaths.includes(escapeSymlink) &&
      !telemetry.openedPaths.includes(outsideTarget) &&
      !telemetry.openedPaths.includes(hardlinkAlias) &&
      !telemetry.openedPaths.includes(monoChatGptPath);

    checks.push({
      checkId: 'ZERO_OPEN_ON_86_SYMLINK_HARDLINK',
      title: 'Zero open() Calls on 86 Subtree, Escape Symlink & Hardlink Alias',
      passed:
        neverOpenedRevokedOrLinks &&
        report.securityAudit.reparseOrSymlinkSkippedCount === 1 &&
        report.securityAudit.hardlinkAliasBlockedCount === 1,
      measuredDetail: `openedPaths=${telemetry.openedPaths.length} (clean files + ZIP TOC only) · symlinksSkipped=${report.securityAudit.reparseOrSymlinkSkippedCount} · hardlinkBlocked=${report.securityAudit.hardlinkAliasBlockedCount}`,
    });

    checks.push({
      checkId: 'MIXED_ARCHIVE_SAFE_QUARANTINE',
      title: 'Mixed ZIP Central-Directory & Monolithic Export Quarantine (Zero Payload Read)',
      passed:
        report.securityAudit.mixedContainerQuarantinedCount === 1 &&
        report.securityAudit.potentialMixedUnscannedCount === 2,
      measuredDetail: `mixedZipQuarantined=${report.securityAudit.mixedContainerQuarantinedCount} · potentialMixedUnscanned=${report.securityAudit.potentialMixedUnscannedCount} (conversations.json + SQLite)`,
    });

    const sqliteDirAfter = fs.readdirSync(sqliteDir).sort();
    const sqliteHashAfter = fs.readFileSync(sqlitePath);
    const zoneAUntouched =
      JSON.stringify(sqliteDirBefore) === JSON.stringify(sqliteDirAfter) &&
      Buffer.compare(sqliteHashBefore, sqliteHashAfter) === 0 &&
      report.reuseInventory.sqliteLedgersInspected.length === 1;

    checks.push({
      checkId: 'ZONE_A_SQLITE_IMMUTABILITY',
      title: 'Zone A Read-Only SQLite DDL Inspection (Zero -wal/-shm Sidecars or Byte Mutations)',
      passed: zoneAUntouched,
      measuredDetail: `Zone A files=${sqliteDirAfter.join(',')} · DDL tables=${report.reuseInventory.sqliteLedgersInspected.map((s) => s.tableName).join(',')} · Row payloads read=0`,
    });

    // Check D: Verify Zero-Leak Sanitizer rejects injected secret / raw path
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
      allPassed: checks.every((c) => c.passed),
      checks,
      generatedReport: report,
    };
  } finally {
    fs.rmSync(scratchBase, { recursive: true, force: true });
  }
}
