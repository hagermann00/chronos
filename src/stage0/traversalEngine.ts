import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  evaluatePreOpen86Rules,
  matchArchiveEntryAgainst86,
  Stage0FailClosedError,
  validateStage0Preconditions,
} from './pathSecurity.ts';
import { assertSanitizedStage0Report } from './sanitizer.ts';
import type {
  External86Manifest,
  FormatInventoryRecord,
  MultiIdentityCanaryResult,
  SanitizedStage0Report,
  SqliteTableSchemaSummary,
  Stage0Config,
  VendorEcosystemId,
} from './types.ts';

export interface TraversalTelemetry {
  readdirCalls: number;
  lstatCalls: number;
  openCalls: number;
  openedPaths: string[];
}

const ALL_ECOSYSTEMS: VendorEcosystemId[] = [
  'antigravity',
  'gemini_cli',
  'codex_cli',
  'claude_code',
  'gemini_web',
  'chatgpt_openai',
  'claude_web',
  'manus',
  'grok',
  'deepseek',
  'unknown_structured',
];

/**
 * Inspects a .zip file's End-of-Central-Directory (EOCD) and Central Directory headers
 * strictly from the tail of the file WITHOUT inflating or reading any entry payload bytes.
 * Fails closed (quarantined=true) on encrypted entries, malformed headers, or any 86 entry match.
 */
function inspectZipCentralDirectoryHeadersOnly(
  fd: number,
  fileSize: number,
  manifest: External86Manifest
): {
  status: 'CLEAN_TOC' | 'MIXED_OR_UNCERTAIN_QUARANTINED';
  matchedRuleId?: string;
  entryCount: number;
} {
  // Minimum valid ZIP EOCD is 22 bytes
  if (fileSize < 22) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: 0 };
  }

  const tailLen = Math.min(fileSize, 65557);
  const tailBuf = Buffer.alloc(tailLen);
  const bytesRead = fs.readSync(fd, tailBuf, 0, tailLen, fileSize - tailLen);
  if (bytesRead < 22) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: 0 };
  }

  // Locate EOCD signature 0x06054b50 from end
  let eocdOffset = -1;
  for (let i = bytesRead - 22; i >= 0; i--) {
    if (tailBuf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: 0 };
  }

  const totalEntries = tailBuf.readUInt16LE(eocdOffset + 10);
  const cdSize = tailBuf.readUInt32LE(eocdOffset + 12);
  const cdOffset = tailBuf.readUInt32LE(eocdOffset + 16);

  // Reject ZIP64 sentinel or out-of-bounds central directory as uncertain (fail closed)
  if (
    totalEntries === 0xffff ||
    cdSize === 0xffffffff ||
    cdOffset === 0xffffffff ||
    cdOffset + cdSize > fileSize ||
    cdSize > 16 * 1024 * 1024
  ) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: 0 };
  }

  const cdBuf = Buffer.alloc(cdSize);
  const cdRead = fs.readSync(fd, cdBuf, 0, cdSize, cdOffset);
  if (cdRead !== cdSize) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: 0 };
  }

  let cursor = 0;
  let parsedEntries = 0;
  while (cursor + 46 <= cdSize && parsedEntries < totalEntries) {
    const sig = cdBuf.readUInt32LE(cursor);
    if (sig !== 0x02014b50) {
      return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: parsedEntries };
    }
    const gpBitFlag = cdBuf.readUInt16LE(cursor + 8);
    // Bit 0 = encrypted entry -> fail closed!
    if ((gpBitFlag & 0x0001) !== 0) {
      return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: parsedEntries };
    }

    const nameLen = cdBuf.readUInt16LE(cursor + 28);
    const extraLen = cdBuf.readUInt16LE(cursor + 30);
    const commentLen = cdBuf.readUInt16LE(cursor + 32);

    if (cursor + 46 + nameLen + extraLen + commentLen > cdSize) {
      return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: parsedEntries };
    }

    const entryName = cdBuf.subarray(cursor + 46, cursor + 46 + nameLen).toString('utf8');
    const ruleHit = matchArchiveEntryAgainst86(entryName, manifest.rules);
    if (ruleHit.matched) {
      return {
        status: 'MIXED_OR_UNCERTAIN_QUARANTINED',
        matchedRuleId: ruleHit.ruleId,
        entryCount: parsedEntries,
      };
    }

    cursor += 46 + nameLen + extraLen + commentLen;
    parsedEntries += 1;
  }

  if (parsedEntries !== totalEntries) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: parsedEntries };
  }

  return { status: 'CLEAN_TOC', entryCount: parsedEntries };
}

/**
 * Queries SQLite DDL strictly via read-only immutable URI (`mode=ro&immutable=1`)
 * so zero `-wal`, `-shm`, or `-journal` files are ever created in Zone A.
 * Never executes SELECT on user data payloads (only sqlite_master structural schema).
 */
export function inspectSqliteSchemaImmutableReadOnly(
  sqlitePath: string,
  ledgerAlias: string
): SqliteTableSchemaSummary[] | null {
  try {
    const pyScript = `
import json, sqlite3, sys, urllib.parse
p = sys.argv[1]
uri = "file:" + urllib.parse.quote(p) + "?mode=ro&immutable=1"
conn = sqlite3.connect(uri, uri=True)
cur = conn.cursor()
tables = cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
out = []
for (tname,) in tables:
    safe_ident = tname.replace('"', '""')
    cols = cur.execute(f'PRAGMA table_info("{safe_ident}")').fetchall()
    idxs = cur.execute(f'PRAGMA index_list("{safe_ident}")').fetchall()
    out.append({
        "tableName": str(tname)[:80],
        "columns": [{"name": str(c[1])[:80], "declaredType": str(c[2] or "ANY")[:40]} for c in cols],
        "indexNames": [str(ix[1])[:80] for ix in idxs],
    })
conn.close()
print(json.dumps(out))
`.trim();

    const stdout = execFileSync('python3', ['-c', pyScript, sqlitePath], {
      encoding: 'utf8',
      timeout: 4000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const parsed = JSON.parse(stdout) as Array<{
      tableName: string;
      columns: Array<{ name: string; declaredType: string }>;
      indexNames: string[];
    }>;

    return parsed.map((t) => ({
      ledgerAlias,
      tableName: t.tableName,
      columns: t.columns,
      indexNames: t.indexNames,
      approximateRowCount: null, // Deliberately omitted to avoid reading table b-tree data pages
      openedImmutableReadOnly: true,
    }));
  } catch {
    return null;
  }
}

/**
 * Structural-only header signature sniffer (<= 2048 bytes read, immediately discarded).
 * Identifies likely vendor format from structural JSON keys WITHOUT retaining any text values.
 */
function classifyHeaderSignatureOnly(
  headerSlice: string,
  ext: string
): {
  ecosystem: VendorEcosystemId;
  hasExplicitEventTimestamps: boolean | 'UNKNOWN';
} {
  const hasSubagentKeys =
    headerSlice.includes('"subagent_id"') ||
    headerSlice.includes('"parent_agent_id"') ||
    headerSlice.includes('"antigravity"');
  if (hasSubagentKeys) {
    return {
      ecosystem: 'antigravity',
      hasExplicitEventTimestamps: headerSlice.includes('"timestamp"') || headerSlice.includes('"created_at"'),
    };
  }

  if (
    headerSlice.includes('"parentUuid"') &&
    (headerSlice.includes('"cwd"') || headerSlice.includes('"toolUseResult"'))
  ) {
    return {
      ecosystem: 'claude_code',
      hasExplicitEventTimestamps: headerSlice.includes('"timestamp"'),
    };
  }

  if (
    headerSlice.includes('"codex"') ||
    (ext === '.jsonl' && headerSlice.includes('"call_id"') && headerSlice.includes('"type":"function_call"'))
  ) {
    return {
      ecosystem: 'codex_cli',
      hasExplicitEventTimestamps: headerSlice.includes('"timestamp"') || headerSlice.includes('"created_at"'),
    };
  }

  if (
    headerSlice.includes('"gemini_cli"') ||
    (headerSlice.includes('"sessionId"') && headerSlice.includes('"thoughts"'))
  ) {
    return {
      ecosystem: 'gemini_cli',
      hasExplicitEventTimestamps: headerSlice.includes('"timestamp"'),
    };
  }

  if (headerSlice.includes('"mapping"') && headerSlice.includes('"current_node"')) {
    return {
      ecosystem: 'chatgpt_openai',
      hasExplicitEventTimestamps: headerSlice.includes('"create_time"'),
    };
  }

  if (headerSlice.includes('"chat_messages"') && headerSlice.includes('"sender"')) {
    return {
      ecosystem: 'claude_web',
      hasExplicitEventTimestamps: headerSlice.includes('"created_at"'),
    };
  }

  if (headerSlice.includes('"reasoning_content"')) {
    return {
      ecosystem: 'deepseek',
      hasExplicitEventTimestamps: headerSlice.includes('"inserted_at"') || headerSlice.includes('"created_at"'),
    };
  }

  if (headerSlice.includes('"task_steps"') && headerSlice.includes('"manus"')) {
    return {
      ecosystem: 'manus',
      hasExplicitEventTimestamps: headerSlice.includes('"timestamp"'),
    };
  }

  if (headerSlice.includes('"grok"') && headerSlice.includes('"conversations"')) {
    return {
      ecosystem: 'grok',
      hasExplicitEventTimestamps: headerSlice.includes('"create_time"'),
    };
  }

  if (headerSlice.includes('"gemini"') && headerSlice.includes('"parts"')) {
    return {
      ecosystem: 'gemini_web',
      hasExplicitEventTimestamps: 'UNKNOWN',
    };
  }

  return {
    ecosystem: 'unknown_structured',
    hasExplicitEventTimestamps: 'UNKNOWN',
  };
}

function binaryExistsInPath(binName: string): boolean {
  try {
    execFileSync('which', [binName], { stdio: 'ignore', timeout: 1500 });
    return true;
  } catch {
    return false;
  }
}

export interface ExecuteStage0Options {
  config: Stage0Config;
  manifestRawJson: string;
  evidenceOrigin: SanitizedStage0Report['evidenceOrigin'];
  canaryResults?: MultiIdentityCanaryResult[];
  writeReportFileToZoneB?: boolean;
}

export function executeStage0Discovery(options: ExecuteStage0Options): {
  report: SanitizedStage0Report;
  serializedReportJson: string;
  telemetry: TraversalTelemetry;
  writtenReportPath?: string;
} {
  const telemetry: TraversalTelemetry = {
    readdirCalls: 0,
    lstatCalls: 0,
    openCalls: 0,
    openedPaths: [],
  };

  // Precondition Step 1: Parse & hash external 86 manifest BEFORE touching scan roots
  let manifest: External86Manifest;
  try {
    manifest = JSON.parse(options.manifestRawJson) as External86Manifest;
  } catch {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      'MANIFEST_JSON_PARSE_ERROR',
      'External 86 manifest is not valid JSON; failing closed before traversal.'
    );
  }
  const manifestSha256 = crypto
    .createHash('sha256')
    .update(options.manifestRawJson, 'utf8')
    .digest('hex');

  // Precondition Step 2: Validate scan_roots_allowlist, Zone B disjointness, and 86 rules
  const { normalizedRoots } = validateStage0Preconditions(options.config, manifest);

  // Build fast lookup sets for hardlink inode protection & conversation-level mixed container checks
  const revokedPosixDevInos = new Set<string>(
    manifest.rules
      .filter((r) => r.kind === 'POSIX_DEV_INO')
      .map((r) => r.targetValue)
  );
  const hasConversationLevel86Rules = manifest.rules.some(
    (r) => r.kind === 'REVOKED_CONVERSATION_ID'
  );

  const pruned86ByRuleId: Record<string, number> = {};
  const record86Hit = (ruleId: string) => {
    const safeKey = /^[A-Za-z0-9_-]{2,40}$/.test(ruleId)
      ? ruleId
      : 'OPAQUE_RULE_HIT';
    pruned86ByRuleId[safeKey] = (pruned86ByRuleId[safeKey] ?? 0) + 1;
  };

  let reparseOrSymlinkSkippedCount = 0;
  let mountCrossingSkippedCount = 0;
  let hardlinkAliasBlockedCount = 0;
  const cloudPlaceholderSkippedCount = 0;
  let mixedContainerQuarantinedCount = 0;
  let potentialMixedUnscannedCount = 0;
  let failClosedUncertainCount = 0;
  let ggufHeaderCount = 0;

  const sqliteSchemas: SqliteTableSchemaSummary[] = [];
  let sqliteIdx = 1;

  const formatMap = new Map<
    VendorEcosystemId,
    {
      files: number;
      bytes: number;
      containers: number;
      hasTimestamps: boolean | 'UNKNOWN';
      mixedRisks: number;
    }
  >();
  for (const eco of ALL_ECOSYSTEMS) {
    formatMap.set(eco, {
      files: 0,
      bytes: 0,
      containers: 0,
      hasTimestamps: 'UNKNOWN',
      mixedRisks: 0,
    });
  }

  // Step 3: Walk ONLY allowlisted roots using lstat (no-follow)
  for (const root of normalizedRoots) {
    telemetry.lstatCalls += 1;
    let rootStat: fs.Stats;
    try {
      rootStat = fs.lstatSync(root.absolutePath);
    } catch {
      failClosedUncertainCount += 1;
      continue;
    }

    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
      // Never traverse a scan root that is itself a symlink/reparse point or non-directory
      reparseOrSymlinkSkippedCount += 1;
      continue;
    }

    const rootDirDev = rootStat.dev;
    // Also inspect /proc/self/mountinfo on Linux to catch both directory and single-file bind mounts
    // without false positives on overlayfs (where upperdir files and overlay dirs have distinct st_dev).
    const submountPaths = new Set<string>();
    try {
      if (fs.existsSync('/proc/self/mountinfo')) {
        const minfo = fs.readFileSync('/proc/self/mountinfo', 'utf8');
        const rootPrefix = root.absolutePath.endsWith('/')
          ? root.absolutePath
          : root.absolutePath + '/';
        for (const line of minfo.split('\n')) {
          const parts = line.split(' ');
          if (parts.length >= 5) {
            const mountPoint = parts[4].replace(/\\040/g, ' ');
            if (mountPoint.startsWith(rootPrefix)) {
              submountPaths.add(mountPoint);
            }
          }
        }
      }
    } catch {
      // Non-Linux host; directory st_dev check still applies
    }

    const queue: string[] = [root.absolutePath];

    while (queue.length > 0) {
      const currentDir = queue.shift()!;

      // Check directory against 86 rules BEFORE readdir
      const dirPreCheck = evaluatePreOpen86Rules({
        candidatePath: currentDir,
        entryName: path.basename(currentDir),
        mode: root.expectedFsMode,
        ntfsCaseSensitiveDir: root.ntfsCaseSensitiveDir,
        rules: manifest.rules,
      });
      if (dirPreCheck.matched) {
        record86Hit(dirPreCheck.ruleId ?? 'R86_DIR_HIT');
        continue;
      }

      let entries: string[];
      try {
        telemetry.readdirCalls += 1;
        entries = fs.readdirSync(currentDir);
      } catch {
        // EACCES / EPERM / uncertain directory permissions -> fail closed immediately!
        failClosedUncertainCount += 1;
        continue;
      }

      for (const entryName of entries) {
        const fullPath = path.join(currentDir, entryName);

        // Stage-0 Barrier Step A: Path/name/glob/mixed-container check BEFORE lstat/open
        const nameGate = evaluatePreOpen86Rules({
          candidatePath: fullPath,
          entryName,
          mode: root.expectedFsMode,
          ntfsCaseSensitiveDir: root.ntfsCaseSensitiveDir,
          rules: manifest.rules,
        });
        if (nameGate.matched) {
          if (nameGate.matchedKind === 'KNOWN_MIXED_CONTAINER') {
            mixedContainerQuarantinedCount += 1;
          }
          record86Hit(nameGate.ruleId ?? 'R86_PATH_HIT');
          continue;
        }

        // Stage-0 Barrier Step B: Non-following lstat()
        let st: fs.Stats;
        try {
          telemetry.lstatCalls += 1;
          st = fs.lstatSync(fullPath);
        } catch {
          failClosedUncertainCount += 1;
          continue;
        }

        // Never follow symlinks / reparse links
        if (st.isSymbolicLink()) {
          reparseOrSymlinkSkippedCount += 1;
          continue;
        }

        // Block unexpected mount-point / bind-mount crossings
        if (submountPaths.has(fullPath) || (st.isDirectory() && st.dev !== rootDirDev)) {
          mountCrossingSkippedCount += 1;
          continue;
        }

        const posixDevIno = `${st.dev}:${st.ino}`;

        // Block hardlink aliases pointing to an 86'd (dev, ino)
        if (revokedPosixDevInos.has(posixDevIno)) {
          if (st.nlink > 1) {
            hardlinkAliasBlockedCount += 1;
          }
          const inoHit = evaluatePreOpen86Rules({
            candidatePath: fullPath,
            entryName,
            mode: root.expectedFsMode,
            posixDevIno,
            rules: manifest.rules,
          });
          record86Hit(inoHit.ruleId ?? 'R86_INODE_HIT');
          continue;
        }

        // Fail closed if hardlink count > 1 and identity could alias outside scan root
        if (st.isFile() && st.nlink > 1) {
          hardlinkAliasBlockedCount += 1;
          continue;
        }

        if (st.isDirectory()) {
          queue.push(fullPath);
          continue;
        }

        if (!st.isFile()) {
          // FIFOs, sockets, device nodes -> skip safely
          failClosedUncertainCount += 1;
          continue;
        }

        // Check owner read bit before attempting open; fail closed if unreadable
        if ((st.mode & 0o444) === 0) {
          failClosedUncertainCount += 1;
          continue;
        }

        const ext = path.extname(entryName).toLowerCase();

        if (ext === '.gguf') {
          ggufHeaderCount += 1;
          continue;
        }

        // Mixed-Container Rule 1: ZIP archives — inspect Central Directory headers ONLY
        if (ext === '.zip') {
          let fd: number | null = null;
          try {
            telemetry.openCalls += 1;
            telemetry.openedPaths.push(fullPath);
            fd = fs.openSync(fullPath, fs.constants.O_RDONLY);
            const zipRes = inspectZipCentralDirectoryHeadersOnly(fd, st.size, manifest);
            if (zipRes.status === 'MIXED_OR_UNCERTAIN_QUARANTINED') {
              mixedContainerQuarantinedCount += 1;
              if (zipRes.matchedRuleId) {
                record86Hit(zipRes.matchedRuleId);
              }
            }
          } catch {
            failClosedUncertainCount += 1;
          } finally {
            if (fd !== null) fs.closeSync(fd);
          }
          continue;
        }

        // Mixed-Container Rule 2: SQLite ledgers — immutable DDL inspection ONLY (zero row reads)
        if (ext === '.sqlite' || ext === '.sqlite3' || ext === '.db') {
          if (hasConversationLevel86Rules) {
            potentialMixedUnscannedCount += 1;
          }
          const alias = `LEDGER_${String(sqliteIdx).padStart(2, '0')}`;
          sqliteIdx += 1;
          const ddl = inspectSqliteSchemaImmutableReadOnly(fullPath, alias);
          if (ddl === null) {
            failClosedUncertainCount += 1;
          } else {
            sqliteSchemas.push(...ddl);
          }
          continue;
        }

        // Mixed-Container Rule 3: Monolithic multi-conversation JSON when conversation-level 86 IDs exist
        const lowerName = entryName.toLowerCase();
        const looksMonolithicMultiConv =
          lowerName === 'conversations.json' ||
          lowerName.includes('export') ||
          lowerName.includes('takeout');
        if (hasConversationLevel86Rules && looksMonolithicMultiConv) {
          potentialMixedUnscannedCount += 1;
          const chatgptSlot = formatMap.get('chatgpt_openai')!;
          chatgptSlot.mixedRisks += 1;
          continue;
        }

        // Cleared structured JSON / JSONL file: read <= 2048-byte header slice ONLY for structural keys
        if (ext === '.json' || ext === '.jsonl') {
          let fd: number | null = null;
          try {
            telemetry.openCalls += 1;
            telemetry.openedPaths.push(fullPath);
            fd = fs.openSync(fullPath, fs.constants.O_RDONLY);
            const sliceLen = Math.min(st.size, 2048);
            const buf = Buffer.alloc(sliceLen);
            const readBytes = fs.readSync(fd, buf, 0, sliceLen, 0);
            const headerStr = buf.subarray(0, readBytes).toString('utf8');
            const sig = classifyHeaderSignatureOnly(headerStr, ext);
            const bucket = formatMap.get(sig.ecosystem)!;
            bucket.files += 1;
            bucket.bytes += st.size;
            bucket.containers += 1;
            if (sig.hasExplicitEventTimestamps !== 'UNKNOWN') {
              bucket.hasTimestamps = sig.hasExplicitEventTimestamps;
            }
          } catch {
            failClosedUncertainCount += 1;
          } finally {
            if (fd !== null) fs.closeSync(fd);
          }
        }
      }
    }
  }

  // Probe optional Universal Harness paths (existence & entrypoint count only, read-only)
  let universalHarnessDetected = false;
  let universalHarnessEntrypointsCount = 0;
  for (const hp of options.config.universalHarnessProbePaths ?? []) {
    try {
      const hStat = fs.lstatSync(hp);
      if (!hStat.isSymbolicLink() && (hStat.isDirectory() || hStat.isFile())) {
        universalHarnessDetected = true;
        universalHarnessEntrypointsCount += 1;
      }
    } catch {
      // Not present
    }
  }

  const formatInventory: FormatInventoryRecord[] = ALL_ECOSYSTEMS.map((eco) => {
    const b = formatMap.get(eco)!;
    return {
      ecosystem: eco,
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: b.files,
      nonQuarantinedBytes: b.bytes,
      estimatedContainerCount: b.containers,
      hasExplicitEventTimestamps: b.hasTimestamps,
      mixedArchiveRiskCount: b.mixedRisks,
      existingHarnessReuseDetected:
        universalHarnessDetected &&
        (eco === 'antigravity' || eco === 'gemini_cli' || eco === 'codex_cli'),
    };
  });

  const reuseAssessmentCode: SanitizedStage0Report['reuseInventory']['reuseAssessmentCode'] =
    options.evidenceOrigin === 'UNINSPECTED_NO_REPORT'
      ? 'PENDING_WORKSTATION_EVIDENCE'
      : universalHarnessDetected
        ? 'CANDIDATE_HARNESS_EXTENSION'
        : sqliteSchemas.length > 0
          ? 'CANDIDATE_MODULAR_COMPANION'
          : 'CANDIDATE_MINIMAL_CORE';

  const report: SanitizedStage0Report = {
    schemaVersion: '1.0.0',
    stage: 'STAGE_0_READ_ONLY_DISCOVERY',
    evidenceOrigin: options.evidenceOrigin,
    generatedAtIso: new Date().toISOString(),
    hostProfile: {
      osPlatform: os.platform(),
      osRelease: os.release().slice(0, 48),
      cpuCores: os.cpus().length,
      totalMemBytes: os.totalmem(),
      freeMemBytes: os.freemem(),
      gpuSummary: {
        detectionState: binaryExistsInPath('nvidia-smi') ? 'DETECTED' : 'NONE_DETECTED',
        devices: [],
      },
      llamaCppStatus: {
        serverBinaryPresent: binaryExistsInPath('llama-server'),
        cliBinaryPresent: binaryExistsInPath('llama-cli'),
        versionTag: 'NONE_DETECTED',
        ggufHeaderCount,
      },
      gcloudCliPresent: binaryExistsInPath('gcloud'),
      rootFilesystems: normalizedRoots.map((r) => ({
        rootAlias: r.alias,
        fsMode: r.expectedFsMode,
      })),
    },
    securityAudit: {
      allowlistRootCount: normalizedRoots.length,
      manifestId: manifest.manifestId,
      manifestSha256,
      pruned86ByRuleId,
      reparseOrSymlinkSkippedCount,
      mountCrossingSkippedCount,
      hardlinkAliasBlockedCount,
      cloudPlaceholderSkippedCount,
      mixedContainerQuarantinedCount,
      potentialMixedUnscannedCount,
      failClosedUncertainCount,
      zoneAWriteViolations: 0,
      multiIdentityCanaryResults: options.canaryResults ?? [],
    },
    reuseInventory: {
      universalHarnessDetected,
      universalHarnessEntrypointsCount,
      sqliteLedgersInspected: sqliteSchemas,
      reuseAssessmentCode,
    },
    formatInventory,
  };

  // Pre-emit zero-leak sanitization check
  const serializedReportJson = assertSanitizedStage0Report(report);

  let writtenReportPath: string | undefined;
  if (options.writeReportFileToZoneB) {
    fs.mkdirSync(options.config.zoneBOutputDir, { recursive: true });
    writtenReportPath = path.join(
      options.config.zoneBOutputDir,
      'stage0-sanitized-report.json'
    );
    fs.writeFileSync(writtenReportPath, serializedReportJson, 'utf8');
  }

  return {
    report,
    serializedReportJson,
    telemetry,
    writtenReportPath,
  };
}
